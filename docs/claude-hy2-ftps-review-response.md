# Claude 独立审查意见（界面转录）

日期：2026-09-16。来源：用户已登录的 Claude 桌面程序，Code 会话“HY2/FTPS 上传 TS 故障技术审查”，界面显示模型 Opus 5 / Ultracode。

以下保留 Claude 回复措辞，移除复制等界面按钮，纯文本提取未保留全部 Markdown 排版。回复中的严重程度和实验建议是 Claude 的审查判断，并非每项都已独立复现。Codex 的补充核对见同目录 claude-hy2-ftps-review-assessment.md。

---

核对完毕。我读了审查请求全文、shoes-plus 的相关源码、vendored quinn/quinn-proto、Docker 测试脚本与 Go 测试客户端，以及 run/hy2-ftp-20260916-190232/ 下的原始日志与快照；另外用网络按固定 commit 独立取回了 sing-quic 的 hysteria2/service.go 做对照。没有运行任何测试或构建，没有修改任何文件。
一、认可的结论
1. 核心缺陷真实，复现证据强度：高
我独立核对了机制链条，而不是只看结论：
• copy_bidirectional.rs 的 Future::poll 末尾是 (Poll::Ready(Err(e)), _) | (_, Poll::Ready(Err(e))) => Poll::Ready(Err(e)) —— 任一方向出错立即终止整体复制。随后 hysteria2_server.rs:2173 的 futures::join!(..., client_stream.shutdown()) 给目标发 FIN。所以「反向 Stopped → 丢弃未转发的上传 → 目标看到干净 EOF」在代码上成立。
• late-stop-before.log:9 是硬证据：expected=4194493, received=2398093, error=None。同一次运行里两个对照（只 FIN、只反向数据无 STOP）都通过，说明确实需要 STOP + 反向数据的组合。
• 反混淆设计是有效的。我查了 vendored quinn 的 SendStream::stopped() 文档与实现（vendor/quinn/src/send_stream.rs:227）：finish() 之后返回 None 确实表示对端已 ACK 全部数据与 FIN。因此测试断言的「字节已经到达代理侧」成立，丢失发生在代理内部。
2. 修复方向正确
保留独立上传方向、只把反向 Stopped 转成丢弃，符合 RFC 9000 §3.5 的单向语义。上传 RESET_STREAM、目标 I/O 错误、其他 WriteError 都仍然报错，四个单元测试（含 does_not_mask_upload_reset）覆盖了这几条边界。
3. 参考实现审查在我抽查范围内没有误读
• sing-box route/conn.go 的 connectionCopy：err != nil → common.Close(source, destination)，只有正常 EOF 才 CloseWrite()。我在本机 sing-box-reference clone 里逐行看过，附件二的表述准确 —— 包括「参考实现自己也会因反向错误终止上传」这个不讨好的结论。
• quic-go SendStream.handleStopSendingFrame：确实清 reliableSize/numOutstandingFrames、returnFramesToPool()、排入 queuedResetStreamFrame，与附件二一致。
• sing-quic serverConn.Close() = CancelRead(0) + Stream.Close() + SetWriteDeadline(now)。我用 raw.githubusercontent.com 按固定 commit 4ab2ece 取回原文，与本机 reference-sources/ 副本、Go module cache 三者逐字一致，包括那条看起来不像上游风格的内嵌注释。所以「没有修改参考源码」这条我可以背书。
4. reset-on-observed-Stopped 在 Quinn 语义上正确
SendStream::reset() 只作用发送半边；Drop for SendStream（vendor/quinn/src/send_stream.rs:329-352）本来就在 FinishError::Stopped(reason) 时做同样的 reset。所以这只是提前，不是新语义。重复 reset 返回 ClosedStream被 let _ = 吞掉，Drop 里再走到 FinishError::ClosedStream 分支无操作，不会 panic、不会二次排帧。所有权处理是对的。
5. 测试客户端 TLS/EOF 校准问题的区分正确
不把 qtls 包装的 EOF 处理失误归因给 node-agent，这个判断成立（但见 §3.2 —— 我认为这段证据被过度排除了）。
二、具体问题与严重程度
【P1】错误路径仍然把「上传被中断」翻译成给目标的干净 FIN
• 位置：hysteria2_server.rs:2173，同形代码另见 tcp/tcp_server.rs:437、quic_server.rs:702、tuic_server.rs:849。全仓库没有任何 set_linger/SO_LINGER 使用。
• 触发条件：copy_bidirectional 返回 Err 的任意原因 —— 客户端 RESET_STREAM、QUIC 连接丢失、目标 I/O 错误、TrafficMeterStream::poll_cancelled（用户被删除、inbound reload）。
• 影响：目标 socket 收到 FIN 而不是 RST，FTP/FTPS 服务端把残缺文件当作正常结束并回 226。这正是本次缺陷之所以静默的放大器。修复拆掉了一个触发器，放大器原封不动。
• 证据性质：「Err → FIN」是我读代码得出的推断，本轮没有单独复现。但「服务端对截断上传照回 226」是已复现事实（见 §3.2）。
• 建议：区分是哪个方向失败 —— 上传方向（server_stream → client_stream）异常结束时对 TCP 目标做 abortive close，正常 EOF 才 FIN。前提是 copy_bidirectional_with_sizes 需要报告出错方向，目前它只返回一个 io::Error。跨协议，建议单独一轮。
【P1】drain 路径不计量、不限速，且可由客户端主动、确定性地触发
• 位置：Hysteria2ResponseStream::poll_write 的 peer_stopped 短路分支（hysteria2_server.rs:1943-1949）。
• 触发条件：客户端开流 → 发 TCP 请求头 → 立刻 recv.stop()。代理照常拨号目标、写响应拿到 Stopped、然后把目标的全部响应读进 sink。
• 与旧行为的差别：旧的 PeerStopped 分支要求 STOP 抢在成功响应之前，是一个竞态；补丁把它扩展到任意时刻后，变成确定可达。
• 影响：这些字节走在 TrafficMeterStream 之外，既不计入 conn.add_tx，也不经过 poll_acquire_tx 限速；上传方向 Done 之后 drain 完全不再 poll 计量流，所以配额/限速/取消检查都失效。一个用户可以用多条流持续占用服务器出口带宽而账面为零。
• 边界（缓解）：scope_connection_until_cancelled + QuicConnectionLifecycle 的 DropGuard（quic_server.rs:87-105、hysteria2_server.rs:378-381）保证物理连接消失时任务被取消，所以不是无限期泄漏。但 HY2 连接本来就是长连接。
• 建议：在上传方向到达 Done（已给目标 FIN）之后再给 drain 加有界预算（字节上限或截止时间）。此时上传已经结束，不可能再截断慢上传 —— 所以这与报告里「不加任意超时以免再次截断」的顾虑并不冲突。我认为报告那条结论下得过宽了：它把「上传进行中不能加超时」正确的理由，扩展成了「任何阶段都不加超时」。
【P2】reset 是「写触发」而非「事件触发」
• 位置：quic_stream.rs:47-57。
• 触发条件：客户端发 STOP_SENDING 之后目标再无反向数据 —— FTP STOR 的数据连接正好是这种形态。
• 影响：send 半边留在 send map 里直到 process_tcp_stream 结束才由 Drop 清理。实际影响很小（unacked_data通常为 0，ACK 正常回收）。
• 真正的问题是文案：附件二第 6 节的契约写成「已观察到的 STOP 必须回收相应发送状态」，而实现覆盖的是「写操作观察到 Stopped 时」。契约名字比实际覆盖面大，回归也只覆盖有后续写的那条路径。建议改契约文案，而不是为此加后台 watcher。
【P2】peer_stopped 之后所有写错误被吞掉，包括 ConnectionLost
drain 期间 QUIC 连接断开时，如果上传方向已 Done，relay 只剩「读目标 → 丢弃」，感知不到连接已死，完全依赖 lifecycle 取消兜底。当前是安全的，但这个依赖没有写在注释里 —— 以后有人动 DropGuard 就会变成真泄漏。
【P3】包装器吃掉了 vectored 写
Hysteria2ResponseStream 没有转发 poll_write_vectored / is_write_vectored。而 TrafficMeterStream 专门转发了它们并注释说明「否则会在 TLS 记录路径上损失吞吐」。新包装器叠在它上面把这个能力抵消了。当前 copy_bidirectional 不用 vectored，所以无实际影响，属于会被下一次改动踩到的陷阱。
【P3】被 reset 丢弃的、已被 quinn 接收但未发出的响应字节仍计过 tx
计量在 quinn 之外的上层，reset 丢弃 quinn 已排队的数据。既有 Drop 路径也有同样偏差，量级是一次 write 缓冲，记录即可。
【P3，但对现场排查影响最大】release 构建里这条失败不留任何日志
shoes-plus/Cargo.toml:63 启用了 log 的 release_max_level_info，Cargo feature 统一会让整个 workspace 生效（node-agent 依赖 shoes）。于是 hysteria2_server.rs:1829 的 debug!("Hysteria2 TCP stream ended: {e}") 在 release 里被编译掉。恰恰是会静默截断上传的那类事件，在生产上完全不可见。 这是所有建议里代价最低、对回答「用户到底是不是这个 bug」帮助最大的一条。
一处需要修正的表述（关系到将来升级 quinn）
附件二写「Quinn 已有 state.rs:1945–2026 回归覆盖发送窗口满时仍须报告 Stopped」。我核对了 vendor/quinn-proto/.../streams/mod.rs:255-266：stop_reason 检查确实排在 limit == 0 的 Blocked 检查之前；但 git log 显示这来自本仓库自己的 vendored 提交 fd758ea fix(quic): report stopped writers before flow-control waits，不是上游 Quinn 行为。
这不是小事：「写被流控阻塞时 STOP 仍会报 Stopped」正是 reset-on-Stopped 不会死锁的前提。写成「Quinn 已有」，下一次升级 vendored quinn 时很容易把它丢掉。应改成「本仓库 vendored 的改动 + 其回归」。
三、证据缺口
3.1 118/118 的 FTPS 矩阵在结构上不可能复现这个缺陷
我核对了 tests/interop/sing-quic-switch/cmd/ftp-integrity/ftp.go:287-294：graceful 模式下客户端先 CloseWrite() 发 close_notify，然后 io.Copy(io.Discard, eofReader{secured})把反向读到 EOF，最后才 data.Close()。也就是说会产生 STOP_SENDING 的那次 Close，永远发生在反向已经 EOF 之后 —— 触发条件被结构性排除了。
而 tests/docker/hy2-ftp/run.py:162 把 --close-mode 硬编码成 graceful，run.py:182 还要求 row["close_mode"] == "graceful" 才判通过。immediate 在这一轮矩阵里一次都没跑过。
报告写「没有在这套正常 FTPS 矩阵中重现现场故障」是对的，但把 118/118、236 次、2.04 GiB 放在同一份结论里，读者很容易读成「正常路径已被广泛验证没有这个问题」。应该明确写成：该矩阵按构造避开了触发条件，因此「修复前也通过」不是弱证据，而是零证据。
3.2 被当作「测试程序校准问题」排除掉的那次直连失败，是本次调查里最接近用户症状的一次复现
baseline-ftps/direct-large.log：
"mode":"direct", "ftps":true, uploaded_bytes=33713288,
stor_code=226, remote_bytes=30818304, retrieved_bytes=30818304, retr_code=226
完全不经过 node-agent，FTPS，immediate 关闭 → 服务端落盘少 2.9 MB，两个 FTP 响应都是 226。
归因判断（不是 node-agent 的问题）是对的，但推论「因此与现场无关」下得过早。它同时证明了两件对现场很关键的事：
1. pyftpdlib/OpenSSL 这类服务端会对被截断的 TLS 上传照回 226 —— 用户「以为成功」的症状不需要代理参与就能产生；
2. 「客户端写完立刻关 socket」这种关闭方式，即使没有任何代理，也能产生「226 + 目标文件更短」。
如果 FileZilla 的关闭时序接近 immediate，那么修完 HY2 之后用户仍可能看到同样的症状。 这个竞争假设应该进入结论，而不是留在「测试程序的两个校准问题」一节里被排除掉。
3.3 用户现场故障的证据强度：低
没有版本、没有故障源/目标文件对、没有 SHA、没有控制通道日志、没有 QUIC 日志；「多线程上传」只是用户的猜测。
目前只有一条机制上说得通的推理链：FTPS 数据连接上确实存在反向 close_notify，因此满足「STOP + 反向数据」的触发条件。这是我读代码加读客户端行为得出的推断，没有复现过。 报告在这一点上的克制是恰当的，不应被这次审查放松。
3.4 收尾快照里三个未解释项
• agent_active_connections：before 0 → after 1；agent_online_users 同样 0 → 1。本次改动恰恰延长了逻辑流的生命周期，这条残留应该被单独定位，而不是留成「有界检查推不出全部资源已回落」的 caveat。它同时也决定面板的在线连接数会不会缓慢漂移。
• RSS 41,096 → 61,216 KiB，同上。
• 计量对不上：我自己算了 final-reviewed 各 stage 的字节数 —— HY2 模式实际上传 509,621,000 B，而 after.json 的 traffic.alice.uplink_bytes 只有 489,412,685；下行差得更多（421,572,228）。考虑到 TLS/FTP/HY2 头部开销，计量值应当高于净荷而不是低于。最可能的解释是 telemetry 按 delta 上报、快照时最后几批未 flush（reports=8），但这一轮数据既不能证实也不能证伪报告里「丢弃的响应不再算作实际发送流量」这句 —— 该结论目前只有代码层面的支持。
3.5 「干净 EOF」只在 Rust 回归里验证过
断言的是目标侧 read 返回 Ok(0)。真实 FTPS 服务端在这条触发路径下会不会回 226，本轮没有直接测过（§3.2 那次是另一条路径）。
3.6 丢失量完全由缓冲决定
Windows 两次是 84,021 / 82,601 B，Docker 是 2,398,093 B，差两个数量级。这说明现场可能表现为「只少了几十 KB」，用户肉眼比大小根本看不出来。这一点应该写进给用户的排查指引 —— 「大多数时候大小一致」这个观察本身，并不能把这个缺陷排除掉。
四、优先实验
E1（最高优先）用 immediate 关闭模式跑完整 FTPS 矩阵，修复前 / 修复后各一次
• 怎么做：run.py 去掉硬编码的 graceful，加一档 immediate。前置条件：先把客户端在 immediate 模式下的自身缺陷排掉 —— 发完 close_notify 后不要在入站仍有未读数据时直接关 socket；先确认 direct 基线干净，再跑 hy2。否则又会变成测客户端。
• 能区分什么：修复前 hy2 出现截断、修复后不出现 → 现场机制基本坐实。修复前后都不出现 → 说明触发条件比现在的理解更窄，还需要 close_notify 之外的反向数据。
E2 在真实 FTPS 上确认「服务端回 226 但文件更短」
• 怎么做：修复前二进制 + E1 的客户端，让 pyftpdlib 记录 STOR 响应码与落盘大小，断言出现 226 + 短文件。
• 能区分什么：证明这个缺陷在真实 FTPS 服务端上确实是静默的（没有被 426/425 挡住）。这直接决定用户「以为成功」的症状能否由它解释。顺带验证 §二 P1 的「Err → FIN」放大器。
E3 抓一次 FileZilla 的真实关闭时序
• 怎么做：不碰用户的机器。本地装 FileZilla Client 对本地 FTPS 做一次 STOR，抓包看数据连接末尾的顺序：客户端 close_notify → 是否等服务端 close_notify → FIN 还是 RST。再把同一次走本地 HY2 客户端，看代理侧是否出现 STOP_SENDING。记录 FileZilla 版本。
• 能区分什么：这是唯一能把「客户端是否会在反向未 EOF 时取消接收」从推断变成事实的实验。 没有它，E1/E2 只能证明「存在这样一类客户端」，不能证明 FileZilla 属于这一类。
E4 给 drain 加「上传方向已 Done 之后」的有界预算，并配回归
• 回归形态：客户端 STOP 响应方向 + 完成上传 FIN，目标永不 EOF；断言逻辑流在 N 秒内释放、flow permit 归还、telemetry 的 active connections 回落。
• 能区分什么：同时钉死 §二 P1 第二条与 §3.4 的 agent_active_connections = 1 —— 如果加预算后残留消失，残留就是这条路径。
E5 把 HY2 TCP 流的复制失败提到 release 可见的级别，然后在用户节点上等一次故障
• 输出要含：目标地址、两个方向已复制字节数、错误 kind、是否 peer_stopped；做速率限制。
• 能区分什么：现场唯一的判别器。下次用户报故障时，日志里有没有对应时刻的 copy 失败，直接把「HY2 缺陷」和「FileZilla / 服务端 / 播放侧」分开。
• 同时给用户的留证清单：故障源/目标 TS 的 SHA-256 与字节数、FileZilla 完整控制日志（含最后一条 STOR 的响应码与 SIZE）、FileZilla 版本、HY2 客户端与 node-agent 版本。
五、是否阻塞合入
不阻塞。 理由：
• 缺陷真实、复现确定、修复方向符合 RFC 9000 与 Quinn 的所有权语义；
• 变更面小且只对 HY2 开启（quic_stream.rs 的开关默认关闭，只有 hysteria2_server.rs:2074 打开），其他协议的通用复制器没动；
• 20 项 Docker 回归我核对过 build-final.log（3+4+7+1+5 = 20，含 observed_reverse_stop_is_reset_before_upload_fin），118 次真实 FTPS 上传回读与 20 份 TS 解码在最终二进制上通过；
• 本次改动带来的新风险（drain 被滥用、连接残留）都收敛在单条 QUIC 连接的生命周期内，并有 lifecycle DropGuard 兜底。
合入前建议只改两处文案，免得后来人误读证据：
1. 明确写出 FTPS 矩阵按构造避开了触发条件（§3.1）；
2. 把「Quinn 已有回归」改成「本仓库 vendored 的 fd758ea 及其回归」（§二末），并把「已观察到的 STOP」契约收窄为「写操作观察到 Stopped 时」。
一句话给用户的判断：已确认的是「node-agent 的 HY2 存在一个会静默截断上传的半关闭缺陷，且已修复」；尚未确认的是这就是他遇到的那个故障。§3.2 那条直连证据说明，同样的症状不需要代理参与也能产生 —— 所以在拿到 E3 的抓包或 E5 的现场日志之前，不应该告诉用户「问题已解决」。
