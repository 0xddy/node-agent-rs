# 请 Claude 独立审查：node-agent-rs / HY2 / FTPS 上传 TS 偶发截断

请用中文做一次独立技术审查。以下是用户原始问题、此次处理报告、固定版本参考实现审查、最终核心补丁和新增协议回归。请质疑材料中的判断，不要因为测试通过或另一位助手这样解释就默认正确。这里只请求分析意见；请勿更改代码、部署或联系其他人。

## 用户原始问题与澄清

用户最初说：“好像遇到一个Bug，使用 node-agent-rs 的 hy2 协议，使用 ftp上传 视频的 ts，播放视频偶尔出现媒体播放卡顿问题，像数据有点损坏或者不完整（我猜的），帮我自己分析看看，再用 docker 做测试。”

随后澄清：使用 FileZilla Client；曾比较文件大小，很多时候一致，但发现过一次最后一个 TS 的目标文件比源文件小；确认全部上传结束后才播放；使用 FTPS，并说“而且开的还是多线程上传吧”，所以并发目前只记为可能，不能当作已核对的配置。

用户又提出：底层细节应参考 sing-box 源码处理，以便提前避免踩坑，不应只等故障出现才补救。最后明确要求把问题和本次处理发给 Claude 听取意见。

尚无线上 node-agent/HY2 客户端/FileZilla 的确切版本、完整代理链路、故障源/目标 TS 文件对、SHA-256 和现场 FTP/QUIC 日志。不要自行补造这些信息。

## 希望你重点回答

1. 请分别判断“已复现的 HY2 核心截断缺陷”和“用户实际 FileZilla 偶发故障”的证据强度。核心回归是否还存在重要混淆因素？
2. 客户端 STOP_SENDING 反向接收后，服务端排空并丢弃响应、继续上传的语义是否正确？错误传播、计量、生命周期、无限等待或资源消耗方面有无问题？请给出具体触发条件。
3. HY2 写操作观察到 Stopped 后显式 reset 发送半边，是否正确处理 Quinn 的所有权和清理责任？没有后续写、发送窗口耗尽、RESET 与 FIN 竞争时，有哪些遗漏值得优先测试？
4. 对 sing-box / sing / sing-quic / quic-go 的固定源码对照是否有误读？请区分参考实现本身的行为与协议应有契约；如无法打开来源，请明确说明，勿假称核对过。
5. 正常 FTP/FTPS 矩阵在修复前后都通过，且测试使用自写 Go 客户端而非 FileZilla。为了缩小现场原因，下一轮最有价值的 3–5 个实验或证据是什么？请说明每项能排除或区分什么。
6. 有哪些结论过度、修复风险或应阻止合入的问题？如无阻塞问题也请说明理由及仍然缺失的证据。

请按“认可的结论 / 具体问题与严重程度 / 证据缺口 / 优先实验”回答。每个技术问题尽量给出文件/函数、触发条件、影响、建议验证方式。请将源码推断与实际复现分开；不把测试程序自身的 TLS/EOF 校准错误归因于 node-agent，也不把 QUIC ACK 等同于目标落盘。

附件内的测试和构建记录由此次处理者提供，尚未经过你的独立运行。本文件是发给你的审查请求，绝不是 Claude 已给出的意见。

---
## 附件一：排查报告（完整）

# FTPS 并发上传 TS 的完整性排查

2026-09-16，本机 Windows + Docker Desktop Linux 实测。用户反馈：FileZilla 使用
FTPS、可能并发上传；全部上传结束后才播放；曾发现最后一个 TS 的目标大小小于
源文件，大多数时候大小相同。尚未提供 FileZilla、HY2 客户端及线上 node-agent
的版本，也没有发生故障的源/目标 TS 对。

## 已证实的核心缺陷

本次修改前，`shoes-plus` 的已有修复只保护 HY2 初始成功响应写入时收到的
`STOP_SENDING`。如果初始响应已成功，客户端随后取消接收反向数据，而目标又发送
反向数据，QUIC 写入返回 `WriteError::Stopped`。通用双向复制器把任一方向的错误
当作整个复制结束，随后给目标发送 TCP FIN，仍未转发的上传数据被丢弃。

这个结果不是文件内部随机改字节：它可以是**较短文件和干净 EOF**。FTP 完成响应
也不能代替源/目标内容校验。

新测试 `crates/shoes-engine/tests/ftp_upload_late_stop.rs` 先等待所有上传字节及 FIN
被 QUIC ACK，再释放目标端慢读。整个 QUIC 连接始终存活，排除了“只是客户端
write 返回”和“客户端提前关闭整条连接”这两个混淆因素。

| Docker 场景 | 修复前收到 | 修复后收到 |
| --- | ---: | ---: |
| 上传后 STOP，目标只有 FIN | 4,194,493 B | 4,194,493 B |
| 目标反向数据，无 STOP | 4,194,493 B | 4,194,493 B |
| 上传后 STOP，目标反向数据 | **2,398,093 B，干净 EOF** | **4,194,493 B，SHA-256 一致，干净 EOF** |

Windows 对同一失败分支的两次复现分别收到 84,021 和 82,601 B。截断位置取决于
时序和缓冲，没有固定文件大小阈值。

## 修复

`shoes-plus/src/hysteria2_server.rs` 新增 HY2 私有响应包装器：成功建立目标连接后，
仅将反向 `quinn::WriteError::Stopped` 转为排空并丢弃响应；上传继续直到自己的 EOF。
这覆盖初始响应、目标握手的 early data 以及后续复制。其余写错误和上传 RESET
继续报错。沿用 32 KiB 有界缓冲和原有公平调度，不修改其他协议的通用复制器。

包装器在流量计量层之外，丢弃的响应不再算作实际发送流量。目标反向数据仍读到
EOF，避免带着未读数据关闭 TCP socket。补丁保存为
`patches/shoes-plus-hy2-late-stop.patch`，CI 和 release 在固定核心 revision 上应用。
已在干净的固定 revision 文件上验证：先应用既有 observation 补丁，再应用此补丁，
结果与本次测试核心一致。

随后按用户建议对照了固定版本的 sing-box、sing、sing-quic 和 quic-go，详见
[半关闭源码审查](hy2-half-close-reference-audit.md)。由此补上第二层处理：仅 HY2
在写操作观察到 `Stopped(code)` 时显式重置发送半边，再把原错误交给外层丢弃逻辑。
这提前归还本地发送预算，不取消上传。新增回归先证实原丢弃逻辑会推迟 RESET，
再验证上传尚未 FIN 时 RESET 已到达，之后剩余上传仍完整。该收尾没有改变其他
QUIC 协议，也没有将对端流控信用、存储释放和本地预算恢复混为一谈。

最终修复后 Docker 的 20 项相关集成测试通过，包含新截断与发送 RESET 回归、
既有 FTP 风格关闭、fast-open、HY2 基础行为、128 MiB 上传、背压以及丢包/乱序。
第一版修复在 Windows 另通过 14 项集成测试及 31 项核心 HY2 单元测试；追加 RESET
收尾后又通过 8 项 FTP / late-stop / fast-open 集成测试，相关 Clippy 和格式检查通过。

## 真实 FTP / FTPS 测试方法

入口为 [Docker harness](../tests/docker/hy2-ftp/README.md)。测试运行真正的 Linux
release `node-agent`，由独立 ACP fixture 完成认证、配置和用户同步，并等待配置 ACK。
FTPS 服务采用系统包 pyftpdlib 1.5.7 / OpenSSL；HY2 客户端采用已锁定的官方
sing-quic `v0.7.0-beta.4` / quic-go `v0.61.0-sing-box-mod.7`。

Windows 客户端 → Docker 发布的 HY2 UDP 端口 → 容器内 FTPS 控制及被动数据连接。
直连控制使用同一网络命名空间里的 Linux 客户端。所有凭证和证书只用于本地测试。
每次客户端调用共用一个 QUIC 连接，禁止自动重连掩盖失败；并发 worker 各有 FTP
控制连接，控制连接跨 round 复用。

FTPS 使用 AUTH TLS、PBSZ 0、PROT P，数据采用 TYPE I。每次传输要求：

- STOR/RETR 均返回 226；客户端实际写入、FTP SIZE、下载大小均等于源文件。
- 下载 SHA-256 与源文件一致；服务端完成事件独立计算的 SHA-256 也一致。
- 每个 worker 最后一次回读的真实 TS 保留，并用 FFmpeg 严格解码检查。

样本为 H.264/AAC MPEG-TS：小样本 1,642,744 B，大样本 33,713,288 B。
矩阵含普通 FTP 控制、直连 FTPS、顺序/四并发、小/大文件、fast-open、每连接
2 MiB/s 目标限读，以及 daemon 出口 10 ms 延迟和 0.5% 丢包。

本轮 FTPS 矩阵使用自动带宽配置（服务端 up/down 为 0、忽略客户端带宽参数），
未启用流量分析。Brutal 带宽模式由上述 Rust 上传回归覆盖，不等同于再跑一套
Brutal FTPS 矩阵。FTPS 的 fast-open 阶段跳过显式等待 HY2 成功响应，但 TLS 握手
本身仍需往返，不能据此声称覆盖 QUIC 0-RTT 或应用数据提前发送的所有时序。

## 第一轮真实传输结果

19:26–19:28 两版并行运行相同矩阵，均通过。此结果验证正常 TLS 关闭流程下的
完整性，**没有在这套正常 FTPS 矩阵中重现现场故障**；确定性半关闭回归才提供
上述核心缺陷的修复前后差异。

| 检查 | 修复前 release | 修复后 release |
| --- | ---: | ---: |
| 明文 FTP 经 HY2 控制 | 2/2 | 2/2 |
| 直连 FTPS 控制 | 3/3 | 3/3 |
| 经 HY2 的 FTPS 顺序、并发、背压、丢包 | 113/113 | 113/113 |
| 服务端独立 SHA-256 检查 | 118/118 | 118/118 |
| 保留 TS 的严格解码 | 20/20 | 20/20 |
| 实际上传字节数 | 546,619,776 B | 546,619,776 B |
| 实际回读字节数 | 546,619,776 B | 546,619,776 B |

两版合计 236 次上传及回读，约 2.04 GiB 有效负载。所有阶段退出码为 0。
结束快照中 daemon 和 ACP fixture 正常，daemon FD 均恢复到起始的 13 个，
UDP socket 队列为空；随后本轮测试容器全部正常停止，未发生 OOM。
这不是公网性能基准，也没有将人工 netem 丢包等同于真实链路情况。

两版基于 node-agent-rs `56e4ef7`、shoes-plus `32e5864` 及本机原有 observation
工作区修改。修复版额外应用本次 HY2 补丁。完整构建与二进制关联记录在
`verified-build-provenance.json`。矩阵使用 `--skip-build` 是为了复用本任务中刚完成的
两次构建；并非以当前源码 revision 冒充旧 volume 的构建来源。

| 二进制 | SHA-256 |
| --- | --- |
| 原始 node-agent | `d89b813d60b4c361e600df53eac92f140d3e57a61e923c0267abd6d8005b6874` |
| 第一版修复 node-agent（尚未加入上述主动 RESET 收尾） | `e5e5a530d91f3b1d0c15442097f4b7b15f560f52a16b378bf3609502a47c13fb` |

完整结果分别位于 `baseline-final/`、`fixed-final/`。第一版 Linux amd64 二进制保存在
`fixed-final/node-agent-linux-amd64`，导出后再次核对 SHA-256 与被测二进制相同。

## 最终版本复验

源码对照及主动 RESET 收尾完成后，重新构建 Linux release，并在 Docker 运行全部
20 项相关集成测试，均通过。同轮于 19:41–19:42 对最终二进制重跑相同 FTP/FTPS
矩阵：118 次上传及回读、118 次服务端 SHA-256 检查、20 份保留 TS 严格解码均通过，
上传与回读各 546,619,776 B。此结果延续正常 FTPS 的完整性验证；确定性回归仍是
截断及 RESET 清理缺陷的前后对照依据。

四个测试容器正常退出且无 OOM；daemon 与配置 fixture 的 FD 均为 13→13，
UDP 收发队列为空。这些有界检查不能推出全部资源已回落：daemon RSS 从
41,096 增至 61,216 KiB，最终遥测仍有 1 条活动连接；TCP 亦存在重置和重传计数，
本轮没有逐包归因，但没有对应的文件完整性失败。

最终证据位于 `final-reviewed/`，`result.json` 记录成功结果；根目录的 `build-final.log`
保存最终构建与 20 项回归输出。`final-reviewed/verified-build-provenance.json`
关联构建容器、最终核心补丁、两个核心源文件及二进制 SHA-256，补足 `--skip-build`
运行本身不验证构建来源的限制。

已导出并核对与被测文件一致的 Linux amd64 二进制：
`final-reviewed/node-agent-linux-amd64`。
SHA-256：`346f2c564ca98a9b8c04945cfedd9d4b43af1873fde12014b230a6845985618b`。

## 测试程序的两个校准问题

最初普通 FTP 回读已得到完整文件和一致 SHA，但客户端把 sing-quic 包装过的正常
`io.EOF` 当错误。TLS 回读还暴露了同一个适配问题：仅在 TLS 外层处理错误会让
Go TLS 放弃最后一个已经收到的密文记录，曾导致回读少最后 4,344 B，而目标文件
本身完整。现于 TLS 下方统一把最底层原因严格等于 `io.EOF` 的错误规范化；不能简单使用
`errors.Is`，因为该 SDK 也把某些本地主动取消匹配为 EOF。重置、取消、UnexpectedEOF
仍是失败。新增真实 TLS 正反对照测试验证最后一条记录不丢失。这些测试程序失败
分别保留在初始目录和 `baseline-ftps-graceful/`，没有作为核心损坏证据。

最初 FTPS 测试采用写完立刻 `tls.Close`，直连控制就出现 33,713,288 B 写入、
30,818,304 B 落盘，两个 FTP 响应都是 226。这个失败发生在 HY2 之前，不能归因于
node-agent。正常矩阵因此采用 TLS `CloseWrite`、读取对端关闭响应至 EOF、再关闭
底层连接；`--close-mode immediate` 保留作关闭压力对照。

这两种关闭方式不能直接代表未知版本 FileZilla 的具体实现。TLS 关闭通知与底层
连接可靠交付是不同层次；参见 [TLS 1.3 关闭语义](https://www.rfc-editor.org/rfc/rfc8446#section-6.1)。

## 对现场的解释边界

FTPS 存在 TLS 反向消息，使已证实的 HY2 分支比普通单向 FTP 更值得怀疑，但本次
没有操作用户的 FileZilla，也没有取得现场故障日志，不能把核心回归等同于用户
实际故障的完整复现。用户确认完成上传后才播放，故不把上传途中读取当作既定原因。

等大小不能证明内容一致。下一次出现问题，保留对应源/目标 TS 的 SHA-256、
FileZilla 最后一次 STOR 的控制日志，以及客户端和 node-agent 版本。如果大小和
SHA 都相同，应转向 TS 时间戳/分片衔接、播放网络及缓存路径；如果变短，则继续
对照关闭/重置和传输完成时序。FileZilla 的二进制模式不会做文本换行转换，参见
[官方传输类型说明](https://filezillapro.com/docs/v3/advanced/file-type-classifications-for-ftp-and-ftps/)。

本机原始证据根目录：`run/hy2-ftp-20260916-190232/`。`late-stop-before.log` 和
`regressions-after.log` 保存 Docker 核心前后对照；`build-baseline.log` 保存原始
release 构建。所有结果只说明对应二进制、客户端和有界流量下的行为。


---
## 附件二：固定版本参考源码审查（完整）

# HY2 半关闭与取消：sing-box 固定源码对照

审查日期：2026-09-16。范围仅包括本次 FTP/FTPS 上传截断修复涉及的 TCP 数据方向、EOF、取消、复制和资源释放；不将参考实现的默认行为直接当作 Rust 的正确性标准。本文是源码审查，真实 Docker 上传结果另见本轮测试报告。

## 结论

本次 Rust 修复保留了独立上传方向，覆盖成功响应之后才收到 `STOP_SENDING` 的情况；数据完整性回归已验证该改动。参考实现确认了三个应固定的边界：先处理最后一批数据再处理 EOF；正常结束与取消不能混为一谈；取消一条 QUIC 发送方向应释放相应发送状态。

**sing-box 的普通双向复制同样会因一个方向的错误关闭两端。**因此不能声称本次修复是逐行照搬 sing-box，也不能只因为参考项目存在该行为就恢复会截断上传的逻辑。值得保留的是可检查的协议契约和回归用例。

本次对照另外发现并补上了取消方向的清理责任：当前 Quinn 在报告 `Stopped` 后由应用负责 reset/drop，而 quic-go 在收到 STOP 时直接排入 RESET 并清理发送队列。仅有外层 sink 会把该清理推迟到上传结束；新增回归先证实上传保持打开时收不到 RESET，再验证 HY2 专用的 reset-on-observed-Stopped 修正。它没有改变其他 QUIC 协议的默认行为，也没有把未经复现的同连接死锁写成事实。

## 1. 固定版本与来源

| 组件 | 版本 | 已确认提交 |
| --- | --- | --- |
| sing-box | `v1.14.0` | [`0b8995879f29a9b98ee027bc17b75e101445b238`](https://github.com/SagerNet/sing-box/tree/0b8995879f29a9b98ee027bc17b75e101445b238) |
| sing-quic | `v0.7.0-beta.4` | [`4ab2eceaac81e073f53b22ec72ff56aaea89a3d1`](https://github.com/SagerNet/sing-quic/tree/4ab2eceaac81e073f53b22ec72ff56aaea89a3d1) |
| sing | `v0.9.0-beta.4` | [`3f8f790b7a2968307bbf900544fc8030791c715e`](https://github.com/SagerNet/sing/tree/3f8f790b7a2968307bbf900544fc8030791c715e) |
| SagerNet/quic-go | `v0.61.0-sing-box-mod.7` | [`0cae1a7786ee290bd9ecce40b6782d4c227ef1d6`](https://github.com/SagerNet/quic-go/tree/0cae1a7786ee290bd9ecce40b6782d4c227ef1d6) |

依赖版本来自上述 sing-box 的 [`go.mod:47–53`](https://github.com/SagerNet/sing-box/blob/0b8995879f29a9b98ee027bc17b75e101445b238/go.mod#L47)。标签通过本机 HTTP 代理执行 `git ls-remote` 核对；sing-box 已按标签浅克隆到 `run/hy2-ftp-20260916-190232/sing-box-reference`。其余源码先读本机 Go 模块缓存，再与固定提交的官方原始文件比较：本次使用的 9 个文件均一致，副本保存在同次运行的 `reference-sources` 下。没有修改参考源码或模块缓存；本地 Rust 后续的小范围收尾见第 5 节。

## 2. QUIC 的两个方向与三种结束事件

QUIC 双向流由独立的发送、接收状态构成。FIN 表示本方向数据结束；STOP 请求对端停止向自己发送数据，并促使该发送方向 reset；它本身不要求应用放弃另一方向。要主动终止两个方向，需要分别处理。RFC 也明确 RESET 不改变反方向的数据流控状态。这是传输层契约，不代表所有代理应用必须对任何业务错误继续传输。[RFC 9000 §3.4](https://www.rfc-editor.org/rfc/rfc9000.html#section-3.4)、[§3.5](https://www.rfc-editor.org/rfc/rfc9000.html#section-3.5)、[§4.4](https://www.rfc-editor.org/rfc/rfc9000.html#section-4.4)、[§19.5](https://www.rfc-editor.org/rfc/rfc9000.html#section-19.5)

实际 API 也必须分层看：quic-go [`Stream.Close:181–184`](https://github.com/SagerNet/quic-go/blob/0cae1a7786ee290bd9ecce40b6782d4c227ef1d6/stream.go#L181)只关闭发送方向；`CancelRead` 和 `CancelWrite` 分别操作接收、发送方向（同文件 155–164）。不能把 Go 的 `Close()` 名字直接对应成 TCP 全关闭，也不能把 Quinn 的 `finish()` 当成远端文件已经落盘。

## 3. sing-quic 与 sing-box 实际怎样结束复制

| 层 | 源码行为 | 对本次修复的含义 |
| --- | --- | --- |
| HY2 服务端响应 | `serverConn.HandshakeSuccess` 写成功响应，错误直接返回；`Write` 将首批数据与响应合并或直接写原始流，并包装错误。[service.go:403–430](https://github.com/SagerNet/sing-quic/blob/4ab2eceaac81e073f53b22ec72ff56aaea89a3d1/hysteria2/service.go#L403) | 此处没有把远端 STOP 改成 sink 的专用分支。不能由参考代码推出“成功响应后上传天然安全”。 |
| HY2 客户端与服务端关闭 | 两个适配器的 `Close` 均先 `CancelRead(0)`，再 `Stream.Close()`，最后将写 deadline 设为当前时间来唤醒阻塞写。它们没有调用 `CancelWrite` 丢弃已排队的发送数据。[服务端 441–447](https://github.com/SagerNet/sing-quic/blob/4ab2eceaac81e073f53b22ec72ff56aaea89a3d1/hysteria2/service.go#L441)、[客户端 782–788](https://github.com/SagerNet/sing-quic/blob/4ab2eceaac81e073f53b22ec72ff56aaea89a3d1/hysteria2/client.go#L782) | 这确实可能产生 FIN 与反向 STOP 的组合；只证明该 SDK 的行为，不能替代对用户实际客户端链路的确认。适配器关闭与底层 QUIC 单向 `Close` 不是同一语义。 |
| sing-box 路由 | outbound 成功后报告 handshake；报告失败会关闭 remoteConn 和 inbound。之后两个 goroutine 各复制一个方向。[conn.go:122–153](https://github.com/SagerNet/sing-box/blob/0b8995879f29a9b98ee027bc17b75e101445b238/route/conn.go#L122) | 建链响应错误与后续业务复制是两个窗口；本次 Rust 分别保留原成功响应特判和后续 sink。 |
| sing-box 双向复制结束 | 任一方向复制错误立即 `common.Close(source, destination)`；正常结束且目标实现 `N.WriteCloser` 才 `CloseWrite()`，否则调用目标 `Close()`；第二个方向结束时统一关闭双方。[conn.go:273–289](https://github.com/SagerNet/sing-box/blob/0b8995879f29a9b98ee027bc17b75e101445b238/route/conn.go#L273) | 参考版本也允许反向错误终止上传。`serverConn` 自身没有 `CloseWrite` 方法；还必须考虑具体包装器是否暴露该能力，不能只看函数名就断言完整半关闭。 |
| sing 通用 `CopyConn` | 两个任务复制；有 `N.WriteCloser` 才在正常 EOF 后半关闭；复制错误关闭对应目标。其 task group 在这里没有启用 `FastFail`，最终 cleanup 关闭双方，外部 context 取消也触发 cleanup。[copy.go:221–258](https://github.com/SagerNet/sing/blob/3f8f790b7a2968307bbf900544fc8030791c715e/common/bufio/copy.go#L221)、[task.go:84–120](https://github.com/SagerNet/sing/blob/3f8f790b7a2968307bbf900544fc8030791c715e/common/task/task.go#L84) | `CopyConn` 和 sing-box 路由自己的 `connectionCopy` 不是同一个函数；不能混用它们的取消策略。 |

普通缓冲复制按读取一批、完成写入、再读下一批工作，写端阻塞会形成背压。[sing copy.go:186–218](https://github.com/SagerNet/sing/blob/3f8f790b7a2968307bbf900544fc8030791c715e/common/bufio/copy.go#L186) Rust 继续使用现有两个 32 KiB 缓冲和协作调度，未为取消方向积累无限数据，也未改变其他代理协议的通用复制行为。

## 4. EOF 与 FTPS 尾部数据

`sing-quic` 的 Read 返回 `n` 并通过 `qtls.WrapError` 包装错误，连正常 EOF 也会被包装。[service.go:413–415](https://github.com/SagerNet/sing-quic/blob/4ab2eceaac81e073f53b22ec72ff56aaea89a3d1/hysteria2/service.go#L413)、[client.go:741–756](https://github.com/SagerNet/sing-quic/blob/4ab2eceaac81e073f53b22ec72ff56aaea89a3d1/hysteria2/client.go#L741)、[quic_error.go:16–28](https://github.com/SagerNet/sing-quic/blob/4ab2eceaac81e073f53b22ec72ff56aaea89a3d1/quic_error.go#L16)

sing 的 `ExtendedReaderWrapper.ReadBuffer` 先按 `n` 设置 buffer 长度；当 `n > 0 && errors.Is(err, io.EOF)` 时返回 nil，使这一批有效数据先被写走。直接遇到 EOF 就退出的上层实现可能丢尾部数据。[conn.go:120–126](https://github.com/SagerNet/sing/blob/3f8f790b7a2968307bbf900544fc8030791c715e/common/bufio/conn.go#L120)

但 `errors.Is(err, io.EOF)` 也不能无差别用作 TLS 正常化规则：`qtls.quicError.Is` 还把“本地取消、错误码 0”的 StreamError 分类成 EOF，而远端 reset 保留错误（[quic_error.go:31–58](https://github.com/SagerNet/sing-quic/blob/4ab2eceaac81e073f53b22ec72ff56aaea89a3d1/quic_error.go#L31)）。因此本轮测试客户端应只解包真正的 EOF，保留 reset、超时和异常关闭；TLS 完整性验证应同时核对明文长度、SHA 与关闭错误。不能将 TLS 错误统统改成成功，或从 wrapped EOF 的处理失误反推服务端必然损坏文件。

## 5. 对照后补齐的 Rust 取消清理

`shoes-plus/src/hysteria2_server.rs:1928–2002` 的私有 `Hysteria2ResponseStream` 位于计量流外层，仅在下层返回明确的 `quinn::WriteError::Stopped` 后把后续响应变成 sink。读取仍穿过原计量流，因此上传 RESET、目标 I/O 错误和物理连接取消没有被改成成功。已成功写入 QUIC 的字节照常计量；被 sink 丢弃的后续字节不再次调用计量写。`2143–2172` 将这一路径用于 early data 和原有有界双向复制。

**外层 sink 还必须配合释放已取消的 QUIC 发送状态，不能仅隐藏 Stopped 后一直持有发送句柄。**

quic-go 的 [`SendStream.handleStopSendingFrame:717–737`](https://github.com/SagerNet/quic-go/blob/0cae1a7786ee290bd9ecce40b6782d4c227ef1d6/send_stream.go#L717)会释放排队帧、记录远端 reset、排入 RESET_STREAM 并唤醒写者。当前 vendored Quinn 的行为不同：

- `vendor/quinn-proto/src/connection/streams/state.rs:362–377` 只记录停止原因并发出 `Stopped` 事件。
- `vendor/quinn/src/send_stream.rs:151–159` 的写操作把 `Stopped` 返回应用，未在这里 reset。
- `vendor/quinn-proto/src/connection/streams/mod.rs:338–343` 才在显式 reset 时减去未确认发送数据、归还本地发送窗口并排入 RESET_STREAM；ACK 也可逐步释放已发送数据。
- `vendor/quinn/src/send_stream.rs:344–359` 在 Drop 时处理 stopped 流的 reset。外层 sink 继续持有内层直到上传与目标读取结束，所以该兜底清理可能较晚。

Quinn 已有 `vendor/quinn-proto/src/connection/streams/state.rs:1945–2026` 回归覆盖发送窗口满和连接 MAX_DATA 耗尽时仍须报告 Stopped，以及 owner reset 后的预算恢复。这个回归说明了库调用者的清理责任；不能直接用它宣称真实 FTPS 已出现同连接死锁，正常 ACK 也可能释放一部分数据。

本轮追加了直接协议回归 `observed_reverse_stop_is_reset_before_upload_fin`：客户端上传一个字节后保持发送方向打开，取消接收，再让目标发送响应，迫使 HY2 的 `poll_write` 观察 Stopped。仅有 sink 时，2 秒内客户端的 `frame_rx.reset_stream` 不增加，测试失败；加上收尾后，在发送上传 FIN 之前已收到 RESET，且剩余上传仍完整送达目标。这个用例不依赖构造大流量死锁，也没有只等待文件结束后再检查清理。

最小收尾位于 `shoes-plus/src/quic_stream.rs:24–59`：新增默认关闭的 opt-in；开启时若 `poll_write` 返回 `Stopped(code)`，先 `send_stream.reset(code)`，再返回原 Stopped 供外层 sink 消化。仅 `hysteria2_server.rs:2074` 开启该选项。reset 的重复关闭错误不替代原错误；接收半边、计量行为及其他 QUIC 协议保持原样。

此处及时归还的是 **本地未确认发送预算并排入 RESET**；流状态和相关存储通常还需 RESET 被确认，远端连接流控信用也要等待对端通告，不能声称所有资源瞬时释放。与 quic-go 的另一差异仍应明确：这是“应用写观察到 Stopped 时”清理，不是收到任何 STOP 帧时立即运行后台监听；没有后续 response write 的情况沿用原有 Drop/连接生命周期路径。本轮没有为此扩展底层协议状态机。

另一个寿命边界是目标接到上传 FIN 后仍永不结束响应：复制器会继续等待该目标 EOF，直到物理连接/用户生命周期取消。原正常双向复制及旧 PeerStopped drain 已有这个等待语义。本轮没有为此增加任意短超时，以免把较慢的合法上传再次截断。

## 6. 值得固定的回归契约

| 契约 | 本轮覆盖 / 后续验收 |
| --- | --- |
| 成功响应之前/之后的反向 STOP 都不能丢弃已收到的合法上传 | `ftp_upload.rs` 与 `ftp_upload_late_stop.rs`：完整长度、SHA、目标 EOF；包含 gated outbound 和晚到反向数据 |
| 纯 FIN、STOP+FIN 与 STOP+反向数据必须分开验证 | 新测试的两个控制与原失败场景分别运行，避免将所有半关闭等同于故障 |
| 写成功或 QUIC ACK 不等于目标文件完整 | 目标实际读到的字节数、SHA、EOF 为断言；真实 FTP/FTPS 另核对服务端文件与重新下载 |
| 最后一批数据与 EOF 同次到达不能丢数据 | 客户端 Reader/TLS 测试需覆盖 `n > 0` 的真正 EOF；reset/截断/超时仍须失败 |
| 恢复后物理连接可复用 | 原失败场景完成后释放旧流，再在同一 QUIC 连接新建流并完成 `who`；当前已通过 |
| 已观察到的 STOP 必须回收相应发送状态，不能等待另一方向全部结束才验证 | 新增协议回归在上传保持打开时检查 RESET 已抵达，再完成剩余上传；既有 Quinn 单元测试覆盖窗口耗尽下的 Stopped 与 reset 预算恢复 |
| drain 不能引入无限缓存或忽略真正失败 | 保持固定缓冲、独立调度和生命周期取消；已有单元测试覆盖其他 WriteError 与上传 RESET |

此后修改 HY2、Quinn、流量计量包装或测试客户端错误包装时，应围绕上述契约回归；无需为所有协议复制一套新的传输实现。


---
## 附件三：最终核心补丁（完整）
```diff

diff --git a/src/hysteria2_server.rs b/src/hysteria2_server.rs
index d688a7c..4bf8fd4 100644
--- a/src/hysteria2_server.rs
+++ b/src/hysteria2_server.rs
@@ -6,6 +6,7 @@ use std::num::NonZeroUsize;
 use std::pin::Pin;
 use std::str;
 use std::sync::{Arc, Mutex};
+use std::task::{Context, Poll};
 use std::time::Duration;
 
 use bytes::{Bytes, BytesMut};
@@ -14,7 +15,7 @@ use log::{debug, warn};
 use rand::distr::Alphanumeric;
 use rand::{Rng, RngExt};
 use rustc_hash::FxHashMap;
-use tokio::io::{AsyncWriteExt, ReadBuf};
+use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
 use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
 use tokio::task::JoinHandle;
 use tokio::time::{Instant, timeout, timeout_at};
@@ -125,7 +126,7 @@ const MAX_UDP_QUEUED_BYTES_PER_CONNECTION: usize = 16 * 1024 * 1024;
 const CLOSE_ERR_CODE_OK: u32 = 0x100; // HTTP3 ErrCodeNoError
 
 use crate::address::NetLocation;
-use crate::async_stream::{AsyncMessageStream, AsyncStream};
+use crate::async_stream::{AsyncMessageStream, AsyncPing, AsyncStream};
 use crate::client_proxy_selector::{ClientProxySelector, ConnectDecision};
 use crate::copy_bidirectional::copy_bidirectional_with_sizes;
 use crate::dynamic::{
@@ -1917,6 +1918,90 @@ enum TcpResponseWrite {
     PeerStopped,
 }
 
+/// After successful outbound setup, cancellation of the HY2 response direction
+/// must not cancel the independent upload. Keep draining the target into a sink
+/// after STOP_SENDING so dropping a socket with unread data cannot reset it.
+///
+/// This wrapper sits outside TrafficMeterStream: discarded responses are never
+/// handed to QUIC or charged as transmitted bytes. Upload reads still use the
+/// original metered stream, and the ordinary bounded relay provides scheduling.
+struct Hysteria2ResponseStream<S> {
+    inner: S,
+    peer_stopped: bool,
+}
+
+impl<S: AsyncRead + Unpin> AsyncRead for Hysteria2ResponseStream<S> {
+    fn poll_read(
+        self: Pin<&mut Self>,
+        cx: &mut Context<'_>,
+        buf: &mut ReadBuf<'_>,
+    ) -> Poll<std::io::Result<()>> {
+        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
+    }
+}
+
+impl<S: AsyncWrite + Unpin> AsyncWrite for Hysteria2ResponseStream<S> {
+    fn poll_write(
+        self: Pin<&mut Self>,
+        cx: &mut Context<'_>,
+        buf: &[u8],
+    ) -> Poll<std::io::Result<usize>> {
+        let this = self.get_mut();
+        if this.peer_stopped {
+            return Poll::Ready(Ok(buf.len()));
+        }
+        match Pin::new(&mut this.inner).poll_write(cx, buf) {
+            Poll::Ready(Err(error))
+                if matches!(
+                    error
+                        .get_ref()
+                        .and_then(|cause| cause.downcast_ref::<quinn::WriteError>()),
+                    Some(quinn::WriteError::Stopped(_))
+                ) =>
+            {
+                this.peer_stopped = true;
+                Poll::Ready(Ok(buf.len()))
+            }
+            result => result,
+        }
+    }
+
+    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
+        let this = self.get_mut();
+        if this.peer_stopped {
+            Poll::Ready(Ok(()))
+        } else {
+            Pin::new(&mut this.inner).poll_flush(cx)
+        }
+    }
+
+    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
+        let this = self.get_mut();
+        if this.peer_stopped {
+            Poll::Ready(Ok(()))
+        } else {
+            Pin::new(&mut this.inner).poll_shutdown(cx)
+        }
+    }
+}
+
+impl<S: AsyncPing + Unpin> AsyncPing for Hysteria2ResponseStream<S> {
+    fn supports_ping(&self) -> bool {
+        !self.peer_stopped && self.inner.supports_ping()
+    }
+
+    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
+        let this = self.get_mut();
+        if this.peer_stopped {
+            Poll::Ready(Ok(false))
+        } else {
+            Pin::new(&mut this.inner).poll_write_ping(cx)
+        }
+    }
+}
+
+impl<S: AsyncStream> AsyncStream for Hysteria2ResponseStream<S> {}
+
 async fn write_tcp_response<W>(
     stream: &mut W,
     ok: bool,
@@ -1986,9 +2071,10 @@ async fn process_tcp_stream(
     // they are bytes the client put on the wire and had put back to it. Reading the
     // header through the wrapper is also what makes `handle_tcp_header` take one
     // stream instead of quinn's send and recv halves.
+    let quic_stream = QuicStream::from(send, recv).with_reset_on_send_stopped();
     let mut server_stream: Box<dyn AsyncStream> = match meter {
-        Some(meter) => Box::new(TrafficMeterStream::new(QuicStream::from(send, recv), meter)),
-        None => Box::new(QuicStream::from(send, recv)),
+        Some(meter) => Box::new(TrafficMeterStream::new(quic_stream, meter)),
+        None => Box::new(quic_stream),
     };
 
     let header = read_tcp_request_header_before_deadline(
@@ -2056,13 +2142,13 @@ async fn process_tcp_stream(
     // Match sing-box: a successful TCP response reports that routing, DNS and the
     // outbound dial have all completed, not merely that the request parsed.
     let response = write_tcp_response(&mut server_stream, true, "").await?;
-    let mut client_stream = if response == TcpResponseWrite::PeerStopped {
-        // The client no longer wants reverse traffic, including any bytes the
-        // outbound handshake already buffered. Retain the target for the upload.
-        client_setup.client_stream
-    } else {
-        apply_client_early_data(&mut server_stream, client_setup).await?
-    };
+    // STOP_SENDING may arrive during the status, buffered outbound early data,
+    // or any later response write. Preserve the upload across all three phases.
+    let mut server_stream: Box<dyn AsyncStream> = Box::new(Hysteria2ResponseStream {
+        inner: server_stream,
+        peer_stopped: response == TcpResponseWrite::PeerStopped,
+    });
+    let mut client_stream = apply_client_early_data(&mut server_stream, client_setup).await?;
 
     let client_requires_flush = if replay.is_empty() {
         false
@@ -2071,35 +2157,18 @@ async fn process_tcp_stream(
         true
     };
 
-    let copy_result = if response == TcpResponseWrite::PeerStopped {
-        // Discard reverse traffic after cancellation, but keep reading it: a
-        // target may write before reading the upload, and dropping a TCP socket
-        // with unread data can reset it while upload bytes are still in flight.
-        let (mut target_read, mut target_write) = tokio::io::split(&mut client_stream);
-        let upload = async {
-            if client_requires_flush {
-                target_write.flush().await?;
-            }
-            tokio::io::copy(&mut server_stream, &mut target_write).await?;
-            // The target needs FIN to finish the file and close its reply side.
-            target_write.shutdown().await
-        };
-        let mut discarded = tokio::io::sink();
-        let drain = tokio::io::copy(&mut target_read, &mut discarded);
-        tokio::try_join!(upload, drain).map(|_| ())
-    } else {
-        // Use 32KB buffers to match hysteria2/sing-box reference implementations
-        copy_bidirectional_with_sizes(
-            &mut server_stream,
-            &mut client_stream,
-            // no need to flush even though we wrote this response since it's QUIC
-            false,
-            client_requires_flush,
-            32768,
-            32768,
-        )
-        .await
-    };
+    // Both normal responses and discarded responses use the same bounded,
+    // cooperative relay. Each direction still waits for its own EOF and FIN.
+    let copy_result = copy_bidirectional_with_sizes(
+        &mut server_stream,
+        &mut client_stream,
+        // no need to flush even though we wrote this response since it's QUIC
+        false,
+        client_requires_flush,
+        32768,
+        32768,
+    )
+    .await;
 
     let (_, _) = futures::join!(server_stream.shutdown(), client_stream.shutdown());
 
@@ -2351,13 +2420,14 @@ pub async fn start_hysteria2_server(
 #[cfg(test)]
 mod tests {
     use super::{
-        MAX_ACTIVE_TCP_LOGICAL_FLOWS, MAX_FRAGMENT_CACHE_SIZE, MAX_TCP_RESPONSE_MESSAGE_LENGTH,
-        MAX_UDP_FRAGMENT_BYTES_PER_CONNECTION, MAX_UDP_PACKET_SIZE, MAX_UDP_TARGETS_PER_SESSION,
-        TCP_REQUEST_HEADER_TIMEOUT, TcpResponseWrite, UdpForwardCommand, UdpFragmentCache,
-        UdpResponseSendOutcome, UdpSession, UdpTargetEvent, UdpTargetPermit, UdpTargetWorker,
-        acquire_udp_target_permits, checked_response_fragment_count, checked_udp_packet_len,
-        cleanup_udp_sessions, connect_udp_target, decode_udp_address_length,
-        dispatch_udp_target_command, encode_tcp_response, read_tcp_request_header_before_deadline,
+        Hysteria2ResponseStream, MAX_ACTIVE_TCP_LOGICAL_FLOWS, MAX_FRAGMENT_CACHE_SIZE,
+        MAX_TCP_RESPONSE_MESSAGE_LENGTH, MAX_UDP_FRAGMENT_BYTES_PER_CONNECTION,
+        MAX_UDP_PACKET_SIZE, MAX_UDP_TARGETS_PER_SESSION, TCP_REQUEST_HEADER_TIMEOUT,
+        TcpResponseWrite, UdpForwardCommand, UdpFragmentCache, UdpResponseSendOutcome, UdpSession,
+        UdpTargetEvent, UdpTargetPermit, UdpTargetWorker, acquire_udp_target_permits,
+        checked_response_fragment_count, checked_udp_packet_len, cleanup_udp_sessions,
+        connect_udp_target, decode_udp_address_length, dispatch_udp_target_command,
+        encode_tcp_response, read_tcp_request_header_before_deadline,
         run_connected_udp_target_worker, send_udp_response_with, try_admit_tcp_logical_flow,
         try_reserve_payload_bytes, try_reserve_udp_target_worker, udp_response_send_allowed,
         valid_udp_fragment, write_tcp_fast_open_replay, write_tcp_response,
@@ -2388,7 +2458,7 @@ mod tests {
     use std::sync::{Arc, Mutex};
     use std::task::{Context, Poll};
     use std::time::Duration;
-    use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
+    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
     use tokio::sync::Semaphore;
     use tokio::time::{Instant, advance};
     use tokio_util::sync::CancellationToken;
@@ -3348,6 +3418,146 @@ mod tests {
         }
     }
 
+    struct ResponseStreamProbe {
+        upload: std::io::Cursor<Vec<u8>>,
+        accepted: Vec<u8>,
+        accepted_limit: usize,
+        write_error: quinn::WriteError,
+        read_error: Option<quinn::ReadError>,
+        write_polls: usize,
+    }
+
+    impl ResponseStreamProbe {
+        fn new(write_error: quinn::WriteError) -> Self {
+            Self {
+                upload: std::io::Cursor::new(b"complete upload".to_vec()),
+                accepted: Vec::new(),
+                accepted_limit: 0,
+                write_error,
+                read_error: None,
+                write_polls: 0,
+            }
+        }
+    }
+
+    impl AsyncRead for ResponseStreamProbe {
+        fn poll_read(
+            self: Pin<&mut Self>,
+            cx: &mut Context<'_>,
+            buf: &mut ReadBuf<'_>,
+        ) -> Poll<std::io::Result<()>> {
+            let this = self.get_mut();
+            if let Some(error) = &this.read_error {
+                return Poll::Ready(Err(error.clone().into()));
+            }
+            Pin::new(&mut this.upload).poll_read(cx, buf)
+        }
+    }
+
+    impl AsyncWrite for ResponseStreamProbe {
+        fn poll_write(
+            self: Pin<&mut Self>,
+            _cx: &mut Context<'_>,
+            buf: &[u8],
+        ) -> Poll<std::io::Result<usize>> {
+            let this = self.get_mut();
+            this.write_polls += 1;
+            let remaining = this.accepted_limit - this.accepted.len();
+            if remaining == 0 {
+                return Poll::Ready(Err(this.write_error.clone().into()));
+            }
+            let written = remaining.min(buf.len());
+            this.accepted.extend_from_slice(&buf[..written]);
+            Poll::Ready(Ok(written))
+        }
+
+        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
+            Poll::Ready(Ok(()))
+        }
+
+        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
+            Poll::Ready(Ok(()))
+        }
+    }
+
+    #[tokio::test]
+    async fn tcp_response_stream_preserves_upload_after_partial_reverse_write() {
+        for code in [0u32, 42] {
+            let mut inner = ResponseStreamProbe::new(quinn::WriteError::Stopped(code.into()));
+            inner.accepted_limit = 3;
+            let mut stream = Hysteria2ResponseStream {
+                inner,
+                peer_stopped: false,
+            };
+            stream.write_all(b"early data").await.unwrap();
+            stream.write_all(b"later response").await.unwrap();
+            stream.flush().await.unwrap();
+            stream.shutdown().await.unwrap();
+            assert_eq!(stream.inner.accepted, b"ear");
+            assert_eq!(stream.inner.write_polls, 2);
+            let mut upload = Vec::new();
+            stream.read_to_end(&mut upload).await.unwrap();
+            assert_eq!(upload, b"complete upload");
+        }
+    }
+
+    #[tokio::test]
+    async fn tcp_response_stream_skips_metered_writes_after_initial_stop() {
+        let mut stream = Hysteria2ResponseStream {
+            inner: ResponseStreamProbe::new(quinn::WriteError::Stopped(0u32.into())),
+            peer_stopped: true,
+        };
+        stream
+            .write_all(b"buffered outbound response")
+            .await
+            .unwrap();
+        assert_eq!(stream.inner.write_polls, 0);
+        assert!(stream.inner.accepted.is_empty());
+        let mut upload = Vec::new();
+        stream.read_to_end(&mut upload).await.unwrap();
+        assert_eq!(upload, b"complete upload");
+    }
+
+    #[tokio::test]
+    async fn tcp_response_stream_preserves_other_transport_errors() {
+        for error in [
+            quinn::WriteError::ConnectionLost(quinn::ConnectionError::TimedOut),
+            quinn::WriteError::ClosedStream,
+            quinn::WriteError::ZeroRttRejected,
+        ] {
+            let mut stream = Hysteria2ResponseStream {
+                inner: ResponseStreamProbe::new(error.clone()),
+                peer_stopped: false,
+            };
+            let failure = stream.write_all(b"response").await.unwrap_err();
+            assert_eq!(
+                failure
+                    .get_ref()
+                    .and_then(|cause| cause.downcast_ref::<quinn::WriteError>()),
+                Some(&error)
+            );
+            assert!(!stream.peer_stopped);
+        }
+    }
+
+    #[tokio::test]
+    async fn tcp_response_stream_does_not_mask_upload_reset() {
+        let mut inner = ResponseStreamProbe::new(quinn::WriteError::Stopped(0u32.into()));
+        inner.read_error = Some(quinn::ReadError::Reset(7u32.into()));
+        let mut stream = Hysteria2ResponseStream {
+            inner,
+            peer_stopped: false,
+        };
+        stream.write_all(b"discarded response").await.unwrap();
+        let error = stream.read(&mut [0; 16]).await.unwrap_err();
+        assert!(matches!(
+            error
+                .get_ref()
+                .and_then(|cause| cause.downcast_ref::<quinn::ReadError>()),
+            Some(quinn::ReadError::Reset(code)) if *code == 7u32.into()
+        ));
+    }
+
     #[tokio::test]
     async fn tcp_success_response_allows_a_cancelled_read_direction() {
         // STOP_SENDING cancels only the response direction, regardless of its
diff --git a/src/quic_stream.rs b/src/quic_stream.rs
index 7d20090..a72f1a9 100644
--- a/src/quic_stream.rs
+++ b/src/quic_stream.rs
@@ -9,6 +9,7 @@ use crate::async_stream::{AsyncPing, AsyncStream};
 pub struct QuicStream {
     send_stream: SendStream,
     recv_stream: RecvStream,
+    reset_on_send_stopped: bool,
 }
 
 impl QuicStream {
@@ -16,8 +17,16 @@ impl QuicStream {
         Self {
             send_stream,
             recv_stream,
+            reset_on_send_stopped: false,
         }
     }
+
+    /// Used by HY2 when the caller preserves the upload after a response STOP.
+    /// Reset the cancelled send half before keeping this stream alive to drain.
+    pub(crate) fn with_reset_on_send_stopped(mut self) -> Self {
+        self.reset_on_send_stopped = true;
+        self
+    }
 }
 
 impl AsyncRead for QuicStream {
@@ -38,9 +47,15 @@ impl AsyncWrite for QuicStream {
         buf: &[u8],
     ) -> Poll<std::io::Result<usize>> {
         let this = self.get_mut();
-        Pin::new(&mut this.send_stream)
-            .poll_write(cx, buf)
-            .map_err(|err| err.into())
+        let result = Pin::new(&mut this.send_stream).poll_write(cx, buf);
+        if this.reset_on_send_stopped
+            && let Poll::Ready(Err(quinn::WriteError::Stopped(code))) = &result
+        {
+            // Match SendStream's drop cleanup without dropping the independent
+            // receive half. Preserve Stopped for the HY2 response sink.
+            let _ = this.send_stream.reset(*code);
+        }
+        result.map_err(|err| err.into())
     }
 
     fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {


```

---
## 附件四：新增协议回归测试（完整）
文件：crates/shoes-engine/tests/ftp_upload_late_stop.rs
```rust

//! Regressions for STOP_SENDING after the Hysteria2 success response.
//!
//! The destination deliberately responds before consuming a queued upload. This
//! is a generic TCP half-close contract test, not a claim about FileZilla's wire
//! behavior. A peer cancelling its receive direction must not cancel its upload.

mod common;

use std::io;
use std::time::Duration;

use common::hysteria2::Hysteria2Client;
use common::*;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PASSWORD: &str = "late-stop-upload-password";
const PAYLOAD_SIZE: usize = 4 * 1024 * 1024 + 189;

async fn upload_after_response(stop_reading: bool, reverse_payload: bool) {
    tokio::time::timeout(Duration::from_secs(30), async {
        let engine = engine().await;
        let server = free_addr();
        let mut config = hysteria2_inbound_with_bandwidth(server, 0, 0, false);
        config["protocol"]["ignore_client_bandwidth"] = serde_json::json!(true);
        engine
            .add_inbound(dynamic("late-stop-upload", config))
            .await
            .expect("start Hysteria2 inbound");
        engine
            .add_user("late-stop-upload", password_user("alice", PASSWORD))
            .expect("add upload user");

        let socket = tokio::net::TcpSocket::new_v4().expect("create target socket");
        socket.set_recv_buffer_size(16 * 1024).unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = socket.listen(1).unwrap();
        let target = listener.local_addr().unwrap();
        let (release_target, target_gate) = tokio::sync::oneshot::channel();
        let destination = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            target_gate.await.map_err(io::Error::other)?;
            if reverse_payload {
                stream.write_all(b"late target response\r\n").await?;
            }
            // A FIN only closes the target's write direction; it keeps accepting
            // the upload. A late payload additionally exercises QUIC poll_write.
            stream.shutdown().await?;
            let mut received = Vec::new();
            let mut chunk = [0; 16 * 1024];
            let error = loop {
                match stream.read(&mut chunk).await {
                    Ok(0) => break None,
                    Ok(n) => {
                        received.extend_from_slice(&chunk[..n]);
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                    Err(error) => break Some(error.to_string()),
                }
            };
            Ok::<_, io::Error>((received, error))
        });

        let client = Hysteria2Client::connect_with_rates_bps(server, PASSWORD, 0, 0)
            .await
            .expect("authenticate upload client");
        // Waiting for the response guarantees the initial response was Sent,
        // excluding the separate PeerStopped-during-outbound-setup branch.
        let mut stream = client.open_tcp(target).await.expect("read TCP success");
        let payload: Vec<u8> = (0..PAYLOAD_SIZE)
            .map(|offset| ((offset * 31 + offset / 188) % 251) as u8)
            .collect();
        stream.send.write_all(&payload).await.expect("enqueue upload");
        stream.send.finish().expect("finish upload direction");
        assert_eq!(
            stream.send.stopped().await.expect("acknowledge upload"),
            None,
            "all upload bytes and FIN should reach the proxy before the target reads"
        );
        if stop_reading {
            stream.recv.stop(0u32.into()).expect("cancel reverse direction");
            // Allow the local STOP_SENDING to arrive before the target is allowed
            // to write. The target gate makes the slow-read backlog deterministic.
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        release_target.send(()).expect("release target");
        let (received, error) = destination.await.unwrap().unwrap();
        eprintln!(
            "late-stop upload: stop={stop_reading}, reverse_payload={reverse_payload}, expected={}, received={}, error={error:?}",
            payload.len(),
            received.len()
        );
        assert_eq!(received.len(), payload.len(), "target upload is truncated");
        assert_eq!(Sha256::digest(&received), Sha256::digest(&payload));
        assert!(error.is_none(), "target must observe clean EOF: {error:?}");
        // Keep the physical QUIC connection and handles alive until target EOF.
        drop(stream);
        if stop_reading && reverse_payload {
            let probe = Sink::start("late-stop-connection-alive").await;
            let mut next_stream = client
                .open_tcp(probe.address)
                .await
                .expect("late STOP must leave the same QUIC connection usable");
            next_stream.write_all(b"who\n").await.unwrap();
            assert_eq!(next_stream.read_line().await.unwrap(), probe.name);
        }
        drop(client);
    })
    .await
    .expect("late reverse cancellation scenario must finish");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_survives_late_reverse_stop_and_target_fin() {
    upload_after_response(true, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_survives_target_reverse_payload_without_stop() {
    upload_after_response(false, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upload_survives_late_reverse_stop_and_target_payload() {
    upload_after_response(true, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn observed_reverse_stop_is_reset_before_upload_fin() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let engine = engine().await;
        let server = free_addr();
        engine
            .add_inbound(dynamic("reset-upload", hysteria2_inbound(server, false)))
            .await
            .unwrap();
        engine
            .add_user("reset-upload", password_user("alice", PASSWORD))
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (prefix_received, ready) = tokio::sync::oneshot::channel();
        let (release_target, target_gate) = tokio::sync::oneshot::channel();
        let destination = tokio::spawn(async move {
            let (mut target, _) = listener.accept().await.unwrap();
            let mut prefix = [0; 1];
            target.read_exact(&mut prefix).await.unwrap();
            assert_eq!(prefix, [b'a']);
            prefix_received.send(()).unwrap();
            target_gate.await.unwrap();
            // Force the proxy to observe Stopped in poll_write, while the upload
            // direction stays open. Merely receiving STOP is a different case.
            target.write_all(b"cancelled response").await.unwrap();
            target.shutdown().await.unwrap();
            let mut tail = Vec::new();
            target.read_to_end(&mut tail).await.unwrap();
            tail
        });
        let client = Hysteria2Client::connect_with_rates_bps(server, PASSWORD, 0, 0)
            .await
            .unwrap();
        let mut stream = client.open_tcp(address).await.unwrap();
        stream.write_all(b"a").await.unwrap();
        ready.await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let resets_before = client.stats().frame_rx.reset_stream;
        stream.recv.stop(42u32.into()).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        release_target.send(()).unwrap();
        let reset_arrived = tokio::time::timeout(Duration::from_secs(2), async {
            while client.stats().frame_rx.reset_stream == resets_before {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(
            reset_arrived.is_ok(),
            "an observed STOP must send RESET_STREAM before the upload ends"
        );
        // Resetting the server's response must leave the opposite direction usable.
        stream.write_all(b"remaining upload").await.unwrap();
        stream.send.finish().unwrap();
        assert_eq!(destination.await.unwrap(), b"remaining upload");
        drop(stream);
        drop(client);
    })
    .await
    .expect("the half-close reset scenario must finish");
}


```