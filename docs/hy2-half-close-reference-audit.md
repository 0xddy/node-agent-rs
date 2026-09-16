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

本仓库使用的 vendored Quinn 包含 `shoes-plus` 提交 `fd758ead3fd63d0a732163ff50d30949996c6c68`（`fix(quic): report stopped writers before flow-control waits`）：在流控阻塞判断之前报告 Stopped。相应的 `vendor/quinn-proto/src/connection/streams/state.rs:1945–2026` 回归覆盖发送窗口满和连接 MAX_DATA 耗尽时仍须报告 Stopped，以及 owner reset 后的预算恢复。这是本仓库保留的改动与回归，不应泛称上游 Quinn 原有行为，升级依赖时必须核对。这些回归说明了库调用者的清理责任；不能直接用它们宣称真实 FTPS 已出现同连接死锁，正常 ACK 也可能释放一部分数据。

本轮追加了直接协议回归 `observed_reverse_stop_is_reset_before_upload_fin`：客户端上传一个字节后保持发送方向打开，取消接收，再让目标发送响应，迫使 HY2 的 `poll_write` 观察 Stopped。仅有 sink 时，2 秒内客户端的 `frame_rx.reset_stream` 不增加，测试失败；加上收尾后，在发送上传 FIN 之前已收到 RESET，且剩余上传仍完整送达目标。这个用例不依赖构造大流量死锁，也没有只等待文件结束后再检查清理。

最小收尾位于 `shoes-plus/src/quic_stream.rs:24–59`：新增默认关闭的 opt-in；开启时若 `poll_write` 返回 `Stopped(code)`，先 `send_stream.reset(code)`，再返回原 Stopped 供外层 sink 消化。仅 `hysteria2_server.rs:2074` 开启该选项。reset 的重复关闭错误不替代原错误；接收半边、计量行为及其他 QUIC 协议保持原样。

此处及时归还的是 **本地未确认发送预算并排入 RESET**；流状态和相关存储通常还需 RESET 被确认，远端连接流控信用也要等待对端通告，不能声称所有资源瞬时释放。与 quic-go 的另一差异仍应明确：这是“应用写观察到 Stopped 时”清理，不是收到任何 STOP 帧时立即运行后台监听；没有后续 response write 的情况沿用原有 Drop/连接生命周期路径。本轮没有为此扩展底层协议状态机。

另一个寿命边界是上传方向已完成本地写入和 shutdown，但目标仍永不结束响应：复制器会继续等待目标 EOF，直到物理连接/用户生命周期取消。原正常双向复制及旧 PeerStopped drain 已有这个等待语义。持续丢弃响应存在目标侧网络和 CPU 消耗风险，值得另行设计分阶段的排空预算；不能把保全上传理解为允许任何阶段无限排空。本轮尚未实现这种预算。本地上传方向 Done 也不等于目标应用已完整读取或落盘，因此预算触发后的关闭方式必须通过慢目标回归验证，避免重新造成截断。

## 6. 值得固定的回归契约

| 契约 | 本轮覆盖 / 后续验收 |
| --- | --- |
| 成功响应之前/之后的反向 STOP 都不能丢弃已收到的合法上传 | `ftp_upload.rs` 与 `ftp_upload_late_stop.rs`：完整长度、SHA、目标 EOF；包含 gated outbound 和晚到反向数据 |
| 纯 FIN、STOP+FIN 与 STOP+反向数据必须分开验证 | 新测试的两个控制与原失败场景分别运行，避免将所有半关闭等同于故障 |
| 写成功或 QUIC ACK 不等于目标文件完整 | 目标实际读到的字节数、SHA、EOF 为断言；真实 FTP/FTPS 另核对服务端文件与重新下载 |
| 最后一批数据与 EOF 同次到达不能丢数据 | 客户端 Reader/TLS 测试需覆盖 `n > 0` 的真正 EOF；reset/截断/超时仍须失败 |
| 恢复后物理连接可复用 | 原失败场景完成后释放旧流，再在同一 QUIC 连接新建流并完成 `who`；当前已通过 |
| 写操作观察到 Stopped 时必须回收相应发送状态，不能等待另一方向全部结束才验证 | 新增协议回归在上传保持打开时检查 RESET 已抵达，再完成剩余上传；本仓库 vendored Quinn 的回归覆盖窗口耗尽下的 Stopped 与 reset 预算恢复；没有后续写的情况仍沿用 Drop/连接生命周期 |
| drain 不能引入无限缓存或忽略真正失败 | 保持固定缓冲、独立调度和生命周期取消；已有单元测试覆盖其他 WriteError 与上传 RESET |

此后修改 HY2、Quinn、流量计量包装或测试客户端错误包装时，应围绕上述契约回归；无需为所有协议复制一套新的传输实现。
