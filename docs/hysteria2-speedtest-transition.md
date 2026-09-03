# HY2：下载结束后立即上传的连接停顿排查

审查日期：2026-09-03。用户反馈上一版已经可以上传 2 GB 文件，但 Speedtest 仍可能令客户端失去网络，随后补充触发时点似乎是“下载测试完成，上传刚开始”。因此本轮检查的是同一 QUIC 连接双向切换时的 ACK、拥塞窗口与发送节奏。

## 已确认并修正的代码缺陷

### 1. 发送受限时，到期 ACK 被待发送数据一起堵住

`shoes-plus/vendor/quinn-proto/src/connection/mod.rs` 的 `poll_transmit` 根据待发送 STREAM、MAX_DATA 等帧将整个 packet space 判为需要拥塞控制。拥塞窗口不足或 pacer 暂不允许发送时，旧实现跳过整个空间，即使反向流量的 ACK 已经到期。

这会造成一个方向的发送阻塞拖延另一个方向的确认。客户端刚从下载转为上传时，服务端可能仍有尾部下载数据和流控更新待发送，因此这是与本次现象相关的候选原因；尚没有现场日志或抓包证明它就是该次断网的根因。

修复在这两种阻塞路径中单独发送到期 ACK，继续保留 STREAM、FIN、MAX_DATA 及 pacing 唤醒。四个内存协议测试覆盖拥塞窗口/pacer，以及 MTU padding 开/关：旧代码基础两项都失败；修复后四项全部通过。测试解密检查实际帧，确认业务数据没有跟随 ACK 绕过拥塞控制，并在释放原有下载报文后验证完整 1 MiB、FIN 和挂起的 MAX_DATA 都能正常完成。

这对应成熟实现中的明确控制：[quic-go v0.61.0 的发送器](https://github.com/quic-go/quic-go/blob/v0.61.0/connection.go) 在 `SendAck` 和 `SendPacingLimited` 分支调用 `maybeSendAckOnlyPacket`；本机固定的 SagerNet `v0.61.0-sing-box-mod.7` 也保留此行为。[RFC 9002 §7 与 §7.7](https://www.rfc-editor.org/rfc/rfc9002.html#section-7)区分确认报文与受拥塞控制的数据，并建议只含 ACK 的包避免 pacing 延迟。原有 anti-amplification、Initial 最小报文规则及可选 padding 记账保持不变。

### 2. BBR STARTUP 窗口增长和带宽样本过滤错误

固定的 `quinn-proto 0.11.17` 还有两处错误：STARTUP 将无量纲的窗口增益与字节数目标比较，窗口可能随累计确认字节持续增长；带宽过滤器只接受比历史峰值更高的非 application-limited 样本，不能正常过期旧峰值，也拒绝了本应提高估计的 application-limited 样本。

本轮采用 [Quinn PR #2798](https://github.com/quinn-rs/quinn/pull/2798) 提出的两处修正，参考提交 `fd3881f93ede58f4a4daf524cf39e1dc1ac9364b`。该 PR 在审查时仍未合并，vendor 的 `PATCH.md` 已明确记录这一点。

四个新增确定性用例覆盖两类 application-limited STARTUP、旧带宽峰值过期、正常高带宽启动。旧代码三项失败：窗口随约 20 MB 确认流量增长至约 20 MB，或实际速率降低多个采样轮次后仍保留旧峰值；修正后四项全部通过。这里修的是有独立证据的计算错误，并未替换整个 BBR，也不能据此认定所有 WAN 停顿都已解决。

## 验证方式与边界

`crates/shoes-engine/tests/hysteria2_download.rs` 使用真实本地 TCP/HY2 连接，在同一 QUIC 连接上完成四路共 512 MiB 下载，紧接着四路共 128 MiB 上传。每路用 64 KiB 缓冲逐块核对数据，检查最终 EOF；上传还要收到目标服务的确认字节。Rust 用例覆盖 BBR 和 Brutal，两阶段还检查同一连接的新流与另一用户的新连接，最后再次检查原连接存活。

`tests/interop/sing-quic-switch` 是固定官方 sing-quic `v0.7.0-beta.4` 的 Go 客户端，执行相同下载/上传切换，并核对 `bounded-peer` 探针响应。它拒绝第二次建立底层 UDP 连接，防止 SDK 自动重连把失败隐藏成成功。测试仅允许数值 loopback 地址，TLS 跳过校验仅用于本地测试证书。

本机 Windows 验证：Rust BBR、Rust Brutal 和官方 Go 客户端三个切换用例全部通过。Go 用例下载耗时约 5.38 秒，上传约 1.56 秒，最后返回 `probe=bounded-peer`；耗时仅是本机观测。完整 vendor 协议测试 286 项通过。

```powershell
# 在 tests/interop/sing-quic-switch 中编译；可执行文件放到临时目录
go build -mod=readonly -o "$env:TEMP/sing-quic-switch.exe" .
# 回到 node-agent-rs 根目录，运行 Rust 两模式以及外部 Go 客户端
$env:EXTERNAL_HY2_CLIENT = "$env:TEMP/sing-quic-switch.exe"
cargo test --locked -p shoes-engine --test hysteria2_download -- --include-ignored --nocapture
# 在 shoes-plus 根目录运行整个 vendor 协议测试；两仓库 CI 也执行此项
cargo test --manifest-path vendor/quinn-proto/Cargo.toml --locked --lib
```

这些测试验证正确性、有限时内完成与连接继续可用，不代表真实公网 Speedtest 已复现或已经完全修复，也不证明全程没有延迟尖峰。需要用新构建复测现场；若仍异常，最有用的信息是客户端/内核版本、断网时刻，以及服务端 `Hysteria2 authenticated connection ended abnormally` 或 `I/O error` 前后的日志。

另外只读审查发现，Quinn 连接驱动遇到 socket 发送错误时，有退出驱动但未统一唤醒挂起流的路径。本轮没有对应现场日志，未把它混入已确认的修复。此前[资源控制对标](hy2-core-resource-audit.md)记录的跨连接预算等问题也仍独立存在。
