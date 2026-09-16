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

FTPS 使用 AUTH TLS、PBSZ 0、PROT P，数据采用 TYPE I。

主矩阵的 FTPS 上传数据连接采用 `graceful` 关闭：先发送 TLS 关闭通知，再读取反向至
EOF，最后关闭底层 HY2 流。因此正常完成路径上的反向 STOP 出现在反向 EOF 之后，
主动避开了本次“反向尚未结束就取消接收”的触发时序。下列矩阵验证正常传输完整性，
不能验证这个故障分支；其修复前后差异由独立的 Rust 确定性回归提供。

每次传输要求：

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

## Linux FileZilla 真实客户端复验

在上述最终二进制上又运行了 Debian 12 官方 FileZilla Client 3.63.0。FileZilla 本身
运行于 1280×800 Xvfb，使用显式 FTPS 和二进制模式；它的 SOCKS5 控制连接及所有
EPSV 数据连接由受限测试适配器映射为同一条 `sing-quic` HY2 会话上的逻辑流。详细
拓扑和复现命令见 [FileZilla Docker harness](../tests/docker/hy2-filezilla/README.md)。

| 阶段 | 结果 |
| --- | ---: |
| FileZilla 直连 FTPS、单路对照 | 2/2 |
| FileZilla 经 HY2、单路依次上传 | 10/10 |
| FileZilla 经 HY2、四路并发上传 | 12/12 |
| FileZilla 经 HY2、四路大文件上传 | 4/4 |
| FileZilla 经 HY2、慢服务端大文件上传 | 2/2 |

合计 30 个 TS、229,549,128 B，其中 28 个经 HY2。FileZilla 报告 30 次成功；FTPS
服务端记录 30 次完成、0 次 incomplete，逐文件大小及 SHA-256 全部匹配。HY2
适配器记录 40 条已关闭的数据流，包括上传和目录列表，数据流错误为 0。五个阶段
各抽取一个目标 TS，加上两个源样本，FFmpeg 严格解码均无输出错误。

客户端保持物理 HY2 会话时，遥测为 active/online `1/1`，这与 FileZilla 已完成的
逻辑上传数无关。关闭适配器后，它记录 `stopping` 和 `stopped`，遥测回到 `0/0`，
daemon FD 从测试中的 16 回到起始的 13，UDP drops 保持 0。daemon RSS 为
42,088 KiB → 86,052 KiB → 80,852 KiB；一次有界运行不能据此判断长期内存趋势。

最终证据位于 `run/hy2-filezilla-20260916-211658-476545/`，`result.json` 记录成功
结果，`filezilla-debug.log` 保存 FileZilla 控制协议及每次传输状态，服务端事件、
SOCKS 流事件、截图、目标文件和三个时点的进程/网络快照均保留。被测 node-agent
SHA-256 与上述最终二进制一致。

这个结果把“真实 FileZilla 是否能通过修复后的 HY2 完整并发上传”从推断变为本地
实测，但仍不能代表用户现场未知版本的 Windows FileZilla，也不能替代实际 HY2
客户端、生产 FTPS 服务、公网时序及故障文件对。

## 测试客户端校准与独立截断对照

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

直连截断也应作为现场排查的竞争假设保留：它证明本测试环境中，即使没有代理，也
可能出现“目标文件更短且 FTP 返回 226”。它既不能证明 node-agent 导致这次直连故障，
也不能证明未知版本的 FileZilla 使用同样的关闭时序。需用真实客户端对照区分这两类原因。

这两种关闭方式不能直接代表未知版本 FileZilla 的具体实现。TLS 关闭通知与底层
连接可靠交付是不同层次；参见 [TLS 1.3 关闭语义](https://www.rfc-editor.org/rfc/rfc8446#section-6.1)。

## 对现场的解释边界

FTPS 存在 TLS 反向消息，使已证实的 HY2 分支比普通单向 FTP 更值得怀疑。本次已
操作 Linux FileZilla 3.63.0，但没有用户现场的 Windows FileZilla、实际 HY2 客户端
和故障日志，仍不能把核心回归等同于用户实际故障的完整复现。用户确认完成上传后
才播放，故不把上传途中读取当作既定原因。

等大小不能证明内容一致。下一次出现问题，保留对应源/目标 TS 的 SHA-256、
FileZilla 最后一次 STOR 的控制日志，以及客户端和 node-agent 版本。如果大小和
SHA 都相同，应转向 TS 时间戳/分片衔接、播放网络及缓存路径；如果变短，则继续
对照关闭/重置和传输完成时序。FileZilla 的二进制模式不会做文本换行转换，参见
[官方传输类型说明](https://filezillapro.com/docs/v3/advanced/file-type-classifications-for-ftp-and-ftps/)。

本机原始证据根目录：`run/hy2-ftp-20260916-190232/`。`late-stop-before.log` 和
`regressions-after.log` 保存 Docker 核心前后对照；`build-baseline.log` 保存原始
release 构建。所有结果只说明对应二进制、客户端和有界流量下的行为。
