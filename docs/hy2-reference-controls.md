# HY2 资源控制参考审计：sing-box、quic-go 与 Xray

审计日期：2026-09-03。本文是固定版本的源码审计，不是压力测试结果，也不代表这些项目所有协议、平台和部署配置。目标是回答：客户端不遵守带宽协商、持续大量发送 UDP、制造连接或逻辑流时，哪些约束由服务端真正执行，哪些资源仍然可能随客户端数量增长。

## 1. 版本与比较边界

| 源码 | 本文固定版本 | 角色与复核来源 |
| --- | --- | --- |
| SagerNet/sing-box | `v1.14.0` | HY2 入站参数、TLS 超时、路由复制；[入站代码][sb-inbound]、[复制代码][sb-copy] |
| SagerNet/sing-quic | `v0.7.0-beta.4` | HY2 认证、拥塞协商、TCP 请求和 UDP 关联；[服务代码][sq-service] |
| SagerNet/quic-go | `v0.61.0-sing-box-mod.7` | 实际 QUIC 传输层；[参数定义][q-params]、[连接实现][q-conn] |
| SagerNet/sing | `v0.9.0-beta.4` | 复制、缓存、UDP 超时包装；[复制实现][sing-copy]、[LRU 实现][sing-lru] |
| XTLS/Xray-core | `5ca6f4b7d4dc20a881d4330e498892697627ec0c` | 本机模块版本 `v1.260327.1-0.20260728075948-5ca6f4b7d4dc`；比较 UDP Hub、代理管道、普通 TCP 入站、VLESS/Trojan 和 Mux 的执行路径 |
| 本地 sing-box-acp | `e7ba3f961942ccf63e7173009498b16308eb93fc` | 本机 Go node-agent 的对照分支；其[根 go.mod][acp-mod]固定 quic-go mod.7、sing beta.4，并替换内嵌 sing-quic。与官方认证发布顺序的差异见第 2 节；未核实线上实际二进制版本 |
| 本地 Go node-agent | `08a578a1267e2e4defd4bdb8ffc0d06e549ccf29` | 本机可获得的用户级限速包装，不属于官方 sing-box 默认保护；[tracker.go][node-tracker] |

本地源码来自 Go 模块缓存和上述干净 Git 工作树。官方标签文件与 GitHub 原始文件经本地 `10886` HTTP 代理抽查一致。这里使用 quic-go **mod.7**：sing-quic 自身 `go.mod` 的较低版本不能取代 sing-box 根模块实际选中的版本。

Xray 的 TCP 管道和生命周期管理可以作为设计参考；本文没有把 Xray 的 TCP 接收窗口、TCP 内核调度或某个 Mux 参数当作 HY2/QUIC 的等价实现，也没有据此断言 Xray 的所有传输都具备同一套防护。

## 2. `0/0`、`auto` 与协商不一致时到底执行什么

为避免服务端、客户端的 up/down 命名混淆，下文定义 `S = 服务端 SendBPS`、`R = 服务端 ReceiveBPS`、`C = 客户端认证请求中声明的 Rx`。官方 sing-box `protocol/hysteria2/inbound.go:183-184` 的参数映射是 `SendBPS ← UpMbps`、`ReceiveBPS ← DownMbps`；`C` 描述客户端声明的接收能力，不是服务端测量到的上传速率。[参数映射][sb-inbound]、[协议字段][sq-http]

下面是 sing-quic `hysteria2/service.go:282-313` **首次认证**的实际分支。假定密码有效，除表中拒绝分支外，不存在这一层独立的入站 token bucket。

| 条件 | 服务端发送控制 | 给客户端的接收带宽响应 | 对恶意上传者的实际约束 |
| --- | --- | --- | --- |
| `R=0` 且 `ignore_client_bandwidth=true`，包括 `S=R=0` | BBR | `auto` | 没有入站 Mbps 强制上限；仍受 QUIC 收流窗口、收包队列和协议校验约束 |
| 不满足上一行，且 `C>0` | Brutal；目标值为 `C`，若 `S>0` 则取 `min(C,S)` | 数字 `R`，可能为 `0` | 约束的是服务端的发送控制；对客户端上传是协商信息，不能证明其遵守 |
| `R>0`、`ignore_client_bandwidth=true`、`C=0` | 进入拒绝分支 | masquerade 响应，正常客户端认证失败 | 这是声明的兼容性检查，不是按实际入站流量执法；该官方版本还有下述认证状态顺序问题 |
| 其余 `C=0` 情况 | BBR | `auto` | 同样没有这一层入站速率执法 |

证据为 [service.go:282-313][sq-negotiation]。因此，“`0/0` 必然使 Brutal 按无限速率运行”与此版本的代码不符。另一方面，“改成 BBR/auto 就能约束恶意发送者”也不成立。

客户端 `client.go:583-593` 从响应取 `actualTx`，若其为 `0` 或高于客户端配置的 `sendBPS` 就改用客户端配置；仅当非 `auto` 且最终值大于 `0` 时使用 Brutal，否则使用 BBR。特别是客户端 `sendBPS=0` 时，数字响应也不等于一个服务端强制的上传限速器。[客户端实现][sq-client]

Brutal 的 pacer 和拥塞窗口包含 `bps / ackRate`，允许按丢包补偿调整发送，不能把目标值当作严格的线上字节率上限。BBR 也只是本端发送控制；两个算法都无法阻止对端自己构造大量网络包。[Brutal:41-76][sq-brutal]

**固定版本的额外边界：**官方 `service.go:288-289` 在执行 `R>0 && ignore && C==0` 的拒绝判断前已经写入 `authUser` 和 `authenticated=true`，拒绝时仅返回 masquerade，没有回滚认证状态或关闭 QUIC。后续 `dispatchStream:332` 使用该标记。因此不能把该分支描述为可靠的会话撤销。此结论只针对持有有效密码的协商不匹配会话，不能据此声称任意无密码客户端可通过认证。本地 ACP 分支在 `401-419` 先完成该判断，再发布认证身份，已与官方快照不同。[官方顺序][sq-negotiation]、[ACP 顺序][acp-auth]

协议解析还会忽略 `strconv.ParseUint` 的错误：缺失或非数字的请求 Rx 会进入零值路径，数值溢出的返回语义则不同；不能把此字段当作经过真实性验证的流量测量值。[http.go:33-38][sq-http]

## 3. quic-go：UDP 到 QUIC 连接的强制控制

以下“连接”均指一个物理 QUIC 连接，其上可能承载很多浏览器请求、上传流和 UDP 关联。`STREAM` 流控字节与线上 UDP 包数是两种不同资源。

| 阶段 / 资源 | 真实限制与作用域 | 超限或结束行为 | 不能据此声称什么 | 源码证据 |
| --- | --- | --- | --- | --- |
| UDP socket 缓冲 | 希望内核收、发缓冲各为 8 MiB；作用域是 socket，设置结果还受操作系统约束 | 内核按自身策略处理拥塞/丢包 | 不是 Go 堆预算，不是 PPS 或整个进程内存限制 | `internal/protocol/params.go:5-9` [参数][q-params]；sing-quic `quic.go:78` [socket 设置][sq-quic] |
| 尚未路由到连接的服务端报文队列 | 每个 listener 的 `receivedPackets` 1024 项 | `handlePacket` 非阻塞入队，满时释放并丢弃包 | 不限制已创建握手数量；不限制内核收包/解析成本 | `server.go:266-274,395` [服务端队列][q-server] |
| 拒绝、Retry 和版本响应队列 | 版本响应 4、无效 token 4、连接拒绝 4、Retry 8；每 listener | 相应队列满则丢包，避免控制响应积压 | 不是新连接速率限制 | `server.go:271-274,861-868` [队列][q-server] |
| 提前到达的 0-RTT | 最多 32 个队列、每队列 31 包、等待 Initial 最长 100 ms；每 listener | 超出丢弃，过期清理 | 不是已创建连接的总数量配额 | `params.go:160-169` [定义][q-params]；`server.go:580-616` [执行][q-server] |
| 地址验证 / Retry | 可选 `VerifySourceAddress` 回调；也可选 `GetConfigForClient`、`ConnContext` 拒绝 | 要求 Retry 或在建立连接前拒绝 | sing-quic 默认创建的 `quic.Transport` 没有装上这些准入回调；不能把扩展点当默认防护 | `transport.go:110-131` [接口][q-transport]；`server.go:743,766-786` [执行][q-server]；`quic.go:266` [实际配置][sq-quic] |
| 反放大 | 地址未验证时，本连接服务端发送受已收字节 3 倍约束 | 发送受阻，验证后解除 | 这是防反射放大，不是入站丢包、CPU 或内存配额 | `sent_packet_handler.go:28,1189-1193` [实现][q-sent] |
| 握手期限 | quic-go 默认 idle 5 s、总期限 `2×idle`；标准 sing-box TLS 默认 15 s 传入后通常为 idle 15 s、总 30 s，可配置覆盖 | 超时终止该 QUIC 连接 | 有期限不等于并发握手数有限，也不是 HY2 应用认证的绝对期限 | `config.go:17-18,67-69` [计算][q-config]；`connection.go:706-712` [检查][q-conn]；`quic.go:152-163` [映射][sq-quic]；`std_server.go:491-500` [TLS 默认][sb-tls] |
| 等待应用 Accept 的连接 | `connQueue` 32 项；作用域每 listener | 握手完成/early ready 后尝试入队，满则以 `ConnectionRefused` 关闭该连接 | **不是 32 个并发握手上限**：新连接对象和 goroutine 在此前已创建；`handshakingCount` 是 WaitGroup | `server.go:817-857,871-898` [完整路径][q-server] |
| 已知连接的待处理网络包 | 每物理连接 256 项 | 队列满则丢包；其他连接的队列额度独立 | 不保证包被处理前没有成本；不能约束总连接数乘以每连接成本 | `connection.go:1985-2007` [入队][q-conn] |
| 连接事件循环 | 每轮最多处理 32 个接收包，然后让本连接 ACK、发送和计时器获得执行机会；循环前检查关闭信号 | 有余包时重新通知；关闭不需要排在普通接收包之后 | 这是明确的处理批次边界，不是所有用户的 CPU 时间公平保证，也不是每秒只处理 32 包 | `connection.go:616-625,1026-1074` [调度][q-conn] |
| 暂时无法解密的包 | 等待密钥的队列最多 32 项；每连接 | 多余丢弃；真正解密失败的包也丢弃 | 解密失败丢弃仍然花费 CPU；没有从此得到无效包 PPS 硬配额 | `params.go:18` [定义][q-params]；`connection.go:1451,3005` [执行][q-conn] |
| STREAM 接收信用 | HY2 默认每流 8 MiB、每连接 20 MiB；初始和最大窗口均如此，可配置覆盖；按 offset/已消费字节推进 | 超出已通告流/连接信用返回 `FLOW_CONTROL_ERROR`，终止该物理连接；正常消费才归还信用 | 不是累计文件大小上限，也不是固定 RSS 上限；不覆盖大量空流、重复包、控制帧和 DATAGRAM | `service.go:85-94` [HY2 配置][sq-service]；`hysteria/protocol.go:18-19` [值][sq-defaults]；`receive_stream.go:445-465` [先校验再组装][q-recv-stream]；[流级][q-flow-stream]、[连接级][q-flow-conn] |
| 流数量 | quic-go 默认 bidi/uni 各 100，但 HY2 把 bidi 改成 `1<<60`；仅显式配置正数 `MaxConcurrentStreams` 才覆盖 | 超过通告的 stream ID 限制返回 `STREAM_LIMIT_ERROR` | **HY2 默认值不是实用的流对象配额。**接收较高但合法的 ID 时，会逐个实例化中间流；字节窗口无法替代元数据配额 | `params.go:40-43` [默认][q-params]；`service.go:85` [覆盖][sq-service]；`quic.go:63-64` [可配置][sq-quic]；`streams_map_incoming.go:115-151` [检查及对象创建][q-stream-map] |
| STREAM 重排结构 | 每流最多 20000 个 gap；小 STREAM 数据另有 128 字节阈值的缓冲保留优化 | 过多 gap 返回错误，进入连接错误处理 | gap 限制不等于流总字节预算，更不等于允许无限流对象 | `frame_sorter.go:181` [检查][q-sorter]；`params.go:81-86` [定义][q-params] |
| CRYPTO 握手数据 | CRYPTO 最大 offset 16 KiB | `CRYPTO_BUFFER_EXCEEDED` 关闭该连接 | 不限制同时进行多少握手 | `crypto_stream.go:36-39` [执行][q-crypto] |
| 控制帧状态 | 待发送 `PATH_RESPONSE` 最多 256；一般待发送控制帧最多 16384；每连接 | 多余 PATH_RESPONSE 不入队；一般控制帧超限置位，连接循环以 `INTERNAL_ERROR` 终止该连接 | 不能保证恶意物理连接里的其他流继续工作；保护边界是物理连接 | `framer.go:16-17,66-85` [队列][q-framer]；`connection.go:616-619` [关闭][q-conn] |
| ACK / 已发包历史 | 本端接收历史最多 64 个 ACK range；已发包跟踪达到 40000/50000 时分别停止普通新发/停止发包 | 截断旧接收历史；发送模式收缩 | 64 是本端历史限制，不能描述成解析任意对端 ACK 的统一数量上限；发送历史限制也不是入站 PPS 限制 | `received_packet_history.go:41-42` [接收历史][q-ack-history]；`sent_packet_handler.go:1139-1169` [发送门槛][q-sent] |
| QUIC DATAGRAM 队列 | 每连接接收 128 项、发送 32 项 | 收满丢新 DATAGRAM；发满等待空间/关闭；关闭唤醒等待者 | DATAGRAM 没有 STREAM 接收流控，丢失不会由 QUIC 重传；接收路径在检查队列前先分配并复制，所以 retained queue 有界不等于分配速率有界 | `datagram_queue.go:13-14,46-63,93-136` [执行][q-datagram] |
| UDP 发送队列 | 每连接 8 个发送项 | 连接循环等可写通知，发送完成释放；关闭等待发送任务结束 | 不是共享 socket 的总字节或总发送任务配额 | `send_queue.go:35-43,70-110` [实现][q-send-queue] |

### 连接关闭与隔离的实际边界

`connection.go:579-592` 在退出时取消该连接 context，并排空未处理网络包、归还引用；`2291-2294` 关闭该连接所有 STREAM 和 DATAGRAM 等待者，后续关闭连接 ID 管理。`flow_controller_stream.go:112-118` 的 `Abandon` 将未读信用归还到连接层，防止废弃流永久占据连接接收信用。[连接关闭][q-conn]、[废弃流信用][q-flow-stream]

这说明普通 QUIC 协议错误应局限到一个物理连接。它**不等于每条代理流完全独立**：该物理连接一旦关闭，其上的上传、下载和网页都会受影响，进程仍可存活。另一方面，共享 `Transport` 的底层 UDP socket 遭遇不可恢复读错误时，`transport.go:539-562` 调用 `t.close`，`508-532` 遍历关闭其连接，这是另一种更大的故障范围。[Transport 生命周期][q-transport]

队列满时丢弃网络包使正常的可靠 STREAM 依靠 QUIC 丢包恢复继续推进；混在该包内的 DATAGRAM 不获得可靠重传承诺。控制事件优先、关闭能唤醒、取消能归还预算，是比“进程没有退出”更具体的隔离标准。

## 4. sing-quic / sing-box：认证以后仍需关注的上层资源

| 阶段 / 资源 | 已执行的约束 | 超限 / 回收 | 仍缺少或不能推导的保护 | 证据 |
| --- | --- | --- | --- | --- |
| HY2 认证准入 | 密码查表，未认证不进入 HY2 TCP dispatcher；无效请求交 masquerade | 正常客户端收到失败会主动关闭 | `loopConnections` 每次 Accept 后启动 session；本路径没有进程/用户/IP 并发 semaphore | `service.go:227-258,271-289,331-337` [服务][sq-service] |
| 应用认证期限 | QUIC 握手期限存在；HTTP/3 默认 header section 上限使用 Go `http.DefaultMaxHeaderBytes`；客户端自己的认证请求有 timeout | 超大 HTTP 头触发 HTTP/3 错误；客户端 timeout 只约束正常客户端 | 服务端构造 `http3.Server` 仅设置 handler/dispatcher，未设置从握手结束到 HY2 成功认证的绝对期限。QUIC idle timeout 不能替代它，活动包可延长存活 | `service.go:250-253` [HTTP 服务配置][sq-service]；`http3/server.go:139-158,577-581` [HTTP 限制][q-http3]；`client.go:560-566` [仅客户端期限][sq-client] |
| TCP 请求头 | 目标地址最长 2048 字节、padding 最长 4096 字节 | 解析失败关闭对应流读侧/写侧，不主动关闭监听器 | 字节长度界限不等于耗时期限；`handleStream` 读取请求时没有本层独立的 deadline；每条接收流可启动 goroutine | `internal/protocol/proxy.go:20-24,39-60` [协议界限][sq-proxy]；`service.go:343-359` [分发][sq-service] |
| 上传 / 下载复制 | 两方向各自 goroutine；普通缓冲路径顺序 `ReadBuffer → WriteBuffer → 下一次 ReadBuffer`；目的端阻塞会停止该方向继续读取 | 出错关闭两端；正常可半关闭，双向完成后统一回收 | 没有随累计上传文件大小建立无限缓存；但 goroutine 总数、每用户并发和总堆预算不由这个复制循环限制 | `route/conn.go:152-153,273-289` [sing-box 路由][sb-copy]；`common/bufio/copy.go:186-218` [sing 复制][sing-copy] |
| HY2 UDP 关联 | 每关联入站 channel 64 项；完整消息入队满则释放丢弃 | 关联 Close 取消 context，调用 onDestroy 从 map 删除 | sessionID→关联 map 未设置实用数量配额；新 sessionID 可带来新的对象、缓存和处理 goroutine；没有跨关联总字节预算 | `service_packet.go:37-55` [关联创建][sq-packets]；`packet.go:133-145,257-273,293-303` [队列和回收][sq-packet] |
| UDP 空闲期限 | sing-box 未配置时使用 5 分钟，交 `canceler.NewPacketConn` 包装 | 空闲导致 deadline/取消并走关联关闭路径 | 活动关联可持续续命；idle TTL 不限制瞬时创建量 | `inbound.go:128-131` [设置][sb-inbound]；`constant/timeout.go:12` [默认][sb-timeout]；`service_packet.go:52-53` [实际包装][sq-packets]；[超时包装][sing-canceler] |
| UDP 分片 | packet ID 为 uint16，fragment total 为 uint8；拒绝越界片号、丢弃重复分片；缓存 age=10 s，访问可刷新，evict 释放分片 | 完整消息合并；缓存操作时清理过期项 | 未配置 `WithSize`；TTL 不是定时器保证的即时释放，也不是总 bytes 上限。ID 的理论有限空间不能当成合理资源配额；不同关联可各自扩张 | `packet.go:330-401` [组装][sq-packet]；`lrucache.go:35-37,263-284` [大小与过期的实际执行][sing-lru] |
| UDP 最大长度 | 本端 WritePacket/WriteTo 限制 4096 字节 | 本端超大发送返回错误 | 入站分片合并 `finalLength` 后直接 `buf.NewSize`，没有在此应用同一 4096 检查；不能写成“任意入站消息最多 4096 字节” | `packet.go:187-188,222-223,383-391` [不对称路径][sq-packet] |
| UDP 格式错误 | `loopMessages` 将 decode/处理错误传给 `closeWithError` | 关闭整个物理 QUIC session，取消所有 UDP 关联 | 不是仅丢坏关联；该连接承载的 TCP 代理流同样受影响 | `service_packet.go:11-31` [错误传播][sq-packets]；`service.go:363-385` [会话关闭][sq-service] |

回收还需要区分“最终可 GC”与“立即归还应用池/预算”。`udpPacketConn.closeWithError` 只是取消 context，本方法没有主动排空 64 项 channel 或 `Clear` 分片缓存；session 关闭会换掉 map 并取消关联。不能因此直接断言存在永久泄漏，但也不能声称关闭时全部 payload 都立即归还缓冲池。[packet.go:293-303][sq-packet]、[service.go:378-385][sq-service]

本地 Go node-agent 另外有实际服务端限速：`trafficTracker` 按用户共享 limiter；`newByteLimiter(0)` 不创建限速器，正值使用 `rate.Limiter.WaitN`，突发额度在 4 KiB 到 1 MiB 范围。上传 `limitedConn.Read` 先从传输读取，再按实际应用字节等待；下载 Write 在写入前等待。因此这是可由服务端强制执行的**应用字节消费/发送速率**，能向可靠流传递背压，但覆盖不到更早的原始 UDP 收包、无效密文处理、QUIC 握手和零负载控制包。[tracker.go:177,433-490,506-526][node-tracker] 它属于用户代码，不应归功于官方 sing-box 默认策略。

## 5. Xray：可借鉴的约束及其作用域

以下仅针对固定提交中所列路径。TCP 的 OS 接收窗口能够向正常 TCP 对端传递背压，但不能用它推论用户态 HY2 UDP 入口自动安全。缓冲 pool 复用减少分配，并不自动限制 pool 外活跃对象的总量。

| 阶段 / 资源 | 真实限制与作用域 | 满载 / 结束行为 | 重要边界 | 证据 |
| --- | --- | --- | --- | --- |
| UDP socket 到 Hub | 每 Hub 默认缓存 256 个 packet，可配置；本版本 `buf.Size=8192` | Hub channel 满则释放新 buffer、丢包 | 256 是每 Hub 的保留项数；已完成 socket 接收和可能的处理，不是 PPS 准入；8 KiB 是该版本缓冲常量，不应套用旧版 2 KiB | `transport/internet/udp/hub.go:35-37,81,100-154` [Hub][x-udp]；`common/buf/buffer.go:13,41` [缓冲][x-buffer] |
| UDP 关联 pipe | 每个 `udpWorker` 关联的入站 pipe 使用 `DiscardOverflow + WithSizeLimit(16*1024)` | 过载释放 MultiBuffer，并返回成功以继续处理其他数据；不会让该关联的慢消费者一直阻塞 Hub | pipe 检查的是追加前现有长度，16 KiB 是阈值而非逐字节硬上限；关联总数没有在这里设置配额 | `worker.go:280-308` [关联管道][x-worker]；`impl.go:28-29,128-172` [阈值执行][x-pipe] |
| UDP 关联生命周期 | activeConn map；一分钟扫描一次，最后活动超过 120 s 则关闭删除 | 空闲关联清除；正常完成也关闭删除 | 实际过期有扫描延迟，持续活动可保活；`make(map,16)` 是容量提示，不是最多 16 个关联 | `worker.go:369-424` [回收][x-worker] |
| 普通 TCP accept | 每连接启动 goroutine；过多文件等 Accept 错误时部分路径 sleep 500 ms | 关闭单连接、继续 accept，或监听器关闭后退出 | 所列 listener 没有进程/每 IP 的活动连接 semaphore；错误退避不是准入配额 | `tcp/hub.go:101-129` [接入][x-tcp] |
| 代理握手期限 | SessionDefault 为 60 s，VLESS/Trojan 的协议读取路径确实设置 ReadDeadline；可配置 | 到期读取错误，结束该代理连接 | 不可直接声称覆盖所有前置 TLS/REALITY/可选加密握手；例如 VLESS 某前置 decryption.Handshake 在此 deadline 设置之前 | `policy.go:125-133` [默认][x-policy]；`vless/inbound.go:276-282` [VLESS][x-vless]；`trojan/server.go:153` [Trojan][x-trojan] |
| 双向代理 pipe | 常见桌面/服务器架构默认每 pipe 512 KiB；arm64/mips64 为 4 KiB，部分低端架构为 0；环境显式配置 0 则选无限模式 | 满时写端等待读端或 done；`DiscardOverflow` 模式则释放丢弃 | `getLink` 创建上传/下载两个 pipe；所谓 PerConnection 不是两方向合计 RSS 硬上限。判断为 `curSize > limit` 且发生在新批次追加前，可超调一个传入 MultiBuffer | `policy.go:93-110` [默认与无限模式][x-policy]；`dispatcher/default.go:140-143` [两条 pipe][x-dispatch]；`pipe/impl.go:28-29,128-172` [实际背压][x-pipe] |
| 复制 / 调度 | `buf.Copy` 顺序读取一个 MultiBuffer 并写入，写阻塞时不继续读；双向 task 并发运行 | reader 消费后通知 writer；没有循环轮询等待 | `task.Run` 的 semaphore 大小是本次 tasks 数量，属于局部协调，不是整个进程 goroutine/连接并发限制 | `buf/copy.go:91-107` [复制][x-copy]；`task/task.go:20-54` [任务][x-task] |
| 用户策略 / 活动超时 | session policy 可按用户应用；默认连接 idle 300 s、单向阶段 1 s；VLESS/Trojan 显式建立活动计时器和 buffer policy | 超时取消，复制错误时走 Close/Interrupt 回收 | 计时器只解决不活动或结束的寿命，不限制活跃恶意用户；此处字节统计不是按用户 token bucket | `policy.go:125-140` [策略][x-policy]；`vless/inbound.go:416-417,507` [使用][x-vless]；`trojan/server.go:329-355` [使用][x-trojan] |
| Mux 逻辑 session | 客户端 `Allocate(ClientStrategy)` 检查 MaxConcurrency / MaxConnection；服务端 `Add` 检查 closed 后写 map | client 配额满停止分配；server 关闭后拒绝 Add | 不能用客户端参数证明恶意客户端受到服务端等额限制；session ID 的 uint16 范围也不是妥善的活跃资源预算 | `mux/session.go:54-85` [客户端与服务端区别][x-mux-session]；`mux/server.go:282` [服务端调用][x-mux-server] |
| pipe 关闭 / 中断 | Close 关闭 done，允许已有数据被读取；Interrupt 主动 ReleaseMulti 并清空 data | 阻塞 writer 被 done 唤醒并释放自己的待写批次；reader 获得结束/错误 | 仅取消 context 不等于所有任意 net.Conn IO 已自动中断，需调用者继续关闭实际 IO；共享 Mux 传输关闭也会影响其全部 session | `impl.go:156-204` [释放与唤醒][x-pipe]；`worker.go:122-126` [实际连接关闭][x-worker]；[Mux 生命周期][x-mux-server] |

这些代码的共同特点是：可靠流通过有界缓冲和等待传递背压，UDP 满载时直接丢弃，错误路径显式取消、关闭和释放资源。不能从中推出“Xray 默认具有一个覆盖所有协议、所有用户的进程级 CPU/内存硬配额”。

## 6. 对整体隔离设计的结论与仍需补齐的层次

1. **每连接队列必须有限，但不能到此为止。**256 包只是每连接保留上界。若没有活动连接、握手和总保留字节的共享预算，很多连接仍可放大总成本。入队前的解析、解密尝试和 DATAGRAM 复制也要单独看成本。
2. **字节、对象、任务和时间是四种预算。**8/20 MiB 的 STREAM 信用限制未消费的可靠数据；空流/高流 ID 引起的对象创建、UDP 关联、分片缓存、后台任务、认证等待都需要各自的有限规则。本文对高流 ID 的资源风险是源码推论，未做攻击复现。
3. **服务端必须自己决定准入。**地址验证/Retry、握手并发、认证绝对期限、每 IP/每用户活动连接与关联数、总内存额度，都不能由客户端自报带宽替代。查到可选接口不等于实际部署已启用；查到默认值也不能替代运行配置核验。
4. **速率与资源保护分层。**按用户应用字节限速是服务端可执行策略；对早期 UDP/PPS/无效密文/重复或零负载控制包，它生效太晚。这里审计的标准路径没有因此获得进程级这些成本的硬上限。额外防护可能由具体部署的内核、防火墙或流量入口提供，但本文没有审计也没有假设它们存在。
5. **调度和取消必须能够前进。**有限包处理批次给 ACK、定时器和关闭留出机会；满队列不能阻塞控制事件；可靠流目的端慢时停止扩张输入缓冲；UDP 超额丢弃；取消应解除 IO 等待并归还预算。任务并发或 Go runtime 调度本身不是可量化的用户公平承诺。
6. **故障域需要分别观察。**请求流、物理 QUIC 连接、共享 UDP socket/endpoint、整个进程是不同层次。单连接协议错误导致同一客户端网页、上传、下载一起中断，与进程仍然健康并不矛盾；但其他物理连接和健康探针应能继续服务。
7. **不能直接复制成熟项目的所有默认值。**sing-quic 的实用流并发缺省值、无关联总数门槛、仅 TTL 的分片缓存；Xray pipe 的批次超调和服务端 Mux 配额缺口，都说明需要按当前服务的资源预算选取约束，并检查所有绕过路径，而不是仅对齐常量。

用于验收整体保护的场景应分别覆盖：持续可靠上传且目的端很慢、正常流与大量无效包并行、许多物理连接、很多空流/慢请求头、DATAGRAM/关联/分片压力、认证后不遵守协商、队列满载下取消与连接重建。应记录各阶段拒绝/丢弃数、活跃对象数、保留字节、关闭原因，以及独立健康客户端的延迟和可用性。固定的文件大小测试只能证明对应正常上传链路，不能代替这些资源隔离证据。

## 源码索引

以下链接固定到本文版本/提交；`#L...` 为已核对的起始行。一个文件内的其他具体行号已在表格列出。

[sb-inbound]: https://github.com/SagerNet/sing-box/blob/v1.14.0/protocol/hysteria2/inbound.go#L128
[sb-copy]: https://github.com/SagerNet/sing-box/blob/v1.14.0/route/conn.go#L152
[sb-tls]: https://github.com/SagerNet/sing-box/blob/v1.14.0/common/tls/std_server.go#L491
[sb-timeout]: https://github.com/SagerNet/sing-box/blob/v1.14.0/constant/timeout.go#L9
[sq-service]: https://github.com/SagerNet/sing-quic/blob/v0.7.0-beta.4/hysteria2/service.go#L81
[sq-negotiation]: https://github.com/SagerNet/sing-quic/blob/v0.7.0-beta.4/hysteria2/service.go#L282
[sq-client]: https://github.com/SagerNet/sing-quic/blob/v0.7.0-beta.4/hysteria2/client.go#L559
[sq-http]: https://github.com/SagerNet/sing-quic/blob/v0.7.0-beta.4/hysteria2/internal/protocol/http.go#L20
[sq-brutal]: https://github.com/SagerNet/sing-quic/blob/v0.7.0-beta.4/hysteria/congestion/brutal.go#L41
[sq-quic]: https://github.com/SagerNet/sing-quic/blob/v0.7.0-beta.4/quic.go#L54
[sq-defaults]: https://github.com/SagerNet/sing-quic/blob/v0.7.0-beta.4/hysteria/protocol.go#L18
[sq-packet]: https://github.com/SagerNet/sing-quic/blob/v0.7.0-beta.4/hysteria2/packet.go#L133
[sq-packets]: https://github.com/SagerNet/sing-quic/blob/v0.7.0-beta.4/hysteria2/service_packet.go#L11
[sq-proxy]: https://github.com/SagerNet/sing-quic/blob/v0.7.0-beta.4/hysteria2/internal/protocol/proxy.go#L20
[sing-copy]: https://github.com/SagerNet/sing/blob/v0.9.0-beta.4/common/bufio/copy.go#L186
[sing-lru]: https://github.com/SagerNet/sing/blob/v0.9.0-beta.4/common/cache/lrucache.go#L263
[sing-canceler]: https://github.com/SagerNet/sing/blob/v0.9.0-beta.4/common/canceler/packet.go#L27
[q-params]: https://github.com/SagerNet/quic-go/blob/v0.61.0-sing-box-mod.7/internal/protocol/params.go#L5
[q-server]: https://github.com/SagerNet/quic-go/blob/v0.61.0-sing-box-mod.7/server.go#L266
[q-transport]: https://github.com/SagerNet/quic-go/blob/v0.61.0-sing-box-mod.7/transport.go#L110
[q-conn]: https://github.com/SagerNet/quic-go/blob/v0.61.0-sing-box-mod.7/connection.go#L579
[q-config]: https://github.com/SagerNet/quic-go/blob/v0.61.0-sing-box-mod.7/config.go#L17
[q-flow-stream]: https://github.com/SagerNet/quic-go/blob/v0.61.0-sing-box-mod.7/flow_controller_stream.go#L51
[q-flow-conn]: https://github.com/SagerNet/quic-go/blob/v0.61.0-sing-box-mod.7/flow_controller_connection.go#L46
[q-recv-stream]: https://github.com/SagerNet/quic-go/blob/v0.61.0-sing-box-mod.7/receive_stream.go#L445
[q-stream-map]: https://github.com/SagerNet/quic-go/blob/v0.61.0-sing-box-mod.7/streams_map_incoming.go#L115
[q-sorter]: https://github.com/SagerNet/quic-go/blob/v0.61.0-sing-box-mod.7/frame_sorter.go#L181
[q-crypto]: https://github.com/SagerNet/quic-go/blob/v0.61.0-sing-box-mod.7/crypto_stream.go#L36
[q-framer]: https://github.com/SagerNet/quic-go/blob/v0.61.0-sing-box-mod.7/framer.go#L66
[q-sent]: https://github.com/SagerNet/quic-go/blob/v0.61.0-sing-box-mod.7/internal/ackhandler/sent_packet_handler.go#L1139
[q-ack-history]: https://github.com/SagerNet/quic-go/blob/v0.61.0-sing-box-mod.7/internal/ackhandler/received_packet_history.go#L41
[q-datagram]: https://github.com/SagerNet/quic-go/blob/v0.61.0-sing-box-mod.7/datagram_queue.go#L13
[q-send-queue]: https://github.com/SagerNet/quic-go/blob/v0.61.0-sing-box-mod.7/send_queue.go#L35
[q-http3]: https://github.com/SagerNet/quic-go/blob/v0.61.0-sing-box-mod.7/http3/server.go#L139
[x-udp]: https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/transport/internet/udp/hub.go#L35
[x-buffer]: https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/common/buf/buffer.go#L13
[x-worker]: https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/app/proxyman/inbound/worker.go#L280
[x-tcp]: https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/transport/internet/tcp/hub.go#L101
[x-policy]: https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/features/policy/policy.go#L93
[x-pipe]: https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/transport/pipe/impl.go#L28
[x-dispatch]: https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/app/dispatcher/default.go#L140
[x-copy]: https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/common/buf/copy.go#L91
[x-task]: https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/common/task/task.go#L20
[x-vless]: https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/proxy/vless/inbound/inbound.go#L276
[x-trojan]: https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/proxy/trojan/server.go#L153
[x-mux-session]: https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/common/mux/session.go#L54
[x-mux-server]: https://github.com/XTLS/Xray-core/blob/5ca6f4b7d4dc20a881d4330e498892697627ec0c/common/mux/server.go#L282
[acp-mod]: https://github.com/0xddy/sing-box-acp/blob/e7ba3f961942ccf63e7173009498b16308eb93fc/go.mod#L47
[acp-auth]: https://github.com/0xddy/sing-box-acp/blob/e7ba3f961942ccf63e7173009498b16308eb93fc/third_party/sing-quic-acp/hysteria2/service.go#L401
[node-tracker]: https://github.com/0xddy/node-agent/blob/08a578a1267e2e4defd4bdb8ffc0d06e549ccf29/src/internal/runtime/tracker.go#L433
