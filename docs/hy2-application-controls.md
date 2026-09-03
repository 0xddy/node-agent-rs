# HY2 应用层异常客户端隔离审计

审计范围：当前本地 `../shoes-plus/src/hysteria2_server.rs`，以及它调用的认证登记、UDP 代理链和 masquerade。这里区分已核实的代码边界、可构造的缺口和尚待压力验证的风险。没有把有限的 localhost 测试等同于公网抗攻击保证；`copy_bidirectional.rs` 的调度审计由另一项工作负责。

## 当前已经生效的边界

下列行号均指 `../shoes-plus/src/hysteria2_server.rs`，另注明文件的除外。

| 范围 | 实际限制与超限行为 | 代码 |
| --- | --- | --- |
| 未认证连接 | 一个逻辑 listener 的全部 SO_REUSEPORT endpoint 共用握手门；全体 1024、每来源 IP 64；先 Retry 验证地址，再占门、spawn，满额立即 refuse | 2132–2135、2235–2274；`tcp/handshake_gate.rs:52–60` |
| 认证时间 | transport 最长 15 秒；H3 setup 最长 15 秒；应用认证最长 3 秒；外层从入门开始绝对 60 秒，PING 不延期 | 383–478；`quic_server.rs:60–69` |
| 物理 QUIC | 接收窗口 20 MiB、每流 8 MiB、发送窗口 16 MiB；传输 idle 30 秒、keepalive 10 秒 | 2141–2173 |
| TCP 逻辑流 | 每物理连接 1024 个 permit，整个解析、拨号、复制生命周期持有；传输层额外广告 64 流 headroom；满额 reset/stop 新流，无等待队列 | 44–66、1765–1819 |
| TCP 解析 | 15 秒绝对头期限；类型必须 `0x401`，地址不超过 2048 字节、padding 不超过 4096 字节；解析器缓冲 8192 字节 | 1790、1835–1870、1958–1968 |
| TCP 后续建立 | sniff 最长 300 ms、64 KiB；路由/DNS/拨号外层最长 60 秒；错误限定于当前逻辑流 | 1976–2017；`routing/protocol.rs:18–20,42–78` |
| UDP 会话 | 每物理连接最多 512；每会话一个 router 任务，命令队列 64；满额丢新会话或新包 | 80–85、1055–1095、1717–1754 |
| UDP 目标 | 每会话 map 最多 64；每连接已占用目标 permit 最多 1024；目标命令队列 8；满队列 `try_send` 丢包，目标满额时 LRU 替换 | 87–103、1168–1288、1374–1442 |
| UDP 上传排队 | 跨所有会话/目标共享 16 MiB 逻辑 payload permit，写和 flush 完成才释放；空 payload 仍占 1 个 permit | 216–221、1340–1354、1585–1586、1707–1745 |
| UDP 回包 | 每会话回包队列 1；目标 read buffer 65535 字节；满队列丢响应，不等待其他目标；分片发送每片可取消，MTU 改变的 TooLarge 只丢本包 | 258–354、1292–1367、1455–1461、1542–1574 |
| UDP 重组 | 每连接 256 个未完成报文、8 MiB 逻辑 payload；单报文不超过 65535 字节；分片个数/index 校验；重复/个数改变丢该报文；10 秒 TTL | 24、106–114、833–1035 |
| UDP 清理 | 每 10 秒扫会话，60 秒无活动删除；fragment TTL 独立扫；会话/目标 Drop 都 cancel 子任务 | 797–830、1098–1117、1588–1604 |
| 连接关闭 | 每物理连接有 cancel-on-drop root；user/inbound 撤销、连接正常/异常退出触发子树取消；TCP 包括解析和拨号，UDP 包括 permit 等待、connect、write、限速等待 | 376–410、532–539、572、1243–1285、1347–1351、1804–1815；`quic_server.rs:82–105` |
| 共享锁 | HY2 本身仅会话 `last_activity` 的短同步 Mutex；锁内读取/更新时间，不跨 await；session/target/fragment map 由单任务独占 | 770–787、1040–1051、1509–1511、1584–1587 |

未发现 HY2 应用层使用 `unbounded_channel`。主要队列满额使用立即丢包；不会因一个目标 write 堵塞而在全连接入站 DATAGRAM 循环里 await 该目标。

## 已确认的隔离缺口

### 1. 已认证连接缺少 listener 级总额度，可通过多连接放大所有单连接额度

认证成功立即 `drop(handshake_permit)`（486），后续只受用户可配置的 `max_conns` 影响。HY2 listener 没有 generic QUIC 所用的 active-connection gate；对照 `quic_server.rs:79–80,288–294`。`dynamic/user.rs:288–292` 明确把 `max_conns == 0` 当作无限制，经典配置的 `admit_unmetered` 也不登记活动连接（316–317）。

因此“1024 TCP 流/1024 UDP target/16 MiB queue”只是每条物理连接的上限。一个合法账号可以串行完成认证，释放握手槽，再重复创建连接；限制握手并发无法限制这些存活连接的累积。没有核实到 listener 或跨用户的 TCP 流、UDP socket、排队字节总预算。

这些常量也不是低成本额度：1024 个 TCP 双向 32 KiB copy buffer 约 64 MiB；1024 个 UDP target read buffer 约 64 MiB；512 个会话各一个队列响应和一个正在分片/等待发送的响应，逻辑 payload 最坏可再占约 64 MiB。上述是各自峰值的预算分析，未声称是一个连接的实测 RSS，并且尚未包含 QUIC、内核 socket、元数据和代理链的额外开销。

最小验证：有限地建立 2/4 条同账号连接，每条创建固定数量的 TCP hold 或 UDP target，观察资源随连接数线性增加；并验证配置 `max_conns` 后认证被拒绝。不要以耗尽真实机器资源为目标。工程修复方向是增加 listener 级活动连接和资源总预算，并保留每用户/每连接的局部限制。

### 2. 8 MiB/16 MiB 预算只计 payload 长度，未计 `Bytes` 切片持有的完整包与地址

UDP 入站以 `data.slice(next_index + address_len..)` 取得 payload（1665），随后将该切片直接放进分片缓存或命令队列（1010、1743）。非空 `Bytes` 切片共享底层分配，而预算只增加 `payload.len()`（976–986、1014、1708）。地址允许到 2048 字节（1655），`address.rs:52–53,101–120` 并未在解析阶段按 DNS hostname 长度进一步截断。

可发送“较长地址 + 1 字节 payload”的大量未完成分片：每个 cache entry 最多存 254/255 片后不完成，最多 256 entry。预算计入的 payload 很少，却可保留数万块含长地址的 backing allocation，另外还有 `Vec<Option<Bytes>>` 和目的地字符串。总内存仍受 entry/fragment 数和传输包大小约束，**不是无限内存漏洞**，但不能把 `MAX_UDP_FRAGMENT_BYTES_PER_CONNECTION` 解释为该缓存实际只占 8 MiB。

最小验证：在受控进程中发送有限数量（如 64 个 packet id × 128 个分片、每片 1 字节 payload 和 900 字节地址），仅维持不足 10 秒；比较逻辑 cache bytes 与分配器/RSS 增量，并等待 TTL 或断开确认释放。修复可在持久化时只复制有效 payload，或统一预算实际拥有的存储和元数据；不要仅放大常量。

### 3. UDP 目标建立、write/flush 没有独立绝对期限，目标只有会话级 idle 清理

目标 connect 外层 select 只等 cancel 或完成（1248–1253）；write/flush 同样只等 cancel（1342–1351）。代理链 `client_proxy_chain.rs:491–606,1633–1672` 没有包住整条 UDP 建链过程的总期限；直接 UDP DNS 也只是 await（`tcp/socket_connector_impl.rs:541–550`）。底层个别 connect/DNS 可能自行超时，不能替代整个 HY2 UDP 目标工作流程的统一期限。

仅有会话 idle（1098–1117），且任何发往已存在 session 的可解析地址包会更新时间（1683–1685），即使之后分片被拒绝/队列丢包。一个 session 中其他目标持续活动也会保留该 session 所有旧 target。结果是卡住的建立/写操作可长期占住 target permit 和队列；当前已把影响限定在目标/会话，未证明其直接阻断另一个用户，但与多连接放大叠加后会长时间保留资源。

最小验证：使用本地代理或 fake connector，使一个 target 的建链/flush 永远 Pending；同时同 session 另一 target 做 echo，持续有限时间，观察独立目标进展及 permit 长期占用；取消 session/连接后必须迅速释放。修复方向是目标建立/写期限和目标级 idle/LRU 释放策略。

## 尚需压力验证的边界，不能当成已复现缺陷

1. **目标替换中的等待任务数不等于 1024 个 socket permit。** 连接 permit 用完时，满 64 个 target 的 session 可以先取消 LRU，再以 `UdpTargetPermit::Awaiting` spawn 替代任务（1174–1176、1202、1280–1285）。取消是异步的，JoinHandle 未保存，旧任务可能还未被 poll 到。每 session map 有 64 项上限，但“活/等待/已取消尚未结束的 task 总数”没有单独原子 gate；高速 target churn 应实测峰值和回落。不得将此直接写成已证明无限任务泄漏。
2. **控制帧/流创建的操作速率没有应用级 gate。** uni 流被直接 accept/stop（510–525），不会经过流量计量；TCP 会并发创建最多 1024 个解析任务，合法/畸形请求结束后立刻回收 permit（1765–1819）。并发限制和字节限速都不等同于每秒解析/建流/销毁工作的额度。需要持续短流/UNI/DATAGRAM churn 与健康客户端延迟测试；下层 Quinn 调度由单独传输层审计覆盖。
3. **masquerade HTTP driver 没有显式随请求 abort 的所有权。** HTTP/1、HTTP/2 driver 在 `hysteria2_masquerade.rs:220–241` detached spawn；外层认证 3 秒到期会取消 caller，但未保存 driver handle。Hyper 通常会因请求/发送者/body 生命周期结束而关闭连接，不能仅凭 detached spawn 判定泄漏。应以慢响应、永不结束 body 的本地上游验证取消后 driver/socket 回落，并检查 H1/H2 两条分支。
4. **UDP target 读写是一个 owner。** 两侧同时 ready 时轮换优先级（1313–1335），但进入 write/flush await 后不再 poll read，直至写完成/取消（1342–1351）。这是单目标的背压范围；其他 target 有独立任务。需要代理型 UDP 的双向堵塞测试，不能从已有轮换注释推出 pending write 期间仍能接收。

## 限速与防止共享故障的区别

`ignore_client_bandwidth` 只决定对端被建议采用的拥塞控制。服务器的用户级 TCP/DATAGRAM 计量和限速另外执行：TCP 在头解析前套 `TrafficMeterStream`（1948–1955）；UDP 上传先 admission，再验证，畸形 datagram 也计入（1613–1627）；回包每片 admission（314–350）。这能够在应用交付层限制不守约客户端；无法凭这个字段阻止其先把 UDP 线路/QUIC 解密计算打满。

所需验证应分别报告：（a）应用实际交付是否受服务器聚合限额约束；（b）异常客户端存在时健康账号新握手、请求、下载是否仍能进展；（c）异常结束后任务、socket、队列是否回落。三者不能用单一平均吞吐量或“进程仍在”替代。

## 本次新增的有限 localhost 实测

`crates/shoes-engine/tests/hysteria2_isolation.rs` 首次运行 2/2 通过；每个用例使用两个 Tokio worker，最长 15 秒，所有目标为 localhost。没有改变生产限额。

- 收到 `Hysteria-CC-RX: auto` 后，两个同账号客户端主动强制 128 MiB/s Brutal；服务端用户上传限制为 16 Mibit/s（2 MiB/s）。两个 TCP 目的端合计确认收到 6 MiB，用时 **2.5205 秒**，符合单个聚合桶扣除最大 1 MiB burst 后至少 2.5 秒的约束。上传期间原 QUIC 的 1 MiB 下载、另一账号新握手和请求均成功，两项并行探针共 124.5 ms。测试的下界为 2.25 秒，能够区分同账号错误获得两个独立 bucket 的约 1 秒结果。
- 持续 2.005 秒提交短报文、非法分片数、截断地址 varint 和无效 UTF-8 地址：**8832 个实际 QUIC DATAGRAM frame、152 个 QUIC packet**，服务器为该账号计入 68448 字节。另一账号三次新握手/请求均在生成器继续运行期间完成，耗时 7–8 ms；发送端随后仍可在原连接请求正常 TCP 目标。Windows 的 timer 粒度使这不是高 PPS 负载，结论限定为持续畸形应用输入下的隔离和继续进展。

这些测试没有覆盖前述多连接资源乘法、真实链路饱和或多机器攻击，也没有证明连接之间吞吐量公平。测试统计同时区分 application 提交量、实际发送 frame 和 packet，避免把 QUIC 队列接收成功误当作全部上线路由。
