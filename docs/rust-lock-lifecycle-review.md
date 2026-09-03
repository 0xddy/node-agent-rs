# Rust 锁竞争与 Arc 生命周期审查

审查日期：2026-09-03。对象为当前工作区（包含此前三轮内存优化），以及实际 path 依赖 `../shoes-plus` 的连接计量和 DNS 生命周期实现。

## 后续修复记录

用户授权全部修复后，已落实下表。后文编号 1–8 保留的是**修复前**的审查证据；原始行号随实现调整会发生变化。

| 原问题 | 修复后的行为 |
| --- | --- |
| 1：进度响应占住拓扑锁 | 正常进度保持顺序；单次发送超过 1 秒时取消该远控子流，解除发送等待，已开始的本地事务继续完成并保存真实终态。不会取消父会话令牌。 |
| 2：Agent 外层取消后保活 | `Agent::run` 由独立 supervisor 承接；调用方 Drop/abort 发出关闭请求，继续执行等待在途事务、关闭资源、收取尾流量、停止面板的顺序。 |
| 3：同步日志放大锁等待 | 本地输出交给单一写线程；producer 不执行 stdout/文件 I/O；用户连接拒绝日志移到生命周期锁外。 |
| 4：日志转换重入死锁 | 先短暂检查订阅，释放 broker 锁后转换文本，再加锁分发；无订阅不格式化、单订阅转移原缓冲仍保留。 |
| 5：远控请求无限派发 | 控制器共用 16 个许可，读取并 spawn 下一请求前取得；许可随任务 owner 保留到结束，跨重连仍有界。 |
| 6：DoQ writer 滞留 | socket 保存 writer 的 AbortHandle，Drop 终止连接/收发等待，并清掉 poller 可能保留的 shared 传输；迟到的连接不能复活失败状态。 |
| 7：端口后端阻塞 worker | 正常配置、关闭及回滚路径统一使用 `spawn_blocking`；owned 事务继续等待真实完成，后端 panic 按状态不确定处理。 |
| 8：规则下载占用 apply | 增加独立配置顺序锁，下载在 `apply` 外执行；不可变快照仍仅在成功事务后推进 last-good 缓存。提交前检查关闭/代际。 |
| 8 附项：周期任务忙轮询 | 在检查状态前注册 Notify，等待完成/设置变化；RAII 负责异常退出时清理 attempt 并通知后继。 |
| 关闭链路补强 | Manager 在等待拓扑锁之前通过 `begin_close` 取消规则准备；signal→等待→资源关闭全部由 owned task 执行，调用方丢弃也会完成。 |

新增关闭信号只作用于准备阶段，已开始的数据面修改仍到达终态。只有显式关闭且底层明确报告旧运行时 unchanged/rolled_back 时，Adapter 才跳过冗余恢复；常规失败和状态不确定的恢复策略保持。

本地日志的边界是 1024 条 / 1 MiB 队列、32 KiB 单行（UTF-8 安全截断并标记）；文件切换队列最多 4 项。过载会丢最旧的本地日志，写线程恢复后报告丢失数量，远程日志使用独立队列。正常 close 排空并关闭文件，最多等待 2 秒；若操作系统 I/O 仍不返回，只保留原来一个 writer，拒绝再创建更多阻塞线程。普通 flush 合并为异步请求，最终排空由 close 承担。Panic 应急 I/O 最多等待 250 ms，然后保留既有退出码 2。

操作系统永久不返回的同步 I/O 无法安全强制终止线程；这项修复隔离其影响并限制保留量。Linux netlink 的真实系统调用仍需 Linux 环境验证，本机测试通过阻塞路由替身检查 Tokio 线程可继续运行。

新增回归覆盖：两阶段进度背压、请求并发上限、周期唤醒、Agent Drop/abort、DoQ Pending connect/真实 VLESS 写背压/迟到连接、日志重入和有界输出、writer panic 清理、慢规则下载期间 drain/kick/close，以及真实 Manager→Adapter→ShoesRuntime 的关闭与取消关闭调用方。

## 修复后验证

本轮共通过 **472 项测试**：

- `cargo test --workspace --lib --offline --locked -- --test-threads 4`：348 项（acp-proto 18、node-agent 217、shoes-engine 113）。
- `cargo test -p node-agent --test agent_session --test topology_manager_control --test remote_control_adapter --test topology_compile --offline --locked -- --test-threads 4`：97 项，覆盖会话、协议适配、配置编译与拓扑事务。
- `cargo test --manifest-path ../shoes-plus/Cargo.toml --target-dir G:/Development/Project/node-agent-rs/target --lib dns::proxy_runtime::tests --offline --locked`：13 项。
- 对上一步同次构建的 shoes 单测产物执行 `dynamic::user::tests:: --test-threads 4`：14 项，覆盖准入、并发连接计数及关闭。

`cargo clippy --workspace --all-targets --offline --locked` 无新增警告；保留原有 `crates/shoes-engine/tests/hysteria2_rebind.rs:151` 的 `collapsible_if` 样式提示。工作区格式检查、两个依赖修改文件的 rustfmt 检查及两仓库 `git diff --check` 均通过。

实现同时涉及主工作区与 `../shoes-plus` 的 `src/dns/proxy_runtime.rs`、`src/dynamic/user.rs`，核心修复已提交为 `f010c624b063e6c4fb1a9702cc6ac564895ebb8a`；CI 与发布流程已同步固定到此版本。Agent Drop/abort 的有序异步清理要求宿主 Tokio runtime 继续运行；直接销毁整个 runtime 无法继续执行异步清理。

## 原始审查结论

结论：没有发现认证/计量主路径必须重做锁结构的证据，也没有在已追踪的核心对象中发现直接的强引用环。但存在需要处理的事务锁阻塞、任务退出不完整和同步 I/O 放大锁等待的问题。活动用户较少并不能消除这些问题：慢面板、单个背压连接或一次任务取消就足以触发部分路径。

这是源码审查和定向复现，不是生产负载采样；不能据此宣称不存在其他泄漏，或量化实际锁等待的 p95/p99。审查阶段未改变业务实现，后续修复见上表。

## 1. P1：进度响应的背压可以长期占住全局拓扑锁

位置：

- `crates/node-agent/src/topology/manager.rs:1168`：取得 `operation` 后，多次等待 `reporter.report(...)`，包括端口配置之后的 `:1201` 和提交之后的 `:1223`。
- `crates/node-agent/src/remote_control.rs:470`：`ResponseSink::send` 等待有界通道，仅监听 `stream_cancel`。
- `crates/node-agent/src/remote_control.rs:800`：重载超时取消的是 `operation_cancel`，随后仍等待同一事务结束，无法取消上述进度发送。
- `crates/node-agent/src/topology/manager.rs:1008`：关闭、其他变更及 loaded users 查询也需要 `operation`。

当面板保持连接但停止读取响应，且响应队列被填满，进度消息就会在事务锁内等待。配置下载和其他请求共享该队列，因此不需要很多数据面连接。后续用户更新、重载和关闭会排队；如果在 ConfigurePortHopping 之后阻塞，还会延长中间状态的存活时间。

正常退出也存在等待依赖：`Agent::run` 先等待 `topologies.close()`，之后才取消 `session_shutdown`（`agent.rs:168`、`:183`）。若重载正等同一会话的响应背压，关闭在等拓扑锁，释放发送等待所需的会话取消又在关闭之后。

已通过两项定向探针验证。探针直接调用生产 `handle_remote_control_request → PanelRemoteFetcher → TopologyManager → ResponseSink`，面板数据和底层运行时用测试替身；通道容量保持 64，Tokio 时间推进 121 秒：

```text
stage=pull_configuration: deadline passed; reload pending; loaded_users and close blocked
stage=start_instance: deadline passed; configured=true; applied=false; close blocked
stream cancellation released progress send and operation lock; close completed
```

第二种情况预填 60 帧，让前四个进度入队，验证卡在端口配置之后。两种情况都在显式取消远控流后恢复；没有用强制 abort 掩盖事务结果。这证明队列背压和锁阻塞路径，完整网络流控及整个 Agent 信号退出链尚未做端到端复现。

建议先修这一项。进度上报应与事务推进解耦：使用有界、非阻塞的进度投递，必要时合并阶段；终态单独保证发送。如果协议必须逐阶段可靠送达，应给发送设定明确期限并使流退出，不能无限占用事务锁。不要直接取消已修改数据面的事务，否则会破坏现有回滚和计费保证。

## 2. P2：直接取消 Agent::run 后，子任务继续保留 Agent 和运行时

位置：`crates/node-agent/src/agent.rs:134–143`、`:199–222`。

`run` 创建独立的会话/流量取消 token，并用普通 `JoinHandle` 管理两个子任务。调用方若 `abort` 或丢弃正在执行的 `run` future，句柄被丢弃，任务仍运行；局部 token 的析构也不会自动取消。面板重连闭包持有 `Arc<Agent>`，流量任务另持运行时、聚合器和队列。

这是任务保活导致的资源滞留，没有形成对象之间的直接 Arc 环。只要 Tokio runtime 仍存活，面板重连可以一直继续；再次取消原来的 process token 也不能补救，因为两个子 token 与它独立。

当前 CLI 在 `main.rs:77` 附近直接 await `agent.run(shutdown)`，正常信号关闭不走 abort 路径。因此它主要影响库嵌入、上层 timeout/任务监督和测试中的强制取消。

已用当前编译产物复现，完全禁用网络拨号，仅保留真实会话重试生命周期：

```text
agent_abort=false; agent_alive=false; runtime_alive=false
agent_abort=true;  agent_alive=true;  runtime_alive=true
```

探针用 `Weak::upgrade` 检查对象，而不是观察 RSS。正常退出与直接 abort 使用相同构造方式；检查时运行时继续调度。

建议在 `run` 的作用域增加取消/abort-on-drop 守卫，保证异常丢弃时会话与 flusher 都退出；正常关闭仍保留“关闭数据面、收取尾流量、停止面板”的顺序。已经开始的拓扑事务继续由其独立 owner 完成，不能一并粗暴 abort。

## 3. P2：同步日志 I/O 会阻塞 Tokio 工作线程，并放大用户锁持有时间

位置：

- `crates/node-agent/src/logging/logger.rs:197–205`：调用线程同步写 stdout 和日志文件。
- `crates/node-agent/src/logging/file.rs:74`、`:105`、`:190`：文件锁覆盖写入、轮转、`sync_all` 和备份复制。
- `../shoes-plus/src/dynamic/user.rs:380–390`：连接上限拒绝分支持有用户 `connections` Mutex 时调用 `log::debug!`。

正常日志配置的 RwLock 已在 I/O 前释放，这一层不用重写。实际问题是 stdout/文件操作本身同步执行；轮转还会在文件锁内复制备份。慢磁盘或 stdout 背压可让其他日志调用等待，并占用 Tokio worker。

启用 debug 后，单个用户反复触发连接上限就会把慢日志延迟带入该用户生命周期锁，影响认证注册、连接释放及删除。这里没有必要假设几千活跃用户。

已确认同步 I/O 和锁范围；没有生产磁盘/日志速率测量，不能把它描述为已经发生的严重竞争。

建议先把连接拒绝日志移出用户锁，改动很小。若实际有日志延迟，再使用一个独立写线程和有界队列承接正常日志；避免每条日志创建 `spawn_blocking` 任务或使用无界日志队列。崩溃日志保留独立的尽力写入路径。

## 4. P2：RemoteBroker 的公开文本转换接口可以重入死锁

位置：`crates/node-agent/src/logging/remote.rs:101–140`。

上一轮惰性分配优化让公开 `publish(text: impl Into<String>)` 的 `text.into()` 在 broker Mutex 内执行。`Into<String>` 可以是用户自定义代码；若转换时订阅、关闭订阅或再次发布到同一个 broker，会再次取得同一把非重入锁。

已复现：创建一个活跃订阅，自定义转换先发出“已进入转换”信号，再调用同 broker 的 `subscribe()`；转换已开始，但 `publish` 无法完成。探针把这一调用放到独立线程，主线程限时观测，随后退出探针进程。

```text
remote_into_entered=true; publish_completed_within_300ms=false
```

当前项目调用方主要传 `String` / `&str`；私有前缀格式化闭包也不重入。因此这是已确认的 API 死锁边界，不能说所有正常日志都会死锁。

建议公开入口在锁外转换，保留私有、受控的惰性格式化路径给 `publish_remote`。若要同时保持公开入口的无订阅快路径，可短暂检查订阅后释放锁，再转换、加锁分发；不要在锁内执行外部转换代码。

## 5. P2：远控请求任务数量没有随响应队列一起受限

位置：`crates/node-agent/src/remote_control.rs:978–1001`、`:1030`；配置下载的局部配置缓存在 `handle_current_config` 中跨发送等待存活。

每个收到的请求立即 spawn，另创建一个监控任务。响应通道虽有容量限制，却只限制已入队响应，不能限制等待发送的任务数。面板继续提交请求但消费响应很慢时，任务及其请求数据、依赖 Arc、配置副本会积累。

这属于背压不足引起的内存增长，没有直接 Arc 环。正常低频控制流风险较小；大量请求来自面板而非数据面用户数。它也能放大第 1 项的进度队列拥塞。

建议在读取/派发入口限制同时执行的请求数，并以结构化任务集合管理。许可必须在 spawn 之前取得，否则只是把无限等待移动到更多任务里。重载事务已经有 gate，其他读请求也需要总量边界；具体容量按管理面实际请求频率确定。

## 6. P2：经代理的 DoQ writer 在持续背压时滞留

位置：`../shoes-plus/src/dns/proxy_runtime.rs:360–390`、`:415–447`。

代理 DNS-over-QUIC socket 的 detached writer 在连接阶段有超时，但取出一条消息之后直接等待底层 `poll_write_message` / `poll_flush_message`，没有 socket 所有者消失或发送超时分支。如果底层代理传输一直 Pending，释放 socket 的发送端不能让正在写入的 future 回到 `recv` 观察通道关闭。

因此旧传输及其 shared 状态可能存活到写恢复或 Tokio runtime 退出。该路径只涉及配置了代理 detour 的 DoQ，需要按实际启用情况决定优先级；普通直连 DNS 不应被包含在此结论内。

已做实现级复现：探针抽取当前 writer/shared 实现，并直接引入实际 `vless_message_stream.rs`，以 `duplex(1)` 制造持续背压、DropSpy 检查流释放：

```text
after owner drop: writer_still_pending=true shared_alive=true stream_dropped=false
after peer drop: shared_alive=false stream_dropped=true
```

这验证了真实 writer 与 VLESS 编码层的释放行为，传输使用可控 duplex，尚非完整网络端到端复现。只有连接建立超时不能覆盖它；TCP keepalive 也不能保证仍响应 TCP、但不读应用数据的对端解除背压。

建议 socket 所有者 drop 时显式取消 writer，并让每次 write/flush 同时观察取消。只把 Arc 改成 Weak 无法中断已经升级并进入等待的传输操作。

## 7. Linux 端口跳跃控制会同步占用工作线程

`topology/manager.rs:315`、`:509` 等位置从 async 事务直接调用同步 `port_router.reconcile`；`porthopping/manager.rs:46` 持 Mutex 执行平台操作。Linux backend 使用同步 netlink I/O，有单次 socket 超时，但未移到阻塞线程。

这不是数据包路径的全局锁，也不是无限等待的证据。慢内核响应/防火墙更新会占用当前 Tokio worker，同时拉长控制事务。Windows 当前 backend 为 no-op；Linux 路径未在本次 Windows 环境实测。

如部署使用 Linux 端口跳跃，建议把一次完整 reconcile/close 放到 `spawn_blocking`，仍保留现有串行和事务完成边界，不要把单次 socket 超时误当成整个事务的严格总时限。

## 8. P2：远程规则准备在 Runtime 操作锁内串行等待

`runtime.rs:591` / `:845` 获取 `apply`，`:622–626` 在锁内调用规则准备。`rule_set.rs:389` 串行处理资源，单次 HTTP 总超时为 30 秒（`:365–366`）。多个需要更新、有缓存可回退、但远端不可达的规则源可能依次消耗超时，累加为很长的控制操作等待。

其间流量收取（`runtime.rs:2177`）、踢用户（`:2141`）和关闭（`:2031`）等待同一把锁；已有连接的字节转发不直接获取该锁，因此不能说整个数据面随之停转。

这属于有边界但可累加的队头阻塞，源码可确认，未注入真实网络超时测量。把资源准备移到锁外需要提交前重新检查代际/配置，以及处理缓存发布和回滚，改动比前几项大，应后排。

另有一个重连组合场景：`remote_control.rs:933–935` 在旧周期拉取仍占 attempt 时仅 `yield_now` 重试。旧会话被 StreamGroup 超时退出，而其 owned 事务还未完成时，新会话可能一直让出调度再重试。建议用完成通知等待；这是静态条件风险，尚未做定向复现，不把它列为当前已发生的严重锁竞争。

## 已核查的锁与所有权边界

| 范围 | 当前结论 |
| --- | --- |
| 用户流量计量 | 字节计数主要走原子操作；启用限速时按用户、方向分开的短锁在等待前释放。未见需要替换为复杂无锁结构的依据。 |
| Registry writer | 保护多索引一致性；认证不取 writer；remove 在等待连接关闭前释放 writer 和 DashMap guard。 |
| DashMap | 使用分片锁，不是完全无锁；当前关键查找没有跨 await 保留 guard。 |
| 拓扑 / Runtime / Engine 操作锁 | 大多用于保证事务一致性。正常控制事务串行不能直接视为缺陷；应优先切断第 1 项的外部进度背压。 |
| 流量队列 receiver 锁 | 整个 stream 持有 async guard，目的是只允许一个消费代际；不是每个用户都争用它。 |
| 聚合器 / ACK 缓存 | 同步短临界区，排序在聚合锁外，ACK 执行在缓存锁外；没有找到严重竞争依据。 |
| RemoteBroker / 订阅 | 两个方向均通过 Weak 关联，关闭顺序未见逆序持锁；队列有行数和字节上限。问题在公开回调重入，不在 Arc 环。 |
| Runtime watcher | 睡眠期间只有 Weak；刷新结束后强引用在下次 sleep 前释放。 |
| Engine / Inbound | listener、连接没有反向持有 EngineInner；最后一个 Engine 释放时停止接受新连接，已有连接可继续排空。 |
| DNS / replay / URLTest | 已追踪的缓存、lineage 和后台探测回指使用 Weak；DoQ writer 的持续 Pending 是独立的任务生命周期问题。 |
| UserContext / ConnContext | 连接持有用户，用户只保存 cancellation token，不保存连接 Arc；连接 Drop 解除注册。 |
| PendingTrafficReservation | 临时事务对象持有 RuntimeInner；RuntimeInner 中没有反向存储 reservation，因此没有这条强引用环。 |

取消删除后的 `draining` tombstone 需要单独解释：`users.rs:765` 保存 generation，成功收取最终计数后在 `:819–831` 清理。如果调用方取消后永不重试，记录会保留到 registry 释放。这是账单恢复契约，生产 NodeRuntime 还有 owned transaction / remove 重试保护。它不是 Arc 环，不应以 TTL 直接删除而丢失尾流量；必要时观测未收取记录数即可。

## 修复前验证记录

- 真实远控/拓扑实现的两个背压探针：2/2 通过；确认超过 2 分钟操作期限仍持锁，以及在端口配置之后阻塞。
- 对当前库编译产物运行独立生命周期/重入探针：确认正常退出释放、直接 abort 保活、公开日志转换重入阻塞。
- DoQ writer / VLESS 实现级释放探针：所有者释放后仍保活，解除底层背压后释放。
- 运行当前 `shoes-engine` 单测产物的 `users::tests::`：67/67 通过，覆盖并发 writer、取消 remove 后重试和旧 finalizer 不误删新 generation。
- 临时探针目录：`C:/Users/DING/AppData/Local/Temp/node-agent-lock-lifecycle-review-20260903`。
- DoQ 探针：`C:/Users/DING/AppData/Local/Temp/node-agent-doq-lifecycle-audit/probe.rs`。
- 未进行生产并发压测、长期 RSS 采样或 Linux netlink 实测；结构正确和现有测试通过不能代替这些测量。

原建议处理顺序（现已落实）：先消除持拓扑锁等待进度响应，再补齐 Agent 异常退出的任务清理和公开日志接口的重入边界；同步日志/端口操作与 DoQ writer 随后处理。无需为普通 Arc clone、字段重排或少量用户下的短锁再做大改。
