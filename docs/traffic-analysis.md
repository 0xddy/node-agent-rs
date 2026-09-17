# 流量分类与用户画像采集

Rust agent 使用与 Go agent 相同的 ACP 流量分析协议，面板无需为 Rust 节点增加另一套接收或存储接口。节点上报用户分钟汇总和域名分钟汇总，应用名称、类别与图标仍由面板外部规则文件和前端资源管理。

## 开关与配置

在面板配置中启用采集并重启面板服务：

```toml
[application.traffic_analysis]
enabled = true
```

分析默认关闭，面板通过 `NodeConfig.traffic_analysis` 下发开关和资源限额。节点的引导 TOML 还支持本地强制关闭：

```toml
disable_traffic_analysis = true
```

此项默认为 `false`，修改后需重启 agent。设为 `true` 时优先于面板设置：不挂载分析采集器，不启动分析采样或上报任务，并关闭 TCP / UDP 嗅探，包括面板 provider 设置的嗅探。计费流量、业务转发和遥测继续运行；依赖嗅探所得协议或域名的路由条件将失去这类输入。面板重连、拓扑更新及远程 reload 均不能重新开启嗅探。

每次主会话完成 Hello、打开控制流后，无条件重新读取一次 `GetMachineConfig`。即使拓扑摘要相同，也会得到新开关；摘要未变时继续使用现有用户及代理运行配置，不重复拉用户或重新应用运行时。本地强制关闭会在每次会话配置确认时重新覆盖面板分析开关。

分析配置不参与拓扑摘要与代理配置编译，拓扑回滚不能覆盖主会话确认的分析状态。配置读取失败时，当前代理继续运行，分析保持暂停并随主会话退避重连。

## 断连与数据口径

- 主会话断开时立即暂停分析，作废该代分钟桶和发送队列；旧会话回调不能写入新代统计。
- 开启状态重新连接后，之前已经登记且仍存活的连接从零累计恢复后的字节，不重复增加新建会话数。
- 关闭后重新开启，只登记之后新建的连接。暂停期间的字节和新连接不补采。
- 只有分析连接断开时，单独重建分析连接，沿用当前身份会话与采集代次，不重新 Hello 或读取配置。

统计独立于套餐扣量，只保存纳入 Web 分析的原始上行和下行字节。后台定时读取连接增量，按观测到的 UTC 分钟归桶；关闭连接的尾数由同一采样路径收取一次。只发送已经封口的分钟，不重新打开旧桶，不保存逐连接请求明细。

分析采用应用协议白名单：保留 sniff 识别的 `http`、`tls`、`quic`；FTP、SSH、DNS 及其他协议、未识别协议不进入用户或域名分析汇总，也不计入分析会话数。目标有域名或使用 443 端口都不能代替协议识别。UDP 按实际目标分别判断，仅首次产生符合条件的流量时计一次 association。套餐扣量和原有流量统计继续覆盖全部业务流量，历史分析数据不自动删除。

这里的 Web 是基于当前嗅探能力的筛选口径：TLS / QUIC 也可能承载其他加密应用，DNS over HTTPS 等无法仅凭协议标签与普通 HTTPS 分开。它不等于解密后的请求级网站访问识别。

节点保留已完成的 sniff 观测，不在计数回调中再次解析协议。`domain` 是原始可见 HTTP Host / TLS 或 QUIC SNI，`destination_domain` 单独保存原始请求目标域名；没有观测或请求目标为 IP 时，相应字段为空。大小写、尾点、Unicode 等原样上报，节点只检查 253 字节上限、UTF-8 与 NUL 边界；域名有效性、规范化、主域名提取和站点归属交给面板。协议保留旧 `root_domain`、`domain_source` 字段编号和名称，不再发送这两个字段。

TLS / QUIC ClientHello 包含 `0xfe0d` 扩展时，保留可见外层 SNI 并设置 `ech_present`，包括 GREASE ECH；这个标记不代表 ECH 被接受或已识别加密后的站点。可见域名、请求目标域名和 ECH 标记是独立的分钟聚合维度，已有路由继续使用原来的嗅探结果。

UDP 按实际目标归属，首个被识别目标的域名不能继承到整个 association。用户汇总中的 `identified_*_bytes` 表示可见或请求域名任一非空的字节数，不代表验证过的站点归属；细分预算耗尽也保留这一计数。已确认 Web 协议但没有域名的记录仍保留协议，细分超限时汇入空域名、空请求域名、`ech_present=false`、`app_protocol=unknown` 的降级记录。会话数与域名目标会话数分别统计。

TCP 沿用 300 ms 总超时和首包缓存回放，Hysteria2 默认开启 sniff；VLESS 继续遵循面板 provider 的 sniff 设置。面板分析开关不改变代理路由，本地 `disable_traffic_analysis = true` 则会强制关闭所有 sniff。UDP 的协议识别是有界、被动的分析采集：每个目标只检查最初的有限数据，最多 8 包、64 KiB，QUIC CRYPTO 重组最多 16 KiB、64 个碎片。它不会等待额外 UDP 数据，不会因识别超时关闭 association，也不提供新增 QUIC 协议路由能力。识别预算用尽后业务流量继续正常转发，未确认 Web 协议的目标不再参与分析。

## 高频流量与上报隔离

分析使用独立 TCP / HTTP/2 gRPC 连接、发送任务、限速器和有界内存队列，复用当前认证 session。控制、套餐流量、遥测等业务不会与分析共享同一个 HTTP/2 连接窗口；各连接仍共享进程 CPU、内存及网卡，因此限额同时作用于采集和发送。

| 项目 | 默认值 |
| --- | --- |
| 增量采样周期 | 5 秒，分钟边界额外采样 |
| 每批大小 | 最多 1024 条、256 KiB |
| 发送队列 | 16 MiB，最多等待 20 秒 |
| 发送速率 / 突发 | 256 KiB/s / 512 KiB |
| 单次发送等待 | 1 秒 |
| 分钟域名组合 | 每节点进程最多 20,000 |
| 已确认 Web 的 UDP 目标 | 每节点进程 40,000，每会话 64 |
| 待识别 UDP 计数项 | 每节点进程最多 1,024，且不超过下发的目标上限 |
| 待识别资源子预算 | 总分析内存预算的 1/4，最多 16 MiB |
| 分析内存预算 | 每节点进程 64 MiB |

UDP 待识别资源同时计入子预算与总预算，包含尚未出现 Web 流量的 association、目标包装器、待识别计数和 QUIC 临时缓冲。确认 Web 后转入普通分析预算；非 Web 或识别到期时移除待识别计数、停止分析回调，并归还 association 内并发嗅探名额，不影响业务转发。仍随业务流存活的包装器继续计入子预算，直到释放，避免只清计数却漏算实际内存。每个 association 最多同时嗅探 64 个目标，完成识别后名额可复用；待识别子预算耗尽时会跳过新的 UDP 候选，保护其余分析容量。

面板下发省略值时使用以上默认值，超出安全边界的值会按 Go agent 相同规则收紧。分钟发送附加 0～10 秒错峰，传输重连使用带抖动的退避。域名细分超限时优先保留用户总计，细分记为 `unknown`；队列满、数据过期、内存不足或发送失败时允许丢弃，原因计数随遥测上报。

`AnalysisStream` 没有逐批业务 ACK。节点不重试已交给发送流程的批次，不补报、不落磁盘。发送成功只表示本地 gRPC 消费了请求数据，不表示面板已经写入 ClickHouse。面板的 Redis 队列、批量写入与分类规则均在面板侧处理。

## 配套内核版本

原始域名观测对应 Go agent `d74fc89b40293b8f08cf066e822b5952a7f43c53`；本地分析与嗅探覆盖同步至 `4b503c5`，ACP 契约同步至 `920c670`。配套 `shoes-plus` 使用已发布基线 `32e58642cab6c5b2e1c8fda24fdc3907ae6af112`，并应用本仓库的 `patches/shoes-plus-raw-observations.patch`；`.github/workflows/ci.yml`、`.github/workflows/release.yml` 和 README 的源码构建示例均执行相同的补丁步骤。

本地构建时，在上述干净基线上应用补丁一次；已经包含这些改动的工作区无需重复应用。补丁随本仓库保存，使构建不依赖尚未发布的内核提交。以后内核发布包含此补丁的新提交时，可将固定 SHA 更新到该提交并删除补丁及应用步骤。

## 验证

```bash
cargo test -p acp-proto
cargo test -p node-agent --test analysis_session
cargo test -p node-agent --test analysis_web_only
cargo test -p node-agent --test topology_compile analysis
cargo test -p node-agent analysis
cargo test -p shoes-engine --test analysis
cargo test --manifest-path ../shoes-plus/Cargo.toml --lib dynamic::analysis::tests
cargo test --manifest-path ../shoes-plus/Cargo.toml --lib routing::udp_sniff::tests
cargo test --manifest-path ../shoes-plus/Cargo.toml --lib routing::protocol::tests
```

协议测试校验 Go 源文件校验和、分析配置限额和排除分析字段后的拓扑摘要。真实 tonic 会话测试验证开关切换、配置失败时暂停、重复连接不重新应用拓扑，以及分析连接单独重建时继续复用当前 session；本地强制关闭测试覆盖面板反复开关、重连后不建分析流，并验证每个会话的计费报告正常送达。采集器测试覆盖分钟封口、尾数、统计代次、目标归属和资源边界。

`shoes-engine` 分析测试通过真实 TCP 和 Hysteria2 UDP 转发验证域名、上下行字节及多目标 association 归属。内核测试覆盖包装对象预算释放、预算拒绝后继续转发、QUIC 分片隔离与原包不变，以及 TCP 嗅探的总超时和缓存回放。

`analysis_web_only` 使用真实 VLESS 转发验证 HTTP 进入分析，而 SSH、FTP、原始 TCP、DNS/UDP 不产生分析记录；同时核对所有协议的字节仍完整进入原有计费计数。TLS 回归测试验证 ECH 保留可见 SNI、单独上报标记，并保持完整转发字节和计费。采集器测试还覆盖原始域名与请求域名的独立聚合、混合 UDP 目标、QUIC 首包待识别计数、未知协议和重连会话数。

这些功能测试不替代部署规模下的持续压测；吞吐、CPU 和内存表现应分别在 sniff 关闭、sniff 开启、分析开启三组条件下测量。
