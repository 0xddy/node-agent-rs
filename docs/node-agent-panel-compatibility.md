# Rust node-agent 面板兼容边界

更新日期：2026-08-26

## 结论

生产模式下，Rust `node-agent` 直接读取现有 Go `node-agent` 的扁平 TOML 引导配置，不需要转换，也不需要改成 shoes YAML。面板下发的 ACP topology 仍是唯一业务配置来源，由 Rust 胶水层在内存中编译为 shoes 配置并事务应用。

切换时可以继续使用原 TOML 文件和原启动参数形态：

```powershell
G:\Development\Project\shoes-r\target\release\node-agent.exe C:\path\to\node-agent.toml
```

唯一的 CLI 例外是 Go 的 `node-agent dev` 本地开发辅助子命令：Rust 版本目前不实现它。该子命令直接加载 sing-box JSON，不参与生产 ACP 会话，也不影响现有生产 TOML 的无缝切换。

同一个 `machine_id` / `node_id` 不能让 Go 和 Rust 两个进程同时在线；灰度时先停止旧进程，再启动 Rust 进程。

## 引导 TOML

下列字段、缺省值和核心校验顺序与 Go 实现对齐：

| 字段 | 兼容情况 |
|---|---|
| `panel_grpc_endpoint` | 直接兼容，支持 `grpc://` 与 `grpcs://` |
| `machine_id`、`node_id`、`machine_secret` | 直接兼容 |
| `ca_cert_path`、`tls_insecure_skip_verify` | 直接兼容；显式 CA 要求至少一张可解析 X.509，混合坏 PEM block 时保留有效证书 |
| `debug`、`log_file_path` | 直接兼容 |
| `traffic_report_min_delta_bytes` | 直接兼容；缺省仍为 25 MiB，显式 0 仍拒绝 |

规则集缓存、拓扑快照和刷新状态是 Rust 的内部运行数据，不会增加必填 TOML 字段。

控制面 TLS root 合并也按 Go 的容错边界处理：系统 native root 为空不会提前挡住显式私有 CA；没有有效 X.509 的 CA 文件仍作为配置错误拒绝，而不是让 tonic 静默忽略。node-agent 编译出的数据面 TLS（Trojan/VLESS、Hysteria2 client、URLTest HTTPS probe、加密 DNS upstream 与 Hysteria2 proxy masquerade）也显式使用操作系统信任策略；系统 verifier 按进程缓存复用，初始化失败时加密握手 fail closed，但不会 panic 或回退到 bundled roots。明文 system/UDP/TCP DNS 不加载系统 TLS 根。独立 shoes YAML 未启用 `use_native_roots` 时仍使用历史 bundled WebPKI roots，避免改变上游默认行为。

端点的普通域名、IPv4、无 zone IPv6，以及 URI 可表示的 RFC 6874 scoped IPv6（例如 `%25eth0`）均可直接使用。解析前会按 Go `net/url` 的 host 词法拒绝控制字符、非法/ASCII percent escape 与 host 中不允许的裸字符，避免 WHATWG 解析静默删除或规范化后连接到另一地址。一个极端词法例外是：Go 允许 zone 解码后包含空格等 HTTP URI 非法字符（例如 `%25Ethernet%202`），tonic 无法把它表示为 endpoint；Rust 会在配置阶段明确拒绝，而不是接受后在拨号时失败。

日志安全语义也已对齐：Unix 文件保持 `0600`，Windows 活动日志和备份使用 protected DACL 且仅当前用户拥有访问 ACE。Rust panic 会尽力以非阻塞方式写入并同步当前 `log_file_path`，随后以状态码 2 退出；若 panic 正发生在持有 logger/file 锁的代码中，为避免崩溃钩子死锁，文件写入可能跳过。稳定 Rust 也只能抓取 panic 线程的 backtrace，无法像 Go `runtime.Stack(..., true)` 枚举进程内所有线程栈。这些是崩溃诊断信息上的已知差异，不影响正常运行或 ACP 协议。

## 解耦边界

增强按三层放置，避免把面板模型侵入 shoes：

| 层 | 职责 |
|---|---|
| `crates/node-agent` | ACP/gRPC、Go 业务语义、面板 topology 校验和翻译 |
| `crates/shoes-engine` | 入站生命周期、动态用户、计量和事务运行时 |
| `shoes` | 可独立复用的数据面能力：路由 predicate、SRS、DNS policy、socket dialer、URLTest、原生代理客户端 |

shoes 不认识 ACP protobuf、machine/node ID 或面板资源 ID。既有 shoes YAML 中未配置这些新增可选字段时，行为保持不变。

## 面板 topology 支持矩阵

### 入站与控制面

| 能力 | 状态 |
|---|---|
| ACP 认证、控制流、两阶段 ACK、拓扑 digest | 已实现 |
| Config / Control / Traffic / Telemetry / Log / Remote gRPC service | 已实现 |
| VLESS + REALITY + Vision 入站 | 已实现 |
| Hysteria2 + Salamander + Brutal + masquerade 入站 | 已实现 |
| 动态用户、限速、连接数、踢线、凭据轮换 | 已实现 |
| Hysteria2 入站端口跳跃 | Linux 已实现；Windows 与 Go 一样是会告警的开发期 no-op；其他平台返回 capability error |

### 路由

面板当前编辑器会产生的以下条件可直接翻译：

- `domain`、`domain_suffix`、`domain_keyword`、`domain_regex`
- `inbound`
- `ip_cidr`、面板自动生成的 `ip_version`
- `port`、`port_range`
- `network=tcp|udp`
- `invert`
- `protocol=http|tls`
- 本地、远程、source JSON 与 binary SRS 规则集，以及 headless logical rule
- 顶层直接条件与 `rule_set` 的混写；destination-address 与 destination-port 分别按 sing-box 的类别状态合并，同类别可由直接字段或规则集命中，不同类别仍保持 AND
- `route`、`reject`、`reject-drop`、`final`

`protocol` 只在 VLESS provider 的 `sniff=true` 时启用。嗅探按需执行，限制为 300 ms / 64 KiB；HTTP Host 和 TLS SNI 可参与后续域名规则，读取的首包字节会完整转发。没有 protocol 规则时不读取应用数据，也不会增加 300 ms 等待。

远程规则集使用不可变内容快照。下载有 64 MiB 实际读取上限，候选内容先经 shoes 同一解析器验证；只有 shoes 运行时事务成功后才推进磁盘 last-good。刷新失败、解析失败或应用失败都继续使用上一成功版本。

不支持的路由字段不会被忽略后上报 `APPLIED`，而是在改变流量含义之前严格拒绝。当前仍拒绝的专家字段包括：

- 顶层 `auto_detect_interface`、`default_interface`、`default_mark`、`find_process`、`geoip`、`geosite`、`override_android_vpn` 与默认网络策略/类型/fallback 字段；
- 规则中的 source IP/port、private-IP、进程/包名/用户、Wi-Fi/网络类型、GeoIP/Geosite、`rule_set_ip_cidr_match_source` 以及 route/direct/sniff/resolve option 对象；
- Hysteria2 入站上的 protocol sniff 规则，以及 VLESS `sniff=false` 时的 protocol 规则；
- VLESS 入站 `tcp_fast_open=true`。

这些字段大多不由当前面板编辑器产生；若以后面板开始使用，应先补 shoes 的通用能力，再放开 node-agent 翻译。

### DNS

当前面板内部使用的 Router/Lookup 地址解析路径已原生覆盖：

- 有序的 exact / suffix / keyword / regex 域名规则；
- 按 inbound 投影规则；
- local/remote、source JSON、binary SRS 与 inline headless rule-set 中的域名规则；inline DNS rule-set 支持 logical/invert，若包含 IP、端口、network、protocol 或其他地址 Lookup 无法观察的条件会在应用前拒绝；
- 直接域名条件与 rule-set 混写时复用 shoes 路由 predicate 的 sing-box 类别状态合并，不会退化成普通 AND，也不会静默放宽；
- 转发到指定 DNS server、默认 final server；
- system、UDP、TCP、DoT、DoQ、DoH、DoH3 upstream；
- DNS server 的 outbound detour，以及面板生成的 Direct “同出口 DNS”拓扑；
- DoQ / DoH3 的非直连 detour 通过 shoes 通用 QUIC datagram adapter 执行：目标地址固定，每个代理 message 对应一个 QUIC packet，并使用有界发送队列；不支持 UDP 的 chain 会在启动前拒绝，不会退回直连；
- 每个出站独立的 `domain_resolver`，含空策略、`prefer_ipv4`、`prefer_ipv6`、`ipv4_only`、`ipv6_only`；需要不同地址族顺序时生成私有 upstream 变体，不扩大成全局 DNS 策略；
- `predefined` 的 `NOERROR`、`NXDOMAIN`、`REFUSED`、`SERVFAIL`；非 NOERROR rcode 以可下转识别的 typed terminal outcome 保留；
- reject 的 `default` 与 `method=drop`；drop 同样保留为独立 typed terminal outcome，不与普通 reject 混同；
- `answer`、`ns`、`extra` 中 Hickory 支持的标准 zone-file 文本 RR，以及任意可解码的 base64 wire RR，均在 topology 应用前完整解析和有界校验；
- route 动作的逐规则 Go duration 超时。

这里的“任意 RR 支持”需要按两个真实边界理解。第一，base64 wire 形式可以承载任意 RR；文本形式使用 Hickory zone parser，覆盖面板常用记录，但 Go `miekg/dns.NewRR` 接受而 Hickory 尚不接受的部分 DNSSEC 文本与 RFC 3597 unknown `TYPE#### \# ...` 文本必须改用 base64 wire，否则 topology 会明确拒绝。第二，Go node-agent/sing-box 与 Rust 当前都通过 Router/Lookup 做地址解析，所以运行时只把 `answer` 中的 A/AAAA 投影为地址；其他 RR 以及 `ns` / `extra` 会完整解析校验，但不会进入地址结果。这与当前面板内部解析路径等价，不表示 shoes 已提供通用 DNS wire server。若未来增加 DNS Exchange/hijack 入站并要求回送完整 wire response，需要再扩展 resolver 接口。

DNS route 的 `timeout` 按 Go duration 语法解析，并要求为正数且能精确表示为整毫秒；无法精确落到 shoes 超时单位的值会在应用前拒绝，不做截断或四舍五入。

仍严格拒绝的 DNS 专家控制是：

- 规则级 `no_drop`、`disable_cache`、`rewrite_ttl`、`client_subnet`；
- `route.default_domain_resolver` 与 `dns.final` 不同，或它携带 strategy/cache/TTL/client-subnet 控制；
- plain UDP upstream 配非直连 detour，或 DoQ / DoH3 detour 没有任何 UDP-capable chain；
- selector/urltest 自身声明 `domain_resolver`，因为这两类对象不是 sing-box dialer；
- 未知 server、未知 rule-set、无匹配条件，以及 DNS Lookup 无法观察的 rule-set 条件。

### 出站与拨号

| 出站 | 原生支持范围 | 仍严格拒绝的边界 |
|---|---|---|
| Direct | TCP/UDP；interface、IPv4/IPv6 源地址、Linux mark、connect timeout、Linux bind-address-no-port、逐出站 DNS resolver | 下表列出的 sing-box 专家 dialer 字段 |
| Shadowsocks | TCP；SIP003 legacy AEAD 与 2022 原生 UDP；显式 UoT v2；网络缺省为 TCP+UDP | UDP-only；原生 UDP 与 detour 同时使用；UoT 非 v2 |
| Trojan | TCP + 原生 UDP-over-TCP；普通 TLS | UDP-only；普通 TLS 字段以外的扩展 |
| VLESS | TCP；legacy CommandUDP、XUDP、packetaddr；普通 TLS / Vision | UDP-only；未知 flow/packet encoding；Vision 未配 TLS |
| Hysteria2 client | QUIC 原生 TCP stream 与 UDP datagram、H3 auth、Salamander、Brutal up/down、TLS/SNI/insecure、连接复用 | 见下方 Hysteria2 限制 |
| selector | 静态选择 `default`，未配时选择第一个成员 | 动态切换控制面不存在，因此不做 round-robin 或伪动态选择 |
| URLTest | 原生活性探测、延迟选择、interval/idle/tolerance，可用于 route 与 DNS detour；Trojan/VLESS 最终 hop 的计时起点对齐 Go 的首次协议写入：不计 socket、前序 hop 和最终 transport TLS/REALITY/WS/ShadowTLS 建链，计入最终协议头、目标 TLS 与 HTTP HEAD RTT。连接失败默认只清延迟历史并保留 selected（与 Go 一致）。shoes 另提供默认关闭的 `reselect_on_connection_failure` 解耦增强，node-agent 固定关闭 | nested URLTest、`interrupt_exist_connections=true`、未知字段或不能精确表示的 duration |

所有代理出站均支持引用/环检测；可证明等价的 `detour` 会编译为有序多跳链。当前出站同时配置 detour 和本地 dialer 字段时会拒绝，因为 sing-box 会绕过当前出站的本地 dialer，而把这些字段套到 shoes hop zero 会改变语义。

仍拒绝的 Direct/sing-box 专家 dialer 字段包括：

- `reuse_addr`、`tcp_fast_open`、`tcp_multi_path`、`udp_fragment`、`udp_timeout`；
- `domain_strategy`、`network_strategy`、`network_type`、`fallback_network_type`、`fallback_delay`；
- `protect_path`、`netns`；
- `disable_tcp_keep_alive`、`tcp_keep_alive`、`tcp_keep_alive_interval`；
- `override_address`、`override_port`；
- Direct 自身的 `detour`。

Hysteria2 client 的严格限制是：

- `server_ports` / `hop_interval` 出站端口跳跃尚未实现；
- 自身 `detour` 不支持，因为 Hysteria2 必须拥有底层 UDP/QUIC socket 并位于链首；
- 显式非空 `connect_timeout` 不支持。当前对 DNS 解析后的全部候选地址、QUIC + TLS + H3 认证维持一个共享 15 秒总预算，不会按地址重置成 `N × 15s`，也不能把 dial timeout 错套到整段握手；
- `bind_address_no_port=true` 尚未落到 Hysteria2 UDP socket；
- `brutal_debug=true` 没有 shoes 对应控制；
- `network=udp` 的 UDP-only 模式拒绝；省略、`null`、空数组或 TCP+UDP 均按 Go 语义接受；
- TLS 必须启用；obfs 只接受 Salamander；其他 TLS/obfs 未知字段拒绝。

面板自动生成的单栈 Direct、`ip_version` 拒绝 guard、同出口 DNS clone 会作为一个整体校验；不能证明等价的 resolver strategy 或循环引用不会被消费。

## 自动化门禁

测试总数会随 shoes 上游变化，因此文档不固化容易漂移的数字。最终合入以以下命令全部通过为准：

```powershell
cargo fmt --all -- --check
cargo test --workspace --all-targets --locked
cargo clippy -p node-agent --all-targets --locked -- -D warnings
cargo clippy -p shoes --lib --locked -- -D warnings
cargo build --release --locked -p node-agent --bin node-agent
```

并使用当前 release 产物跑 Go 原仓库的真实 ACP 兼容门禁：

```powershell
Set-Location 'G:\Development\Project\国际机场\node-agent\test'
$env:ACP_RUST_NODE_AGENT_BIN='G:\Development\Project\shoes-r\target\release\node-agent.exe'
go test ./cmd/acp-test-panel -run '^TestRustNodeAgentCompatibility$' -count=1 -v
```

该门禁覆盖 Hello/HMAC、digest、控制 ready 与两阶段 ACK、Config/Control/Traffic/Telemetry/Log/Remote service 以及进程优雅退出；数据面协议、路由、DNS 与事务回滚由 Rust 单元和集成测试覆盖。

2026-08-26 本批代码已通过上述全部 Rust 门禁，并用刚构建的 `target/release/node-agent.exe` 通过 Go `TestRustNodeAgentCompatibility`；没有复用旧 release 结果。

## 仍需真实环境验证

本地门禁覆盖编译、schema preflight、事务回滚、真实 ACP release 进程兼容测试面板，以及入站/出站协议链路。正式无缝切换仍应在 Linux 节点做单机灰度，重点对比在线人数、流量曲线、DNS/路由命中、原生 UDP 与 nftables 端口跳跃；这需要真实面板凭据和维护窗口，不能由仓库测试替代。
