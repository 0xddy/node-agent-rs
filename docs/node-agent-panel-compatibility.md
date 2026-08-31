# Rust node-agent 面板兼容边界

更新日期：2026-08-26

## 结论

生产模式下，Rust `node-agent` 直接读取现有 Go `node-agent` 的扁平 TOML 引导配置，不需要转换，也不需要改成 shoes YAML。面板下发的 ACP topology 仍是唯一业务配置来源，由 Rust 胶水层在内存中编译为 shoes 配置并事务应用。

切换时可以继续使用原 TOML 文件和原启动参数形态：

```powershell
.\target\release\node-agent.exe C:\path\to\node-agent.toml
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

VLESS provider 的 `sniff` 开关会被显式传入 shoes：`true` 与 Go 一样对每条 TCP 流执行有界嗅探，因此即使原始目标是 IP，domain-only 规则也能使用 HTTP Host / TLS SNI；`false` 明确关闭嗅探。Hysteria2 没有面板 sniff 开关，保持 shoes 的 Auto 模式，只在存在 `protocol` 规则时自动启用。嗅探限制为 300 ms / 64 KiB，读取的首包字节会完整回放；带 SNI/Host/protocol metadata 的 TCP 判定单独绕过 destination-only cache，普通 TCP/UDP 仍可缓存，因此同一 IP:port 上不同 SNI 不会串用决定，也不会让大规则集的 UDP 路由退化成全量线性扫描。

SOCKS5、HTTP CONNECT、Snell 等等待隧道应答的客户端会先收到并 flush 成功应答，再读取应用首包，因而不再固定空等 300 ms。这个时序意味着：仅在确实需要继续读取首包时，客户端可能先看到隧道成功，随后因 sniff 后命中的 reject 或出站连接失败而被关闭；不需要继续读取时仍保留“出站成功后再应答”的原时序。普通 TCP、generic QUIC、Hysteria2、TUIC、TUN，以及 VLESS h2mux 的每个 TCP 子流使用相同的 metadata 与 replay 路径；h2mux 不能再绕过 `protocol` / SNI / Host 规则。只有不会在已接受物理连接内继续产生独立路由工作的 inbound 才使用 logical-flow RCU：新 flow 原子读取当前 selector/handler 与 resolver generation，已经运行的 flow 保持其原代直至结束。SOCKS/Mixed UDP、启用 UDP 的 Hysteria2、TUIC 以及可承载 mux 子流的协议会明确拒绝原地 reload；node-agent 随后走 hard replacement 并关闭旧 connection tree，因此旧 association 不能靠持续创建新 destination 绕过更新后的规则。

QUIC 入站在占用未认证预算前要求地址已验证；首次无 token 的客户端通过标准 QUIC Retry 验证，不能用伪造源地址的 Initial 数据报耗尽全局或单源额度。Hysteria2、TUIC 和 generic QUIC 的 transport handshake 最多占用 admission 15 秒，Hysteria2 H3 setup 另有同样的短上限；整个未认证阶段仍受从入场开始计算、不会被 PING/keepalive 重置的 60 秒绝对 deadline 约束。generic QUIC 另把底层 active-connection quota 与每条 bidi stream 的 pending-handshake gate 分开：首条真正完成协议握手的流只解除 pre-auth deadline，不释放连接额度，因而“成功一条廉价流后以 PING 保持无限空连接”不能绕过 gate。认证失败后转入 VLESS/ShadowTLS/AnyTLS camouflage fallback 的流只释放自己的 stream permit，不会把整个 QUIC connection 误标为已认证；Naive 的请求级延迟认证不在面板 provider 范围内，generic QUIC + Naive 仍受该 60 秒边界。

VMess auth id 与 Shadowsocks 2022 salt 的防重放状态由 inbound 生命周期持有：同一 inbound 的所有 bind IP、展开后的 listener group、热重载 handler generation，以及 Go 兼容 forced reload 真正重建出的新 listener slot 都通过绑定 tag、Engine identity 与 lineage epoch 的 replay lease 共享过滤器；不同 inbound 仍彼此隔离，陈旧或来自另一 Engine 的 lease 不能覆盖更新的命名空间。频繁的面板同步、失败回滚和后续 recovery 都不会重开 VMess ±120 秒或 Shadowsocks salt window。

普通 `ApplyConfig` 的可热更部分继续使用 logical-flow RCU；forced reload、全局 DNS/route/rule-set generation 变化以及真正需要 listener replacement 的路径则按 Go 的 Box 生命周期 hard cutover：先停止完整旧 listener 集并关闭其已认证、未认证和 camouflage fallback 连接，再启动任何 candidate inbound。候选失败时先清理已启动的新代，再恢复完整旧拓扑，不会在事务窗口长期暴露 old/candidate 混合数据面。

远程规则集使用不可变内容快照。下载有 64 MiB 实际读取上限，候选内容先经 shoes 同一解析器验证；只有 shoes 运行时事务成功后才推进磁盘 last-good。刷新失败、解析失败或应用失败都继续使用上一成功版本。

不支持的路由字段不会被忽略后上报 `APPLIED`，而是在改变流量含义之前严格拒绝。当前仍拒绝的专家字段包括：

- 顶层 `auto_detect_interface`、`default_interface`、`default_mark`、`find_process`、`geoip`、`geosite`、`override_android_vpn` 与默认网络策略/类型/fallback 字段；
- 规则中的 source IP/port、private-IP、进程/包名/用户、Wi-Fi/网络类型、GeoIP/Geosite、`rule_set_ip_cidr_match_source` 以及 route/direct/sniff/resolve option 对象；
- VLESS `sniff=false` 时的 protocol 规则；
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
- `predefined` 严格按 Go/miekg 的大小写敏感名称支持 `NOERROR`、`FORMERR`、`SERVFAIL`、`NXDOMAIN`、`NOTIMP`（含历史别名 `NOTIMPL`）、`REFUSED`、`YXDOMAIN`、`YXRRSET`、`NXRRSET`、`NOTAUTH`、`NOTZONE`、`DSOTYPENI`、`BADSIG`、`BADKEY`、`BADTIME`、`BADMODE`、`BADNAME`、`BADALG`、`BADTRUNC`、`BADCOOKIE`；非 NOERROR rcode 以可下转识别的 typed terminal outcome 保留；不接受大小写或空白规范化，也不额外接受 `SUCCESS`；
- reject 的 `default` 与 `method=drop`；drop 同样保留为独立 typed terminal outcome，不与普通 reject 混同；
- `answer`、`ns`、`extra` 中 Hickory 支持的标准 zone-file 文本 RR、Go/miekg 常见但 Hickory 缺失的 URI/LOC/APL/HIP 与 RFC 3597 `TYPE#### \# ...` 文本，以及任意可解码的 base64 wire RR，均在 topology 应用前完成严格、有界校验；base64 与 Go `StdEncoding` 一样只忽略 CR/LF，并按 sing-box 读取第一个完整 RR、忽略仍受输入总量上限约束的尾随字节；
- route 动作的逐规则 Go duration 超时；
- 规则级 `disable_cache`、`rewrite_ttl` 与 EDNS `client_subnet`：node-agent 按源 server 和查询参数生成确定性的私有 upstream 变体，但这些变体按 Go 的 `independent_cache=false` 语义共享一个 DNS-client 级 1024-question LRU，key 只有保留原始大小写的 FQDN 与 A/AAAA 类型；Hickory 自身 cache 关闭。`disable_cache` 绕过读取、singleflight 与写入；ECS 可以命中普通热缓存，冷请求会注入 EDNS subnet 但不 singleflight/写缓存；普通冷请求按“question + 原 transport tag”合并并发，leader 完成后 follower 只重查一次 cache，若 leader 因 TTL 0 或错误未留下热结果，则 follower 与 Go 一样在 singleflight 外并发重试，不把上游 I/O 串行化。`rewrite_ttl` 只作用于冷路径的可缓存响应，不改写已有热缓存；只缓存 NOERROR（含 NODATA）与 NXDOMAIN。正响应按 Answer/Authority/Additional（排除 OPT）的最小非零 TTL，负响应在存在非零 SOA-derived TTL 时精确使用；Hickory 的高层错误会丢弃无有效 SOA 响应中的任意 Answer/Additional RR，这一场景安全退化为 TTL 0、不写缓存，除非面板显式用非零 `rewrite_ttl` 覆盖。TTL 完整保留 `uint32` 范围。裸 IPv4/IPv6 ECS 规范化为 `/32`/`/128`，CIDR host bits 在发包前清零；
- 显式 `system` DNS profile：在受支持的 Unix/Windows 平台一律构造可观察 wire TTL/RCODE、接入共享 question cache 且每五秒刷新配置的解析链；原生系统解析器只保留给“完全未配置 DNS”的隐式默认以及不支持读取系统 DNS 配置的 target，后者若请求高级 query 控制会明确拒绝。普通平台 resolver 先查 hosts，正族命中按 Go 使用 600 秒 TTL，只有另一地址族命中则返回 terminal NOERROR/NODATA TTL 0；`resolv.conf` nameserver 默认按用户顺序串行尝试，`options rotate` 才轮转起始 server，`use-vc`/`usevc`/`tcp` 强制 TCP，`trust-ad` 设置问题的 AD bit。Go 的 `ndots` clamp 为 0..15，timeout/attempts 最小为 1；Go 的 attempts 是总轮数，转换到 Hickory 时减去首次请求。Go 的 `single-request` 控制同一 DNS Exchange 内的搜索名竞速，而 Shoes 地址 Lookup 发出的每次 Exchange 已经只有一个绝对 A/AAAA question，因此没有额外可切换的并包行为。Linux 会先识别 leading systemd marker，再解析可能含 scoped link-local nameserver 的 base 配置；启用 systemd-resolved transport 时与 Go 一样绕过 hosts，只通过固定绝对路径的官方 `resolvectl` 查询 IPv4 或 IPv6 默认路由 link，严格保留 DNSEx server 顺序、显式端口和 `#server_name`，并把 direct TCP/UDP socket 绑定到该 link。有效 `DNSOverTLS=no` 使用明文 DNS（常规查询走 UDP，仅在截断/报文过大时续传同 server TCP）；`yes` 只使用 native-roots DoT；`opportunistic` 在每个 A/AAAA question 的同一个 shared-cache/singleflight 边界内，对每个 server 先 DoT，仅当传输、握手或解码失败后才尝试同 server 明文组，NXDOMAIN/NODATA/其他 DNS RCODE 不降级，两个 transport 组均失败后才进入下一个 server；每个 primary/fallback transport 自身的 Hickory attempts 固定为 0，只有外层 Ordered resolver 控制降级与下一 server，避免单个 server 被重复请求。未显式配置端口时 DoT/明文分别用 853/53，未给 TLS name 时使用去除 zone 的 IP。固定命令缺失/超时/非零退出、未知模式/输出会在首次构建时明确失败；已经确认使用 systemd-resolved 后的刷新失败会立即 fail-closed，绝不继续旧直连或退回可能吞掉 ECS/降级 DoT 的 stub，后续五秒检查成功时自动恢复；普通平台配置刷新失败才保留 last-good。scoped IPv6 link-local 上游依赖 Linux `SO_BINDTODEVICE` 在 scope-id 为零时完成路由，已保留并绑定其 link，但不宣称跨内核完全等价；当前未实现 Go 的进程内 systemd D-Bus 信号监听。Windows 只采纳 up、非 tunnel 且有 gateway 的 adapter；Hickory 的 `IpAddr` 配置无法保留 Windows IPv6 link-local ZoneId，因此这类上游会被明确过滤，若没有其他上游则拒绝构建；同时无法像 Go 的 NetworkManager 那样精确排除被系统报告为非 tunnel 且带 gateway 的 Shoes 自有虚拟网卡；
- reject 的 `no_drop` 会按 sing-box schema 接受并做动作约束校验。Go 的地址查询走 `Router.Lookup`，其默认 reject 在同一规则的滚动 30 秒窗口内前 50 次返回 reset，第 51 次起降级为 drop；`no_drop=true` 禁止该降级。Rust 按相同的逐规则并发安全计数语义执行：inbound-only remove/add 继续使用当前 DNS-client generation 的窗口，完整 DNS/Box reload 与 rollback 重建才重置。

这里的“任意 RR 支持”需要按两个真实边界理解。第一，base64 wire 形式可以承载任意 RR；文本形式先使用 Hickory zone parser，并为 Go `miekg/dns.NewRR` 会接受而 Hickory 缺失的 URI/LOC/APL/HIP 和 RFC 3597 `TYPE#### \# ...` 提供严格兼容解析。URI 文本 target 按 miekg 的 character-string 词法限制为 255 个解码字节，但 URI wire RDATA 的 target 是剩余 octets，不套用这一文本限制。RFC 3597 的已知 TYPE 仍通过 wire decoder 做类型级校验，因此 `TYPE1`/`TYPE28` 会按 A/AAAA 投影；零 RDLENGTH 的已知 TYPE 保留为 update record，不会伪造地址；尚未纳入兼容解析的其他 miekg-only 文本类型仍可用 base64 wire 表达。第二，Go node-agent/sing-box 与 Rust 当前都通过 Router/Lookup 做地址解析，所以运行时只把 `answer` 中的 A/AAAA 投影为地址；其他 RR 以及 `ns` / `extra` 会完整解析校验，但不会进入地址结果。这与当前面板内部解析路径等价，不表示 shoes 已提供通用 DNS wire server。若未来增加 DNS Exchange/hijack 入站并要求回送完整 wire response，需要再扩展 resolver 接口。

DNS route 的 `timeout` 按 Go duration 语法解析，并要求为正数且能精确表示为整毫秒；无法精确落到 shoes 超时单位的值会在应用前拒绝，不做截断或四舍五入。`rewrite_ttl` 按去空白后的十进制 `uint32` 解析，包含 `0`；非法、负数、小数和溢出值均拒绝。Shoes 当前是地址 Lookup API，没有可回送给客户端的 DNS wire RR，因此 TTL 的可观察语义是正/负结果及外层地址缓存的有效期。

这些规则级专家字段不是纯理论选项：ACP、panel-api 的策略 `action_value`、初始 MachineConfig 与实时 route patch 都能携带它们。当前 panel-web 没有对应可见控件；已有 `rewrite_ttl`/`client_subnet` 可被 Web draft 保留，而通过 API 写入的 `disable_cache`/`no_drop` 在再次用 Web 保存策略时可能被移除。运行端仍完整支持，以保证直接 API、未来 UI 和 gRPC 下发兼容。

仍严格拒绝的 DNS 边界是：

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
| selector | 静态选择 `default`，未配时选择第一个成员；允许 Go 接受的重复成员；`interrupt_exist_connections` 保持 bool 类型校验但在静态折叠后为惰性字段；选中 URLTest 时向 route/DNS action 提升其完整 selection | 动态切换控制面不存在，因此不做 round-robin 或伪动态选择 |
| URLTest | 原生活性探测、延迟选择、interval/idle/tolerance，可用于 route 与 DNS detour；同一逻辑 outbound 在 route、DNS、多 inbound 与 TUN 投影中共享一个 generation-scoped selection/worker，跨不同 URLTest group 的延迟历史按 Go `RealTag` 共享。周期 probe 失败删除 `RealTag` 历史，live dial 失败按 Go 的原始 member tag 删除；连接失败默认保留 selected。探测使用无 inbound context 的 generation-global DNS sidecar。HTTP HEAD wire 对齐 Go 的 Basic Auth、User-Agent、LF/CRLF/混合换行、非 101 的 1xx、累计 10 MiB header 与 transfer metadata 校验；无效 URL 在 topology ACK 后异步探测失败。Trojan/VLESS 最终 hop 的计时起点对齐 Go 的首次协议写入：不计 socket、前序 hop 和最终 transport TLS/REALITY/WS/ShadowTLS 建链，计入最终协议头、目标 TLS 与 HTTP HEAD RTT。shoes 另提供默认关闭的 `reselect_on_connection_failure` 解耦增强，node-agent 固定关闭 | nested URLTest、`interrupt_exist_connections=true`、未知字段或不能精确表示的 duration |

所有代理出站均支持引用/环检测；目录校验会线性遍历 selector 的全部成员、URLTest 的全部成员和 detour，包括运行时未选中的边，而静态 selector 投影只编译选中分支。引用 tag 使用目录中的精确字符串身份（非全空白 tag 的首尾空白不会在查找或环检测时被改写）。任意引用路径最多包含 128 个 outbound；这是 Rust 为避免控制面配置触发递归栈/资源耗尽而增加的 fail-loud 治理边界，不宣称 Go 有同一上限。一次 `RuntimeConfig` 中实际生成的 client-chain 投影还共同受 65,536 hop 和 64 MiB JSON 上限约束，累计所有 inbound 的 route、DNS detour 与 DNS profile variant 副本；active URLTest 另受每个 RuntimeConfig 最多 256 个 distinct group、合计 8,192 个 candidate 的 fail-loud 边界，同一 generation 的实际网络 probe 共享 10 个并发许可。最后一项只在大量 group 同时收敛时延后探测，不改变稳定 selection/history 语义；旧 generation 被替换时，许可排队和进行中的 probe 均可取消。URLTest 按每个直接 member 的一层 Go `RealTag`（selector 的立即 selected tag，非 selector 的自身 tag）只保留首次出现的候选，随后才为实际链递归静态折叠 selector。这使重复 member 和直接选中同一 tag 的 selector alias 共享一次 probe/history，同时保留嵌套 selector 每一层不同的 Go 身份。整次投影会对 selector 到 terminal 的路径做压缩；validated catalog 为每个 outbound 分配稳定数字身份，terminal/selected 缓存保存借用 handle，链样本与 URLTest RealTag 集按数字身份索引，因此 alias 不会复制或反复比较长 tag。adapter 对 detour 内共享 selector 的选中 handle、cache key 与 active path 也使用 catalog 数字身份，而不缓存每层完整链后缀，避免宽共享子图的重复扫描、长 tag 的重复复制/比较和深链的二次方缓存。不同 `RealTag` 即使落到同一 terminal，仍按 Go 语义分别发射并逐项计入预算；大量不同实际 member 共享深 detour 后缀时也会在最终组装 chain 前 fail-loud。该累计边界同样是 Rust 资源治理限制，不是 Go schema 限制。可证明等价的 `detour` 会编译为有序多跳链；URLTest 只能位于 action 根（允许先经过静态 selector），经 selector 或 detour 间接嵌入另一 active URLTest 仍拒绝。每个 hostname hop 使用绑定到该 hop 的命名 resolver，并依次尝试其全部地址；IP predicate 为路由判定检查全部候选并保留完整有序答案，最终 direct TCP/QUIC/UDP 拨号不会被截断成单地址。外层 hop 更换候选地址时会重新构建并重新解析完整 detour 前缀，不会复用已经失败的内层 socket。VLESS XUDP 建流时依次尝试全部候选，session 边界保留原 hostname、最终选中的候选和独立回包地址；响应帧回显原 hostname 时复用建流前已解析的固定目标，意外 hostname 会拒绝、同 session 的其他 literal IP 允许，不会逃逸到操作系统 DNS。当前出站同时配置 detour 和本地 dialer 字段时会拒绝，因为 sing-box 会绕过当前出站的本地 dialer，而把这些字段套到 shoes hop zero 会改变语义。

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
- 显式非空 `connect_timeout` 不支持。DNS 候选只在创建、绑定并 `connect` 实际交给 Quinn 的 UDP socket 失败时依次前进；第一个 socket 准备成功后只执行一次 QUIC + TLS + H3 认证，并共享一个 15 秒预算，握手/认证失败不会误判成地址候选失败后再试下一项；
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
$goPanelTestDir = 'C:\path\to\go-node-agent\test'
$rustRepo = 'C:\path\to\node-agent-rust'
Set-Location -LiteralPath $goPanelTestDir
$env:ACP_RUST_NODE_AGENT_BIN = Join-Path $rustRepo 'target\release\node-agent.exe'
go test ./cmd/acp-test-panel -run '^TestRustNodeAgentCompatibility$' -count=1 -v
```

该门禁覆盖 Hello/HMAC、digest、控制 ready 与两阶段 ACK、Config/Control/Traffic/Telemetry/Log/Remote service 以及进程优雅退出；数据面协议、路由、DNS 与事务回滚由 Rust 单元和集成测试覆盖。

2026-08-27 本批最终源码已通过上述全部 Rust 门禁；Windows 全工作区 all-targets 中 shoes lib/bin 各 1285 项通过，Linux Docker 独立通过 workspace all-targets check、node-agent 全目标、shoes-engine 全目标及 shoes 1293 项 library tests。随后重新构建 `target/release/node-agent.exe` 并通过 Go `TestRustNodeAgentCompatibility`，没有复用旧 release 结果；最终只读多代理审计未发现可复现 P0-P2。

## 仍需真实环境验证

本地门禁覆盖编译、schema preflight、事务回滚、真实 ACP release 进程兼容测试面板，以及入站/出站协议链路。正式无缝切换仍应在 Linux 节点做单机灰度，重点对比在线人数、流量曲线、DNS/路由命中、原生 UDP 与 nftables 端口跳跃；这需要真实面板凭据和维护窗口，不能由仓库测试替代。
