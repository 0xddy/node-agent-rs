# node-agent-rust

[English](README.md) | 中文

上游 [`shoes`](https://github.com/cfal/shoes) 读一个 YAML 文件，启动全部监听器，然后一直阻塞：
用户和规则在进程生命周期内固定不变。`node-agent-rust` 保留这一行为，并在其上增加两样东西：

- **`shoes-engine`** —— 可编程驱动的 `Engine`。启动时可以没有任何入站、没有任何用户，之后由
  嵌入方用它自己的 API 填充。
- **`node-agent`** —— 对外发布的守护进程：Go ACP node agent 的原地替代，数据面用 shoes 取代
  它内嵌的 sing-box。

`shoes/` 仍基于 `git subtree` 与上游同步；集成改动保持集中，以便持续合并上游更新。

## Engine

```rust
let engine = Engine::bootstrap().await?;

engine.add_inbound(InboundSpec {
    tag: "vless-443".into(),
    config: serde_json::json!({
        "address": "0.0.0.0:443",
        "protocol": {"type": "vless", "udp_enabled": true},
    }),
    users: Some(vec![]),          // 动态模式，此刻还没有任何用户
}).await?;

engine.add_user("vless-443", UserSpec {
    id: Some("alice".into()),
    uuid: Some("b85798ef-e9dc-46a4-9a87-8da4499d36d0".into()),
    password: None,
    enabled: true,
    max_conns: None,
    upload_limit_bps: None,
    download_limit_bps: None,
})?;                              // 下一次握手即生效

let period = engine.take_inbound_traffic("vless-443")?;
```

用户可以在活跃的监听器上增加、停用和删除，各自持有独立凭据和字节计数。停用只拒绝新握手，不动
已有会话；删除会吊销凭据、主动关闭该用户的全部会话并收齐最终计数。规则和协议设置的替换不会打断
已建立的连接。

走注册表认证的协议：VLESS、VMess、Trojan、Shadowsocks 2022、Hysteria2、TUIC、AnyTLS、
NaiveProxy。Snell 不在其中，它没有多用户身份机制。未注入注册表时，普通 YAML 配置的认证行为与
上游完全一致。

## node-agent

直接读 Go agent 的扁平引导 TOML，无需改动：

```toml
panel_grpc_endpoint = "grpcs://panel.example.com:443"
machine_id = "replace-with-machine-id"
node_id = "replace-with-node-id"
machine_secret = "replace-with-machine-secret"

ca_cert_path = ""
tls_insecure_skip_verify = false
debug = false
log_file_path = "node-agent.log"
traffic_report_min_delta_bytes = 26214400
```

```bash
cargo build --release --locked -p node-agent --bin node-agent
```

```bash
./target/release/node-agent ./node-agent.toml
```

面板下发的 topology 仍是唯一业务配置来源：在内存中编译成 shoes 入站，事务式应用，任一步失败则
回滚。一次会话跑五条流——control、traffic、telemetry、log、remote control。provider 为
`vless-reality-vision@1` 和 `hysteria2-salamander@1`。Hysteria2 端口跳跃在 Linux 上走原生
nftables 后端；其他平台对非空计划直接拒绝，而不是静默忽略。

`node-agent dev` 未实现。同一组 `machine_id` / `node_id` 上不要让 Go 和 Rust 两个进程同时在线。

发布由手动触发的 **Release node-agent** workflow 产出：裸二进制加 `SHA256SUMS`，覆盖
linux-gnu x86_64/aarch64、windows-msvc x86_64、macOS x86_64/aarch64。

## 目录

| 路径 | 内容 |
|---|---|
| `shoes/` | 上游 subtree。**不要重构。** 扩展点在 `shoes/src/dynamic/`。 |
| `crates/shoes-engine/` | `Engine`、用户注册表、验收测试。嵌入方链接的就是它。 |
| `crates/shoes-api/` | 参数与报告类型，单独拆出，转换层无需链接引擎即可引用。 |
| `crates/acp-proto/` | ACP protobuf、拓扑 digest、与 Go 一致的 HMAC。 |
| `crates/node-agent/` | ACP 会话、拓扑编译器、事务运行时、端口跳跃、遥测与日志。 |
| `docs/` | 设计记录。 |

协议线格式留在 `shoes/`，通用运行时控制留在 `shoes-engine`，面板策略留在 `node-agent`。
`shoes-engine` 不认识 ACP，也不认识 gRPC。

## 文档

- [dynamic-engine-design.md](docs/dynamic-engine-design.md) —— 架构，§9 汇总了全部不变量。
  改动 `shoes/src/dynamic/` 或新增协议前先读它。
- [dynamic-engine-plan.md](docs/dynamic-engine-plan.md) —— 改造排期。
- [node-agent-panel-compatibility.md](docs/node-agent-panel-compatibility.md) —— 引导
  TOML、拓扑支持矩阵，以及每一条拒绝规则。

## 门禁

```bash
cargo fmt --all --check
```

```bash
cargo clippy --workspace --all-targets --locked
```

```bash
cargo test --workspace --locked
```

`--all-targets` 不可省：少了它，约 15,000 行验收测试根本不会被 lint。CI 在 Linux 上跑这三条，
因为 unix socket、`SO_REUSEPORT` 和 TUN 在 Windows 上被 `cfg` 掉了。测试不需要网络。ACP 兼容性
另由 Go 面板的 `TestRustNodeAgentCompatibility` 对 release 产物单独把关。

## 新增协议

1. 用注册表查询替换内联凭据比较；未注入注册表时，配置自带的凭据变成单用户
   `StaticUserRegistry`。
2. 被停用的用户一律报告为"不存在"，而不是"存在但拒绝"。
3. 拿到足够的协议证明后，准入只发生一次，使计数与可移除连接的登记保持原子。
4. `note_auth` 只能作用于不可能被旁路复制的字节。TUIC、VMess、Shadowsocks 2022 因此改在
   handler 中、在一个不可伪造的步骤之后计数。
5. `users` 必须管辖树中每一个 target；任何一个不认证用户的同级 target 都会让整个入站被拒绝。
6. 计量跨越 `tokio::spawn` 时必须显式传 `Arc<ConnContext>`；缺失时被跟踪用户 fail closed。
7. 在 `crates/shoes-engine/tests/` 下补端到端测试，三条门禁全绿，并在提交信息里点名该测试
   暴露出的既有 bug。

第 4、5 条是最常被破坏的。

## 资源上限

认证后：`UserSpec.max_conns`、每条 Hysteria2/TUIC 连接 512 个 UDP 会话、每会话 256 条 AnyTLS
流、256 条 HTTP/2 流。认证前：`shoes/src/tcp/handshake_gate.rs` 限制每个监听器在途握手数
（总计 1024，单源 IP 64）。重放：`shoes/src/replay_filter.rs`（Shadowsocks 60 秒 salt，VMess
240 秒 auth id）。每个上限都是常量，理由写在各自的文档注释里。按 IP 限速、重放过滤器容量上限、
UDP 会话 LRU 淘汰均已评估后刻意不做——不是遗漏。
