# node-agent-rust

English | [中文](README.zh-CN.md)

Upstream [`shoes`](https://github.com/cfal/shoes) reads a YAML file, starts every
listener, and blocks forever: users and rules are fixed for the life of the process.
`node-agent-rust` keeps that behaviour and adds two things on top:

- **`shoes-engine`** — an `Engine` driven programmatically. Comes up with no inbounds and
  no users, populated over whatever API the embedder already speaks.
- **`node-agent`** — the shipped daemon: a drop-in replacement for the Go ACP node agent,
  running shoes where the Go agent embedded sing-box.

`shoes/` remains subtree-derived from upstream. Integration changes stay focused so
upstream merges remain reviewable.

## Engine

```rust
let engine = Engine::bootstrap().await?;

engine.add_inbound(InboundSpec {
    tag: "vless-443".into(),
    config: serde_json::json!({
        "address": "0.0.0.0:443",
        "protocol": {"type": "vless", "udp_enabled": true},
    }),
    users: Some(vec![]),          // dynamic mode, nobody admitted yet
}).await?;

engine.add_user("vless-443", UserSpec {
    id: Some("alice".into()),
    uuid: Some("b85798ef-e9dc-46a4-9a87-8da4499d36d0".into()),
    password: None,
    enabled: true,
    max_conns: None,
    upload_limit_bps: None,
    download_limit_bps: None,
})?;                              // live on the next handshake

let period = engine.take_inbound_traffic("vless-443")?;
```

Users are added, suspended and removed on a live listener, each with its own credential
and byte counters. Suspending refuses new handshakes and leaves current sessions alone;
removing closes the user's sessions and collects final counters. Rules and protocol
settings swap without dropping established connections.

Registry-backed protocols: VLESS, VMess, Trojan, Shadowsocks 2022, Hysteria2, TUIC,
AnyTLS, NaiveProxy. Snell is out — it has no multi-user identity. With no registry
injected, a plain YAML config authenticates exactly as upstream.

## node-agent

Reads the same flat bootstrap TOML as the Go agent, unchanged:

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

Panel topology stays the only source of business config: it is compiled in memory into
shoes inbounds and applied transactionally, rolling back on any failed step. A session
runs five streams — control, traffic, telemetry, log, remote control. Providers are
`vless-reality-vision@1` and `hysteria2-salamander@1`. Hysteria2 port hopping uses a
native nftables backend on Linux; other platforms reject a non-empty plan instead of
ignoring it.

`node-agent dev` is not implemented. Never run the Go and Rust agents on the same
`machine_id` / `node_id` at once.

Releases come from the manual **Release node-agent** workflow: raw binaries plus
`SHA256SUMS` for linux-gnu x86_64/aarch64, windows-msvc x86_64, macOS x86_64/aarch64.

## Layout

| path | what |
|---|---|
| `shoes/` | upstream subtree. **Never restructure.** Extension points in `shoes/src/dynamic/`. |
| `crates/shoes-engine/` | `Engine`, the user registry, the acceptance suites. What an embedder links. |
| `crates/shoes-api/` | argument and report types, split out so a conversion layer need not link the engine. |
| `crates/acp-proto/` | ACP protobuf, topology digest, Go-compatible HMAC. |
| `crates/node-agent/` | ACP session, topology compiler, transactional runtime, port hopping, telemetry, logs. |
| `docs/` | the design record. |

Wire formats stay in `shoes/`, runtime control in `shoes-engine`, panel policy in
`node-agent`. `shoes-engine` knows nothing about ACP or gRPC.

## Docs

- [dynamic-engine-design.md](docs/dynamic-engine-design.md) — architecture; §9 collects
  the invariants. Read it before touching `shoes/src/dynamic/` or adding a protocol.
- [dynamic-engine-plan.md](docs/dynamic-engine-plan.md) — the conversion schedule.
- [node-agent-panel-compatibility.md](docs/node-agent-panel-compatibility.md) (中文) —
  bootstrap TOML, the topology support matrix, and every rejection case.

## Gates

```bash
cargo fmt --all --check
```

```bash
cargo clippy --workspace --all-targets --locked
```

```bash
cargo test --workspace --locked
```

`--all-targets` is load-bearing: without it the ~15,000 lines of acceptance suite are
never linted. CI runs these on Linux, since unix sockets, `SO_REUSEPORT` and TUN are
`cfg`'d out on Windows. The suites need no network. ACP compatibility is gated separately
by the Go panel's `TestRustNodeAgentCompatibility` against a release binary.

## Adding a protocol

1. A registry lookup replaces the inline credential comparison; with no registry, the
   config's own credential becomes a one-user `StaticUserRegistry`.
2. A disabled user is reported absent, never present-but-denied.
3. Admission happens exactly once after sufficient protocol proof, so counting and
   removable-connection registration are atomic.
4. `note_auth` only on bytes that could not have been copied off the wire. TUIC, VMess
   and Shadowsocks 2022 count in the handler after an unforgeable step instead.
5. A `users` list governs every target in the tree; a sibling that authenticates nobody
   refuses the whole inbound.
6. `Arc<ConnContext>` wherever metering crosses a `tokio::spawn`; tracked users fail
   closed without it.
7. An end-to-end suite under `crates/shoes-engine/tests/`, all three gates clean, and a
   commit message naming any pre-existing bug the suite flushed out.

Items 4 and 5 are the ones that keep getting broken.

## Limits

Post-auth: `UserSpec.max_conns`, 512 UDP sessions per Hysteria2/TUIC connection, 256
AnyTLS streams per session, 256 HTTP/2 streams. Pre-auth:
`shoes/src/tcp/handshake_gate.rs` caps handshakes in flight per listener (1024 total, 64
per source IP). Replay: `shoes/src/replay_filter.rs` (Shadowsocks 60s salts, VMess 240s
auth ids). Each is a const with its reasoning in the doc comment. A per-IP rate limiter,
a replay-filter capacity cap and UDP session LRU were evaluated and deliberately not
built — not oversights.
