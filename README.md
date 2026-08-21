# shoes-r

An API-driven proxy engine, built on [`shoes`](https://github.com/cfal/shoes) without
forking it.

Upstream shoes loads a YAML file, starts every listener, and blocks forever: users and
rules are fixed for the life of the process. `shoes-r` keeps that behaviour exactly as
it is and adds a second way in — an `Engine` an embedder drives programmatically, which
can come up with **no inbounds and no users at all** and be populated over whatever API
the embedder already speaks:

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
})?;                              // live on the next handshake

let period = engine.take_inbound_traffic("vless-443")?;
```

Users can be added, suspended and removed on a live listener, each authenticating
independently with per-user byte accounting; rules and protocol settings can be swapped
without disturbing established connections. Every protocol shoes can tell users apart on
is covered: VLESS, VMess, Trojan, Shadowsocks 2022, Hysteria2, TUIC, AnyTLS, NaiveProxy.

## Layout

| path | what it is |
|---|---|
| `shoes/` | upstream, imported verbatim by `git subtree`. **Never restructure it** — it has to stay mergeable. Its extension points live in `shoes/src/dynamic/`. |
| `crates/shoes-engine/` | the integration point: `Engine`, the in-memory user registry, the acceptance suites. This is what an embedder links. |
| `crates/shoes-api/` | the argument and report types `Engine`'s methods take, split out so a conversion layer can name them without linking the proxy engine. |
| `docs/` | the design record. |

There is deliberately **no crate above `shoes-engine`** — no daemon, no wire protocol.
Shipping one would put transport and policy decisions in the repository that has to stay
mergeable, and would make anyone wanting a different transport fork it.

## Documentation

- **[docs/dynamic-engine-design.md](docs/dynamic-engine-design.md)** — the architecture:
  the crate seam, the registry, metering, RCU reload, and a collected invariant
  checklist in §9. **Read this before changing anything under `shoes/src/dynamic/` or
  adding a protocol** — four of those invariants fail silently.
- **[docs/dynamic-engine-plan.md](docs/dynamic-engine-plan.md)** — the schedule the
  conversion followed, each increment annotated with what it actually took.

## Building and checking

```bash
cargo test --workspace
```

The three gates, all of which must be clean:

```bash
cargo fmt --all --check
```

```bash
cargo clippy --workspace --all-targets
```

```bash
cargo test --workspace
```

`shoes/` still emits a handful of upstream warnings, most of them platform-conditional
on Windows; `crates/` and `shoes/src/dynamic/` are expected to be warning-free.

## Adding a protocol

The convention every increment has followed:

1. A registry lookup replaces the inline credential comparison. With no registry
   injected, the config's own credential becomes a one-user `StaticUserRegistry`, so
   behaviour is identical to what it replaced.
2. A disabled user is reported **absent**, never present-but-denied.
3. Metering: the task local where authentication is inline, an explicit
   `Arc<ConnContext>` wherever it crosses a `tokio::spawn`. Getting this wrong is
   silent — TCP still adds up and the user's counters sit at zero.
4. An end-to-end suite under `crates/shoes-engine/tests/`, driving `Engine` in process.
5. All three gates above.
6. A commit message that explains the design decision and **names any pre-existing bug
   the new suite flushed out** — several have turned up that way.
