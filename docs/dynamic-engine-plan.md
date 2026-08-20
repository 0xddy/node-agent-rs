# Dynamic engine: remaining work

The plan of record for `feature/dynamic-engine`. Written 2026-08-21, after the TUIC
increment landed as `6f163d9`.

The goal has not changed: turn `shoes` from a static config-file CLI into an
API-driven dynamic engine by 微创手术 — minimally invasive edits, so upstream stays
mergeable. Protocols are converted one at a time to authenticate through
`Arc<dyn UserRegistry>` and to meter traffic through `ConnContext`.

## Where things stand

| Protocol | Registry auth | Metering | Commit |
|---|---|---|---|
| VLESS | yes | yes | (earlier) |
| Trojan | yes | yes | (earlier) |
| VMess | yes | yes | `42e5bef` |
| Shadowsocks 2022 | yes | yes | `d5c9ae3` |
| Hysteria2 | yes | yes | `d439df4` |
| TUIC v5 | yes | yes | `6f163d9` |
| AnyTLS | yes | yes | increment 2 |
| **NaiveProxy** | **no** — own `UserLookup` | **no** — auth is past a `tokio::spawn` | increment 3 |
| Snell | n/a | n/a | out of scope: no multi-user identity mechanism exists |

Rules hot-reload works for every inbound, including Hysteria2 and TUIC — see
increment 1, which has landed.

One increment remains.

---

## 1. Rules hot-reload for the QUIC-native inbounds — **landed**

Built as designed below. `SelectorSlot` sits beside `HandlerSlot` in
`shoes/src/dynamic/reload.rs`; the two QUIC-native arms of `start_quic_servers`
record one per bind address and their accept loops `load()` once per accepted
connection. The settings comparison went the way the decision section proposes,
with one refinement found on contact with the code: a dynamic inbound's config
credential is a placeholder the engine regenerates on every `update_inbound`, so it
carries no operator intent and is excluded from the comparison — `FixedProtocol`
records whether a registry was injected so it knows to skip it. Without a registry
the credential is real and is compared.

Covered by four unit tests in `reload.rs` and
`a_quic_native_inbound_swaps_its_rules_in_place` in
`crates/shoes-engine/tests/reload.rs`.

<details>
<summary>The original plan, kept as the design record</summary>

### The gap

`ServerHandle::reload` swaps an `Arc<dyn TcpServerHandler>` held in a `HandlerSlot`.
Hysteria2 and TUIC never build a `TcpServerHandler` — they authenticate inside their
own QUIC accept loops — so `ServerHandle.slots` is empty for them and `check_reload`
refuses outright:

> this protocol authenticates inside its own accept loop, so its settings are fixed
> until the listener is replaced

Their `Arc<ClientProxySelector>` is instead baked in at `start_hysteria2_server` /
`start_tuic_server` time and cloned per accepted connection. So the rules an operator
edits never reach a running QUIC inbound; the only way to change them is to remove and
re-add the inbound, which drops every established connection.

### The design

`SelectorSlot`, an exact analogue of `HandlerSlot`:

```rust
pub struct SelectorSlot {
    current: ArcSwap<ClientProxySelector>,
    generation: AtomicU64,
}
```

The safety argument transfers unchanged, and it is worth restating because it is the
whole reason this needs no draining: the accept loop calls `load()` **once per
accepted QUIC connection** and hands that `Arc` to the connection's loops. The
connection is therefore pinned to the generation it started on, and a `store` can only
change what the *next* `load` returns. The old selector is freed when its last
connection ends. That is the entire grace period.

`ClientProxySelector` is already `Sized`, unlike `dyn TcpServerHandler`, so no
`HandlerCell`-style indirection is needed.

### Changes

**`shoes/src/dynamic/reload.rs`**
- Add `SelectorSlot` beside `HandlerSlot`, with the same `load` / `store` /
  `generation` surface.
- `ServerHandle.selectors: Vec<Arc<SelectorSlot>>`, plus a
  `push_selector(&mut self, selector) -> Arc<SelectorSlot>` for the start functions.
- `generation()` takes the max across both slot kinds.
- `check_reload`: the "nothing to swap" refusal becomes `slots.is_empty() &&
  selectors.is_empty()`.
- `reload()`: after building the shared `Arc<ClientProxySelector>` it already builds,
  store it into every selector slot as well as rebuilding the handlers. Keep the
  existing all-or-nothing shape — everything fallible before the first `store`.

**`shoes/src/quic_server.rs`**
- The Hysteria2 arm (the comment at `:474`) and the TuicV5 arm (`:508`) register a
  selector slot instead of explaining why they cannot.
- Both pass `Arc<SelectorSlot>` where they now pass `Arc<ClientProxySelector>`.

**`shoes/src/hysteria2_server.rs`, `shoes/src/tuic_server.rs`**
- `start_*_server` and `process_connection` take `Arc<SelectorSlot>`.
- `process_connection` calls `load()` once, right after authentication, and everything
  below it keeps taking `Arc<ClientProxySelector>` exactly as today. The four TUIC
  loops and Hysteria2's three are untouched.

### The decision this forces

For these two protocols a reload can swap **rules only**. `udp_enabled`,
`zero_rtt_handshake`, the credential and the QUIC certificates all live in the accept
loop or the endpoint, not behind anything swappable. (Certificates are already fixed
for every QUIC inbound — `reload`'s own docs say so.)

Silently ignoring a changed `udp_enabled` would be fail-open, and the failure would be
invisible until someone noticed UDP still working. So: have `ServerHandle` remember
the `ServerProxyConfig` these arms started with, compare it on reload, and reject a
config that changes anything but the rules — with a message naming the field that
cannot change in place. That matches how `check_bind_location` already refuses a
changed listen set.

### Tests

Extend `crates/shoes-engine/tests/reload.rs`, which already owns this property for
TCP. Using `redirect_to(dest)` rules and two named sinks:

- a connection opened after the swap reaches sink B;
- a connection established before the swap still reaches sink A, and completes;
- users, credentials and counters survive the swap untouched;
- a config that changes `udp_enabled` is refused, and the inbound keeps serving.

`a_handle_without_slots_refuses_to_reload` (`reload.rs:575`) stays valid — a handle
with neither kind of slot still refuses — and gains a sibling for the selectors-only
case that reloads successfully.

**Risk: moderate.** This touches the reload core every other inbound depends on. The
mitigation is that `SelectorSlot` is additive: nothing existing changes shape.

</details>

---

## 2. AnyTLS — **landed**

Built as designed below. Both questions the handler asks go to the registry:
`find_password_sha256` for the full 32 bytes and `has_password_sha256_prefix` for the
8-byte probe, the latter documented and tested as ignoring `is_enabled` so a
suspension stays unobservable. The engine's prefix index is the refcounted
`DashMap<[u8; 8], usize>` the plan calls for.

Two things the plan got right and one it did not anticipate: the list-shaped
placeholder became `PLACEHOLDER_USER_LISTS`, which NaiveProxy will reuse — but
AnyTLS's `users` is a `OneOrSome`, which refuses an *empty* list, so the placeholder
has to **insert** a one-element throwaway rather than merely reject a declared one.
Separately, AnyTLS is the first protocol here whose config was already multi-user, so
the classic-mode fallback loads *every* declared user into a static registry rather
than one.

<details>
<summary>The original plan, kept as the design record</summary>

### The gap

`AnyTlsServerHandler` carries its own two-level table built from config
(`anytls_server_handler.rs:35`, `:39`):

```rust
users: HashMap<[u8; 32], String>,      // SHA-256(password) -> user name
hash_prefixes: HashSet<[u8; 8]>,       // first 8 bytes of each hash
```

The prefix set is not an optimisation. AnyTLS peeks 8 bytes (`:117`) and, on a miss,
diverts the connection to its fallback destination *without waiting for the full 32* —
which is what stops a prober from hanging the handler. Only on a prefix hit does it
read all 32 and look up the real hash (`:131`).

### Registry additions

Two methods, because the handler asks two different questions:

```rust
fn find_password_sha256(&self, hash: &[u8; 32]) -> Option<Arc<UserContext>>;
fn has_password_sha256_prefix(&self, prefix: &[u8; 8]) -> bool;
```

The probe must stay a *plausibility* test. `true` means "keep reading", never "this
user exists" — and a disabled user must still answer `true`, or the fallback becomes
an oracle for which users are suspended. Say so in the trait docs, the way
`find_tuic_uuid` says it does not authenticate.

`CredentialKinds` gains `anytls_password: bool`. AnyTLS starts from the same cleartext
`password` field Trojan and Hysteria2 do — it is a third derivation of one value, not a
third meaning — so it is not a `conflict()` with either.

### The new shape to watch

Every protocol converted so far declares its credential as a **leaf field**
(`user_id`, `password`), which `PLACEHOLDER_FIELDS` fills with a throwaway. AnyTLS
declares a **list** of `{name, password}` objects instead. A throwaway list makes no
sense, so `install_placeholder_credentials` needs a second behaviour for this shape:
reject a non-empty `users` list on a dynamic inbound, and leave an absent one absent.
NaiveProxy has the same shape, so solve it here and increment 3 inherits it.

Second thing to watch, in the engine's `MemoryUserRegistry`: the prefix index needs a
count, not a set. Two users can share an 8-byte prefix, and removing one must not blind
the probe to the other. A `DashMap<[u8; 8], usize>` refcount, decremented on removal
and on rotation, is the smallest thing that is correct.

### Files

- `shoes/src/dynamic/registry.rs`, `static_registry.rs` — the two methods, plus
  `add_anytls_password` / `single_anytls_password`.
- `crates/shoes-engine/src/users.rs` — `by_anytls_hash: DashMap<[u8; 32], Arc<Entry>>`
  and the prefix refcount; maintain both in `upsert` and `remove`.
- `crates/shoes-engine/src/protocol.rs` — `ServerProxyConfig::Anytls` moves out of the
  not-wired-up arm; the list-shaped placeholder rule.
- `shoes/src/anytls/anytls_server_handler.rs` — take `Arc<dyn UserRegistry>`, replace
  both lookups.
- `shoes/src/tcp/tcp_server_handler_factory.rs:314` — **the Anytls arm destructures a
  config field named `users`, shadowing the `users: Option<&Arc<dyn UserRegistry>>`
  parameter.** Rename before touching anything else in that arm.

### Metering

Nothing to thread. AnyTLS authenticates inline in `setup_server_stream`, *before* its
`tokio::spawn` at `:175`, so `bind_connection_user` reaches the context through the
task local like every TCP protocol. This is the easy one.

### Tests

`crates/shoes-engine/tests/anytls.rs`. Unlike Hysteria2 and TUIC, shoes **has** an
AnyTLS client (`anytls_client_handler.rs`), so the suite can use the
socks-inbound-with-a-`client_chain` trick every TCP suite uses — no hand-written
protocol client. Cover the usual set, plus the two things specific to AnyTLS: a
disabled user diverts to the fallback rather than being denied, and a prefix collision
between two users resolves to the right one.

**Risk: low-moderate.** The prefix index and the list-shaped placeholder are the only
genuinely new pieces.

</details>

---

## 3. NaiveProxy

### The gap

Two problems, and the second is the interesting one.

`UserLookup::new` panics on an empty list (`naiveproxy/user_lookup.rs:44`):

```rust
assert!(!credentials.is_empty(), "NaiveProxy requires at least one user");
```

A dynamic inbound starts with `users: []` by design, so this is a crash on the very
first thing an operator would do.

And authentication happens at `naive_hyper_service.rs:257`, **inside** the hyper
`serve_connection` task spawned at `:145` / `:172`. Task locals do not cross
`tokio::spawn`, so `bind_connection_user` would find nothing there and every
NaiveProxy user's counters would sit at zero.

### The fix for the second one

The same explicit-threading pattern Hysteria2 and TUIC use, for a different reason —
there it was the protocol fanning out into loops, here it is hyper owning the task.
Capture `current_connection()` *before* the spawn, carry the `Option<Arc<ConnContext>>`
in `NaiveConfig`, and bind at `:257` where the credential is checked.

### The credential shape

NaiveProxy authenticates with HTTP Basic: `base64("username:password")`. `UserSpec`
has `id`, `uuid`, `password` — no `username`. Rather than add a field to the public
API for one protocol, use the user's **`id` as the username**, so the encoded
credential is `base64("{id}:{password}")`. That fits how naive configs already name
users, and it keeps `UserSpec` as it is.

Consequence worth stating in the docs: for a NaiveProxy inbound the `id` is part of
the credential, so renaming a user rotates it. Say so at `add_user`'s error site.

Registry method:

```rust
fn find_naive_basic(&self, encoded: &[u8]) -> Option<Arc<UserContext>>;
```

taking the base64 bytes exactly as they arrive after `Basic `, so the constant-time
comparison happens against the stored encoding — which is what `UserLookup::validate`
already does and should keep doing.

### Files

- `shoes/src/dynamic/registry.rs`, `static_registry.rs` — the method and its builders.
- `crates/shoes-engine/src/users.rs` — a `by_naive_encoded` index;
  `CredentialKinds::naive_basic`.
- `crates/shoes-engine/src/protocol.rs` — `Naiveproxy` out of the not-wired-up arm;
  reuses AnyTLS's list-shaped placeholder rule.
- `shoes/src/naiveproxy/user_lookup.rs` — drop the assert; likely delete the type
  entirely once the registry answers for it.
- `shoes/src/naiveproxy/naive_hyper_service.rs` — the context across the spawn, the
  lookup at `:257`.
- `shoes/src/tcp/tcp_server_handler_factory.rs` — `create_tls_server_target` (`:360`)
  destructures `users` at `:422` **and** `:580`, shadowing the registry parameter in
  both. Same hazard as AnyTLS, twice.

### Tests

`crates/shoes-engine/tests/naiveproxy.rs`. shoes has a naive client
(`naive_client_handler.rs`), so the socks-chain trick works here too. Add one case for
the empty registry specifically — an inbound that starts with no users must serve and
refuse everyone, not panic.

**Risk: moderate.** The `Arc<ConnContext>` across the hyper boundary is the fiddly
part, and it is the part a passing TCP-only suite would not catch.

---

## What "done" means for an increment

The convention the last four commits established:

1. Registry lookup replaces the inline comparison. Without an injected registry, the
   config's own credential becomes a one-user `StaticUserRegistry` — behaviour
   identical to what it replaced.
2. A disabled user is reported **absent**, never present-but-denied.
3. Metering: task local where authentication is inline, explicit `Arc<ConnContext>`
   where it crosses a `tokio::spawn`.
4. An end-to-end suite under `crates/shoes-engine/tests/`, driving `Engine` in
   process, covering: attribution across users, an unregistered credential, a miss
   billed to nobody, disabled users, rotation, removal leaving an established
   connection alone, and both classic and dynamic mode.
5. `cargo fmt`, `cargo clippy`, `cargo test --workspace` all clean.
6. A commit message that explains the design decision and **names any pre-existing bug
   the new suite flushed out** — three of the four so far found at least one.

## Still open

- **`docs/dynamic-engine-design.md`** — a design document to sit beside this plan,
  covering the registry/metering architecture rather than the schedule. Offered
  several times, never answered.
- **Snell** stays out. It has no multi-user identity mechanism at all, so
  `credential_kinds` should keep classifying it as "no registry credentials" and the
  engine should keep refusing it a `users` list.
