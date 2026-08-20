# Dynamic engine: architecture

How `shoes-r` turns upstream [`shoes`](https://github.com/cfal/shoes) — a config-file
CLI — into an engine an API can drive, without making `shoes/` unmergeable.

This is the design record: the boundaries, the invariants, and why each decision went
the way it did. For *what is left to build*, see
[dynamic-engine-plan.md](dynamic-engine-plan.md).

---

## 1. The constraint that shapes everything

Upstream shoes loads YAML, validates it, starts every listener, and blocks forever.
Users and rules are fixed for the life of the process.

We need three things it does not do:

1. come up with **zero inbounds and zero users**, and be populated over an API;
2. add, suspend and remove **users on a live inbound**, each authenticating
   independently, with per-user byte accounting;
3. **swap rules and protocol settings** on a running listener without disturbing
   established connections.

And one thing that must not change: `shoes/` is imported verbatim by `git subtree` and
has to keep absorbing upstream releases. Every line added there is a line a future
merge has to survive.

So the governing rule is a seam, not a feature list:

> **`shoes/` gets extension points. Everything that decides policy, speaks to an
> operator, or stores a user lives outside it.**

The test for "is this allowed inside `shoes/`" is dependency-shaped and easy to apply:
`shoes/src/dynamic/` pulls in **no new crate**. Nothing in it knows about HTTP, JSON,
gRPC, or a database. If a change would need one of those, it belongs in
`crates/`.

---

## 2. Layering

```
                    embedder's own service layer
                    (gRPC / HTTP / FFI — not in this repo)
                                  │
                                  ▼
   crates/shoes-engine ──────────────────────────── the integration point
        Engine, InboundSlot, MemoryUserRegistry,     lifecycle + policy
        CredentialKinds, the placeholder pass
                                  │
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
   crates/shoes-api                  shoes/src/dynamic/  ── the extension points
     InboundSpec, UserSpec,            UserRegistry, UserContext, ConnContext,
     InboundInfo, UserInfo             TrafficMeterStream, HandlerSlot,
     (vocabulary only)                 ServerHandle, StaticUserRegistry, credential
                                                  │
                                                  ▼
                                       shoes/  ── the proxy engine (subtree)
```

| crate | role |
|---|---|
| `shoes` | the proxy engine, plus the hooks under `src/dynamic/` |
| `shoes-engine` | programmatic control of inbounds and users — the thing an embedder links |
| `shoes-api` | the argument and report types those methods take, re-exported by `shoes-engine` |

**There is deliberately no crate above `shoes-engine`.** An embedder drives `Engine`
directly from whatever it already speaks. Shipping a wire protocol or a daemon here
would put transport and policy decisions in the one repository that has to stay
mergeable — and would make everyone who wanted a different transport fork it.

`shoes-api` is split out only so a conversion layer (an FFI shim, a gRPC service) can
name the types without linking the proxy engine. Nobody depending on `shoes-engine`
needs to know it exists.

### What went *inside* `shoes/` anyway, and why

Two substantial modules live inside `shoes/` rather than in `crates/`, and the reason
is the same for both: **they are wire format**, and wire format belongs with the
protocol that speaks it.

- `shoes/src/shadowsocks/eih.rs` — Shadowsocks 2022 extensible identity headers. A
  multi-user 2022 server has a circularity to break: the salt says nothing about who
  the client is, and the session key it would need to decrypt something identifying is
  derived from the very PSK it is looking for. The identity header names the PSK
  before any of it is in use. That is protocol, not policy.
- `shoes/src/vmess/auth.rs` — sealing and opening a VMess auth id. VMess sends 16 bytes
  encrypted under a key derived from the uuid, holding only a timestamp and a CRC32C.
  Recognising a user means trial-decrypting with each known key.

Putting either outside `shoes/` would mean a second implementation of a wire format in
the tree, and the two would drift. `shoes/src/dynamic/credential.rs` exists for exactly
the same reason at the boundary: it re-exports the derivations (`parse_uuid`,
`trojan_password_hash`, `shadowsocks_psk_hash`, `VmessAuthKey`) so an out-of-crate
registry indexes on precisely the bytes `StaticUserRegistry` does.

---

## 3. Authentication: the registry

### Why a trait, not an interceptor

Authentication cannot be wrapped from the outside, because every protocol carries its
credential differently *and at a different point in its handshake*: VLESS puts a raw
uuid at byte offset 1, Trojan sends a hex digest terminated by CRLF, VMess hides an
AEAD-sealed auth id findable only by trial decryption, Hysteria2 sends a password in an
HTTP/3 header, TUIC sends a uuid beside a token keyed with a password.

So the thing that gets abstracted is the **credential lookup itself**, injected into
the existing handlers rather than layered on top of them:

```rust
pub trait UserRegistry: Send + Sync + Debug {
    fn find_uuid(&self, uuid: &[u8; 16]) -> Option<Arc<UserContext>> { None }
    fn find_trojan_hash(&self, hash: &[u8]) -> Option<Arc<UserContext>> { None }
    fn find_password(&self, password: &str) -> Option<Arc<UserContext>> { None }
    fn find_vmess_auth_id(&self, auth_id: &[u8; 16]) -> Option<VmessIdentity> { None }
    fn find_shadowsocks_psk_hash(&self, hash: &[u8; 16]) -> Option<ShadowsocksIdentity> { None }
    fn find_tuic_uuid(&self, uuid: &[u8; 16]) -> Option<TuicIdentity> { None }
    fn user_count(&self) -> usize;
}
```

Every method **defaults to denying**. An implementation answers only for the credential
shapes its inbound actually uses, and a registry that implements nothing rejects
everyone — which is the correct behaviour for an inbound with no users yet.

### Three credential shapes

The return types are not uniform, and the differences are the design:

| shape | protocols | returns | why |
|---|---|---|---|
| **indexable** | VLESS, Trojan, Hysteria2, AnyTLS\* | `Arc<UserContext>` | the client names itself; a hit is the whole answer |
| **derived** | Shadowsocks 2022, VMess | identity + key material | naming the user is not enough — the rest of the handshake derives from their key |
| **paired** | TUIC | identity + password, **unauthenticated** | half the credential is public; only the caller can check the other half |

\* not yet converted — see the plan.

VMess is the one that cannot be indexed at all: its auth id carries no identifier, so
recognising a user is linear in the user count. Every implementation of the protocol
has this cost; it is well under a microsecond per user, once per connection.

TUIC is the one that breaks the "a lookup authenticates" rule. Its uuid crosses the
wire in cleartext, and the 32-byte token beside it is keyed with the user's password
**and** the QUIC connection's exported keying material — which the registry has never
seen. So `find_tuic_uuid` hands back a password rather than a verdict, deliberately
does **not** call `note_auth`, and says so in its own documentation. The handler counts
the authentication once the token matches.

### Invariants

These are load-bearing. Breaking any of them is a security bug, not a style problem.

1. **A disabled user is reported absent, never present-but-denied.** Handlers treat
   `None` as "unknown credential" and may divert the connection to a probe-resistant
   fallback. Distinguishing the two cases at the protocol level would hand an observer
   a way to confirm that a credential is valid.
2. **The hash probe is not proof.** Lookups index on a hash, which is not constant
   time; what that leaks is bucket occupancy, not credential bytes. Every
   implementation still finishes with a constant-time comparison of the stored
   credential.
3. **The registry counts the authentication**, via `note_auth`, so a handler cannot
   forget to. This works because for every credential *except TUIC's* the key is the
   proof. TUIC is the documented exception.
4. **A credential is never an identity.** `UserContext.id` is chosen by whoever
   registered the user; `UserInfo` has no credential field at all, and a test asserts
   the serialised form does not echo one. Where a uuid *is* the reported id, that is a
   deliberate call: it already crosses the wire in cleartext and operators already
   refer to the user by it.
5. **No lock on the connection path.** A lookup runs inline in connection setup,
   before the handshake can proceed, so a lock held there stalls every concurrent
   dial.

### Two implementations, one trait object

| | `StaticUserRegistry` | `MemoryUserRegistry` |
|---|---|---|
| lives in | `shoes/src/dynamic/` | `crates/shoes-engine/` |
| built from | one inbound's own config credential | the API |
| structure | immutable `FxHashMap` | sharded `DashMap` |
| mutable | no | yes, while serving |

Handlers never branch on which one they hold. `resolve_uuid_users` and its siblings in
`tcp_server_handler_factory.rs` take `Option<&Arc<dyn UserRegistry>>` and fall back to
building a one-user `StaticUserRegistry` from the config credential.

**That fallback is what makes the whole change behaviour-preserving.** A plain YAML
config authenticates exactly as it did before registries existed: one credential,
compared in constant time, nothing else accepted. The classic path is not a special
case in the code — it is the general case with a registry of size one.

### Why the user table needs no RCU

RCU exists to publish a *consistent set* atomically. A user table is not one: each
lookup concerns exactly one user, and adding Bob has no bearing on whether Alice's
credential is valid. A sharded concurrent map is both sufficient and cheaper — a writer
touching Bob's shard cannot delay a reader looking up Alice's.

VMess is the exception, and it proves the rule. Because it must *try* every uuid-bearing
user, walking a `DashMap` would take a read lock per shard on the connection path. So
those entries are additionally published as an immutable `Vec` behind an `ArcSwap`: a
mutation rebuilds and stores a new one, a lookup reads a pointer and walks a slice. It
is the same `Arc<Entry>`s either way, so there is no second copy of anyone's state to
drift.

---

## 4. Accounting: the meter

### Where the bytes are counted

`TrafficMeterStream` wraps a connection at the **very bottom of the stack**, as soon as
it is accepted and before any protocol has looked at it. Everything the client sends or
receives therefore passes through it exactly once: TLS records, WebSocket frames,
protocol headers, padding, and the payload. That is the *wire bytes* figure an operator
bills on.

Sitting at the bottom also means most datagram protocols need no separate treatment —
VLESS UDP, Trojan UDP and XUDP all tunnel over the accepted connection, so their bytes
are already counted, fragmentation headers included.

Only the client side is metered. The stream this proxy opens to the target is
deliberately left alone: it is not the user's traffic, and counting both would double
every byte.

### The late-bind problem

The meter has to be installed **before the user is known** — the credential arrives
partway into the handshake, and for TLS-wrapped protocols it arrives after a handshake
the meter is already counting.

So a connection starts anonymous. Bytes accumulate in the `ConnContext` itself, and the
moment a handler authenticates, `bind` hands over what has accumulated:

```rust
pub fn bind(&self, user: Arc<UserContext>) -> bool {
    if self.user.set(user).is_err() { return false; }
    let user = self.user.get().expect("just set");
    user.open_conn();
    user.add_tx(self.pending_tx.swap(0, Ordering::Relaxed));
    user.add_rx(self.pending_rx.swap(0, Ordering::Relaxed));
    true
}
```

The handover is a `swap` to zero rather than a read, so a byte counted during the bind
lands in the user's counters through exactly one of the two paths and never through
both. A connection that never authenticates is billed to nobody, and dropping its
unbound context touches no user's live count.

### How the context reaches the handler: two shapes

This is the part that has bitten every increment, so it is worth stating as a rule.

**Shape A — task local.** The handler finds the context through
`METERED_CONNECTION.try_with(..)`. Threading an `Arc<ConnContext>` from the accept loop
down to the byte offset where a uuid appears would mean touching every handler
signature in between, including the ones with nothing to do with users. The task local
costs one thread-local read per connection and leaves those signatures untouched.

**Shape B — explicit parameter.** Task locals do not cross `tokio::spawn`. Shape A
therefore works only where authentication happens *inline on the task that accepted the
connection*. Where it does not, the context is passed as
`type Meter = Option<Arc<ConnContext>>`.

| protocol | shape | why |
|---|---|---|
| VLESS, VMess, Trojan, Shadowsocks 2022 | A | authenticate inline, then spawn |
| AnyTLS\* | A | authenticates in `setup_server_stream`, *before* its own spawn |
| Hysteria2 | B | authenticates once, then fans out into three loops, each its own task |
| TUIC | B | same, four loops |
| NaiveProxy\* | B | auth happens *inside* a hyper `serve_connection` task |

\* not yet converted.

The failure mode when this is got wrong is silent: TCP still adds up perfectly and the
user's counters simply sit at zero. Every suite therefore has a section that moves
traffic on the path that crosses the spawn.

### Datagrams that do not ride the stream

Hysteria2 and TUIC carry UDP over **QUIC datagrams**, not over the stream the
connection was accepted on, so there is nothing there to wrap: quinn owns the datagram,
and the loop that builds one is the only place its size is known. `ConnContext` grows
`count_datagram_tx` / `count_datagram_rx` for exactly that.

Two conventions hold there:

- **Count the datagram, not the payload** — the session and address headers the client
  is charged for are the ones actually put on the wire.
- **Count on receipt, before validation.** Every rejection past that point discards a
  datagram the client has already sent and this proxy has already received. Billing
  only the well-formed ones would let a client move bytes for free by malforming them.

The figure excludes the QUIC framing and AEAD tag quinn adds around the datagram — the
same caveat every QUIC inbound's accounting carries.

TUIC's `quic` UDP relay mode rides uni streams instead, and those *are* wrappable, so
it meters them with `TrafficMeterStream` like any other stream.

### `UserContext`: layout and ordering

Exactly one record exists per user. Every connection authenticating as that user shares
the same `Arc`, so a reader sees the sum across every inbound, transport and worker
thread at once.

- **`#[repr(align(64))]`, counters first.** `Arc` honours the alignment of the value it
  stores, so each user's hot counters land on their own cache line and two users
  metered concurrently on different cores never invalidate each other's line. A test
  asserts the alignment rather than trusting the comment.
- **`Relaxed` everywhere.** There is nothing to synchronise: values are only
  incremented by `fetch_add` and read for reporting, so the only guarantee needed is
  that no increment is lost. Anything stronger would put a memory barrier on the
  per-buffer I/O path for no benefit.
- **`close_conn` saturates rather than wraps.** An unbalanced close reporting billions
  of open connections is worse than reporting zero.
- **A stats snapshot is not atomic.** Making it so would need a lock on the I/O path;
  slight skew between `tx` and `rx` is irrelevant for reporting.

`conns == 0` is the barrier that makes a user's totals final: bytes are counted as they
move, so a snapshot taken mid-transfer is a race. The test harness's `quiet()` helper
exists for that.

---

## 5. Reload: RCU without a grace period

### The grace period is the `Arc`

An accept loop reads its handler out of a `HandlerSlot` **once per accepted
connection** and hands that `Arc` to the connection. Everything the connection needs
afterwards — protocol settings, routing rules, TLS config — hangs off it, so the
connection is pinned to the generation it started on.

`HandlerSlot::store` therefore cannot affect anything already running: it only changes
what the *next* `load` returns. The old handler is freed when its last connection ends.
There is nothing to count, drain, or wait for.

### Why the swap is at the handler, not inside the rule list

`ClientProxySelector::judge` returns a decision that **borrows** the rule it matched. A
rule list that could change under a live borrow would need every caller to hold a
guard. Replacing the handler wholesale needs no such cooperation — and it can change
strictly more: protocol options and certificates travel with it.

### Stopping a listener without stopping its connections

Every accepted connection is `tokio::spawn`ed, so a listener task is only ever the
accept loop. Cancelling it cannot reach the connections it started: the token stops the
loop, the listener drops, the port is free, and established sessions run to completion
against the rules they were accepted under.

**QUIC cannot be quite that clean.** Its connections are multiplexed over one UDP socket
owned by the endpoint, so releasing the port *is* tearing the connections down. The
QUIC accept loops stop accepting, refuse new handshakes, and then wait — bounded — for
live connections to finish before dropping the endpoint. The bounds nest deliberately:
`InboundSlot::LISTENER_DRAIN_TIMEOUT` must exceed `quic_server::QUIC_DRAIN_TIMEOUT`, or
the abort would cut exactly the connections the drain exists to protect.

### What reload does not cover

- **QUIC certificates.** They live in the endpoint, not the handler, so they are fixed
  until the listener is replaced.
- **The listen set and the transport.** Changing either is a different set of
  listeners, which is not something to do silently; `check_reload` refuses both with a
  message naming what it is serving.
- **Hysteria2 and TUIC, entirely** — they register no `HandlerSlot` because they never
  build a `TcpServerHandler`. This is the one acknowledged gap, and it is increment 1
  of the plan.

---

## 6. The control plane

`Engine` is a cheap-to-clone handle over shared state:

```rust
struct EngineInner {
    control: tokio::sync::Mutex<ControlState>,  // serialises mutations
    inbounds: DashMap<String, Arc<InboundSlot>>, // read-mostly, lock-free
    bound: DashMap<SocketAddr, String>,          // address -> owning tag
}
```

**Mutations are serialised; reads are not.** Serialising is what lets the engine treat
its own address registry as authoritative — two concurrent `add_inbound` calls can
never both pass the conflict check for the same port. Reads (`list_inbounds`,
`get_user`) go through the `DashMap`s and never contend with an in-flight reload.

User mutations are deliberately **outside** the control lock: `MemoryUserRegistry` is
already concurrent, and the same `Arc` is inside the running handlers, so adding a user
takes effect on the next handshake with no restart and no coordination.

`Engine::bootstrap` starts with nothing — no config file, no inbounds, no users — and
is fully operational in that state. Its one piece of eager work is recording the
process thread count that shoes' QUIC paths read (and `unwrap`) before any config is
parsed; skipping it would panic the first time an operator added a QUIC inbound rather
than at startup.

Nothing in `shoes-engine` reimplements shoes logic. Every step reuses the exact
upstream entry point `main.rs` uses: `convert_cert_paths`, `create_server_configs`,
`build_dns_registry`, `start_servers_with_users`.

### Dynamic mode vs classic mode

One field decides it — `InboundSpec.users`:

| `users` | mode | meaning |
|---|---|---|
| `Some(vec![...])`, including `Some(vec![])` | **dynamic** | a `MemoryUserRegistry` is the sole credential authority |
| `None` | **classic** | the config's own credential stands, exactly as upstream |

`Some(vec![])` is not the same as `None`. It is an inbound that is up and authenticates
nobody — which is the empty state the whole design exists to support.

### Fail closed on credentials

Two refusals matter more than they look.

**A `users` list on an inbound the registry cannot serve is an error, not a no-op.**
`credential_kinds` walks the *expanded* config — seeing through TLS, Reality, ShadowTLS
and WebSocket nesting rather than just the outer protocol name — and an empty result
means the inbound authenticates some other way. Accepting the list anyway would leave
the caller believing they had configured access control that is never consulted:
fail-open, and invisible until someone connects with a credential nobody granted.

That match is **exhaustive on purpose, with no wildcard arm**. Adding registry support
for a protocol is a deliberate decision, and so is absorbing a new protocol from
upstream; both should stop the build there rather than silently classify as "no users".

**A credential in the config of a dynamic inbound is an error, not something to
overwrite.** Shoes' schema requires `user_id` on VLESS, `password` on Hysteria2, both
`uuid` and `password` on TUIC — all dead once a registry is injected. The engine fills
them with random throwaways (`PLACEHOLDER_FIELDS`), but a value the caller actually
wrote is rejected: a credential that silently stops working is the worst way to learn
about this rule.

That pass walks raw JSON, before deserialization, and descends **only** through the
positions where a *server* protocol nests another. It deliberately does not search the
payload for `type: vless` at large: an inbound's `rules` carry a `client_chain`, whose
protocol objects look identical but describe an **outbound**, where `user_id` is a
real, required credential belonging to the far end. A blind search would reject those
configs, or worse, overwrite a missing one with a throwaway and dial out with a
credential nobody granted.

### One `password` field, several meanings

A control plane sends one credential per user, so `CredentialKinds` has to refuse
combinations where `password` would have to mean two things at once — a cleartext
password on one target and a base64 Shadowsocks PSK on another, or a 16-byte key here
and a 32-byte key there. Saying so when the inbound is added beats accepting users who
can only reach half of it.

Trojan and Hysteria2 together are **not** a conflict, even though one hashes the
password and the other compares it as sent: both start from the same cleartext value,
so one field serves both and the two indexes are two derivations of it. TUIC is the
odd one out in the other direction — it needs `uuid` *and* `password` together, and a
user with only one is refused when added rather than left in the table unable to
connect.

---

## 7. Testing strategy

Every acceptance suite drives `Engine` **in process**: it bootstraps an engine, injects
the inbounds it needs, and speaks to them over loopback. There is no management API and
no child process. The surface under test is the one an embedder links against, so a
passing test says something about the library rather than about a shell in front of it.

The chain most suites build:

```
test client --socks5--> socks inbound --<protocol>--> protocol inbound --direct--> Sink
                        (static, no auth)             (dynamic users)
```

The socks leg exists only to speak the client half of the protocol under test, which is
otherwise a great deal of crypto to reimplement. Giving each user their own socks port
is what makes "alice's traffic" and "bob's traffic" separable at the client end.

Hysteria2 and TUIC are the exceptions: shoes ships no client for either, so those
suites speak QUIC (and HTTP/3, for Hysteria2) directly — roughly 500-600 lines of
hand-written client each. The alternative was a suite that never authenticated anybody.

Assertions are **soft**: `Checks` accumulates and reports every failure at once. A test
that stops at the first bad assertion hides how much else broke, which is exactly the
information needed to tell "one property regressed" from "the chain is not up at all".

Suites have found three pre-existing upstream bugs so far — an AF_INET6 UDP socket that
could never reach an IPv4 peer, a SO_REUSEPORT default that panicked on platforms
lacking it, and TUIC's uni-stream packet header missing its two leading bytes.

---

## 8. Footprint

What a future `git subtree` merge of upstream has to survive, measured against
`master`:

| area | size |
|---|---|
| `shoes/src/dynamic/` (entirely new) | ~2,200 lines |
| the rest of `shoes/` | 24 files, +1,945 / −440 |
| `crates/` | ~8,600 lines, of which ~5,100 are tests |

Inside `shoes/`, outside the new module, the changes are of four kinds:

1. **Visibility widenings** — `pub mod tcp;`, `pub mod socket_util;`, exporting
   `DnsRegistry`; plus `[profile.release]` moved to the workspace root, because Cargo
   ignores profiles in a non-root member.
2. **Registry injection at six authentication sites** — VLESS, Trojan, VMess,
   Shadowsocks 2022, Hysteria2, TUIC. Behaviour-preserving by construction, per §3.
3. **Metering and reload threading** — `Option<Arc<dyn UserRegistry>>` and a `metered`
   flag through the handler factory and the accept loops; `HandlerSlot` / `ServerHandle`
   in place of a bare handler.
4. **Two new wire-format modules** — `shadowsocks/eih.rs`, `vmess/auth.rs`, per §2.

> **Known stale:** the "Invasiveness" table in `crates/shoes-engine/src/lib.rs` still
> describes the phase-2a footprint — "two authentication sites (VLESS, Trojan)". The
> numbers above supersede it.

---

## 9. Invariants, collected

For review checklists and for the next protocol conversion.

1. A disabled user reports **absent**, never present-but-denied.
2. A hash hit is a candidate, not proof; finish with a constant-time comparison.
3. The registry calls `note_auth` — unless its lookup cannot authenticate, in which
   case it says so and the handler calls it.
4. No lock and no allocation on the connection path.
5. Credentials never appear in an id, a log line, or a report.
6. With no registry injected, behaviour is bit-for-bit what upstream did.
7. A reload changes what the *next* connection sees, never a live one.
8. `shoes/src/dynamic/` adds no dependency.
9. An inbound that cannot use a `users` list refuses one.
10. Count bytes on the wire, once, on the client side only.
