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

The test for "is this allowed inside `shoes/`" is dependency-shaped and easy to apply.
`shoes/src/dynamic/` added exactly **one** crate: `arc-swap`, for the pointer swap a
reload is built on — a concurrency primitive of the same kind as the `tokio` already
there. Nothing in the module knows about HTTP, JSON, gRPC, or a database, and if a
change would need one of those, it belongs in `crates/` instead.

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
     InboundInfo, UserInfo             TrafficMeterStream, HandlerSlot, SelectorSlot,
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
HTTP/3 header, TUIC sends a uuid beside a token keyed with a password, AnyTLS opens
with a bare hash, NaiveProxy waits for an HTTP/2 request header.

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
    fn find_password_sha256(&self, hash: &[u8; 32]) -> Option<Arc<UserContext>> { None }
    fn has_password_sha256_prefix(&self, prefix: &[u8; 8]) -> bool { false }
    fn find_naive_basic(&self, encoded: &[u8]) -> Option<Arc<UserContext>> { None }
    fn user_count(&self) -> usize;
}
```

Every method **defaults to denying**. An implementation answers only for the credential
shapes its inbound actually uses, and a registry that implements nothing rejects
everyone — which is the correct behaviour for an inbound with no users yet.

### Four credential shapes

The return types are not uniform, and the differences are the design:

| shape | protocols | returns | why |
|---|---|---|---|
| **indexable** | VLESS, Trojan, Hysteria2, AnyTLS, NaiveProxy | `Arc<UserContext>` | the client names itself; a confirmed hit supplies all proof needed for immediate admission |
| **derived** | Shadowsocks 2022, VMess | identity + key material | naming the user is not enough — the rest of the handshake derives from their key |
| **paired** | TUIC | identity + password, **unauthenticated** | half the credential is public; only the caller can check the other half |
| **incomplete** | AnyTLS | `bool` | asked *before* the credential has fully arrived, so it can only be a plausibility test |

Three protocols index a *derivation* of one cleartext password, and each is its own
key: Trojan sends 56 hex characters of SHA-224, Hysteria2 sends the cleartext, AnyTLS
sends 32 raw bytes of SHA-256. One `password` on a user feeds all three, which is why
`CredentialKinds` does not treat them as a conflict — but they are never one index,
because sharing one would accept a secret in a form its owner never sends.

VMess is the one that cannot be indexed at all: its auth id carries no identifier, so
recognising a user is linear in the user count. Every implementation of the protocol
has this cost; it is well under a microsecond per user, once per connection.

Registry lookup and admission are deliberately separate for every protocol. A lookup
only resolves an enabled candidate and never changes counters. Once the protocol has
enough proof, the handler performs one connection-aware admission. Inline handlers
call `bind_connection_user`; protocols carrying an explicit `ConnContext` call
`bind_authenticated`, or `bind_or_matches` when each request on one transport repeats
authentication. On a metered connection this counts the authentication and registers
its cancellation token under one per-user lifecycle lock; on a classic unmetered
inbound it records only the authentication. This single contract applies to both
`StaticUserRegistry` and `MemoryUserRegistry`, so a custom handler has the same public
atomic admission APIs as the built-in protocols. Dynamic registries create tracked
`UserContext`s, which reject admission if a handler loses its connection context;
only immutable config registries opt into explicitly untracked records.

TUIC is the clearest reason for the split. Its uuid crosses the wire in cleartext, and
the 32-byte token beside it is keyed with the user's password **and** the QUIC
connection's exported keying material — which the registry has never seen. So
`find_tuic_uuid` hands back a password and the handler waits to admit the candidate
until the token matches.

AnyTLS breaks a different one. It peeks at the first 8 bytes of a connection and, on a
miss, diverts it to a fallback destination without waiting for the remaining 24 —
which is what stops a prober from hanging the handler. So
`has_password_sha256_prefix` has to answer *before the credential is complete*, and it
is therefore a plausibility test rather than a lookup: `true` means "keep reading",
never "this user exists". In particular it **ignores whether the user is enabled**.
Answering `false` for a suspended user would send their connections to the fallback
while a live user's went to the handler, which is an observable difference an
attacker could use to enumerate suspensions.

NaiveProxy's credential is the only one that contains the user's **id**: it is HTTP
Basic, base64 of `username:password`, and `UserSpec` has no username field of its own.
So on such an inbound the id is part of the credential, and renaming a user rotates
it — stated here because it is the one place where an id is not merely a label.

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
3. **Lookup resolves; proof admits.** No registry lookup changes accounting. The
   handler admits a resolved user only when its protocol proves possession. For
   VLESS, Trojan, Hysteria2, AnyTLS and NaiveProxy that is immediately after the
   constant-time credential comparison. TUIC's cleartext uuid, VMess' auth id, and a
   Shadowsocks 2022 identity header can be copied off the wire, so those handlers wait
   for a connection-bound token or an AEAD opened under the user's own key. Admitting
   on the copyable half would let a recording inflate another user's counters.
4. **A credential is never an identity.** `UserContext.id` is chosen by whoever
   registered the user; `UserInfo` has no credential field at all, and a test asserts
   the serialised form does not echo one. Where a uuid *is* the reported id, that is a
   deliberate call: it already crosses the wire in cleartext and operators already
   refer to the user by it. An id reaches logs — the AnyTLS handler debug-logs it on
   every successful authentication — so a config user who declared no name is
   reported by *position*, never by their password, which is what an earlier version
   did.

   One protocol is the exception in the other direction: on a NaiveProxy inbound the
   id is the username half of an HTTP Basic credential, so it is part of the
   credential by construction. That makes `id:password` ambiguous when an id contains
   a colon — `("alice", "b:c")` and `("alice:b", "c")` encode identically — so the
   duplicate-credential check covers this index too, rather than assuming distinct
   ids imply distinct credentials.
5. **Nothing on the connection path waits on the control plane.** A lookup runs
   inline in connection setup, before the handshake can proceed, so anything that
   blocks there stalls every concurrent dial. A lookup does take one `DashMap` shard
   read guard, held for the length of a constant-time comparison; what it never takes
   is the registry's writer lock or the engine's control lock.

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
moment a handler authenticates, `bind_authenticated` performs one atomic admission and
hands over what has accumulated. Conceptually, the operation is:

```rust
pub fn bind_authenticated(&self, user: &Arc<UserContext>) -> bool {
    let _binding = self.binding.lock();
    let Some(registration) = user.register_authenticated_connection(self.cancel.clone())
    else { return false; };
    self.publish_binding(user.clone(), registration);
    self.handover_pending_bytes();
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
`type Meter = Option<Arc<ConnContext>>`; single-auth transports use
`ConnContext::bind_authenticated`, while request-authenticated multiplexing uses
`ConnContext::bind_or_matches`.

| protocol | shape | why |
|---|---|---|
| VLESS, VMess, Trojan, Shadowsocks 2022 | A | authenticate inline, then spawn |
| AnyTLS | A | authenticates in `setup_server_stream`, *before* its own spawn |
| Hysteria2 | B | authenticates once, then fans out into three loops, each its own task |
| TUIC | B | same, four loops |
| NaiveProxy | B | hyper owns the task from `serve_connection` on, and the credential is not read until a request arrives |

Tracked dynamic users now fail closed when this propagation is missing: authentication
is rejected rather than creating an unmetered, non-revocable session. Every suite still
has a section that moves traffic on the path that crosses the spawn, proving the
explicit hand-off is actually present.

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
- **Relaxed bytes, release/acquire completion.** Byte and lifetime-authentication
  counters are relaxed, so the per-buffer I/O path has no memory barrier. The live
  connection counter's final decrement is a release and observing zero is an acquire;
  therefore removal sees that connection's last byte increments before returning its
  final snapshot.
- **`close_conn` saturates rather than wraps.** An unbalanced close reporting billions
  of open connections is worse than reporting zero.
- **A stats snapshot is not atomic.** Making it so would need a lock on the I/O path;
  slight skew between `tx` and `rx` is irrelevant for reporting.

`conns == 0` is the barrier that makes a user's totals final: bytes are counted as they
move, so a snapshot taken mid-transfer is a race. The test harness's `quiet()` helper
exists for that.

### Removing a user is a revocation barrier

Suspension and removal deliberately have different meanings. Setting `enabled = false`
is admission control: subsequent authentications see the user as absent, while sessions
that already authenticated keep running. `remove_user`, by contrast, is an async strong
revocation operation:

1. under the registry's writer lock, mark the `UserContext` revoked and cancel every
   registered connection before retiring its credential indexes;
2. make proof admission and connection registration one lifecycle operation, so a
   racing connection is either included in the drain or rejected before success;
3. keep a draining tombstone for the id, so it cannot be re-added as a second accounting
   generation while old sockets are closing;
4. wait for `conns == 0`, then return the final byte and lifetime-connection counters.

The per-connection cancellation token is observed at two levels. Metered TCP and generic
QUIC streams fail pending and future I/O with `ConnectionAborted`; protocols that multiplex
an authenticated user over a whole transport (Hysteria2, TUIC and AnyTLS) also close that
transport so the old client cannot open another logical stream. On the normal Tokio
engine runtime the drain finalizer is spawned before the caller awaits it. If that API
request is cancelled, the final snapshot remains on the tombstone; repeating
`remove_user` for the same id attaches to the same generation and returns it. The id
stays reserved, even after its connections reach zero, until that result is collected;
this prevents a re-add from silently discarding final counters.

### Closing a billing period

Reading the counters and then zeroing them are one operation, not two:
`Engine::take_user_traffic` and `take_inbound_traffic` report what they took. Two calls
would drop whatever moved in between, and the whole point of the meter is that every
byte lands in exactly one period. A sweep takes each user individually rather than as
one snapshot, so a user transferring while it runs has their bytes *split* between two
periods rather than double-counted or lost — and `remove_user` already reports a
departing user's final counters, which is where their last bytes are. `conns` and
`total_conns` are untouched: one is live state, the other a lifetime total, and neither
belongs to a period.

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

### The resolver travels with the handler

A reload rebuilds the handler *and its resolver* — an inbound may declare its own
`dns` section, so the two are not independent. That means the resolver cannot live in
the accept loop, which reads it once at startup and would otherwise hand every new
connection one generation's rules and another's DNS. It goes in the slot instead, so a
`load` returns both halves of one generation and a connection is pinned to both.

### What reload does not cover

Everything here is **refused by name**, not ignored. A reload that reports success
while quietly keeping the old value is worse than a refusal, and the worst case is the
one an operator acts on: after rotating a certificate, the next thing they do is stop
worrying about the old one.

- **Anything the listener baked in**: `tcp_settings.no_delay`, read once before the
  accept loop starts, and every field of `quic_settings` — the certificate, the key,
  the ALPN list, client CAs and fingerprints, the endpoint count. These belong to the
  socket and the endpoint, which a reload does not rebuild. `FixedListener` records
  them at start and `check_reload` compares.
- **The listen set and the transport.** Changing either is a different set of
  listeners, which is not something to do silently. For a unix socket that means the
  *path*, not merely "still a unix socket" — the path is the socket, so `/tmp/a` to
  `/tmp/b` is a different listener and used to report success while serving `/tmp/a`.
- **What a dynamic inbound authenticates with.** Its registry was built to answer one
  set of questions and its users hold credentials of those shapes. Swapping VLESS for
  Trojan strands every user; swapping it for a plain SOCKS proxy strands the *access
  control*, leaving an open proxy on a live port while the API goes on reporting the
  users it no longer consults. Both are refused by comparing `credential_kinds`
  against the registry's own.
- **Protocol settings on Hysteria2 and TUIC.** They never build a `TcpServerHandler`,
  so they register a [`SelectorSlot`](#5-reload-rcu-without-a-grace-period) instead,
  which reaches their rules and nothing else. `udp_enabled`, `zero_rtt_handshake` and
  the credential were read once before the accept loop started, so the handle records
  them and `check_reload` refuses a change by name rather than ignoring it — silently
  ignoring a `udp_enabled: false` would leave UDP running after an operator turned it
  off. In dynamic mode the credential is excluded from that comparison, because the
  engine regenerates its placeholder on every call and it carries no intent.

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

User mutations are deliberately **outside** the control lock: the same `Arc` is inside
the running handlers, so adding a user takes effect on the next handshake with no
restart and no coordination, and it never waits on a reload that is holding sockets.

They are not, however, unserialised. `MemoryUserRegistry` carries a `Mutex` of its own,
taken by `upsert` and `remove` and by nothing else. A *reader* concerns one user, which
is why the table needs no RCU; a *writer* does not — one `upsert` reads the indexes to
reject a credential someone else holds, reads the previous entry to decide which keys to
retire, and then writes up to six maps. Each step is atomic and the sequence is not, so
two writers interleaving produce exactly what the steps exist to prevent: two users both
told they were granted one uuid, and a rotated-away credential left live in an index.
Neither was a rare interleaving — both reproduced on ~99% of attempts before the lock
existed, and both now have a regression test. No lookup takes that lock, so §3's
invariant about the connection path is untouched.

### What an address claim covers

`bound` is keyed by *socket*, not by address. A TCP listener and a QUIC endpoint on
`:443` are two different things and holding both is the ordinary way to serve HTTP/3
beside HTTP/2 — keying on the `SocketAddr` alone refused the second as a conflict with
the first. A unix socket has no address at all and so needs its own kind of key rather
than being left out of the registry, which is what let two inbounds claim one path and
the second silently delete the first one's socket file. The pre-flight bind follows the
same rule: a QUIC inbound is probed with a UDP socket, because probing TCP tests a port
nobody was going to open.

### Cancelling a control-plane call

`add_inbound` and `remove_inbound` are `async`, and an embedder's transport will cancel
them — a gRPC client hangs up, a request times out. Dropping either future used to leak:
`add_inbound` opens sockets before it registers the inbound, so a cancellation in
between left listeners serving with no tag to name them and no way to stop them;
`remove_inbound` takes the slot out of `inbounds` before it releases the addresses, so a
cancellation left them claimed forever by a tag that no longer existed.

Both are covered by drop guards now, and both are honest about what a guard can do.
`Drop` cannot await, so they call the *synchronous* half — `CancellationToken::cancel`,
which stops the accept loops without waiting for the drain. So a cancelled call still
cleans up; what it gives up is the guarantee that the port is free the moment it
returns. A caller that retries the same address immediately may race the listener it
just cancelled, which is a reason to drive these futures to completion rather than a
reason to distrust them.

Dropping the last `Engine` handle stops accepting on every inbound, for the same
reason: an engine is the only thing that can name its inbounds, so listeners outliving
it are unreachable by anything.

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

Three refusals matter more than they look.

**A `users` list on an inbound the registry cannot serve is an error, not a no-op.**
`credential_kinds` walks the *expanded* config — seeing through TLS, Reality, ShadowTLS
and WebSocket nesting rather than just the outer protocol name — and an empty result
means the inbound authenticates some other way. Accepting the list anyway would leave
the caller believing they had configured access control that is never consulted:
fail-open, and invisible until someone connects with a credential nobody granted.

That match is **exhaustive on purpose, with no wildcard arm**. Adding registry support
for a protocol is a deliberate decision, and so is absorbing a new protocol from
upstream; both should stop the build there rather than silently classify as "no users".

**A target the list does not govern refuses the whole inbound, even when its
neighbours are governed.** "Does anything here authenticate through a registry" and
"is the whole inbound governed by the list" are different questions, and a tree can
answer yes to the first while one target answers no to the second. Two shapes end up
there, and both are fail-open:

- **A target that cannot act on a registry it is handed.** Shadowsocks is the only
  protocol that can be in that position, because it is the only handler that
  **branches** on whether a registry was injected — a 2022 *chacha20* target has no
  identity header to name a user with, and that combination cannot even start.
- **A target that authenticates nobody at all.** A plain HTTP, SOCKS or mixed target
  with neither `username` nor `password`, or a port-forward, serves every client that
  reaches its SNI. Sharing an inbound with VLESS does not change that, and it is
  precisely the case where a `users` list reads as protection it is not.

`unservable_registry_target` walks the same tree `credential_kinds` does and names the
offending target. What it deliberately does *not* name is a target that authenticates
on its own terms: legacy shadowsocks, Snell, or an HTTP target with a credential.
Those keep what the operator actually wrote — nothing invented one for them, since
only `PLACEHOLDER_FIELDS` protocols get a throwaway — so the inbound is not open, it
is simply not per-user there.

The check lives on **both** entry points. A reload rebuilds the handlers from the new
config and hands them the registry the inbound already has, so `update_inbound` can
introduce such a target exactly as `add_inbound` can — and it never goes through
`build_user_registry`, so one copy of the check would not cover it.

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
| `shoes/src/dynamic/` (entirely new) | ~3,200 lines |
| the rest of `shoes/` | 28 files, +2,381 / −746 |
| `crates/` | ~11,800 lines, of which ~6,800 are tests |

Inside `shoes/`, outside the new module, the changes are of four kinds:

1. **Visibility widenings** — `pub mod tcp;`, `pub mod socket_util;`,
   `pub mod dynamic;`, exporting `DnsRegistry`; plus the `arc-swap` dependency and
   `[profile.release]` moved to the workspace root, because Cargo ignores profiles in
   a non-root member. `shoes/Cargo.toml` also carries a package-scoped
   `[lints.clippy]` allowing `absurd_extreme_comparisons`: three of upstream's VMess
   tests assert `length_mask <= u16::MAX` on a value that is already a `u16`, which
   clippy denies by default — that made `cargo clippy --workspace --all-targets` fail
   to *compile*, so no test code in the workspace could be linted. A `Cargo.toml`
   line beats editing upstream test bodies that every merge would then carry.
2. **Registry injection at eight authentication sites** — VLESS, Trojan, VMess,
   Shadowsocks 2022, Hysteria2, TUIC, AnyTLS, NaiveProxy. Behaviour-preserving by
   construction, per §3. One deletion: NaiveProxy's `UserLookup` is gone, because the
   registry answers everything it answered.
3. **Metering and reload threading** — `Option<Arc<dyn UserRegistry>>` and a `metered`
   flag through the handler factory and the accept loops; `HandlerSlot` / `ServerHandle`
   in place of a bare handler.
4. **Two new wire-format modules** — `shadowsocks/eih.rs`, `vmess/auth.rs`, per §2.

Every protocol shoes can tell users apart on is now registry-backed. Snell is the only
one left out, and it is not a gap: it has no multi-user identity mechanism at all, so
there is nothing for a registry to answer.

---

## 9. Invariants, collected

For review checklists and for the next protocol conversion.

1. A disabled user reports **absent**, never present-but-denied.
2. A hash hit is a candidate, not proof; finish with a constant-time comparison.
3. Registry lookups never change accounting. After sufficient proof, the handler
   admits exactly once; TUIC, VMess and Shadowsocks 2022 wait beyond their first
   copyable identity field.
4. No lock a control-plane call can hold on the connection path. A lookup does take
   one `DashMap` shard read guard, for the length of a constant-time comparison; what
   it must never wait on is a writer, a reload, or I/O. (One allocation survives:
   `find_shadowsocks_psk_hash` clones the user's PSK, because the handler derives the
   connection's session keys from it.)
5. Credentials never appear in an id, a log line, or a report.
6. With no registry injected, behaviour is bit-for-bit what upstream did.
7. A reload changes what the *next* connection sees, never a live one.
8. `shoes/src/dynamic/` adds no dependency an *application* would need — no
   transport, no serialisation format, no store. (`arc-swap` is the one crate it did
   add, and it is a concurrency primitive.)
9. An inbound that cannot use a `users` list refuses one — including one whose
   *targets* disagree, whether because a target cannot act on a registry or because
   it authenticates nobody at all.
10. Count bytes on the wire, once, on the client side only. One connection belongs to
    one user: a protocol that reads a credential more than once per connection
    refuses a second, different one rather than billing them to the first.
11. What a dynamic inbound authenticates with is fixed for its life. A reload may
    change its rules, its protocol settings and its certificates-in-the-handler; it
    may not change the credential shape its registered users hold, and it may not
    change the protocol to one that consults no registry.
12. A claim on an address is a claim on a *socket*: TCP `:443` and QUIC `:443` are two
    of them, and a unix path is a third kind. Pre-flight binds test the socket the
    listener will really open.
13. Cancelling a control-plane call leaks nothing. Listeners started but never
    registered are stopped; addresses held by an inbound being removed are released.
    What cancellation gives up is *timing* — nothing is left to await the drain — not
    cleanup.
