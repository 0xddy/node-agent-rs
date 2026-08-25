//! The dynamic, in-memory user store.
//!
//! One [`MemoryUserRegistry`] is created per inbound and handed to `shoes` as an
//! `Arc<dyn UserRegistry>` when its listeners start. Because the handlers only ever
//! hold that trait object, mutations made here are visible to the next connection
//! immediately -- there is no reload step for users and nothing to swap.
//!
//! # Why this needs no RCU
//!
//! RCU exists to publish a *consistent set* of rules atomically. A user table is
//! not that: each lookup concerns exactly one user, and adding Bob has no bearing
//! on whether Alice's credential is valid. So a sharded concurrent map is both
//! sufficient and cheaper -- a writer touching Bob's shard cannot delay a reader
//! looking up Alice's.
//!
//! # Cost on the hot path
//!
//! A lookup is one hash, one shard read lock, one 16 or 56 byte constant-time
//! comparison, and an `Arc` clone. It happens once per connection, during the
//! handshake, never per packet. Once the protocol has proved the credential,
//! admission briefly enters only that user's lifecycle gate; that is what makes it
//! linearise against removal. Neither lock is held across I/O, and unrelated users
//! never share the lifecycle gate.
//!
//! # Writers, unlike readers, are serialised
//!
//! Readers concern one user, but a *writer* does not: one `upsert` reads the
//! indexes to reject a credential another user already holds, reads the previous
//! entry to work out which index keys to retire, and then writes to as many as six
//! maps. Each of those steps is individually atomic and the sequence is not, so two
//! writers interleaving produce exactly the outcomes the steps exist to prevent --
//! two users both told they were granted one uuid, or a rotated-away credential
//! left live in an index. A `Mutex` around the mutations is what closes that
//! window; see [`MemoryUserRegistry::writer`]. No lookup takes it, so the
//! connection path is unaffected.
//!
//! # The exception: VMess
//!
//! VMess is the one protocol here whose credential cannot be indexed at all -- its
//! auth id carries no identifier, only a sealed timestamp -- so recognising a user
//! means trying every uuid-bearing user's key. Walking a `DashMap` to do that would
//! take a read lock per shard on the connection path, which is exactly what this
//! module exists to avoid, so those entries are *also* published as an immutable
//! `Vec` behind an `ArcSwap`. A mutation rebuilds and stores a new one; a lookup
//! reads a pointer and walks a slice.
//!
//! It is the same records either way: the snapshot holds the same `Arc<Entry>`s the
//! maps do, so there is no second copy of anyone's state that could drift.

use std::sync::{Arc, Mutex, OnceLock};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use shoes::dynamic::credential::VmessAuthKey;
use shoes::dynamic::{
    ShadowsocksIdentity, TuicIdentity, UserContext, UserRegistry, VmessIdentity, credential,
};
use shoes_api::{UserInfo, UserSpec};
use subtle::ConstantTimeEq;

use crate::error::{EngineError, EngineResult};

/// What a `password` means to an inbound's Shadowsocks 2022 targets, if any.
///
/// The length matters because a PSK is raw key material: a 16 byte key is not a
/// short aes-256-gcm key, it is a key that cipher can never use. Carrying the
/// expected length here is what lets a wrong-sized key be refused when the user is
/// added, rather than accepted into the table and then silently unable to connect.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ShadowsocksPsk {
    /// No Shadowsocks target here, or one that cannot tell users apart.
    #[default]
    None,
    /// Every Shadowsocks target here wants a PSK of this many bytes: 16 for
    /// aes-128-gcm, 32 for aes-256-gcm.
    Len(usize),
    /// Two targets disagree about the length. Refused rather than resolved; see
    /// [`CredentialKinds::conflict`].
    Mixed,
}

/// The credential forms an inbound authenticates with.
///
/// This is a set rather than a single value because one inbound legitimately can
/// need more than one: a TLS inbound maps each SNI to its own inner protocol, so
/// `tls_targets` may carry VLESS on one name and Trojan on another.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CredentialKinds {
    /// VLESS: a raw 16 byte uuid, sent in cleartext at offset 1 of the header.
    pub uuid: bool,
    /// Trojan: SHA-224 of a password, hex encoded, terminated by CRLF.
    pub trojan_password: bool,
    /// Hysteria2: the password itself, sent in cleartext in an HTTP/3 header.
    pub plain_password: bool,
    /// Shadowsocks 2022: a raw PSK, given base64 encoded, recognised on the wire by
    /// the identity header a client seals with it.
    pub shadowsocks_psk: ShadowsocksPsk,
    /// TUIC: a uuid *and* a password, together. The odd one out here -- every other
    /// kind is one field, and a user who supplies it can connect. A TUIC user needs
    /// both: the uuid names them in cleartext and the password keys the 32 byte token
    /// beside it, so half a credential authenticates nobody.
    pub tuic: bool,
    /// AnyTLS: the raw SHA-256 of a password. A third derivation of the same
    /// cleartext value Trojan and Hysteria2 start from, not a third meaning of it,
    /// so it never conflicts with either.
    pub anytls_password: bool,
    /// NaiveProxy: HTTP Basic, base64 of `username:password`. The username half is
    /// the user's `id`, since [`UserSpec`] has no field of its own for it -- so on
    /// such an inbound the id is part of the credential and renaming a user rotates
    /// it.
    pub naive_basic: bool,
}

impl CredentialKinds {
    pub const NONE: Self = Self {
        uuid: false,
        trojan_password: false,
        plain_password: false,
        shadowsocks_psk: ShadowsocksPsk::None,
        tuic: false,
        anytls_password: false,
        naive_basic: false,
    };

    pub const UUID: Self = Self {
        uuid: true,
        ..Self::NONE
    };

    pub const TROJAN_PASSWORD: Self = Self {
        trojan_password: true,
        ..Self::NONE
    };

    pub const PLAIN_PASSWORD: Self = Self {
        plain_password: true,
        ..Self::NONE
    };

    /// A TUIC user's uuid is a real uuid credential -- it is what `find_tuic_uuid`
    /// indexes on -- so the pair sets `uuid` as well as `tuic`.
    pub const TUIC: Self = Self {
        uuid: true,
        tuic: true,
        ..Self::NONE
    };

    pub const ANYTLS_PASSWORD: Self = Self {
        anytls_password: true,
        ..Self::NONE
    };

    pub const NAIVE_BASIC: Self = Self {
        naive_basic: true,
        ..Self::NONE
    };

    /// Shadowsocks 2022 users whose PSKs are `len` bytes, i.e. whatever the inbound's
    /// cipher uses.
    pub const fn shadowsocks_psk(len: usize) -> Self {
        Self {
            shadowsocks_psk: ShadowsocksPsk::Len(len),
            ..Self::NONE
        }
    }

    pub fn is_empty(&self) -> bool {
        *self == Self::NONE
    }

    pub fn merge(&mut self, other: Self) {
        self.uuid |= other.uuid;
        self.trojan_password |= other.trojan_password;
        self.plain_password |= other.plain_password;
        self.tuic |= other.tuic;
        self.anytls_password |= other.anytls_password;
        self.naive_basic |= other.naive_basic;
        self.shadowsocks_psk = match (self.shadowsocks_psk, other.shadowsocks_psk) {
            (ShadowsocksPsk::None, only) | (only, ShadowsocksPsk::None) => only,
            (ShadowsocksPsk::Len(a), ShadowsocksPsk::Len(b)) if a == b => ShadowsocksPsk::Len(a),
            _ => ShadowsocksPsk::Mixed,
        };
    }

    /// Whether a user's `password` means anything to this inbound.
    fn takes_password(&self) -> bool {
        self.trojan_password
            || self.plain_password
            || self.tuic
            || self.anytls_password
            || self.naive_basic
            || matches!(self.shadowsocks_psk, ShadowsocksPsk::Len(_))
    }

    /// Why this combination of credential forms cannot share one user table.
    ///
    /// Both cases come down to `password` having to mean one thing. A control plane
    /// sends one credential per user, so if that field would have to be a cleartext
    /// password on one target and a base64 PSK on another -- or a 16 byte key here and
    /// a 32 byte key there -- there is no value it could hold that reaches the whole
    /// inbound. Saying so when the inbound is added is better than accepting users who
    /// can only reach half of it.
    ///
    /// Trojan and Hysteria2 together are *not* a conflict, even though one hashes the
    /// password and the other compares it as sent: both start from the same cleartext
    /// value, so one `password` field serves both and the two indexes are simply two
    /// derivations of it.
    ///
    /// Checked by the engine before building a registry; [`MemoryUserRegistry::new`]
    /// takes the kinds as given.
    pub fn conflict(&self) -> Option<String> {
        match self.shadowsocks_psk {
            ShadowsocksPsk::Mixed => Some(
                "its shadowsocks targets use ciphers with different key lengths, so one \
                 `password` cannot serve them all; give each cipher its own inbound"
                    .to_string(),
            ),
            ShadowsocksPsk::Len(_)
                if self.trojan_password
                    || self.plain_password
                    || self.anytls_password
                    || self.naive_basic =>
            {
                Some(
                    "it mixes shadowsocks with a protocol that wants a cleartext password, \
                     so its `password` field would mean two different things -- a password \
                     and a base64 PSK; give each its own inbound"
                        .to_string(),
                )
            }
            _ => None,
        }
    }

    /// The credential fields a caller may set, for use in error messages.
    pub fn accepted_fields(&self) -> String {
        // TUIC wants both at once, which "or" would misstate.
        if self.tuic {
            return "`uuid` and `password`".to_string();
        }
        let mut fields = Vec::new();
        if self.uuid {
            fields.push("`uuid`");
        }
        if self.takes_password() {
            fields.push("`password`");
        }
        if fields.is_empty() {
            return "nothing".to_string();
        }
        fields.join(" or ")
    }
}

/// A user's Shadowsocks 2022 key, and the 16 bytes that name it on the wire.
struct ShadowsocksCredential {
    /// Truncated blake3 of `psk` -- what a client's identity header decrypts to, and
    /// so the index key.
    hash: [u8; 16],
    /// The key itself. Handed back on a hit because the handler derives the session
    /// keys from it; the identity PSK it arrived under is the inbound's, not this
    /// user's.
    psk: Box<[u8]>,
}

/// The wire-form credentials of one user, already converted to index keys.
struct Credentials {
    uuid: Option<[u8; 16]>,
    trojan_hash: Option<Box<[u8]>>,
    /// The password as the client will send it. Its own index key: Hysteria2 compares
    /// the cleartext, so there is nothing to derive.
    password: Option<Box<str>>,
    shadowsocks: Option<ShadowsocksCredential>,
    /// The password half of a TUIC credential. Not an index key and not a credential
    /// on its own -- the uuid is what is looked up, and this is what the token beside
    /// it is keyed with. Two TUIC users may share a password without conflict; it is
    /// their uuids that must differ.
    tuic_password: Option<Arc<str>>,
    /// Raw SHA-256 of the password, which is what an AnyTLS client puts on the wire.
    anytls_hash: Option<[u8; 32]>,
    /// base64("id:password"), which is what a NaiveProxy client puts in its
    /// `proxy-authorization` header.
    naive_encoded: Option<Box<[u8]>>,
}

/// One user: their shared accounting record plus the credentials that reach it.
struct Entry {
    context: Arc<UserContext>,
    /// Retained so a hash hit can be confirmed in constant time. The hash probe
    /// that found this entry is not constant time and proves nothing on its own.
    uuid: Option<[u8; 16]>,
    trojan_hash: Option<Box<[u8]>>,
    password: Option<Box<str>>,
    shadowsocks: Option<ShadowsocksCredential>,
    tuic_password: Option<Arc<str>>,
    anytls_hash: Option<[u8; 32]>,
    naive_encoded: Option<Box<[u8]>>,
    /// Derived from `uuid` once, here, because VMess auth ids can only be recognised
    /// by trial: deriving this per connection would mean an MD5, a KDF and an AES key
    /// schedule *per user* on every handshake.
    vmess: Option<VmessAuthKey>,
}

/// One removed accounting generation, including its recoverable final snapshot.
struct DrainingUser {
    entry: Arc<Entry>,
    result: OnceLock<UserInfo>,
    completed: tokio::sync::Notify,
}

impl DrainingUser {
    fn new(entry: Arc<Entry>) -> Arc<Self> {
        Arc::new(Self {
            entry,
            result: OnceLock::new(),
            completed: tokio::sync::Notify::new(),
        })
    }

    fn complete(&self) -> UserInfo {
        debug_assert_eq!(self.entry.context.conns(), 0);
        let info = self
            .result
            .get_or_init(|| user_info(&self.entry.context))
            .clone();
        self.completed.notify_waiters();
        info
    }

    async fn completed_result(&self) -> UserInfo {
        loop {
            // Register before checking the value, so completion between the check
            // and await cannot be missed.
            let notified = self.completed.notified();
            if let Some(info) = self.result.get() {
                return info.clone();
            }
            notified.await;
        }
    }

    async fn finish(&self) -> UserInfo {
        if let Some(info) = self.result.get() {
            return info.clone();
        }

        // Several retried remove calls may attach at once. UserContext wakes one
        // zero waiter; that winner stores the result and wakes every other caller.
        tokio::select! {
            info = self.completed_result() => info,
            () = self.entry.context.wait_for_connections_closed() => self.complete(),
        }
    }
}

/// Clear only the tombstone owned by this exact accounting generation.
///
/// A completed old finalizer can race with re-adding and then removing the same id.
/// Key-only removal would let that stale finalizer erase the newer generation's
/// tombstone and permit two live generations to overlap.
fn clear_draining_generation(
    draining: &DashMap<Arc<str>, Arc<DrainingUser>>,
    generation: &Arc<DrainingUser>,
) {
    draining.remove_if(generation.entry.context.id().as_ref(), |_, current| {
        Arc::ptr_eq(current, generation)
    });
}

impl Entry {
    /// Confirms a candidate hit and, on success, hands out the shared record.
    ///
    /// A disabled user returns `None`, i.e. is indistinguishable from an unknown
    /// one. That matters for VLESS, whose fallback destination would otherwise
    /// become an oracle for "this credential exists but is suspended".
    fn accept(&self, expected: &[u8], presented: &[u8]) -> Option<Arc<UserContext>> {
        if expected.ct_eq(presented).unwrap_u8() == 0 || !self.context.is_enabled() {
            return None;
        }
        Some(self.context.clone())
    }

    /// Whether this user sealed `auth_id`, and what the handshake needs next.
    ///
    /// No constant-time comparison here, unlike `accept`, and none is called for:
    /// nothing is being compared against a stored secret. A valid checksum shows
    /// somebody held the uuid, but the auth id itself can be replayed, so there is no
    /// stored credential for a timing probe to walk a byte at a time.
    ///
    /// A disabled user reports absent, same as `accept`. The auth id names a user
    /// without proving anything an observer could not have copied, so the handler
    /// waits to admit it until the header AEAD opens. See
    /// [`UserRegistry::find_vmess_auth_id`].
    fn accept_vmess(&self, auth_id: &[u8; 16]) -> Option<VmessIdentity> {
        let key = self.vmess.as_ref()?;
        let timestamp = key.open(auth_id)?;
        if !self.context.is_enabled() {
            return None;
        }
        Some(VmessIdentity {
            user: self.context.clone(),
            instruction_key: *key.instruction_key(),
            timestamp,
        })
    }
}

/// A user table that can be mutated while the inbound it belongs to is serving.
pub struct MemoryUserRegistry {
    kinds: CredentialKinds,
    /// Serialises `upsert` and `remove`, and nothing else.
    ///
    /// The maps below are individually concurrent, but a mutation touches several of
    /// them and has to look before it writes: `check_credentials_unclaimed` reads the
    /// indexes, and `upsert` reads the previous entry to work out which index keys to
    /// retire. Without this lock those reads are a time-of-check window, and two
    /// concurrent writers walk straight through it -- two users are both told they
    /// were granted the same uuid when only one of them can ever authenticate, and a
    /// credential rotated away by one writer stays live in an index the other
    /// rebuilt. Both were reproducible on the first try, not rare races.
    ///
    /// It is deliberately *not* the engine's control lock. That one is async and is
    /// held across socket work; this one is a `std::sync::Mutex` held for a few map
    /// writes with no await in between, which is what keeps `add_user` a synchronous
    /// method.
    ///
    /// **No lookup ever takes it.** The connection path reads the maps directly, so
    /// authentication still never waits on a control-plane call -- the invariant this
    /// module exists to hold.
    writer: Mutex<()>,
    /// id -> user. Authoritative: `list` and `remove` work from this map, and it is
    /// the only place a user without a usable credential could be observed.
    users: DashMap<Arc<str>, Arc<Entry>>,
    /// Removed users whose existing connections are still shutting down. Keeping a
    /// tombstone prevents the same public id from acquiring a second accounting
    /// generation before the first one has produced its final counters.
    ///
    /// The state stores the final snapshot. A detached finalizer can complete after
    /// the first `remove_user` future is cancelled, and a repeated call attaches to
    /// this same generation instead of losing its last billing result.
    draining: Arc<DashMap<Arc<str>, Arc<DrainingUser>>>,
    /// wire uuid -> user. The index `find_uuid` hits.
    by_uuid: DashMap<[u8; 16], Arc<Entry>>,
    /// wire hash -> user. The index `find_trojan_hash` hits.
    by_trojan_hash: DashMap<Box<[u8]>, Arc<Entry>>,
    /// cleartext password -> user. The index `find_password` hits.
    by_password: DashMap<Box<str>, Arc<Entry>>,
    /// named psk -> user. The index `find_shadowsocks_psk_hash` hits.
    by_psk_hash: DashMap<[u8; 16], Arc<Entry>>,
    /// sha256(password) -> user. The index `find_password_sha256` hits.
    by_anytls_hash: DashMap<[u8; 32], Arc<Entry>>,
    /// base64("id:password") -> user. The index `find_naive_basic` hits.
    by_naive_encoded: DashMap<Box<[u8]>, Arc<Entry>>,
    /// How many live users' hashes start with each 8-byte prefix.
    ///
    /// A count rather than a set, because two users can share a prefix and removing
    /// one must not blind the probe to the other. Entries are dropped when the count
    /// reaches zero, so the map does not grow across rotations.
    anytls_prefixes: DashMap<[u8; 8], usize>,
    /// Every uuid-bearing user, as an immutable snapshot for VMess to walk. Not an
    /// index -- there is nothing to index on -- so it is republished whole on each
    /// mutation. See the module docs.
    vmess_candidates: ArcSwap<Vec<Arc<Entry>>>,
}

impl std::fmt::Debug for MemoryUserRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryUserRegistry")
            .field("kinds", &self.kinds)
            .field("num_users", &self.users.len())
            .field("num_draining", &self.draining.len())
            .finish()
    }
}

impl MemoryUserRegistry {
    pub fn new(kinds: CredentialKinds) -> Arc<Self> {
        Arc::new(Self {
            kinds,
            users: DashMap::new(),
            draining: Arc::new(DashMap::new()),
            by_uuid: DashMap::new(),
            by_trojan_hash: DashMap::new(),
            by_password: DashMap::new(),
            by_psk_hash: DashMap::new(),
            by_anytls_hash: DashMap::new(),
            anytls_prefixes: DashMap::new(),
            by_naive_encoded: DashMap::new(),
            vmess_candidates: ArcSwap::from_pointee(Vec::new()),
            writer: Mutex::new(()),
        })
    }

    pub fn kinds(&self) -> CredentialKinds {
        self.kinds
    }

    pub fn len(&self) -> usize {
        self.users.len()
    }

    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }

    /// Adds a user, or updates one that already has this id.
    ///
    /// An update keeps the existing [`UserContext`], so the user's counters carry
    /// over and, more importantly, connections already metering into that record
    /// keep hitting the same one. Replacing the record instead would strand every
    /// in-flight byte in an object nobody reports on.
    ///
    /// Writers are serialised by [`MemoryUserRegistry::writer`], so the
    /// authoritative map and the credential indexes cannot be observed disagreeing
    /// about which user owns a credential. The engine's control lock is *not* what
    /// does this -- user mutations are deliberately outside it, so that adding a user
    /// never waits on a reload.
    pub fn upsert(&self, spec: UserSpec) -> EngineResult<UserInfo> {
        // Held across the whole check-then-write below, which is the only reason the
        // duplicate-credential check and the index retirement mean anything.
        let _writer = self.lock_writer();

        let id: Arc<str> = match spec.resolved_id() {
            Some(id) if !id.trim().is_empty() => id.into(),
            _ => {
                return Err(EngineError::InvalidUser(
                    "user needs an `id`, or a `uuid` to use as one".into(),
                ));
            }
        };

        if let Some(draining) = self.draining.get(id.as_ref()) {
            let state = if draining.entry.context.conns() == 0 {
                "has completed removal, but its final counters have not been collected"
            } else {
                "is still disconnecting after removal"
            };
            return Err(EngineError::InvalidUser(format!(
                "user {id} {state}; call remove_user again to collect that removal before re-adding the id"
            )));
        }

        let credentials = self.parse_credentials(&id, &spec)?;
        self.check_credentials_unclaimed(&id, &credentials)?;

        // Everything past here must succeed: the table is about to change.
        let previous = self.users.get(&id).map(|entry| entry.value().clone());

        let context = match &previous {
            Some(entry) => entry.context.clone(),
            None => UserContext::new(id.clone()),
        };
        context.set_enabled(spec.enabled);
        // Applied on every upsert, so an update that omits the field clears a
        // previously set ceiling rather than silently keeping it. `UserSpec` is a
        // whole-record description, not a patch: the same reason an omitted
        // credential is rotated away above rather than preserved.
        context.set_max_conns(spec.max_conns.unwrap_or(0));
        context.set_speed_limits(
            spec.upload_limit_bps.unwrap_or(0),
            spec.download_limit_bps.unwrap_or(0),
        );

        let entry = Arc::new(Entry {
            context,
            uuid: credentials.uuid,
            trojan_hash: credentials.trojan_hash,
            password: credentials.password,
            shadowsocks: credentials.shadowsocks,
            // Nothing to retire below, unlike the fields above it: this is carried on
            // the entry rather than indexed, so rotating it replaces the whole record.
            tuic_password: credentials.tuic_password,
            anytls_hash: credentials.anytls_hash,
            naive_encoded: credentials.naive_encoded,
            // Built whenever the user has a uuid, whether or not this inbound speaks
            // VMess. One registry serves a whole inbound, and a TLS inbound can carry
            // VLESS on one SNI and VMess on another, so "is VMess in use here" is not
            // a question this type is in a position to answer.
            vmess: credentials.uuid.as_ref().map(VmessAuthKey::new),
        });

        // Retire index keys the user no longer presents, or an old credential would
        // keep working after being rotated away.
        if let Some(previous) = previous {
            if previous.uuid != entry.uuid
                && let Some(uuid) = previous.uuid
            {
                self.by_uuid.remove(&uuid);
            }
            if previous.trojan_hash != entry.trojan_hash
                && let Some(hash) = &previous.trojan_hash
            {
                self.by_trojan_hash.remove(hash);
            }
            if previous.password != entry.password
                && let Some(password) = &previous.password
            {
                self.by_password.remove(password);
            }
            if let Some(old) = &previous.shadowsocks
                && entry.shadowsocks.as_ref().map(|new| new.hash) != Some(old.hash)
            {
                self.by_psk_hash.remove(&old.hash);
            }
            if previous.anytls_hash != entry.anytls_hash
                && let Some(hash) = previous.anytls_hash
            {
                self.by_anytls_hash.remove(&hash);
                self.release_anytls_prefix(&hash);
            }
            if previous.naive_encoded != entry.naive_encoded
                && let Some(encoded) = &previous.naive_encoded
            {
                self.by_naive_encoded.remove(encoded);
            }
        }

        if let Some(uuid) = entry.uuid {
            self.by_uuid.insert(uuid, entry.clone());
        }
        if let Some(hash) = &entry.trojan_hash {
            self.by_trojan_hash.insert(hash.clone(), entry.clone());
        }
        if let Some(password) = &entry.password {
            self.by_password.insert(password.clone(), entry.clone());
        }
        if let Some(shadowsocks) = &entry.shadowsocks {
            self.by_psk_hash.insert(shadowsocks.hash, entry.clone());
        }
        if let Some(encoded) = &entry.naive_encoded {
            self.by_naive_encoded.insert(encoded.clone(), entry.clone());
        }
        if let Some(hash) = entry.anytls_hash
            && self.by_anytls_hash.insert(hash, entry.clone()).is_none()
        {
            // Only on a genuinely new key: re-registering the same hash under the
            // same id must not double-count the prefix.
            self.claim_anytls_prefix(&hash);
        }
        self.users.insert(id, entry.clone());
        self.republish_vmess();

        Ok(user_info(&entry.context))
    }

    /// Removes a user, closes every connection authenticated as them, and returns
    /// only after their counters are final.
    ///
    /// Revocation and index retirement happen under the writer lock, but the async
    /// drain does not: unrelated user mutations remain fast while sockets close.
    /// On the normal Tokio engine runtime a detached finalizer owns the wait, so
    /// cancelling this control-plane future does not cancel disconnection. Its final
    /// snapshot stays on the drain tombstone and a repeated remove returns it. The
    /// tombstone also prevents a second generation of the same id from overlapping;
    /// it remains reserved until a repeated remove collects the result, including
    /// when the original Tokio runtime shut down while the finalizer was pending.
    pub async fn remove(&self, tag: &str, id: &str) -> EngineResult<UserInfo> {
        let (generation, newly_removed) = {
            // Same lock as `upsert`: removing a user reads their entry to learn which
            // index keys are theirs, and a concurrent upsert of the same id would make
            // that answer stale between the read and the removals.
            let _writer = self.lock_writer();

            match self.users.get(id).map(|entry| entry.value().clone()) {
                Some(entry) => {
                    // This is the removal linearization point. Old map/ArcSwap
                    // readers may still hold the Entry, but admission and connection
                    // registration now fail closed and all registered connections
                    // are signalled.
                    entry.context.revoke_connections();
                    self.users.remove(id);
                    let generation = DrainingUser::new(entry.clone());
                    self.draining
                        .insert(entry.context.id().clone(), generation.clone());

                    if let Some(uuid) = entry.uuid {
                        self.by_uuid.remove(&uuid);
                    }
                    if let Some(hash) = &entry.trojan_hash {
                        self.by_trojan_hash.remove(hash);
                    }
                    if let Some(password) = &entry.password {
                        self.by_password.remove(password);
                    }
                    if let Some(shadowsocks) = &entry.shadowsocks {
                        self.by_psk_hash.remove(&shadowsocks.hash);
                    }
                    if let Some(hash) = entry.anytls_hash {
                        self.by_anytls_hash.remove(&hash);
                        self.release_anytls_prefix(&hash);
                    }
                    if let Some(encoded) = &entry.naive_encoded {
                        self.by_naive_encoded.remove(encoded);
                    }
                    self.republish_vmess();
                    (generation, true)
                }
                None => {
                    let generation = self
                        .draining
                        .get(id)
                        .map(|entry| entry.value().clone())
                        .ok_or_else(|| EngineError::UnknownUser {
                            tag: tag.to_string(),
                            id: id.to_string(),
                        })?;
                    (generation, false)
                }
            }
        };

        if !newly_removed {
            let info = generation.finish().await;
            clear_draining_generation(&self.draining, &generation);
            return Ok(info);
        }

        let finalizer_generation = generation.clone();
        let finalizer = async move { finalizer_generation.finish().await };

        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            match runtime.spawn(finalizer).await {
                Ok(info) => {
                    clear_draining_generation(&self.draining, &generation);
                    Ok(info)
                }
                Err(error) => {
                    // Leave the generation recoverable for a repeated remove. If
                    // every connection did close before task cancellation, publish
                    // its snapshot now so the retry completes immediately.
                    if generation.entry.context.conns() == 0 {
                        generation.complete();
                    }
                    Err(EngineError::Io(std::io::Error::other(format!(
                        "user removal finalizer failed: {error}"
                    ))))
                }
            }
        } else {
            // Engine operations normally run on Tokio. Polling this future from a
            // different executor is still safe: wait inline rather than panicking at
            // tokio::spawn. A cancelled caller leaves a generation that a repeated
            // remove can finish and collect after its connections close.
            let info = finalizer.await;
            clear_draining_generation(&self.draining, &generation);
            Ok(info)
        }
    }

    pub fn get(&self, id: &str) -> Option<UserInfo> {
        self.users.get(id).map(|entry| user_info(&entry.context))
    }

    /// Cancels the user's currently open connections without removing or
    /// disabling the user. New authentications are allowed immediately.
    pub fn kick(&self, tag: &str, id: &str) -> EngineResult<u64> {
        let entry = self.users.get(id).ok_or_else(|| EngineError::UnknownUser {
            tag: tag.to_string(),
            id: id.to_string(),
        })?;
        Ok(entry.context.kick_connections())
    }

    /// Reports one user's traffic and zeroes it, in a single step.
    ///
    /// For closing a billing period. Reading and then zeroing as two calls would drop
    /// whatever moved in between; the swap underneath this is what makes every byte
    /// land in exactly one period.
    ///
    /// The returned [`UserInfo`] carries the bytes that were *taken*, not the zeroes
    /// left behind. `conns` and `total_conns` are untouched -- they are live state and
    /// a lifetime count, neither of which belongs to a period.
    pub fn take_traffic(&self, tag: &str, id: &str) -> EngineResult<UserInfo> {
        let entry = self.users.get(id).ok_or_else(|| EngineError::UnknownUser {
            tag: tag.to_string(),
            id: id.to_string(),
        })?;
        Ok(taken_user_info(&entry.context))
    }

    /// The same, for every user at once: the usual shape of a billing sweep.
    ///
    /// Not a snapshot. Each user is taken individually, so a user metering traffic
    /// while the sweep runs has their bytes split across two periods rather than
    /// counted twice or lost -- which is the property that actually matters here.
    ///
    /// A user removed mid-sweep may be missing from the result; [`Self::remove`]
    /// already reports their final counters, so that is where their last bytes are.
    pub fn take_all_traffic(&self) -> Vec<UserInfo> {
        let mut infos: Vec<UserInfo> = self
            .users
            .iter()
            .map(|entry| taken_user_info(&entry.value().context))
            .collect();
        infos.sort_by(|a, b| a.id.cmp(&b.id));
        infos
    }

    pub fn list(&self) -> Vec<UserInfo> {
        let mut infos: Vec<UserInfo> = self
            .users
            .iter()
            .map(|entry| user_info(&entry.value().context))
            .collect();
        infos.sort_by(|a, b| a.id.cmp(&b.id));
        infos
    }

    /// Turns a spec's operator-facing credentials into wire-form index keys.
    ///
    /// A credential this inbound's protocol cannot use is an error rather than a
    /// field that gets dropped: silently ignoring it would report success for a
    /// user who can never connect.
    ///
    /// `password` is read as whichever form the inbound wants. It cannot want both --
    /// [`CredentialKinds::conflict`] refuses that combination before a registry is
    /// built -- so there is no ambiguity to resolve here.
    ///
    /// `id` is taken as well as the spec because NaiveProxy's credential contains it:
    /// its wire form is base64 of `username:password`, and the id is the username.
    fn parse_credentials(&self, id: &str, spec: &UserSpec) -> EngineResult<Credentials> {
        if spec.uuid.is_some() && !self.kinds.uuid {
            return Err(EngineError::InvalidUser(format!(
                "this inbound does not authenticate by uuid; it accepts {}",
                self.kinds.accepted_fields()
            )));
        }
        if spec.password.is_some() && !self.kinds.takes_password() {
            return Err(EngineError::InvalidUser(format!(
                "this inbound does not authenticate by password; it accepts {}",
                self.kinds.accepted_fields()
            )));
        }
        if spec.uuid.is_none() && spec.password.is_none() {
            return Err(EngineError::InvalidUser(format!(
                "user needs a credential: {}",
                self.kinds.accepted_fields()
            )));
        }
        // The one form that needs two fields at once. Refused here rather than left to
        // the lookup, where a user missing half would simply never match and look to
        // the operator like a client problem.
        if self.kinds.tuic && (spec.uuid.is_none() || spec.password.is_none()) {
            return Err(EngineError::InvalidUser(
                "a tuic user needs both `uuid` and `password`: the uuid names them \
                 on the wire and the password keys the token beside it"
                    .to_string(),
            ));
        }

        let uuid = match spec.uuid.as_deref() {
            Some(uuid) => Some(
                credential::parse_uuid(uuid)
                    .map_err(|e| EngineError::InvalidUser(e.to_string()))?,
            ),
            None => None,
        };

        let shadowsocks = match (spec.password.as_deref(), self.kinds.shadowsocks_psk) {
            (Some(password), ShadowsocksPsk::Len(len)) => {
                let psk = credential::decode_shadowsocks_psk(password)
                    .map_err(|e| EngineError::InvalidUser(e.to_string()))?;
                if psk.len() != len {
                    return Err(EngineError::InvalidUser(format!(
                        "this inbound's cipher needs a {} byte psk, and `password` \
                         base64 decoded to {}",
                        len,
                        psk.len()
                    )));
                }
                Some(ShadowsocksCredential {
                    hash: credential::shadowsocks_psk_hash(&psk),
                    psk,
                })
            }
            _ => None,
        };

        Ok(Credentials {
            uuid,
            trojan_hash: match self.kinds.trojan_password {
                true => spec
                    .password
                    .as_deref()
                    .map(credential::trojan_password_hash),
                false => None,
            },
            // Kept as sent, and deliberately not deduplicated against `trojan_hash`:
            // an inbound that speaks both wants the same value indexed twice, once
            // hashed and once not.
            password: match self.kinds.plain_password {
                true => spec.password.as_deref().map(Box::from),
                false => None,
            },
            shadowsocks,
            tuic_password: match self.kinds.tuic {
                true => spec.password.as_deref().map(Arc::from),
                false => None,
            },
            anytls_hash: match self.kinds.anytls_password {
                true => spec.password.as_deref().map(credential::password_sha256),
                false => None,
            },
            // The id is the username half. `UserSpec` has no field for one, and
            // adding a public field for a single protocol is a worse trade than
            // saying plainly that on a naive inbound the id is part of the
            // credential -- so renaming a user rotates it.
            naive_encoded: match self.kinds.naive_basic {
                true => spec
                    .password
                    .as_deref()
                    .map(|password| credential::naive_basic_credential(id, password)),
                false => None,
            },
        })
    }

    /// Rejects a credential that already belongs to a different user.
    ///
    /// Without this the second insert would overwrite the first user's index entry,
    /// leaving them listed but unable to connect -- a failure that looks like
    /// nothing went wrong.
    fn check_credentials_unclaimed(&self, id: &str, credentials: &Credentials) -> EngineResult<()> {
        if let Some(uuid) = credentials.uuid
            && let Some(owner) = self.credential_owner_uuid(&uuid)
            && &*owner != id
        {
            return Err(EngineError::DuplicateCredential {
                id: id.to_string(),
                owner: owner.to_string(),
            });
        }
        if let Some(hash) = &credentials.trojan_hash
            && let Some(owner) = self.credential_owner_trojan(hash)
            && &*owner != id
        {
            return Err(EngineError::DuplicateCredential {
                id: id.to_string(),
                owner: owner.to_string(),
            });
        }
        if let Some(password) = &credentials.password
            && let Some(owner) = self.credential_owner_password(password)
            && &*owner != id
        {
            return Err(EngineError::DuplicateCredential {
                id: id.to_string(),
                owner: owner.to_string(),
            });
        }
        if let Some(shadowsocks) = &credentials.shadowsocks
            && let Some(owner) = self.credential_owner_psk(&shadowsocks.hash)
            && &*owner != id
        {
            return Err(EngineError::DuplicateCredential {
                id: id.to_string(),
                owner: owner.to_string(),
            });
        }
        if let Some(hash) = &credentials.anytls_hash
            && let Some(owner) = self.credential_owner_anytls(hash)
            && &*owner != id
        {
            return Err(EngineError::DuplicateCredential {
                id: id.to_string(),
                owner: owner.to_string(),
            });
        }
        // The id being baked into this one does *not* make it collision-free, which
        // is what an earlier version of this function assumed. `id:password` is
        // ambiguous where an id may contain a colon: ("alice", "b:c") and
        // ("alice:b", "c") encode the same bytes, so without this check the second
        // one silently takes over the first one's index entry and the first user is
        // listed but can never connect -- the exact failure the rest of this
        // function exists to prevent.
        if let Some(encoded) = &credentials.naive_encoded
            && let Some(owner) = self.credential_owner_naive(encoded)
            && &*owner != id
        {
            return Err(EngineError::DuplicateCredential {
                id: id.to_string(),
                owner: owner.to_string(),
            });
        }
        Ok(())
    }

    /// Take the writer lock, recovering from a poisoned one.
    ///
    /// The mutex guards `()`, so there is no state a panicking writer could have left
    /// half-updated for the next one to observe -- the maps are what carry the state,
    /// and a poisoned lock says nothing about them. Refusing every later write would
    /// turn one panic into a permanently unmanageable inbound.
    fn lock_writer(&self) -> std::sync::MutexGuard<'_, ()> {
        self.writer.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Note one more live user whose hash starts with this prefix.
    fn claim_anytls_prefix(&self, hash: &[u8; 32]) {
        *self
            .anytls_prefixes
            .entry(credential::password_sha256_prefix(hash))
            .or_insert(0) += 1;
    }

    /// Drop one, removing the entry entirely at zero so the map does not grow.
    fn release_anytls_prefix(&self, hash: &[u8; 32]) {
        let prefix = credential::password_sha256_prefix(hash);
        if let dashmap::mapref::entry::Entry::Occupied(mut entry) =
            self.anytls_prefixes.entry(prefix)
        {
            let count = entry.get_mut();
            *count = count.saturating_sub(1);
            if *count == 0 {
                entry.remove();
            }
        }
    }

    fn credential_owner_uuid(&self, uuid: &[u8; 16]) -> Option<Arc<str>> {
        self.by_uuid.get(uuid).map(|e| e.context.id().clone())
    }

    fn credential_owner_trojan(&self, hash: &[u8]) -> Option<Arc<str>> {
        self.by_trojan_hash
            .get(hash)
            .map(|e| e.context.id().clone())
    }

    fn credential_owner_password(&self, password: &str) -> Option<Arc<str>> {
        self.by_password
            .get(password)
            .map(|e| e.context.id().clone())
    }

    fn credential_owner_psk(&self, hash: &[u8; 16]) -> Option<Arc<str>> {
        self.by_psk_hash.get(hash).map(|e| e.context.id().clone())
    }

    fn credential_owner_anytls(&self, hash: &[u8; 32]) -> Option<Arc<str>> {
        self.by_anytls_hash
            .get(hash)
            .map(|e| e.context.id().clone())
    }

    fn credential_owner_naive(&self, encoded: &[u8]) -> Option<Arc<str>> {
        self.by_naive_encoded
            .get(encoded)
            .map(|e| e.context.id().clone())
    }

    /// Republish the VMess trial snapshot from the authoritative map.
    ///
    /// Rebuilt whole rather than patched, so it cannot drift from the map it is
    /// derived from. The cost is one allocation and one pass over the users, on a
    /// control-plane path that already holds the engine's write lock -- and it buys a
    /// candidate lookup that takes no index lock at all. The handler still enters the
    /// winning user's lifecycle gate after decrypting the header.
    ///
    /// The snapshot lags the maps by the few instructions between the two writes. A
    /// connection landing in that window can see the *older* set, so a just-added user
    /// is briefly unknown. A removed candidate cannot get back in through the stale
    /// snapshot: after opening the header the handler atomically admits and binds the
    /// connection, and revocation makes that operation fail closed.
    fn republish_vmess(&self) {
        let candidates: Vec<Arc<Entry>> = self
            .users
            .iter()
            .filter(|entry| entry.value().vmess.is_some())
            .map(|entry| entry.value().clone())
            .collect();
        self.vmess_candidates.store(Arc::new(candidates));
    }
}

impl UserRegistry for MemoryUserRegistry {
    fn find_uuid(&self, uuid: &[u8; 16]) -> Option<Arc<UserContext>> {
        let entry = self.by_uuid.get(uuid)?;
        let expected = entry.uuid.as_ref()?;
        entry.accept(&expected[..], &uuid[..])
    }

    fn find_trojan_hash(&self, hash: &[u8]) -> Option<Arc<UserContext>> {
        let entry = self.by_trojan_hash.get(hash)?;
        let expected = entry.trojan_hash.as_deref()?;
        entry.accept(expected, hash)
    }

    /// The whole of Hysteria2 authentication: the client sends its password in
    /// cleartext, so a hit on the index is the credential.
    ///
    /// The map lookup found this entry by hash, which is not constant time and proves
    /// nothing; `accept` re-checks the bytes, same as every other lookup here.
    fn find_password(&self, password: &str) -> Option<Arc<UserContext>> {
        let entry = self.by_password.get(password)?;
        let expected = entry.password.as_deref()?;
        entry.accept(expected.as_bytes(), password.as_bytes())
    }

    fn find_vmess_auth_id(&self, auth_id: &[u8; 16]) -> Option<VmessIdentity> {
        // Linear in the user count, by necessity -- see the trait method's docs. The
        // `load` is a pointer read, so the walk holds no lock: a concurrent `upsert`
        // neither blocks it nor mutates the slice underneath it.
        self.vmess_candidates
            .load()
            .iter()
            .find_map(|entry| entry.accept_vmess(auth_id))
    }

    /// Who an identity header named, and the key their session derives from.
    ///
    /// The header is sealed under the *inbound's* key rather than this user's, so it
    /// names them without showing the sender is them. The handler admits it once the
    /// record layer opens a chunk. See the trait method's docs.
    fn find_shadowsocks_psk_hash(&self, hash: &[u8; 16]) -> Option<ShadowsocksIdentity> {
        let entry = self.by_psk_hash.get(hash)?;
        let credential = entry.shadowsocks.as_ref()?;
        let expected = &credential.hash;
        if expected.ct_eq(&hash[..]).unwrap_u8() == 0 || !entry.context.is_enabled() {
            return None;
        }
        Some(ShadowsocksIdentity {
            user: entry.context.clone(),
            psk: credential.psk.clone(),
        })
    }

    /// The uuid half of a TUIC credential, plus the password its token is keyed with.
    ///
    /// The token that proves the client holds that password has not been checked yet
    /// and cannot be checked from here, so there is nothing yet to admit. The handler
    /// admits it once the token matches. See the trait method's docs.
    ///
    /// A user registered without a TUIC password -- which this inbound's
    /// `parse_credentials` refuses, but a registry built for another protocol would
    /// hold -- is absent here rather than authenticated on their uuid alone.
    fn find_tuic_uuid(&self, uuid: &[u8; 16]) -> Option<TuicIdentity> {
        let entry = self.by_uuid.get(uuid)?;
        let password = entry.tuic_password.clone()?;
        let expected = entry.uuid.as_ref()?;
        if expected.ct_eq(&uuid[..]).unwrap_u8() == 0 || !entry.context.is_enabled() {
            return None;
        }
        Some(TuicIdentity {
            user: entry.context.clone(),
            password,
        })
    }

    fn find_password_sha256(&self, hash: &[u8; 32]) -> Option<Arc<UserContext>> {
        let entry = self.by_anytls_hash.get(hash)?;
        let expected = entry.anytls_hash.as_ref()?;
        entry.accept(&expected[..], &hash[..])
    }

    /// Whether it is worth reading the other 24 bytes.
    ///
    /// Deliberately no `is_enabled` check, unlike every lookup here: this is a
    /// plausibility test, and answering `false` for a suspended user would divert
    /// their connections to the fallback while a live user's went to the handler --
    /// an observable difference that leaks who has been suspended. See the trait
    /// method's docs.
    fn has_password_sha256_prefix(&self, prefix: &[u8; 8]) -> bool {
        self.anytls_prefixes.contains_key(prefix)
    }

    fn find_naive_basic(&self, encoded: &[u8]) -> Option<Arc<UserContext>> {
        let entry = self.by_naive_encoded.get(encoded)?;
        let expected = entry.naive_encoded.as_deref()?;
        entry.accept(expected, encoded)
    }

    fn user_count(&self) -> usize {
        self.users.len()
    }
}

/// [`user_info`], but the byte counters are taken rather than read.
fn taken_user_info(context: &UserContext) -> UserInfo {
    // The swaps decide the reported figure: they are the only reads that also
    // close the period, so each increment belongs to exactly one drain.
    let (tx, rx) = context.take_traffic();
    // Byte increments publish their observation time before incrementing the
    // counter. Read it after both swaps so every byte included above has also made
    // its timestamp visible to this snapshot.
    let mut info = user_info(context);
    info.tx = tx;
    info.rx = rx;
    info
}

fn user_info(context: &UserContext) -> UserInfo {
    let stats = context.stats();
    UserInfo {
        id: stats.id.to_string(),
        enabled: stats.enabled,
        tx: stats.tx,
        rx: stats.rx,
        last_traffic_observed_at_unix_millis: stats.last_traffic_observed_at_unix_millis,
        conns: stats.conns,
        total_conns: stats.total_conns,
        max_conns: stats.max_conns,
        upload_limit_bps: stats.upload_limit_bps,
        download_limit_bps: stats.download_limit_bps,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shoes::dynamic::ConnContext;

    const UUID_A: &str = "b85798ef-e9dc-46a4-9a87-8da4499d36d0";
    const UUID_B: &str = "11111111-1111-4111-8111-111111111111";
    const UUID_C: &str = "22222222-2222-4222-8222-222222222222";

    fn uuid_bytes(s: &str) -> [u8; 16] {
        credential::parse_uuid(s).unwrap()
    }

    fn uuid_spec(id: &str, uuid: &str) -> UserSpec {
        UserSpec {
            id: Some(id.to_string()),
            uuid: Some(uuid.to_string()),
            password: None,
            enabled: true,
            max_conns: None,
            upload_limit_bps: None,
            download_limit_bps: None,
        }
    }

    fn psk_spec(id: &str, psk: &[u8]) -> UserSpec {
        UserSpec {
            id: Some(id.to_string()),
            uuid: None,
            password: Some(credential::encode_shadowsocks_psk(psk)),
            enabled: true,
            max_conns: None,
            upload_limit_bps: None,
            download_limit_bps: None,
        }
    }

    fn naive_spec(id: &str, password: &str) -> UserSpec {
        UserSpec {
            id: Some(id.to_string()),
            uuid: None,
            password: Some(password.to_string()),
            enabled: true,
            max_conns: None,
            upload_limit_bps: None,
            download_limit_bps: None,
        }
    }

    fn trojan_spec(id: &str, password: &str) -> UserSpec {
        UserSpec {
            id: Some(id.to_string()),
            uuid: None,
            password: Some(password.to_string()),
            enabled: true,
            max_conns: None,
            upload_limit_bps: None,
            download_limit_bps: None,
        }
    }

    /// A 2022 PSK spec. The key is `len` bytes derived from `id`, so distinct users
    /// get distinct keys without any of them being a real secret.
    fn tuic_spec(id: &str, uuid: &str, password: &str) -> UserSpec {
        UserSpec {
            id: Some(id.to_string()),
            uuid: Some(uuid.to_string()),
            password: Some(password.to_string()),
            enabled: true,
            max_conns: None,
            upload_limit_bps: None,
            download_limit_bps: None,
        }
    }

    fn ss_spec(id: &str, len: usize) -> UserSpec {
        UserSpec {
            id: Some(id.to_string()),
            uuid: None,
            password: Some(credential::encode_shadowsocks_psk(&ss_psk(id, len))),
            enabled: true,
            max_conns: None,
            upload_limit_bps: None,
            download_limit_bps: None,
        }
    }

    fn ss_psk(id: &str, len: usize) -> Vec<u8> {
        id.bytes().cycle().take(len).collect()
    }

    /// The 16 bytes a client's identity header decrypts to for this user.
    fn ss_name(id: &str, len: usize) -> [u8; 16] {
        credential::shadowsocks_psk_hash(&ss_psk(id, len))
    }

    #[test]
    fn an_empty_registry_denies_everyone() {
        let registry = MemoryUserRegistry::new(CredentialKinds::UUID);
        assert_eq!(registry.user_count(), 0);
        assert!(registry.find_uuid(&uuid_bytes(UUID_A)).is_none());
    }

    #[tokio::test]
    async fn authenticates_two_users_independently() {
        // The phase 2 acceptance case: two users on one inbound, each with their own
        // record, and removing one leaves the other untouched.
        let registry = MemoryUserRegistry::new(CredentialKinds::UUID);
        registry.upsert(uuid_spec("alice", UUID_A)).unwrap();
        registry.upsert(uuid_spec("bob", UUID_B)).unwrap();

        let alice = registry.find_uuid(&uuid_bytes(UUID_A)).unwrap();
        let bob = registry.find_uuid(&uuid_bytes(UUID_B)).unwrap();
        assert_eq!(&**alice.id(), "alice");
        assert_eq!(&**bob.id(), "bob");
        assert!(!Arc::ptr_eq(&alice, &bob));

        alice.add_tx(100);
        bob.add_tx(7);
        assert_eq!((alice.tx(), bob.tx()), (100, 7));

        registry.remove("in", "alice").await.unwrap();
        assert!(registry.find_uuid(&uuid_bytes(UUID_A)).is_none());
        assert!(registry.find_uuid(&uuid_bytes(UUID_B)).is_some());
        assert!(alice.is_revoked());
        assert!(!bob.is_revoked());

        // Re-adding the public id creates a fresh lifecycle; the permanently
        // cancelled record can never poison its replacement.
        registry.upsert(uuid_spec("alice", UUID_A)).unwrap();
        let replacement = registry.find_uuid(&uuid_bytes(UUID_A)).unwrap();
        assert!(!Arc::ptr_eq(&alice, &replacement));
        assert!(!replacement.is_revoked());
    }

    #[tokio::test]
    async fn kick_ends_current_sessions_without_revoking_the_user() {
        let registry = MemoryUserRegistry::new(CredentialKinds::UUID);
        registry.upsert(uuid_spec("alice", UUID_A)).unwrap();
        let alice = registry.find_uuid(&uuid_bytes(UUID_A)).unwrap();

        let current = ConnContext::new();
        assert!(current.bind_authenticated(Arc::clone(&alice)));
        assert_eq!(registry.kick("in", "alice").unwrap(), 1);
        tokio::time::timeout(std::time::Duration::from_secs(1), current.cancelled())
            .await
            .expect("the current connection must be signalled");

        assert!(!alice.is_revoked());
        assert!(registry.find_uuid(&uuid_bytes(UUID_A)).is_some());
        let replacement = ConnContext::new();
        assert!(replacement.bind_authenticated(alice));
    }

    #[tokio::test]
    async fn cancelling_remove_keeps_its_final_snapshot_recoverable_by_retry() {
        let registry = MemoryUserRegistry::new(CredentialKinds::UUID);
        registry.upsert(uuid_spec("alice", UUID_A)).unwrap();
        let alice = registry.find_uuid(&uuid_bytes(UUID_A)).unwrap();
        let connection = ConnContext::new();
        assert!(connection.bind_authenticated(Arc::clone(&alice)));
        alice.add_rx(123);

        let remover_registry = Arc::clone(&registry);
        let remover = tokio::spawn(async move { remover_registry.remove("in", "alice").await });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !alice.is_revoked() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("removal must linearise");

        remover.abort();
        let _ = remover.await;
        assert!(registry.get("alice").is_none());
        assert!(
            registry.upsert(uuid_spec("alice", UUID_A)).is_err(),
            "the old accounting generation is still draining"
        );

        drop(connection);
        assert!(
            registry.upsert(uuid_spec("alice", UUID_A)).is_err(),
            "a completed removal keeps the id reserved until its result is collected"
        );
        let recovered = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            registry.remove("in", "alice"),
        )
        .await
        .expect("a repeated remove must attach to the detached finalizer")
        .expect("the final snapshot remains recoverable");
        assert_eq!(recovered.rx, 123);
        assert_eq!(recovered.conns, 0);
        assert!(registry.draining.is_empty());

        registry
            .upsert(uuid_spec("alice", UUID_A))
            .expect("the id can be reused after all old connections close");
    }

    #[test]
    fn a_stale_finalizer_cannot_clear_a_new_generation_tombstone() {
        let registry = MemoryUserRegistry::new(CredentialKinds::UUID);
        registry.upsert(uuid_spec("alice", UUID_A)).unwrap();
        let old = registry.users.get("alice").unwrap().value().clone();

        let replacement_registry = MemoryUserRegistry::new(CredentialKinds::UUID);
        replacement_registry
            .upsert(uuid_spec("alice", UUID_B))
            .unwrap();
        let replacement = replacement_registry
            .users
            .get("alice")
            .unwrap()
            .value()
            .clone();

        let old_generation = DrainingUser::new(old);
        let replacement_generation = DrainingUser::new(replacement);

        registry.draining.insert(
            replacement_generation.entry.context.id().clone(),
            replacement_generation.clone(),
        );
        clear_draining_generation(&registry.draining, &old_generation);

        let current = registry.draining.get("alice").unwrap();
        assert!(Arc::ptr_eq(current.value(), &replacement_generation));
    }

    #[test]
    fn repeated_lookups_share_one_record() {
        let registry = MemoryUserRegistry::new(CredentialKinds::UUID);
        registry.upsert(uuid_spec("alice", UUID_A)).unwrap();
        let first = registry.find_uuid(&uuid_bytes(UUID_A)).unwrap();
        let second = registry.find_uuid(&uuid_bytes(UUID_A)).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(
            first.total_conns(),
            0,
            "a revocable registry defers admission until the meter can register the connection"
        );
    }

    #[test]
    fn an_update_keeps_the_counters_and_rotates_the_credential() {
        let registry = MemoryUserRegistry::new(CredentialKinds::UUID);
        registry.upsert(uuid_spec("alice", UUID_A)).unwrap();
        let before = registry.find_uuid(&uuid_bytes(UUID_A)).unwrap();
        before.add_rx(4096);

        registry.upsert(uuid_spec("alice", UUID_B)).unwrap();
        assert_eq!(registry.user_count(), 1);

        // The retired uuid stops working, the new one starts.
        assert!(registry.find_uuid(&uuid_bytes(UUID_A)).is_none());
        let after = registry.find_uuid(&uuid_bytes(UUID_B)).unwrap();
        assert!(Arc::ptr_eq(&before, &after));
        assert_eq!(after.rx(), 4096);
    }

    #[test]
    fn the_connection_ceiling_survives_an_upsert_and_is_reported() {
        let registry = MemoryUserRegistry::new(CredentialKinds::UUID);
        let mut spec = uuid_spec("alice", UUID_A);
        spec.max_conns = Some(3);
        registry.upsert(spec).unwrap();

        let alice = registry.find_uuid(&uuid_bytes(UUID_A)).unwrap();
        assert_eq!(alice.max_conns(), 3);
        assert_eq!(registry.get("alice").unwrap().max_conns, 3);

        // Raising it keeps the same record, so the counters are not reset with it.
        alice.add_tx(64);
        let mut spec = uuid_spec("alice", UUID_A);
        spec.max_conns = Some(9);
        registry.upsert(spec).unwrap();
        assert_eq!(alice.max_conns(), 9);
        assert_eq!(registry.get("alice").unwrap().tx, 64);
    }

    #[test]
    fn an_upsert_without_a_ceiling_clears_the_previous_one() {
        // `UserSpec` describes a whole record rather than a patch, which is already
        // how a rotated-away credential behaves. A ceiling that silently outlived the
        // spec that stopped asking for it would be the one field that does not.
        let registry = MemoryUserRegistry::new(CredentialKinds::UUID);
        let mut spec = uuid_spec("alice", UUID_A);
        spec.max_conns = Some(3);
        registry.upsert(spec).unwrap();
        assert_eq!(
            registry.find_uuid(&uuid_bytes(UUID_A)).unwrap().max_conns(),
            3
        );

        registry.upsert(uuid_spec("alice", UUID_A)).unwrap();
        assert_eq!(
            registry.find_uuid(&uuid_bytes(UUID_A)).unwrap().max_conns(),
            0
        );
    }

    #[test]
    fn a_disabled_user_looks_absent_but_keeps_their_counters() {
        let registry = MemoryUserRegistry::new(CredentialKinds::UUID);
        registry.upsert(uuid_spec("alice", UUID_A)).unwrap();
        registry.find_uuid(&uuid_bytes(UUID_A)).unwrap().add_tx(10);

        let mut spec = uuid_spec("alice", UUID_A);
        spec.enabled = false;
        registry.upsert(spec).unwrap();
        assert!(registry.find_uuid(&uuid_bytes(UUID_A)).is_none());
        assert_eq!(registry.get("alice").unwrap().tx, 10);

        registry.upsert(uuid_spec("alice", UUID_A)).unwrap();
        assert!(registry.find_uuid(&uuid_bytes(UUID_A)).is_some());
    }

    #[test]
    fn rejects_a_credential_owned_by_another_user() {
        let registry = MemoryUserRegistry::new(CredentialKinds::UUID);
        registry.upsert(uuid_spec("alice", UUID_A)).unwrap();

        let err = registry.upsert(uuid_spec("bob", UUID_A)).unwrap_err();
        assert!(matches!(err, EngineError::DuplicateCredential { .. }));

        // Alice is untouched, and bob was never created.
        assert_eq!(registry.user_count(), 1);
        assert_eq!(
            &**registry.find_uuid(&uuid_bytes(UUID_A)).unwrap().id(),
            "alice"
        );
    }

    #[test]
    fn rejects_a_credential_the_protocol_cannot_use() {
        let registry = MemoryUserRegistry::new(CredentialKinds::UUID);
        let err = registry
            .upsert(trojan_spec("alice", "hunter2"))
            .unwrap_err();
        assert!(matches!(err, EngineError::InvalidUser(_)));

        let registry = MemoryUserRegistry::new(CredentialKinds::TROJAN_PASSWORD);
        let err = registry.upsert(uuid_spec("alice", UUID_A)).unwrap_err();
        assert!(matches!(err, EngineError::InvalidUser(_)));
    }

    #[test]
    fn rejects_a_user_with_no_credential_at_all() {
        let registry = MemoryUserRegistry::new(CredentialKinds::UUID);
        let err = registry
            .upsert(UserSpec {
                id: Some("alice".into()),
                uuid: None,
                password: None,
                enabled: true,
                max_conns: None,
                upload_limit_bps: None,
                download_limit_bps: None,
            })
            .unwrap_err();
        assert!(matches!(err, EngineError::InvalidUser(_)));
        assert_eq!(registry.user_count(), 0);
    }

    #[test]
    fn defaults_the_id_to_the_uuid() {
        let registry = MemoryUserRegistry::new(CredentialKinds::UUID);
        let info = registry
            .upsert(UserSpec {
                id: None,
                uuid: Some(UUID_A.to_string()),
                password: None,
                enabled: true,
                max_conns: None,
                upload_limit_bps: None,
                download_limit_bps: None,
            })
            .unwrap();
        assert_eq!(info.id, UUID_A);
        assert!(registry.get(UUID_A).is_some());
    }

    #[test]
    fn rejects_a_malformed_uuid_without_changing_the_table() {
        let registry = MemoryUserRegistry::new(CredentialKinds::UUID);
        assert!(registry.upsert(uuid_spec("alice", "not-a-uuid")).is_err());
        assert_eq!(registry.user_count(), 0);
    }

    #[test]
    fn finds_a_trojan_user_by_their_wire_hash() {
        let registry = MemoryUserRegistry::new(CredentialKinds::TROJAN_PASSWORD);
        registry.upsert(trojan_spec("alice", "hunter2")).unwrap();

        let hash = credential::trojan_password_hash("hunter2");
        assert_eq!(&**registry.find_trojan_hash(&hash).unwrap().id(), "alice");
        assert!(
            registry
                .find_trojan_hash(&credential::trojan_password_hash("hunter3"))
                .is_none()
        );
        // A short or empty read must not match or panic.
        assert!(registry.find_trojan_hash(b"").is_none());
        assert!(registry.find_trojan_hash(&hash[..55]).is_none());
    }

    #[test]
    fn serves_both_credential_kinds_on_a_mixed_inbound() {
        // A TLS inbound can map one SNI to VLESS and another to Trojan, so its
        // registry has to answer both lookups.
        let mut kinds = CredentialKinds::UUID;
        kinds.merge(CredentialKinds::TROJAN_PASSWORD);
        let registry = MemoryUserRegistry::new(kinds);

        registry.upsert(uuid_spec("alice", UUID_A)).unwrap();
        registry.upsert(trojan_spec("bob", "hunter2")).unwrap();
        registry
            .upsert(UserSpec {
                id: Some("carol".into()),
                uuid: Some(UUID_B.to_string()),
                password: Some("s3cret".into()),
                enabled: true,
                max_conns: None,
                upload_limit_bps: None,
                download_limit_bps: None,
            })
            .unwrap();

        assert!(registry.find_uuid(&uuid_bytes(UUID_A)).is_some());
        assert!(
            registry
                .find_trojan_hash(&credential::trojan_password_hash("hunter2"))
                .is_some()
        );
        // Carol reaches the same record through either credential.
        let by_uuid = registry.find_uuid(&uuid_bytes(UUID_B)).unwrap();
        let by_password = registry
            .find_trojan_hash(&credential::trojan_password_hash("s3cret"))
            .unwrap();
        assert!(Arc::ptr_eq(&by_uuid, &by_password));
    }

    #[tokio::test]
    async fn remove_reports_an_unknown_id() {
        let registry = MemoryUserRegistry::new(CredentialKinds::UUID);
        let err = registry.remove("in", "nobody").await.unwrap_err();
        assert!(matches!(err, EngineError::UnknownUser { .. }));
    }

    // -- Hysteria2: the password compared as sent -----------------------------------

    #[test]
    fn finds_a_user_by_their_cleartext_password() {
        let registry = MemoryUserRegistry::new(CredentialKinds::PLAIN_PASSWORD);
        registry.upsert(trojan_spec("alice", "hunter2")).unwrap();
        registry.upsert(trojan_spec("bob", "hunter3")).unwrap();

        assert_eq!(&**registry.find_password("hunter2").unwrap().id(), "alice");
        assert_eq!(&**registry.find_password("hunter3").unwrap().id(), "bob");
        assert_eq!(registry.get("alice").unwrap().total_conns, 0);

        // A prefix is not a match: the comparison covers the whole value.
        assert!(registry.find_password("hunter").is_none());
        assert!(registry.find_password("hunter22").is_none());
        assert!(registry.find_password("").is_none());
    }

    #[test]
    fn a_plain_password_is_not_a_trojan_hash_or_the_reverse() {
        // The two derive from the same field, so an inbound that speaks only one of
        // them must not answer the other's lookup.
        let plain = MemoryUserRegistry::new(CredentialKinds::PLAIN_PASSWORD);
        plain.upsert(trojan_spec("alice", "hunter2")).unwrap();
        assert!(
            plain
                .find_trojan_hash(&credential::trojan_password_hash("hunter2"))
                .is_none()
        );

        let trojan = MemoryUserRegistry::new(CredentialKinds::TROJAN_PASSWORD);
        trojan.upsert(trojan_spec("alice", "hunter2")).unwrap();
        assert!(trojan.find_password("hunter2").is_none());
    }

    #[test]
    fn one_password_serves_trojan_and_hysteria2_together() {
        // Not a conflict, unlike shadowsocks: both start from the same cleartext, so
        // the user's one `password` reaches the same record either way.
        let mut kinds = CredentialKinds::TROJAN_PASSWORD;
        kinds.merge(CredentialKinds::PLAIN_PASSWORD);
        assert!(kinds.conflict().is_none());
        let registry = MemoryUserRegistry::new(kinds);
        registry.upsert(trojan_spec("alice", "hunter2")).unwrap();

        let by_plain = registry.find_password("hunter2").unwrap();
        let by_hash = registry
            .find_trojan_hash(&credential::trojan_password_hash("hunter2"))
            .unwrap();
        assert!(Arc::ptr_eq(&by_plain, &by_hash));
    }

    #[tokio::test]
    async fn rotating_a_password_retires_the_old_one() {
        let registry = MemoryUserRegistry::new(CredentialKinds::PLAIN_PASSWORD);
        registry.upsert(trojan_spec("alice", "hunter2")).unwrap();
        let before = registry.find_password("hunter2").unwrap();
        before.add_rx(128);

        registry.upsert(trojan_spec("alice", "hunter3")).unwrap();
        assert_eq!(registry.user_count(), 1);
        assert!(registry.find_password("hunter2").is_none());
        let after = registry.find_password("hunter3").unwrap();
        assert!(Arc::ptr_eq(&before, &after));
        assert_eq!(after.rx(), 128);

        registry.remove("in", "alice").await.unwrap();
        assert!(registry.find_password("hunter3").is_none());
    }

    #[test]
    fn a_disabled_password_user_looks_absent() {
        let registry = MemoryUserRegistry::new(CredentialKinds::PLAIN_PASSWORD);
        let mut spec = trojan_spec("alice", "hunter2");
        spec.enabled = false;
        registry.upsert(spec).unwrap();
        assert!(registry.find_password("hunter2").is_none());
        assert_eq!(registry.get("alice").unwrap().total_conns, 0);

        registry.upsert(trojan_spec("alice", "hunter2")).unwrap();
        assert!(registry.find_password("hunter2").is_some());
    }

    #[test]
    fn rejects_a_password_owned_by_another_user() {
        let registry = MemoryUserRegistry::new(CredentialKinds::PLAIN_PASSWORD);
        registry.upsert(trojan_spec("alice", "hunter2")).unwrap();
        let err = registry.upsert(trojan_spec("bob", "hunter2")).unwrap_err();
        assert!(matches!(err, EngineError::DuplicateCredential { .. }));
        assert_eq!(registry.user_count(), 1);
        assert_eq!(&**registry.find_password("hunter2").unwrap().id(), "alice");
    }

    #[test]
    fn a_uuid_registry_answers_no_password_lookup() {
        let registry = MemoryUserRegistry::new(CredentialKinds::UUID);
        registry.upsert(uuid_spec("alice", UUID_A)).unwrap();
        assert!(registry.find_password("hunter2").is_none());
        assert!(registry.find_password("").is_none());
        assert!(registry.upsert(trojan_spec("bob", "hunter2")).is_err());
    }

    // -- Shadowsocks 2022: found by the name in an identity header ------------------

    #[test]
    fn finds_a_shadowsocks_user_by_their_named_psk() {
        let registry = MemoryUserRegistry::new(CredentialKinds::shadowsocks_psk(16));
        registry.upsert(ss_spec("alice", 16)).unwrap();
        registry.upsert(ss_spec("bob", 16)).unwrap();

        let found = registry
            .find_shadowsocks_psk_hash(&ss_name("alice", 16))
            .unwrap();
        assert_eq!(&**found.user.id(), "alice");
        // The handler derives session keys from this, so it must be the *user's* key
        // and not the inbound's identity PSK.
        assert_eq!(&*found.psk, &ss_psk("alice", 16)[..]);

        assert_eq!(
            &**registry
                .find_shadowsocks_psk_hash(&ss_name("bob", 16))
                .unwrap()
                .user
                .id(),
            "bob"
        );
        assert!(registry.find_shadowsocks_psk_hash(&[0u8; 16]).is_none());
        // Naming a user is not authenticating them here: an identity header is
        // sealed under the *inbound's* key, which every client of the inbound knows,
        // so it can be copied off the wire and replayed. The handler counts once the
        // record layer opens a chunk under alice's own PSK.
        assert_eq!(registry.get("alice").unwrap().total_conns, 0);
    }

    #[tokio::test]
    async fn rotating_a_psk_retires_the_old_name() {
        let registry = MemoryUserRegistry::new(CredentialKinds::shadowsocks_psk(32));
        registry.upsert(ss_spec("alice", 32)).unwrap();
        let before = registry
            .find_shadowsocks_psk_hash(&ss_name("alice", 32))
            .unwrap()
            .user;
        before.add_tx(64);

        let mut rotated = ss_spec("alice", 32);
        rotated.password = Some(credential::encode_shadowsocks_psk(&ss_psk("rotated", 32)));
        registry.upsert(rotated).unwrap();

        assert!(
            registry
                .find_shadowsocks_psk_hash(&ss_name("alice", 32))
                .is_none()
        );
        let after = registry
            .find_shadowsocks_psk_hash(&ss_name("rotated", 32))
            .unwrap();
        assert!(Arc::ptr_eq(&before, &after.user));
        assert_eq!(after.user.tx(), 64);

        registry.remove("in", "alice").await.unwrap();
        assert!(
            registry
                .find_shadowsocks_psk_hash(&ss_name("rotated", 32))
                .is_none()
        );
    }

    #[test]
    fn a_disabled_shadowsocks_user_looks_absent() {
        let registry = MemoryUserRegistry::new(CredentialKinds::shadowsocks_psk(16));
        let mut spec = ss_spec("alice", 16);
        spec.enabled = false;
        registry.upsert(spec).unwrap();
        assert!(
            registry
                .find_shadowsocks_psk_hash(&ss_name("alice", 16))
                .is_none()
        );
        assert_eq!(registry.get("alice").unwrap().total_conns, 0);
    }

    #[test]
    fn refuses_a_psk_the_cipher_cannot_use() {
        // A PSK is raw key material: 32 bytes is not an over-long aes-128-gcm key, it
        // is one that cipher can never load. Caught here rather than at the handshake,
        // where it would look like a user who simply cannot connect.
        let registry = MemoryUserRegistry::new(CredentialKinds::shadowsocks_psk(16));
        let err = registry.upsert(ss_spec("alice", 32)).unwrap_err();
        assert!(matches!(err, EngineError::InvalidUser(_)));
        assert!(err.to_string().contains("16 byte psk"));
        assert_eq!(registry.user_count(), 0);

        // And a password that is not base64 at all.
        let err = registry
            .upsert(trojan_spec("alice", "not base64!"))
            .unwrap_err();
        assert!(matches!(err, EngineError::InvalidUser(_)));
        assert_eq!(registry.user_count(), 0);
    }

    #[test]
    fn rejects_a_psk_owned_by_another_user() {
        let registry = MemoryUserRegistry::new(CredentialKinds::shadowsocks_psk(16));
        registry.upsert(ss_spec("alice", 16)).unwrap();

        let mut bob = ss_spec("bob", 16);
        bob.password = ss_spec("alice", 16).password;
        let err = registry.upsert(bob).unwrap_err();
        assert!(matches!(err, EngineError::DuplicateCredential { .. }));
        assert_eq!(registry.user_count(), 1);
        assert_eq!(
            &**registry
                .find_shadowsocks_psk_hash(&ss_name("alice", 16))
                .unwrap()
                .user
                .id(),
            "alice"
        );
    }

    #[test]
    fn a_uuid_registry_answers_no_shadowsocks_lookup() {
        // One registry serves whatever the inbound turns out to be, so every lookup has
        // to be safe to ask -- and must not match.
        let registry = MemoryUserRegistry::new(CredentialKinds::UUID);
        registry.upsert(uuid_spec("alice", UUID_A)).unwrap();
        assert!(registry.find_shadowsocks_psk_hash(&[0u8; 16]).is_none());
        assert!(
            registry
                .find_shadowsocks_psk_hash(&ss_name("alice", 16))
                .is_none()
        );
        // And a PSK is not a credential it will accept.
        assert!(registry.upsert(ss_spec("bob", 16)).is_err());
    }

    #[test]
    fn shadowsocks_and_vless_can_share_an_inbound() {
        // Not a common shape, but `tls_targets` allows it, and the union has to work:
        // one user reaches their record by uuid, another by named psk.
        let mut kinds = CredentialKinds::UUID;
        kinds.merge(CredentialKinds::shadowsocks_psk(16));
        assert!(kinds.conflict().is_none());
        let registry = MemoryUserRegistry::new(kinds);

        registry.upsert(uuid_spec("alice", UUID_A)).unwrap();
        registry.upsert(ss_spec("bob", 16)).unwrap();
        assert!(registry.find_uuid(&uuid_bytes(UUID_A)).is_some());
        assert!(
            registry
                .find_shadowsocks_psk_hash(&ss_name("bob", 16))
                .is_some()
        );
    }

    #[test]
    fn finds_a_tuic_user_without_counting_an_authentication() {
        let registry = MemoryUserRegistry::new(CredentialKinds::TUIC);
        registry
            .upsert(tuic_spec("alice", UUID_A, "hunter2"))
            .unwrap();

        let found = registry.find_tuic_uuid(&uuid_bytes(UUID_A)).unwrap();
        assert_eq!(&**found.user.id(), "alice");
        assert_eq!(&*found.password, "hunter2");
        // The whole point of this lookup being different: the token has not been
        // checked yet, so nothing may be billed. The handler counts it once it has.
        assert_eq!(found.user.total_conns(), 0);

        assert!(registry.find_tuic_uuid(&uuid_bytes(UUID_B)).is_none());
    }

    #[test]
    fn a_tuic_user_needs_both_halves() {
        let registry = MemoryUserRegistry::new(CredentialKinds::TUIC);

        let uuid_only = registry.upsert(uuid_spec("alice", UUID_A)).unwrap_err();
        assert!(uuid_only.to_string().contains("both `uuid` and `password`"));
        let password_only = registry
            .upsert(trojan_spec("alice", "hunter2"))
            .unwrap_err();
        assert!(
            password_only
                .to_string()
                .contains("both `uuid` and `password`")
        );
        assert_eq!(registry.user_count(), 0);

        registry
            .upsert(tuic_spec("alice", UUID_A, "hunter2"))
            .unwrap();
        assert_eq!(registry.user_count(), 1);
    }

    #[test]
    fn half_a_tuic_credential_authenticates_nothing() {
        // A TUIC user's password is not indexed as a password credential, and a plain
        // uuid user has no password for a token to be keyed with. Neither half stands
        // alone, whichever direction it is asked from.
        let tuic = MemoryUserRegistry::new(CredentialKinds::TUIC);
        tuic.upsert(tuic_spec("alice", UUID_A, "hunter2")).unwrap();
        assert!(tuic.find_password("hunter2").is_none());
        assert!(
            tuic.find_trojan_hash(&credential::trojan_password_hash("hunter2"))
                .is_none()
        );

        let vless = MemoryUserRegistry::new(CredentialKinds::UUID);
        vless.upsert(uuid_spec("alice", UUID_A)).unwrap();
        assert!(vless.find_tuic_uuid(&uuid_bytes(UUID_A)).is_none());
    }

    #[test]
    fn a_disabled_tuic_user_looks_absent() {
        let registry = MemoryUserRegistry::new(CredentialKinds::TUIC);
        registry
            .upsert(tuic_spec("alice", UUID_A, "hunter2"))
            .unwrap();
        let user = registry.find_tuic_uuid(&uuid_bytes(UUID_A)).unwrap().user;

        user.set_enabled(false);
        assert!(registry.find_tuic_uuid(&uuid_bytes(UUID_A)).is_none());
        user.set_enabled(true);
        assert!(registry.find_tuic_uuid(&uuid_bytes(UUID_A)).is_some());
    }

    #[test]
    fn rotating_a_tuic_password_retires_the_old_one() {
        // The password is carried on the entry rather than indexed, so what retires it
        // is the entry being replaced whole. Worth its own check: the uuid, which *is*
        // indexed, stays the same across this rotation and would hide a stale password.
        let registry = MemoryUserRegistry::new(CredentialKinds::TUIC);
        registry
            .upsert(tuic_spec("alice", UUID_A, "hunter2"))
            .unwrap();
        registry
            .upsert(tuic_spec("alice", UUID_A, "hunter3"))
            .unwrap();

        let found = registry.find_tuic_uuid(&uuid_bytes(UUID_A)).unwrap();
        assert_eq!(&*found.password, "hunter3");
        assert_eq!(registry.user_count(), 1);
    }

    #[test]
    fn two_tuic_users_may_share_a_password() {
        // Only the uuid is an index key, so a shared password collides with nothing.
        // Refusing it would be a rule with no mechanism behind it.
        let registry = MemoryUserRegistry::new(CredentialKinds::TUIC);
        registry
            .upsert(tuic_spec("alice", UUID_A, "hunter2"))
            .unwrap();
        registry
            .upsert(tuic_spec("bob", UUID_B, "hunter2"))
            .unwrap();

        assert_eq!(
            &**registry
                .find_tuic_uuid(&uuid_bytes(UUID_A))
                .unwrap()
                .user
                .id(),
            "alice"
        );
        assert_eq!(
            &**registry
                .find_tuic_uuid(&uuid_bytes(UUID_B))
                .unwrap()
                .user
                .id(),
            "bob"
        );

        // The uuid still is one, though.
        let err = registry
            .upsert(tuic_spec("mallory", UUID_A, "hunter4"))
            .unwrap_err();
        assert!(matches!(err, EngineError::DuplicateCredential { .. }));
    }

    #[test]
    fn finds_an_anytls_user_by_the_hash_they_send() {
        let registry = MemoryUserRegistry::new(CredentialKinds::ANYTLS_PASSWORD);
        registry.upsert(trojan_spec("alice", "hunter2")).unwrap();

        let hash = credential::password_sha256("hunter2");
        let found = registry.find_password_sha256(&hash).unwrap();
        assert_eq!(&**found.id(), "alice");
        assert_eq!(found.total_conns(), 0);

        assert!(
            registry
                .find_password_sha256(&credential::password_sha256("hunter3"))
                .is_none()
        );
        // And the cleartext is not a credential of its own: AnyTLS never sends it.
        assert!(registry.find_password("hunter2").is_none());
    }

    #[test]
    fn the_anytls_prefix_probe_ignores_whether_a_user_is_enabled() {
        // A plausibility test, not a lookup. Answering `false` for a suspended user
        // would divert their connections to the fallback while a live user's went to
        // the handler, which is an observable difference an attacker can use.
        let registry = MemoryUserRegistry::new(CredentialKinds::ANYTLS_PASSWORD);
        registry.upsert(trojan_spec("alice", "hunter2")).unwrap();

        let hash = credential::password_sha256("hunter2");
        let prefix = credential::password_sha256_prefix(&hash);
        assert!(registry.has_password_sha256_prefix(&prefix));

        let user = registry.find_password_sha256(&hash).unwrap();
        user.set_enabled(false);
        assert!(registry.find_password_sha256(&hash).is_none());
        assert!(registry.has_password_sha256_prefix(&prefix));

        assert!(!registry.has_password_sha256_prefix(&[0u8; 8]));
    }

    #[tokio::test]
    async fn the_anytls_prefix_index_is_counted_rather_than_a_set() {
        // Two users can share an 8-byte prefix, so removing one must not blind the
        // probe to the other. A set would.
        let registry = MemoryUserRegistry::new(CredentialKinds::ANYTLS_PASSWORD);
        registry.upsert(trojan_spec("alice", "hunter2")).unwrap();
        registry.upsert(trojan_spec("bob", "hunter3")).unwrap();

        let alice_hash = credential::password_sha256("hunter2");
        let bob_hash = credential::password_sha256("hunter3");
        let prefix = credential::password_sha256_prefix(&alice_hash);

        // Force the collision the real world would only produce by accident: give
        // bob's entry alice's prefix by claiming it directly, which is what two
        // colliding hashes would do.
        registry.claim_anytls_prefix(&alice_hash);
        assert!(registry.has_password_sha256_prefix(&prefix));

        registry.remove("anytls", "alice").await.unwrap();
        assert!(
            registry.has_password_sha256_prefix(&prefix),
            "the second claim on this prefix is still live"
        );
        registry.release_anytls_prefix(&alice_hash);
        assert!(
            !registry.has_password_sha256_prefix(&prefix),
            "and the last release drops it"
        );

        // Bob is untouched throughout.
        assert!(registry.find_password_sha256(&bob_hash).is_some());
    }

    #[test]
    fn rotating_an_anytls_password_retires_the_old_hash_and_its_prefix() {
        let registry = MemoryUserRegistry::new(CredentialKinds::ANYTLS_PASSWORD);
        registry.upsert(trojan_spec("alice", "hunter2")).unwrap();
        let old = credential::password_sha256("hunter2");

        registry.upsert(trojan_spec("alice", "hunter3")).unwrap();
        let new = credential::password_sha256("hunter3");

        assert!(registry.find_password_sha256(&new).is_some());
        assert!(registry.find_password_sha256(&old).is_none());
        assert!(
            !registry.has_password_sha256_prefix(&credential::password_sha256_prefix(&old)),
            "the retired prefix must not keep a probe alive"
        );
        assert!(registry.has_password_sha256_prefix(&credential::password_sha256_prefix(&new)));
        assert_eq!(registry.user_count(), 1);
    }

    #[test]
    fn rejects_an_anytls_password_owned_by_another_user() {
        let registry = MemoryUserRegistry::new(CredentialKinds::ANYTLS_PASSWORD);
        registry.upsert(trojan_spec("alice", "hunter2")).unwrap();

        let err = registry.upsert(trojan_spec("bob", "hunter2")).unwrap_err();
        assert!(matches!(err, EngineError::DuplicateCredential { .. }));
        assert_eq!(registry.user_count(), 1);
    }

    #[test]
    fn finds_a_naive_user_by_their_basic_credential() {
        let registry = MemoryUserRegistry::new(CredentialKinds::NAIVE_BASIC);
        registry.upsert(trojan_spec("alice", "hunter2")).unwrap();

        let encoded = credential::naive_basic_credential("alice", "hunter2");
        let found = registry.find_naive_basic(&encoded).unwrap();
        assert_eq!(&**found.id(), "alice");
        assert_eq!(found.total_conns(), 0);

        // Neither half stands alone, and garbage off a header must not match.
        assert!(
            registry
                .find_naive_basic(&credential::naive_basic_credential("alice", "hunter3"))
                .is_none()
        );
        assert!(
            registry
                .find_naive_basic(&credential::naive_basic_credential("bob", "hunter2"))
                .is_none()
        );
        assert!(registry.find_naive_basic(b"not base64").is_none());
        assert!(registry.find_naive_basic(&[0xff, 0xfe]).is_none());
    }

    #[tokio::test]
    async fn renaming_a_naive_user_rotates_their_credential() {
        // The consequence of the id being the username half. Worth pinning, because
        // it is the one place in this crate where an id is not merely a label.
        let registry = MemoryUserRegistry::new(CredentialKinds::NAIVE_BASIC);
        registry.upsert(trojan_spec("alice", "hunter2")).unwrap();
        registry.upsert(trojan_spec("alice2", "hunter2")).unwrap();

        assert!(
            registry
                .find_naive_basic(&credential::naive_basic_credential("alice2", "hunter2"))
                .is_some()
        );
        // The old id is a separate user, not a retired name, so it still works --
        // renaming is add-plus-remove, which is what the API offers.
        assert!(
            registry
                .find_naive_basic(&credential::naive_basic_credential("alice", "hunter2"))
                .is_some()
        );
        assert_eq!(registry.user_count(), 2);

        registry.remove("naive", "alice").await.unwrap();
        assert!(
            registry
                .find_naive_basic(&credential::naive_basic_credential("alice", "hunter2"))
                .is_none()
        );
    }

    #[test]
    fn rotating_a_naive_password_retires_the_old_credential() {
        let registry = MemoryUserRegistry::new(CredentialKinds::NAIVE_BASIC);
        registry.upsert(trojan_spec("alice", "hunter2")).unwrap();
        registry.upsert(trojan_spec("alice", "hunter3")).unwrap();

        assert!(
            registry
                .find_naive_basic(&credential::naive_basic_credential("alice", "hunter3"))
                .is_some()
        );
        assert!(
            registry
                .find_naive_basic(&credential::naive_basic_credential("alice", "hunter2"))
                .is_none()
        );
        assert_eq!(registry.user_count(), 1);
    }

    #[test]
    fn a_disabled_naive_user_looks_absent() {
        let registry = MemoryUserRegistry::new(CredentialKinds::NAIVE_BASIC);
        registry.upsert(trojan_spec("alice", "hunter2")).unwrap();
        let encoded = credential::naive_basic_credential("alice", "hunter2");

        let user = registry.find_naive_basic(&encoded).unwrap();
        user.set_enabled(false);
        assert!(registry.find_naive_basic(&encoded).is_none());
        assert_eq!(user.total_conns(), 0, "a denial is not a connection");
        user.set_enabled(true);
        assert!(registry.find_naive_basic(&encoded).is_some());
    }

    #[test]
    fn refuses_an_inbound_whose_password_would_mean_two_things() {
        // Trojan wants a cleartext password, shadowsocks a base64 PSK. There is no one
        // value a user could send that serves both, so the combination is refused when
        // the inbound is added rather than accepted and half-working.
        let mut trojan_and_ss = CredentialKinds::TROJAN_PASSWORD;
        trojan_and_ss.merge(CredentialKinds::shadowsocks_psk(16));
        assert!(trojan_and_ss.conflict().is_some());

        // A cleartext password is no more compatible with a PSK than a hashed one.
        let mut plain_and_ss = CredentialKinds::PLAIN_PASSWORD;
        plain_and_ss.merge(CredentialKinds::shadowsocks_psk(32));
        assert!(plain_and_ss.conflict().is_some());

        // Same for two shadowsocks ciphers with different key lengths.
        let mut two_lengths = CredentialKinds::shadowsocks_psk(16);
        two_lengths.merge(CredentialKinds::shadowsocks_psk(32));
        assert_eq!(two_lengths.shadowsocks_psk, ShadowsocksPsk::Mixed);
        assert!(two_lengths.conflict().is_some());

        // The same length twice is not a conflict: two SNIs, one cipher.
        let mut same = CredentialKinds::shadowsocks_psk(32);
        same.merge(CredentialKinds::shadowsocks_psk(32));
        assert_eq!(same.shadowsocks_psk, ShadowsocksPsk::Len(32));
        assert!(same.conflict().is_none());

        // And merging with nothing is still nothing to conflict with.
        let mut alone = CredentialKinds::shadowsocks_psk(16);
        alone.merge(CredentialKinds::NONE);
        assert_eq!(alone.shadowsocks_psk, ShadowsocksPsk::Len(16));
        assert!(!alone.is_empty());
    }

    // -- VMess: the same users, found by trial rather than by index ----------------

    /// An auth id as a client would send it. The timestamp is irrelevant to the
    /// registry, which recognises the user and leaves freshness to the handler.
    fn vmess_auth_id(uuid: &str) -> [u8; 16] {
        VmessAuthKey::new(&uuid_bytes(uuid)).seal(1_700_000_000, [1, 2, 3, 4])
    }

    #[test]
    fn picks_the_right_user_out_of_a_crowd() {
        // The property the trial exists for: no index, but still exactly one answer.
        let registry = MemoryUserRegistry::new(CredentialKinds::UUID);
        let uuids: Vec<String> = (0..64)
            .map(|n| format!("00000000-0000-4000-8000-{n:012x}"))
            .collect();
        for (n, uuid) in uuids.iter().enumerate() {
            registry
                .upsert(uuid_spec(&format!("user{n}"), uuid))
                .unwrap();
        }

        for (n, uuid) in uuids.iter().enumerate() {
            let found = registry
                .find_vmess_auth_id(&vmess_auth_id(uuid))
                .unwrap_or_else(|| panic!("user{n} should be recognised"));
            assert_eq!(&**found.user.id(), format!("user{n}"));
            assert_eq!(found.timestamp, 1_700_000_000);
            assert_eq!(
                found.instruction_key,
                *VmessAuthKey::new(&uuid_bytes(uuid)).instruction_key(),
                "the handshake continues with this key, so it must be user{n}'s"
            );
        }

        assert!(
            registry
                .find_vmess_auth_id(&vmess_auth_id(UUID_A))
                .is_none(),
            "a uuid nobody registered must not match anyone"
        );
    }

    #[test]
    fn vmess_and_vless_reach_one_record() {
        // Same user, two protocols, one set of counters. If the trial snapshot held
        // its own contexts, half of a user's traffic would land somewhere nobody
        // reports on.
        let registry = MemoryUserRegistry::new(CredentialKinds::UUID);
        registry.upsert(uuid_spec("alice", UUID_A)).unwrap();

        let by_uuid = registry.find_uuid(&uuid_bytes(UUID_A)).unwrap();
        let by_auth_id = registry
            .find_vmess_auth_id(&vmess_auth_id(UUID_A))
            .unwrap()
            .user;
        assert!(Arc::ptr_eq(&by_uuid, &by_auth_id));

        by_auth_id.add_rx(512);
        assert_eq!(registry.get("alice").unwrap().rx, 512);
        // Both lookups only identify a candidate. The protocol handler atomically
        // counts and registers the connection once it admits it to the data path.
        assert_eq!(by_uuid.total_conns(), 0);
    }

    #[tokio::test]
    async fn the_trial_snapshot_tracks_every_mutation() {
        // The snapshot is a second structure derived from the same entries, so the
        // risk it introduces is drift. Each mutation is checked through it.
        let registry = MemoryUserRegistry::new(CredentialKinds::UUID);
        assert!(
            registry
                .find_vmess_auth_id(&vmess_auth_id(UUID_A))
                .is_none()
        );

        // add
        registry.upsert(uuid_spec("alice", UUID_A)).unwrap();
        assert!(
            registry
                .find_vmess_auth_id(&vmess_auth_id(UUID_A))
                .is_some()
        );

        // rotate: the old auth id must stop working the moment the new one starts
        registry.upsert(uuid_spec("alice", UUID_B)).unwrap();
        assert!(
            registry
                .find_vmess_auth_id(&vmess_auth_id(UUID_A))
                .is_none()
        );
        assert_eq!(
            &**registry
                .find_vmess_auth_id(&vmess_auth_id(UUID_B))
                .unwrap()
                .user
                .id(),
            "alice"
        );

        // disable: absent, not denied, and not counted
        let mut disabled = uuid_spec("alice", UUID_B);
        disabled.enabled = false;
        registry.upsert(disabled).unwrap();
        let before = registry.get("alice").unwrap().total_conns;
        assert!(
            registry
                .find_vmess_auth_id(&vmess_auth_id(UUID_B))
                .is_none()
        );
        assert_eq!(registry.get("alice").unwrap().total_conns, before);

        // re-enable
        registry.upsert(uuid_spec("alice", UUID_B)).unwrap();
        assert!(
            registry
                .find_vmess_auth_id(&vmess_auth_id(UUID_B))
                .is_some()
        );

        // remove
        registry.remove("in", "alice").await.unwrap();
        assert!(
            registry
                .find_vmess_auth_id(&vmess_auth_id(UUID_B))
                .is_none()
        );
    }

    #[test]
    fn a_trojan_only_registry_has_nothing_to_try() {
        // No uuids means an empty snapshot. The walk must come up empty rather than
        // fall over, since one registry serves whatever the inbound turns out to be.
        let registry = MemoryUserRegistry::new(CredentialKinds::TROJAN_PASSWORD);
        registry.upsert(trojan_spec("alice", "hunter2")).unwrap();
        assert!(
            registry
                .find_vmess_auth_id(&vmess_auth_id(UUID_A))
                .is_none()
        );
        assert!(registry.find_vmess_auth_id(&[0u8; 16]).is_none());
    }

    #[test]
    fn garbage_is_not_recognised_as_anyone() {
        let registry = MemoryUserRegistry::new(CredentialKinds::UUID);
        registry.upsert(uuid_spec("alice", UUID_A)).unwrap();
        for seed in 0u8..64 {
            assert!(registry.find_vmess_auth_id(&[seed; 16]).is_none());
        }
        // Nothing was billed for the failures.
        assert_eq!(registry.get("alice").unwrap().total_conns, 0);
    }

    #[test]
    fn lists_users_by_id_without_echoing_credentials() {
        let registry = MemoryUserRegistry::new(CredentialKinds::UUID);
        registry.upsert(uuid_spec("bob", UUID_B)).unwrap();
        registry.upsert(uuid_spec("alice", UUID_A)).unwrap();

        let listed = registry.list();
        let ids: Vec<&str> = listed.iter().map(|u| u.id.as_str()).collect();
        assert_eq!(ids, vec!["alice", "bob"]);

        // UserInfo has no credential field at all; assert the rendered form too, so
        // adding one later has to be a deliberate change to this test.
        let json = serde_json::to_string(&listed[0]).unwrap();
        assert!(
            !json.contains(UUID_A),
            "credentials must not be echoed back"
        );
    }

    #[test]
    fn a_colon_in_an_id_cannot_forge_another_user_s_basic_credential() {
        // NaiveProxy's wire credential is base64("id:password"), so an id holding a
        // colon makes the split ambiguous: these two users encode the same bytes.
        // Without the duplicate check the second upsert silently takes over the
        // first's index entry, leaving alice listed and unable to connect.
        let registry = MemoryUserRegistry::new(CredentialKinds::NAIVE_BASIC);
        registry
            .upsert(naive_spec("alice", "b:c"))
            .expect("the first user is unremarkable");

        let clash = registry.upsert(naive_spec("alice:b", "c"));
        assert!(
            matches!(clash, Err(EngineError::DuplicateCredential { .. })),
            "the colliding id must be refused, got {clash:?}"
        );
        assert_eq!(registry.len(), 1, "and must not be left in the table");

        // The original credential still belongs to the original user.
        let wire = credential::naive_basic_credential("alice", "b:c");
        assert_eq!(
            registry.find_naive_basic(&wire).map(|u| u.id().to_string()),
            Some("alice".to_string())
        );

        // An id with a colon is fine on its own -- it is only a collision that is
        // refused, and refusing every colon would be a rule nobody could predict.
        assert!(registry.upsert(naive_spec("has:colon", "other")).is_ok());
    }

    #[test]
    fn lookups_resolve_candidates_without_admitting_them() {
        // Every registry implementation has one contract: lookup resolves an enabled
        // candidate, while the handler admits only after its protocol has enough
        // proof. For these first two protocols that proof comes later than lookup.
        let ss_registry = MemoryUserRegistry::new(CredentialKinds::shadowsocks_psk(16));
        ss_registry
            .upsert(psk_spec("alice", &[7u8; 16]))
            .expect("alice added");
        let named = ss_registry
            .find_shadowsocks_psk_hash(&credential::shadowsocks_psk_hash(&[7u8; 16]))
            .expect("the header names alice");
        assert_eq!(&**named.user.id(), "alice");
        assert_eq!(
            named.user.total_conns(),
            0,
            "an identity header is sealed under the inbound's key, not alice's"
        );

        let vmess_registry = MemoryUserRegistry::new(CredentialKinds::UUID);
        vmess_registry
            .upsert(uuid_spec("bob", UUID_A))
            .expect("bob added");
        let found = vmess_registry
            .find_vmess_auth_id(&vmess_auth_id(UUID_A))
            .expect("the auth id names bob");
        assert_eq!(&**found.user.id(), "bob");
        assert_eq!(
            found.user.total_conns(),
            0,
            "an auth id crosses the wire in the clear and can be replayed"
        );

        // Even a credential the client had to hold is only a candidate at lookup.
        // Admission is deferred until the meter can count and register it as one
        // operation against concurrent removal.
        let trojan_registry = MemoryUserRegistry::new(CredentialKinds::TROJAN_PASSWORD);
        trojan_registry
            .upsert(trojan_spec("carol", "hunter2"))
            .expect("carol added");
        let carol = trojan_registry
            .find_trojan_hash(&credential::trojan_password_hash("hunter2"))
            .expect("carol authenticates");
        assert_eq!(carol.total_conns(), 0);
    }

    #[test]
    fn taking_traffic_reports_what_it_zeroed() {
        let registry = MemoryUserRegistry::new(CredentialKinds::UUID);
        registry.upsert(uuid_spec("alice", UUID_A)).unwrap();
        registry.upsert(uuid_spec("bob", UUID_B)).unwrap();

        // Stand in for a connection: authenticate, then move some bytes.
        let alice = registry.find_uuid(&uuid_bytes(UUID_A)).unwrap();
        let connection = ConnContext::new();
        assert!(connection.bind_authenticated(Arc::clone(&alice)));
        alice.add_tx(400);
        alice.add_rx(600);
        let observed_at = alice.last_traffic_observed_at_unix_millis();
        assert_ne!(observed_at, 0);

        let taken = registry.take_traffic("t", "alice").unwrap();
        assert_eq!((taken.tx, taken.rx), (400, 600), "the period's bytes");
        assert_eq!(taken.last_traffic_observed_at_unix_millis, observed_at);
        // Live and lifetime connection counts are not part of a period.
        assert_eq!((taken.conns, taken.total_conns), (1, 1));

        let after = registry.get("alice").unwrap();
        assert_eq!((after.tx, after.rx), (0, 0), "the counters are zeroed");
        assert_eq!((after.conns, after.total_conns), (1, 1));

        // A second take with nothing in between reports zero rather than repeating
        // the period that was already closed.
        let again = registry.take_traffic("t", "alice").unwrap();
        assert_eq!((again.tx, again.rx), (0, 0));

        // Bytes counted after the take belong to the next period, and the connection
        // is still bound to the same record.
        alice.add_tx(7);
        assert_eq!(registry.take_traffic("t", "alice").unwrap().tx, 7);

        assert!(registry.take_traffic("t", "nobody").is_err());
    }

    #[test]
    fn a_sweep_takes_every_user_and_leaves_the_table_alone() {
        let registry = MemoryUserRegistry::new(CredentialKinds::UUID);
        registry.upsert(uuid_spec("alice", UUID_A)).unwrap();
        registry.upsert(uuid_spec("bob", UUID_B)).unwrap();
        registry.find_uuid(&uuid_bytes(UUID_A)).unwrap().add_tx(10);
        registry.find_uuid(&uuid_bytes(UUID_B)).unwrap().add_rx(20);

        let swept = registry.take_all_traffic();
        let reported: Vec<(&str, u64, u64)> =
            swept.iter().map(|u| (u.id.as_str(), u.tx, u.rx)).collect();
        assert_eq!(reported, vec![("alice", 10, 0), ("bob", 0, 20)]);

        // A sweep closes a period; it does not remove anybody or disturb their
        // credentials.
        assert_eq!(registry.len(), 2);
        assert!(registry.find_uuid(&uuid_bytes(UUID_A)).is_some());
        assert!(
            registry
                .take_all_traffic()
                .iter()
                .all(|u| u.tx == 0 && u.rx == 0)
        );
    }

    use std::sync::atomic;

    // -- concurrent writers -------------------------------------------------
    //
    // Both of these check a property the single-threaded tests above already
    // cover; what they add is that it survives two control-plane calls landing at
    // once. Before the writer lock existed each of them failed on ~99% of rounds,
    // so a low round count is enough -- this is not a rare interleaving.

    /// Ten threads, one round each, released together.
    fn race<F: Fn(usize) + Sync>(threads: usize, body: F) {
        let barrier = std::sync::Barrier::new(threads);
        std::thread::scope(|scope| {
            for i in 0..threads {
                let barrier = &barrier;
                let body = &body;
                scope.spawn(move || {
                    barrier.wait();
                    body(i);
                });
            }
        });
    }

    #[test]
    fn two_writers_cannot_both_be_granted_one_uuid() {
        for round in 0..200 {
            let registry = MemoryUserRegistry::new(CredentialKinds::UUID);
            let accepted = atomic::AtomicUsize::new(0);

            race(2, |i| {
                let id = if i == 0 { "alice" } else { "bob" };
                if registry.upsert(uuid_spec(id, UUID_A)).is_ok() {
                    accepted.fetch_add(1, atomic::Ordering::Relaxed);
                }
            });

            assert_eq!(
                accepted.load(atomic::Ordering::Relaxed),
                1,
                "round {round}: exactly one writer may claim a uuid; the loser must \
                 be told so rather than listed as a user who can never connect"
            );
            assert_eq!(registry.len(), 1, "round {round}");
        }
    }

    #[test]
    fn a_concurrently_rotated_credential_stops_working() {
        for round in 0..200 {
            let registry = MemoryUserRegistry::new(CredentialKinds::UUID);
            registry.upsert(uuid_spec("alice", UUID_A)).unwrap();

            // Two rotations of the same user, landing together. Whichever wins, the
            // other two uuids must be dead: a retired credential that still
            // authenticates is a revocation that silently did not happen.
            race(2, |i| {
                let uuid = if i == 0 { UUID_B } else { UUID_C };
                let _ = registry.upsert(uuid_spec("alice", uuid));
            });

            let live = [UUID_A, UUID_B, UUID_C]
                .iter()
                .filter(|uuid| registry.find_uuid(&uuid_bytes(uuid)).is_some())
                .count();
            assert_eq!(
                live, 1,
                "round {round}: only the current uuid may authenticate"
            );
        }
    }
}
