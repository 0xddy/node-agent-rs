//! The credential lookup abstraction that protocol handlers authenticate against.

use std::sync::Arc;

use super::user::UserContext;

/// Who a Shadowsocks 2022 identity header names, and the key that follows from it.
///
/// The header names a PSK, and every session key for the connection derives from that
/// PSK -- so, as with VMess, "yes, that is a user" is not enough to carry on with. The
/// lookup hands back the key material it found alongside the user.
pub struct ShadowsocksIdentity {
    /// The user whose PSK the identity header named.
    pub user: Arc<UserContext>,
    /// That user's PSK, which the connection's session keys derive from. Note this is
    /// the user's own key, *not* the inbound's identity PSK that opened the header.
    pub psk: Box<[u8]>,
}

/// Who a TUIC uuid names, and the password its token is keyed with.
///
/// TUIC's `AUTHENTICATE` command puts the uuid on the wire in cleartext, next to a
/// 32-byte token that only the user's password and the QUIC connection's own exported
/// keying material can produce. So, as with Shadowsocks 2022, naming the user is not
/// the end of it: the lookup hands back the password the server needs to derive the
/// token it expects to see.
pub struct TuicIdentity {
    /// The user the uuid named -- **not yet authenticated**. See
    /// [`UserRegistry::find_tuic_uuid`].
    pub user: Arc<UserContext>,
    /// That user's password, which the expected token is derived from.
    pub password: Arc<str>,
}

/// Who a VMess auth id belongs to, and what the rest of the handshake needs.
///
/// A VMess server cannot proceed on "yes, that is a valid user" alone -- the next
/// thing it does is derive the request header's AEAD keys from that user's
/// instruction key -- so the search hands back everything it recovered rather than a
/// bare `Arc<UserContext>`.
pub struct VmessIdentity {
    /// The user whose key sealed the auth id.
    pub user: Arc<UserContext>,
    /// The key the request header's AEAD keys are derived from.
    pub instruction_key: [u8; 16],
    /// The unix timestamp, in seconds, that the client sealed into the auth id.
    ///
    /// Recovered but **not** judged: see [`UserRegistry::find_vmess_auth_id`] for why
    /// the freshness check belongs to the caller.
    pub timestamp: u64,
}

/// Resolves a credential presented during a handshake to the user it belongs to.
///
/// One registry belongs to one inbound. Implementations must be cheap to call and
/// must not block: a lookup runs inline in the connection setup path, before the
/// handshake can proceed, so a lock held here stalls every concurrent dial.
///
/// Every method has a default that denies, so an implementation only needs to
/// answer for the credential shapes its inbound actually uses. A registry that
/// implements nothing is a registry that rejects everyone, which is the correct
/// behaviour for an inbound with no users yet.
///
/// # Timing
///
/// The lookups are hash based, so the probe itself is not constant time. What that
/// leaks is bucket occupancy, not credential bytes, and it cannot be walked one
/// byte at a time the way a naive `memcmp` against a secret can. Implementations
/// are still expected to finish with a constant-time comparison of the stored
/// credential, which is what both of the bundled implementations do and what
/// `naiveproxy::UserLookup` already did before this trait existed.
///
/// # Disabled users
///
/// A suspended user must be reported as absent rather than as present-but-denied.
/// Handlers treat `None` as "unknown credential" and may divert the connection to
/// a probe-resistant fallback; distinguishing the two cases at the protocol level
/// would hand an observer a way to confirm that a credential is valid.
///
/// # Counting the authentication
///
/// A lookup that returns `Some` has already called
/// [`note_auth`](UserContext::note_auth), so that a handler cannot forget to. That
/// works because for every credential here the key *is* the proof: a password or a
/// hash is compared against the stored value, and a VMess auth id carries a checksum
/// only the uuid holder can produce.
///
/// [`find_tuic_uuid`](Self::find_tuic_uuid) is the one exception, and it says so.
pub trait UserRegistry: Send + Sync + std::fmt::Debug {
    /// Look up the 16-byte uuid that VLESS sends in cleartext at offset 1 of its
    /// request header, and that VMess seals into its auth id.
    ///
    /// `uuid` is the value as it appeared on the wire, in network order.
    fn find_uuid(&self, uuid: &[u8; 16]) -> Option<Arc<UserContext>> {
        let _ = uuid;
        None
    }

    /// Look up the credential Trojan sends as its first line: 56 lowercase hex
    /// characters, being SHA-224 of the password.
    ///
    /// The slice is caller-supplied and its length is not validated beforehand, so
    /// implementations must not assume 56 bytes.
    fn find_trojan_hash(&self, hash: &[u8]) -> Option<Arc<UserContext>> {
        let _ = hash;
        None
    }

    /// Look up a plaintext password, as used by AnyTLS and Hysteria2.
    fn find_password(&self, password: &str) -> Option<Arc<UserContext>> {
        let _ = password;
        None
    }

    /// Find whose VMess auth id this is, together with the material the rest of that
    /// user's handshake is derived from.
    ///
    /// This one is a search rather than a lookup, because a VMess auth id carries no
    /// identifier to index on -- see [`VmessAuthKey`](super::credential::VmessAuthKey)
    /// for what is actually in those 16 bytes. An implementation is expected to try
    /// each of its users' keys until one validates, so the cost is linear in the user
    /// count. That is what every other implementation of this protocol does too, and
    /// it is a per-connection cost of well under a microsecond per user.
    ///
    /// The timestamp is recovered but deliberately not checked. Judging freshness is
    /// the handler's business: rejecting a recognised user's stale auth id inside the
    /// search would send their connection on to the remaining users and have it come
    /// back as an unknown credential, which is a much worse diagnostic than "your
    /// clock is wrong".
    fn find_vmess_auth_id(&self, auth_id: &[u8; 16]) -> Option<VmessIdentity> {
        let _ = auth_id;
        None
    }

    /// Find whose PSK a Shadowsocks 2022 identity header named.
    ///
    /// `hash` is the plaintext recovered from the header: blake3 of the user's PSK,
    /// truncated to 16 bytes (see [`psk_hash`](crate::shadowsocks::psk_hash)). Unlike
    /// VMess this really is a lookup -- the client did the work of naming itself -- so
    /// implementations should index on the hash rather than walk their users.
    fn find_shadowsocks_psk_hash(&self, hash: &[u8; 16]) -> Option<ShadowsocksIdentity> {
        let _ = hash;
        None
    }

    /// Find whose TUIC uuid this is, together with the password its token is keyed
    /// with.
    ///
    /// Kept apart from [`find_uuid`](Self::find_uuid) because a TUIC credential is two
    /// values at once and half of it will not do: a VLESS user registered with the same
    /// uuid has no password to derive a token from, so authenticating them here would
    /// let a cleartext uuid stand in for the whole handshake.
    ///
    /// **This is the one lookup here that does not authenticate.** The uuid arrives in
    /// cleartext, so a hit proves nothing until the token beside it has been checked,
    /// and only the caller can check it -- deriving the expected token needs the QUIC
    /// connection's exported keying material, which the registry has never seen. So
    /// implementations must *not* call [`note_auth`](UserContext::note_auth); the
    /// handler calls it once the token matches. They must still treat a disabled user
    /// as absent.
    fn find_tuic_uuid(&self, uuid: &[u8; 16]) -> Option<TuicIdentity> {
        let _ = uuid;
        None
    }

    /// Find whose AnyTLS credential this is: the raw SHA-256 of their password, as
    /// [`password_sha256`](super::credential::password_sha256) derives it.
    ///
    /// Kept apart from [`find_password`](Self::find_password) because the hash is
    /// what crosses the wire -- AnyTLS never sends the cleartext -- and apart from
    /// [`find_trojan_hash`](Self::find_trojan_hash) because that is a different
    /// digest in a different encoding. One password can be indexed under all three.
    fn find_password_sha256(&self, hash: &[u8; 32]) -> Option<Arc<UserContext>> {
        let _ = hash;
        None
    }

    /// Whether any user's password hash *starts* with these 8 bytes.
    ///
    /// AnyTLS peeks at the first 8 bytes of a connection and, on a miss, diverts it
    /// to a fallback destination without waiting for the remaining 24. That is what
    /// stops a prober from hanging the handler, and it is why this question has to be
    /// answerable before the credential is complete.
    ///
    /// **This is a plausibility test, not a lookup.** `true` means "keep reading",
    /// never "this user exists" -- and in particular a **disabled user must still
    /// answer `true`**. Answering `false` for them would send their connections to
    /// the fallback while a live user's went to the handler, which is an observable
    /// difference an attacker can use to enumerate which credentials are suspended.
    ///
    /// What the probe leaks is 8 bytes' worth of "some registered password hashes
    /// start like this", which cannot be walked a byte at a time and does not narrow
    /// the remaining 24 bytes or the password behind them.
    fn has_password_sha256_prefix(&self, prefix: &[u8; 8]) -> bool {
        let _ = prefix;
        false
    }

    /// Look up the HTTP Basic credential NaiveProxy sends in `proxy-authorization`:
    /// base64 of `username:password`, with the `Basic ` prefix already stripped.
    ///
    /// `encoded` is caller-supplied and comes straight off a header, so
    /// implementations must not assume it is valid base64, valid UTF-8, or any
    /// particular length -- only compare it, never decode it.
    fn find_naive_basic(&self, encoded: &[u8]) -> Option<Arc<UserContext>> {
        let _ = encoded;
        None
    }

    /// How many users are registered. For diagnostics and API responses only; this
    /// may take a lock or walk shards, so it must not be called per connection.
    fn user_count(&self) -> usize;
}
