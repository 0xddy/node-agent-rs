//! The credential lookup abstraction that protocol handlers authenticate against.

use std::sync::Arc;

use super::user::UserContext;

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

    /// How many users are registered. For diagnostics and API responses only; this
    /// may take a lock or walk shards, so it must not be called per connection.
    fn user_count(&self) -> usize;
}
