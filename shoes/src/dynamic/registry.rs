//! The credential lookup abstraction that protocol handlers authenticate against.

use std::sync::Arc;

use super::user::UserContext;

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

    /// How many users are registered. For diagnostics and API responses only; this
    /// may take a lock or walk shards, so it must not be called per connection.
    fn user_count(&self) -> usize;
}
