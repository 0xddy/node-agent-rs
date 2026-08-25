//! Replay-protection state whose lifetime is the lifetime of one inbound.
//!
//! A TCP handler is only one immutable generation of an inbound. There may be one
//! handler per bind IP, and dynamic reload replaces all of them. Keeping replay
//! filters inside those handlers therefore splits the protection across addresses
//! and forgets it on every reload. This scope is instead owned by `ServerHandle` and
//! cloned into every handler generation belonging to that handle.

use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use parking_lot::Mutex;

use crate::replay_filter::ReplayFilter;
use crate::shadowsocks::salt_checker::SaltChecker;

/// A VMess auth id can be fresh for 120 seconds on either side of its timestamp.
/// Remembering it for the whole 240-second admissible interval leaves no replay gap.
pub(crate) const VMESS_AUTH_ID_WINDOW: Duration = Duration::from_secs(240);

/// SIP022 only requires an AEAD salt to be retained for 60 seconds.
pub(crate) const SHADOWSOCKS_SALT_WINDOW: Duration = Duration::from_secs(60);

pub(crate) type VmessAuthIdFilter = Arc<Mutex<ReplayFilter>>;
pub(crate) type ShadowsocksSaltFilter = Arc<Mutex<dyn SaltChecker>>;

/// The replay namespace for exactly one configured inbound.
///
/// VMess and Shadowsocks deliberately have separate filters: their wire values and
/// freshness windows are unrelated. Two configured inbounds deliberately get two
/// instances, while all bind addresses and reload generations of one inbound clone
/// these same two handles.
#[derive(Clone, Default)]
pub(crate) struct InboundReplayState {
    inner: Arc<InboundReplayStateInner>,
}

#[derive(Default)]
struct InboundReplayStateInner {
    vmess_auth_ids: OnceLock<VmessAuthIdFilter>,
    shadowsocks_salts: OnceLock<ShadowsocksSaltFilter>,
}

impl InboundReplayState {
    pub(crate) fn vmess_auth_ids(&self) -> VmessAuthIdFilter {
        Arc::clone(
            self.inner
                .vmess_auth_ids
                .get_or_init(new_vmess_auth_id_filter),
        )
    }

    pub(crate) fn shadowsocks_salts(&self) -> ShadowsocksSaltFilter {
        Arc::clone(
            self.inner
                .shadowsocks_salts
                .get_or_init(new_shadowsocks_salt_filter),
        )
    }
}

pub(crate) fn new_vmess_auth_id_filter() -> VmessAuthIdFilter {
    Arc::new(Mutex::new(ReplayFilter::new(VMESS_AUTH_ID_WINDOW)))
}

pub(crate) fn new_shadowsocks_salt_filter() -> ShadowsocksSaltFilter {
    Arc::new(Mutex::new(ReplayFilter::new(SHADOWSOCKS_SALT_WINDOW)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_share_one_inbound_but_new_scopes_are_isolated() {
        let inbound = InboundReplayState::default();
        let another_handler = inbound.clone();
        let another_inbound = InboundReplayState::default();

        assert!(inbound.inner.vmess_auth_ids.get().is_none());
        assert!(inbound.inner.shadowsocks_salts.get().is_none());

        let vmess = inbound.vmess_auth_ids();
        let shadowsocks = inbound.shadowsocks_salts();
        assert!(Arc::ptr_eq(&vmess, &another_handler.vmess_auth_ids()));
        assert!(Arc::ptr_eq(
            &shadowsocks,
            &another_handler.shadowsocks_salts()
        ));
        assert!(!Arc::ptr_eq(
            &inbound.vmess_auth_ids(),
            &another_inbound.vmess_auth_ids()
        ));
        assert!(!Arc::ptr_eq(
            &inbound.shadowsocks_salts(),
            &another_inbound.shadowsocks_salts()
        ));
    }
}
