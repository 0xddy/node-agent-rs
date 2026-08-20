//! The registry used when an inbound gets its users from a config file.
//!
//! Immutable once built, so lookups need no synchronisation at all. This is the
//! fallback path: when nothing injects a registry, each protocol handler builds one
//! of these from the credentials in its own config section, which reproduces the
//! single-user comparison the handlers did before the registry existed.

use std::sync::Arc;

use rustc_hash::FxHashMap;
use subtle::ConstantTimeEq;

use super::registry::UserRegistry;
use super::user::UserContext;
use crate::trojan_handler::create_password_hash;
use crate::uuid_util::parse_uuid;

/// Identity reported for users that came from a config file rather than an API.
///
/// Password-based protocols have no name in their config, and the password itself
/// must never be used as an identity, so they all share this label.
const CONFIG_USER_ID: &str = "config";

struct Entry {
    context: Arc<UserContext>,
    /// The credential exactly as it arrives on the wire, retained so that a hit can
    /// be confirmed in constant time. The hash probe that found this entry is not
    /// constant time and is not treated as proof of anything.
    credential: Box<[u8]>,
}

impl Entry {
    fn new(id: &str, credential: impl Into<Box<[u8]>>) -> Self {
        Self {
            context: UserContext::new(id),
            credential: credential.into(),
        }
    }

    fn verify(&self, presented: &[u8]) -> Option<Arc<UserContext>> {
        if self.credential.ct_eq(presented).unwrap_u8() == 0 || !self.context.is_enabled() {
            return None;
        }
        self.context.note_auth();
        Some(self.context.clone())
    }
}

#[derive(Default)]
pub struct StaticUserRegistry {
    by_uuid: FxHashMap<[u8; 16], Entry>,
    by_trojan_hash: FxHashMap<Box<[u8]>, Entry>,
    by_password: FxHashMap<Box<str>, Entry>,
}

impl std::fmt::Debug for StaticUserRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticUserRegistry")
            .field("num_users", &self.user_count())
            .finish()
    }
}

impl StaticUserRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a uuid credential, identified by its own canonical form.
    ///
    /// A uuid is not a secret in the sense a password is: it is what VLESS puts on
    /// the wire in cleartext, and it is already the identity every operator uses to
    /// refer to the user, so it is safe and useful as the reported id.
    pub fn add_uuid(&mut self, uuid_str: &str) -> std::io::Result<&mut Self> {
        let bytes = parse_uuid(uuid_str)?;
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&bytes);
        self.by_uuid.insert(uuid, Entry::new(uuid_str, uuid));
        Ok(self)
    }

    pub fn add_trojan_password(&mut self, password: &str) -> &mut Self {
        let hash = create_password_hash(password);
        self.by_trojan_hash
            .insert(hash.clone(), Entry::new(CONFIG_USER_ID, hash));
        self
    }

    pub fn add_password(&mut self, id: &str, password: &str) -> &mut Self {
        self.by_password.insert(
            password.into(),
            Entry::new(id, password.as_bytes().to_vec()),
        );
        self
    }

    /// Registry for a config that declares exactly one uuid.
    pub fn single_uuid(uuid_str: &str) -> std::io::Result<Arc<dyn UserRegistry>> {
        let mut registry = Self::new();
        registry.add_uuid(uuid_str)?;
        Ok(Arc::new(registry))
    }

    /// Registry for a config that declares exactly one Trojan password.
    pub fn single_trojan_password(password: &str) -> Arc<dyn UserRegistry> {
        let mut registry = Self::new();
        registry.add_trojan_password(password);
        Arc::new(registry)
    }
}

impl UserRegistry for StaticUserRegistry {
    fn find_uuid(&self, uuid: &[u8; 16]) -> Option<Arc<UserContext>> {
        self.by_uuid.get(uuid)?.verify(uuid)
    }

    fn find_trojan_hash(&self, hash: &[u8]) -> Option<Arc<UserContext>> {
        self.by_trojan_hash.get(hash)?.verify(hash)
    }

    fn find_password(&self, password: &str) -> Option<Arc<UserContext>> {
        self.by_password
            .get(password)?
            .verify(password.as_bytes())
    }

    fn user_count(&self) -> usize {
        self.by_uuid.len() + self.by_trojan_hash.len() + self.by_password.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "b85798ef-e9dc-46a4-9a87-8da4499d36d0";

    fn uuid_bytes(s: &str) -> [u8; 16] {
        let mut out = [0u8; 16];
        out.copy_from_slice(&parse_uuid(s).unwrap());
        out
    }

    #[test]
    fn finds_a_registered_uuid_and_rejects_others() {
        let registry = StaticUserRegistry::single_uuid(UUID).unwrap();

        let found = registry.find_uuid(&uuid_bytes(UUID)).unwrap();
        assert_eq!(&**found.id(), UUID);
        assert_eq!(found.total_conns(), 1);

        assert!(
            registry
                .find_uuid(&uuid_bytes("11111111-1111-4111-8111-111111111111"))
                .is_none()
        );
    }

    #[test]
    fn accepts_a_uuid_without_dashes() {
        // VLESS carries raw bytes, so the wire form of both spellings is identical.
        let registry = StaticUserRegistry::single_uuid(UUID).unwrap();
        assert!(
            registry
                .find_uuid(&uuid_bytes(&UUID.replace('-', "")))
                .is_some()
        );
    }

    #[test]
    fn rejects_an_invalid_uuid_at_build_time() {
        assert!(StaticUserRegistry::single_uuid("not-a-uuid").is_err());
    }

    #[test]
    fn shares_one_context_across_lookups() {
        let registry = StaticUserRegistry::single_uuid(UUID).unwrap();
        let a = registry.find_uuid(&uuid_bytes(UUID)).unwrap();
        let b = registry.find_uuid(&uuid_bytes(UUID)).unwrap();
        assert!(Arc::ptr_eq(&a, &b), "each user must have one shared record");

        a.add_rx(100);
        b.add_tx(40);
        assert_eq!((b.rx(), a.tx()), (100, 40));
    }

    #[test]
    fn a_disabled_user_looks_absent() {
        let registry = StaticUserRegistry::single_uuid(UUID).unwrap();
        let user = registry.find_uuid(&uuid_bytes(UUID)).unwrap();
        user.set_enabled(false);
        assert!(registry.find_uuid(&uuid_bytes(UUID)).is_none());
        user.set_enabled(true);
        assert!(registry.find_uuid(&uuid_bytes(UUID)).is_some());
    }

    #[test]
    fn finds_a_trojan_password_by_its_wire_hash() {
        let registry = StaticUserRegistry::single_trojan_password("hunter2");
        let hash = create_password_hash("hunter2");
        assert_eq!(hash.len(), 56);
        assert!(registry.find_trojan_hash(&hash).is_some());
        assert!(
            registry
                .find_trojan_hash(&create_password_hash("hunter3"))
                .is_none()
        );
        // A short read must not panic or match.
        assert!(registry.find_trojan_hash(b"").is_none());
        assert!(registry.find_trojan_hash(&hash[..55]).is_none());
    }

    #[test]
    fn an_empty_registry_denies_everyone() {
        let registry = StaticUserRegistry::new();
        assert_eq!(registry.user_count(), 0);
        assert!(registry.find_uuid(&uuid_bytes(UUID)).is_none());
        assert!(registry.find_trojan_hash(&create_password_hash("x")).is_none());
        assert!(registry.find_password("x").is_none());
    }
}
