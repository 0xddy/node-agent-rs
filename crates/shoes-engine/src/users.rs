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
//! handshake, never per packet. The read guard is held only for the comparison, so
//! a concurrent `POST /users` on the same shard waits nanoseconds, not for I/O.

use std::sync::Arc;

use dashmap::DashMap;
use shoes::dynamic::{UserContext, UserRegistry, credential};
use shoes_api::{UserInfo, UserSpec};
use subtle::ConstantTimeEq;

use crate::error::{EngineError, EngineResult};

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
}

impl CredentialKinds {
    pub const NONE: Self = Self {
        uuid: false,
        trojan_password: false,
    };

    pub const UUID: Self = Self {
        uuid: true,
        trojan_password: false,
    };

    pub const TROJAN_PASSWORD: Self = Self {
        uuid: false,
        trojan_password: true,
    };

    pub fn is_empty(&self) -> bool {
        *self == Self::NONE
    }

    pub fn merge(&mut self, other: Self) {
        self.uuid |= other.uuid;
        self.trojan_password |= other.trojan_password;
    }

    /// The credential fields a caller may set, for use in error messages.
    fn accepted_fields(&self) -> &'static str {
        match (self.uuid, self.trojan_password) {
            (true, true) => "`uuid` or `password`",
            (true, false) => "`uuid`",
            (false, true) => "`password`",
            (false, false) => "nothing",
        }
    }
}

/// The wire-form credentials of one user, already converted to index keys.
struct Credentials {
    uuid: Option<[u8; 16]>,
    trojan_hash: Option<Box<[u8]>>,
}

/// One user: their shared accounting record plus the credentials that reach it.
struct Entry {
    context: Arc<UserContext>,
    /// Retained so a hash hit can be confirmed in constant time. The hash probe
    /// that found this entry is not constant time and proves nothing on its own.
    uuid: Option<[u8; 16]>,
    trojan_hash: Option<Box<[u8]>>,
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
        self.context.note_auth();
        Some(self.context.clone())
    }
}

/// A user table that can be mutated while the inbound it belongs to is serving.
pub struct MemoryUserRegistry {
    kinds: CredentialKinds,
    /// id -> user. Authoritative: `list` and `remove` work from this map, and it is
    /// the only place a user without a usable credential could be observed.
    users: DashMap<Arc<str>, Arc<Entry>>,
    /// wire uuid -> user. The index `find_uuid` hits.
    by_uuid: DashMap<[u8; 16], Arc<Entry>>,
    /// wire hash -> user. The index `find_trojan_hash` hits.
    by_trojan_hash: DashMap<Box<[u8]>, Arc<Entry>>,
}

impl std::fmt::Debug for MemoryUserRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryUserRegistry")
            .field("kinds", &self.kinds)
            .field("num_users", &self.users.len())
            .finish()
    }
}

impl MemoryUserRegistry {
    pub fn new(kinds: CredentialKinds) -> Arc<Self> {
        Arc::new(Self {
            kinds,
            users: DashMap::new(),
            by_uuid: DashMap::new(),
            by_trojan_hash: DashMap::new(),
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
    /// Writers are serialised by the engine's control lock, so the authoritative
    /// map and the credential indexes cannot be observed disagreeing about which
    /// user owns a credential.
    pub fn upsert(&self, spec: UserSpec) -> EngineResult<UserInfo> {
        let id: Arc<str> = match spec.resolved_id() {
            Some(id) if !id.trim().is_empty() => id.into(),
            _ => {
                return Err(EngineError::InvalidUser(
                    "user needs an `id`, or a `uuid` to use as one".into(),
                ));
            }
        };

        let credentials = self.parse_credentials(&spec)?;
        self.check_credentials_unclaimed(&id, &credentials)?;

        // Everything past here must succeed: the table is about to change.
        let previous = self.users.get(&id).map(|entry| entry.value().clone());

        let context = match &previous {
            Some(entry) => entry.context.clone(),
            None => UserContext::new(id.clone()),
        };
        context.set_enabled(spec.enabled);

        let entry = Arc::new(Entry {
            context,
            uuid: credentials.uuid,
            trojan_hash: credentials.trojan_hash,
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
        }

        if let Some(uuid) = entry.uuid {
            self.by_uuid.insert(uuid, entry.clone());
        }
        if let Some(hash) = &entry.trojan_hash {
            self.by_trojan_hash.insert(hash.clone(), entry.clone());
        }
        self.users.insert(id, entry.clone());

        Ok(user_info(&entry.context))
    }

    /// Removes a user so no new connection can authenticate as them.
    ///
    /// Established connections are deliberately untouched. They hold their own
    /// `Arc<UserContext>`, taken at handshake time, so they keep running and keep
    /// accounting; only the lookup path forgets the credential. Cutting them off
    /// would need a per-user cancellation token, which is a different feature from
    /// revoking a credential.
    pub fn remove(&self, tag: &str, id: &str) -> EngineResult<UserInfo> {
        let (_, entry) = self.users.remove(id).ok_or_else(|| EngineError::UnknownUser {
            tag: tag.to_string(),
            id: id.to_string(),
        })?;

        if let Some(uuid) = entry.uuid {
            self.by_uuid.remove(&uuid);
        }
        if let Some(hash) = &entry.trojan_hash {
            self.by_trojan_hash.remove(hash);
        }

        Ok(user_info(&entry.context))
    }

    pub fn get(&self, id: &str) -> Option<UserInfo> {
        self.users.get(id).map(|entry| user_info(&entry.context))
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
    fn parse_credentials(&self, spec: &UserSpec) -> EngineResult<Credentials> {
        if spec.uuid.is_some() && !self.kinds.uuid {
            return Err(EngineError::InvalidUser(format!(
                "this inbound does not authenticate by uuid; it accepts {}",
                self.kinds.accepted_fields()
            )));
        }
        if spec.password.is_some() && !self.kinds.trojan_password {
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

        let uuid = match spec.uuid.as_deref() {
            Some(uuid) => Some(
                credential::parse_uuid(uuid)
                    .map_err(|e| EngineError::InvalidUser(e.to_string()))?,
            ),
            None => None,
        };

        Ok(Credentials {
            uuid,
            trojan_hash: spec
                .password
                .as_deref()
                .map(credential::trojan_password_hash),
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
        Ok(())
    }

    fn credential_owner_uuid(&self, uuid: &[u8; 16]) -> Option<Arc<str>> {
        self.by_uuid.get(uuid).map(|e| e.context.id().clone())
    }

    fn credential_owner_trojan(&self, hash: &[u8]) -> Option<Arc<str>> {
        self.by_trojan_hash
            .get(hash)
            .map(|e| e.context.id().clone())
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

    fn user_count(&self) -> usize {
        self.users.len()
    }
}

fn user_info(context: &UserContext) -> UserInfo {
    let stats = context.stats();
    UserInfo {
        id: stats.id.to_string(),
        enabled: stats.enabled,
        tx: stats.tx,
        rx: stats.rx,
        conns: stats.conns,
        total_conns: stats.total_conns,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID_A: &str = "b85798ef-e9dc-46a4-9a87-8da4499d36d0";
    const UUID_B: &str = "11111111-1111-4111-8111-111111111111";

    fn uuid_bytes(s: &str) -> [u8; 16] {
        credential::parse_uuid(s).unwrap()
    }

    fn uuid_spec(id: &str, uuid: &str) -> UserSpec {
        UserSpec {
            id: Some(id.to_string()),
            uuid: Some(uuid.to_string()),
            password: None,
            enabled: true,
        }
    }

    fn trojan_spec(id: &str, password: &str) -> UserSpec {
        UserSpec {
            id: Some(id.to_string()),
            uuid: None,
            password: Some(password.to_string()),
            enabled: true,
        }
    }

    #[test]
    fn an_empty_registry_denies_everyone() {
        let registry = MemoryUserRegistry::new(CredentialKinds::UUID);
        assert_eq!(registry.user_count(), 0);
        assert!(registry.find_uuid(&uuid_bytes(UUID_A)).is_none());
    }

    #[test]
    fn authenticates_two_users_independently() {
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

        registry.remove("in", "alice").unwrap();
        assert!(registry.find_uuid(&uuid_bytes(UUID_A)).is_none());
        assert!(registry.find_uuid(&uuid_bytes(UUID_B)).is_some());
        // Alice's live connections still hold their record and still account to it.
        alice.add_tx(1);
        assert_eq!(alice.tx(), 101);
    }

    #[test]
    fn repeated_lookups_share_one_record() {
        let registry = MemoryUserRegistry::new(CredentialKinds::UUID);
        registry.upsert(uuid_spec("alice", UUID_A)).unwrap();
        let first = registry.find_uuid(&uuid_bytes(UUID_A)).unwrap();
        let second = registry.find_uuid(&uuid_bytes(UUID_A)).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(first.total_conns(), 2);
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
        let err = registry.upsert(trojan_spec("alice", "hunter2")).unwrap_err();
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

    #[test]
    fn remove_reports_an_unknown_id() {
        let registry = MemoryUserRegistry::new(CredentialKinds::UUID);
        let err = registry.remove("in", "nobody").unwrap_err();
        assert!(matches!(err, EngineError::UnknownUser { .. }));
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
        assert!(!json.contains(UUID_A), "credentials must not be echoed back");
    }
}
