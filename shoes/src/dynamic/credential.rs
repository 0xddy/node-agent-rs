//! Credential derivation for registries built outside this crate.
//!
//! A control plane receives credentials the way an operator writes them -- a uuid
//! in canonical form, a Trojan password in cleartext -- but the handlers look users
//! up by what arrives on the wire. These are the two conversions in between.
//!
//! They exist so that an out-of-crate registry indexes on exactly the same bytes
//! `StaticUserRegistry` does. Re-deriving either of them elsewhere would put a
//! second implementation of a wire format in the tree, and the two would drift.

/// Parse a uuid into the 16 raw bytes VLESS and VMess put on the wire.
///
/// Dashes are optional and ignored, matching what `shoes` accepts in a config file.
pub fn parse_uuid(uuid_str: &str) -> std::io::Result<[u8; 16]> {
    let bytes = crate::uuid_util::parse_uuid(uuid_str)?;
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&bytes);
    Ok(uuid)
}

/// Derive the credential a Trojan client sends: SHA-224 of the password, rendered
/// as lowercase hex, 56 bytes.
pub fn trojan_password_hash(password: &str) -> Box<[u8]> {
    crate::trojan_handler::create_password_hash(password)
}

/// A fresh random uuid v4, in canonical form.
///
/// Meant for filling a config field that a [`super::UserRegistry`] has taken over,
/// where the schema still demands a credential that will never be consulted. It is
/// random rather than a fixed constant so that if such a value ever did reach an
/// authentication path, it would not be a credential an attacker could guess.
pub fn random_uuid() -> String {
    crate::uuid_util::generate_uuid()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_uuid_spellings_to_the_same_bytes() {
        let dashed = parse_uuid("b85798ef-e9dc-46a4-9a87-8da4499d36d0").unwrap();
        let bare = parse_uuid("b85798efe9dc46a49a878da4499d36d0").unwrap();
        assert_eq!(dashed, bare);
        assert_eq!(dashed[0], 0xb8);
        assert_eq!(dashed[15], 0xd0);
    }

    #[test]
    fn rejects_a_malformed_uuid() {
        assert!(parse_uuid("nope").is_err());
        // Too short: parse_uuid must not leave the tail zeroed and call it a uuid.
        assert!(parse_uuid("b85798ef").is_err());
    }

    #[test]
    fn derives_the_trojan_wire_credential() {
        let hash = trojan_password_hash("hunter2");
        assert_eq!(hash.len(), 56);
        assert!(hash.iter().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(hash, trojan_password_hash("hunter3"));
    }

    #[test]
    fn generates_parseable_and_distinct_uuids() {
        let first = random_uuid();
        let second = random_uuid();
        assert_ne!(first, second);
        assert!(parse_uuid(&first).is_ok());
    }
}
