//! Machine-secret signing for `Hello` and for every authenticated request.
//!
//! A port of `src/pkg/acpauth/auth.go`. The panel recomputes these signatures
//! and rejects anything that does not match, so the two canonical strings below
//! are a byte-for-byte contract: a stray separator or a differently formatted
//! integer is an `Unauthenticated` status and a session that never opens.
//!
//! The agent only ever *signs*. Verification is the panel's side of the
//! contract and is deliberately not implemented here.

use base64::Engine as _;
use hmac::{Hmac, KeyInit as _, Mac as _};
use rand::Rng as _;
use sha2::Sha256;

use crate::hex;

/// gRPC metadata keys carried on every authenticated request.
pub const METADATA_MACHINE_ID: &str = "acp-machine-id";
pub const METADATA_SESSION_ID: &str = "acp-session-id";
pub const METADATA_TIMESTAMP_UNIX: &str = "acp-timestamp-unix";
pub const METADATA_NONCE: &str = "acp-nonce";
pub const METADATA_SIGNATURE: &str = "acp-signature";

/// Nonce length in bytes, matching `acpauth.NewSessionFields`.
pub const NONCE_BYTES: usize = 24;

/// A required field was empty.
///
/// Go returns an error for each of these rather than signing a degenerate
/// payload, and so do we. A signature over an empty machine id is not a weaker
/// signature -- it is an unverifiable one, and failing here turns a silent
/// authentication failure into an obvious startup error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingField(pub &'static str);

impl std::fmt::Display for MissingField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} is required", self.0)
    }
}

impl std::error::Error for MissingField {}

/// The fields covered by the `Hello` signature.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HelloFields {
    pub machine_id: String,
    pub node_id: String,
    pub agent_version: String,
    /// Reported to the panel as the data-plane version.
    ///
    /// The field keeps its `sing_box` name because it is part of the signed
    /// payload and of the proto contract. Only the value changes now that shoes
    /// is the data plane.
    pub sing_box_version: String,
    pub timestamp_unix: i64,
    pub nonce: String,
    pub topology_revision: u64,
}

/// The fields covered by the per-request signature.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionFields {
    pub machine_id: String,
    pub session_id: String,
    pub timestamp_unix: i64,
    pub nonce: String,
}

/// Generates a fresh nonce: `len` random bytes, base64url with no padding.
///
/// Uses the same thread-local CSPRNG that shoes uses for REALITY key material.
#[must_use]
pub fn new_nonce(len: usize) -> String {
    let mut buf = vec![0u8; len];
    rand::rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&buf)
}

/// Builds `SessionFields` with a fresh nonce and the given timestamp.
pub fn new_session_fields(
    machine_id: impl Into<String>,
    session_id: impl Into<String>,
    timestamp_unix: i64,
) -> SessionFields {
    SessionFields {
        machine_id: machine_id.into(),
        session_id: session_id.into(),
        timestamp_unix,
        nonce: new_nonce(NONCE_BYTES),
    }
}

/// The exact string the `Hello` HMAC covers.
///
/// Seven newline-separated fields in this order. Integers are plain decimal with
/// no padding and no sign, matching Go's `%d`.
fn canonical_hello(fields: &HelloFields) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}",
        fields.machine_id,
        fields.node_id,
        fields.agent_version,
        fields.sing_box_version,
        fields.timestamp_unix,
        fields.nonce,
        fields.topology_revision,
    )
}

/// The exact string the per-request HMAC covers.
fn canonical_session(fields: &SessionFields) -> String {
    format!(
        "{}\n{}\n{}\n{}",
        fields.machine_id, fields.session_id, fields.timestamp_unix, fields.nonce,
    )
}

/// Signs a `Hello`. Requires a secret, a machine id, and a node id.
///
/// # Errors
///
/// Returns [`MissingField`] when the secret, machine id, or node id is empty.
pub fn sign_hello(secret: &str, fields: &HelloFields) -> Result<String, MissingField> {
    if secret.is_empty() {
        return Err(MissingField("machine secret"));
    }
    if fields.machine_id.is_empty() {
        return Err(MissingField("machine id"));
    }
    if fields.node_id.is_empty() {
        return Err(MissingField("node id"));
    }
    Ok(sign(secret, &canonical_hello(fields)))
}

/// Signs an authenticated request. Requires a secret, a machine id, a session
/// id, and a nonce.
///
/// # Errors
///
/// Returns [`MissingField`] when the secret, machine id, session id, or nonce is
/// empty.
pub fn sign_session(secret: &str, fields: &SessionFields) -> Result<String, MissingField> {
    if secret.is_empty() {
        return Err(MissingField("machine secret"));
    }
    if fields.machine_id.is_empty() {
        return Err(MissingField("machine id"));
    }
    if fields.session_id.is_empty() {
        return Err(MissingField("session id"));
    }
    if fields.nonce.is_empty() {
        return Err(MissingField("nonce"));
    }
    Ok(sign(secret, &canonical_session(fields)))
}

/// The five metadata pairs an authenticated request carries, in the order Go
/// appends them.
///
/// Order is irrelevant to HTTP/2, but keeping it makes captured traffic from the
/// two agents line up field for field during the migration.
///
/// # Errors
///
/// Returns [`MissingField`] when any field required by [`sign_session`] is
/// empty.
pub fn session_metadata(
    secret: &str,
    fields: &SessionFields,
) -> Result<[(&'static str, String); 5], MissingField> {
    let signature = sign_session(secret, fields)?;
    Ok([
        (METADATA_MACHINE_ID, fields.machine_id.clone()),
        (METADATA_SESSION_ID, fields.session_id.clone()),
        (METADATA_TIMESTAMP_UNIX, fields.timestamp_unix.to_string()),
        (METADATA_NONCE, fields.nonce.clone()),
        (METADATA_SIGNATURE, signature),
    ])
}

fn sign(secret: &str, payload: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts a key of any length");
    mac.update(payload.as_bytes());
    hex::encode(&mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Signatures produced by the real Go `acpauth` package over the fixtures
    /// below. These are not self-consistency checks: they were generated by
    /// running `acpauth.SignHello` / `acpauth.SignSession` from node-agent's Go
    /// module, so they fail if this port drifts from the panel's expectations
    /// in any way -- canonical string, field order, integer formatting, or hash.
    const GO_HELLO_SIGNATURE: &str =
        "c02c75cb2a58889d80d7de72d68fee0b3509ccddf717d5593e75b40d20aa2a8d";
    const GO_SESSION_SIGNATURE: &str =
        "0e7d1ae58ad5389b13bb9a6263eefa887db95121e568724a0a2d47b198e46afe";

    fn hello() -> HelloFields {
        HelloFields {
            machine_id: "machine-1".to_string(),
            node_id: "node-1".to_string(),
            agent_version: "0.1.0-dev".to_string(),
            sing_box_version: "shoes-0.2.8".to_string(),
            timestamp_unix: 1_700_000_000,
            nonce: "Zm9vYmFyLXRlc3Qtbm9uY2UtMjQ".to_string(),
            topology_revision: 42,
        }
    }

    fn session() -> SessionFields {
        SessionFields {
            machine_id: "machine-1".to_string(),
            session_id: "session-abc".to_string(),
            timestamp_unix: 1_700_000_000,
            nonce: "Zm9vYmFyLXRlc3Qtbm9uY2UtMjQ".to_string(),
        }
    }

    #[test]
    fn signatures_match_the_go_implementation() {
        assert_eq!(
            sign_hello("s3cr3t", &hello()).unwrap(),
            GO_HELLO_SIGNATURE,
            "the panel rejects a Hello whose HMAC differs by one byte"
        );
        assert_eq!(
            sign_session("s3cr3t", &session()).unwrap(),
            GO_SESSION_SIGNATURE
        );
    }

    #[test]
    fn the_canonical_strings_have_the_documented_shape() {
        assert_eq!(
            canonical_hello(&hello()),
            "machine-1\nnode-1\n0.1.0-dev\nshoes-0.2.8\n1700000000\nZm9vYmFyLXRlc3Qtbm9uY2UtMjQ\n42"
        );
        assert_eq!(
            canonical_session(&session()),
            "machine-1\nsession-abc\n1700000000\nZm9vYmFyLXRlc3Qtbm9uY2UtMjQ"
        );
    }

    #[test]
    fn every_signed_field_actually_changes_the_signature() {
        // A field that is in the struct but not in the canonical string would
        // be a silent authentication hole: the agent would think it committed
        // to a value the panel never checked.
        let baseline = sign_hello("s3cr3t", &hello()).unwrap();
        let variants = [
            HelloFields {
                machine_id: "other".into(),
                ..hello()
            },
            HelloFields {
                node_id: "other".into(),
                ..hello()
            },
            HelloFields {
                agent_version: "other".into(),
                ..hello()
            },
            HelloFields {
                sing_box_version: "other".into(),
                ..hello()
            },
            HelloFields {
                timestamp_unix: 1_700_000_001,
                ..hello()
            },
            HelloFields {
                nonce: "other".into(),
                ..hello()
            },
            HelloFields {
                topology_revision: 43,
                ..hello()
            },
        ];
        for variant in variants {
            assert_ne!(sign_hello("s3cr3t", &variant).unwrap(), baseline);
        }
        assert_ne!(sign_hello("different-secret", &hello()).unwrap(), baseline);
    }

    #[test]
    fn field_boundaries_are_unambiguous() {
        // Without a separator, ("ab", "c") and ("a", "bc") would sign the same
        // bytes, letting one machine forge another's identity.
        let left = HelloFields {
            machine_id: "ab".into(),
            node_id: "c".into(),
            ..hello()
        };
        let right = HelloFields {
            machine_id: "a".into(),
            node_id: "bc".into(),
            ..hello()
        };
        assert_ne!(
            sign_hello("s3cr3t", &left).unwrap(),
            sign_hello("s3cr3t", &right).unwrap()
        );
    }

    #[test]
    fn empty_required_fields_are_refused_rather_than_signed() {
        assert_eq!(
            sign_hello("", &hello()),
            Err(MissingField("machine secret"))
        );
        assert_eq!(
            sign_hello(
                "s",
                &HelloFields {
                    machine_id: String::new(),
                    ..hello()
                }
            ),
            Err(MissingField("machine id"))
        );
        assert_eq!(
            sign_hello(
                "s",
                &HelloFields {
                    node_id: String::new(),
                    ..hello()
                }
            ),
            Err(MissingField("node id"))
        );
        assert_eq!(
            sign_session("", &session()),
            Err(MissingField("machine secret"))
        );
        assert_eq!(
            sign_session(
                "s",
                &SessionFields {
                    session_id: String::new(),
                    ..session()
                }
            ),
            Err(MissingField("session id"))
        );
        assert_eq!(
            sign_session(
                "s",
                &SessionFields {
                    nonce: String::new(),
                    ..session()
                }
            ),
            Err(MissingField("nonce"))
        );
    }

    #[test]
    fn a_nonce_is_base64url_without_padding() {
        let nonce = new_nonce(NONCE_BYTES);
        assert_eq!(nonce.len(), 32, "24 bytes base64-encodes to 32 characters");
        assert!(!nonce.contains('='), "raw encoding carries no padding");
        assert!(
            !nonce.contains('+') && !nonce.contains('/'),
            "url-safe alphabet only"
        );
        assert_ne!(nonce, new_nonce(NONCE_BYTES), "nonces must not repeat");
    }

    #[test]
    fn metadata_carries_five_pairs_with_the_signature_last() {
        let metadata = session_metadata("s3cr3t", &session()).unwrap();
        let keys: Vec<_> = metadata.iter().map(|(key, _)| *key).collect();
        assert_eq!(
            keys,
            vec![
                METADATA_MACHINE_ID,
                METADATA_SESSION_ID,
                METADATA_TIMESTAMP_UNIX,
                METADATA_NONCE,
                METADATA_SIGNATURE,
            ]
        );
        assert_eq!(metadata[2].1, "1700000000", "plain decimal, no separators");
        assert_eq!(metadata[4].1, GO_SESSION_SIGNATURE);
    }
}
