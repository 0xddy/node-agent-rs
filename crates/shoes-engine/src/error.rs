use std::fmt;

/// Errors surfaced by the engine control plane.
///
/// The variants are kept distinct so an embedder can map them onto whatever its
/// own service layer reports -- gRPC status codes, HTTP statuses, FFI error
/// numbers. The distinction that matters, and the one worth preserving in any such
/// mapping, is "the caller asked for something invalid" versus "the engine could
/// not carry out something valid": the first must not invite a retry.
#[derive(Debug)]
pub enum EngineError {
    /// The submitted payload could not be turned into a shoes config.
    InvalidConfig(String),
    /// The requested tag is already registered.
    DuplicateTag(String),
    /// The requested tag is not registered.
    UnknownTag(String),
    /// The submitted user could not be accepted.
    InvalidUser(String),
    /// A different user on this inbound already presents the same credential.
    DuplicateCredential { id: String, owner: String },
    /// The requested user id is not registered on this inbound.
    UnknownUser { tag: String, id: String },
    /// Another inbound already listens on one of the requested addresses.
    AddressInUse { address: String, tag: String },
    /// The engine could not bind or start the listeners.
    Io(std::io::Error),
    /// The requested feature exists upstream but is not reachable through the
    /// dynamic API yet.
    Unsupported(String),
    /// The candidate is valid, but one or more settings are owned by the running
    /// listener and therefore cannot be swapped in place.
    ///
    /// Callers may handle this by explicitly removing and re-adding the inbound.
    /// Keeping this distinct from [`InvalidConfig`](Self::InvalidConfig) prevents a
    /// control plane from tearing down a healthy listener merely because a malformed
    /// candidate happened to produce a similar error message.
    ReloadRequired(String),
}

pub type EngineResult<T> = Result<T, EngineError>;

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "invalid inbound config: {msg}"),
            Self::DuplicateTag(tag) => write!(f, "inbound tag already registered: {tag}"),
            Self::UnknownTag(tag) => write!(f, "no such inbound tag: {tag}"),
            Self::InvalidUser(msg) => write!(f, "invalid user: {msg}"),
            Self::DuplicateCredential { id, owner } => write!(
                f,
                "cannot add user {id}: that credential already belongs to user {owner}"
            ),
            Self::UnknownUser { tag, id } => {
                write!(f, "no such user on inbound {tag}: {id}")
            }
            Self::AddressInUse { address, tag } => {
                write!(f, "address {address} is already used by inbound {tag}")
            }
            Self::Io(e) => write!(f, "{e}"),
            Self::Unsupported(msg) => write!(f, "unsupported: {msg}"),
            Self::ReloadRequired(msg) => write!(f, "inbound must be replaced: {msg}"),
        }
    }
}

impl std::error::Error for EngineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for EngineError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl EngineError {
    /// Construct a retryable update race without extending this public, historically
    /// exhaustive enum. The dedicated source marker lets callers distinguish this
    /// condition from an unrelated `WouldBlock` I/O failure.
    pub(crate) fn concurrent_modification(message: impl Into<String>) -> Self {
        Self::Io(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            ConcurrentModificationError(message.into()),
        ))
    }

    /// Whether this error reports that an inbound changed while an update was
    /// being prepared outside the engine's global control lock.
    ///
    /// Retrying such an update is safe: its candidate failed the identity/revision
    /// fence and was never published. This helper is intentionally more precise
    /// than matching every [`std::io::ErrorKind::WouldBlock`] error.
    #[must_use]
    pub fn is_concurrent_modification(&self) -> bool {
        match self {
            Self::Io(error) => error
                .get_ref()
                .and_then(|source| source.downcast_ref::<ConcurrentModificationError>())
                .is_some(),
            _ => false,
        }
    }

    /// Classifies an [`std::io::Error`] that came from a *rejected request*
    /// rather than from a failed operation.
    ///
    /// `shoes` reports its own refusals as `io::Error`, because that is the error
    /// type its APIs return -- but "this config does not describe the listeners
    /// that are running" is the caller's mistake, not the engine's failure, and
    /// reporting it as an I/O failure would invite a retry that can never succeed.
    /// The two kinds shoes uses deliberately are mapped through; anything else is a
    /// genuine I/O failure and stays one.
    pub(crate) fn from_reload_rejection(e: std::io::Error) -> Self {
        match e.kind() {
            // `InboundSlot::reload` validates every candidate before it swaps a
            // slot, and its InvalidInput/Unsupported paths all describe a running
            // listener that cannot represent the requested change in place.
            std::io::ErrorKind::InvalidInput | std::io::ErrorKind::Unsupported => {
                Self::ReloadRequired(e.to_string())
            }
            _ => Self::Io(e),
        }
    }
}

#[derive(Debug)]
struct ConcurrentModificationError(String);

impl fmt::Display for ConcurrentModificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "inbound changed while update was being prepared: {}",
            self.0
        )
    }
}

impl std::error::Error for ConcurrentModificationError {}

#[cfg(test)]
mod tests {
    use super::EngineError;

    #[test]
    fn concurrent_modification_uses_compatible_io_variant_and_exact_marker() {
        let error = EngineError::concurrent_modification("inbound example was replaced");
        assert!(error.is_concurrent_modification());
        let EngineError::Io(io) = error else {
            panic!("the retryable race must use the pre-existing Io variant");
        };
        assert_eq!(io.kind(), std::io::ErrorKind::WouldBlock);
        assert!(io.to_string().contains("inbound example was replaced"));

        let unrelated = EngineError::Io(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "ordinary backpressure",
        ));
        assert!(!unrelated.is_concurrent_modification());
    }

    // This intentionally lists the pre-existing public variants. Adding another
    // one makes this crate's own compatibility guard fail to compile just as it
    // would break an embedder's exhaustive match.
    #[allow(dead_code)]
    fn exhaustive_match_remains_source_compatible(error: &EngineError) {
        match error {
            EngineError::InvalidConfig(_)
            | EngineError::DuplicateTag(_)
            | EngineError::UnknownTag(_)
            | EngineError::InvalidUser(_)
            | EngineError::DuplicateCredential { .. }
            | EngineError::UnknownUser { .. }
            | EngineError::AddressInUse { .. }
            | EngineError::Io(_)
            | EngineError::Unsupported(_)
            | EngineError::ReloadRequired(_) => {}
        }
    }
}
