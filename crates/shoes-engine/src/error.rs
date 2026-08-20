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
    /// Classifies an [`std::io::Error`] that came from a *rejected request*
    /// rather than from a failed operation.
    ///
    /// `shoes` reports its own refusals as `io::Error`, because that is the error
    /// type its APIs return -- but "this config does not describe the listeners
    /// that are running" is the caller's mistake, not the engine's failure, and
    /// reporting it as an I/O failure would invite a retry that can never succeed.
    /// The two kinds shoes uses deliberately are mapped through; anything else is a
    /// genuine I/O failure and stays one.
    pub(crate) fn from_rejection(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::InvalidInput => Self::InvalidConfig(e.to_string()),
            std::io::ErrorKind::Unsupported => Self::Unsupported(e.to_string()),
            _ => Self::Io(e),
        }
    }
}
