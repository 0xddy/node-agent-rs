use std::fmt;

/// Errors surfaced by the engine control plane.
///
/// Each variant maps to a distinct HTTP status in `shoes-controller`, so the
/// distinction between "the caller sent something invalid" and "the engine could
/// not carry it out" is preserved all the way to the API response.
#[derive(Debug)]
pub enum EngineError {
    /// The submitted payload could not be turned into a shoes config.
    InvalidConfig(String),
    /// The requested tag is already registered.
    DuplicateTag(String),
    /// The requested tag is not registered.
    UnknownTag(String),
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
