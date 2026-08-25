//! Error classes shared by all forwarding backends.

use std::error::Error;
use std::fmt;

pub(crate) type BoxError = Box<dyn Error + Send + Sync + 'static>;
pub(crate) type BackendResult<T = ()> = Result<T, BoxError>;

/// The current platform cannot provide a required non-empty forwarding plan.
#[derive(Debug)]
pub struct CapabilityError {
    pub platform: String,
    pub capability: String,
    pub reason: String,
    source: Option<BoxError>,
}

impl CapabilityError {
    pub fn new(
        platform: impl Into<String>,
        capability: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            platform: platform.into(),
            capability: capability.into(),
            reason: reason.into(),
            source: None,
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn with_source(mut self, source: impl Error + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut message = String::from("port hopping forwarding capability is unavailable");
        if !self.platform.is_empty() {
            message.push_str(" on ");
            message.push_str(&self.platform);
        }
        if !self.capability.is_empty() {
            message.push_str(": ");
            message.push_str(&self.capability);
        }
        let reason = if self.reason.is_empty() {
            self.source.as_ref().map(ToString::to_string)
        } else {
            Some(self.reason.clone())
        };
        if let Some(reason) = reason.filter(|reason| !reason.is_empty()) {
            message.push_str(" (");
            message.push_str(&reason);
            message.push(')');
        }
        formatter.write_str(&message)
    }
}

impl Error for CapabilityError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

/// An atomic platform operation was submitted but its final state is unknown.
#[derive(Debug)]
pub struct StateUncertainError {
    source: Option<BoxError>,
}

impl StateUncertainError {
    pub fn new(source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            source: Some(Box::new(source)),
        }
    }

    #[cfg(test)]
    pub(crate) fn without_source() -> Self {
        Self { source: None }
    }
}

impl fmt::Display for StateUncertainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.source {
            Some(source) => fmt::Display::fmt(source, formatter),
            None => formatter.write_str("port hopping forwarding state is uncertain"),
        }
    }
}

impl Error for StateUncertainError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

#[derive(Debug)]
pub(crate) struct OperationError {
    message: String,
    source: Option<BoxError>,
}

impl OperationError {
    pub(crate) fn message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn wrap(message: impl Into<String>, source: BoxError) -> Self {
        Self {
            message: message.into(),
            source: Some(source),
        }
    }
}

impl fmt::Display for OperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)?;
        if let Some(source) = &self.source {
            write!(formatter, ": {source}")?;
        }
        Ok(())
    }
}

impl Error for OperationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

#[derive(Debug)]
pub struct RouterClosedError;

impl fmt::Display for RouterClosedError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("port hopping router is closed")
    }
}

impl Error for RouterClosedError {}

pub fn is_capability_unsupported(error: &(dyn Error + 'static)) -> bool {
    error_chain_contains::<CapabilityError>(error)
}

pub fn is_state_uncertain(error: &(dyn Error + 'static)) -> bool {
    error_chain_contains::<StateUncertainError>(error)
}

pub fn is_router_closed(error: &(dyn Error + 'static)) -> bool {
    error_chain_contains::<RouterClosedError>(error)
}

fn error_chain_contains<T: Error + 'static>(mut error: &(dyn Error + 'static)) -> bool {
    loop {
        if error.is::<T>() {
            return true;
        }
        let Some(source) = error.source() else {
            return false;
        };
        error = source;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CapabilityError, OperationError, StateUncertainError, is_capability_unsupported,
        is_state_uncertain,
    };

    #[test]
    fn classification_walks_wrapped_sources_without_cross_classifying() {
        let uncertain =
            OperationError::wrap("outer", Box::new(StateUncertainError::without_source()));
        assert!(is_state_uncertain(&uncertain));
        assert!(!is_capability_unsupported(&uncertain));

        let capability = OperationError::wrap(
            "outer",
            Box::new(CapabilityError::new("linux", "nftables", "unsupported")),
        );
        assert!(is_capability_unsupported(&capability));
        assert!(!is_state_uncertain(&capability));
    }
}
