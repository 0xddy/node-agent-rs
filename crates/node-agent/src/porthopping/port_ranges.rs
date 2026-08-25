//! Provider-compatible inclusive UDP port range parsing.

use std::fmt;

/// One inclusive TCP/UDP port range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub const fn new(start: u16, end: u16) -> Self {
        Self { start, end }
    }

    pub const fn contains(self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(formatter, "{}", self.start)
        } else {
            write!(formatter, "{}-{}", self.start, self.end)
        }
    }
}

/// Parse the panel's comma-separated port/range syntax.
///
/// Results are sorted and overlapping or adjacent ranges are merged, matching
/// `api/provider/port_ranges.go`.
pub fn parse_port_ranges(expression: &str) -> Result<Vec<PortRange>, PortRangeError> {
    if expression.trim().is_empty() {
        return Ok(Vec::new());
    }

    let mut ranges = Vec::new();
    for raw_item in expression.split(',') {
        let item = raw_item.trim();
        if item.is_empty() {
            return Err(PortRangeError::new("port range contains an empty item"));
        }
        let bounds: Vec<_> = item.split('-').collect();
        if bounds.len() > 2 {
            return Err(PortRangeError::new(format!("invalid port range {item:?}")));
        }
        let start = parse_port(bounds[0].trim()).map_err(|error| {
            PortRangeError::new(format!("invalid port range {item:?}: {error}"))
        })?;
        let end = if bounds.len() == 2 {
            parse_port(bounds[1].trim()).map_err(|error| {
                PortRangeError::new(format!("invalid port range {item:?}: {error}"))
            })?
        } else {
            start
        };
        if end < start {
            return Err(PortRangeError::new(format!(
                "invalid port range {item:?}: end must not be less than start"
            )));
        }
        ranges.push(PortRange { start, end });
    }
    Ok(merge_port_ranges(ranges))
}

pub fn normalize_port_ranges(expression: &str) -> Result<String, PortRangeError> {
    Ok(parse_port_ranges(expression)?
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(","))
}

fn parse_port(value: &str) -> Result<u16, PortRangeError> {
    if value.is_empty() {
        return Err(PortRangeError::new("port is required"));
    }
    if !value.bytes().all(|digit| digit.is_ascii_digit()) {
        return Err(PortRangeError::new("port must contain decimal digits only"));
    }
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| PortRangeError::new("port must be between 1 and 65535"))
}

fn merge_port_ranges(mut ranges: Vec<PortRange>) -> Vec<PortRange> {
    ranges.sort_unstable();
    let mut merged: Vec<PortRange> = Vec::with_capacity(ranges.len());
    for current in ranges {
        if let Some(last) = merged.last_mut()
            && u32::from(current.start) <= u32::from(last.end) + 1
        {
            last.end = last.end.max(current.end);
            continue;
        }
        merged.push(current);
    }
    merged
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortRangeError(String);

impl PortRangeError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for PortRangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for PortRangeError {}

#[cfg(test)]
mod tests {
    use super::{PortRange, normalize_port_ranges, parse_port_ranges};

    #[test]
    fn parses_sorts_and_merges_like_the_provider() {
        assert_eq!(
            parse_port_ranges(" 200-210,100,101-199,300-301,301 ").unwrap(),
            vec![PortRange::new(100, 210), PortRange::new(300, 301)]
        );
        assert_eq!(
            normalize_port_ranges("443,1000-1002"),
            Ok("443,1000-1002".into())
        );
        assert!(parse_port_ranges("  ").unwrap().is_empty());
    }

    #[test]
    fn rejects_the_same_invalid_forms_as_go() {
        for expression in [",", "1,", "-1", "1-", "1-2-3", "0", "65536", "2-1", "+1"] {
            assert!(
                parse_port_ranges(expression).is_err(),
                "accepted {expression:?}"
            );
        }
    }
}
