//! Small command-line surface shared by the binary and tests.

use std::fmt;
use std::io::{self, Write};

pub const AGENT_VERSION: &str = match option_env!("NODE_AGENT_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

#[derive(Debug)]
pub enum VersionCommandError {
    Usage,
    Write(io::Error),
}

impl fmt::Display for VersionCommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage => formatter.write_str("usage: node-agent version [--json]"),
            Self::Write(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

impl std::error::Error for VersionCommandError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Write(error) => Some(error),
            Self::Usage => None,
        }
    }
}

/// Returns `false` without writing when the arguments are not the version
/// command. The output bytes and usage boundary match the Go binary.
pub fn run_version_command(
    args: &[String],
    mut stdout: impl Write,
) -> Result<bool, VersionCommandError> {
    if args.get(1).map(String::as_str) != Some("version") {
        return Ok(false);
    }
    match args.get(2..).unwrap_or_default() {
        [] => writeln!(stdout, "{AGENT_VERSION}"),
        [flag] if flag == "--json" => {
            serde_json::to_writer(
                &mut stdout,
                &serde_json::json!({ "version": AGENT_VERSION }),
            )
            .map_err(|error| VersionCommandError::Write(io::Error::other(error.to_string())))?;
            writeln!(stdout)
        }
        _ => return Err(VersionCommandError::Usage),
    }
    .map_err(VersionCommandError::Write)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_json_invalid_and_non_version_boundaries_match_go() {
        let mut output = Vec::new();
        assert!(run_version_command(&args(&["version"]), &mut output).unwrap());
        assert_eq!(
            String::from_utf8(output).unwrap(),
            format!("{AGENT_VERSION}\n")
        );

        let mut output = Vec::new();
        assert!(run_version_command(&args(&["version", "--json"]), &mut output).unwrap());
        assert_eq!(
            String::from_utf8(output).unwrap(),
            format!("{{\"version\":\"{AGENT_VERSION}\"}}\n")
        );

        assert_eq!(
            run_version_command(&args(&["version", "--verbose"]), Vec::new())
                .unwrap_err()
                .to_string(),
            "usage: node-agent version [--json]"
        );
        assert!(!run_version_command(&args(&["config.toml"]), Vec::new()).unwrap());
    }

    #[test]
    fn write_failures_are_returned() {
        let error = run_version_command(&args(&["version"]), FailingWriter).unwrap_err();
        assert!(matches!(error, VersionCommandError::Write(_)));
    }

    fn args(rest: &[&str]) -> Vec<String> {
        std::iter::once("node-agent")
            .chain(rest.iter().copied())
            .map(str::to_string)
            .collect()
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("write failed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
