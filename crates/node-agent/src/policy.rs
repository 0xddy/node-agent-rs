//! Policy commands whose only current effect is the telemetry state string.

use std::sync::atomic::{AtomicBool, Ordering};

use acp_proto::{ControlCommand, ControlCommandType, control_command};
use serde::Deserialize;

#[derive(Debug, Default)]
pub struct PolicyState {
    maintenance: AtomicBool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError(String);

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PolicyError {}

impl PolicyState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply(&self, command: &ControlCommand) -> Result<String, PolicyError> {
        match ControlCommandType::try_from(command.r#type).ok() {
            Some(ControlCommandType::Diagnostics) => Ok("diagnostics command accepted".to_string()),
            Some(ControlCommandType::Maintenance) => {
                let enabled = match &command.payload {
                    Some(control_command::Payload::Maintenance(payload)) => payload.enabled,
                    _ => decode_legacy_maintenance(&command.legacy_payload)?,
                };
                self.maintenance.store(enabled, Ordering::Release);
                Ok(format!("maintenance mode set to {enabled}"))
            }
            known => Err(PolicyError(format!(
                "unsupported control command type {}",
                known.map_or_else(
                    || command.r#type.to_string(),
                    |kind| kind.as_str_name().to_string()
                )
            ))),
        }
    }

    pub fn maintenance(&self) -> bool {
        self.maintenance.load(Ordering::Acquire)
    }
}

#[derive(Deserialize)]
struct LegacyMaintenance {
    enabled: bool,
}

fn decode_legacy_maintenance(payload: &[u8]) -> Result<bool, PolicyError> {
    if payload.is_empty() {
        return Err(PolicyError("payload is required".into()));
    }
    serde_json::from_slice::<LegacyMaintenance>(payload)
        .map(|payload| payload.enabled)
        .map_err(|error| PolicyError(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use acp_proto::{DiagnosticsCommand, MaintenanceCommand};

    fn command(kind: ControlCommandType) -> ControlCommand {
        ControlCommand {
            r#type: kind as i32,
            ..Default::default()
        }
    }

    #[test]
    fn typed_maintenance_changes_only_the_state_flag() {
        let state = PolicyState::new();
        let mut enable = command(ControlCommandType::Maintenance);
        enable.payload = Some(control_command::Payload::Maintenance(MaintenanceCommand {
            enabled: true,
            reject_new_connections: true,
            message: "maintenance".into(),
        }));
        assert_eq!(
            state.apply(&enable).unwrap(),
            "maintenance mode set to true"
        );
        assert!(state.maintenance());

        let mut disable = enable;
        disable.payload = Some(control_command::Payload::Maintenance(MaintenanceCommand {
            enabled: false,
            ..Default::default()
        }));
        assert_eq!(
            state.apply(&disable).unwrap(),
            "maintenance mode set to false"
        );
        assert!(!state.maintenance());
    }

    #[test]
    fn legacy_payload_and_diagnostics_match_go() {
        let state = PolicyState::new();
        let mut legacy = command(ControlCommandType::Maintenance);
        legacy.legacy_payload = br#"{"enabled":true}"#.to_vec();
        state.apply(&legacy).unwrap();
        assert!(state.maintenance());

        let mut diagnostics = command(ControlCommandType::Diagnostics);
        diagnostics.payload = Some(control_command::Payload::Diagnostics(
            DiagnosticsCommand::default(),
        ));
        assert_eq!(
            state.apply(&diagnostics).unwrap(),
            "diagnostics command accepted"
        );
        assert!(
            state.maintenance(),
            "diagnostics does not change maintenance"
        );
    }

    #[test]
    fn malformed_or_unsupported_commands_fail_without_mutation() {
        let state = PolicyState::new();
        let maintenance = command(ControlCommandType::Maintenance);
        assert_eq!(
            state.apply(&maintenance).unwrap_err().to_string(),
            "payload is required"
        );
        assert!(!state.maintenance());

        let upgrade = command(ControlCommandType::Upgrade);
        assert_eq!(
            state.apply(&upgrade).unwrap_err().to_string(),
            "unsupported control command type CONTROL_COMMAND_TYPE_UPGRADE"
        );
        assert!(!state.maintenance());
    }
}
