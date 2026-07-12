use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;
use std::collections::BTreeMap;
use thiserror::Error;

const RUN_CAPABILITIES: [ControlPlaneCapability; 3] = [
    ControlPlaneCapability::SessionCreation,
    ControlPlaneCapability::TurnStart,
    ControlPlaneCapability::EventObservation,
];
const STEER_CAPABILITIES: [ControlPlaneCapability; 2] = [
    ControlPlaneCapability::Steering,
    ControlPlaneCapability::EventObservation,
];
const STOP_CAPABILITIES: [ControlPlaneCapability; 2] = [
    ControlPlaneCapability::Cancellation,
    ControlPlaneCapability::EventObservation,
];
const STATUS_CAPABILITIES: [ControlPlaneCapability; 2] = [
    ControlPlaneCapability::Status,
    ControlPlaneCapability::Steering,
];

/// A public Satelle operation that may require Codex control-plane support.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlPlaneOperation {
    Run,
    Steer,
    Stop,
    Status,
}

impl ControlPlaneOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::Steer => "steer",
            Self::Stop => "stop",
            Self::Status => "status",
        }
    }

    /// The exact stable capabilities needed when this operation contacts the
    /// upstream control plane. Durable Satelle status reads remain local; the
    /// Status mapping is for upstream recovery and ownership observation.
    pub const fn required_capabilities(self) -> &'static [ControlPlaneCapability] {
        match self {
            Self::Run => &RUN_CAPABILITIES,
            Self::Steer => &STEER_CAPABILITIES,
            Self::Stop => &STOP_CAPABILITIES,
            Self::Status => &STATUS_CAPABILITIES,
        }
    }
}

/// Stable Satelle capability names. Upstream method spellings never cross this
/// boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlPlaneCapability {
    SessionCreation,
    TurnStart,
    EventObservation,
    Steering,
    Status,
    Cancellation,
}

impl ControlPlaneCapability {
    pub const ALL: [Self; 6] = [
        Self::SessionCreation,
        Self::TurnStart,
        Self::EventObservation,
        Self::Steering,
        Self::Status,
        Self::Cancellation,
    ];

    const fn bit(self) -> u8 {
        match self {
            Self::SessionCreation => 1 << 0,
            Self::TurnStart => 1 << 1,
            Self::EventObservation => 1 << 2,
            Self::Steering => 1 << 3,
            Self::Status => 1 << 4,
            Self::Cancellation => 1 << 5,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SessionCreation => "session_creation",
            Self::TurnStart => "turn_start",
            Self::EventObservation => "event_observation",
            Self::Steering => "steering",
            Self::Status => "status",
            Self::Cancellation => "cancellation",
        }
    }
}

/// Compact closed set of stable control-plane capabilities.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ControlPlaneCapabilitySet(u8);

impl ControlPlaneCapabilitySet {
    pub const EMPTY: Self = Self(0);

    pub const fn contains(self, capability: ControlPlaneCapability) -> bool {
        self.0 & capability.bit() != 0
    }
}

impl FromIterator<ControlPlaneCapability> for ControlPlaneCapabilitySet {
    fn from_iter<T: IntoIterator<Item = ControlPlaneCapability>>(capabilities: T) -> Self {
        Self(
            capabilities
                .into_iter()
                .fold(0, |bits, capability| bits | capability.bit()),
        )
    }
}

/// Closed, diagnostic-safe reasons an installed Codex control plane cannot
/// admit an operation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlPlaneFailureReason {
    RuntimeMissing,
    VersionMalformed,
    VersionUnavailable,
    VersionUnsupported,
    SchemaUnavailable,
    HandshakeUnavailable,
    RequiredCapabilityMissing,
}

impl ControlPlaneFailureReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeMissing => "runtime_missing",
            Self::VersionMalformed => "version_malformed",
            Self::VersionUnavailable => "version_unavailable",
            Self::VersionUnsupported => "version_unsupported",
            Self::SchemaUnavailable => "schema_unavailable",
            Self::HandshakeUnavailable => "handshake_unavailable",
            Self::RequiredCapabilityMissing => "required_capability_missing",
        }
    }
}

/// Validated public details for `incompatible-control-plane`. Required
/// capabilities always match the selected operation; missing capabilities are
/// a unique subset in canonical order.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(try_from = "IncompatibleControlPlaneDetailsWire")]
pub struct IncompatibleControlPlaneDetails {
    operation: ControlPlaneOperation,
    reason: ControlPlaneFailureReason,
    missing_capabilities: Vec<ControlPlaneCapability>,
}

impl IncompatibleControlPlaneDetails {
    pub fn new(
        operation: ControlPlaneOperation,
        reason: ControlPlaneFailureReason,
        missing_capabilities: &[ControlPlaneCapability],
    ) -> Result<Self, IncompatibleControlPlaneDetailsError> {
        let supplied_missing = missing_capabilities;
        let mut missing_capabilities = Vec::with_capacity(supplied_missing.len());
        for capability in operation.required_capabilities() {
            let occurrences = supplied_missing
                .iter()
                .filter(|candidate| *candidate == capability)
                .count();
            if occurrences > 1 {
                return Err(IncompatibleControlPlaneDetailsError::DuplicateMissingCapability);
            }
            if occurrences == 1 {
                missing_capabilities.push(*capability);
            }
        }
        if supplied_missing
            .iter()
            .any(|capability| !operation.required_capabilities().contains(capability))
        {
            return Err(IncompatibleControlPlaneDetailsError::CapabilityNotRequired);
        }

        match (reason, missing_capabilities.is_empty()) {
            (ControlPlaneFailureReason::RequiredCapabilityMissing, true) => {
                return Err(IncompatibleControlPlaneDetailsError::MissingCapabilityRequired);
            }
            (ControlPlaneFailureReason::RequiredCapabilityMissing, false) | (_, true) => {}
            (_, false) => {
                return Err(IncompatibleControlPlaneDetailsError::UnexpectedMissingCapability);
            }
        }

        Ok(Self {
            operation,
            reason,
            missing_capabilities,
        })
    }

    pub const fn operation(&self) -> ControlPlaneOperation {
        self.operation
    }

    pub const fn reason(&self) -> ControlPlaneFailureReason {
        self.reason
    }

    pub fn required_capabilities(&self) -> &[ControlPlaneCapability] {
        self.operation.required_capabilities()
    }

    pub fn missing_capabilities(&self) -> &[ControlPlaneCapability] {
        &self.missing_capabilities
    }

    pub(crate) fn into_error_details(self) -> BTreeMap<String, Value> {
        BTreeMap::from([
            (
                "operation".to_string(),
                Value::String(self.operation.as_str().to_string()),
            ),
            (
                "reason".to_string(),
                Value::String(self.reason.as_str().to_string()),
            ),
            (
                "required_capabilities".to_string(),
                capability_values(self.operation.required_capabilities()),
            ),
            (
                "missing_capabilities".to_string(),
                capability_values(&self.missing_capabilities),
            ),
        ])
    }
}

impl Serialize for IncompatibleControlPlaneDetails {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        IncompatibleControlPlaneDetailsWireRef {
            operation: self.operation,
            reason: self.reason,
            required_capabilities: self.operation.required_capabilities(),
            missing_capabilities: &self.missing_capabilities,
        }
        .serialize(serializer)
    }
}

fn capability_values(capabilities: &[ControlPlaneCapability]) -> Value {
    Value::Array(
        capabilities
            .iter()
            .map(|capability| Value::String(capability.as_str().to_string()))
            .collect(),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IncompatibleControlPlaneDetailsWire {
    operation: ControlPlaneOperation,
    reason: ControlPlaneFailureReason,
    required_capabilities: Vec<ControlPlaneCapability>,
    missing_capabilities: Vec<ControlPlaneCapability>,
}

#[derive(Serialize)]
struct IncompatibleControlPlaneDetailsWireRef<'a> {
    operation: ControlPlaneOperation,
    reason: ControlPlaneFailureReason,
    required_capabilities: &'a [ControlPlaneCapability],
    missing_capabilities: &'a [ControlPlaneCapability],
}

impl TryFrom<IncompatibleControlPlaneDetailsWire> for IncompatibleControlPlaneDetails {
    type Error = IncompatibleControlPlaneDetailsError;

    fn try_from(wire: IncompatibleControlPlaneDetailsWire) -> Result<Self, Self::Error> {
        if wire.required_capabilities != wire.operation.required_capabilities() {
            return Err(IncompatibleControlPlaneDetailsError::RequiredCapabilitiesMismatch);
        }
        Self::new(wire.operation, wire.reason, &wire.missing_capabilities)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum IncompatibleControlPlaneDetailsError {
    #[error("required capabilities do not match the operation")]
    RequiredCapabilitiesMismatch,
    #[error("required_capability_missing needs at least one missing capability")]
    MissingCapabilityRequired,
    #[error("missing capabilities are valid only for required_capability_missing")]
    UnexpectedMissingCapability,
    #[error("a missing capability is not required by the operation")]
    CapabilityNotRequired,
    #[error("a missing capability is duplicated")]
    DuplicateMissingCapability,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ErrorCode, SatelleError};
    use serde_json::json;

    #[test]
    fn operation_requirements_are_exact_and_stable() {
        assert_eq!(
            ControlPlaneOperation::Run.required_capabilities(),
            &[
                ControlPlaneCapability::SessionCreation,
                ControlPlaneCapability::TurnStart,
                ControlPlaneCapability::EventObservation,
            ]
        );
        assert_eq!(
            ControlPlaneOperation::Steer.required_capabilities(),
            &[
                ControlPlaneCapability::Steering,
                ControlPlaneCapability::EventObservation,
            ]
        );
        assert_eq!(
            ControlPlaneOperation::Stop.required_capabilities(),
            [
                ControlPlaneCapability::Cancellation,
                ControlPlaneCapability::EventObservation,
            ]
        );
        assert_eq!(
            ControlPlaneOperation::Status.required_capabilities(),
            [
                ControlPlaneCapability::Status,
                ControlPlaneCapability::Steering,
            ]
        );
    }

    #[test]
    fn details_are_canonical_and_serialize_without_extra_fields() {
        let details = IncompatibleControlPlaneDetails::new(
            ControlPlaneOperation::Run,
            ControlPlaneFailureReason::RequiredCapabilityMissing,
            &[
                ControlPlaneCapability::EventObservation,
                ControlPlaneCapability::SessionCreation,
            ],
        )
        .expect("valid missing capabilities");

        assert_eq!(
            serde_json::to_value(&details).expect("serialize details"),
            json!({
                "operation": "run",
                "reason": "required_capability_missing",
                "required_capabilities": [
                    "session_creation",
                    "turn_start",
                    "event_observation"
                ],
                "missing_capabilities": [
                    "session_creation",
                    "event_observation"
                ]
            })
        );
    }

    #[test]
    fn details_reject_noncanonical_or_inconsistent_values() {
        assert_eq!(
            IncompatibleControlPlaneDetails::new(
                ControlPlaneOperation::Run,
                ControlPlaneFailureReason::RequiredCapabilityMissing,
                &[],
            ),
            Err(IncompatibleControlPlaneDetailsError::MissingCapabilityRequired)
        );
        assert_eq!(
            IncompatibleControlPlaneDetails::new(
                ControlPlaneOperation::Run,
                ControlPlaneFailureReason::SchemaUnavailable,
                &[ControlPlaneCapability::SessionCreation],
            ),
            Err(IncompatibleControlPlaneDetailsError::UnexpectedMissingCapability)
        );
        assert_eq!(
            IncompatibleControlPlaneDetails::new(
                ControlPlaneOperation::Status,
                ControlPlaneFailureReason::RequiredCapabilityMissing,
                &[ControlPlaneCapability::TurnStart],
            ),
            Err(IncompatibleControlPlaneDetailsError::CapabilityNotRequired)
        );
        assert_eq!(
            IncompatibleControlPlaneDetails::new(
                ControlPlaneOperation::Stop,
                ControlPlaneFailureReason::RequiredCapabilityMissing,
                &[
                    ControlPlaneCapability::Cancellation,
                    ControlPlaneCapability::Cancellation,
                ],
            ),
            Err(IncompatibleControlPlaneDetailsError::DuplicateMissingCapability)
        );
    }

    #[test]
    fn deserialization_revalidates_required_fields_and_rejects_unknown_fields() {
        let wrong_requirements = json!({
            "operation": "status",
            "reason": "handshake_unavailable",
            "required_capabilities": ["turn_start"],
            "missing_capabilities": []
        });
        assert!(
            serde_json::from_value::<IncompatibleControlPlaneDetails>(wrong_requirements).is_err()
        );

        let unknown_field = json!({
            "operation": "status",
            "reason": "handshake_unavailable",
            "required_capabilities": ["status", "steering"],
            "missing_capabilities": [],
            "raw_message": "PRIVATE_CANARY"
        });
        assert!(serde_json::from_value::<IncompatibleControlPlaneDetails>(unknown_field).is_err());
    }

    #[test]
    fn public_tokens_and_unavailable_exit_class_are_exact() {
        let operations = [
            (ControlPlaneOperation::Run, "run"),
            (ControlPlaneOperation::Steer, "steer"),
            (ControlPlaneOperation::Stop, "stop"),
            (ControlPlaneOperation::Status, "status"),
        ];
        for (operation, token) in operations {
            assert_eq!(serde_json::to_value(operation).unwrap(), json!(token));
        }

        let capabilities = [
            (ControlPlaneCapability::SessionCreation, "session_creation"),
            (ControlPlaneCapability::TurnStart, "turn_start"),
            (
                ControlPlaneCapability::EventObservation,
                "event_observation",
            ),
            (ControlPlaneCapability::Steering, "steering"),
            (ControlPlaneCapability::Status, "status"),
            (ControlPlaneCapability::Cancellation, "cancellation"),
        ];
        for (capability, token) in capabilities {
            assert_eq!(serde_json::to_value(capability).unwrap(), json!(token));
        }

        let reasons = [
            (ControlPlaneFailureReason::RuntimeMissing, "runtime_missing"),
            (
                ControlPlaneFailureReason::VersionMalformed,
                "version_malformed",
            ),
            (
                ControlPlaneFailureReason::VersionUnavailable,
                "version_unavailable",
            ),
            (
                ControlPlaneFailureReason::VersionUnsupported,
                "version_unsupported",
            ),
            (
                ControlPlaneFailureReason::SchemaUnavailable,
                "schema_unavailable",
            ),
            (
                ControlPlaneFailureReason::HandshakeUnavailable,
                "handshake_unavailable",
            ),
            (
                ControlPlaneFailureReason::RequiredCapabilityMissing,
                "required_capability_missing",
            ),
        ];
        for (reason, token) in reasons {
            assert_eq!(serde_json::to_value(reason).unwrap(), json!(token));
        }

        assert_eq!(
            ErrorCode::IncompatibleControlPlane.as_str(),
            "incompatible-control-plane"
        );
        assert_eq!(ErrorCode::IncompatibleControlPlane.exit_code(), 75);
        assert_eq!(ErrorCode::ComputerUseNotReady.exit_code(), 75);
        assert_eq!(ErrorCode::DoctorReadinessBlockersFound.exit_code(), 75);
    }

    #[test]
    fn satelle_error_contains_only_validated_details_and_exact_recovery() {
        let details = IncompatibleControlPlaneDetails::new(
            ControlPlaneOperation::Steer,
            ControlPlaneFailureReason::HandshakeUnavailable,
            &[],
        )
        .unwrap();

        let error = SatelleError::incompatible_control_plane(details.clone());

        assert_eq!(error.code, ErrorCode::IncompatibleControlPlane);
        assert_eq!(error.exit_code(), 75);
        assert_eq!(
            error.recovery_command.as_deref(),
            Some("satelle doctor --scope codex --refresh --json")
        );
        assert_eq!(error.source_detail, None);
        assert_eq!(
            serde_json::to_value(error.details).unwrap(),
            serde_json::to_value(details).unwrap()
        );
    }
}
