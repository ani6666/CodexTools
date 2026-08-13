use std::fmt;

use serde::{Deserialize, Serialize};

pub const M31_CONTRACT_VERSION: u16 = 1;
pub const COMMAND_DESCRIBE_CONTRACT_V1: &str = "describe_contract_v1";
pub const COMMAND_CANCEL_OPERATION_V1: &str = "cancel_operation_v1";

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct SafeIdentifier(String);

impl SafeIdentifier {
    pub fn parse(value: impl Into<String>) -> Result<Self, IdentifierValidationError> {
        let value = value.into();
        if codex_domain::contains_high_confidence_secret(&value) {
            return Err(IdentifierValidationError);
        }
        let valid_length = (1..=64).contains(&value.len());
        let valid_characters = value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'));
        if valid_length && valid_characters {
            Ok(Self(value))
        } else {
            Err(IdentifierValidationError)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SafeIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SafeIdentifier")
            .field(&self.0)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentifierValidationError;

impl fmt::Display for IdentifierValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("identifier is invalid")
    }
}

impl std::error::Error for IdentifierValidationError {}

impl<'de> Deserialize<'de> for SafeIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DescribeContractRequest {
    pub schema_version: u16,
    pub correlation_id: SafeIdentifier,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommandNamesDto {
    pub describe_contract: String,
    pub cancel_operation: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EventNamesDto {
    pub operation_status: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractCapabilitiesDto {
    pub accepts_secret_material: bool,
    pub accesses_live_codex_state: bool,
    pub performs_network_requests: bool,
    pub supports_cancellation_contract: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DescribeContractResponse {
    pub schema_version: u16,
    pub correlation_id: SafeIdentifier,
    pub commands: CommandNamesDto,
    pub events: EventNamesDto,
    pub capabilities: ContractCapabilitiesDto,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CancelOperationRequest {
    pub schema_version: u16,
    pub operation_id: SafeIdentifier,
    pub correlation_id: SafeIdentifier,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CancelOperationResponse {
    pub schema_version: u16,
    pub operation_id: SafeIdentifier,
    pub correlation_id: SafeIdentifier,
    pub outcome: crate::application_facade::CancellationOutcome,
}
