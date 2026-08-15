use std::fmt;

use serde::{Deserialize, Serialize};

use super::{M31_CONTRACT_VERSION, SafeIdentifier};

pub const EVENT_OPERATION_STATUS_V1: &str = "codextools://operation-status/v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStage {
    Accepted,
    AwaitingApproval,
    ExecutingAtomic,
    Verifying,
    Queued,
    Preparing,
    Validated,
    EnteringCritical,
    Committing,
    Completed,
    Cancelled,
    Conflict,
    RecoveryRequired,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperationStatusEvent {
    pub schema_version: u16,
    pub operation_id: SafeIdentifier,
    pub correlation_id: SafeIdentifier,
    pub stage: OperationStage,
    pub status: OperationStatus,
    pub completed_items: u64,
    pub total_items: Option<u64>,
    pub summary_code: Option<SafeIdentifier>,
}

impl OperationStatusEvent {
    #[must_use]
    pub fn accepted(operation_id: SafeIdentifier, correlation_id: SafeIdentifier) -> Self {
        Self {
            schema_version: M31_CONTRACT_VERSION,
            operation_id,
            correlation_id,
            stage: OperationStage::Accepted,
            status: OperationStatus::Running,
            completed_items: 0,
            total_items: None,
            summary_code: None,
        }
    }

    #[must_use]
    pub fn finished(
        operation_id: SafeIdentifier,
        correlation_id: SafeIdentifier,
        succeeded: bool,
        summary_code: SafeIdentifier,
    ) -> Self {
        Self {
            schema_version: M31_CONTRACT_VERSION,
            operation_id,
            correlation_id,
            stage: OperationStage::Completed,
            status: if succeeded {
                OperationStatus::Succeeded
            } else {
                OperationStatus::Failed
            },
            completed_items: u64::from(succeeded),
            total_items: Some(1),
            summary_code: Some(summary_code),
        }
    }

    #[must_use]
    pub fn progress(
        operation_id: SafeIdentifier,
        correlation_id: SafeIdentifier,
        stage: OperationStage,
        status: OperationStatus,
        completed_items: u64,
        total_items: Option<u64>,
    ) -> Self {
        Self {
            schema_version: M31_CONTRACT_VERSION,
            operation_id,
            correlation_id,
            stage,
            status,
            completed_items,
            total_items,
            summary_code: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventSinkError;

impl fmt::Display for EventSinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("event delivery is unavailable")
    }
}

impl std::error::Error for EventSinkError {}

pub trait EventSink: Send + Sync {
    fn publish(&self, event: &OperationStatusEvent) -> Result<(), EventSinkError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoopEventSink;

impl EventSink for NoopEventSink {
    fn publish(&self, _event: &OperationStatusEvent) -> Result<(), EventSinkError> {
        Ok(())
    }
}
