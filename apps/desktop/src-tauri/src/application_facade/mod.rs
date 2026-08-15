mod cancellation;
mod contract;
mod error;
mod events;
mod m33;
mod m34;

use std::sync::{Arc, Mutex};

pub use cancellation::{
    CancellationCheckpoint, CancellationOutcome, OperationRegistrationError, OperationRegistry,
};
pub use contract::{
    COMMAND_CANCEL_OPERATION_V1, COMMAND_DESCRIBE_CONTRACT_V1, CancelOperationRequest,
    CancelOperationResponse, CommandNamesDto, ContractCapabilitiesDto, DescribeContractRequest,
    DescribeContractResponse, EventNamesDto, IdentifierValidationError, M31_CONTRACT_VERSION,
    SafeIdentifier,
};
pub use error::{ErrorCode, ErrorEnvelope};
pub use events::{
    EVENT_OPERATION_STATUS_V1, EventSink, EventSinkError, NoopEventSink, OperationStage,
    OperationStatus, OperationStatusEvent,
};
pub use m33::*;
pub use m34::*;

pub struct ApplicationFacade {
    operations: Arc<Mutex<OperationRegistry>>,
    events: Arc<dyn EventSink>,
    m33: Arc<dyn M33Backend>,
    m34: Arc<dyn M34Backend>,
}

impl Clone for ApplicationFacade {
    fn clone(&self) -> Self {
        Self {
            operations: Arc::clone(&self.operations),
            events: Arc::clone(&self.events),
            m33: Arc::clone(&self.m33),
            m34: Arc::clone(&self.m34),
        }
    }
}

impl fmt::Debug for ApplicationFacade {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApplicationFacade")
            .field("operations", &"[NON_SECRET_REGISTRY]")
            .field("events", &"[EVENT_SINK]")
            .finish()
    }
}

use std::fmt;

impl Default for ApplicationFacade {
    fn default() -> Self {
        Self::new(Arc::new(NoopEventSink))
    }
}

impl ApplicationFacade {
    #[must_use]
    pub fn new(events: Arc<dyn EventSink>) -> Self {
        Self::with_backends(
            events,
            Arc::new(UnavailableM33Backend),
            Arc::new(UnavailableM34Backend),
        )
    }

    #[must_use]
    pub fn with_backend(events: Arc<dyn EventSink>, m33: Arc<dyn M33Backend>) -> Self {
        Self::with_backends(events, m33, Arc::new(UnavailableM34Backend))
    }

    #[must_use]
    pub fn with_backends(
        events: Arc<dyn EventSink>,
        m33: Arc<dyn M33Backend>,
        m34: Arc<dyn M34Backend>,
    ) -> Self {
        Self {
            operations: Arc::new(Mutex::new(OperationRegistry::default())),
            events,
            m33,
            m34,
        }
    }

    pub fn describe_contract(
        &self,
        request: DescribeContractRequest,
    ) -> Result<DescribeContractResponse, ErrorEnvelope> {
        ensure_version(request.schema_version)?;
        Ok(DescribeContractResponse {
            schema_version: M31_CONTRACT_VERSION,
            correlation_id: request.correlation_id,
            commands: CommandNamesDto {
                describe_contract: COMMAND_DESCRIBE_CONTRACT_V1.to_owned(),
                cancel_operation: COMMAND_CANCEL_OPERATION_V1.to_owned(),
            },
            events: EventNamesDto {
                operation_status: EVENT_OPERATION_STATUS_V1.to_owned(),
            },
            capabilities: ContractCapabilitiesDto {
                accepts_secret_material: false,
                accesses_live_codex_state: false,
                performs_network_requests: false,
                supports_cancellation_contract: true,
            },
        })
    }

    pub fn cancel_operation(
        &self,
        request: CancelOperationRequest,
    ) -> Result<CancelOperationResponse, ErrorEnvelope> {
        ensure_version(request.schema_version)?;
        let outcome = self
            .operations
            .lock()
            .map_err(|_| ErrorEnvelope::from_code(ErrorCode::Internal))?
            .cancel(&request.operation_id);
        Ok(CancelOperationResponse {
            schema_version: M31_CONTRACT_VERSION,
            operation_id: request.operation_id,
            correlation_id: request.correlation_id,
            outcome,
        })
    }

    pub fn register_operation(
        &self,
        operation_id: SafeIdentifier,
        correlation_id: SafeIdentifier,
    ) -> Result<(), ErrorEnvelope> {
        self.operations
            .lock()
            .map_err(|_| ErrorEnvelope::from_code(ErrorCode::Internal))?
            .register(operation_id.clone())
            .map_err(|_| ErrorEnvelope::from_code(ErrorCode::Conflict))?;
        let event = OperationStatusEvent::accepted(operation_id.clone(), correlation_id);
        if self.events.publish(&event).is_err() {
            let rolled_back = self
                .operations
                .lock()
                .map_err(|_| ErrorEnvelope::from_code(ErrorCode::Internal))?
                .rollback_registration(&operation_id);
            return Err(ErrorEnvelope::from_code(if rolled_back {
                ErrorCode::Unavailable
            } else {
                ErrorCode::RecoveryRequired
            }));
        }
        Ok(())
    }

    pub fn cancellation_checkpoint(
        &self,
        operation_id: &SafeIdentifier,
    ) -> Result<(), ErrorEnvelope> {
        let checkpoint = self
            .operations
            .lock()
            .map_err(|_| ErrorEnvelope::from_code(ErrorCode::Internal))?
            .checkpoint(operation_id);
        match checkpoint {
            CancellationCheckpoint::Continue => Ok(()),
            CancellationCheckpoint::Cancelled => {
                Err(ErrorEnvelope::from_code(ErrorCode::Cancelled))
            }
        }
    }

    /// 必须在调用 M2 原子执行入口前进入；成功后取消只能得到 `too_late`。
    pub fn enter_non_cancellable(
        &self,
        operation_id: &SafeIdentifier,
    ) -> Result<(), ErrorEnvelope> {
        self.operations
            .lock()
            .map_err(|_| ErrorEnvelope::from_code(ErrorCode::Internal))?
            .enter_non_cancellable(operation_id)
            .map_err(|checkpoint| match checkpoint {
                CancellationCheckpoint::Cancelled => ErrorEnvelope::from_code(ErrorCode::Cancelled),
                CancellationCheckpoint::Continue => ErrorEnvelope::from_code(ErrorCode::Conflict),
            })
    }

    pub fn complete_operation(&self, operation_id: &SafeIdentifier) -> Result<(), ErrorEnvelope> {
        let completed = self
            .operations
            .lock()
            .map_err(|_| ErrorEnvelope::from_code(ErrorCode::Internal))?
            .complete(operation_id);
        if completed {
            Ok(())
        } else {
            Err(ErrorEnvelope::from_code(ErrorCode::NotFound))
        }
    }

    pub fn operation_count(&self) -> Result<usize, ErrorEnvelope> {
        Ok(self
            .operations
            .lock()
            .map_err(|_| ErrorEnvelope::from_code(ErrorCode::Internal))?
            .len())
    }

    pub fn release_completed_operation(
        &self,
        operation_id: &SafeIdentifier,
    ) -> Result<(), ErrorEnvelope> {
        let removed = self
            .operations
            .lock()
            .map_err(|_| ErrorEnvelope::from_code(ErrorCode::Internal))?
            .remove_completed(operation_id);
        if removed {
            Ok(())
        } else {
            Err(ErrorEnvelope::from_code(ErrorCode::Conflict))
        }
    }
}

fn ensure_version(version: u16) -> Result<(), ErrorEnvelope> {
    if version == M31_CONTRACT_VERSION {
        Ok(())
    } else {
        Err(ErrorEnvelope::from_code(ErrorCode::Validation))
    }
}
