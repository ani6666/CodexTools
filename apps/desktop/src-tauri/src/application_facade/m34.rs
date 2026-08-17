use serde::{Deserialize, Serialize};

use super::{
    ApplicationFacade, ErrorCode, ErrorEnvelope, IdentitySummaryDto, ModelPresetSummaryDto,
    OperationStage, OperationStatus, OperationStatusEvent, SafeIdentifier,
};

pub const M34_CONTRACT_VERSION: u16 = 1;
pub const COMMAND_PREVIEW_SWITCH_V1: &str = "preview_switch_v1";
pub const COMMAND_EXECUTE_SWITCH_V1: &str = "execute_switch_v1";
pub const COMMAND_QUERY_SWITCH_OPERATION_V1: &str = "query_switch_operation_v1";
pub const COMMAND_LIST_SWITCH_RECOVERIES_V1: &str = "list_switch_recoveries_v1";
pub const COMMAND_RECOVER_SWITCH_V1: &str = "recover_switch_v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SwitchCompatibilityDto {
    Ready,
    CompatibilityProtected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SwitchAffectedCategoryDto {
    Configuration,
    Authentication,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SwitchExecutionStatusDto {
    Applied,
    AlreadyApplied,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SwitchOperationStateDto {
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SwitchPreviewDto {
    pub plan_id: SafeIdentifier,
    pub plan_version: u64,
    pub operation_id: SafeIdentifier,
    pub identity: IdentitySummaryDto,
    pub preset: ModelPresetSummaryDto,
    pub affected_categories: Vec<SwitchAffectedCategoryDto>,
    pub affected_items: u64,
    pub warning_codes: Vec<SafeIdentifier>,
    pub compatibility: SwitchCompatibilityDto,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewSwitchRequest {
    pub schema_version: u16,
    pub correlation_id: SafeIdentifier,
    pub identity_id: SafeIdentifier,
    pub expected_identity_version: u64,
    pub preset_id: SafeIdentifier,
    pub expected_preset_version: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreviewSwitchResponse {
    pub schema_version: u16,
    pub correlation_id: SafeIdentifier,
    pub preview: SwitchPreviewDto,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteSwitchRequest {
    pub schema_version: u16,
    pub correlation_id: SafeIdentifier,
    pub plan_id: SafeIdentifier,
    pub expected_plan_version: u64,
    pub operation_id: SafeIdentifier,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SwitchOperationDto {
    pub operation_id: SafeIdentifier,
    pub state: SwitchOperationStateDto,
    pub completed_items: u64,
    pub total_items: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecuteSwitchResponse {
    pub schema_version: u16,
    pub correlation_id: SafeIdentifier,
    pub status: SwitchExecutionStatusDto,
    pub operation: SwitchOperationDto,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QuerySwitchOperationRequest {
    pub schema_version: u16,
    pub correlation_id: SafeIdentifier,
    pub operation_id: SafeIdentifier,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuerySwitchOperationResponse {
    pub schema_version: u16,
    pub correlation_id: SafeIdentifier,
    pub operation: SwitchOperationDto,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListSwitchRecoveriesRequest {
    pub schema_version: u16,
    pub correlation_id: SafeIdentifier,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SwitchRecoverySummaryDto {
    pub recovery_id: SafeIdentifier,
    pub state: SwitchOperationStateDto,
    pub affected_items: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListSwitchRecoveriesResponse {
    pub schema_version: u16,
    pub correlation_id: SafeIdentifier,
    pub recoveries: Vec<SwitchRecoverySummaryDto>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverSwitchRequest {
    pub schema_version: u16,
    pub correlation_id: SafeIdentifier,
    pub operation_id: SafeIdentifier,
    pub recovery_id: SafeIdentifier,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecoverSwitchResponse {
    pub schema_version: u16,
    pub correlation_id: SafeIdentifier,
    pub operation: SwitchOperationDto,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum M34BackendError {
    Validation,
    NotFound,
    Conflict,
    PlanStale,
    CompatibilityProtected,
    RecoveryRequired,
    Unavailable,
    Internal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendSwitchPreview {
    pub plan_id: String,
    pub plan_version: u64,
    pub operation_id: String,
    pub identity: IdentitySummaryDto,
    pub preset: ModelPresetSummaryDto,
    pub affected_items: u64,
    pub compatibility: SwitchCompatibilityDto,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendSwitchOperation {
    pub operation_id: String,
    pub state: SwitchOperationStateDto,
    pub completed_items: u64,
    pub total_items: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendSwitchExecution {
    pub status: SwitchExecutionStatusDto,
    pub operation: BackendSwitchOperation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendRecoverySummary {
    pub recovery_id: String,
    pub affected_items: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendRecoveryResult {
    pub operation: BackendSwitchOperation,
}

pub trait M34Backend: Send + Sync {
    fn preview_switch(
        &self,
        _request: &PreviewSwitchRequest,
    ) -> Result<BackendSwitchPreview, M34BackendError> {
        Err(M34BackendError::Unavailable)
    }
    fn validate_switch(
        &self,
        _plan_id: &str,
        _expected_plan_version: u64,
        _operation_id: &str,
    ) -> Result<(), M34BackendError> {
        Err(M34BackendError::Unavailable)
    }
    fn execute_switch(
        &self,
        _plan_id: &str,
        _expected_plan_version: u64,
        _operation_id: &str,
    ) -> Result<BackendSwitchExecution, M34BackendError> {
        Err(M34BackendError::Unavailable)
    }
    fn query_switch(&self, _operation_id: &str) -> Result<BackendSwitchOperation, M34BackendError> {
        Err(M34BackendError::Unavailable)
    }
    fn list_recoveries(&self) -> Result<Vec<BackendRecoverySummary>, M34BackendError> {
        Err(M34BackendError::Unavailable)
    }
    fn recover_switch(&self, _recovery_id: &str) -> Result<BackendRecoveryResult, M34BackendError> {
        Err(M34BackendError::Unavailable)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableM34Backend;
impl M34Backend for UnavailableM34Backend {}

impl ApplicationFacade {
    pub fn preview_switch(
        &self,
        request: PreviewSwitchRequest,
    ) -> Result<PreviewSwitchResponse, ErrorEnvelope> {
        ensure_m34_version(request.schema_version)?;
        let backend = self.m34.preview_switch(&request)?;
        let preview = SwitchPreviewDto {
            plan_id: parse_backend_identifier(&backend.plan_id)?,
            plan_version: backend.plan_version,
            operation_id: parse_backend_identifier(&backend.operation_id)?,
            identity: backend.identity,
            preset: backend.preset,
            affected_categories: vec![
                SwitchAffectedCategoryDto::Configuration,
                SwitchAffectedCategoryDto::Authentication,
            ],
            affected_items: backend.affected_items,
            warning_codes: vec![
                SafeIdentifier::parse("local-state-changes")
                    .map_err(|_| ErrorEnvelope::from_code(ErrorCode::Internal))?,
                SafeIdentifier::parse("cancellation-ends-at-critical")
                    .map_err(|_| ErrorEnvelope::from_code(ErrorCode::Internal))?,
            ],
            compatibility: backend.compatibility,
        };
        Ok(PreviewSwitchResponse {
            schema_version: M34_CONTRACT_VERSION,
            correlation_id: request.correlation_id,
            preview,
        })
    }

    pub fn execute_switch(
        &self,
        request: ExecuteSwitchRequest,
    ) -> Result<ExecuteSwitchResponse, ErrorEnvelope> {
        ensure_m34_version(request.schema_version)?;
        self.register_operation(request.operation_id.clone(), request.correlation_id.clone())?;
        if let Err(error) = self.publish_required(&request, OperationStage::Queued) {
            self.finish_and_release(&request, OperationStage::Failed, OperationStatus::Failed);
            return Err(error);
        }
        if let Err(error) = self.cancellation_checkpoint(&request.operation_id) {
            self.finish_and_release(
                &request,
                OperationStage::Cancelled,
                OperationStatus::Cancelled,
            );
            return Err(error);
        }
        if let Err(error) = self.publish_required(&request, OperationStage::Preparing) {
            self.finish_and_release(&request, OperationStage::Failed, OperationStatus::Failed);
            return Err(error);
        }
        if let Err(error) = self.m34.validate_switch(
            request.plan_id.as_str(),
            request.expected_plan_version,
            request.operation_id.as_str(),
        ) {
            self.finish_and_release(&request, stage_for_error(error), status_for_error(error));
            return Err(error.into());
        }
        if let Err(error) = self.publish_required(&request, OperationStage::Validated) {
            self.finish_and_release(&request, OperationStage::Failed, OperationStatus::Failed);
            return Err(error);
        }
        if let Err(error) = self.cancellation_checkpoint(&request.operation_id) {
            self.finish_and_release(
                &request,
                OperationStage::Cancelled,
                OperationStatus::Cancelled,
            );
            return Err(error);
        }
        if let Err(error) = self.enter_non_cancellable(&request.operation_id) {
            self.finish_and_release(
                &request,
                OperationStage::Cancelled,
                OperationStatus::Cancelled,
            );
            return Err(error);
        }
        self.publish_best_effort(
            &request,
            OperationStage::EnteringCritical,
            OperationStatus::Running,
        );
        self.publish_best_effort(
            &request,
            OperationStage::Committing,
            OperationStatus::Running,
        );
        match self.m34.execute_switch(
            request.plan_id.as_str(),
            request.expected_plan_version,
            request.operation_id.as_str(),
        ) {
            Ok(result) => {
                self.finish_and_release(
                    &request,
                    OperationStage::Completed,
                    OperationStatus::Succeeded,
                );
                Ok(ExecuteSwitchResponse {
                    schema_version: M34_CONTRACT_VERSION,
                    correlation_id: request.correlation_id,
                    status: result.status,
                    operation: operation_dto(result.operation)?,
                })
            }
            Err(error) => {
                self.finish_and_release(&request, stage_for_error(error), status_for_error(error));
                Err(error.into())
            }
        }
    }

    pub fn query_switch_operation(
        &self,
        request: QuerySwitchOperationRequest,
    ) -> Result<QuerySwitchOperationResponse, ErrorEnvelope> {
        ensure_m34_version(request.schema_version)?;
        Ok(QuerySwitchOperationResponse {
            schema_version: M34_CONTRACT_VERSION,
            correlation_id: request.correlation_id,
            operation: operation_dto(self.m34.query_switch(request.operation_id.as_str())?)?,
        })
    }

    pub fn list_switch_recoveries(
        &self,
        request: ListSwitchRecoveriesRequest,
    ) -> Result<ListSwitchRecoveriesResponse, ErrorEnvelope> {
        ensure_m34_version(request.schema_version)?;
        let recoveries = self
            .m34
            .list_recoveries()?
            .into_iter()
            .map(|item| {
                Ok(SwitchRecoverySummaryDto {
                    recovery_id: parse_backend_identifier(&item.recovery_id)?,
                    state: SwitchOperationStateDto::RecoveryRequired,
                    affected_items: item.affected_items,
                })
            })
            .collect::<Result<Vec<_>, ErrorEnvelope>>()?;
        Ok(ListSwitchRecoveriesResponse {
            schema_version: M34_CONTRACT_VERSION,
            correlation_id: request.correlation_id,
            recoveries,
        })
    }

    pub fn recover_switch(
        &self,
        request: RecoverSwitchRequest,
    ) -> Result<RecoverSwitchResponse, ErrorEnvelope> {
        ensure_m34_version(request.schema_version)?;
        self.register_operation(request.operation_id.clone(), request.correlation_id.clone())?;
        self.cancellation_checkpoint(&request.operation_id)?;
        if let Err(error) = self.enter_non_cancellable(&request.operation_id) {
            let _ = self.complete_operation(&request.operation_id);
            let _ = self.release_completed_operation(&request.operation_id);
            return Err(error);
        }
        self.publish_best_effort_recovery(
            &request,
            OperationStage::EnteringCritical,
            OperationStatus::Running,
        );
        match self.m34.recover_switch(request.recovery_id.as_str()) {
            Ok(result) => {
                self.finish_and_release_recovery(
                    &request,
                    OperationStage::Completed,
                    OperationStatus::Succeeded,
                );
                Ok(RecoverSwitchResponse {
                    schema_version: M34_CONTRACT_VERSION,
                    correlation_id: request.correlation_id,
                    operation: operation_dto(result.operation)?,
                })
            }
            Err(error) => {
                self.finish_and_release_recovery(
                    &request,
                    stage_for_error(error),
                    status_for_error(error),
                );
                Err(error.into())
            }
        }
    }

    fn publish_required(
        &self,
        request: &ExecuteSwitchRequest,
        stage: OperationStage,
    ) -> Result<(), ErrorEnvelope> {
        self.events
            .publish(&OperationStatusEvent::progress(
                request.operation_id.clone(),
                request.correlation_id.clone(),
                stage,
                OperationStatus::Running,
                0,
                Some(2),
            ))
            .map_err(|_| ErrorEnvelope::from_code(ErrorCode::Unavailable))
    }

    fn publish_best_effort(
        &self,
        request: &ExecuteSwitchRequest,
        stage: OperationStage,
        status: OperationStatus,
    ) {
        let _ = self.events.publish(&OperationStatusEvent::progress(
            request.operation_id.clone(),
            request.correlation_id.clone(),
            stage,
            status,
            u64::from(matches!(stage, OperationStage::Completed)),
            Some(2),
        ));
    }

    fn finish_and_release(
        &self,
        request: &ExecuteSwitchRequest,
        stage: OperationStage,
        status: OperationStatus,
    ) {
        let _ = self.complete_operation(&request.operation_id);
        self.publish_best_effort(request, stage, status);
        let _ = self.release_completed_operation(&request.operation_id);
    }

    fn publish_best_effort_recovery(
        &self,
        request: &RecoverSwitchRequest,
        stage: OperationStage,
        status: OperationStatus,
    ) {
        let _ = self.events.publish(&OperationStatusEvent::progress(
            request.operation_id.clone(),
            request.correlation_id.clone(),
            stage,
            status,
            0,
            Some(1),
        ));
    }

    fn finish_and_release_recovery(
        &self,
        request: &RecoverSwitchRequest,
        stage: OperationStage,
        status: OperationStatus,
    ) {
        let _ = self.complete_operation(&request.operation_id);
        self.publish_best_effort_recovery(request, stage, status);
        let _ = self.release_completed_operation(&request.operation_id);
    }
}

fn ensure_m34_version(version: u16) -> Result<(), ErrorEnvelope> {
    if version == M34_CONTRACT_VERSION {
        Ok(())
    } else {
        Err(ErrorEnvelope::from_code(ErrorCode::Validation))
    }
}

fn parse_backend_identifier(value: &str) -> Result<SafeIdentifier, ErrorEnvelope> {
    SafeIdentifier::parse(value).map_err(|_| ErrorEnvelope::from_code(ErrorCode::Internal))
}

fn operation_dto(value: BackendSwitchOperation) -> Result<SwitchOperationDto, ErrorEnvelope> {
    Ok(SwitchOperationDto {
        operation_id: parse_backend_identifier(&value.operation_id)?,
        state: value.state,
        completed_items: value.completed_items,
        total_items: value.total_items,
    })
}

const fn stage_for_error(error: M34BackendError) -> OperationStage {
    match error {
        M34BackendError::Conflict | M34BackendError::PlanStale => OperationStage::Conflict,
        M34BackendError::RecoveryRequired => OperationStage::RecoveryRequired,
        _ => OperationStage::Failed,
    }
}

const fn status_for_error(error: M34BackendError) -> OperationStatus {
    match error {
        M34BackendError::Conflict | M34BackendError::PlanStale => OperationStatus::Failed,
        M34BackendError::RecoveryRequired => OperationStatus::Failed,
        _ => OperationStatus::Failed,
    }
}
