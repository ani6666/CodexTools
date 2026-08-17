use std::fmt;

use codex_domain::{EntityName, ModelId, ModelPreset};
use serde::{Deserialize, Serialize};

use super::{ApplicationFacade, ErrorCode, ErrorEnvelope, OperationStatusEvent, SafeIdentifier};

pub const M33_CONTRACT_VERSION: u16 = 1;
pub const COMMAND_SCAN_DEFAULT_CODEX_V1: &str = "scan_default_codex_v1";
pub const COMMAND_IMPORT_CANDIDATE_V1: &str = "import_candidate_v1";
pub const COMMAND_LIST_IDENTITIES_V1: &str = "list_identities_v1";
pub const COMMAND_RENAME_IDENTITY_V1: &str = "rename_identity_v1";
pub const COMMAND_LIST_PRESETS_V1: &str = "list_presets_v1";
pub const COMMAND_CREATE_PRESET_AND_BIND_V1: &str = "create_preset_and_bind_v1";
pub const COMMAND_UPDATE_PRESET_AND_BIND_V1: &str = "update_preset_and_bind_v1";

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ManagedNameDto(String);

impl ManagedNameDto {
    fn parse(value: String) -> Result<Self, &'static str> {
        let name = EntityName::parse(&value).map_err(|_| "managed name is invalid")?;
        let model = ModelId::parse("safe-model").map_err(|_| "managed name is invalid")?;
        ModelPreset::validate_managed_metadata(&name, &model)
            .map_err(|_| "managed name is invalid")?;
        Ok(Self(name.as_str().to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ManagedNameDto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ManagedNameDto([VALIDATED])")
    }
}

impl<'de> Deserialize<'de> for ManagedNameDto {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ManagedModelIdDto(String);

impl ManagedModelIdDto {
    fn parse(value: String) -> Result<Self, &'static str> {
        let name = EntityName::parse("安全预设").map_err(|_| "managed model is invalid")?;
        let model = ModelId::parse(&value).map_err(|_| "managed model is invalid")?;
        ModelPreset::validate_managed_metadata(&name, &model)
            .map_err(|_| "managed model is invalid")?;
        Ok(Self(model.as_str().to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ManagedModelIdDto {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ManagedModelIdDto([VALIDATED])")
    }
}

impl<'de> Deserialize<'de> for ManagedModelIdDto {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlledRootDto {
    DefaultCodex,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthModeDto {
    ApiKey,
    OAuth,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStateDto {
    Idle,
    Scanning,
    NotFound,
    Candidate,
    Duplicate,
    CompatibilityProtected,
    Conflict,
    RecoveryRequired,
    Error,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanCandidateDto {
    pub scan_id: String,
    pub auth_mode: AuthModeDto,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanDefaultCodexResponse {
    pub schema_version: u16,
    pub correlation_id: SafeIdentifier,
    pub status: ScanStateDto,
    pub candidate: Option<ScanCandidateDto>,
    pub existing_identity_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScanDefaultCodexRequest {
    pub schema_version: u16,
    pub correlation_id: SafeIdentifier,
    pub root: ControlledRootDto,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImportCandidateRequest {
    pub schema_version: u16,
    pub operation_id: SafeIdentifier,
    pub correlation_id: SafeIdentifier,
    pub root: ControlledRootDto,
    pub scan_id: SafeIdentifier,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportStatusDto {
    Imported,
    Duplicate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ImportCandidateResponse {
    pub schema_version: u16,
    pub operation_id: SafeIdentifier,
    pub correlation_id: SafeIdentifier,
    pub status: ImportStatusDto,
    pub identity_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListIdentitiesRequest {
    pub schema_version: u16,
    pub correlation_id: SafeIdentifier,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IdentitySummaryDto {
    pub identity_id: String,
    pub credential_ref_id: String,
    pub name: String,
    pub provider_name: String,
    pub auth_mode: AuthModeDto,
    pub status: String,
    pub default_preset_id: Option<String>,
    pub version: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListIdentitiesResponse {
    pub schema_version: u16,
    pub correlation_id: SafeIdentifier,
    pub identities: Vec<IdentitySummaryDto>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RenameIdentityRequest {
    pub schema_version: u16,
    pub correlation_id: SafeIdentifier,
    pub identity_id: SafeIdentifier,
    pub expected_version: u64,
    pub name: ManagedNameDto,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RenameIdentityResponse {
    pub schema_version: u16,
    pub correlation_id: SafeIdentifier,
    pub identity: IdentitySummaryDto,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListPresetsRequest {
    pub schema_version: u16,
    pub correlation_id: SafeIdentifier,
    pub identity_id: SafeIdentifier,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ModelPresetSummaryDto {
    pub preset_id: String,
    pub name: String,
    pub model_id: String,
    pub version: u64,
    pub is_default: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListPresetsResponse {
    pub schema_version: u16,
    pub correlation_id: SafeIdentifier,
    pub presets: Vec<ModelPresetSummaryDto>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePresetAndBindRequest {
    pub schema_version: u16,
    pub operation_id: SafeIdentifier,
    pub correlation_id: SafeIdentifier,
    pub identity_id: SafeIdentifier,
    pub expected_identity_version: u64,
    pub preset_id: SafeIdentifier,
    pub name: ManagedNameDto,
    pub model_id: ManagedModelIdDto,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdatePresetAndBindRequest {
    pub schema_version: u16,
    pub operation_id: SafeIdentifier,
    pub correlation_id: SafeIdentifier,
    pub identity_id: SafeIdentifier,
    pub expected_identity_version: u64,
    pub preset_id: SafeIdentifier,
    pub expected_preset_version: u64,
    pub name: ManagedNameDto,
    pub model_id: ManagedModelIdDto,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PresetBindingResponse {
    pub schema_version: u16,
    pub operation_id: SafeIdentifier,
    pub correlation_id: SafeIdentifier,
    pub identity_version: u64,
    pub preset: ModelPresetSummaryDto,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum M33BackendError {
    Validation,
    NotFound,
    Conflict,
    CompatibilityProtected,
    RecoveryRequired,
    Unavailable,
    Internal,
}

pub trait M33Backend: Send + Sync {
    fn scan_default_codex(&self) -> Result<BackendScanResult, M33BackendError>;
    fn import_candidate(&self, scan_id: &str) -> Result<BackendImportResult, M33BackendError>;
    fn list_identities(&self) -> Result<Vec<IdentitySummaryDto>, M33BackendError>;
    fn rename_identity(
        &self,
        identity_id: &str,
        expected_version: u64,
        name: &str,
    ) -> Result<IdentitySummaryDto, M33BackendError>;
    fn list_presets(
        &self,
        identity_id: &str,
    ) -> Result<Vec<ModelPresetSummaryDto>, M33BackendError>;
    fn create_preset_and_bind(
        &self,
        request: &CreatePresetAndBindRequest,
    ) -> Result<BackendPresetResult, M33BackendError>;
    fn update_preset_and_bind(
        &self,
        request: &UpdatePresetAndBindRequest,
    ) -> Result<BackendPresetResult, M33BackendError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendScanResult {
    pub status: ScanStateDto,
    pub candidate: Option<ScanCandidateDto>,
    pub existing_identity_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendImportResult {
    pub status: ImportStatusDto,
    pub identity_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendPresetResult {
    pub identity_version: u64,
    pub preset: ModelPresetSummaryDto,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableM33Backend;

impl M33Backend for UnavailableM33Backend {
    fn scan_default_codex(&self) -> Result<BackendScanResult, M33BackendError> {
        Err(M33BackendError::Unavailable)
    }
    fn import_candidate(&self, _: &str) -> Result<BackendImportResult, M33BackendError> {
        Err(M33BackendError::Unavailable)
    }
    fn list_identities(&self) -> Result<Vec<IdentitySummaryDto>, M33BackendError> {
        Err(M33BackendError::Unavailable)
    }
    fn rename_identity(
        &self,
        _: &str,
        _: u64,
        _: &str,
    ) -> Result<IdentitySummaryDto, M33BackendError> {
        Err(M33BackendError::Unavailable)
    }
    fn list_presets(&self, _: &str) -> Result<Vec<ModelPresetSummaryDto>, M33BackendError> {
        Err(M33BackendError::Unavailable)
    }
    fn create_preset_and_bind(
        &self,
        _: &CreatePresetAndBindRequest,
    ) -> Result<BackendPresetResult, M33BackendError> {
        Err(M33BackendError::Unavailable)
    }
    fn update_preset_and_bind(
        &self,
        _: &UpdatePresetAndBindRequest,
    ) -> Result<BackendPresetResult, M33BackendError> {
        Err(M33BackendError::Unavailable)
    }
}

impl ApplicationFacade {
    pub fn scan_default_codex(
        &self,
        request: ScanDefaultCodexRequest,
    ) -> Result<ScanDefaultCodexResponse, ErrorEnvelope> {
        ensure_m33_version(request.schema_version)?;
        let result = self.m33.scan_default_codex()?;
        Ok(ScanDefaultCodexResponse {
            schema_version: M33_CONTRACT_VERSION,
            correlation_id: request.correlation_id,
            status: result.status,
            candidate: result.candidate,
            existing_identity_id: result.existing_identity_id,
        })
    }

    pub fn import_candidate(
        &self,
        request: ImportCandidateRequest,
    ) -> Result<ImportCandidateResponse, ErrorEnvelope> {
        ensure_m33_version(request.schema_version)?;
        self.register_operation(request.operation_id.clone(), request.correlation_id.clone())?;
        self.cancellation_checkpoint(&request.operation_id)?;
        self.enter_non_cancellable(&request.operation_id)?;
        match self.m33.import_candidate(request.scan_id.as_str()) {
            Ok(result) => {
                self.complete_and_publish(
                    &request.operation_id,
                    &request.correlation_id,
                    true,
                    "import_completed",
                )?;
                Ok(ImportCandidateResponse {
                    schema_version: M33_CONTRACT_VERSION,
                    operation_id: request.operation_id,
                    correlation_id: request.correlation_id,
                    status: result.status,
                    identity_id: result.identity_id,
                })
            }
            Err(error) => {
                self.fail_and_release(
                    &request.operation_id,
                    &request.correlation_id,
                    "import_failed",
                );
                Err(error.into())
            }
        }
    }

    pub fn list_identities(
        &self,
        request: ListIdentitiesRequest,
    ) -> Result<ListIdentitiesResponse, ErrorEnvelope> {
        ensure_m33_version(request.schema_version)?;
        Ok(ListIdentitiesResponse {
            schema_version: M33_CONTRACT_VERSION,
            correlation_id: request.correlation_id,
            identities: self.m33.list_identities()?,
        })
    }

    pub fn rename_identity(
        &self,
        request: RenameIdentityRequest,
    ) -> Result<RenameIdentityResponse, ErrorEnvelope> {
        ensure_m33_version(request.schema_version)?;
        let identity = self.m33.rename_identity(
            request.identity_id.as_str(),
            request.expected_version,
            request.name.as_str(),
        )?;
        Ok(RenameIdentityResponse {
            schema_version: M33_CONTRACT_VERSION,
            correlation_id: request.correlation_id,
            identity,
        })
    }

    pub fn list_presets(
        &self,
        request: ListPresetsRequest,
    ) -> Result<ListPresetsResponse, ErrorEnvelope> {
        ensure_m33_version(request.schema_version)?;
        Ok(ListPresetsResponse {
            schema_version: M33_CONTRACT_VERSION,
            correlation_id: request.correlation_id,
            presets: self.m33.list_presets(request.identity_id.as_str())?,
        })
    }

    pub fn create_preset_and_bind(
        &self,
        request: CreatePresetAndBindRequest,
    ) -> Result<PresetBindingResponse, ErrorEnvelope> {
        ensure_m33_version(request.schema_version)?;
        self.register_operation(request.operation_id.clone(), request.correlation_id.clone())?;
        self.cancellation_checkpoint(&request.operation_id)?;
        self.enter_non_cancellable(&request.operation_id)?;
        match self.m33.create_preset_and_bind(&request) {
            Ok(result) => {
                self.complete_and_publish(
                    &request.operation_id,
                    &request.correlation_id,
                    true,
                    "preset_bound",
                )?;
                Ok(PresetBindingResponse {
                    schema_version: M33_CONTRACT_VERSION,
                    operation_id: request.operation_id,
                    correlation_id: request.correlation_id,
                    identity_version: result.identity_version,
                    preset: result.preset,
                })
            }
            Err(error) => {
                self.fail_and_release(
                    &request.operation_id,
                    &request.correlation_id,
                    "preset_failed",
                );
                Err(error.into())
            }
        }
    }

    pub fn update_preset_and_bind(
        &self,
        request: UpdatePresetAndBindRequest,
    ) -> Result<PresetBindingResponse, ErrorEnvelope> {
        ensure_m33_version(request.schema_version)?;
        self.register_operation(request.operation_id.clone(), request.correlation_id.clone())?;
        self.cancellation_checkpoint(&request.operation_id)?;
        self.enter_non_cancellable(&request.operation_id)?;
        match self.m33.update_preset_and_bind(&request) {
            Ok(result) => {
                self.complete_and_publish(
                    &request.operation_id,
                    &request.correlation_id,
                    true,
                    "preset_bound",
                )?;
                Ok(PresetBindingResponse {
                    schema_version: M33_CONTRACT_VERSION,
                    operation_id: request.operation_id,
                    correlation_id: request.correlation_id,
                    identity_version: result.identity_version,
                    preset: result.preset,
                })
            }
            Err(error) => {
                self.fail_and_release(
                    &request.operation_id,
                    &request.correlation_id,
                    "preset_failed",
                );
                Err(error.into())
            }
        }
    }

    fn complete_and_publish(
        &self,
        operation_id: &SafeIdentifier,
        correlation_id: &SafeIdentifier,
        succeeded: bool,
        summary: &str,
    ) -> Result<(), ErrorEnvelope> {
        self.complete_operation(operation_id)?;
        let summary = SafeIdentifier::parse(summary)
            .map_err(|_| ErrorEnvelope::from_code(ErrorCode::Internal))?;
        self.events
            .publish(&OperationStatusEvent::finished(
                operation_id.clone(),
                correlation_id.clone(),
                succeeded,
                summary,
            ))
            .map_err(|_| ErrorEnvelope::from_code(ErrorCode::RecoveryRequired))
    }

    fn fail_and_release(
        &self,
        operation_id: &SafeIdentifier,
        correlation_id: &SafeIdentifier,
        summary: &str,
    ) {
        let _ = self.complete_operation(operation_id);
        if let Ok(summary) = SafeIdentifier::parse(summary) {
            let _ = self.events.publish(&OperationStatusEvent::finished(
                operation_id.clone(),
                correlation_id.clone(),
                false,
                summary,
            ));
        }
        let _ = self.release_completed_operation(operation_id);
    }
}

fn ensure_m33_version(version: u16) -> Result<(), ErrorEnvelope> {
    if version == M33_CONTRACT_VERSION {
        Ok(())
    } else {
        Err(ErrorEnvelope::from_code(ErrorCode::Validation))
    }
}
