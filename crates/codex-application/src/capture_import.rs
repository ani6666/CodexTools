use std::{fmt, path::PathBuf};

use codex_domain::{
    AuthMode, ContentHash, CredentialBackend, CredentialFingerprint, CredentialRefId, EntityName,
    EntityVersion, IdentityId, ManagedConfigPatchId, ModelPresetId, SchemaFingerprint, UnixMillis,
};

use crate::{ActualCodexState, CompatibilityReason, RepositoryError};

/// 生产边界只接受固定后端根选择器，不接受调用方路径。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlledRoot {
    DefaultCodex,
}

impl ControlledRoot {
    #[must_use]
    pub const fn as_storage_str(self) -> &'static str {
        match self {
            Self::DefaultCodex => "default_codex",
        }
    }

    pub fn from_storage(value: &str) -> Result<Self, RepositoryError> {
        match value {
            "default_codex" => Ok(Self::DefaultCodex),
            _ => Err(RepositoryError::corrupt_data()),
        }
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ControlledScanId(ContentHash);

impl ControlledScanId {
    pub fn parse(value: &str) -> Result<Self, codex_domain::DomainError> {
        ContentHash::parse(value).map(Self)
    }

    #[must_use]
    pub const fn from_hash(value: ContentHash) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn as_hash(&self) -> &ContentHash {
        &self.0
    }
}

impl std::str::FromStr for ControlledScanId {
    type Err = codex_domain::DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl fmt::Debug for ControlledScanId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ControlledScanId([REDACTED])")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlledScanSummary {
    pub scan_id: ControlledScanId,
    pub auth_mode: AuthMode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlledScanStatus {
    Ready(ControlledScanSummary),
    CompatibilityProtected(CompatibilityReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlledSourceError {
    CompatibilityProtected(CompatibilityReason),
    ScanChanged,
    IoUnavailable,
    ConsumerRejected,
    Busy,
    RecoveryRequired,
}

impl fmt::Display for ControlledSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CompatibilityProtected(_) => "controlled scan is compatibility protected",
            Self::ScanChanged => "controlled scan changed",
            Self::IoUnavailable => "controlled scan is unavailable",
            Self::ConsumerRejected => "controlled secret consumer rejected input",
            Self::Busy => "controlled root is busy",
            Self::RecoveryRequired => "controlled root recovery is required",
        })
    }
}

impl std::error::Error for ControlledSourceError {}

/// 该端口只在 source 的受限调用栈内借用 auth bytes；实现不得保留借用。
pub trait ScannedAuthConsumer {
    fn consume(
        &mut self,
        actual: &ActualCodexState,
        auth: &mut [u8],
    ) -> Result<(), ControlledSourceError>;
}

pub trait ControlledCodexSource {
    fn scan(&self, root: ControlledRoot) -> ControlledScanStatus;

    fn consume_confirmed(
        &self,
        root: ControlledRoot,
        expected: &ControlledScanId,
        consumer: &mut dyn ScannedAuthConsumer,
    ) -> Result<(), ControlledSourceError>;
}

/// 路径只存在于后端 resolver 端口，不出现在 facade 请求或结果中。
pub trait ControlledRootResolver {
    fn resolve(&self, root: ControlledRoot) -> Result<PathBuf, ControlledSourceError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureImportRequest {
    pub root: ControlledRoot,
    pub scan_id: ControlledScanId,
    pub credential_id: CredentialRefId,
    pub identity_id: IdentityId,
    pub identity_name: EntityName,
    pub preset_id: ModelPresetId,
    pub preset_name: EntityName,
    pub patch_id: ManagedConfigPatchId,
    pub now: UnixMillis,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureImportDiagnostic {
    JournalUnavailable,
    CredentialPending,
    BundlePending,
    CleanupPending,
    InconsistentState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaptureImportStatus {
    Imported(IdentityId),
    AlreadyImported(IdentityId),
    CompatibilityProtected(CompatibilityReason),
    Conflict,
    RecoveryRequired(CaptureImportDiagnostic),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureImportPhase {
    Prepared,
    CredentialReady,
    BundleReady,
    RecoveryRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureImportCredentialOrigin {
    Created,
    Reused,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureImportRecoveryRecord {
    pub operation_id: String,
    pub root: ControlledRoot,
    pub scan_id: ControlledScanId,
    pub credential_id: CredentialRefId,
    pub identity_id: IdentityId,
    pub identity_name: EntityName,
    pub preset_id: ModelPresetId,
    pub preset_name: EntityName,
    pub patch_id: ManagedConfigPatchId,
    pub auth_mode: AuthMode,
    pub auth_schema_fingerprint: SchemaFingerprint,
    pub credential_origin: CaptureImportCredentialOrigin,
    pub credential_backend: CredentialBackend,
    pub credential_schema_fingerprint: SchemaFingerprint,
    pub credential_fingerprint: CredentialFingerprint,
    pub credential_version: EntityVersion,
    pub credential_created_at: UnixMillis,
    pub credential_updated_at: UnixMillis,
    pub provider_id: codex_domain::ProviderId,
    pub provider_display_name: EntityName,
    pub api_base_url: codex_domain::EndpointUrl,
    pub model_id: codex_domain::ModelId,
    pub config_hash: ContentHash,
    pub phase: CaptureImportPhase,
    pub diagnostic: Option<CaptureImportDiagnostic>,
    pub created_at: UnixMillis,
    pub updated_at: UnixMillis,
    pub version: EntityVersion,
}

pub trait CaptureImportRecoveryRepository {
    fn create_capture_import_recovery(
        &mut self,
        record: &CaptureImportRecoveryRecord,
    ) -> Result<(), RepositoryError>;

    fn get_capture_import_recovery(
        &self,
        operation_id: &str,
    ) -> Result<Option<CaptureImportRecoveryRecord>, RepositoryError>;

    fn update_capture_import_recovery(
        &mut self,
        record: &CaptureImportRecoveryRecord,
        expected_version: EntityVersion,
    ) -> Result<(), RepositoryError>;

    fn delete_capture_import_recovery(
        &mut self,
        operation_id: &str,
        expected_version: EntityVersion,
    ) -> Result<(), RepositoryError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureImportBundlePreflight {
    Available,
    Conflict,
}

/// capture-import 专用的 SQLite 条件提交端口。
///
/// 实现必须在同一事务内复读 exact credential reference 后才创建 bundle。
pub trait CaptureImportBundleRepository {
    fn preflight_capture_import(
        &self,
        record: &CaptureImportRecoveryRecord,
    ) -> Result<CaptureImportBundlePreflight, RepositoryError>;

    fn create_identity_bundle_if_credential_exact(
        &mut self,
        bundle: &crate::IdentityBundle,
        expected: &codex_domain::CredentialReference,
    ) -> Result<(), RepositoryError>;

    /// 判断未完成操作是否尚未创建任何属于目标 identity 的 aggregate 行。
    /// 与其他 identity 发生的 preset/patch ID 冲突不属于目标部分提交。
    fn capture_import_target_is_empty(
        &self,
        record: &CaptureImportRecoveryRecord,
    ) -> Result<bool, RepositoryError>;
}
