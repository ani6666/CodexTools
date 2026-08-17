use std::{
    fmt,
    path::{Path, PathBuf},
};

use codex_domain::{
    ContentHash, CredentialFingerprint, EntityVersion, ModelId, ProviderId, SwitchTransaction,
    SwitchTransactionId, UnixMillis,
};
use zeroize::Zeroizing;

use crate::{CompatibilityReason, RepositoryError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileBaseline {
    pub existed_before: bool,
    pub length: u64,
    pub sha256: Option<ContentHash>,
}

impl FileBaseline {
    #[must_use]
    pub const fn present(length: u64, sha256: ContentHash) -> Self {
        Self {
            existed_before: true,
            length,
            sha256: Some(sha256),
        }
    }
    #[must_use]
    pub const fn absent() -> Self {
        Self {
            existed_before: false,
            length: 0,
            sha256: None,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SwitchPlan {
    id: SwitchTransactionId,
    root: PathBuf,
    config_source: FileBaseline,
    auth_source: FileBaseline,
    target_config: Zeroizing<Vec<u8>>,
    target_auth: Zeroizing<Vec<u8>>,
    provider_id: ProviderId,
    model_id: ModelId,
    auth_fingerprint: CredentialFingerprint,
    created_at: UnixMillis,
    expires_at: UnixMillis,
}

impl fmt::Debug for SwitchPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwitchPlan")
            .field("id", &self.id)
            .field("root", &"[REDACTED_PATH]")
            .field("config_source", &self.config_source)
            .field("auth_source", &self.auth_source)
            .field("target_config", &"[REDACTED_BYTES]")
            .field("target_auth", &"[REDACTED_BYTES]")
            .field("provider_id", &self.provider_id)
            .field("model_id", &self.model_id)
            .field("auth_fingerprint", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl SwitchPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: SwitchTransactionId,
        root: PathBuf,
        config_source: FileBaseline,
        auth_source: FileBaseline,
        target_config: Vec<u8>,
        target_auth: Vec<u8>,
        provider_id: ProviderId,
        model_id: ModelId,
        auth_fingerprint: CredentialFingerprint,
        created_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, SwitchExecutionError> {
        Self::new_zeroizing(
            id,
            root,
            config_source,
            auth_source,
            Zeroizing::new(target_config),
            Zeroizing::new(target_auth),
            provider_id,
            model_id,
            auth_fingerprint,
            created_at,
            expires_at,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_zeroizing_auth(
        id: SwitchTransactionId,
        root: PathBuf,
        config_source: FileBaseline,
        auth_source: FileBaseline,
        target_config: Vec<u8>,
        target_auth: Zeroizing<Vec<u8>>,
        provider_id: ProviderId,
        model_id: ModelId,
        auth_fingerprint: CredentialFingerprint,
        created_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, SwitchExecutionError> {
        Self::new_zeroizing(
            id,
            root,
            config_source,
            auth_source,
            Zeroizing::new(target_config),
            target_auth,
            provider_id,
            model_id,
            auth_fingerprint,
            created_at,
            expires_at,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_zeroizing(
        id: SwitchTransactionId,
        root: PathBuf,
        config_source: FileBaseline,
        auth_source: FileBaseline,
        target_config: Zeroizing<Vec<u8>>,
        target_auth: Zeroizing<Vec<u8>>,
        provider_id: ProviderId,
        model_id: ModelId,
        auth_fingerprint: CredentialFingerprint,
        created_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, SwitchExecutionError> {
        if !root.is_absolute()
            || target_config.is_empty()
            || target_auth.is_empty()
            || expires_at <= created_at
        {
            return Err(SwitchExecutionError::InvalidPlan);
        }
        Ok(Self {
            id,
            root,
            config_source,
            auth_source,
            target_config,
            target_auth,
            provider_id,
            model_id,
            auth_fingerprint,
            created_at,
            expires_at,
        })
    }
    pub const fn id(&self) -> &SwitchTransactionId {
        &self.id
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub const fn config_source(&self) -> &FileBaseline {
        &self.config_source
    }
    pub const fn auth_source(&self) -> &FileBaseline {
        &self.auth_source
    }
    pub fn target_config(&self) -> &[u8] {
        &self.target_config
    }
    pub fn target_auth(&self) -> &[u8] {
        &self.target_auth
    }
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }
    pub const fn model_id(&self) -> &ModelId {
        &self.model_id
    }
    pub const fn auth_fingerprint(&self) -> &CredentialFingerprint {
        &self.auth_fingerprint
    }
    pub const fn created_at(&self) -> UnixMillis {
        self.created_at
    }
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SwitchErrorCode {
    Busy,
    PlanStale,
    CompatibilityProtected,
    SnapshotInvalid,
    IoFailure,
    RepositoryFailure,
    InjectedFailure,
    RecoveryRequired,
}

impl SwitchErrorCode {
    pub const fn as_storage_str(self) -> &'static str {
        match self {
            Self::Busy => "busy",
            Self::PlanStale => "plan_stale",
            Self::CompatibilityProtected => "compatibility_protected",
            Self::SnapshotInvalid => "snapshot_invalid",
            Self::IoFailure => "io_failure",
            Self::RepositoryFailure => "repository_failure",
            Self::InjectedFailure => "injected_failure",
            Self::RecoveryRequired => "recovery_required",
        }
    }
    pub fn parse_storage(value: &str) -> Result<Self, RepositoryError> {
        match value {
            "busy" => Ok(Self::Busy),
            "plan_stale" => Ok(Self::PlanStale),
            "compatibility_protected" => Ok(Self::CompatibilityProtected),
            "snapshot_invalid" => Ok(Self::SnapshotInvalid),
            "io_failure" => Ok(Self::IoFailure),
            "repository_failure" => Ok(Self::RepositoryFailure),
            "injected_failure" => Ok(Self::InjectedFailure),
            "recovery_required" => Ok(Self::RecoveryRequired),
            _ => Err(RepositoryError::corrupt_data()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SwitchExecutionError {
    Busy,
    PlanStale,
    CompatibilityProtected(CompatibilityReason),
    InvalidPlan,
    SnapshotInvalid,
    IoFailure,
    RepositoryFailure,
    InjectedFailure,
    Interrupted,
    RecoveryRequired,
}

impl fmt::Display for SwitchExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Busy => "switch lock is contended",
            Self::PlanStale => "switch plan is stale",
            Self::CompatibilityProtected(_) => "Codex state is compatibility protected",
            Self::InvalidPlan => "switch plan is invalid",
            Self::SnapshotInvalid => "switch snapshot is invalid",
            Self::IoFailure => "switch file operation failed",
            Self::RepositoryFailure => "switch transaction storage failed",
            Self::InjectedFailure => "switch fault was injected",
            Self::Interrupted => "switch execution was interrupted",
            Self::RecoveryRequired => "switch recovery requires manual intervention",
        })
    }
}
impl std::error::Error for SwitchExecutionError {}
impl From<RepositoryError> for SwitchExecutionError {
    fn from(_: RepositoryError) -> Self {
        Self::RepositoryFailure
    }
}

pub trait Clock {
    fn now(&self) -> UnixMillis;
}
pub trait StabilityWindow {
    fn between_observations(&mut self, root: &Path) -> Result<(), SwitchExecutionError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SwitchTransactionRecord {
    pub transaction: SwitchTransaction,
    pub last_error: Option<SwitchErrorCode>,
    pub snapshot_manifest_hash: Option<ContentHash>,
}

/// 供人工恢复入口只读展示的非秘密诊断信息。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SwitchRecoveryDiagnostic {
    pub record: SwitchTransactionRecord,
    pub material_ref: PathBuf,
}

pub trait SwitchTransactionRepository {
    fn create_switch_transaction(
        &mut self,
        record: &SwitchTransactionRecord,
    ) -> Result<(), RepositoryError>;
    fn update_switch_transaction(
        &mut self,
        record: &SwitchTransactionRecord,
        expected_version: EntityVersion,
    ) -> Result<(), RepositoryError>;
    fn get_switch_transaction(
        &self,
        id: &SwitchTransactionId,
    ) -> Result<Option<SwitchTransactionRecord>, RepositoryError>;
    fn list_unfinished_switch_transactions(
        &self,
        root_ref: &ContentHash,
    ) -> Result<Vec<SwitchTransactionRecord>, RepositoryError>;
    fn list_blocking_switch_transactions(
        &self,
        root_ref: &ContentHash,
    ) -> Result<Vec<SwitchTransactionRecord>, RepositoryError>;
    fn list_recovery_required_diagnostics(
        &self,
        root_ref: &ContentHash,
    ) -> Result<Vec<SwitchRecoveryDiagnostic>, RepositoryError>;
}
