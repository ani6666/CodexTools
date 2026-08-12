use std::{fmt, path::PathBuf};

use codex_domain::{ContentHash, SwitchTransactionId, UnixMillis};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupKind {
    Permanent,
    History,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupState {
    Ready,
    Protected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupRecoveryOperation {
    Publish,
    Delete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupRecoveryPhase {
    Prepared,
    Validated,
    Published,
    Renamed,
    MetadataDeleted,
    RecoveryRequired,
}

#[derive(Clone, Eq, PartialEq)]
pub struct BackupRecord {
    pub id: String,
    pub root_ref: ContentHash,
    pub kind: BackupKind,
    pub sequence: u64,
    pub manifest_hash: ContentHash,
    pub material_ref: PathBuf,
    pub transaction_id: Option<SwitchTransactionId>,
    pub state: BackupState,
    pub created_at: UnixMillis,
}

/// 持久化的非秘密备份恢复意图。它只记录哈希和相对材料引用。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupRecoveryRecord {
    pub operation_id: String,
    pub operation: BackupRecoveryOperation,
    pub phase: BackupRecoveryPhase,
    pub backup: BackupRecord,
    pub pending_ref: Option<PathBuf>,
    pub diagnostic_code: Option<String>,
}

impl fmt::Debug for BackupRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackupRecord")
            .field("id", &self.id)
            .field("root_ref", &"[HASH]")
            .field("kind", &self.kind)
            .field("sequence", &self.sequence)
            .field("manifest_hash", &"[HASH]")
            .field("material_ref", &self.material_ref)
            .field("transaction_id", &self.transaction_id)
            .field("state", &self.state)
            .field("created_at", &self.created_at)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupStoreError {
    AlreadyExists,
    NotFound,
    PlanStale,
    CompatibilityProtected,
    RecoveryRequired,
    CorruptMaterial,
    IoFailure,
    RepositoryFailure,
}

impl fmt::Display for BackupStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AlreadyExists => "backup already exists",
            Self::NotFound => "backup was not found",
            Self::PlanStale => "backup plan is stale",
            Self::CompatibilityProtected => "backup operation is compatibility protected",
            Self::RecoveryRequired => "backup recovery is required",
            Self::CorruptMaterial => "backup material is invalid",
            Self::IoFailure => "backup storage failed",
            Self::RepositoryFailure => "backup metadata storage failed",
        })
    }
}
impl std::error::Error for BackupStoreError {}

pub trait BackupRepository {
    fn create_backup(&mut self, record: &BackupRecord) -> Result<(), RepositoryError>;
    fn get_backup(&self, id: &str) -> Result<Option<BackupRecord>, RepositoryError>;
    fn list_backups(&self, root_ref: &ContentHash) -> Result<Vec<BackupRecord>, RepositoryError>;
    fn delete_backup(&mut self, id: &str) -> Result<(), RepositoryError>;
    fn create_backup_recovery(
        &mut self,
        record: &BackupRecoveryRecord,
    ) -> Result<(), RepositoryError>;
    fn list_backup_recoveries(
        &self,
        root_ref: &ContentHash,
    ) -> Result<Vec<BackupRecoveryRecord>, RepositoryError>;
    fn update_backup_recovery(
        &mut self,
        operation_id: &str,
        phase: BackupRecoveryPhase,
        diagnostic_code: Option<&str>,
    ) -> Result<(), RepositoryError>;
    fn delete_backup_recovery(&mut self, operation_id: &str) -> Result<(), RepositoryError>;
}

use crate::RepositoryError;
