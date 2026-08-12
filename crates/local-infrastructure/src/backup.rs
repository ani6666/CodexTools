use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use codex_application::{
    BackupKind, BackupRecord, BackupRecoveryOperation, BackupRecoveryPhase, BackupRecoveryRecord,
    BackupRepository, BackupState, BackupStoreError, FileBaseline, SwitchTransactionRepository,
};
use codex_domain::{ContentHash, SwitchTransactionId, UnixMillis};
use windows_platform::{
    DpapiCurrentUser, secure_read_contained_file, secure_validate_contained_directory,
};
use zeroize::{Zeroize, Zeroizing};

use crate::CrossProcessWriteLock;

pub const PERMANENT: &str = "permanent";
pub const HISTORY_LIMIT: usize = 10;
const MANIFEST_VERSION: u32 = 2;
static STAGE_NONCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupFaultPoint {
    AfterConfigObserve,
    AfterAuthObserve,
    ConfigWrite,
    AuthEncryption,
    AuthWrite,
    ManifestWrite,
    BeforePublishObservation,
    AfterRecoveryPrepared,
    BetweenSecondObservations,
    AfterValidated,
    Publish,
    Metadata,
    RotationDelete,
    AfterDeleteRename,
    AfterDeleteMetadata,
    PhysicalDelete,
}

pub trait BackupFaults {
    fn fail(&mut self, point: BackupFaultPoint) -> bool;
}

#[derive(Default)]
pub struct NoBackupFaults;
impl BackupFaults for NoBackupFaults {
    fn fail(&mut self, _point: BackupFaultPoint) -> bool {
        false
    }
}

pub struct BackupRestoreTarget {
    pub config: Option<Vec<u8>>,
    pub auth: Option<Vec<u8>>,
    pub config_readonly: bool,
    pub auth_readonly: bool,
    pub config_source: FileBaseline,
    pub auth_source: FileBaseline,
}

impl Drop for BackupRestoreTarget {
    fn drop(&mut self) {
        if let Some(auth) = self.auth.as_mut() {
            auth.zeroize();
        }
    }
}

pub struct BackupService<'a, R, F> {
    repository: &'a mut R,
    faults: &'a mut F,
    protector: DpapiCurrentUser,
}

impl<'a, R, F> BackupService<'a, R, F>
where
    R: BackupRepository + SwitchTransactionRepository,
    F: BackupFaults,
{
    pub fn new(repository: &'a mut R, faults: &'a mut F) -> Self {
        Self {
            repository,
            faults,
            protector: DpapiCurrentUser,
        }
    }

    /// 在根锁内幂等收敛可证明的发布/删除意图；不可证明的现场保持阻塞。
    pub fn reconcile_root(
        &mut self,
        live_root: &Path,
        backup_root: &Path,
        now: UnixMillis,
    ) -> Result<(), BackupStoreError> {
        let (live, backup, root_ref, _lock) = locked_roots(live_root, backup_root, now)?;
        self.reconcile_locked(&live, &backup, &root_ref)
    }

    /// 人工确认放弃尚未登记的 publish 材料；已登记记录不会由此删除。
    pub fn rollback_unpublished(
        &mut self,
        live_root: &Path,
        backup_root: &Path,
        operation_id: &str,
        now: UnixMillis,
    ) -> Result<(), BackupStoreError> {
        let (_live, backup, root_ref, _lock) = locked_roots(live_root, backup_root, now)?;
        let operation = self
            .repository
            .list_backup_recoveries(&root_ref)
            .map_err(repo_error)?
            .into_iter()
            .find(|candidate| candidate.operation_id == operation_id)
            .ok_or(BackupStoreError::NotFound)?;
        if operation.operation != BackupRecoveryOperation::Publish
            || self
                .repository
                .get_backup(&operation.backup.id)
                .map_err(repo_error)?
                .is_some()
        {
            return Err(BackupStoreError::RecoveryRequired);
        }
        let final_path = checked_path(&backup, &operation.backup.material_ref, false)?;
        let pending_ref = operation
            .pending_ref
            .as_ref()
            .ok_or(BackupStoreError::RecoveryRequired)?;
        let pending = checked_path(&backup, pending_ref, false)?;
        if final_path.exists() && pending.exists() {
            return Err(BackupStoreError::RecoveryRequired);
        }
        if final_path.exists() {
            remove_checked_dir(&backup, &operation.backup.material_ref)?;
        }
        if pending.exists() {
            remove_checked_dir(&backup, pending_ref)?;
        }
        self.repository
            .delete_backup_recovery(operation_id)
            .map_err(repo_error)
    }

    pub fn create_permanent(
        &mut self,
        live_root: &Path,
        backup_root: &Path,
        id: &str,
        created_at: UnixMillis,
    ) -> Result<BackupRecord, BackupStoreError> {
        let (live, backup, root_ref, _lock) = locked_roots(live_root, backup_root, created_at)?;
        self.reconcile_locked(&live, &backup, &root_ref)?;
        if let Some(existing) = self
            .repository
            .list_backups(&root_ref)
            .map_err(repo_error)?
            .into_iter()
            .find(|record| record.kind == BackupKind::Permanent)
        {
            let _loaded = load_material(&self.protector, &backup, &existing)?;
            return Ok(existing);
        }
        self.create_locked(
            &live,
            &backup,
            root_ref,
            id,
            BackupKind::Permanent,
            0,
            None,
            BackupState::Ready,
            created_at,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_history(
        &mut self,
        live_root: &Path,
        backup_root: &Path,
        id: &str,
        transaction_id: Option<SwitchTransactionId>,
        protected: bool,
        created_at: UnixMillis,
    ) -> Result<BackupRecord, BackupStoreError> {
        let (live, backup, root_ref, _lock) = locked_roots(live_root, backup_root, created_at)?;
        self.reconcile_locked(&live, &backup, &root_ref)?;
        if let Some(existing) = self.repository.get_backup(id).map_err(repo_error)? {
            if existing.root_ref == root_ref && existing.kind == BackupKind::History {
                let _loaded = load_material(&self.protector, &backup, &existing)?;
                self.rotate_history(&live, &backup, &root_ref)?;
                return Ok(existing);
            }
            return Err(BackupStoreError::AlreadyExists);
        }
        let records = self
            .repository
            .list_backups(&root_ref)
            .map_err(repo_error)?;
        let sequence = records
            .iter()
            .filter(|r| r.kind == BackupKind::History)
            .map(|r| r.sequence)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(BackupStoreError::RecoveryRequired)?;
        let record = self.create_locked(
            &live,
            &backup,
            root_ref.clone(),
            id,
            BackupKind::History,
            sequence,
            transaction_id,
            if protected {
                BackupState::Protected
            } else {
                BackupState::Ready
            },
            created_at,
        )?;
        self.rotate_history(&live, &backup, &root_ref)?;
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    fn create_locked(
        &mut self,
        live_root: &Path,
        backup_root: &Path,
        root_ref: ContentHash,
        id: &str,
        kind: BackupKind,
        sequence: u64,
        transaction_id: Option<SwitchTransactionId>,
        state: BackupState,
        created_at: UnixMillis,
    ) -> Result<BackupRecord, BackupStoreError> {
        validate_id(id)?;
        let config = observe(live_root.join("config.toml"))?;
        if self.faults.fail(BackupFaultPoint::AfterConfigObserve) {
            return Err(BackupStoreError::PlanStale);
        }
        let mut auth = observe(live_root.join("auth.json"))?;
        if self.faults.fail(BackupFaultPoint::AfterAuthObserve) {
            auth.bytes.zeroize();
            return Err(BackupStoreError::PlanStale);
        }
        let relative = material_relative(kind, sequence, id);
        let stage_relative = PathBuf::from(format!(
            ".stage-{id}-{}-{}",
            std::process::id(),
            STAGE_NONCE.fetch_add(1, Ordering::Relaxed)
        ));
        let stage = checked_path(backup_root, &stage_relative, false)?;
        fs::create_dir(&stage).map_err(|_| BackupStoreError::IoFailure)?;
        let mut cleanup = CleanupDir::new(stage.clone());
        let result = (|| {
            if self.faults.fail(BackupFaultPoint::ConfigWrite) {
                return Err(BackupStoreError::IoFailure);
            }
            if config.existed {
                write_synced(&stage.join("config.bin"), &config.bytes)?;
            }
            let auth_hash = auth.hash.clone();
            if auth.existed {
                if self.faults.fail(BackupFaultPoint::AuthEncryption) {
                    return Err(BackupStoreError::IoFailure);
                }
                let entropy = backup_entropy(
                    &root_ref,
                    kind,
                    sequence,
                    &relative,
                    id,
                    "auth",
                    auth_hash.as_ref().expect("hash"),
                );
                let encrypted = self
                    .protector
                    .protect(&entropy, &auth.bytes)
                    .map_err(|_| BackupStoreError::IoFailure)?;
                auth.bytes.zeroize();
                if self.faults.fail(BackupFaultPoint::AuthWrite) {
                    return Err(BackupStoreError::IoFailure);
                }
                write_synced(&stage.join("auth.dpapi"), &encrypted)?;
            }
            let manifest = manifest_bytes(
                id,
                &root_ref,
                &relative,
                kind,
                sequence,
                transaction_id.as_ref(),
                state,
                created_at,
                &config,
                auth.existed,
                auth.length,
                auth_hash.as_ref(),
                auth.readonly,
            );
            if self.faults.fail(BackupFaultPoint::ManifestWrite) {
                return Err(BackupStoreError::IoFailure);
            }
            write_synced(&stage.join("manifest.v2"), &manifest)?;
            let manifest_hash = codex_adapter::hash_bytes(&manifest);
            let final_path = checked_path(backup_root, &relative, false)?;
            if let Some(parent) = final_path.parent() {
                fs::create_dir_all(parent).map_err(|_| BackupStoreError::IoFailure)?;
                ensure_no_reparse(backup_root, parent)?;
            }
            if final_path.exists() {
                return Err(BackupStoreError::AlreadyExists);
            }
            let record = BackupRecord {
                id: id.to_owned(),
                root_ref,
                kind,
                sequence,
                manifest_hash,
                material_ref: relative,
                transaction_id,
                state,
                created_at,
            };
            let recovery = BackupRecoveryRecord {
                operation_id: format!("publish-{id}"),
                operation: BackupRecoveryOperation::Publish,
                phase: BackupRecoveryPhase::Prepared,
                backup: record.clone(),
                pending_ref: Some(stage_relative),
                diagnostic_code: None,
            };
            self.repository
                .create_backup_recovery(&recovery)
                .map_err(repo_error)?;
            if self.faults.fail(BackupFaultPoint::AfterRecoveryPrepared) {
                cleanup.disarm();
                return Err(BackupStoreError::RecoveryRequired);
            }
            if self.faults.fail(BackupFaultPoint::BeforePublishObservation) {
                self.repository
                    .delete_backup_recovery(&recovery.operation_id)
                    .map_err(repo_error)?;
                return Err(BackupStoreError::PlanStale);
            }
            let config_second = match observe(live_root.join("config.toml")) {
                Ok(observed) => observed,
                Err(error) => {
                    self.repository
                        .delete_backup_recovery(&recovery.operation_id)
                        .map_err(repo_error)?;
                    return Err(error);
                }
            };
            let _ = self
                .faults
                .fail(BackupFaultPoint::BetweenSecondObservations);
            let mut auth_second = match observe(live_root.join("auth.json")) {
                Ok(observed) => observed,
                Err(error) => {
                    self.repository
                        .delete_backup_recovery(&recovery.operation_id)
                        .map_err(repo_error)?;
                    return Err(error);
                }
            };
            let config_final = observe(live_root.join("config.toml"))?;
            let mut auth_final = observe(live_root.join("auth.json"))?;
            let stable = config.same_identity(&config_second)
                && auth.same_identity(&auth_second)
                && config.same_identity(&config_final)
                && auth.same_identity(&auth_final);
            auth_second.bytes.zeroize();
            auth_final.bytes.zeroize();
            if !stable {
                self.repository
                    .delete_backup_recovery(&recovery.operation_id)
                    .map_err(repo_error)?;
                return Err(BackupStoreError::PlanStale);
            }
            self.repository
                .update_backup_recovery(
                    &recovery.operation_id,
                    BackupRecoveryPhase::Validated,
                    None,
                )
                .map_err(repo_error)?;
            if self.faults.fail(BackupFaultPoint::AfterValidated) {
                cleanup.disarm();
                return Err(BackupStoreError::RecoveryRequired);
            }
            let config_publish = observe(live_root.join("config.toml"))?;
            let mut auth_publish = observe(live_root.join("auth.json"))?;
            let publish_stable =
                config.same_identity(&config_publish) && auth.same_identity(&auth_publish);
            auth_publish.bytes.zeroize();
            if !publish_stable {
                self.repository
                    .delete_backup_recovery(&recovery.operation_id)
                    .map_err(repo_error)?;
                return Err(BackupStoreError::PlanStale);
            }
            if self.faults.fail(BackupFaultPoint::Publish) {
                self.repository
                    .delete_backup_recovery(&recovery.operation_id)
                    .map_err(repo_error)?;
                return Err(BackupStoreError::IoFailure);
            }
            let config_rename = observe(live_root.join("config.toml"))?;
            let auth_rename = observe(live_root.join("auth.json"))?;
            if !config.same_identity(&config_rename) || !auth.same_identity(&auth_rename) {
                self.repository
                    .delete_backup_recovery(&recovery.operation_id)
                    .map_err(repo_error)?;
                return Err(BackupStoreError::PlanStale);
            }
            if fs::rename(&stage, &final_path).is_err() {
                let _ = self
                    .repository
                    .delete_backup_recovery(&recovery.operation_id);
                return Err(BackupStoreError::IoFailure);
            }
            cleanup.disarm();
            self.repository
                .update_backup_recovery(
                    &recovery.operation_id,
                    BackupRecoveryPhase::Published,
                    None,
                )
                .map_err(repo_error)?;
            if self.faults.fail(BackupFaultPoint::Metadata)
                || self.repository.create_backup(&record).is_err()
            {
                return self.mark_recovery(&recovery.operation_id, "metadata_pending");
            }
            self.repository
                .delete_backup_recovery(&recovery.operation_id)
                .map_err(repo_error)?;
            sync_directory(final_path.parent().expect("parent"))?;
            Ok(record)
        })();
        auth.bytes.zeroize();
        if result.is_err() {
            cleanup.cleanup()?;
        }
        result
    }

    fn mark_recovery<T>(&mut self, operation_id: &str, code: &str) -> Result<T, BackupStoreError> {
        let _ = self.repository.update_backup_recovery(
            operation_id,
            BackupRecoveryPhase::RecoveryRequired,
            Some(code),
        );
        Err(BackupStoreError::RecoveryRequired)
    }

    fn reconcile_locked(
        &mut self,
        live_root: &Path,
        backup_root: &Path,
        root_ref: &ContentHash,
    ) -> Result<(), BackupStoreError> {
        let operations = self
            .repository
            .list_backup_recoveries(root_ref)
            .map_err(repo_error)?;
        cleanup_unreferenced_stages(backup_root, &operations)?;
        for operation in operations {
            let result = match operation.operation {
                BackupRecoveryOperation::Publish => {
                    self.reconcile_publish(live_root, backup_root, &operation)
                }
                BackupRecoveryOperation::Delete => self.reconcile_delete(backup_root, &operation),
            };
            if result.is_err() {
                let _ = self.repository.update_backup_recovery(
                    &operation.operation_id,
                    BackupRecoveryPhase::RecoveryRequired,
                    Some("reconcile_failed"),
                );
                return Err(BackupStoreError::RecoveryRequired);
            }
        }
        Ok(())
    }

    fn reconcile_publish(
        &mut self,
        live_root: &Path,
        root: &Path,
        operation: &BackupRecoveryRecord,
    ) -> Result<(), BackupStoreError> {
        let final_path = checked_path(root, &operation.backup.material_ref, false)?;
        let pending_ref = operation
            .pending_ref
            .as_ref()
            .ok_or(BackupStoreError::RecoveryRequired)?;
        let pending = checked_path(root, pending_ref, false)?;
        if operation.phase == BackupRecoveryPhase::Prepared {
            if final_path.exists() {
                return Err(BackupStoreError::RecoveryRequired);
            }
            if pending.exists() {
                remove_checked_dir(root, pending_ref)?;
            }
            return self
                .repository
                .delete_backup_recovery(&operation.operation_id)
                .map_err(repo_error);
        }
        if !final_path.exists() {
            if operation.phase != BackupRecoveryPhase::Validated {
                return Err(BackupStoreError::RecoveryRequired);
            }
            if !pending.exists() {
                return Err(BackupStoreError::RecoveryRequired);
            }
            let loaded =
                validate_material_at(&self.protector, root, pending_ref, &operation.backup)?;
            if !live_matches_loaded(live_root, &loaded)? {
                return Err(BackupStoreError::RecoveryRequired);
            }
            if let Some(parent) = final_path.parent() {
                fs::create_dir_all(parent).map_err(|_| BackupStoreError::RecoveryRequired)?;
            }
            fs::rename(&pending, &final_path).map_err(|_| BackupStoreError::RecoveryRequired)?;
        }
        validate_material(root, &operation.backup)?;
        match self
            .repository
            .get_backup(&operation.backup.id)
            .map_err(repo_error)?
        {
            Some(existing) if existing == operation.backup => {}
            Some(_) => return Err(BackupStoreError::RecoveryRequired),
            None => self
                .repository
                .create_backup(&operation.backup)
                .map_err(repo_error)?,
        }
        self.repository
            .delete_backup_recovery(&operation.operation_id)
            .map_err(repo_error)
    }

    fn reconcile_delete(
        &mut self,
        root: &Path,
        operation: &BackupRecoveryRecord,
    ) -> Result<(), BackupStoreError> {
        let final_path = checked_path(root, &operation.backup.material_ref, false)?;
        let pending_ref = operation
            .pending_ref
            .as_ref()
            .ok_or(BackupStoreError::RecoveryRequired)?;
        let pending = checked_path(root, pending_ref, false)?;
        let metadata = self
            .repository
            .get_backup(&operation.backup.id)
            .map_err(repo_error)?;
        match (metadata, final_path.exists(), pending.exists()) {
            (Some(existing), true, false) if existing == operation.backup => {
                self.repository
                    .delete_backup_recovery(&operation.operation_id)
                    .map_err(repo_error)?;
            }
            (Some(existing), false, true) if existing == operation.backup => {
                fs::rename(&pending, &final_path)
                    .map_err(|_| BackupStoreError::RecoveryRequired)?;
                self.repository
                    .delete_backup_recovery(&operation.operation_id)
                    .map_err(repo_error)?;
            }
            (None, false, true) => {
                remove_checked_dir(root, pending_ref)?;
                self.repository
                    .delete_backup_recovery(&operation.operation_id)
                    .map_err(repo_error)?;
            }
            (None, false, false) => self
                .repository
                .delete_backup_recovery(&operation.operation_id)
                .map_err(repo_error)?,
            _ => return Err(BackupStoreError::RecoveryRequired),
        }
        Ok(())
    }

    fn rotate_history(
        &mut self,
        live_root: &Path,
        backup_root: &Path,
        root_ref: &ContentHash,
    ) -> Result<(), BackupStoreError> {
        self.reconcile_locked(live_root, backup_root, root_ref)?;
        let mut records = self
            .repository
            .list_backups(root_ref)
            .map_err(repo_error)?
            .into_iter()
            .filter(|record| record.kind == BackupKind::History)
            .collect::<Vec<_>>();
        records.sort_by_key(|r| (r.sequence, r.created_at.value(), r.id.clone()));
        let mut removable = Vec::new();
        for record in &records {
            let transaction_blocks = if let Some(id) = record.transaction_id.as_ref() {
                self.repository
                    .get_switch_transaction(id)
                    .map_err(repo_error)?
                    .is_some_and(|transaction| {
                        !matches!(
                            transaction.transaction.state(),
                            codex_domain::SwitchTransactionState::Committed
                                | codex_domain::SwitchTransactionState::RolledBack
                        )
                    })
            } else {
                false
            };
            if record.state == BackupState::Ready && !transaction_blocks {
                removable.push(record.clone());
            }
        }
        let mut excess = records.len().saturating_sub(HISTORY_LIMIT);
        for record in removable {
            if excess == 0 {
                break;
            }
            if self.faults.fail(BackupFaultPoint::RotationDelete) {
                return Err(BackupStoreError::RecoveryRequired);
            }
            let pending_ref = PathBuf::from(format!(".delete-{}", record.id));
            let path = checked_path(backup_root, &record.material_ref, true)?;
            let pending = checked_path(backup_root, &pending_ref, false)?;
            let recovery = BackupRecoveryRecord {
                operation_id: format!("delete-{}", record.id),
                operation: BackupRecoveryOperation::Delete,
                phase: BackupRecoveryPhase::Prepared,
                backup: record.clone(),
                pending_ref: Some(pending_ref.clone()),
                diagnostic_code: None,
            };
            self.repository
                .create_backup_recovery(&recovery)
                .map_err(repo_error)?;
            fs::rename(&path, &pending).map_err(|_| BackupStoreError::RecoveryRequired)?;
            self.repository
                .update_backup_recovery(&recovery.operation_id, BackupRecoveryPhase::Renamed, None)
                .map_err(repo_error)?;
            if self.faults.fail(BackupFaultPoint::AfterDeleteRename) {
                return self.mark_recovery(&recovery.operation_id, "delete_renamed");
            }
            self.repository
                .delete_backup(&record.id)
                .map_err(repo_error)?;
            self.repository
                .update_backup_recovery(
                    &recovery.operation_id,
                    BackupRecoveryPhase::MetadataDeleted,
                    None,
                )
                .map_err(repo_error)?;
            if self.faults.fail(BackupFaultPoint::AfterDeleteMetadata) {
                return self.mark_recovery(&recovery.operation_id, "metadata_deleted");
            }
            if self.faults.fail(BackupFaultPoint::PhysicalDelete) {
                return self.mark_recovery(&recovery.operation_id, "physical_delete_failed");
            }
            remove_checked_dir(backup_root, &pending_ref)?;
            self.repository
                .delete_backup_recovery(&recovery.operation_id)
                .map_err(repo_error)?;
            excess -= 1;
        }
        if excess > 0 {
            return Err(BackupStoreError::RecoveryRequired);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn plan_restore(
        &mut self,
        live_root: &Path,
        backup_root: &Path,
        record: &BackupRecord,
        expected_config: &FileBaseline,
        expected_auth: &FileBaseline,
        created_at: UnixMillis,
        expires_at: UnixMillis,
        now: UnixMillis,
    ) -> Result<BackupRestoreTarget, BackupStoreError> {
        if expires_at <= created_at || now < created_at || now >= expires_at {
            return Err(BackupStoreError::PlanStale);
        }
        let (live, backup, root_ref, _lock) = locked_roots(live_root, backup_root, now)?;
        self.reconcile_locked(&live, &backup, &root_ref)?;
        if root_ref != record.root_ref {
            return Err(BackupStoreError::CompatibilityProtected);
        }
        let exact = self
            .repository
            .get_backup(&record.id)
            .map_err(repo_error)?
            .ok_or(BackupStoreError::NotFound)?;
        if exact != *record {
            return Err(BackupStoreError::CompatibilityProtected);
        }
        let current_config = observe(live.join("config.toml"))?;
        let mut current_auth = observe(live.join("auth.json"))?;
        if current_config.baseline() != *expected_config
            || current_auth.baseline() != *expected_auth
        {
            current_auth.bytes.zeroize();
            return Err(BackupStoreError::PlanStale);
        }
        current_auth.bytes.zeroize();
        let mut loaded = load_material(&self.protector, &backup, &exact)?;
        let config_bytes = loaded.config.as_deref().unwrap_or_default();
        let auth_bytes = loaded.auth.as_deref().unwrap_or_default();
        if !matches!(
            codex_adapter::CodexAdapter::new().scan_memory(config_bytes, auth_bytes),
            codex_application::ScanStatus::Ready(_)
        ) {
            return Err(BackupStoreError::CompatibilityProtected);
        }
        let config = loaded.config.take();
        let auth = loaded.auth.take();
        Ok(BackupRestoreTarget {
            config,
            auth,
            config_readonly: loaded.config_readonly,
            auth_readonly: loaded.auth_readonly,
            config_source: current_config.baseline(),
            auth_source: current_auth.baseline(),
        })
    }
}

#[derive(Eq, PartialEq)]
struct Observed {
    existed: bool,
    bytes: Vec<u8>,
    length: u64,
    hash: Option<ContentHash>,
    readonly: bool,
}
impl Observed {
    fn baseline(&self) -> FileBaseline {
        if self.existed {
            FileBaseline::present(self.length, self.hash.clone().expect("hash"))
        } else {
            FileBaseline::absent()
        }
    }
    fn same_identity(&self, other: &Self) -> bool {
        self.existed == other.existed
            && self.length == other.length
            && self.hash == other.hash
            && self.readonly == other.readonly
    }
}
impl Drop for Observed {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

fn live_matches_loaded(
    live_root: &Path,
    loaded: &LoadedBackupMaterial,
) -> Result<bool, BackupStoreError> {
    let config = observe(live_root.join("config.toml"))?;
    let auth = observe(live_root.join("auth.json"))?;
    Ok(
        observed_matches_bytes(&config, loaded.config.as_deref(), loaded.config_readonly)
            && observed_matches_bytes(&auth, loaded.auth.as_deref(), loaded.auth_readonly),
    )
}

fn observed_matches_bytes(observed: &Observed, bytes: Option<&[u8]>, readonly: bool) -> bool {
    match bytes {
        Some(bytes) => {
            observed.existed
                && observed.length == bytes.len() as u64
                && observed.hash.as_ref() == Some(&codex_adapter::hash_bytes(bytes))
                && observed.readonly == readonly
        }
        None => !observed.existed,
    }
}

fn observe(path: PathBuf) -> Result<Observed, BackupStoreError> {
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || metadata_is_reparse(&metadata)
                || !metadata.is_file()
            {
                return Err(BackupStoreError::CompatibilityProtected);
            }
            let root = fs::canonicalize(path.parent().ok_or(BackupStoreError::IoFailure)?)
                .map_err(|_| BackupStoreError::IoFailure)?;
            let bytes = secure_read_contained_file(&root, &path, 1024 * 1024)
                .map_err(|_| BackupStoreError::IoFailure)?;
            Ok(Observed {
                existed: true,
                length: bytes.len() as u64,
                hash: Some(codex_adapter::hash_bytes(&bytes)),
                bytes,
                readonly: metadata.permissions().readonly(),
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Observed {
            existed: false,
            bytes: Vec::new(),
            length: 0,
            hash: None,
            readonly: false,
        }),
        Err(_) => Err(BackupStoreError::IoFailure),
    }
}

fn locked_roots(
    live_root: &Path,
    backup_root: &Path,
    now: UnixMillis,
) -> Result<(PathBuf, PathBuf, ContentHash, CrossProcessWriteLock), BackupStoreError> {
    if !live_root.is_absolute() || !backup_root.is_absolute() {
        return Err(BackupStoreError::IoFailure);
    }
    reject_reparse_path(live_root)?;
    fs::create_dir_all(backup_root).map_err(|_| BackupStoreError::IoFailure)?;
    reject_reparse_path(backup_root)?;
    let live = fs::canonicalize(live_root).map_err(|_| BackupStoreError::IoFailure)?;
    let backup = fs::canonicalize(backup_root).map_err(|_| BackupStoreError::IoFailure)?;
    let lock = CrossProcessWriteLock::try_acquire(&live, now)
        .map_err(|_| BackupStoreError::RecoveryRequired)?;
    let root_ref = codex_adapter::hash_bytes(live.to_string_lossy().to_lowercase().as_bytes());
    Ok((live, backup, root_ref, lock))
}

fn validate_id(id: &str) -> Result<(), BackupStoreError> {
    if id.is_empty()
        || id.len() > 80
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(BackupStoreError::CompatibilityProtected);
    }
    Ok(())
}

fn write_synced(path: &Path, bytes: &[u8]) -> Result<(), BackupStoreError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| BackupStoreError::IoFailure)?;
    file.write_all(bytes)
        .map_err(|_| BackupStoreError::IoFailure)?;
    file.flush().map_err(|_| BackupStoreError::IoFailure)?;
    file.sync_all().map_err(|_| BackupStoreError::IoFailure)
}

#[cfg(not(windows))]
fn sync_directory(path: &Path) -> Result<(), BackupStoreError> {
    OpenOptions::new()
        .read(true)
        .open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| BackupStoreError::IoFailure)
}

#[cfg(windows)]
fn sync_directory(_path: &Path) -> Result<(), BackupStoreError> {
    // Windows 不提供等价于 Unix 目录 fsync 的稳定标准库接口；文件内容已逐个 FlushFileBuffers。
    Ok(())
}

fn material_relative(kind: BackupKind, sequence: u64, id: &str) -> PathBuf {
    match kind {
        BackupKind::Permanent => PathBuf::from(PERMANENT).join(id),
        BackupKind::History => PathBuf::from("history").join(format!("{sequence:020}-{id}")),
    }
}

#[allow(clippy::too_many_arguments)]
fn manifest_bytes(
    id: &str,
    root_ref: &ContentHash,
    material_ref: &Path,
    kind: BackupKind,
    sequence: u64,
    transaction: Option<&SwitchTransactionId>,
    state: BackupState,
    created_at: UnixMillis,
    config: &Observed,
    auth_existed: bool,
    auth_length: u64,
    auth_hash: Option<&ContentHash>,
    auth_readonly: bool,
) -> Vec<u8> {
    format!("version={MANIFEST_VERSION}\nschema=codextools.backup.v2\nid={id}\nroot_ref={}\nkind={}\nsequence={sequence}\nmaterial_ref={}\nreason={}\ntransaction={}\nstate={}\ncreated_at={}\nconfig.existed={}\nconfig.length={}\nconfig.hash={}\nconfig.readonly={}\nconfig.encrypted=false\nauth.existed={}\nauth.length={}\nauth.hash={}\nauth.readonly={}\nauth.encrypted=true\n",
        root_ref.as_str(), kind_str(kind), material_ref.to_string_lossy(), if kind == BackupKind::Permanent { "first_import" } else { "switch_history" }, transaction.map_or("none", SwitchTransactionId::as_str), state_str(state), created_at.value(), config.existed, config.length, config.hash.as_ref().map_or("absent", ContentHash::as_str), config.readonly, auth_existed, auth_length, auth_hash.map_or("absent", ContentHash::as_str), auth_readonly).into_bytes()
}

fn backup_entropy(
    root_ref: &ContentHash,
    kind: BackupKind,
    sequence: u64,
    material_ref: &Path,
    id: &str,
    role: &str,
    hash: &ContentHash,
) -> Vec<u8> {
    format!(
        "codextools:backup:v2:{}:{}:{sequence}:{}:{id}:{role}:{}",
        root_ref.as_str(),
        kind_str(kind),
        material_ref.to_string_lossy(),
        hash.as_str()
    )
    .into_bytes()
}

fn kind_str(kind: BackupKind) -> &'static str {
    match kind {
        BackupKind::Permanent => "permanent",
        BackupKind::History => "history",
    }
}
fn state_str(state: BackupState) -> &'static str {
    match state {
        BackupState::Ready => "ready",
        BackupState::Protected => "protected",
    }
}

fn validate_material(root: &Path, record: &BackupRecord) -> Result<(), BackupStoreError> {
    validate_material_at(&DpapiCurrentUser, root, &record.material_ref, record).map(|_| ())
}

fn validate_material_at(
    protector: &DpapiCurrentUser,
    root: &Path,
    relative: &Path,
    record: &BackupRecord,
) -> Result<LoadedBackupMaterial, BackupStoreError> {
    load_material_at(protector, root, relative, record)
}

struct LoadedBackupMaterial {
    config: Option<Vec<u8>>,
    auth: Option<Vec<u8>>,
    config_readonly: bool,
    auth_readonly: bool,
}
impl Drop for LoadedBackupMaterial {
    fn drop(&mut self) {
        if let Some(auth) = self.auth.as_mut() {
            auth.zeroize();
        }
    }
}
impl Clone for LoadedBackupMaterial {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            auth: self.auth.clone(),
            config_readonly: self.config_readonly,
            auth_readonly: self.auth_readonly,
        }
    }
}

fn load_material(
    protector: &DpapiCurrentUser,
    root: &Path,
    record: &BackupRecord,
) -> Result<LoadedBackupMaterial, BackupStoreError> {
    load_material_at(protector, root, &record.material_ref, record)
}

fn load_material_at(
    protector: &DpapiCurrentUser,
    root: &Path,
    relative: &Path,
    record: &BackupRecord,
) -> Result<LoadedBackupMaterial, BackupStoreError> {
    let directory = checked_path(root, relative, true)?;
    let manifest_path = directory.join("manifest.v2");
    if !manifest_path.exists() {
        return load_legacy_material(protector, root, &directory, record);
    }
    ensure_no_reparse(root, &manifest_path)?;
    let manifest = secure_read_contained_file(root, &manifest_path, 64 * 1024)
        .map_err(|_| BackupStoreError::CorruptMaterial)?;
    if codex_adapter::hash_bytes(&manifest) != record.manifest_hash {
        return Err(BackupStoreError::CorruptMaterial);
    }
    let manifest_text =
        std::str::from_utf8(&manifest).map_err(|_| BackupStoreError::CorruptMaterial)?;
    let values = parse_manifest(manifest_text)?;
    if values.len() != 21
        || values.get("version") != Some(&"2")
        || values.get("schema") != Some(&"codextools.backup.v2")
        || values.get("id") != Some(&record.id.as_str())
        || values.get("root_ref") != Some(&record.root_ref.as_str())
        || values.get("kind") != Some(&kind_str(record.kind))
        || values.get("sequence") != Some(&record.sequence.to_string().as_str())
        || values.get("material_ref") != Some(&record.material_ref.to_string_lossy().as_ref())
        || values.get("state") != Some(&state_str(record.state))
        || values.get("created_at") != Some(&record.created_at.value().to_string().as_str())
        || values.get("config.encrypted") != Some(&"false")
        || values.get("auth.encrypted") != Some(&"true")
    {
        return Err(BackupStoreError::CorruptMaterial);
    }
    let expected_transaction = record
        .transaction_id
        .as_ref()
        .map_or("none", SwitchTransactionId::as_str);
    if values.get("transaction") != Some(&expected_transaction)
        || values.get("reason")
            != Some(&if record.kind == BackupKind::Permanent {
                "first_import"
            } else {
                "switch_history"
            })
    {
        return Err(BackupStoreError::CorruptMaterial);
    }
    let config_readonly = parse_manifest_bool(&values, "config.readonly")?;
    let auth_readonly = parse_manifest_bool(&values, "auth.readonly")?;
    let config_path = directory.join("config.bin");
    let auth_path = directory.join("auth.dpapi");
    let config = match values.get("config.existed") {
        Some(&"true") => Some(
            secure_read_contained_file(root, &config_path, 1024 * 1024)
                .map_err(|_| BackupStoreError::CorruptMaterial)?,
        ),
        Some(&"false") if !config_path.exists() => None,
        _ => return Err(BackupStoreError::CorruptMaterial),
    };
    let auth = match values.get("auth.existed") {
        Some(&"true") => {
            let hash = ContentHash::parse(
                values
                    .get("auth.hash")
                    .ok_or(BackupStoreError::CorruptMaterial)?,
            )
            .map_err(|_| BackupStoreError::CorruptMaterial)?;
            let encrypted = secure_read_contained_file(root, &auth_path, 2 * 1024 * 1024)
                .map_err(|_| BackupStoreError::CorruptMaterial)?;
            let entropy = backup_entropy(
                &record.root_ref,
                record.kind,
                record.sequence,
                &record.material_ref,
                &record.id,
                "auth",
                &hash,
            );
            Some(Zeroizing::new(
                protector
                    .unprotect(&entropy, &encrypted, |plain| Ok(plain.to_vec()))
                    .map_err(|_| BackupStoreError::CorruptMaterial)?,
            ))
        }
        Some(&"false") if !auth_path.exists() => None,
        _ => return Err(BackupStoreError::CorruptMaterial),
    };
    let valid = config.as_ref().map_or(0, |b| b.len() as u64)
        == parse_manifest_u64(&values, "config.length")?
        && auth.as_ref().map_or(0, |b| b.len() as u64)
            == parse_manifest_u64(&values, "auth.length")?
        && config
            .as_ref()
            .map(|bytes| codex_adapter::hash_bytes(bytes))
            .as_ref()
            .map(ContentHash::as_str)
            == values
                .get("config.hash")
                .copied()
                .filter(|v| *v != "absent")
        && auth
            .as_ref()
            .map(|bytes| codex_adapter::hash_bytes(bytes))
            .as_ref()
            .map(ContentHash::as_str)
            == values.get("auth.hash").copied().filter(|v| *v != "absent");
    if !valid {
        return Err(BackupStoreError::CorruptMaterial);
    }
    Ok(LoadedBackupMaterial {
        config,
        auth: auth.as_ref().map(|bytes| bytes.to_vec()),
        config_readonly,
        auth_readonly,
    })
}

fn load_legacy_material(
    protector: &DpapiCurrentUser,
    root: &Path,
    directory: &Path,
    record: &BackupRecord,
) -> Result<LoadedBackupMaterial, BackupStoreError> {
    let manifest_path = directory.join("manifest.v1");
    let manifest = secure_read_contained_file(root, &manifest_path, 64 * 1024)
        .map_err(|_| BackupStoreError::CorruptMaterial)?;
    if codex_adapter::hash_bytes(&manifest) != record.manifest_hash {
        return Err(BackupStoreError::CorruptMaterial);
    }
    let text = std::str::from_utf8(&manifest).map_err(|_| BackupStoreError::CorruptMaterial)?;
    let values = parse_manifest(text)?;
    if values.len() != 18
        || values.get("version") != Some(&"1")
        || values.get("id") != Some(&record.id.as_str())
        || values.get("kind") != Some(&kind_str(record.kind))
        || values.get("sequence") != Some(&record.sequence.to_string().as_str())
        || values.get("state") != Some(&state_str(record.state))
        || values.get("created_at") != Some(&record.created_at.value().to_string().as_str())
        || values.get("config.encrypted") != Some(&"false")
        || values.get("auth.encrypted") != Some(&"true")
    {
        return Err(BackupStoreError::CorruptMaterial);
    }
    let transaction = record
        .transaction_id
        .as_ref()
        .map_or("none", SwitchTransactionId::as_str);
    if values.get("transaction") != Some(&transaction)
        || values.get("reason")
            != Some(&if record.kind == BackupKind::Permanent {
                "first_import"
            } else {
                "switch_history"
            })
    {
        return Err(BackupStoreError::CorruptMaterial);
    }
    let config_readonly = parse_manifest_bool(&values, "config.readonly")?;
    let auth_readonly = parse_manifest_bool(&values, "auth.readonly")?;
    let config_path = directory.join("config.bin");
    let auth_path = directory.join("auth.dpapi");
    let config = match values.get("config.existed") {
        Some(&"true") => Some(
            secure_read_contained_file(root, &config_path, 1024 * 1024)
                .map_err(|_| BackupStoreError::CorruptMaterial)?,
        ),
        Some(&"false") if !config_path.exists() => None,
        _ => return Err(BackupStoreError::CorruptMaterial),
    };
    let auth = match values.get("auth.existed") {
        Some(&"true") => {
            let hash = ContentHash::parse(
                values
                    .get("auth.hash")
                    .ok_or(BackupStoreError::CorruptMaterial)?,
            )
            .map_err(|_| BackupStoreError::CorruptMaterial)?;
            let encrypted = secure_read_contained_file(root, &auth_path, 2 * 1024 * 1024)
                .map_err(|_| BackupStoreError::CorruptMaterial)?;
            let entropy =
                format!("codextools:backup:v1:{}:auth:{}", record.id, hash.as_str()).into_bytes();
            Some(Zeroizing::new(
                protector
                    .unprotect(&entropy, &encrypted, |plain| Ok(plain.to_vec()))
                    .map_err(|_| BackupStoreError::CorruptMaterial)?,
            ))
        }
        Some(&"false") if !auth_path.exists() => None,
        _ => return Err(BackupStoreError::CorruptMaterial),
    };
    let valid = config.as_ref().map_or(0, |bytes| bytes.len() as u64)
        == parse_manifest_u64(&values, "config.length")?
        && auth.as_ref().map_or(0, |bytes| bytes.len() as u64)
            == parse_manifest_u64(&values, "auth.length")?
        && config
            .as_ref()
            .map(|bytes| codex_adapter::hash_bytes(bytes))
            .as_ref()
            .map(ContentHash::as_str)
            == values
                .get("config.hash")
                .copied()
                .filter(|value| *value != "absent")
        && auth
            .as_ref()
            .map(|bytes| codex_adapter::hash_bytes(bytes))
            .as_ref()
            .map(ContentHash::as_str)
            == values
                .get("auth.hash")
                .copied()
                .filter(|value| *value != "absent");
    if !valid {
        return Err(BackupStoreError::CorruptMaterial);
    }
    Ok(LoadedBackupMaterial {
        config,
        auth: auth.as_ref().map(|bytes| bytes.to_vec()),
        config_readonly,
        auth_readonly,
    })
}

fn parse_manifest(
    manifest: &str,
) -> Result<std::collections::BTreeMap<&str, &str>, BackupStoreError> {
    let mut values = std::collections::BTreeMap::new();
    for line in manifest.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or(BackupStoreError::CorruptMaterial)?;
        if key.is_empty() || values.insert(key, value).is_some() {
            return Err(BackupStoreError::CorruptMaterial);
        }
    }
    Ok(values)
}
fn parse_manifest_bool(
    values: &std::collections::BTreeMap<&str, &str>,
    key: &str,
) -> Result<bool, BackupStoreError> {
    match values.get(key) {
        Some(&"true") => Ok(true),
        Some(&"false") => Ok(false),
        _ => Err(BackupStoreError::CorruptMaterial),
    }
}
fn parse_manifest_u64(
    values: &std::collections::BTreeMap<&str, &str>,
    key: &str,
) -> Result<u64, BackupStoreError> {
    values
        .get(key)
        .ok_or(BackupStoreError::CorruptMaterial)?
        .parse()
        .map_err(|_| BackupStoreError::CorruptMaterial)
}

fn checked_path(
    root: &Path,
    relative: &Path,
    must_exist: bool,
) -> Result<PathBuf, BackupStoreError> {
    if relative.is_absolute()
        || !relative
            .components()
            .all(|c| matches!(c, std::path::Component::Normal(_)))
    {
        return Err(BackupStoreError::CorruptMaterial);
    }
    let candidate = root.join(relative);
    ensure_no_reparse(root, &candidate)?;
    if must_exist && !candidate.exists() {
        return Err(BackupStoreError::CorruptMaterial);
    }
    Ok(candidate)
}

fn ensure_no_reparse(root: &Path, candidate: &Path) -> Result<(), BackupStoreError> {
    if !candidate.starts_with(root) {
        return Err(BackupStoreError::CompatibilityProtected);
    }
    let mut current = root.to_path_buf();
    reject_reparse_path(&current)?;
    if let Ok(relative) = candidate.strip_prefix(root) {
        for component in relative.components() {
            current.push(component.as_os_str());
            if current.exists() {
                reject_reparse_path(&current)?;
            }
        }
    }
    Ok(())
}

fn reject_reparse_path(path: &Path) -> Result<(), BackupStoreError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| BackupStoreError::IoFailure)?;
    if metadata.file_type().is_symlink() || metadata_is_reparse(&metadata) {
        Err(BackupStoreError::CompatibilityProtected)
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn metadata_is_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}
#[cfg(not(windows))]
fn metadata_is_reparse(_metadata: &fs::Metadata) -> bool {
    false
}

fn remove_checked_dir(root: &Path, relative: &Path) -> Result<(), BackupStoreError> {
    let path = checked_path(root, relative, true)?;
    secure_validate_contained_directory(root, &path)
        .map_err(|_| BackupStoreError::CompatibilityProtected)?;
    remove_tree_no_follow(&path).map_err(|_| BackupStoreError::RecoveryRequired)
}
fn repo_error(_: codex_application::RepositoryError) -> BackupStoreError {
    BackupStoreError::RepositoryFailure
}

struct CleanupDir {
    path: PathBuf,
    armed: bool,
}
impl CleanupDir {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }
    fn disarm(&mut self) {
        self.armed = false;
    }
    fn cleanup(&mut self) -> Result<(), BackupStoreError> {
        if self.armed {
            remove_tree_no_follow(&self.path).map_err(|_| BackupStoreError::RecoveryRequired)?;
            self.armed = false;
        }
        Ok(())
    }
}
impl Drop for CleanupDir {
    fn drop(&mut self) {
        if self.armed {
            let _ = remove_tree_no_follow(&self.path);
        }
    }
}

fn cleanup_unreferenced_stages(
    root: &Path,
    operations: &[BackupRecoveryRecord],
) -> Result<(), BackupStoreError> {
    let referenced = operations
        .iter()
        .filter_map(|operation| operation.pending_ref.as_ref())
        .collect::<std::collections::BTreeSet<_>>();
    for entry in fs::read_dir(root).map_err(|_| BackupStoreError::IoFailure)? {
        let entry = entry.map_err(|_| BackupStoreError::IoFailure)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(BackupStoreError::CompatibilityProtected);
        };
        if !name.starts_with(".stage-") {
            continue;
        }
        let relative = PathBuf::from(name);
        if !referenced.contains(&relative) {
            remove_checked_dir(root, &relative)?;
        }
    }
    Ok(())
}

fn remove_tree_no_follow(path: &Path) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || metadata_is_reparse(&metadata) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "reparse point rejected",
        ));
    }
    if metadata.is_file() {
        return fs::remove_file(path);
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let child = entry.path();
        let child_metadata = fs::symlink_metadata(&child)?;
        if child_metadata.file_type().is_symlink() || metadata_is_reparse(&child_metadata) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "reparse point rejected",
            ));
        }
        if child_metadata.is_dir() {
            remove_tree_no_follow(&child)?;
        } else if child_metadata.is_file() {
            fs::remove_file(child)?;
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unsupported file type",
            ));
        }
    }
    fs::remove_dir(path)
}
