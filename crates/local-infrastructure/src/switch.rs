use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use codex_adapter::{CodexAdapter, hash_bytes};
use codex_application::{
    Clock, CompatibilityReason, EntityKind, FileBaseline, RepositoryError, ScanStatus,
    StabilityWindow, SwitchErrorCode, SwitchExecutionError, SwitchPlan, SwitchTransactionRecord,
    SwitchTransactionRepository,
};
use codex_domain::{ContentHash, FileRole, SwitchTransaction, SwitchTransactionState, UnixMillis};
use windows_platform::{
    DpapiCurrentUser, FileIdentity128, PinnedLiveFile, RelativePathObservation, RootNamespacePin,
    SensitiveHandleState, SensitiveTempFile, probe_sensitive_temp_capabilities,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    SensitiveDestinationGuard, SensitiveDestinationState, SensitiveTempLifecycle,
    SensitiveTempOwnerRecord, SensitiveTempPhase as OwnerPhase, SensitiveTempRole,
    SqliteMetadataRepository,
};

const SNAPSHOT_VERSION: u32 = 3;
const AUTH_SNAPSHOT_ENVELOPE_VERSION: u32 = 1;
const AUTH_SNAPSHOT_MAGIC: &[u8] = b"CODEXTOOLS-SWITCH-AUTH-SNAPSHOT\0";
const CONFIG_NAME: &str = "config.toml";
const AUTH_NAME: &str = "auth.json";

/// 可注入的敏感临时文件 I/O 边界。生产实现仍直接使用 `std::fs`；测试实现可让真实
/// `File` 的 write/flush/sync/reread/remove 操作在精确边界失败。
pub trait SensitiveTempIo {
    fn create_delete_armed(
        &mut self,
        root: &RootNamespacePin,
        basename: &str,
    ) -> io::Result<SensitiveTempFile> {
        SensitiveTempFile::create_delete_armed(root, basename)
    }

    fn clear_delete_on_close(
        &mut self,
        file: &mut SensitiveTempFile,
        root: &RootNamespacePin,
    ) -> io::Result<()> {
        file.clear_delete_on_close(root)
    }

    fn write(&mut self, file: &mut SensitiveTempFile, bytes: &[u8]) -> io::Result<usize> {
        file.write_once(bytes)
    }

    fn flush(&mut self, file: &mut SensitiveTempFile) -> io::Result<()> {
        file.flush()
    }

    fn sync_all(&mut self, file: &SensitiveTempFile) -> io::Result<()> {
        file.sync_all()
    }

    fn reread(&mut self, file: &mut SensitiveTempFile) -> io::Result<Zeroizing<Vec<u8>>> {
        file.reread(16 * 1024 * 1024)
    }

    fn arm_delete_on_close(&mut self, file: &mut SensitiveTempFile) -> io::Result<()> {
        file.arm_delete_on_close()
    }

    fn rename_relative(
        &mut self,
        file: &mut SensitiveTempFile,
        root: &RootNamespacePin,
        publish_basename: &str,
    ) -> io::Result<()> {
        file.rename_relative(root, publish_basename)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct StdSensitiveTempIo;

impl SensitiveTempIo for StdSensitiveTempIo {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedSensitiveTempIdentity(FileIdentity128);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultPoint {
    BeforeLock,
    AfterLock,
    SnapshotConfig,
    SnapshotAuthentication,
    SnapshotManifest,
    AfterSnapshotManifest,
    StageConfigWrite,
    StageConfigFlush,
    StageConfigReread,
    AfterStageConfig,
    StageAuthenticationWrite,
    StageAuthenticationFlush,
    StageAuthenticationReread,
    AfterStageAuthentication,
    StagedTargetParse,
    BeforeConfigReplace,
    AfterConfigMakeWritable,
    AfterConfigReplace,
    BeforeAuthenticationReplace,
    AfterAuthenticationMakeWritable,
    AfterAuthenticationReplace,
    OriginalPathVerify,
    BeforeCommittedState,
    RollbackConfig,
    RollbackAuthentication,
    TerminalCleanupAuthenticationSnapshot,
    TerminalCleanupConfigSnapshot,
    TerminalCleanupAuthenticationStage,
    TerminalCleanupConfigStage,
    TerminalCleanupManifest,
    TerminalCleanupDirectory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultDisposition {
    Fail,
    Interrupt,
}

pub trait FaultInjector {
    fn check(&mut self, point: FaultPoint) -> Option<FaultDisposition>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LockOwnerInfo {
    pub process_id: u32,
    pub acquired_at: UnixMillis,
}

impl LockOwnerInfo {
    #[must_use]
    pub fn is_stale(self, now: UnixMillis, threshold_ms: i64) -> bool {
        now.value().saturating_sub(self.acquired_at.value()) > threshold_ms
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockDiagnostic {
    Missing,
    Owner(LockOwnerInfo),
    Corrupt,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> UnixMillis {
        let value = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_millis();
        UnixMillis::new(i64::try_from(value).expect("timestamp fits i64")).expect("timestamp")
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ThreadStabilityWindow {
    duration: Duration,
}
impl ThreadStabilityWindow {
    #[must_use]
    pub const fn new(duration: Duration) -> Self {
        Self { duration }
    }
}
impl StabilityWindow for ThreadStabilityWindow {
    fn between_observations(&mut self, _: &Path) -> Result<(), SwitchExecutionError> {
        thread::sleep(self.duration);
        Ok(())
    }
}

pub struct CrossProcessWriteLock {
    file: Option<File>,
    root: Option<RootNamespacePin>,
    owner: LockOwnerInfo,
}

impl std::fmt::Debug for CrossProcessWriteLock {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CrossProcessWriteLock")
            .field("path", &"[REDACTED_PATH]")
            .field("owner", &self.owner)
            .finish()
    }
}

impl CrossProcessWriteLock {
    #[must_use]
    pub fn read_diagnostic(root: &Path) -> LockDiagnostic {
        let root = match pin_write_lock_root(root) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return LockDiagnostic::Missing;
            }
            Err(_) => return LockDiagnostic::Corrupt,
        };
        let mut file = match PinnedLiveFile::open_lock_diagnostic(&root, ".codextools-write.lock") {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return LockDiagnostic::Missing;
            }
            Err(_) => return LockDiagnostic::Corrupt,
        };
        let bytes = match file.reread(4096) {
            Ok(value) => value,
            Err(_) => return LockDiagnostic::Corrupt,
        };
        let text = match std::str::from_utf8(&bytes) {
            Ok(value) => value,
            Err(_) => return LockDiagnostic::Corrupt,
        };
        let mut process_id = None;
        let mut acquired_at = None;
        for line in text.lines() {
            if let Some(value) = line.strip_prefix("pid=") {
                process_id = value.parse::<u32>().ok();
            }
            if let Some(value) = line.strip_prefix("acquired_at=") {
                acquired_at = value
                    .parse::<i64>()
                    .ok()
                    .and_then(|value| UnixMillis::new(value).ok());
            }
        }
        match (process_id, acquired_at) {
            (Some(process_id), Some(acquired_at)) => LockDiagnostic::Owner(LockOwnerInfo {
                process_id,
                acquired_at,
            }),
            _ => LockDiagnostic::Corrupt,
        }
    }
    pub fn try_acquire(root: &Path, now: UnixMillis) -> Result<Self, SwitchExecutionError> {
        if !root.is_absolute() {
            return Err(SwitchExecutionError::IoFailure);
        }
        let root = pin_write_lock_root(root).map_err(|error| {
            if matches!(
                error.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::WouldBlock
            ) || matches!(error.raw_os_error(), Some(32 | 33))
            {
                SwitchExecutionError::Busy
            } else {
                SwitchExecutionError::IoFailure
            }
        })?;
        Self::try_acquire_pinned(root, now)
    }

    pub(crate) fn try_acquire_pinned(
        root: RootNamespacePin,
        now: UnixMillis,
    ) -> Result<Self, SwitchExecutionError> {
        let mut file = root
            .open_write_lock(".codextools-write.lock")
            .map_err(|error| {
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::WouldBlock
                ) || matches!(error.raw_os_error(), Some(32 | 33))
                {
                    SwitchExecutionError::Busy
                } else {
                    SwitchExecutionError::IoFailure
                }
            })?;
        let owner = LockOwnerInfo {
            process_id: std::process::id(),
            acquired_at: now,
        };
        let diagnostic = format!(
            "version=1\npid={}\nacquired_at={}\n",
            owner.process_id,
            now.value()
        );
        file.write_all(diagnostic.as_bytes())
            .map_err(|_| SwitchExecutionError::IoFailure)?;
        file.sync_all()
            .map_err(|_| SwitchExecutionError::IoFailure)?;
        Ok(Self {
            file: Some(file),
            root: Some(root),
            owner,
        })
    }
    pub(crate) fn root_pin(&self) -> Result<&RootNamespacePin, SwitchExecutionError> {
        self.root.as_ref().ok_or(SwitchExecutionError::IoFailure)
    }
    pub const fn owner(&self) -> LockOwnerInfo {
        self.owner
    }
    pub fn release(&mut self) -> Result<(), SwitchExecutionError> {
        if let Some(file) = self.file.take() {
            drop(file);
        }
        if let Some(root) = self.root.take() {
            drop(root);
        }
        Ok(())
    }
}

fn pin_write_lock_root(root: &Path) -> io::Result<RootNamespacePin> {
    #[cfg(windows)]
    if matches!(
        root.components().next(),
        Some(std::path::Component::Prefix(prefix))
            if matches!(prefix.kind(), std::path::Prefix::VerbatimDisk(_))
    ) {
        return RootNamespacePin::acquire_canonical(root);
    }
    RootNamespacePin::acquire(root)
}
impl Drop for CrossProcessWriteLock {
    fn drop(&mut self) {
        let _ = self.release();
    }
}

#[derive(Clone, Eq, PartialEq)]
struct ObservedFile {
    existed: bool,
    bytes: Zeroizing<Vec<u8>>,
    hash: Option<ContentHash>,
    readonly: bool,
}

impl ObservedFile {
    fn baseline(&self) -> FileBaseline {
        match &self.hash {
            Some(hash) => FileBaseline::present(self.bytes.len() as u64, hash.clone()),
            None => FileBaseline::absent(),
        }
    }
}

#[derive(Clone)]
struct SnapshotManifest {
    config: ObservedFile,
    auth: ObservedFile,
    config_target: FileEvidence,
    auth_target: FileEvidence,
}

#[derive(Clone, Eq, PartialEq)]
struct FileEvidence {
    existed: bool,
    length: usize,
    hash: Option<ContentHash>,
    readonly: bool,
}

pub struct SwitchExecutor<'a, C, W, F, I = StdSensitiveTempIo> {
    repository: &'a mut SqliteMetadataRepository,
    clock: &'a C,
    stability: &'a mut W,
    faults: &'a mut F,
    sensitive_io: I,
}

impl<'a, C: Clock, W: StabilityWindow, F: FaultInjector>
    SwitchExecutor<'a, C, W, F, StdSensitiveTempIo>
{
    pub fn new(
        repository: &'a mut SqliteMetadataRepository,
        clock: &'a C,
        stability: &'a mut W,
        faults: &'a mut F,
    ) -> Self {
        Self {
            repository,
            clock,
            stability,
            faults,
            sensitive_io: StdSensitiveTempIo,
        }
    }
}

impl<'a, C: Clock, W: StabilityWindow, F: FaultInjector, I: SensitiveTempIo>
    SwitchExecutor<'a, C, W, F, I>
{
    pub fn new_with_sensitive_temp_io(
        repository: &'a mut SqliteMetadataRepository,
        clock: &'a C,
        stability: &'a mut W,
        faults: &'a mut F,
        sensitive_io: I,
    ) -> Self {
        Self {
            repository,
            clock,
            stability,
            faults,
            sensitive_io,
        }
    }

    pub fn execute(
        &mut self,
        plan: &SwitchPlan,
    ) -> Result<SwitchTransactionRecord, SwitchExecutionError> {
        let now = self.clock.now();
        ensure_plan_fresh(plan, now)?;
        let root = fs::canonicalize(plan.root()).map_err(|_| SwitchExecutionError::IoFailure)?;
        validate_target(plan, plan.target_config(), plan.target_auth())?;
        self.fault(FaultPoint::BeforeLock)?;
        let lock = CrossProcessWriteLock::try_acquire(&root, self.clock.now())?;
        ensure_plan_fresh(plan, self.clock.now())?;
        let root_pin = RootNamespacePin::acquire_canonical(&root).map_err(map_root_pin_error)?;
        probe_sensitive_temp_capabilities(&root_pin).map_err(|_error| {
            SwitchExecutionError::CompatibilityProtected(CompatibilityReason::IoUnavailable)
        })?;
        let root_ref = hash_bytes(root.to_string_lossy().to_lowercase().as_bytes());
        self.reconcile_sensitive_temp_owners(&root_pin, &root_ref)?;
        self.legacy_sensitive_temp_preflight(&root_pin, &root_ref)?;
        self.reconcile_terminal_material(&root)?;
        if !self
            .repository
            .list_blocking_switch_transactions(&root_ref)?
            .is_empty()
        {
            drop(lock);
            return Err(SwitchExecutionError::RecoveryRequired);
        }
        let mut record = SwitchTransactionRecord {
            transaction: SwitchTransaction::new(
                plan.id().clone(),
                root_ref.clone(),
                plan.config_source().sha256.clone(),
                plan.auth_source().sha256.clone(),
                hash_bytes(plan.target_config()),
                hash_bytes(plan.target_auth()),
                plan.provider_id().clone(),
                plan.model_id().clone(),
                plan.auth_fingerprint().clone(),
                now,
            ),
            last_error: None,
            snapshot_manifest_hash: None,
        };
        if let Err(error) = self.repository.create_switch_transaction(&record) {
            drop(lock);
            return Err(map_transaction_create_error(error));
        }
        let result = self.execute_locked(plan, &root, &root_pin, &mut record);
        let outcome = match result {
            Ok(()) => Ok(record),
            Err(SwitchExecutionError::Interrupted) => {
                match self.reconcile_sensitive_temp_owners(&root_pin, &root_ref) {
                    Ok(()) => Err(SwitchExecutionError::Interrupted),
                    Err(_) => Err(SwitchExecutionError::RecoveryRequired),
                }
            }
            Err(error) => Err(self.finish_failure(&root, &mut record, error)),
        };
        drop(lock);
        outcome
    }

    fn execute_locked(
        &mut self,
        plan: &SwitchPlan,
        root: &Path,
        root_pin: &RootNamespacePin,
        record: &mut SwitchTransactionRecord,
    ) -> Result<(), SwitchExecutionError> {
        self.advance(record, SwitchTransactionState::LockAcquired, None)?;
        self.fault(FaultPoint::AfterLock)?;
        ensure_plan_fresh(plan, self.clock.now())?;

        let first = observe_pair(root)?;
        if first.0.baseline() != *plan.config_source() || first.1.baseline() != *plan.auth_source()
        {
            return Err(SwitchExecutionError::PlanStale);
        }
        self.stability.between_observations(root)?;
        ensure_plan_fresh(plan, self.clock.now())?;
        let second = observe_pair(root)?;
        if first.0.baseline() != second.0.baseline() || first.1.baseline() != second.1.baseline() {
            return Err(SwitchExecutionError::PlanStale);
        }

        let manifest_hash =
            self.create_snapshot(root, record.transaction.id(), &second.0, &second.1, plan)?;
        record.snapshot_manifest_hash = Some(manifest_hash);
        self.advance(record, SwitchTransactionState::SnapshotCreated, None)?;
        self.fault(FaultPoint::AfterSnapshotManifest)?;

        let config_stage = self.stage_file(
            root_pin,
            record,
            plan.target_config(),
            second.0.readonly,
            FileRole::Config,
        )?;
        self.fault(FaultPoint::AfterStageConfig)?;
        let auth_stage = self.stage_file(
            root_pin,
            record,
            plan.target_auth(),
            second.1.readonly,
            FileRole::Authentication,
        )?;
        self.fault(FaultPoint::AfterStageAuthentication)?;
        self.fault(FaultPoint::StagedTargetParse)?;
        validate_target(plan, plan.target_config(), plan.target_auth())?;
        self.advance(record, SwitchTransactionState::TargetsStaged, None)?;

        self.fault(FaultPoint::BeforeConfigReplace)?;
        ensure_plan_fresh(plan, self.clock.now())?;
        if !pair_matches_observation(&observe_pair(root)?, &second) {
            return Err(SwitchExecutionError::PlanStale);
        }
        self.advance(record, SwitchTransactionState::Replacing, None)?;
        self.atomic_replace_live(root_pin, config_stage, record, FileRole::Config)?;
        self.fault(FaultPoint::AfterConfigReplace)?;
        self.fault(FaultPoint::BeforeAuthenticationReplace)?;
        let mixed = observe_pair(root).map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        if !file_matches_target(&mixed.0, plan.target_config(), second.0.readonly)
            || !file_matches_observation(&mixed.1, &second.1)
        {
            return Err(SwitchExecutionError::RecoveryRequired);
        }
        self.atomic_replace_live(root_pin, auth_stage, record, FileRole::Authentication)?;
        self.fault(FaultPoint::AfterAuthenticationReplace)?;
        let replaced = observe_pair(root).map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        if !pair_matches_target(&replaced, plan, &second) {
            return Err(SwitchExecutionError::RecoveryRequired);
        }
        self.advance(record, SwitchTransactionState::TargetsReplaced, None)?;

        self.fault(FaultPoint::OriginalPathVerify)?;
        let actual = observe_pair(root).map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        if !pair_matches_target(&actual, plan, &second) {
            return Err(SwitchExecutionError::RecoveryRequired);
        }
        validate_target(plan, &actual.0.bytes, &actual.1.bytes)
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        self.advance(record, SwitchTransactionState::Verified, None)?;
        self.fault(FaultPoint::BeforeCommittedState)?;
        let before_commit =
            observe_pair(root).map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        if !pair_matches_target(&before_commit, plan, &second) {
            return Err(SwitchExecutionError::RecoveryRequired);
        }
        self.finalize_terminal(record, root, SwitchTransactionState::Committed, None)
    }

    pub fn recover_root(
        &mut self,
        root: &Path,
    ) -> Result<Vec<SwitchTransactionRecord>, SwitchExecutionError> {
        let root = fs::canonicalize(root).map_err(|_| SwitchExecutionError::IoFailure)?;
        let root_ref = hash_bytes(root.to_string_lossy().to_lowercase().as_bytes());
        let _lock = CrossProcessWriteLock::try_acquire(&root, self.clock.now())?;
        let root_pin = RootNamespacePin::acquire_canonical(&root).map_err(map_root_pin_error)?;
        probe_sensitive_temp_capabilities(&root_pin).map_err(|_error| {
            SwitchExecutionError::CompatibilityProtected(CompatibilityReason::IoUnavailable)
        })?;
        self.reconcile_sensitive_temp_owners(&root_pin, &root_ref)?;
        self.legacy_sensitive_temp_preflight(&root_pin, &root_ref)?;
        self.reconcile_terminal_material(&root)?;
        let records = self
            .repository
            .list_unfinished_switch_transactions(&root_ref)?;
        let mut recovered = Vec::new();
        for mut record in records {
            let state = record.transaction.state();
            let current = observe_pair(&root)?;
            let requires_snapshot = record_requires_snapshot(&record);
            let manifest = if requires_snapshot {
                match load_snapshot(
                    &root,
                    record.transaction.id(),
                    record.snapshot_manifest_hash.as_ref(),
                ) {
                    Ok(manifest) if snapshot_matches_transaction(&manifest, &record) => {
                        Some(manifest)
                    }
                    _ => None,
                }
            } else {
                None
            };
            let snapshot_valid = !requires_snapshot || manifest.is_some();
            let source = manifest.as_ref().map_or_else(
                || {
                    pair_matches_hashes(
                        &current,
                        record.transaction.config_source(),
                        record.transaction.auth_source(),
                    )
                },
                |manifest| pair_matches_snapshot_source(&current, manifest),
            );
            let target = manifest
                .as_ref()
                .is_some_and(|manifest| pair_matches_snapshot_target(&current, manifest));
            let known_components = manifest
                .as_ref()
                .is_some_and(|manifest| pair_components_are_known(&current, manifest));
            let result = match state {
                _ if !snapshot_valid => Err(SwitchExecutionError::RecoveryRequired),
                SwitchTransactionState::Planned | SwitchTransactionState::LockAcquired
                    if source =>
                {
                    self.finalize_terminal(
                        &mut record,
                        &root,
                        SwitchTransactionState::RolledBack,
                        None,
                    )
                }
                SwitchTransactionState::SnapshotCreated
                | SwitchTransactionState::TargetsStaged
                | SwitchTransactionState::Replacing
                | SwitchTransactionState::TargetsReplaced
                | SwitchTransactionState::Verified
                | SwitchTransactionState::RollingBack
                    if source =>
                {
                    if state != SwitchTransactionState::RollingBack {
                        self.advance(&mut record, SwitchTransactionState::RollingBack, None)?;
                    }
                    self.finalize_terminal(
                        &mut record,
                        &root,
                        SwitchTransactionState::RolledBack,
                        None,
                    )
                }
                SwitchTransactionState::TargetsReplaced | SwitchTransactionState::Verified
                    if target =>
                {
                    if validate_record_target(&record, &current.0.bytes, &current.1.bytes).is_err()
                    {
                        Err(SwitchExecutionError::RecoveryRequired)
                    } else {
                        if state == SwitchTransactionState::TargetsReplaced {
                            self.advance(&mut record, SwitchTransactionState::Verified, None)?;
                        }
                        self.finalize_terminal(
                            &mut record,
                            &root,
                            SwitchTransactionState::Committed,
                            None,
                        )
                    }
                }
                SwitchTransactionState::Replacing | SwitchTransactionState::RollingBack
                    if known_components =>
                {
                    self.restore_snapshot(&root, &root_pin, &mut record)
                }
                SwitchTransactionState::Planned
                | SwitchTransactionState::LockAcquired
                | SwitchTransactionState::SnapshotCreated
                | SwitchTransactionState::TargetsStaged
                | SwitchTransactionState::Replacing
                | SwitchTransactionState::TargetsReplaced
                | SwitchTransactionState::Verified
                | SwitchTransactionState::RollingBack => {
                    Err(SwitchExecutionError::RecoveryRequired)
                }
                _ => Ok(()),
            };
            if result.is_err()
                && matches!(
                    record.transaction.state(),
                    SwitchTransactionState::Committed | SwitchTransactionState::RolledBack
                )
            {
                return Err(SwitchExecutionError::RecoveryRequired);
            }
            if result.is_err() {
                let _ =
                    self.force_recovery_required(&mut record, SwitchErrorCode::RecoveryRequired);
            }
            recovered.push(record);
        }
        Ok(recovered)
    }

    fn fail_and_rollback(
        &mut self,
        root: &Path,
        record: &mut SwitchTransactionRecord,
        error: SwitchExecutionError,
    ) -> Result<(), SwitchExecutionError> {
        let pin = RootNamespacePin::acquire_canonical(root).map_err(map_root_pin_error)?;
        self.reconcile_sensitive_temp_owners(&pin, record.transaction.root_ref())?;
        let code = error_code(error);
        record.last_error = Some(code);
        match record.transaction.state() {
            SwitchTransactionState::Planned | SwitchTransactionState::LockAcquired => {
                self.finalize_terminal(record, root, SwitchTransactionState::RolledBack, Some(code))
            }
            SwitchTransactionState::Replacing
            | SwitchTransactionState::TargetsReplaced
            | SwitchTransactionState::Verified => self.restore_snapshot(root, &pin, record),
            SwitchTransactionState::Committed
            | SwitchTransactionState::RolledBack
            | SwitchTransactionState::RecoveryRequired => Ok(()),
            _ => {
                self.advance(record, SwitchTransactionState::RollingBack, Some(code))?;
                self.finalize_terminal(record, root, SwitchTransactionState::RolledBack, Some(code))
            }
        }
    }

    fn finish_failure(
        &mut self,
        root: &Path,
        record: &mut SwitchTransactionRecord,
        error: SwitchExecutionError,
    ) -> SwitchExecutionError {
        if error == SwitchExecutionError::RecoveryRequired {
            if self
                .repository
                .list_sensitive_temp_owners(record.transaction.root_ref())
                .is_ok_and(|owners| {
                    owners
                        .iter()
                        .any(|owner| owner.transaction_id == *record.transaction.id())
                })
            {
                return SwitchExecutionError::RecoveryRequired;
            }
            if !record.transaction.state().is_terminal() {
                let _ = self.force_recovery_required(record, SwitchErrorCode::RecoveryRequired);
            }
            return SwitchExecutionError::RecoveryRequired;
        }
        if self.fail_and_rollback(root, record, error).is_err()
            || record.transaction.state() == SwitchTransactionState::RecoveryRequired
        {
            if self
                .repository
                .list_sensitive_temp_owners(record.transaction.root_ref())
                .is_ok_and(|owners| {
                    owners
                        .iter()
                        .any(|owner| owner.transaction_id == *record.transaction.id())
                })
            {
                return SwitchExecutionError::RecoveryRequired;
            }
            if !record.transaction.state().is_terminal() {
                let _ = self.force_recovery_required(record, SwitchErrorCode::RecoveryRequired);
            }
            SwitchExecutionError::RecoveryRequired
        } else {
            error
        }
    }

    fn restore_snapshot(
        &mut self,
        root: &Path,
        root_pin: &RootNamespacePin,
        record: &mut SwitchTransactionRecord,
    ) -> Result<(), SwitchExecutionError> {
        if record.transaction.state() != SwitchTransactionState::RollingBack {
            self.advance(
                record,
                SwitchTransactionState::RollingBack,
                record.last_error.or(Some(SwitchErrorCode::IoFailure)),
            )?;
        }
        let manifest = match load_snapshot(
            root,
            record.transaction.id(),
            record.snapshot_manifest_hash.as_ref(),
        ) {
            Ok(manifest) if snapshot_matches_transaction(&manifest, record) => manifest,
            _ => {
                let _ = self.force_recovery_required(record, SwitchErrorCode::SnapshotInvalid);
                return Err(SwitchExecutionError::RecoveryRequired);
            }
        };
        if let Err(error) = self
            .restore_role(
                root,
                root_pin,
                record.transaction.id(),
                FileRole::Config,
                &manifest.config,
            )
            .and_then(|_| {
                self.restore_role(
                    root,
                    root_pin,
                    record.transaction.id(),
                    FileRole::Authentication,
                    &manifest.auth,
                )
            })
        {
            let has_owner = self
                .repository
                .list_sensitive_temp_owners(record.transaction.root_ref())
                .is_ok_and(|owners| {
                    owners
                        .iter()
                        .any(|owner| owner.transaction_id == *record.transaction.id())
                });
            if !has_owner {
                let _ = self.force_recovery_required(record, SwitchErrorCode::RecoveryRequired);
            }
            return Err(error);
        }
        let observed = observe_pair(root)?;
        if !pair_matches_snapshot_source(&observed, &manifest) {
            self.force_recovery_required(record, SwitchErrorCode::RecoveryRequired)?;
            return Err(SwitchExecutionError::RecoveryRequired);
        }
        let owners = self
            .repository
            .list_sensitive_temp_owners(record.transaction.root_ref())?;
        let recovery_owners = owners
            .iter()
            .filter(|owner| {
                owner.transaction_id == *record.transaction.id()
                    && owner.phase == OwnerPhase::Recovery
                    && owner.lifecycle == SensitiveTempLifecycle::Published
            })
            .count();
        if recovery_owners == 0 {
            self.finalize_terminal(
                record,
                root,
                SwitchTransactionState::RolledBack,
                record.last_error,
            )
        } else if recovery_owners == 2
            && owners
                .iter()
                .filter(|owner| owner.transaction_id == *record.transaction.id())
                .count()
                == 2
        {
            write_cleanup_intent(
                root,
                record.transaction.id(),
                SwitchTransactionState::RolledBack,
            )?;
            let expected = record.transaction.version();
            let updated = record
                .transaction
                .transition(SwitchTransactionState::RolledBack, self.clock.now())
                .map_err(|_| SwitchExecutionError::RepositoryFailure)?;
            let candidate = SwitchTransactionRecord {
                transaction: updated,
                last_error: record.last_error,
                snapshot_manifest_hash: record.snapshot_manifest_hash.clone(),
            };
            self.repository
                .finalize_rolled_back_with_recovery_owners(&candidate, expected)?;
            *record = candidate;
            self.cleanup_transaction_material(root, record.transaction.id())
        } else {
            Err(SwitchExecutionError::RecoveryRequired)
        }
    }

    fn restore_role(
        &mut self,
        root: &Path,
        root_pin: &RootNamespacePin,
        id: &codex_domain::SwitchTransactionId,
        role: FileRole,
        observed: &ObservedFile,
    ) -> Result<(), SwitchExecutionError> {
        self.fault(match role {
            FileRole::Config => FaultPoint::RollbackConfig,
            FileRole::Authentication => FaultPoint::RollbackAuthentication,
        })?;
        let record = self
            .repository
            .get_switch_transaction(id)?
            .ok_or(SwitchExecutionError::RecoveryRequired)?;
        if !observed.existed {
            return self.restore_absent_role(root_pin, &record, role);
        }
        if hash_bytes(&observed.bytes)
            != observed
                .hash
                .clone()
                .ok_or(SwitchExecutionError::SnapshotInvalid)?
        {
            return Err(SwitchExecutionError::SnapshotInvalid);
        }
        if let Some(owner) =
            self.repository
                .get_sensitive_temp_owner(id, OwnerPhase::Recovery, owner_role(role))?
        {
            if owner.lifecycle == SensitiveTempLifecycle::Published {
                let current = observe(&root.join(role_name(role)))?;
                if file_matches_observation(&current, observed) {
                    return Ok(());
                }
                return Err(SwitchExecutionError::RecoveryRequired);
            }
            return Err(SwitchExecutionError::RecoveryRequired);
        }
        let mut prepared = self.begin_sensitive_temp(
            root_pin,
            &record,
            role,
            OwnerPhase::Recovery,
            &observed.bytes,
            observed.readonly,
        )?;
        if write_all_with_io(
            &mut self.sensitive_io,
            &mut prepared.handle,
            &observed.bytes,
        )
        .is_err()
            || self.sensitive_io.flush(&mut prepared.handle).is_err()
            || self.sensitive_io.sync_all(&prepared.handle).is_err()
        {
            return self.cleanup_prepared_sensitive_temp(
                root_pin,
                prepared,
                SwitchExecutionError::IoFailure,
            );
        }
        let reread = match self.sensitive_io.reread(&mut prepared.handle) {
            Ok(bytes) => bytes,
            Err(_) => {
                return self.cleanup_prepared_sensitive_temp(
                    root_pin,
                    prepared,
                    SwitchExecutionError::IoFailure,
                );
            }
        };
        if reread.as_slice() != observed.bytes.as_slice()
            || prepared.handle.set_readonly(false).is_err()
        {
            return self.cleanup_prepared_sensitive_temp(
                root_pin,
                prepared,
                SwitchExecutionError::IoFailure,
            );
        }
        self.publish_recovery_role(root_pin, prepared, observed)?;
        Ok(())
    }

    fn restore_absent_role(
        &mut self,
        root_pin: &RootNamespacePin,
        record: &SwitchTransactionRecord,
        role: FileRole,
    ) -> Result<(), SwitchExecutionError> {
        let role = owner_role(role);
        if let Some(owner) = self.repository.get_sensitive_temp_owner(
            record.transaction.id(),
            OwnerPhase::Recovery,
            role,
        )? {
            if owner.lifecycle == SensitiveTempLifecycle::Published
                && matches!(
                    root_pin.observe_relative(
                        &owner.publish_rel,
                        owner
                            .identity
                            .ok_or(SwitchExecutionError::RecoveryRequired)?,
                    ),
                    RelativePathObservation::Absent
                )
            {
                return Ok(());
            }
            return Err(SwitchExecutionError::RecoveryRequired);
        }
        let live = match PinnedLiveFile::open_delete_intent(root_pin, owner_publish_name(role)) {
            Ok(live) => Some(live),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(_) => return Err(SwitchExecutionError::RecoveryRequired),
        };
        if live.is_none() {
            let mut prepared = self.begin_sensitive_temp(
                root_pin,
                record,
                match role {
                    SensitiveTempRole::Config => FileRole::Config,
                    SensitiveTempRole::Authentication => FileRole::Authentication,
                },
                OwnerPhase::Recovery,
                &[],
                false,
            )?;
            self.repository.transition_sensitive_temp_owner(
                record.transaction.id(),
                OwnerPhase::Recovery,
                role,
                SensitiveTempLifecycle::Owned,
                SensitiveTempLifecycle::Published,
                prepared.owner.version,
                self.clock.now(),
            )?;
            prepared.owner.lifecycle = SensitiveTempLifecycle::Published;
            prepared.owner.version += 1;
            prepared
                .handle
                .arm_delete_on_close()
                .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
            let identity = prepared.handle.identity();
            let temp_rel = prepared.owner.temp_rel.clone();
            drop(prepared.handle);
            if !matches!(
                root_pin.observe_relative(&temp_rel, identity),
                RelativePathObservation::Absent
            ) {
                return Err(SwitchExecutionError::RecoveryRequired);
            }
            return Ok(());
        }
        let live = live.expect("checked above");
        let nonce = sensitive_nonce();
        let now = self.clock.now();
        let mut owner = SensitiveTempOwnerRecord {
            transaction_id: record.transaction.id().clone(),
            root_ref: record.transaction.root_ref().clone(),
            role,
            phase: OwnerPhase::Recovery,
            nonce,
            temp_rel: owner_temp_name(record.transaction.id(), role, OwnerPhase::Recovery, &nonce),
            publish_rel: owner_publish_name(role).to_owned(),
            identity: Some(live.identity()),
            expected_length: 0,
            expected_hash: hash_bytes(&[]),
            expected_readonly: false,
            lifecycle: SensitiveTempLifecycle::PrewriteDeleteArmed,
            destination_guard: None,
            created_at: now,
            updated_at: now,
            version: 1,
        };
        self.repository.create_sensitive_temp_owner(&owner)?;
        self.repository.transition_sensitive_temp_owner(
            record.transaction.id(),
            OwnerPhase::Recovery,
            role,
            SensitiveTempLifecycle::PrewriteDeleteArmed,
            SensitiveTempLifecycle::Owned,
            owner.version,
            self.clock.now(),
        )?;
        owner.lifecycle = SensitiveTempLifecycle::Owned;
        owner.version += 1;
        self.repository.transition_sensitive_temp_owner(
            record.transaction.id(),
            OwnerPhase::Recovery,
            role,
            SensitiveTempLifecycle::Owned,
            SensitiveTempLifecycle::Published,
            owner.version,
            self.clock.now(),
        )?;
        owner.lifecycle = SensitiveTempLifecycle::Published;
        owner.version += 1;
        live.arm_delete_on_close()
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        let identity = live.identity();
        drop(live);
        if !matches!(
            root_pin.observe_relative(&owner.publish_rel, identity),
            RelativePathObservation::Absent
        ) {
            return Err(SwitchExecutionError::RecoveryRequired);
        }
        Ok(())
    }

    fn create_snapshot(
        &mut self,
        root: &Path,
        id: &codex_domain::SwitchTransactionId,
        config: &ObservedFile,
        auth: &ObservedFile,
        plan: &SwitchPlan,
    ) -> Result<ContentHash, SwitchExecutionError> {
        let directory = snapshot_dir(root, id);
        fs::create_dir_all(&directory).map_err(|_| SwitchExecutionError::IoFailure)?;
        self.fault(FaultPoint::SnapshotConfig)?;
        if config.existed {
            write_synced(
                &snapshot_file(root, id, FileRole::Config),
                &config.bytes,
                true,
            )?;
        }
        self.fault(FaultPoint::SnapshotAuthentication)?;
        if auth.existed {
            let protected = protect_auth_snapshot(root, id, auth)?;
            write_synced(
                &snapshot_file(root, id, FileRole::Authentication),
                &protected,
                true,
            )?;
        }
        self.fault(FaultPoint::SnapshotManifest)?;
        let text = manifest_text(id, config, auth, plan);
        let temp = directory.join("snapshot.manifest.tmp");
        let target = directory.join("snapshot.manifest");
        write_synced(&temp, text.as_bytes(), true)?;
        fs::rename(&temp, &target).map_err(|_| SwitchExecutionError::IoFailure)?;
        let loaded =
            load_snapshot(root, id, None).map_err(|_| SwitchExecutionError::SnapshotInvalid)?;
        if loaded.config != *config
            || loaded.auth != *auth
            || !file_evidence_matches_bytes(
                &loaded.config_target,
                plan.target_config(),
                config.readonly,
            )
            || !file_evidence_matches_bytes(&loaded.auth_target, plan.target_auth(), auth.readonly)
        {
            return Err(SwitchExecutionError::SnapshotInvalid);
        }
        Ok(hash_bytes(text.as_bytes()))
    }

    fn finalize_terminal(
        &mut self,
        record: &mut SwitchTransactionRecord,
        root: &Path,
        state: SwitchTransactionState,
        error: Option<SwitchErrorCode>,
    ) -> Result<(), SwitchExecutionError> {
        write_cleanup_intent(root, record.transaction.id(), state)?;
        self.advance(record, state, error)?;
        self.cleanup_transaction_material(root, record.transaction.id())
    }

    fn reconcile_terminal_material(&mut self, root: &Path) -> Result<(), SwitchExecutionError> {
        let parent = root.join(".codextools-transactions");
        let entries = match fs::read_dir(&parent) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(SwitchExecutionError::RecoveryRequired),
        };
        for entry in entries {
            let entry = entry.map_err(|_| SwitchExecutionError::RecoveryRequired)?;
            if !entry
                .file_type()
                .map_err(|_| SwitchExecutionError::RecoveryRequired)?
                .is_dir()
            {
                return Err(SwitchExecutionError::RecoveryRequired);
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
            let id = codex_domain::SwitchTransactionId::parse(&name)
                .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
            let record = self
                .repository
                .get_switch_transaction(&id)?
                .ok_or(SwitchExecutionError::RecoveryRequired)?;
            if record.transaction.state().is_terminal()
                && record.transaction.state() != SwitchTransactionState::RecoveryRequired
            {
                self.cleanup_transaction_material(root, &id)?;
            }
        }
        if parent.is_dir()
            && fs::read_dir(&parent)
                .map_err(|_| SwitchExecutionError::RecoveryRequired)?
                .next()
                .is_none()
        {
            fs::remove_dir(parent).map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        }
        Ok(())
    }

    fn cleanup_transaction_material(
        &mut self,
        root: &Path,
        id: &codex_domain::SwitchTransactionId,
    ) -> Result<(), SwitchExecutionError> {
        let directory = snapshot_dir(root, id);
        let _record = self
            .repository
            .get_switch_transaction(id)?
            .ok_or(SwitchExecutionError::RecoveryRequired)?;
        self.fault(FaultPoint::TerminalCleanupAuthenticationSnapshot)
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        remove_file_if_exists(&snapshot_file(root, id, FileRole::Authentication))?;
        self.fault(FaultPoint::TerminalCleanupConfigSnapshot)
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        remove_file_if_exists(&snapshot_file(root, id, FileRole::Config))?;
        self.fault(FaultPoint::TerminalCleanupAuthenticationStage)
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        self.fault(FaultPoint::TerminalCleanupConfigStage)
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        self.fault(FaultPoint::TerminalCleanupManifest)
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        remove_file_if_exists(&directory.join("snapshot.manifest.tmp"))?;
        remove_file_if_exists(&directory.join("snapshot.manifest"))?;
        self.fault(FaultPoint::TerminalCleanupDirectory)
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        remove_file_if_exists(&directory.join("cleanup.intent"))?;
        match fs::remove_dir(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(SwitchExecutionError::RecoveryRequired),
        }
        let parent = root.join(".codextools-transactions");
        if parent.is_dir()
            && fs::read_dir(&parent)
                .map_err(|_| SwitchExecutionError::RecoveryRequired)?
                .next()
                .is_none()
        {
            fs::remove_dir(parent).map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        }
        Ok(())
    }

    fn reconcile_sensitive_temp_owners(
        &mut self,
        root_pin: &RootNamespacePin,
        root_ref: &ContentHash,
    ) -> Result<(), SwitchExecutionError> {
        root_pin
            .verify_identity()
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        let owners = self.repository.list_sensitive_temp_owners(root_ref)?;
        for mut owner in owners {
            let Some(identity) = owner.identity else {
                let zero = FileIdentity128 {
                    volume_serial_number: 0,
                    file_id: [0; 16],
                };
                if matches!(
                    root_pin.observe_relative(&owner.temp_rel, zero),
                    RelativePathObservation::Absent
                ) {
                    self.repository.delete_sensitive_temp_owner(&owner)?;
                    continue;
                }
                return Err(SwitchExecutionError::RecoveryRequired);
            };
            let temp = root_pin.observe_relative(&owner.temp_rel, identity);
            let publish = root_pin.observe_relative(&owner.publish_rel, identity);
            if matches!(
                temp,
                RelativePathObservation::Reparse | RelativePathObservation::QueryError(_)
            ) || matches!(
                publish,
                RelativePathObservation::Reparse | RelativePathObservation::QueryError(_)
            ) || (matches!(temp, RelativePathObservation::SameOwnerId { .. })
                && matches!(publish, RelativePathObservation::SameOwnerId { .. }))
            {
                return Err(SwitchExecutionError::RecoveryRequired);
            }
            match owner.lifecycle {
                SensitiveTempLifecycle::PrewriteDeleteArmed
                | SensitiveTempLifecycle::CleanupDeleteArmed => {
                    if matches!(temp, RelativePathObservation::SameOwnerId { .. }) {
                        let mut handle =
                            SensitiveTempFile::reopen_owned(root_pin, &owner.temp_rel, identity)
                                .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
                        if owner.lifecycle != SensitiveTempLifecycle::CleanupDeleteArmed {
                            self.repository.transition_sensitive_temp_owner(
                                &owner.transaction_id,
                                owner.phase,
                                owner.role,
                                owner.lifecycle,
                                SensitiveTempLifecycle::CleanupDeleteArmed,
                                owner.version,
                                self.clock.now(),
                            )?;
                            owner.lifecycle = SensitiveTempLifecycle::CleanupDeleteArmed;
                            owner.version += 1;
                        }
                        handle
                            .arm_delete_on_close()
                            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
                        drop(handle);
                        if !matches!(
                            root_pin.observe_relative(&owner.temp_rel, identity),
                            RelativePathObservation::Absent
                        ) {
                            return Err(SwitchExecutionError::RecoveryRequired);
                        }
                        self.repository.delete_sensitive_temp_owner(&owner)?;
                    } else if matches!(temp, RelativePathObservation::Absent)
                        && !matches!(publish, RelativePathObservation::SameOwnerId { .. })
                    {
                        self.repository.delete_sensitive_temp_owner(&owner)?;
                    } else {
                        return Err(SwitchExecutionError::RecoveryRequired);
                    }
                }
                SensitiveTempLifecycle::Owned => {
                    if matches!(temp, RelativePathObservation::SameOwnerId { .. }) {
                        let handle =
                            SensitiveTempFile::reopen_owned(root_pin, &owner.temp_rel, identity)
                                .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
                        if owner.destination_guard.is_some() {
                            let mut old = PinnedLiveFile::open(root_pin, &owner.publish_rel)
                                .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
                            self.restore_readonly_guard(&mut owner, &mut old)?;
                        }
                        let prepared = PreparedSensitiveTemp { handle, owner };
                        self.cleanup_prepared_only(root_pin, prepared)?;
                    } else if matches!(temp, RelativePathObservation::Absent)
                        && matches!(publish, RelativePathObservation::SameOwnerId { .. })
                        && owner.phase == OwnerPhase::Target
                    {
                        self.reconcile_maybe_published_target(root_pin, &mut owner)?;
                    } else if matches!(temp, RelativePathObservation::Absent)
                        && matches!(publish, RelativePathObservation::SameOwnerId { .. })
                        && owner.phase == OwnerPhase::Recovery
                    {
                        self.reconcile_maybe_published_recovery(root_pin, &mut owner)?;
                    } else {
                        return Err(SwitchExecutionError::RecoveryRequired);
                    }
                }
                SensitiveTempLifecycle::Published => {
                    if owner.phase == OwnerPhase::Target
                        && matches!(temp, RelativePathObservation::Absent)
                        && matches!(publish, RelativePathObservation::SameOwnerId { .. })
                    {
                        let record = self
                            .repository
                            .get_switch_transaction(&owner.transaction_id)?
                            .ok_or(SwitchExecutionError::RecoveryRequired)?;
                        if record.transaction.completed_roles() & owner_role_bit(owner.role) == 0 {
                            return Err(SwitchExecutionError::RecoveryRequired);
                        }
                        self.repository.delete_sensitive_temp_owner(&owner)?;
                    } else if owner.phase == OwnerPhase::Recovery {
                        if matches!(temp, RelativePathObservation::Absent) {
                            if is_recovery_delete_tombstone(&owner) {
                                if matches!(publish, RelativePathObservation::SameOwnerId { .. }) {
                                    let live = PinnedLiveFile::open_for_delete(
                                        root_pin,
                                        &owner.publish_rel,
                                        owner
                                            .identity
                                            .ok_or(SwitchExecutionError::RecoveryRequired)?,
                                    )
                                    .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
                                    live.arm_delete_on_close()
                                        .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
                                    drop(live);
                                    if !matches!(
                                        root_pin.observe_relative(
                                            &owner.publish_rel,
                                            owner
                                                .identity
                                                .ok_or(SwitchExecutionError::RecoveryRequired)?,
                                        ),
                                        RelativePathObservation::Absent
                                    ) {
                                        return Err(SwitchExecutionError::RecoveryRequired);
                                    }
                                    continue;
                                }
                                if matches!(publish, RelativePathObservation::Absent) {
                                    continue;
                                }
                            } else if matches!(publish, RelativePathObservation::SameOwnerId { .. })
                            {
                                continue;
                            }
                        }
                        return Err(SwitchExecutionError::RecoveryRequired);
                    } else {
                        return Err(SwitchExecutionError::RecoveryRequired);
                    }
                }
            }
        }
        Ok(())
    }

    fn legacy_sensitive_temp_preflight(
        &mut self,
        root_pin: &RootNamespacePin,
        root_ref: &ContentHash,
    ) -> Result<(), SwitchExecutionError> {
        for anomaly in self.repository.list_sensitive_temp_anomalies(root_ref)? {
            let expected = anomaly.observed_identity.unwrap_or(FileIdentity128 {
                volume_serial_number: 0,
                file_id: [0; 16],
            });
            if matches!(
                root_pin.observe_relative(&anomaly.canonical_rel_path, expected),
                RelativePathObservation::Absent
            ) {
                self.repository.delete_sensitive_temp_anomaly(&anomaly)?;
            } else {
                return Err(SwitchExecutionError::RecoveryRequired);
            }
        }
        for _ in 0..2 {
            let entries = fs::read_dir(root_pin.root_path())
                .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
            let mut found = Vec::new();
            for entry in entries {
                let entry = entry.map_err(|_| SwitchExecutionError::RecoveryRequired)?;
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    return Err(SwitchExecutionError::RecoveryRequired);
                };
                let Some((role, phase)) = sensitive_temp_name_role_phase(name) else {
                    continue;
                };
                found.push((name.to_owned(), role, phase));
            }
            if found.is_empty() {
                continue;
            }
            for (name, role, phase) in found {
                let zero = FileIdentity128 {
                    volume_serial_number: 0,
                    file_id: [0; 16],
                };
                let observation = root_pin.observe_relative(&name, zero);
                let (reason, identity, length) = match observation {
                    RelativePathObservation::OtherId {
                        identity, length, ..
                    }
                    | RelativePathObservation::SameOwnerId {
                        identity, length, ..
                    } => ("legacy_mismatch", Some(identity), Some(length)),
                    RelativePathObservation::Reparse => ("reparse", None, None),
                    RelativePathObservation::QueryError(_) => ("query_error", None, None),
                    RelativePathObservation::Absent => continue,
                };
                let now = self.clock.now();
                let tx = sensitive_temp_name_transaction(&name).and_then(|id| {
                    self.repository
                        .get_switch_transaction(&id)
                        .ok()
                        .flatten()
                        .map(|_| id)
                });
                self.repository
                    .upsert_sensitive_temp_anomaly(&crate::SensitiveTempAnomaly {
                        transaction_id: tx,
                        root_ref: root_ref.clone(),
                        role,
                        phase,
                        canonical_rel_path: name,
                        reason: reason.to_owned(),
                        observed_identity: identity,
                        observed_length: length,
                        created_at: now,
                        updated_at: now,
                        version: 1,
                    })?;
            }
            return Err(SwitchExecutionError::RecoveryRequired);
        }
        Ok(())
    }

    fn reconcile_maybe_published_target(
        &mut self,
        root_pin: &RootNamespacePin,
        owner: &mut SensitiveTempOwnerRecord,
    ) -> Result<(), SwitchExecutionError> {
        let mut record = self
            .repository
            .get_switch_transaction(&owner.transaction_id)?
            .ok_or(SwitchExecutionError::RecoveryRequired)?;
        if record.transaction.state() != SwitchTransactionState::Replacing {
            return Err(SwitchExecutionError::RecoveryRequired);
        }
        let expected_bits = match owner.role {
            SensitiveTempRole::Config => 0,
            SensitiveTempRole::Authentication => FileRole::Config.bit(),
        };
        if record.transaction.completed_roles() != expected_bits {
            return Err(SwitchExecutionError::RecoveryRequired);
        }
        let manifest = load_snapshot(
            root_pin.root_path(),
            &owner.transaction_id,
            record.snapshot_manifest_hash.as_ref(),
        )
        .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        if !snapshot_matches_transaction(&manifest, &record) {
            return Err(SwitchExecutionError::RecoveryRequired);
        }
        let identity = owner
            .identity
            .ok_or(SwitchExecutionError::RecoveryRequired)?;
        let mut published = SensitiveTempFile::reopen_owned(root_pin, &owner.publish_rel, identity)
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        let bytes = published
            .reread(16 * 1024 * 1024)
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        if bytes.len() as u64 != owner.expected_length
            || hash_bytes(&bytes) != owner.expected_hash
            || published.readonly().ok() != Some(owner.expected_readonly)
            || published.final_basename().as_deref().ok() != Some(owner.publish_rel.as_str())
        {
            return Err(SwitchExecutionError::RecoveryRequired);
        }
        let other = match owner.role {
            SensitiveTempRole::Config => observe(&root_pin.root_path().join(AUTH_NAME))?,
            SensitiveTempRole::Authentication => observe(&root_pin.root_path().join(CONFIG_NAME))?,
        };
        let pair_truth = match owner.role {
            SensitiveTempRole::Config => file_matches_observation(&other, &manifest.auth),
            SensitiveTempRole::Authentication => {
                file_matches_evidence(&other, &manifest.config_target)
            }
        };
        if !pair_truth {
            return Err(SwitchExecutionError::RecoveryRequired);
        }
        if let Some(guard) = owner.destination_guard.as_ref() {
            if guard.state != SensitiveDestinationState::ReadonlyCleared {
                return Err(SwitchExecutionError::RecoveryRequired);
            }
            let current = owner.clone();
            self.repository.transition_destination_guard(
                &current,
                SensitiveDestinationState::ReadonlyCleared,
                SensitiveDestinationState::None,
                self.clock.now(),
            )?;
            owner.destination_guard = None;
            owner.version += 1;
        }
        let role = match owner.role {
            SensitiveTempRole::Config => FileRole::Config,
            SensitiveTempRole::Authentication => FileRole::Authentication,
        };
        let expected = record.transaction.version();
        let updated = record
            .transaction
            .mark_replaced(role, self.clock.now())
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        let candidate = SwitchTransactionRecord {
            transaction: updated,
            last_error: record.last_error,
            snapshot_manifest_hash: record.snapshot_manifest_hash.clone(),
        };
        self.repository
            .mark_sensitive_owner_published_and_role(owner, &candidate, expected)?;
        owner.lifecycle = SensitiveTempLifecycle::Published;
        owner.version += 1;
        record = candidate;
        self.repository.delete_sensitive_temp_owner(owner)?;
        let _ = record;
        Ok(())
    }

    fn reconcile_maybe_published_recovery(
        &mut self,
        root_pin: &RootNamespacePin,
        owner: &mut SensitiveTempOwnerRecord,
    ) -> Result<(), SwitchExecutionError> {
        let record = self
            .repository
            .get_switch_transaction(&owner.transaction_id)?
            .ok_or(SwitchExecutionError::RecoveryRequired)?;
        if record.transaction.state() != SwitchTransactionState::RollingBack {
            return Err(SwitchExecutionError::RecoveryRequired);
        }
        let identity = owner
            .identity
            .ok_or(SwitchExecutionError::RecoveryRequired)?;
        let mut published = SensitiveTempFile::reopen_owned(root_pin, &owner.publish_rel, identity)
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        let bytes = published
            .reread(16 * 1024 * 1024)
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        if bytes.len() as u64 != owner.expected_length
            || hash_bytes(&bytes) != owner.expected_hash
            || published.readonly().ok() != Some(owner.expected_readonly)
            || published.final_basename().as_deref().ok() != Some(owner.publish_rel.as_str())
        {
            return Err(SwitchExecutionError::RecoveryRequired);
        }
        if let Some(guard) = owner.destination_guard.as_ref() {
            if guard.state != SensitiveDestinationState::ReadonlyCleared {
                return Err(SwitchExecutionError::RecoveryRequired);
            }
            let current = owner.clone();
            self.repository.transition_destination_guard(
                &current,
                SensitiveDestinationState::ReadonlyCleared,
                SensitiveDestinationState::None,
                self.clock.now(),
            )?;
            owner.destination_guard = None;
            owner.version += 1;
        }
        self.repository.transition_sensitive_temp_owner(
            &owner.transaction_id,
            owner.phase,
            owner.role,
            SensitiveTempLifecycle::Owned,
            SensitiveTempLifecycle::Published,
            owner.version,
            self.clock.now(),
        )?;
        owner.lifecycle = SensitiveTempLifecycle::Published;
        owner.version += 1;
        Ok(())
    }

    fn stage_file(
        &mut self,
        root_pin: &RootNamespacePin,
        record: &SwitchTransactionRecord,
        bytes: &[u8],
        readonly: bool,
        role: FileRole,
    ) -> Result<PreparedSensitiveTemp, SwitchExecutionError> {
        let (write, flush, reread) = match role {
            FileRole::Config => (
                FaultPoint::StageConfigWrite,
                FaultPoint::StageConfigFlush,
                FaultPoint::StageConfigReread,
            ),
            FileRole::Authentication => (
                FaultPoint::StageAuthenticationWrite,
                FaultPoint::StageAuthenticationFlush,
                FaultPoint::StageAuthenticationReread,
            ),
        };
        self.fault(write)?;
        let mut owned =
            self.begin_sensitive_temp(root_pin, record, role, OwnerPhase::Target, bytes, readonly)?;
        if let Err(error) = write_all_with_io(&mut self.sensitive_io, &mut owned.handle, bytes) {
            return self.cleanup_prepared_sensitive_temp(root_pin, owned, error);
        }
        if let Err(error) = self.fault(flush) {
            return self.cleanup_prepared_sensitive_temp(root_pin, owned, error);
        }
        if self.sensitive_io.flush(&mut owned.handle).is_err()
            || self.sensitive_io.sync_all(&owned.handle).is_err()
        {
            return self.cleanup_prepared_sensitive_temp(
                root_pin,
                owned,
                SwitchExecutionError::IoFailure,
            );
        }
        if let Err(error) = self.fault(reread) {
            return self.cleanup_prepared_sensitive_temp(root_pin, owned, error);
        }
        let mut observed = match self.sensitive_io.reread(&mut owned.handle) {
            Ok(bytes) => bytes,
            Err(_) => {
                return self.cleanup_prepared_sensitive_temp(
                    root_pin,
                    owned,
                    SwitchExecutionError::IoFailure,
                );
            }
        };
        let matches = observed.as_slice() == bytes;
        if !matches {
            observed.zeroize();
            return self.cleanup_prepared_sensitive_temp(
                root_pin,
                owned,
                SwitchExecutionError::IoFailure,
            );
        }
        if owned.handle.set_readonly(false).is_err() || owned.handle.readonly().ok() != Some(false)
        {
            return self.cleanup_prepared_sensitive_temp(
                root_pin,
                owned,
                SwitchExecutionError::IoFailure,
            );
        }
        Ok(owned)
    }

    fn begin_sensitive_temp(
        &mut self,
        root_pin: &RootNamespacePin,
        record: &SwitchTransactionRecord,
        role: FileRole,
        phase: OwnerPhase,
        bytes: &[u8],
        readonly: bool,
    ) -> Result<PreparedSensitiveTemp, SwitchExecutionError> {
        let nonce = sensitive_nonce();
        let role = owner_role(role);
        let publish_rel = owner_publish_name(role).to_owned();
        let temp_rel = owner_temp_name(record.transaction.id(), role, phase, &nonce);
        let now = self.clock.now();
        let mut owner = SensitiveTempOwnerRecord {
            transaction_id: record.transaction.id().clone(),
            root_ref: record.transaction.root_ref().clone(),
            role,
            phase,
            nonce,
            temp_rel: temp_rel.clone(),
            publish_rel,
            identity: None,
            expected_length: bytes.len() as u64,
            expected_hash: hash_bytes(bytes),
            expected_readonly: readonly,
            lifecycle: SensitiveTempLifecycle::PrewriteDeleteArmed,
            destination_guard: None,
            created_at: now,
            updated_at: now,
            version: 1,
        };
        self.repository.create_sensitive_temp_owner(&owner)?;
        let mut handle = match self.sensitive_io.create_delete_armed(root_pin, &temp_rel) {
            Ok(handle) => handle,
            Err(_) => return Err(SwitchExecutionError::RecoveryRequired),
        };
        let identity = handle.identity();
        self.repository
            .bind_sensitive_temp_owner_identity(
                record.transaction.id(),
                phase,
                role,
                identity,
                owner.version,
                self.clock.now(),
            )
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        owner.identity = Some(identity);
        owner.version += 1;
        owner.updated_at = self.clock.now();
        self.sensitive_io
            .clear_delete_on_close(&mut handle, root_pin)
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        self.repository
            .transition_sensitive_temp_owner(
                record.transaction.id(),
                phase,
                role,
                SensitiveTempLifecycle::PrewriteDeleteArmed,
                SensitiveTempLifecycle::Owned,
                owner.version,
                self.clock.now(),
            )
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        owner.lifecycle = SensitiveTempLifecycle::Owned;
        owner.version += 1;
        owner.updated_at = self.clock.now();
        Ok(PreparedSensitiveTemp { handle, owner })
    }

    fn cleanup_prepared_sensitive_temp<T>(
        &mut self,
        root_pin: &RootNamespacePin,
        prepared: PreparedSensitiveTemp,
        original: SwitchExecutionError,
    ) -> Result<T, SwitchExecutionError> {
        self.cleanup_prepared_only(root_pin, prepared)?;
        Err(original)
    }

    fn cleanup_prepared_only(
        &mut self,
        root_pin: &RootNamespacePin,
        mut prepared: PreparedSensitiveTemp,
    ) -> Result<(), SwitchExecutionError> {
        self.repository
            .transition_sensitive_temp_owner(
                &prepared.owner.transaction_id,
                prepared.owner.phase,
                prepared.owner.role,
                prepared.owner.lifecycle,
                SensitiveTempLifecycle::CleanupDeleteArmed,
                prepared.owner.version,
                self.clock.now(),
            )
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        prepared.owner.lifecycle = SensitiveTempLifecycle::CleanupDeleteArmed;
        prepared.owner.version += 1;
        self.sensitive_io
            .arm_delete_on_close(&mut prepared.handle)
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        let identity = prepared.handle.identity();
        let temp_rel = prepared.owner.temp_rel.clone();
        drop(prepared.handle);
        if !matches!(
            root_pin.observe_relative(&temp_rel, identity),
            RelativePathObservation::Absent
        ) {
            return Err(SwitchExecutionError::RecoveryRequired);
        }
        self.repository
            .delete_sensitive_temp_owner(&prepared.owner)
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        Ok(())
    }

    fn atomic_replace_live(
        &mut self,
        root_pin: &RootNamespacePin,
        mut prepared: PreparedSensitiveTemp,
        record: &mut SwitchTransactionRecord,
        role: FileRole,
    ) -> Result<(), SwitchExecutionError> {
        let publish = role_name(role);
        let expected_source = match role {
            FileRole::Config => record.transaction.config_source(),
            FileRole::Authentication => record.transaction.auth_source(),
        };
        let mut old = match expected_source {
            Some(expected_source) => {
                let mut old = PinnedLiveFile::open(root_pin, publish)
                    .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
                let old_bytes = old
                    .reread(16 * 1024 * 1024)
                    .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
                if hash_bytes(&old_bytes) != *expected_source {
                    return Err(SwitchExecutionError::RecoveryRequired);
                }
                Some(old)
            }
            None => {
                if !matches!(
                    root_pin.observe_relative(
                        publish,
                        FileIdentity128 {
                            volume_serial_number: 0,
                            file_id: [0; 16],
                        },
                    ),
                    RelativePathObservation::Absent
                ) {
                    return Err(SwitchExecutionError::RecoveryRequired);
                }
                None
            }
        };
        if old
            .as_ref()
            .is_some_and(|old| old.readonly().ok() == Some(true))
        {
            let old = old.as_mut().expect("readonly old exists");
            let guard = SensitiveDestinationGuard {
                state: SensitiveDestinationState::ReadonlyClearArmed,
                identity: old.identity(),
                length: old
                    .length()
                    .map_err(|_| SwitchExecutionError::RecoveryRequired)?,
                hash_ref: expected_source.expect("readonly source exists").clone(),
            };
            self.repository
                .arm_destination_readonly_guard(&prepared.owner, &guard, self.clock.now())
                .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
            prepared.owner.destination_guard = Some(guard);
            prepared.owner.version += 1;
            old.set_readonly(false)
                .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
            let current = prepared.owner.clone();
            self.repository
                .transition_destination_guard(
                    &current,
                    SensitiveDestinationState::ReadonlyClearArmed,
                    SensitiveDestinationState::ReadonlyCleared,
                    self.clock.now(),
                )
                .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
            prepared
                .owner
                .destination_guard
                .as_mut()
                .expect("guard exists")
                .state = SensitiveDestinationState::ReadonlyCleared;
            prepared.owner.version += 1;
        }
        if let Err(error) = self.fault(match role {
            FileRole::Config => FaultPoint::AfterConfigMakeWritable,
            FileRole::Authentication => FaultPoint::AfterAuthenticationMakeWritable,
        }) {
            if let Some(old) = old.as_mut() {
                self.restore_readonly_guard(&mut prepared.owner, old)?;
            }
            return self.cleanup_prepared_sensitive_temp(root_pin, prepared, error);
        }
        let rename = self
            .sensitive_io
            .rename_relative(&mut prepared.handle, root_pin, publish);
        if rename.is_err() {
            let final_name = prepared.handle.final_basename();
            if final_name.as_deref().ok() == Some(prepared.owner.temp_rel.as_str()) {
                if let Some(old) = old.as_mut() {
                    self.restore_readonly_guard(&mut prepared.owner, old)?;
                }
                return self.cleanup_prepared_sensitive_temp(
                    root_pin,
                    prepared,
                    SwitchExecutionError::IoFailure,
                );
            }
            if final_name.as_deref().ok() != Some(publish) {
                return Err(SwitchExecutionError::RecoveryRequired);
            }
            if prepared.handle.state() == SensitiveHandleState::RenameFailedUnknown {
                prepared
                    .handle
                    .resolve_failed_rename_as_published(publish)
                    .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
            }
        }
        if prepared.handle.state() != SensitiveHandleState::MaybePublished
            && prepared.handle.final_basename().as_deref().ok() != Some(publish)
        {
            return Err(SwitchExecutionError::RecoveryRequired);
        }
        prepared
            .handle
            .set_readonly(prepared.owner.expected_readonly)
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        let current_bytes = prepared
            .handle
            .reread(16 * 1024 * 1024)
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        if prepared.handle.identity()
            != prepared
                .owner
                .identity
                .ok_or(SwitchExecutionError::RecoveryRequired)?
            || prepared.handle.length().ok() != Some(prepared.owner.expected_length)
            || hash_bytes(&current_bytes) != prepared.owner.expected_hash
            || prepared.handle.readonly().ok() != Some(prepared.owner.expected_readonly)
            || prepared.handle.final_basename().as_deref().ok() != Some(publish)
        {
            return Err(SwitchExecutionError::RecoveryRequired);
        }
        let other = match role {
            FileRole::Config => observe(&root_pin.root_path().join(AUTH_NAME))?,
            FileRole::Authentication => observe(&root_pin.root_path().join(CONFIG_NAME))?,
        };
        let pair_valid = match role {
            FileRole::Config => match record.transaction.auth_source() {
                Some(expected) => other.existed && other.hash.as_ref() == Some(expected),
                None => !other.existed,
            },
            FileRole::Authentication => {
                hash_bytes(&other.bytes) == *record.transaction.config_target()
            }
        };
        if !pair_valid {
            return Err(SwitchExecutionError::RecoveryRequired);
        }
        if prepared.owner.destination_guard.is_some() {
            let current = prepared.owner.clone();
            self.repository
                .transition_destination_guard(
                    &current,
                    SensitiveDestinationState::ReadonlyCleared,
                    SensitiveDestinationState::None,
                    self.clock.now(),
                )
                .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
            prepared.owner.destination_guard = None;
            prepared.owner.version += 1;
        }
        let expected = record.transaction.version();
        let updated = record
            .transaction
            .mark_replaced(role, self.clock.now())
            .map_err(|_| SwitchExecutionError::RepositoryFailure)?;
        let candidate = SwitchTransactionRecord {
            transaction: updated,
            last_error: record.last_error,
            snapshot_manifest_hash: record.snapshot_manifest_hash.clone(),
        };
        self.repository
            .mark_sensitive_owner_published_and_role(&prepared.owner, &candidate, expected)
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        prepared.owner.lifecycle = SensitiveTempLifecycle::Published;
        prepared.owner.version += 1;
        *record = candidate;
        self.repository
            .delete_sensitive_temp_owner(&prepared.owner)
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        prepared
            .handle
            .confirm_published()
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        drop(old);
        Ok(())
    }

    fn restore_readonly_guard(
        &mut self,
        owner: &mut SensitiveTempOwnerRecord,
        old: &mut PinnedLiveFile,
    ) -> Result<(), SwitchExecutionError> {
        let Some(guard) = owner.destination_guard.clone() else {
            return Ok(());
        };
        if old.identity() != guard.identity || old.length().ok() != Some(guard.length) {
            return Err(SwitchExecutionError::RecoveryRequired);
        }
        let bytes = old
            .reread(16 * 1024 * 1024)
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        if hash_bytes(&bytes) != guard.hash_ref {
            return Err(SwitchExecutionError::RecoveryRequired);
        }
        if guard.state == SensitiveDestinationState::ReadonlyCleared {
            old.set_readonly(true)
                .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
            if old.readonly().ok() != Some(true) {
                return Err(SwitchExecutionError::RecoveryRequired);
            }
        }
        let current = owner.clone();
        self.repository
            .transition_destination_guard(
                &current,
                guard.state,
                SensitiveDestinationState::None,
                self.clock.now(),
            )
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        owner.destination_guard = None;
        owner.version += 1;
        Ok(())
    }

    fn publish_recovery_role(
        &mut self,
        root_pin: &RootNamespacePin,
        mut prepared: PreparedSensitiveTemp,
        expected: &ObservedFile,
    ) -> Result<(), SwitchExecutionError> {
        let mut old = PinnedLiveFile::open(root_pin, &prepared.owner.publish_rel)
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        let old_bytes = old
            .reread(16 * 1024 * 1024)
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        if old
            .readonly()
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?
        {
            let guard = SensitiveDestinationGuard {
                state: SensitiveDestinationState::ReadonlyClearArmed,
                identity: old.identity(),
                length: old
                    .length()
                    .map_err(|_| SwitchExecutionError::RecoveryRequired)?,
                hash_ref: hash_bytes(&old_bytes),
            };
            self.repository.arm_destination_readonly_guard(
                &prepared.owner,
                &guard,
                self.clock.now(),
            )?;
            prepared.owner.destination_guard = Some(guard);
            prepared.owner.version += 1;
            old.set_readonly(false)
                .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
            let current = prepared.owner.clone();
            self.repository.transition_destination_guard(
                &current,
                SensitiveDestinationState::ReadonlyClearArmed,
                SensitiveDestinationState::ReadonlyCleared,
                self.clock.now(),
            )?;
            prepared
                .owner
                .destination_guard
                .as_mut()
                .expect("guard exists")
                .state = SensitiveDestinationState::ReadonlyCleared;
            prepared.owner.version += 1;
        }
        if let Err(_error) = self.sensitive_io.rename_relative(
            &mut prepared.handle,
            root_pin,
            &prepared.owner.publish_rel,
        ) {
            if prepared.handle.final_basename().as_deref().ok()
                == Some(prepared.owner.temp_rel.as_str())
            {
                self.restore_readonly_guard(&mut prepared.owner, &mut old)?;
                return self.cleanup_prepared_sensitive_temp(
                    root_pin,
                    prepared,
                    SwitchExecutionError::IoFailure,
                );
            }
            if prepared.handle.final_basename().as_deref().ok()
                != Some(prepared.owner.publish_rel.as_str())
            {
                return Err(SwitchExecutionError::RecoveryRequired);
            }
            if prepared.handle.state() == SensitiveHandleState::RenameFailedUnknown {
                prepared
                    .handle
                    .resolve_failed_rename_as_published(&prepared.owner.publish_rel)
                    .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
            }
        }
        prepared
            .handle
            .set_readonly(expected.readonly)
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        let bytes = prepared
            .handle
            .reread(16 * 1024 * 1024)
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        if bytes.as_slice() != expected.bytes.as_slice()
            || prepared.handle.identity()
                != prepared
                    .owner
                    .identity
                    .ok_or(SwitchExecutionError::RecoveryRequired)?
            || prepared.handle.readonly().ok() != Some(expected.readonly)
            || prepared.handle.final_basename().as_deref().ok()
                != Some(prepared.owner.publish_rel.as_str())
        {
            return Err(SwitchExecutionError::RecoveryRequired);
        }
        if prepared.owner.destination_guard.is_some() {
            let current = prepared.owner.clone();
            self.repository.transition_destination_guard(
                &current,
                SensitiveDestinationState::ReadonlyCleared,
                SensitiveDestinationState::None,
                self.clock.now(),
            )?;
            prepared.owner.destination_guard = None;
            prepared.owner.version += 1;
        }
        self.repository
            .transition_sensitive_temp_owner(
                &prepared.owner.transaction_id,
                prepared.owner.phase,
                prepared.owner.role,
                SensitiveTempLifecycle::Owned,
                SensitiveTempLifecycle::Published,
                prepared.owner.version,
                self.clock.now(),
            )
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        prepared.owner.lifecycle = SensitiveTempLifecycle::Published;
        prepared.owner.version += 1;
        prepared
            .handle
            .confirm_published()
            .map_err(|_| SwitchExecutionError::RecoveryRequired)?;
        drop(old);
        Ok(())
    }

    fn advance(
        &mut self,
        record: &mut SwitchTransactionRecord,
        next: SwitchTransactionState,
        error: Option<SwitchErrorCode>,
    ) -> Result<(), SwitchExecutionError> {
        let expected = record.transaction.version();
        let updated = record
            .transaction
            .transition(next, self.clock.now())
            .map_err(|_| SwitchExecutionError::RepositoryFailure)?;
        let candidate = SwitchTransactionRecord {
            transaction: updated,
            last_error: error.or(record.last_error),
            snapshot_manifest_hash: record.snapshot_manifest_hash.clone(),
        };
        self.repository
            .update_switch_transaction(&candidate, expected)?;
        *record = candidate;
        Ok(())
    }
    fn force_recovery_required(
        &mut self,
        record: &mut SwitchTransactionRecord,
        error: SwitchErrorCode,
    ) -> Result<(), SwitchExecutionError> {
        self.advance(
            record,
            SwitchTransactionState::RecoveryRequired,
            Some(error),
        )
    }
    fn fault(&mut self, point: FaultPoint) -> Result<(), SwitchExecutionError> {
        match self.faults.check(point) {
            None => Ok(()),
            Some(FaultDisposition::Fail) => Err(SwitchExecutionError::InjectedFailure),
            Some(FaultDisposition::Interrupt) => Err(SwitchExecutionError::Interrupted),
        }
    }
}

fn error_code(error: SwitchExecutionError) -> SwitchErrorCode {
    match error {
        SwitchExecutionError::Busy => SwitchErrorCode::Busy,
        SwitchExecutionError::PlanStale => SwitchErrorCode::PlanStale,
        SwitchExecutionError::CompatibilityProtected(_) => SwitchErrorCode::CompatibilityProtected,
        SwitchExecutionError::SnapshotInvalid => SwitchErrorCode::SnapshotInvalid,
        SwitchExecutionError::RepositoryFailure => SwitchErrorCode::RepositoryFailure,
        SwitchExecutionError::InjectedFailure | SwitchExecutionError::Interrupted => {
            SwitchErrorCode::InjectedFailure
        }
        SwitchExecutionError::RecoveryRequired => SwitchErrorCode::RecoveryRequired,
        _ => SwitchErrorCode::IoFailure,
    }
}
fn ensure_plan_fresh(plan: &SwitchPlan, now: UnixMillis) -> Result<(), SwitchExecutionError> {
    if now < plan.created_at() || now >= plan.expires_at() {
        Err(SwitchExecutionError::PlanStale)
    } else {
        Ok(())
    }
}
fn file_matches_observation(actual: &ObservedFile, expected: &ObservedFile) -> bool {
    actual == expected
}
fn pair_matches_observation(
    actual: &(ObservedFile, ObservedFile),
    expected: &(ObservedFile, ObservedFile),
) -> bool {
    file_matches_observation(&actual.0, &expected.0)
        && file_matches_observation(&actual.1, &expected.1)
}
fn file_matches_target(actual: &ObservedFile, target: &[u8], readonly: bool) -> bool {
    actual.existed
        && actual.readonly == readonly
        && actual.bytes.as_slice() == target
        && actual.hash.as_ref() == Some(&hash_bytes(target))
}
fn pair_matches_target(
    actual: &(ObservedFile, ObservedFile),
    plan: &SwitchPlan,
    source: &(ObservedFile, ObservedFile),
) -> bool {
    file_matches_target(&actual.0, plan.target_config(), source.0.readonly)
        && file_matches_target(&actual.1, plan.target_auth(), source.1.readonly)
}
fn snapshot_matches_transaction(
    manifest: &SnapshotManifest,
    record: &SwitchTransactionRecord,
) -> bool {
    manifest.config.existed == record.transaction.config_source().is_some()
        && manifest.auth.existed == record.transaction.auth_source().is_some()
        && manifest.config.hash.as_ref() == record.transaction.config_source()
        && manifest.auth.hash.as_ref() == record.transaction.auth_source()
        && manifest.config_target.existed
        && manifest.auth_target.existed
        && manifest.config_target.hash.as_ref() == Some(record.transaction.config_target())
        && manifest.auth_target.hash.as_ref() == Some(record.transaction.auth_target())
        && manifest.config_target.readonly == manifest.config.readonly
        && manifest.auth_target.readonly == manifest.auth.readonly
}

fn record_requires_snapshot(record: &SwitchTransactionRecord) -> bool {
    record.snapshot_manifest_hash.is_some() || record.transaction.requires_snapshot_manifest()
}

fn map_transaction_create_error(error: RepositoryError) -> SwitchExecutionError {
    match error {
        RepositoryError::AlreadyExists(EntityKind::SwitchTransaction) => {
            SwitchExecutionError::RecoveryRequired
        }
        _ => SwitchExecutionError::RepositoryFailure,
    }
}
fn role_name(role: FileRole) -> &'static str {
    match role {
        FileRole::Config => CONFIG_NAME,
        FileRole::Authentication => AUTH_NAME,
    }
}
fn observe(path: &Path) -> Result<ObservedFile, SwitchExecutionError> {
    match fs::metadata(path) {
        Ok(metadata) => {
            let bytes = fs::read(path).map_err(|_| SwitchExecutionError::IoFailure)?;
            Ok(ObservedFile {
                existed: true,
                hash: Some(hash_bytes(&bytes)),
                bytes: Zeroizing::new(bytes),
                readonly: metadata.permissions().readonly(),
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(ObservedFile {
            existed: false,
            bytes: Zeroizing::new(Vec::new()),
            hash: None,
            readonly: false,
        }),
        Err(_) => Err(SwitchExecutionError::IoFailure),
    }
}
fn observe_pair(root: &Path) -> Result<(ObservedFile, ObservedFile), SwitchExecutionError> {
    Ok((
        observe(&root.join(CONFIG_NAME))?,
        observe(&root.join(AUTH_NAME))?,
    ))
}
fn pair_matches_hashes(
    pair: &(ObservedFile, ObservedFile),
    config: Option<&ContentHash>,
    auth: Option<&ContentHash>,
) -> bool {
    pair.0.hash.as_ref() == config && pair.1.hash.as_ref() == auth
}

fn file_matches_evidence(actual: &ObservedFile, expected: &FileEvidence) -> bool {
    actual.existed == expected.existed
        && actual.bytes.len() == expected.length
        && actual.hash == expected.hash
        && actual.readonly == expected.readonly
}

fn file_evidence_matches_bytes(expected: &FileEvidence, bytes: &[u8], readonly: bool) -> bool {
    expected.existed
        && expected.length == bytes.len()
        && expected.hash.as_ref() == Some(&hash_bytes(bytes))
        && expected.readonly == readonly
}

fn pair_matches_snapshot_source(
    pair: &(ObservedFile, ObservedFile),
    manifest: &SnapshotManifest,
) -> bool {
    pair_matches_observation(pair, &(manifest.config.clone(), manifest.auth.clone()))
}

fn pair_matches_snapshot_target(
    pair: &(ObservedFile, ObservedFile),
    manifest: &SnapshotManifest,
) -> bool {
    file_matches_evidence(&pair.0, &manifest.config_target)
        && file_matches_evidence(&pair.1, &manifest.auth_target)
}

fn pair_components_are_known(
    pair: &(ObservedFile, ObservedFile),
    manifest: &SnapshotManifest,
) -> bool {
    let config_known = file_matches_observation(&pair.0, &manifest.config)
        || file_matches_evidence(&pair.0, &manifest.config_target);
    let auth_known = file_matches_observation(&pair.1, &manifest.auth)
        || file_matches_evidence(&pair.1, &manifest.auth_target);
    config_known && auth_known
}
fn snapshot_dir(root: &Path, id: &codex_domain::SwitchTransactionId) -> PathBuf {
    root.join(".codextools-transactions").join(id.as_str())
}
fn snapshot_file(root: &Path, id: &codex_domain::SwitchTransactionId, role: FileRole) -> PathBuf {
    snapshot_dir(root, id).join(match role {
        FileRole::Config => "snapshot-config.bin",
        FileRole::Authentication => "snapshot-auth.bin",
    })
}
struct PreparedSensitiveTemp {
    handle: SensitiveTempFile,
    owner: SensitiveTempOwnerRecord,
}

fn write_all_with_io<I: SensitiveTempIo>(
    io: &mut I,
    file: &mut SensitiveTempFile,
    bytes: &[u8],
) -> Result<(), SwitchExecutionError> {
    let mut written = 0;
    while written < bytes.len() {
        match io.write(file, &bytes[written..]) {
            Ok(0) => return Err(SwitchExecutionError::IoFailure),
            Ok(count) if count <= bytes.len() - written => written += count,
            Ok(_) | Err(_) => return Err(SwitchExecutionError::IoFailure),
        }
    }
    Ok(())
}

fn owner_role(role: FileRole) -> SensitiveTempRole {
    match role {
        FileRole::Config => SensitiveTempRole::Config,
        FileRole::Authentication => SensitiveTempRole::Authentication,
    }
}

fn owner_publish_name(role: SensitiveTempRole) -> &'static str {
    match role {
        SensitiveTempRole::Config => CONFIG_NAME,
        SensitiveTempRole::Authentication => AUTH_NAME,
    }
}

fn owner_role_bit(role: SensitiveTempRole) -> u8 {
    match role {
        SensitiveTempRole::Config => FileRole::Config.bit(),
        SensitiveTempRole::Authentication => FileRole::Authentication.bit(),
    }
}

fn is_recovery_delete_tombstone(owner: &SensitiveTempOwnerRecord) -> bool {
    owner.phase == OwnerPhase::Recovery
        && owner.expected_length == 0
        && owner.expected_hash == hash_bytes(&[])
}

fn owner_temp_name(
    id: &codex_domain::SwitchTransactionId,
    role: SensitiveTempRole,
    phase: OwnerPhase,
    nonce: &[u8; 16],
) -> String {
    let mut nonce_hex = String::with_capacity(32);
    for byte in nonce {
        use std::fmt::Write as _;
        write!(&mut nonce_hex, "{byte:02x}").expect("writing to String cannot fail");
    }
    format!(
        ".{}.{}.{}.{}",
        owner_publish_name(role),
        id.as_str(),
        nonce_hex,
        match phase {
            OwnerPhase::Target => "stage",
            OwnerPhase::Recovery => "recovery",
        },
    )
}

fn sensitive_nonce() -> [u8; 16] {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQUENCE: AtomicU64 = AtomicU64::new(1);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |value| value.as_nanos());
    let mixed = nanos
        ^ (u128::from(std::process::id()) << 64)
        ^ u128::from(SEQUENCE.fetch_add(1, Ordering::Relaxed));
    mixed.to_be_bytes()
}

fn map_root_pin_error(error: io::Error) -> SwitchExecutionError {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::PermissionDenied => SwitchExecutionError::Busy,
        io::ErrorKind::Unsupported | io::ErrorKind::InvalidData => {
            SwitchExecutionError::CompatibilityProtected(CompatibilityReason::IoUnavailable)
        }
        _ => SwitchExecutionError::IoFailure,
    }
}

fn sensitive_temp_name_role_phase(name: &str) -> Option<(SensitiveTempRole, OwnerPhase)> {
    let role = if name.starts_with(".config.toml.") {
        SensitiveTempRole::Config
    } else if name.starts_with(".auth.json.") {
        SensitiveTempRole::Authentication
    } else {
        return None;
    };
    let phase = if name.ends_with(".stage") {
        OwnerPhase::Target
    } else if name.ends_with(".recovery") {
        OwnerPhase::Recovery
    } else {
        return None;
    };
    Some((role, phase))
}

fn sensitive_temp_name_transaction(name: &str) -> Option<codex_domain::SwitchTransactionId> {
    let prefix = if name.starts_with(".config.toml.") {
        ".config.toml."
    } else if name.starts_with(".auth.json.") {
        ".auth.json."
    } else {
        return None;
    };
    let remainder = &name[prefix.len()..];
    if remainder.len() < 36 {
        return None;
    }
    codex_domain::SwitchTransactionId::parse(&remainder[..36]).ok()
}
fn remove_file_if_exists(path: &Path) -> Result<(), SwitchExecutionError> {
    match fs::metadata(path) {
        Ok(metadata) => {
            if metadata.permissions().readonly() {
                make_writable_checked(path)?;
            }
            fs::remove_file(path).map_err(|_| SwitchExecutionError::RecoveryRequired)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(SwitchExecutionError::RecoveryRequired),
    }
}

fn write_cleanup_intent(
    root: &Path,
    id: &codex_domain::SwitchTransactionId,
    state: SwitchTransactionState,
) -> Result<(), SwitchExecutionError> {
    let directory = snapshot_dir(root, id);
    fs::create_dir_all(&directory).map_err(|_| SwitchExecutionError::RecoveryRequired)?;
    let text = format!(
        "version=1\ntransaction={}\nterminal={}\n",
        id.as_str(),
        match state {
            SwitchTransactionState::Committed => "committed",
            SwitchTransactionState::RolledBack => "rolled_back",
            _ => return Err(SwitchExecutionError::RecoveryRequired),
        }
    );
    let temporary = directory.join("cleanup.intent.tmp");
    let target = directory.join("cleanup.intent");
    remove_file_if_exists(&temporary)?;
    write_synced(&temporary, text.as_bytes(), true)?;
    if target.exists() {
        remove_file_if_exists(&target)?;
    }
    fs::rename(temporary, target).map_err(|_| SwitchExecutionError::RecoveryRequired)
}

fn auth_snapshot_entropy(
    root: &Path,
    id: &codex_domain::SwitchTransactionId,
    auth: &ObservedFile,
) -> Result<Vec<u8>, SwitchExecutionError> {
    let canonical = fs::canonicalize(root).map_err(|_| SwitchExecutionError::SnapshotInvalid)?;
    Ok(format!(
        "schema=switch-auth-snapshot-v1\nroot_ref={}\ntransaction={}\nrole=authentication\nexisted={}\nlength={}\nsha256={}\nreadonly={}\n",
        hash_bytes(canonical.to_string_lossy().to_lowercase().as_bytes()).as_str(),
        id.as_str(),
        u8::from(auth.existed),
        auth.bytes.len(),
        auth.hash.as_ref().map_or("absent", ContentHash::as_str),
        u8::from(auth.readonly),
    )
    .into_bytes())
}

fn protect_auth_snapshot(
    root: &Path,
    id: &codex_domain::SwitchTransactionId,
    auth: &ObservedFile,
) -> Result<Vec<u8>, SwitchExecutionError> {
    let entropy = auth_snapshot_entropy(root, id, auth)?;
    let protected = DpapiCurrentUser
        .protect(&entropy, &auth.bytes)
        .map_err(|_| SwitchExecutionError::SnapshotInvalid)?;
    let protected_length =
        u32::try_from(protected.len()).map_err(|_| SwitchExecutionError::SnapshotInvalid)?;
    let mut envelope = Vec::with_capacity(AUTH_SNAPSHOT_MAGIC.len() + 8 + protected.len());
    envelope.extend_from_slice(AUTH_SNAPSHOT_MAGIC);
    envelope.extend_from_slice(&AUTH_SNAPSHOT_ENVELOPE_VERSION.to_le_bytes());
    envelope.extend_from_slice(&protected_length.to_le_bytes());
    envelope.extend_from_slice(&protected);
    Ok(envelope)
}

fn unprotect_auth_snapshot(
    root: &Path,
    id: &codex_domain::SwitchTransactionId,
    auth: &ObservedFile,
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SwitchExecutionError> {
    let header = AUTH_SNAPSHOT_MAGIC.len() + 8;
    if envelope.len() < header || !envelope.starts_with(AUTH_SNAPSHOT_MAGIC) {
        return Err(SwitchExecutionError::SnapshotInvalid);
    }
    let version = u32::from_le_bytes(
        envelope[AUTH_SNAPSHOT_MAGIC.len()..AUTH_SNAPSHOT_MAGIC.len() + 4]
            .try_into()
            .map_err(|_| SwitchExecutionError::SnapshotInvalid)?,
    );
    let length = u32::from_le_bytes(
        envelope[AUTH_SNAPSHOT_MAGIC.len() + 4..header]
            .try_into()
            .map_err(|_| SwitchExecutionError::SnapshotInvalid)?,
    ) as usize;
    if version != AUTH_SNAPSHOT_ENVELOPE_VERSION || envelope.len() != header + length {
        return Err(SwitchExecutionError::SnapshotInvalid);
    }
    let entropy = auth_snapshot_entropy(root, id, auth)?;
    DpapiCurrentUser
        .unprotect(&entropy, &envelope[header..], |plaintext| {
            let mut protected_plaintext = Zeroizing::new(Vec::with_capacity(plaintext.len()));
            protected_plaintext.extend_from_slice(plaintext);
            Ok(protected_plaintext)
        })
        .map_err(|_| SwitchExecutionError::SnapshotInvalid)
}
#[allow(clippy::permissions_set_readonly_false)]
fn make_writable_checked(path: &Path) -> Result<(), SwitchExecutionError> {
    let metadata = fs::metadata(path).map_err(|_| SwitchExecutionError::IoFailure)?;
    let mut permissions = metadata.permissions();
    if permissions.readonly() {
        permissions.set_readonly(false);
        fs::set_permissions(path, permissions).map_err(|_| SwitchExecutionError::IoFailure)?;
    }
    Ok(())
}
fn write_synced(path: &Path, bytes: &[u8], create_new: bool) -> Result<(), SwitchExecutionError> {
    let mut options = OpenOptions::new();
    options.write(true);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true).truncate(true);
    }
    let mut file = options
        .open(path)
        .map_err(|_| SwitchExecutionError::IoFailure)?;
    file.write_all(bytes)
        .map_err(|_| SwitchExecutionError::IoFailure)?;
    file.flush().map_err(|_| SwitchExecutionError::IoFailure)?;
    file.sync_all().map_err(|_| SwitchExecutionError::IoFailure)
}
fn validate_target(
    plan: &SwitchPlan,
    config: &[u8],
    auth: &[u8],
) -> Result<(), SwitchExecutionError> {
    if hash_bytes(config) != hash_bytes(plan.target_config())
        || hash_bytes(auth) != hash_bytes(plan.target_auth())
    {
        return Err(SwitchExecutionError::PlanStale);
    };
    match CodexAdapter::new().scan_memory(config, auth) {
        ScanStatus::Ready(actual)
            if &actual.config.provider_id == plan.provider_id()
                && &actual.config.model_id == plan.model_id()
                && &actual.authentication.credential_fingerprint == plan.auth_fingerprint() =>
        {
            Ok(())
        }
        ScanStatus::CompatibilityProtected(reason) => {
            Err(SwitchExecutionError::CompatibilityProtected(reason))
        }
        _ => Err(SwitchExecutionError::PlanStale),
    }
}
fn validate_record_target(
    record: &SwitchTransactionRecord,
    config: &[u8],
    auth: &[u8],
) -> Result<(), SwitchExecutionError> {
    if hash_bytes(config) != *record.transaction.config_target()
        || hash_bytes(auth) != *record.transaction.auth_target()
    {
        return Err(SwitchExecutionError::RecoveryRequired);
    }
    match CodexAdapter::new().scan_memory(config, auth) {
        ScanStatus::Ready(actual)
            if &actual.config.provider_id == record.transaction.target_provider_id()
                && &actual.config.model_id == record.transaction.target_model_id()
                && &actual.authentication.credential_fingerprint
                    == record.transaction.target_auth_fingerprint() =>
        {
            Ok(())
        }
        _ => Err(SwitchExecutionError::RecoveryRequired),
    }
}
fn manifest_text(
    id: &codex_domain::SwitchTransactionId,
    config: &ObservedFile,
    auth: &ObservedFile,
    plan: &SwitchPlan,
) -> String {
    format!(
        "version={SNAPSHOT_VERSION}\ntransaction={}\nconfig.existed={}\nconfig.length={}\nconfig.sha256={}\nconfig.readonly={}\nauth.existed={}\nauth.length={}\nauth.sha256={}\nauth.readonly={}\nconfig.target.existed=1\nconfig.target.length={}\nconfig.target.sha256={}\nconfig.target.readonly={}\nauth.target.existed=1\nauth.target.length={}\nauth.target.sha256={}\nauth.target.readonly={}\n",
        id.as_str(),
        u8::from(config.existed),
        config.bytes.len(),
        config.hash.as_ref().map_or("absent", ContentHash::as_str),
        u8::from(config.readonly),
        u8::from(auth.existed),
        auth.bytes.len(),
        auth.hash.as_ref().map_or("absent", ContentHash::as_str),
        u8::from(auth.readonly),
        plan.target_config().len(),
        hash_bytes(plan.target_config()).as_str(),
        u8::from(config.readonly),
        plan.target_auth().len(),
        hash_bytes(plan.target_auth()).as_str(),
        u8::from(auth.readonly)
    )
}
fn load_snapshot(
    root: &Path,
    id: &codex_domain::SwitchTransactionId,
    expected_manifest_hash: Option<&ContentHash>,
) -> Result<SnapshotManifest, SwitchExecutionError> {
    let directory = snapshot_dir(root, id);
    let manifest_bytes = fs::read(directory.join("snapshot.manifest"))
        .map_err(|_| SwitchExecutionError::SnapshotInvalid)?;
    if expected_manifest_hash.is_some_and(|expected| hash_bytes(&manifest_bytes) != *expected) {
        return Err(SwitchExecutionError::SnapshotInvalid);
    }
    let text =
        std::str::from_utf8(&manifest_bytes).map_err(|_| SwitchExecutionError::SnapshotInvalid)?;
    let mut values = std::collections::BTreeMap::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err(SwitchExecutionError::SnapshotInvalid);
        };
        if values.insert(key, value).is_some() {
            return Err(SwitchExecutionError::SnapshotInvalid);
        }
    }
    if values.len() != 18
        || values.get("version") != Some(&"3")
        || values.get("transaction") != Some(&id.as_str())
    {
        return Err(SwitchExecutionError::SnapshotInvalid);
    };
    Ok(SnapshotManifest {
        config: load_manifest_role(root, id, &directory, &values, "config", FileRole::Config)?,
        auth: load_manifest_role(
            root,
            id,
            &directory,
            &values,
            "auth",
            FileRole::Authentication,
        )?,
        config_target: load_manifest_evidence(&values, "config.target")?,
        auth_target: load_manifest_evidence(&values, "auth.target")?,
    })
}

fn load_manifest_evidence(
    values: &std::collections::BTreeMap<&str, &str>,
    prefix: &str,
) -> Result<FileEvidence, SwitchExecutionError> {
    if values.get(format!("{prefix}.existed").as_str()) != Some(&"1") {
        return Err(SwitchExecutionError::SnapshotInvalid);
    }
    let length = values
        .get(format!("{prefix}.length").as_str())
        .ok_or(SwitchExecutionError::SnapshotInvalid)?
        .parse::<usize>()
        .map_err(|_| SwitchExecutionError::SnapshotInvalid)?;
    if length == 0 {
        return Err(SwitchExecutionError::SnapshotInvalid);
    }
    let hash = ContentHash::parse(
        values
            .get(format!("{prefix}.sha256").as_str())
            .ok_or(SwitchExecutionError::SnapshotInvalid)?,
    )
    .map_err(|_| SwitchExecutionError::SnapshotInvalid)?;
    let readonly = match values.get(format!("{prefix}.readonly").as_str()) {
        Some(&"1") => true,
        Some(&"0") => false,
        _ => return Err(SwitchExecutionError::SnapshotInvalid),
    };
    Ok(FileEvidence {
        existed: true,
        length,
        hash: Some(hash),
        readonly,
    })
}
fn load_manifest_role(
    root: &Path,
    id: &codex_domain::SwitchTransactionId,
    directory: &Path,
    values: &std::collections::BTreeMap<&str, &str>,
    prefix: &str,
    role: FileRole,
) -> Result<ObservedFile, SwitchExecutionError> {
    let existed = match values.get(format!("{prefix}.existed").as_str()) {
        Some(&"1") => true,
        Some(&"0") => false,
        _ => return Err(SwitchExecutionError::SnapshotInvalid),
    };
    let length = values
        .get(format!("{prefix}.length").as_str())
        .ok_or(SwitchExecutionError::SnapshotInvalid)?
        .parse::<usize>()
        .map_err(|_| SwitchExecutionError::SnapshotInvalid)?;
    let readonly = match values.get(format!("{prefix}.readonly").as_str()) {
        Some(&"1") => true,
        Some(&"0") => false,
        _ => return Err(SwitchExecutionError::SnapshotInvalid),
    };
    if !existed {
        if length != 0
            || readonly
            || values.get(format!("{prefix}.sha256").as_str()) != Some(&"absent")
        {
            return Err(SwitchExecutionError::SnapshotInvalid);
        };
        return Ok(ObservedFile {
            existed: false,
            bytes: Zeroizing::new(Vec::new()),
            hash: None,
            readonly,
        });
    }
    let hash = ContentHash::parse(
        values
            .get(format!("{prefix}.sha256").as_str())
            .ok_or(SwitchExecutionError::SnapshotInvalid)?,
    )
    .map_err(|_| SwitchExecutionError::SnapshotInvalid)?;
    let path = directory.join(match role {
        FileRole::Config => "snapshot-config.bin",
        FileRole::Authentication => "snapshot-auth.bin",
    });
    let stored = fs::read(path).map_err(|_| SwitchExecutionError::SnapshotInvalid)?;
    let bytes = match role {
        FileRole::Config => Zeroizing::new(stored),
        FileRole::Authentication => {
            let evidence = ObservedFile {
                existed,
                bytes: Zeroizing::new(vec![0; length]),
                hash: Some(hash.clone()),
                readonly,
            };
            unprotect_auth_snapshot(root, id, &evidence, &stored)?
        }
    };
    if bytes.len() != length || hash_bytes(&bytes) != hash {
        return Err(SwitchExecutionError::SnapshotInvalid);
    };
    Ok(ObservedFile {
        existed: true,
        bytes,
        hash: Some(hash),
        readonly,
    })
}
