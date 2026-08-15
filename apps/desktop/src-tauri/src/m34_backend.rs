use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use codex_adapter::hash_bytes;
use codex_application::{
    Clock, ControlledRoot, ControlledRootResolver, CredentialRecoveryRepository,
    CredentialReferenceRepository, CredentialStore, ModelPresetRepository,
    RuntimeIdentityRepository, StabilityWindow, SwitchExecutionError, SwitchTransactionRepository,
};
use codex_domain::{
    AuthMode, EntityVersion, IdentityId, ModelPresetId, RuntimeIdentity, SwitchTransactionId,
    SwitchTransactionState, UnixMillis,
};
use local_infrastructure::{
    DefaultCodexRootResolver, FaultDisposition, FaultInjector, FaultPoint, OpenRepositoryError,
    SqliteMetadataRepository, SwitchExecutor, SystemClock, ThreadStabilityWindow,
    VerticalClosureError, VerticalPreparedIntent, VerticalSwitchPlanner,
};
use windows_platform::WindowsDpapiCredentialStore;

use crate::application_facade::{
    AuthModeDto, BackendRecoveryResult, BackendRecoverySummary, BackendSwitchExecution,
    BackendSwitchOperation, BackendSwitchPreview, IdentitySummaryDto, M34Backend, M34BackendError,
    ModelPresetSummaryDto, PreviewSwitchRequest, SwitchCompatibilityDto, SwitchExecutionStatusDto,
    SwitchOperationStateDto,
};

const PLAN_VERSION: u64 = 1;
const PLAN_LIFETIME_MS: i64 = 5 * 60 * 1000;
const PLAN_LIMIT: usize = 128;
static PLAN_NONCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StoredPlanState {
    Ready,
    Executing,
    Completed,
    Failed,
}

#[derive(Clone)]
struct StoredPlan {
    intent: VerticalPreparedIntent,
    identity_id: IdentityId,
    identity_version: EntityVersion,
    preset_id: ModelPresetId,
    preset_version: EntityVersion,
    operation_id: String,
    expires_at: UnixMillis,
    state: StoredPlanState,
}

impl std::fmt::Debug for StoredPlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredPlan")
            .field("intent", &self.intent)
            .field("identity_id", &self.identity_id)
            .field("identity_version", &self.identity_version)
            .field("preset_id", &self.preset_id)
            .field("preset_version", &self.preset_version)
            .field("operation_id", &self.operation_id)
            .field("expires_at", &self.expires_at)
            .field("state", &self.state)
            .finish()
    }
}

#[derive(Debug)]
pub struct ProductionM34Backend {
    database_path: PathBuf,
    credential_root: PathBuf,
    plans: Mutex<HashMap<String, StoredPlan>>,
}

impl ProductionM34Backend {
    pub fn new(app_data_dir: impl AsRef<Path>) -> Result<Self, M34BackendError> {
        let app_data_dir = app_data_dir.as_ref();
        if !app_data_dir.is_absolute() {
            return Err(M34BackendError::Unavailable);
        }
        fs::create_dir_all(app_data_dir).map_err(|_| M34BackendError::Unavailable)?;
        Ok(Self {
            database_path: app_data_dir.join("metadata.sqlite3"),
            credential_root: app_data_dir.join("credentials"),
            plans: Mutex::new(HashMap::new()),
        })
    }

    fn repository(&self) -> Result<SqliteMetadataRepository, M34BackendError> {
        SqliteMetadataRepository::open(&self.database_path).map_err(map_open_error)
    }

    fn controlled_root(&self) -> Result<PathBuf, M34BackendError> {
        DefaultCodexRootResolver
            .resolve(ControlledRoot::DefaultCodex)
            .map_err(|_| M34BackendError::Unavailable)
    }

    fn preview_with_store<R, S>(
        &self,
        repository: &mut R,
        store: &mut S,
        root: &Path,
        request: &PreviewSwitchRequest,
        created_at: UnixMillis,
    ) -> Result<BackendSwitchPreview, M34BackendError>
    where
        R: CredentialReferenceRepository
            + CredentialRecoveryRepository
            + RuntimeIdentityRepository
            + ModelPresetRepository,
        S: CredentialStore,
    {
        let identity_id = IdentityId::parse(request.identity_id.as_str())
            .map_err(|_| M34BackendError::Validation)?;
        let preset_id = ModelPresetId::parse(request.preset_id.as_str())
            .map_err(|_| M34BackendError::Validation)?;
        let expected_identity = EntityVersion::new(request.expected_identity_version)
            .map_err(|_| M34BackendError::Validation)?;
        let expected_preset = EntityVersion::new(request.expected_preset_version)
            .map_err(|_| M34BackendError::Validation)?;
        let identity = repository
            .get_runtime_identity(&identity_id)
            .map_err(map_repository_error)?
            .ok_or(M34BackendError::NotFound)?;
        let preset = repository
            .get_model_preset(&preset_id)
            .map_err(map_repository_error)?
            .ok_or(M34BackendError::NotFound)?;
        if identity.version() != expected_identity
            || preset.version() != expected_preset
            || preset.identity_id() != identity.id()
            || identity.default_model_preset_id() != Some(preset.id())
        {
            return Err(M34BackendError::Conflict);
        }
        {
            let mut plans = self.plans.lock().map_err(|_| M34BackendError::Internal)?;
            plans.retain(|_, plan| plan.expires_at > created_at);
            if plans.len() >= PLAN_LIMIT
                || plans.values().any(|plan| {
                    plan.identity_id == identity_id
                        && matches!(
                            plan.state,
                            StoredPlanState::Ready | StoredPlanState::Executing
                        )
                })
            {
                return Err(M34BackendError::Conflict);
            }
        }
        let plan_id = new_opaque_uuid()?;
        let transaction_id =
            SwitchTransactionId::parse(&plan_id).map_err(|_| M34BackendError::Internal)?;
        let expires_at = UnixMillis::new(created_at.value().saturating_add(PLAN_LIFETIME_MS))
            .map_err(|_| M34BackendError::Internal)?;
        let intent = VerticalSwitchPlanner::new()
            .preview_from_store(
                repository,
                store,
                root,
                transaction_id,
                &identity,
                &preset,
                identity.credential().id(),
                created_at,
                expires_at,
            )
            .map_err(map_vertical_error)?;
        let stored = StoredPlan {
            intent,
            identity_id: identity_id.clone(),
            identity_version: identity.version(),
            preset_id: preset_id.clone(),
            preset_version: preset.version(),
            operation_id: plan_id.clone(),
            expires_at,
            state: StoredPlanState::Ready,
        };
        let mut plans = self.plans.lock().map_err(|_| M34BackendError::Internal)?;
        if plans.values().any(|plan| {
            plan.identity_id == identity_id
                && matches!(
                    plan.state,
                    StoredPlanState::Ready | StoredPlanState::Executing
                )
        }) {
            return Err(M34BackendError::Conflict);
        }
        plans.insert(plan_id.clone(), stored);
        Ok(BackendSwitchPreview {
            plan_id: plan_id.clone(),
            plan_version: PLAN_VERSION,
            operation_id: plan_id,
            identity: identity_summary(&identity),
            preset: preset_summary(&preset, true),
            affected_items: 2,
            compatibility: SwitchCompatibilityDto::Ready,
        })
    }

    fn validate_stored_plan(
        &self,
        plan_id: &str,
        expected_plan_version: u64,
        operation_id: &str,
    ) -> Result<StoredPlan, M34BackendError> {
        if expected_plan_version != PLAN_VERSION || plan_id != operation_id {
            return Err(M34BackendError::Validation);
        }
        let now = now()?;
        let stored = self
            .plans
            .lock()
            .map_err(|_| M34BackendError::Internal)?
            .get(plan_id)
            .cloned()
            .ok_or(M34BackendError::PlanStale)?;
        if stored.expires_at <= now
            || stored.operation_id != operation_id
            || stored.state != StoredPlanState::Ready
        {
            return Err(match stored.state {
                StoredPlanState::Completed => M34BackendError::Conflict,
                _ => M34BackendError::PlanStale,
            });
        }
        let repository = self.repository()?;
        let identity = repository
            .get_runtime_identity(&stored.identity_id)
            .map_err(map_repository_error)?
            .ok_or(M34BackendError::PlanStale)?;
        let preset = repository
            .get_model_preset(&stored.preset_id)
            .map_err(map_repository_error)?
            .ok_or(M34BackendError::PlanStale)?;
        if identity.version() != stored.identity_version
            || preset.version() != stored.preset_version
            || identity.default_model_preset_id() != Some(preset.id())
        {
            return Err(M34BackendError::PlanStale);
        }
        if !repository
            .list_blocking_switch_transactions(stored.intent.root_ref())
            .map_err(map_repository_error)?
            .is_empty()
        {
            return Err(M34BackendError::RecoveryRequired);
        }
        Ok(stored)
    }

    fn execute_with_store<R, S>(
        &self,
        credential_repository: &mut R,
        store: &mut S,
        switch_repository: &mut SqliteMetadataRepository,
        stored: &StoredPlan,
    ) -> Result<BackendSwitchExecution, M34BackendError>
    where
        R: CredentialReferenceRepository
            + CredentialRecoveryRepository
            + RuntimeIdentityRepository
            + ModelPresetRepository,
        S: CredentialStore,
    {
        let mut stability = ThreadStabilityWindow::new(Duration::from_millis(5));
        let mut faults = NoSwitchFaults;
        self.execute_with_runtime(
            credential_repository,
            store,
            switch_repository,
            &SystemClock,
            &mut stability,
            &mut faults,
            stored,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_with_runtime<R, S, C, W, F>(
        &self,
        credential_repository: &mut R,
        store: &mut S,
        switch_repository: &mut SqliteMetadataRepository,
        clock: &C,
        stability: &mut W,
        faults: &mut F,
        stored: &StoredPlan,
    ) -> Result<BackendSwitchExecution, M34BackendError>
    where
        R: CredentialReferenceRepository
            + CredentialRecoveryRepository
            + RuntimeIdentityRepository
            + ModelPresetRepository,
        S: CredentialStore,
        C: Clock,
        W: StabilityWindow,
        F: FaultInjector,
    {
        let identity = credential_repository
            .get_runtime_identity(&stored.identity_id)
            .map_err(map_repository_error)?
            .ok_or(M34BackendError::PlanStale)?;
        let preset = credential_repository
            .get_model_preset(&stored.preset_id)
            .map_err(map_repository_error)?
            .ok_or(M34BackendError::PlanStale)?;
        VerticalSwitchPlanner::new()
            .execute_approved(
                credential_repository,
                store,
                switch_repository,
                clock,
                stability,
                faults,
                &stored.intent,
                &identity,
                &preset,
            )
            .map_err(map_vertical_error)?;
        Ok(BackendSwitchExecution {
            status: SwitchExecutionStatusDto::Applied,
            operation: BackendSwitchOperation {
                operation_id: stored.operation_id.clone(),
                state: SwitchOperationStateDto::Completed,
                completed_items: 2,
                total_items: 2,
            },
        })
    }

    fn query_transaction(
        &self,
        operation_id: &str,
    ) -> Result<Option<BackendSwitchOperation>, M34BackendError> {
        let transaction_id =
            SwitchTransactionId::parse(operation_id).map_err(|_| M34BackendError::Validation)?;
        let repository = self.repository()?;
        repository
            .get_switch_transaction(&transaction_id)
            .map_err(map_repository_error)
            .map(|record| {
                record.map(|record| operation_from_state(operation_id, record.transaction.state()))
            })
    }

    fn root_and_ref(&self) -> Result<(PathBuf, codex_domain::ContentHash), M34BackendError> {
        let root = self.controlled_root()?;
        let canonical = fs::canonicalize(root).map_err(|_| M34BackendError::Unavailable)?;
        let root_ref = hash_bytes(canonical.to_string_lossy().to_lowercase().as_bytes());
        Ok((canonical, root_ref))
    }
}

impl M34Backend for ProductionM34Backend {
    fn preview_switch(
        &self,
        request: &PreviewSwitchRequest,
    ) -> Result<BackendSwitchPreview, M34BackendError> {
        let root = self.controlled_root()?;
        let mut repository = self.repository()?;
        let mut store = WindowsDpapiCredentialStore::new(&self.credential_root)
            .map_err(|_| M34BackendError::Unavailable)?;
        self.preview_with_store(&mut repository, &mut store, &root, request, now()?)
    }

    fn validate_switch(
        &self,
        plan_id: &str,
        expected_plan_version: u64,
        operation_id: &str,
    ) -> Result<(), M34BackendError> {
        self.validate_stored_plan(plan_id, expected_plan_version, operation_id)
            .map(|_| ())
    }

    fn execute_switch(
        &self,
        plan_id: &str,
        expected_plan_version: u64,
        operation_id: &str,
    ) -> Result<BackendSwitchExecution, M34BackendError> {
        if let Some(operation) = self.query_transaction(operation_id)? {
            return match operation.state {
                SwitchOperationStateDto::Completed => Ok(BackendSwitchExecution {
                    status: SwitchExecutionStatusDto::AlreadyApplied,
                    operation,
                }),
                SwitchOperationStateDto::RecoveryRequired => Err(M34BackendError::RecoveryRequired),
                _ => Err(M34BackendError::Conflict),
            };
        }
        let stored = self.validate_stored_plan(plan_id, expected_plan_version, operation_id)?;
        {
            let mut plans = self.plans.lock().map_err(|_| M34BackendError::Internal)?;
            let current = plans.get_mut(plan_id).ok_or(M34BackendError::PlanStale)?;
            if current.state != StoredPlanState::Ready {
                return Err(M34BackendError::Conflict);
            }
            current.state = StoredPlanState::Executing;
        }
        let result = (|| {
            let mut credential_repository = self.repository()?;
            let mut switch_repository = self.repository()?;
            let mut store = WindowsDpapiCredentialStore::new(&self.credential_root)
                .map_err(|_| M34BackendError::Unavailable)?;
            self.execute_with_store(
                &mut credential_repository,
                &mut store,
                &mut switch_repository,
                &stored,
            )
        })();
        if let Ok(mut plans) = self.plans.lock()
            && let Some(current) = plans.get_mut(plan_id)
        {
            current.state = if result.is_ok() {
                StoredPlanState::Completed
            } else {
                StoredPlanState::Failed
            };
        }
        result
    }

    fn query_switch(&self, operation_id: &str) -> Result<BackendSwitchOperation, M34BackendError> {
        if let Some(operation) = self.query_transaction(operation_id)? {
            return Ok(operation);
        }
        let plans = self.plans.lock().map_err(|_| M34BackendError::Internal)?;
        let plan = plans.get(operation_id).ok_or(M34BackendError::NotFound)?;
        Ok(BackendSwitchOperation {
            operation_id: operation_id.to_owned(),
            state: match plan.state {
                StoredPlanState::Ready => SwitchOperationStateDto::Validated,
                StoredPlanState::Executing => SwitchOperationStateDto::Committing,
                StoredPlanState::Completed => SwitchOperationStateDto::Completed,
                StoredPlanState::Failed => SwitchOperationStateDto::Failed,
            },
            completed_items: u64::from(plan.state == StoredPlanState::Completed) * 2,
            total_items: 2,
        })
    }

    fn list_recoveries(&self) -> Result<Vec<BackendRecoverySummary>, M34BackendError> {
        let (_, root_ref) = self.root_and_ref()?;
        let repository = self.repository()?;
        let blocking = repository
            .list_blocking_switch_transactions(&root_ref)
            .map_err(map_repository_error)?;
        let diagnostics = repository
            .list_recovery_required_diagnostics(&root_ref)
            .map_err(map_repository_error)?;
        let mut seen = HashSet::new();
        Ok(blocking
            .into_iter()
            .map(|record| record.transaction.id().as_str().to_owned())
            .chain(
                diagnostics
                    .into_iter()
                    .map(|diagnostic| diagnostic.record.transaction.id().as_str().to_owned()),
            )
            .filter(|recovery_id| seen.insert(recovery_id.clone()))
            .map(|recovery_id| BackendRecoverySummary {
                recovery_id,
                affected_items: 2,
            })
            .collect())
    }

    fn recover_switch(&self, recovery_id: &str) -> Result<BackendRecoveryResult, M34BackendError> {
        let recovery_id_parsed =
            SwitchTransactionId::parse(recovery_id).map_err(|_| M34BackendError::Validation)?;
        let (root, root_ref) = self.root_and_ref()?;
        let mut repository = self.repository()?;
        if !repository
            .list_blocking_switch_transactions(&root_ref)
            .map_err(map_repository_error)?
            .iter()
            .any(|record| record.transaction.id() == &recovery_id_parsed)
        {
            return Err(M34BackendError::NotFound);
        }
        let mut stability = ThreadStabilityWindow::new(Duration::from_millis(5));
        let mut faults = NoSwitchFaults;
        let recovered =
            SwitchExecutor::new(&mut repository, &SystemClock, &mut stability, &mut faults)
                .recover_root(&root)
                .map_err(map_switch_error)?;
        let record = recovered
            .into_iter()
            .find(|record| record.transaction.id() == &recovery_id_parsed)
            .ok_or(M34BackendError::RecoveryRequired)?;
        Ok(BackendRecoveryResult {
            operation: operation_from_state(recovery_id, record.transaction.state()),
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct NoSwitchFaults;
impl FaultInjector for NoSwitchFaults {
    fn check(&mut self, _: FaultPoint) -> Option<FaultDisposition> {
        None
    }
}

fn identity_summary(identity: &RuntimeIdentity) -> IdentitySummaryDto {
    IdentitySummaryDto {
        identity_id: identity.id().as_str().to_owned(),
        name: identity.name().as_str().to_owned(),
        provider_name: identity.provider_display_name().as_str().to_owned(),
        auth_mode: match identity.auth_mode() {
            AuthMode::ApiKey => AuthModeDto::ApiKey,
            AuthMode::OAuth => AuthModeDto::OAuth,
        },
        status: match identity.status() {
            codex_domain::IdentityStatus::Draft => "draft",
            codex_domain::IdentityStatus::Ready => "ready",
            codex_domain::IdentityStatus::Disabled => "disabled",
        }
        .to_owned(),
        default_preset_id: identity
            .default_model_preset_id()
            .map(|id| id.as_str().to_owned()),
        version: identity.version().value(),
    }
}

fn preset_summary(preset: &codex_domain::ModelPreset, is_default: bool) -> ModelPresetSummaryDto {
    ModelPresetSummaryDto {
        preset_id: preset.id().as_str().to_owned(),
        name: preset.name().as_str().to_owned(),
        model_id: preset.model_id().as_str().to_owned(),
        version: preset.version().value(),
        is_default,
    }
}

fn operation_from_state(
    operation_id: &str,
    state: SwitchTransactionState,
) -> BackendSwitchOperation {
    let mapped = match state {
        SwitchTransactionState::Planned => SwitchOperationStateDto::Queued,
        SwitchTransactionState::LockAcquired => SwitchOperationStateDto::Preparing,
        SwitchTransactionState::SnapshotCreated | SwitchTransactionState::TargetsStaged => {
            SwitchOperationStateDto::Validated
        }
        SwitchTransactionState::Replacing
        | SwitchTransactionState::TargetsReplaced
        | SwitchTransactionState::Verified => SwitchOperationStateDto::Committing,
        SwitchTransactionState::Committed => SwitchOperationStateDto::Completed,
        SwitchTransactionState::RollingBack | SwitchTransactionState::RecoveryRequired => {
            SwitchOperationStateDto::RecoveryRequired
        }
        SwitchTransactionState::RolledBack => SwitchOperationStateDto::Failed,
    };
    BackendSwitchOperation {
        operation_id: operation_id.to_owned(),
        state: mapped,
        completed_items: u64::from(mapped == SwitchOperationStateDto::Completed) * 2,
        total_items: 2,
    }
}

fn map_open_error(error: OpenRepositoryError) -> M34BackendError {
    match error {
        OpenRepositoryError::CorruptData => M34BackendError::RecoveryRequired,
        OpenRepositoryError::Migration(_) | OpenRepositoryError::StorageUnavailable => {
            M34BackendError::Unavailable
        }
    }
}

fn map_repository_error(error: codex_application::RepositoryError) -> M34BackendError {
    match error {
        codex_application::RepositoryError::NotFound(_) => M34BackendError::NotFound,
        codex_application::RepositoryError::AlreadyExists(_)
        | codex_application::RepositoryError::VersionConflict(_)
        | codex_application::RepositoryError::ReferenceConflict(_) => M34BackendError::Conflict,
        codex_application::RepositoryError::CorruptData => M34BackendError::RecoveryRequired,
        codex_application::RepositoryError::StorageUnavailable => M34BackendError::Unavailable,
    }
}

fn map_vertical_error(error: VerticalClosureError) -> M34BackendError {
    match error {
        VerticalClosureError::CompatibilityProtected(_) => M34BackendError::CompatibilityProtected,
        VerticalClosureError::InvalidTarget => M34BackendError::PlanStale,
        VerticalClosureError::IoFailure => M34BackendError::Unavailable,
        VerticalClosureError::Credential(error) => match error {
            local_infrastructure::CredentialServiceError::NotFound => M34BackendError::NotFound,
            local_infrastructure::CredentialServiceError::VersionConflict
            | local_infrastructure::CredentialServiceError::ReferenceConflict
            | local_infrastructure::CredentialServiceError::AlreadyExists => {
                M34BackendError::Conflict
            }
            local_infrastructure::CredentialServiceError::RecoveryRequired => {
                M34BackendError::RecoveryRequired
            }
            local_infrastructure::CredentialServiceError::InvalidSecret => {
                M34BackendError::Validation
            }
            local_infrastructure::CredentialServiceError::StoreFailure
            | local_infrastructure::CredentialServiceError::RepositoryFailure => {
                M34BackendError::Unavailable
            }
        },
        VerticalClosureError::Switch(error) => map_switch_error(error),
    }
}

fn map_switch_error(error: SwitchExecutionError) -> M34BackendError {
    match error {
        SwitchExecutionError::Busy => M34BackendError::Conflict,
        SwitchExecutionError::PlanStale => M34BackendError::PlanStale,
        SwitchExecutionError::CompatibilityProtected(_) => M34BackendError::CompatibilityProtected,
        SwitchExecutionError::InvalidPlan => M34BackendError::Validation,
        SwitchExecutionError::SnapshotInvalid | SwitchExecutionError::RecoveryRequired => {
            M34BackendError::RecoveryRequired
        }
        SwitchExecutionError::IoFailure | SwitchExecutionError::RepositoryFailure => {
            M34BackendError::Unavailable
        }
        SwitchExecutionError::InjectedFailure | SwitchExecutionError::Interrupted => {
            M34BackendError::Internal
        }
    }
}

fn now() -> Result<UnixMillis, M34BackendError> {
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| M34BackendError::Unavailable)?
        .as_millis();
    UnixMillis::new(i64::try_from(value).map_err(|_| M34BackendError::Unavailable)?)
        .map_err(|_| M34BackendError::Unavailable)
}

fn new_opaque_uuid() -> Result<String, M34BackendError> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| M34BackendError::Unavailable)?
        .as_nanos();
    let nonce = u128::from(PLAN_NONCE.fetch_add(1, Ordering::Relaxed));
    let value = nanos ^ (u128::from(std::process::id()) << 64) ^ nonce;
    let mut hex = format!("{value:032x}").into_bytes();
    hex[12] = b'4';
    hex[16] = b'8';
    let value = String::from_utf8(hex).map_err(|_| M34BackendError::Internal)?;
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &value[0..8],
        &value[8..12],
        &value[12..16],
        &value[16..20],
        &value[20..32]
    ))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        fs, io,
        path::PathBuf,
        thread,
    };

    use codex_adapter::CodexAdapter;
    use codex_application::{
        CredentialEnvelopeBinding, CredentialMutationOwner, CredentialStoreError,
        ImportIdentityInput, ImportOutcome, SecretConsumer, import_scanned_identity,
    };
    use codex_domain::{
        CredentialBackend, CredentialKind, CredentialRefId, CredentialReference, EntityName,
        ManagedConfigPatchId,
    };

    use super::*;

    struct FixedClock(UnixMillis);
    impl Clock for FixedClock {
        fn now(&self) -> UnixMillis {
            self.0
        }
    }

    struct NoWait;
    impl StabilityWindow for NoWait {
        fn between_observations(&mut self, _: &Path) -> Result<(), SwitchExecutionError> {
            Ok(())
        }
    }

    struct InterruptOnce {
        point: FaultPoint,
        fired: bool,
    }
    impl FaultInjector for InterruptOnce {
        fn check(&mut self, point: FaultPoint) -> Option<FaultDisposition> {
            if point == self.point && !self.fired {
                self.fired = true;
                Some(FaultDisposition::Interrupt)
            } else {
                None
            }
        }
    }

    struct TempArea {
        temp_root: PathBuf,
        root: PathBuf,
        live: PathBuf,
        app_data: PathBuf,
        created_by_helper: bool,
    }

    const TEMP_AREA_CREATE_ATTEMPTS: usize = 128;
    const TEMP_AREA_PREFIX: &str = "codextools-m34-backend-";
    static TEMP_AREA_NONCE: AtomicU64 = AtomicU64::new(1);

    fn next_temp_area_candidate(
        temp_root: &Path,
        process_id: u32,
        timestamp_nanos: u128,
    ) -> PathBuf {
        let nonce = TEMP_AREA_NONCE.fetch_add(1, Ordering::Relaxed);
        temp_root.join(format!(
            "{TEMP_AREA_PREFIX}{process_id}-{timestamp_nanos}-{nonce}"
        ))
    }

    impl TempArea {
        fn new() -> Self {
            Self::new_with_timestamp(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            })
            .unwrap()
        }

        fn new_with_timestamp(mut timestamp_nanos: impl FnMut() -> u128) -> io::Result<Self> {
            let temp_root = std::env::temp_dir();
            Self::try_new_with_candidate(&temp_root, || {
                next_temp_area_candidate(&temp_root, std::process::id(), timestamp_nanos())
            })
        }

        fn try_new_with_candidate(
            temp_root: &Path,
            mut next_candidate: impl FnMut() -> PathBuf,
        ) -> io::Result<Self> {
            for _ in 0..TEMP_AREA_CREATE_ATTEMPTS {
                let root = next_candidate();
                let is_direct_test_child = root.parent() == Some(temp_root)
                    && root
                        .file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with(TEMP_AREA_PREFIX));
                if !is_direct_test_child {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "M3.4 fixture root must be a direct system-temp child",
                    ));
                }
                match fs::create_dir(&root) {
                    Ok(()) => return Self::initialize_owned(temp_root.to_path_buf(), root),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(error),
                }
            }
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "M3.4 fixture exhausted unique-create attempts",
            ))
        }

        fn initialize_owned(temp_root: PathBuf, root: PathBuf) -> io::Result<Self> {
            let live = root.join("live");
            let app_data = root.join("app-data");
            let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../../tests/fixtures/g1-api-key");
            let initialized = (|| -> io::Result<()> {
                fs::create_dir(&live)?;
                fs::create_dir(&app_data)?;
                fs::copy(fixture.join("config.toml"), live.join("config.toml"))?;
                fs::copy(fixture.join("auth.json"), live.join("auth.json"))?;
                Ok(())
            })();
            if let Err(error) = initialized {
                let _ = fs::remove_dir_all(&root);
                return Err(error);
            }
            Ok(Self {
                temp_root,
                root,
                live,
                app_data,
                created_by_helper: true,
            })
        }
    }

    impl Drop for TempArea {
        fn drop(&mut self) {
            let is_exact_owned_root = self.created_by_helper
                && self.root.parent() == Some(self.temp_root.as_path())
                && self
                    .root
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(TEMP_AREA_PREFIX));
            if is_exact_owned_root {
                let _ = fs::remove_dir_all(&self.root);
                self.created_by_helper = false;
            }
        }
    }

    #[derive(Default)]
    struct FakeCredentialStore {
        material: HashMap<String, Vec<u8>>,
        owner: bool,
    }

    impl CredentialStore for FakeCredentialStore {
        fn begin_mutation(
            &mut self,
            id: &CredentialRefId,
        ) -> Result<CredentialMutationOwner, CredentialStoreError> {
            if self.owner {
                return Err(CredentialStoreError::RecoveryRequired);
            }
            self.owner = true;
            Ok(CredentialMutationOwner::new(id.clone(), 1))
        }

        fn end_mutation(&mut self, _: CredentialMutationOwner) -> Result<(), CredentialStoreError> {
            if !self.owner {
                return Err(CredentialStoreError::RecoveryRequired);
            }
            self.owner = false;
            Ok(())
        }

        fn create(
            &mut self,
            binding: &CredentialEnvelopeBinding,
            secret: &mut [u8],
        ) -> Result<(), CredentialStoreError> {
            self.material
                .insert(binding.id().as_str().to_owned(), secret.to_vec());
            Ok(())
        }

        fn read(
            &self,
            binding: &CredentialEnvelopeBinding,
            consumer: &mut dyn SecretConsumer,
        ) -> Result<(), CredentialStoreError> {
            consumer.consume(
                self.material
                    .get(binding.id().as_str())
                    .ok_or(CredentialStoreError::NotFound)?,
            )
        }

        fn rotate(
            &mut self,
            _: &CredentialEnvelopeBinding,
            _: &CredentialEnvelopeBinding,
            _: &mut [u8],
        ) -> Result<(), CredentialStoreError> {
            Err(CredentialStoreError::RecoveryRequired)
        }
        fn delete(&mut self, _: &CredentialEnvelopeBinding) -> Result<(), CredentialStoreError> {
            Err(CredentialStoreError::RecoveryRequired)
        }
    }

    fn seed_target(
        _area: &TempArea,
        repository: &mut SqliteMetadataRepository,
        store: &mut FakeCredentialStore,
    ) -> (RuntimeIdentity, codex_domain::ModelPreset) {
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../tests/fixtures/g2-oauth");
        let config = fs::read(fixture.join("config.toml")).unwrap();
        let auth = fs::read(fixture.join("auth.json")).unwrap();
        let codex_application::ScanStatus::Ready(actual) =
            CodexAdapter::new().scan_memory(&config, &auth)
        else {
            panic!("synthetic target")
        };
        let credential = CredentialReference::new(
            CredentialRefId::parse("32323232-3232-4232-8232-323232323232").unwrap(),
            match actual.authentication.auth_mode {
                AuthMode::ApiKey => CredentialKind::ApiKey,
                AuthMode::OAuth => CredentialKind::OAuthBundle,
            },
            CredentialBackend::WindowsDpapiCurrentUser,
            local_infrastructure::credential_material_schema_fingerprint(
                match actual.authentication.auth_mode {
                    AuthMode::ApiKey => CredentialKind::ApiKey,
                    AuthMode::OAuth => CredentialKind::OAuthBundle,
                },
            ),
            actual.authentication.credential_fingerprint.clone(),
            UnixMillis::new(10).unwrap(),
        );
        repository.create_credential_reference(&credential).unwrap();
        store
            .material
            .insert(credential.id().as_str().to_owned(), auth);
        let identity_id = IdentityId::parse("42424242-4242-4242-8242-424242424242").unwrap();
        let preset_id = ModelPresetId::parse("52525252-5252-4252-8252-525252525252").unwrap();
        assert_eq!(
            import_scanned_identity(
                repository,
                &actual,
                ImportIdentityInput {
                    identity_id: identity_id.clone(),
                    identity_name: EntityName::parse("Synthetic identity").unwrap(),
                    preset_id: preset_id.clone(),
                    preset_name: EntityName::parse("Synthetic preset").unwrap(),
                    patch_id: ManagedConfigPatchId::parse("62626262-6262-4262-8262-626262626262")
                        .unwrap(),
                    credential: Some(credential),
                    credential_already_persisted: true,
                    now: UnixMillis::new(20).unwrap(),
                },
            )
            .unwrap(),
            ImportOutcome::Imported
        );
        (
            repository
                .get_runtime_identity(&identity_id)
                .unwrap()
                .unwrap(),
            repository.get_model_preset(&preset_id).unwrap().unwrap(),
        )
    }

    #[test]
    fn temp_area_candidate_is_unique_for_identical_timestamp() {
        let temp_root = std::env::temp_dir();
        let first = next_temp_area_candidate(&temp_root, 17, 23);
        let second = next_temp_area_candidate(&temp_root, 17, 23);

        assert_ne!(first, second, "同一进程与同一时间戳不得复用 fixture 根");
    }

    #[test]
    fn temp_area_unique_create_retries_without_owning_existing_directory() {
        let temp_root = std::env::temp_dir();
        let collision = loop {
            let candidate = next_temp_area_candidate(&temp_root, std::process::id(), 29);
            match fs::create_dir(&candidate) {
                Ok(()) => break candidate,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("collision fixture create failed: {error}"),
            }
        };
        let unique = next_temp_area_candidate(&temp_root, std::process::id(), 29);
        let mut calls = 0;
        let area = TempArea::try_new_with_candidate(&temp_root, || {
            calls += 1;
            if calls == 1 {
                collision.clone()
            } else {
                unique.clone()
            }
        })
        .unwrap();
        let owned = area.root.clone();

        assert_eq!(calls, 2);
        assert_ne!(owned, collision);
        drop(area);
        assert!(collision.is_dir(), "helper 不得清理碰撞的既有目录");
        assert!(!owned.exists(), "helper 必须清理自己唯一创建的目录");
        fs::remove_dir(&collision).unwrap();
    }

    #[test]
    fn concurrent_same_timestamp_temp_areas_are_isolated_and_cleaned() {
        const WORKERS: usize = 64;
        const FIXED_TIMESTAMP_NANOS: u128 = 31;

        let handles = (0..WORKERS)
            .map(|_| {
                thread::spawn(|| {
                    let area = TempArea::new_with_timestamp(|| FIXED_TIMESTAMP_NANOS).unwrap();
                    let backend = ProductionM34Backend::new(&area.app_data).unwrap();
                    let mut repository = backend.repository().unwrap();
                    let mut store = FakeCredentialStore::default();
                    let _ = seed_target(&area, &mut repository, &mut store);
                    fs::create_dir(&backend.credential_root).unwrap();
                    assert!(backend.database_path.is_file());
                    assert!(backend.credential_root.is_dir());
                    area
                })
            })
            .collect::<Vec<_>>();
        let areas = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        let roots = areas
            .iter()
            .map(|area| area.root.clone())
            .collect::<Vec<_>>();
        let app_data_roots = areas
            .iter()
            .map(|area| area.app_data.clone())
            .collect::<HashSet<_>>();
        let credential_roots = areas
            .iter()
            .map(|area| area.app_data.join("credentials"))
            .collect::<HashSet<_>>();

        assert_eq!(roots.iter().collect::<HashSet<_>>().len(), WORKERS);
        assert_eq!(app_data_roots.len(), WORKERS);
        assert_eq!(credential_roots.len(), WORKERS);
        assert!(roots.iter().all(|root| root.is_dir()));
        drop(areas);
        assert!(roots.iter().all(|root| !root.exists()));
    }

    #[test]
    fn synthetic_preview_and_execute_reuse_m2_plan_without_real_store_or_root() {
        let area = TempArea::new();
        let backend = ProductionM34Backend::new(&area.app_data).unwrap();
        let mut repository = backend.repository().unwrap();
        let mut store = FakeCredentialStore::default();
        let (identity, preset) = seed_target(&area, &mut repository, &mut store);
        let request = PreviewSwitchRequest {
            schema_version: 1,
            correlation_id: crate::application_facade::SafeIdentifier::parse("synthetic-corr")
                .unwrap(),
            identity_id: crate::application_facade::SafeIdentifier::parse(identity.id().as_str())
                .unwrap(),
            expected_identity_version: identity.version().value(),
            preset_id: crate::application_facade::SafeIdentifier::parse(preset.id().as_str())
                .unwrap(),
            expected_preset_version: preset.version().value(),
        };
        let preview = backend
            .preview_with_store(
                &mut repository,
                &mut store,
                &area.live,
                &request,
                now().unwrap(),
            )
            .unwrap();
        assert_eq!(preview.affected_items, 2);
        assert_eq!(
            backend.preview_with_store(
                &mut repository,
                &mut store,
                &area.live,
                &request,
                now().unwrap()
            ),
            Err(M34BackendError::Conflict)
        );
        assert!(
            backend
                .validate_stored_plan(&preview.plan_id, 1, &preview.operation_id)
                .is_ok()
        );
        let stored = backend
            .plans
            .lock()
            .unwrap()
            .get(&preview.plan_id)
            .unwrap()
            .clone();
        backend
            .plans
            .lock()
            .unwrap()
            .get_mut(&preview.plan_id)
            .unwrap()
            .state = StoredPlanState::Executing;
        let mut switch_repository = backend.repository().unwrap();
        let result = backend
            .execute_with_store(&mut repository, &mut store, &mut switch_repository, &stored)
            .unwrap();
        assert_eq!(result.status, SwitchExecutionStatusDto::Applied);
        let operation = backend
            .query_transaction(&preview.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(operation.state, SwitchOperationStateDto::Completed);
        assert_eq!(
            M34Backend::execute_switch(&backend, &preview.plan_id, 1, &preview.operation_id)
                .unwrap()
                .status,
            SwitchExecutionStatusDto::AlreadyApplied
        );
        assert!(!store.owner);
    }

    #[test]
    fn synthetic_material_change_after_preview_fails_closed_as_plan_stale() {
        let area = TempArea::new();
        let backend = ProductionM34Backend::new(&area.app_data).unwrap();
        let mut repository = backend.repository().unwrap();
        let mut store = FakeCredentialStore::default();
        let (identity, preset) = seed_target(&area, &mut repository, &mut store);
        let request = PreviewSwitchRequest {
            schema_version: 1,
            correlation_id: crate::application_facade::SafeIdentifier::parse("stale-corr").unwrap(),
            identity_id: crate::application_facade::SafeIdentifier::parse(identity.id().as_str())
                .unwrap(),
            expected_identity_version: identity.version().value(),
            preset_id: crate::application_facade::SafeIdentifier::parse(preset.id().as_str())
                .unwrap(),
            expected_preset_version: preset.version().value(),
        };
        let preview = backend
            .preview_with_store(
                &mut repository,
                &mut store,
                &area.live,
                &request,
                now().unwrap(),
            )
            .unwrap();
        fs::write(area.live.join("config.toml"), b"synthetic changed state\n").unwrap();
        let stored = backend
            .plans
            .lock()
            .unwrap()
            .get(&preview.plan_id)
            .unwrap()
            .clone();
        let mut switch_repository = backend.repository().unwrap();
        assert_eq!(
            backend.execute_with_store(
                &mut repository,
                &mut store,
                &mut switch_repository,
                &stored
            ),
            Err(M34BackendError::PlanStale)
        );
        assert!(!store.owner);
    }

    #[test]
    fn interrupted_synthetic_execute_reopens_through_m2_recovery_without_replay() {
        let area = TempArea::new();
        let backend = ProductionM34Backend::new(&area.app_data).unwrap();
        let mut repository = backend.repository().unwrap();
        let mut store = FakeCredentialStore::default();
        let (identity, preset) = seed_target(&area, &mut repository, &mut store);
        let request = PreviewSwitchRequest {
            schema_version: 1,
            correlation_id: crate::application_facade::SafeIdentifier::parse("recovery-corr")
                .unwrap(),
            identity_id: crate::application_facade::SafeIdentifier::parse(identity.id().as_str())
                .unwrap(),
            expected_identity_version: identity.version().value(),
            preset_id: crate::application_facade::SafeIdentifier::parse(preset.id().as_str())
                .unwrap(),
            expected_preset_version: preset.version().value(),
        };
        let preview = backend
            .preview_with_store(
                &mut repository,
                &mut store,
                &area.live,
                &request,
                now().unwrap(),
            )
            .unwrap();
        let stored = backend
            .plans
            .lock()
            .unwrap()
            .get(&preview.plan_id)
            .unwrap()
            .clone();
        let execution_time = UnixMillis::new(stored.intent.created_at().value() + 100).unwrap();
        let mut switch_repository = backend.repository().unwrap();
        let mut wait = NoWait;
        let mut interrupt = InterruptOnce {
            point: FaultPoint::AfterConfigReplace,
            fired: false,
        };
        assert_eq!(
            backend.execute_with_runtime(
                &mut repository,
                &mut store,
                &mut switch_repository,
                &FixedClock(execution_time),
                &mut wait,
                &mut interrupt,
                &stored,
            ),
            Err(M34BackendError::Internal)
        );
        drop(switch_repository);
        let mut recovery_repository = backend.repository().unwrap();
        let recovery_time = UnixMillis::new(execution_time.value() + 100).unwrap();
        let mut recovery_faults = NoSwitchFaults;
        let recovered = SwitchExecutor::new(
            &mut recovery_repository,
            &FixedClock(recovery_time),
            &mut wait,
            &mut recovery_faults,
        )
        .recover_root(&area.live)
        .unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(
            recovered[0].transaction.state(),
            SwitchTransactionState::RolledBack
        );
        assert_eq!(
            backend
                .query_transaction(&preview.operation_id)
                .unwrap()
                .unwrap()
                .state,
            SwitchOperationStateDto::Failed
        );
        let transaction_dir = area.live.join(".codextools-transactions");
        assert!(
            !transaction_dir.exists() || fs::read_dir(transaction_dir).unwrap().next().is_none()
        );
        assert!(!store.owner);
    }
}
