use std::cell::RefCell;

use codex_application::{
    ActualCodexState, AuthenticationDescriptor, CaptureImportBundlePreflight,
    CaptureImportBundleRepository, CaptureImportCredentialOrigin, CaptureImportDiagnostic,
    CaptureImportPhase, CaptureImportRecoveryRecord, CaptureImportRecoveryRepository,
    CaptureImportRequest, CaptureImportStatus, ControlledCodexSource, ControlledRoot,
    ControlledScanStatus, ControlledSourceError, CredentialRecoveryRepository,
    CredentialReferenceRepository, CredentialStore, CredentialStoreError, IdentityBundle,
    IdentityBundleRepository, ImportIdentityInput, ManagedConfigPatchRepository,
    ModelPresetRepository, RepositoryError, RuntimeIdentityRepository, ScannedAuthConsumer,
    ScannedConfig, SecretConsumer, build_scanned_identity_bundle,
};
use codex_domain::{AuthMode, CredentialKind, CredentialReference, EntityVersion, IdentityId};

use crate::{CredentialService, CredentialServiceError, ScopedCredentialError};

#[derive(Clone, Copy, Debug, Default)]
pub struct CaptureImportService;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureImportFaultPoint {
    AfterJournalPrepared,
    AfterCredentialReady,
    BeforeBundleCommit,
    AfterBundleCommitted,
    BeforeJournalCleanup,
}

pub trait CaptureImportFaults {
    fn interrupt(&mut self, point: CaptureImportFaultPoint) -> bool;
}

#[derive(Default)]
pub struct NoCaptureImportFaults;

impl CaptureImportFaults for NoCaptureImportFaults {
    fn interrupt(&mut self, _point: CaptureImportFaultPoint) -> bool {
        false
    }
}

impl CaptureImportService {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    pub fn scan<S: ControlledCodexSource>(
        &self,
        source: &S,
        root: ControlledRoot,
    ) -> ControlledScanStatus {
        source.scan(root)
    }

    pub fn capture_import<S, R, C>(
        &self,
        source: &S,
        repository: &mut R,
        store: &mut C,
        request: CaptureImportRequest,
    ) -> CaptureImportStatus
    where
        S: ControlledCodexSource,
        R: CaptureImportRepository,
        C: CredentialStore,
    {
        self.capture_import_with_faults(
            source,
            repository,
            store,
            request,
            &mut NoCaptureImportFaults,
        )
    }

    pub fn capture_import_with_faults<S, R, C, F>(
        &self,
        source: &S,
        repository: &mut R,
        store: &mut C,
        request: CaptureImportRequest,
        faults: &mut F,
    ) -> CaptureImportStatus
    where
        S: ControlledCodexSource,
        R: CaptureImportRepository,
        C: CredentialStore,
        F: CaptureImportFaults,
    {
        let operation_id = operation_id(&request);
        let existing = match repository.get_capture_import_recovery(&operation_id) {
            Ok(existing) => existing,
            Err(_) => {
                return CaptureImportStatus::RecoveryRequired(
                    CaptureImportDiagnostic::JournalUnavailable,
                );
            }
        };
        if let Some(record) = existing.as_ref() {
            if !record_matches_request(record, &request) {
                return CaptureImportStatus::Conflict;
            }
            if record.phase == CaptureImportPhase::BundleReady {
                return finish_completed(repository, store, record);
            }
            if record.phase == CaptureImportPhase::RecoveryRequired
                && record.diagnostic == Some(CaptureImportDiagnostic::InconsistentState)
            {
                return rollback_conflicted_capture(repository, store, record);
            }
            match committed_bundle_state(repository, store, record) {
                Ok(AggregateState::Exact) => {
                    let bundle_ready = match transition(
                        repository,
                        record.clone(),
                        CaptureImportPhase::BundleReady,
                        None,
                    ) {
                        Ok(record) => record,
                        Err(status) => return status,
                    };
                    return finish_completed(repository, store, &bundle_ready);
                }
                Ok(AggregateState::Empty) => {}
                Ok(AggregateState::Conflict) | Err(()) => {
                    return CaptureImportStatus::RecoveryRequired(
                        CaptureImportDiagnostic::InconsistentState,
                    );
                }
            }
        }

        let credential_id = request.credential_id.clone();
        match CredentialService::new(repository, store).with_mutation_owner_scoped(
            &credential_id,
            |repository, store| {
                let mut consumer = CaptureConsumer {
                    repository,
                    store,
                    request,
                    operation_id,
                    existing,
                    result: None,
                    faults,
                };
                let root = consumer.request.root;
                let scan_id = consumer.request.scan_id.clone();
                let status = match source.consume_confirmed(root, &scan_id, &mut consumer) {
                    Ok(()) => consumer
                        .result
                        .unwrap_or(CaptureImportStatus::RecoveryRequired(
                            CaptureImportDiagnostic::InconsistentState,
                        )),
                    Err(ControlledSourceError::CompatibilityProtected(reason)) => {
                        CaptureImportStatus::CompatibilityProtected(reason)
                    }
                    Err(ControlledSourceError::ScanChanged) => CaptureImportStatus::Conflict,
                    Err(ControlledSourceError::IoUnavailable | ControlledSourceError::Busy) => {
                        CaptureImportStatus::CompatibilityProtected(
                            codex_application::CompatibilityReason::IoUnavailable,
                        )
                    }
                    Err(ControlledSourceError::ConsumerRejected) => consumer
                        .result
                        .unwrap_or(CaptureImportStatus::RecoveryRequired(
                            CaptureImportDiagnostic::InconsistentState,
                        )),
                    Err(ControlledSourceError::RecoveryRequired) => {
                        CaptureImportStatus::RecoveryRequired(
                            CaptureImportDiagnostic::InconsistentState,
                        )
                    }
                };
                Ok::<_, CaptureImportStatus>(status)
            },
        ) {
            Ok(status) => status,
            Err(ScopedCredentialError::Operation(status)) => status,
            Err(ScopedCredentialError::Credential(
                CredentialServiceError::AlreadyExists
                | CredentialServiceError::VersionConflict
                | CredentialServiceError::InvalidSecret,
            )) => CaptureImportStatus::Conflict,
            Err(ScopedCredentialError::Credential(_)) => CaptureImportStatus::RecoveryRequired(
                CaptureImportDiagnostic::CredentialPending,
            ),
        }
    }

    /// 仅依据持久化的非秘密 operation intent 收敛完成态或精确回滚态。
    /// Prepared/CredentialReady 的前滚仍需要重新读取已确认的受控 auth，因此返回稳定诊断。
    pub fn recover_capture_import<R, C>(
        &self,
        repository: &mut R,
        store: &mut C,
        identity_id: &IdentityId,
    ) -> CaptureImportStatus
    where
        R: CaptureImportRepository,
        C: CredentialStore,
    {
        let operation_id = format!("capture-import:{}", identity_id.as_str());
        let record = match repository.get_capture_import_recovery(&operation_id) {
            Ok(Some(record)) => record,
            Ok(None) => return CaptureImportStatus::Conflict,
            Err(_) => {
                return CaptureImportStatus::RecoveryRequired(
                    CaptureImportDiagnostic::JournalUnavailable,
                );
            }
        };
        if record.phase == CaptureImportPhase::BundleReady {
            return finish_completed(repository, store, &record);
        }
        if record.phase == CaptureImportPhase::RecoveryRequired
            && record.diagnostic == Some(CaptureImportDiagnostic::InconsistentState)
        {
            return rollback_conflicted_capture(repository, store, &record);
        }
        match committed_bundle_state(repository, store, &record) {
            Ok(AggregateState::Exact) => {
                let ready =
                    match transition(repository, record, CaptureImportPhase::BundleReady, None) {
                        Ok(ready) => ready,
                        Err(status) => return status,
                    };
                finish_completed(repository, store, &ready)
            }
            Ok(AggregateState::Empty) => {
                CaptureImportStatus::RecoveryRequired(match record.phase {
                    CaptureImportPhase::Prepared => CaptureImportDiagnostic::CredentialPending,
                    CaptureImportPhase::CredentialReady => CaptureImportDiagnostic::BundlePending,
                    CaptureImportPhase::RecoveryRequired => record
                        .diagnostic
                        .unwrap_or(CaptureImportDiagnostic::InconsistentState),
                    CaptureImportPhase::BundleReady => CaptureImportDiagnostic::CleanupPending,
                })
            }
            Ok(AggregateState::Conflict) | Err(()) => {
                CaptureImportStatus::RecoveryRequired(CaptureImportDiagnostic::InconsistentState)
            }
        }
    }
}

pub trait CaptureImportRepository:
    CaptureImportRecoveryRepository
    + CaptureImportBundleRepository
    + CredentialReferenceRepository
    + CredentialRecoveryRepository
    + IdentityBundleRepository
    + RuntimeIdentityRepository
    + ModelPresetRepository
    + ManagedConfigPatchRepository
{
}

impl<T> CaptureImportRepository for T where
    T: CaptureImportRecoveryRepository
        + CaptureImportBundleRepository
        + CredentialReferenceRepository
        + CredentialRecoveryRepository
        + IdentityBundleRepository
        + RuntimeIdentityRepository
        + ModelPresetRepository
        + ManagedConfigPatchRepository
{
}

struct CaptureConsumer<'a, R, C, F> {
    repository: &'a mut R,
    store: &'a mut C,
    request: CaptureImportRequest,
    operation_id: String,
    existing: Option<CaptureImportRecoveryRecord>,
    result: Option<CaptureImportStatus>,
    faults: &'a mut F,
}

impl<R, C, F> ScannedAuthConsumer for CaptureConsumer<'_, R, C, F>
where
    R: CaptureImportRepository,
    C: CredentialStore,
    F: CaptureImportFaults,
{
    fn consume(
        &mut self,
        actual: &ActualCodexState,
        auth: &mut [u8],
    ) -> Result<(), ControlledSourceError> {
        self.result = Some(self.run(actual, auth));
        Ok(())
    }
}

impl<R, C, F> CaptureConsumer<'_, R, C, F>
where
    R: CaptureImportRepository,
    C: CredentialStore,
    F: CaptureImportFaults,
{
    fn run(&mut self, actual: &ActualCodexState, auth: &mut [u8]) -> CaptureImportStatus {
        if self.existing.is_none() {
            match self
                .repository
                .get_credential_reference(&self.request.credential_id)
            {
                Ok(Some(credential)) => {
                    if AuthMode::from(credential.kind()) != actual.authentication.auth_mode
                        || credential.credential_fingerprint()
                            != &actual.authentication.credential_fingerprint
                        || !verify_material_locked(self.repository, self.store, &credential)
                            .unwrap_or(false)
                    {
                        return CaptureImportStatus::Conflict;
                    }
                    let bundle =
                        match expected_bundle_from_actual(&self.request, actual, credential) {
                            Ok(bundle) => bundle,
                            Err(()) => return CaptureImportStatus::Conflict,
                        };
                    match aggregate_state(self.repository, &bundle) {
                        Ok(AggregateState::Exact) => {
                            return CaptureImportStatus::AlreadyImported(
                                self.request.identity_id.clone(),
                            );
                        }
                        Ok(AggregateState::Empty) => {}
                        _ => return CaptureImportStatus::Conflict,
                    }
                }
                Ok(None) => {}
                Err(_) => {
                    return CaptureImportStatus::RecoveryRequired(
                        CaptureImportDiagnostic::InconsistentState,
                    );
                }
            }
        }
        let kind = kind_from(actual.authentication.auth_mode);
        let existing = self.existing.take();
        let faults = RefCell::new(&mut *self.faults);
        let scoped = CredentialService::new(self.repository, self.store)
            .capture_auth_document_prepared_under_owner(
                self.request.credential_id.clone(),
                kind,
                auth,
                self.request.now,
                |repository, _store, origin, credential| {
                    let origin = existing
                        .as_ref()
                        .filter(|record| credential_matches_recovery(credential, record))
                        .map_or(origin, |record| record.credential_origin);
                    let record = recovery_from(
                        &self.operation_id,
                        &self.request,
                        actual,
                        origin,
                        credential,
                    );
                    match repository.preflight_capture_import(&record) {
                        Ok(CaptureImportBundlePreflight::Available) => {}
                        Ok(CaptureImportBundlePreflight::Conflict) => {
                            return Err(CaptureImportStatus::Conflict);
                        }
                        Err(_) => {
                            return Err(CaptureImportStatus::RecoveryRequired(
                                CaptureImportDiagnostic::InconsistentState,
                            ));
                        }
                    }
                    let recovery = match existing {
                        Some(existing)
                            if record_matches_request(&existing, &self.request)
                                && record_matches_actual(&existing, actual)
                                && record_matches_credential(&existing, origin, credential) =>
                        {
                            existing
                        }
                        Some(_) => return Err(CaptureImportStatus::Conflict),
                        None => match repository.create_capture_import_recovery(&record) {
                            Ok(()) => record,
                            Err(RepositoryError::AlreadyExists(_)) => match repository
                                .get_capture_import_recovery(&self.operation_id)
                            {
                                Ok(Some(existing))
                                    if record_matches_request(&existing, &self.request)
                                        && record_matches_actual(&existing, actual)
                                        && record_matches_credential(
                                            &existing, origin, credential,
                                        ) => existing,
                                _ => return Err(CaptureImportStatus::Conflict),
                            },
                            Err(_) => {
                                return Err(CaptureImportStatus::RecoveryRequired(
                                    CaptureImportDiagnostic::JournalUnavailable,
                                ));
                            }
                        },
                    };
                    if faults
                        .borrow_mut()
                        .interrupt(CaptureImportFaultPoint::AfterJournalPrepared)
                    {
                        return Err(CaptureImportStatus::RecoveryRequired(
                            CaptureImportDiagnostic::CredentialPending,
                        ));
                    }
                    Ok(recovery)
                },
                |repository, store, credential, recovery| {
                    complete_bundle_under_owner(
                        repository,
                        store,
                        actual,
                        recovery,
                        credential,
                        &mut **faults.borrow_mut(),
                    )
                },
            );
        let completion = match scoped {
            Ok(completion) => completion,
            Err(ScopedCredentialError::Operation(status)) => return status,
            Err(ScopedCredentialError::Credential(
                CredentialServiceError::AlreadyExists
                | CredentialServiceError::VersionConflict
                | CredentialServiceError::InvalidSecret,
            )) => return CaptureImportStatus::Conflict,
            Err(ScopedCredentialError::Credential(_)) => {
                return CaptureImportStatus::RecoveryRequired(
                    CaptureImportDiagnostic::CredentialPending,
                );
            }
        };
        if self
            .repository
            .delete_capture_import_recovery(
                &completion.recovery.operation_id,
                completion.recovery.version,
            )
            .is_err()
        {
            return CaptureImportStatus::RecoveryRequired(CaptureImportDiagnostic::CleanupPending);
        }
        if completion.already_imported {
            CaptureImportStatus::AlreadyImported(self.request.identity_id.clone())
        } else {
            CaptureImportStatus::Imported(self.request.identity_id.clone())
        }
    }
}

struct LockedCompletion {
    recovery: CaptureImportRecoveryRecord,
    already_imported: bool,
}

fn complete_bundle_under_owner<R, C, F>(
    repository: &mut R,
    store: &mut C,
    actual: &ActualCodexState,
    mut recovery: CaptureImportRecoveryRecord,
    credential: &CredentialReference,
    faults: &mut F,
) -> Result<LockedCompletion, CaptureImportStatus>
where
    R: CaptureImportRepository,
    C: CredentialStore,
    F: CaptureImportFaults,
{
    if AuthMode::from(credential.kind()) != actual.authentication.auth_mode
        || credential.credential_fingerprint() != &actual.authentication.credential_fingerprint
    {
        return Err(mark_recovery(
            repository,
            recovery,
            CaptureImportDiagnostic::InconsistentState,
        ));
    }
    match verify_material_locked(repository, store, credential) {
        Ok(true) => {}
        Ok(false) => {
            return Err(mark_recovery(
                repository,
                recovery,
                CaptureImportDiagnostic::InconsistentState,
            ));
        }
        Err(()) => {
            return Err(mark_recovery(
                repository,
                recovery,
                CaptureImportDiagnostic::BundlePending,
            ));
        }
    }
    if recovery.phase != CaptureImportPhase::CredentialReady {
        recovery = transition(
            repository,
            recovery,
            CaptureImportPhase::CredentialReady,
            None,
        )?;
    }
    if faults.interrupt(CaptureImportFaultPoint::AfterCredentialReady) {
        return Err(CaptureImportStatus::RecoveryRequired(
            CaptureImportDiagnostic::BundlePending,
        ));
    }
    let bundle = expected_bundle(&recovery, credential.clone()).map_err(|()| {
        mark_recovery(
            repository,
            recovery.clone(),
            CaptureImportDiagnostic::InconsistentState,
        )
    })?;
    let already_imported = match aggregate_state(repository, &bundle) {
        Ok(AggregateState::Exact) => true,
        Ok(AggregateState::Empty) => {
            if faults.interrupt(CaptureImportFaultPoint::BeforeBundleCommit) {
                return Err(mark_recovery(
                    repository,
                    recovery,
                    CaptureImportDiagnostic::InconsistentState,
                ));
            }
            if repository
                .create_identity_bundle_if_credential_exact(&bundle, credential)
                .is_err()
            {
                match aggregate_state(repository, &bundle) {
                    Ok(AggregateState::Exact) => true,
                    Ok(AggregateState::Conflict) => {
                        return Err(mark_recovery(
                            repository,
                            recovery,
                            CaptureImportDiagnostic::InconsistentState,
                        ));
                    }
                    _ => {
                        return Err(mark_recovery(
                            repository,
                            recovery,
                            CaptureImportDiagnostic::BundlePending,
                        ));
                    }
                }
            } else {
                if faults.interrupt(CaptureImportFaultPoint::AfterBundleCommitted) {
                    return Err(CaptureImportStatus::RecoveryRequired(
                        CaptureImportDiagnostic::BundlePending,
                    ));
                }
                false
            }
        }
        Ok(AggregateState::Conflict) => {
            return Err(mark_recovery(
                repository,
                recovery,
                CaptureImportDiagnostic::InconsistentState,
            ));
        }
        Err(()) => {
            return Err(mark_recovery(
                repository,
                recovery,
                CaptureImportDiagnostic::BundlePending,
            ));
        }
    };
    recovery = transition(repository, recovery, CaptureImportPhase::BundleReady, None)?;
    if faults.interrupt(CaptureImportFaultPoint::BeforeJournalCleanup) {
        return Err(CaptureImportStatus::RecoveryRequired(
            CaptureImportDiagnostic::CleanupPending,
        ));
    }
    Ok(LockedCompletion {
        recovery,
        already_imported,
    })
}

fn rollback_conflicted_capture<R, C>(
    repository: &mut R,
    store: &mut C,
    recovery: &CaptureImportRecoveryRecord,
) -> CaptureImportStatus
where
    R: CaptureImportRepository,
    C: CredentialStore,
{
    if repository.capture_import_target_is_empty(recovery) != Ok(true) {
        return CaptureImportStatus::RecoveryRequired(CaptureImportDiagnostic::InconsistentState);
    }
    let credential = match repository.get_credential_reference(&recovery.credential_id) {
        Ok(Some(credential)) => credential,
        Ok(None) => {
            let recoveries = match repository.list_credential_recoveries(&recovery.credential_id) {
                Ok(recoveries) => recoveries,
                Err(_) => {
                    return CaptureImportStatus::RecoveryRequired(
                        CaptureImportDiagnostic::InconsistentState,
                    );
                }
            };
            for credential_recovery in &recoveries {
                if credential_recovery.operation
                    != codex_application::CredentialRecoveryOperation::Delete
                    || credential_recovery.kind != kind_from(recovery.auth_mode)
                    || credential_recovery.generation != EntityVersion::initial()
                    || credential_recovery.planned_credential_fingerprint.as_ref()
                        != Some(&recovery.credential_fingerprint)
                    || CredentialService::new(repository, store)
                        .cleanup_recovery(&credential_recovery.operation_id)
                        .is_err()
                {
                    return CaptureImportStatus::RecoveryRequired(
                        CaptureImportDiagnostic::InconsistentState,
                    );
                }
            }
            if !repository
                .list_credential_recoveries(&recovery.credential_id)
                .is_ok_and(|remaining| remaining.is_empty())
            {
                return CaptureImportStatus::RecoveryRequired(
                    CaptureImportDiagnostic::InconsistentState,
                );
            }
            return if repository
                .delete_capture_import_recovery(&recovery.operation_id, recovery.version)
                .is_ok()
            {
                CaptureImportStatus::Conflict
            } else {
                CaptureImportStatus::RecoveryRequired(CaptureImportDiagnostic::CleanupPending)
            };
        }
        Err(_) => {
            return CaptureImportStatus::RecoveryRequired(
                CaptureImportDiagnostic::InconsistentState,
            );
        }
    };
    if !credential_matches_recovery(&credential, recovery) {
        return CaptureImportStatus::RecoveryRequired(CaptureImportDiagnostic::InconsistentState);
    }
    if recovery.credential_origin == CaptureImportCredentialOrigin::Reused {
        return if repository
            .delete_capture_import_recovery(&recovery.operation_id, recovery.version)
            .is_ok()
        {
            CaptureImportStatus::Conflict
        } else {
            CaptureImportStatus::RecoveryRequired(CaptureImportDiagnostic::CleanupPending)
        };
    }
    if CredentialService::new(repository, store)
        .delete_credential(credential.id(), credential.version())
        .is_err()
    {
        return CaptureImportStatus::RecoveryRequired(CaptureImportDiagnostic::InconsistentState);
    }
    if repository
        .delete_capture_import_recovery(&recovery.operation_id, recovery.version)
        .is_err()
    {
        CaptureImportStatus::RecoveryRequired(CaptureImportDiagnostic::CleanupPending)
    } else {
        CaptureImportStatus::Conflict
    }
}

fn finish_completed<R, C>(
    repository: &mut R,
    store: &mut C,
    recovery: &CaptureImportRecoveryRecord,
) -> CaptureImportStatus
where
    R: CaptureImportRepository,
    C: CredentialStore,
{
    let Some(credential) = repository
        .get_credential_reference(&recovery.credential_id)
        .ok()
        .flatten()
    else {
        return CaptureImportStatus::RecoveryRequired(CaptureImportDiagnostic::InconsistentState);
    };
    if !credential_matches_recovery(&credential, recovery)
        || !verify_material(repository, store, &credential)
    {
        return CaptureImportStatus::RecoveryRequired(CaptureImportDiagnostic::InconsistentState);
    }
    let bundle = match expected_bundle(recovery, credential) {
        Ok(bundle) => bundle,
        Err(()) => {
            return CaptureImportStatus::RecoveryRequired(
                CaptureImportDiagnostic::InconsistentState,
            );
        }
    };
    if aggregate_state(repository, &bundle) != Ok(AggregateState::Exact) {
        return CaptureImportStatus::RecoveryRequired(CaptureImportDiagnostic::InconsistentState);
    }
    if repository
        .delete_capture_import_recovery(&recovery.operation_id, recovery.version)
        .is_err()
    {
        return CaptureImportStatus::RecoveryRequired(CaptureImportDiagnostic::CleanupPending);
    }
    CaptureImportStatus::AlreadyImported(recovery.identity_id.clone())
}

fn committed_bundle_state<R, C>(
    repository: &mut R,
    store: &mut C,
    recovery: &CaptureImportRecoveryRecord,
) -> Result<AggregateState, ()>
where
    R: CaptureImportRepository,
    C: CredentialStore,
{
    let credential = match repository
        .get_credential_reference(&recovery.credential_id)
        .map_err(|_| ())?
    {
        Some(credential) => credential,
        None => return aggregate_presence(repository, recovery),
    };
    if !credential_matches_recovery(&credential, recovery)
        || !verify_material(repository, store, &credential)
    {
        return Ok(AggregateState::Conflict);
    }
    let bundle = expected_bundle(recovery, credential)?;
    aggregate_state(repository, &bundle)
}

fn aggregate_presence<R: CaptureImportRepository>(
    repository: &R,
    recovery: &CaptureImportRecoveryRecord,
) -> Result<AggregateState, ()> {
    let identity = repository
        .get_runtime_identity(&recovery.identity_id)
        .map_err(|_| ())?;
    let preset = repository
        .get_model_preset(&recovery.preset_id)
        .map_err(|_| ())?;
    let patch = repository
        .get_managed_config_patch(&recovery.identity_id)
        .map_err(|_| ())?;
    if identity.is_none() && preset.is_none() && patch.is_none() {
        Ok(AggregateState::Empty)
    } else {
        Ok(AggregateState::Conflict)
    }
}

fn expected_bundle(
    record: &CaptureImportRecoveryRecord,
    credential: CredentialReference,
) -> Result<IdentityBundle, ()> {
    let actual = ActualCodexState {
        config: ScannedConfig {
            original_bytes: Vec::new(),
            baseline_sha256: record.config_hash.clone(),
            has_bom: false,
            line_ending: codex_application::LineEnding::None,
            generation: codex_application::FormatGeneration::CompatibleUnknown,
            provider_id: record.provider_id.clone(),
            provider_display_name: record.provider_display_name.clone(),
            api_base_url: record.api_base_url.clone(),
            model_id: record.model_id.clone(),
        },
        authentication: AuthenticationDescriptor {
            auth_mode: record.auth_mode,
            schema_fingerprint: record.auth_schema_fingerprint.clone(),
            credential_fingerprint: record.credential_fingerprint.clone(),
        },
    };
    build_scanned_identity_bundle(
        &actual,
        ImportIdentityInput {
            identity_id: record.identity_id.clone(),
            identity_name: record.identity_name.clone(),
            preset_id: record.preset_id.clone(),
            preset_name: record.preset_name.clone(),
            patch_id: record.patch_id.clone(),
            credential: Some(credential),
            credential_already_persisted: true,
            now: record.created_at,
        },
    )
    .map_err(|_| ())?
    .ok_or(())
}

fn expected_bundle_from_actual(
    request: &CaptureImportRequest,
    actual: &ActualCodexState,
    credential: CredentialReference,
) -> Result<IdentityBundle, ()> {
    build_scanned_identity_bundle(
        actual,
        ImportIdentityInput {
            identity_id: request.identity_id.clone(),
            identity_name: request.identity_name.clone(),
            preset_id: request.preset_id.clone(),
            preset_name: request.preset_name.clone(),
            patch_id: request.patch_id.clone(),
            credential: Some(credential),
            credential_already_persisted: true,
            now: request.now,
        },
    )
    .map_err(|_| ())?
    .ok_or(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AggregateState {
    Empty,
    Exact,
    Conflict,
}

fn aggregate_state<R: CaptureImportRepository>(
    repository: &R,
    expected: &IdentityBundle,
) -> Result<AggregateState, ()> {
    let identity = repository
        .get_runtime_identity(expected.identity.id())
        .map_err(|_| ())?;
    let preset = repository
        .get_model_preset(expected.preset.id())
        .map_err(|_| ())?;
    let patch = repository
        .get_managed_config_patch(expected.identity.id())
        .map_err(|_| ())?;
    match (&identity, &preset, &patch) {
        (None, None, None) => Ok(AggregateState::Empty),
        (Some(identity), Some(preset), Some(patch))
            if identity == &expected.identity
                && preset == &expected.preset
                && patch == &expected.patch =>
        {
            Ok(AggregateState::Exact)
        }
        _ => Ok(AggregateState::Conflict),
    }
}

struct FingerprintVerifier<'a> {
    expected: &'a codex_domain::CredentialFingerprint,
    matches: bool,
}

impl SecretConsumer for FingerprintVerifier<'_> {
    fn consume(&mut self, secret: &[u8]) -> Result<(), CredentialStoreError> {
        self.matches = codex_adapter::hash_bytes(secret).as_str() == self.expected.as_str();
        Ok(())
    }
}

fn verify_material<R, C>(repository: &mut R, store: &mut C, expected: &CredentialReference) -> bool
where
    R: CredentialReferenceRepository + CredentialRecoveryRepository,
    C: CredentialStore,
{
    let mut verifier = FingerprintVerifier {
        expected: expected.credential_fingerprint(),
        matches: false,
    };
    CredentialService::new(repository, store)
        .read_for_switch(expected.id(), &mut verifier)
        .is_ok()
        && verifier.matches
}

fn verify_material_locked<R, C>(
    repository: &mut R,
    store: &mut C,
    expected: &CredentialReference,
) -> Result<bool, ()>
where
    R: CredentialReferenceRepository,
    C: CredentialStore,
{
    let exact = repository
        .get_credential_reference(expected.id())
        .map_err(|_| ())?;
    if exact.as_ref() != Some(expected) {
        return Ok(false);
    }
    let binding = codex_application::CredentialEnvelopeBinding::new(
        expected.id().clone(),
        expected.kind(),
        expected.schema_fingerprint().clone(),
        expected.version(),
    );
    let mut verifier = FingerprintVerifier {
        expected: expected.credential_fingerprint(),
        matches: false,
    };
    store.read(&binding, &mut verifier).map_err(|_| ())?;
    Ok(verifier.matches)
}

fn recovery_from(
    operation_id: &str,
    request: &CaptureImportRequest,
    actual: &ActualCodexState,
    credential_origin: CaptureImportCredentialOrigin,
    credential: &CredentialReference,
) -> CaptureImportRecoveryRecord {
    CaptureImportRecoveryRecord {
        operation_id: operation_id.to_owned(),
        root: request.root,
        scan_id: request.scan_id.clone(),
        credential_id: request.credential_id.clone(),
        identity_id: request.identity_id.clone(),
        identity_name: request.identity_name.clone(),
        preset_id: request.preset_id.clone(),
        preset_name: request.preset_name.clone(),
        patch_id: request.patch_id.clone(),
        auth_mode: actual.authentication.auth_mode,
        auth_schema_fingerprint: actual.authentication.schema_fingerprint.clone(),
        credential_origin,
        credential_backend: credential.backend(),
        credential_schema_fingerprint: credential.schema_fingerprint().clone(),
        credential_fingerprint: actual.authentication.credential_fingerprint.clone(),
        credential_version: credential.version(),
        credential_created_at: credential.created_at(),
        credential_updated_at: credential.updated_at(),
        provider_id: actual.config.provider_id.clone(),
        provider_display_name: actual.config.provider_display_name.clone(),
        api_base_url: actual.config.api_base_url.clone(),
        model_id: actual.config.model_id.clone(),
        config_hash: actual.config.baseline_sha256.clone(),
        phase: CaptureImportPhase::Prepared,
        diagnostic: None,
        created_at: request.now,
        updated_at: request.now,
        version: EntityVersion::initial(),
    }
}

fn credential_matches_recovery(
    credential: &CredentialReference,
    record: &CaptureImportRecoveryRecord,
) -> bool {
    credential.id() == &record.credential_id
        && credential.backend() == record.credential_backend
        && credential.schema_fingerprint() == &record.credential_schema_fingerprint
        && credential.credential_fingerprint() == &record.credential_fingerprint
        && credential.version() == record.credential_version
        && credential.created_at() == record.credential_created_at
        && credential.updated_at() == record.credential_updated_at
        && AuthMode::from(credential.kind()) == record.auth_mode
}

fn record_matches_credential(
    record: &CaptureImportRecoveryRecord,
    origin: CaptureImportCredentialOrigin,
    credential: &CredentialReference,
) -> bool {
    record.credential_origin == origin && credential_matches_recovery(credential, record)
}

fn transition<R: CaptureImportRecoveryRepository>(
    repository: &mut R,
    mut record: CaptureImportRecoveryRecord,
    phase: CaptureImportPhase,
    diagnostic: Option<CaptureImportDiagnostic>,
) -> Result<CaptureImportRecoveryRecord, CaptureImportStatus> {
    let previous = record.version;
    record.phase = phase;
    record.diagnostic = diagnostic;
    record.updated_at = record.created_at;
    record.version = previous.next().map_err(|_| {
        CaptureImportStatus::RecoveryRequired(CaptureImportDiagnostic::JournalUnavailable)
    })?;
    repository
        .update_capture_import_recovery(&record, previous)
        .map_err(|_| {
            CaptureImportStatus::RecoveryRequired(CaptureImportDiagnostic::JournalUnavailable)
        })?;
    Ok(record)
}

fn mark_recovery<R: CaptureImportRecoveryRepository>(
    repository: &mut R,
    record: CaptureImportRecoveryRecord,
    diagnostic: CaptureImportDiagnostic,
) -> CaptureImportStatus {
    if record.phase != CaptureImportPhase::RecoveryRequired
        && transition(
            repository,
            record,
            CaptureImportPhase::RecoveryRequired,
            Some(diagnostic),
        )
        .is_err()
    {
        return CaptureImportStatus::RecoveryRequired(CaptureImportDiagnostic::JournalUnavailable);
    }
    CaptureImportStatus::RecoveryRequired(diagnostic)
}

fn record_matches_request(
    record: &CaptureImportRecoveryRecord,
    request: &CaptureImportRequest,
) -> bool {
    record.root == request.root
        && record.scan_id == request.scan_id
        && record.credential_id == request.credential_id
        && record.identity_id == request.identity_id
        && record.identity_name == request.identity_name
        && record.preset_id == request.preset_id
        && record.preset_name == request.preset_name
        && record.patch_id == request.patch_id
        && record.created_at == request.now
}

fn record_matches_actual(record: &CaptureImportRecoveryRecord, actual: &ActualCodexState) -> bool {
    record.auth_mode == actual.authentication.auth_mode
        && record.auth_schema_fingerprint == actual.authentication.schema_fingerprint
        && record.credential_fingerprint == actual.authentication.credential_fingerprint
        && record.provider_id == actual.config.provider_id
        && record.provider_display_name == actual.config.provider_display_name
        && record.api_base_url == actual.config.api_base_url
        && record.model_id == actual.config.model_id
        && record.config_hash == actual.config.baseline_sha256
}

fn operation_id(request: &CaptureImportRequest) -> String {
    format!("capture-import:{}", request.identity_id.as_str())
}

const fn kind_from(mode: AuthMode) -> CredentialKind {
    match mode {
        AuthMode::ApiKey => CredentialKind::ApiKey,
        AuthMode::OAuth => CredentialKind::OAuthBundle,
    }
}
