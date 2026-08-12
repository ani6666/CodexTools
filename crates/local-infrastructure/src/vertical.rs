use std::{
    fmt, fs,
    path::{Path, PathBuf},
};

use codex_adapter::{CodexAdapter, hash_bytes};
use codex_application::{
    BoundSecretConsumer, Clock, CompatibilityReason, CredentialRecoveryRepository,
    CredentialReferenceRepository, CredentialStore, CredentialStoreError, DesiredManagedConfig,
    FileBaseline, ModelPresetRepository, RuntimeIdentityRepository, ScanStatus, StabilityWindow,
    SwitchExecutionError, SwitchPlan, SwitchTransactionRecord,
};
use codex_domain::{
    AuthMode, ContentHash, CredentialBackend, CredentialFingerprint, CredentialKind,
    CredentialRefId, CredentialReference, EntityVersion, IdentityId, ModelId, ModelPreset,
    ModelPresetId, ProviderId, RuntimeIdentity, SchemaFingerprint, SwitchTransactionId, UnixMillis,
};
use zeroize::Zeroizing;

use crate::{
    BackupRestoreTarget, CredentialService, CredentialServiceError, FaultInjector,
    SqliteMetadataRepository, SwitchExecutor,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerticalClosureError {
    CompatibilityProtected(CompatibilityReason),
    InvalidTarget,
    IoFailure,
    Credential(CredentialServiceError),
    Switch(SwitchExecutionError),
}

impl fmt::Display for VerticalClosureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CompatibilityProtected(_) => "vertical state is compatibility protected",
            Self::InvalidTarget => "vertical target does not match managed identity",
            Self::IoFailure => "vertical explicit root is unavailable",
            Self::Credential(_) => "vertical credential material is unavailable",
            Self::Switch(_) => "vertical switch execution failed",
        })
    }
}
impl std::error::Error for VerticalClosureError {}
impl From<SwitchExecutionError> for VerticalClosureError {
    fn from(value: SwitchExecutionError) -> Self {
        Self::Switch(value)
    }
}
impl From<CredentialServiceError> for VerticalClosureError {
    fn from(value: CredentialServiceError) -> Self {
        Self::Credential(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerticalPreview {
    transaction_id: SwitchTransactionId,
    identity_id: IdentityId,
    provider_id: ProviderId,
    model_id: ModelId,
    config_source: ContentHash,
    config_target: ContentHash,
    auth_source_prefix: String,
    auth_target_prefix: String,
    credential_fingerprint_prefix: String,
    diff: Vec<String>,
}

impl VerticalPreview {
    pub const fn transaction_id(&self) -> &SwitchTransactionId {
        &self.transaction_id
    }
    pub const fn identity_id(&self) -> &IdentityId {
        &self.identity_id
    }
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }
    pub const fn model_id(&self) -> &ModelId {
        &self.model_id
    }
    pub const fn config_source(&self) -> &ContentHash {
        &self.config_source
    }
    pub const fn config_target(&self) -> &ContentHash {
        &self.config_target
    }
    pub fn auth_source_prefix(&self) -> &str {
        &self.auth_source_prefix
    }
    pub fn auth_target_prefix(&self) -> &str {
        &self.auth_target_prefix
    }
    pub fn credential_fingerprint_prefix(&self) -> &str {
        &self.credential_fingerprint_prefix
    }
    pub fn diff(&self) -> &[String] {
        &self.diff
    }
}

/// 调用方可审阅并批准的不可变、非秘密写前意图。
#[derive(Clone, Eq, PartialEq)]
pub struct VerticalPreparedIntent {
    preview: VerticalPreview,
    root: PathBuf,
    root_ref: ContentHash,
    config_source: FileBaseline,
    auth_source: FileBaseline,
    config_target: ContentHash,
    auth_target: ContentHash,
    identity_version: EntityVersion,
    preset_id: ModelPresetId,
    preset_version: EntityVersion,
    credential_id: CredentialRefId,
    credential_kind: CredentialKind,
    credential_backend: CredentialBackend,
    credential_schema_fingerprint: SchemaFingerprint,
    credential_generation: EntityVersion,
    credential_fingerprint: CredentialFingerprint,
    created_at: UnixMillis,
    expires_at: UnixMillis,
}

impl VerticalPreparedIntent {
    pub const fn preview(&self) -> &VerticalPreview {
        &self.preview
    }
    pub const fn root_ref(&self) -> &ContentHash {
        &self.root_ref
    }
    pub const fn credential_id(&self) -> &CredentialRefId {
        &self.credential_id
    }
    pub const fn credential_generation(&self) -> EntityVersion {
        self.credential_generation
    }
    pub const fn created_at(&self) -> UnixMillis {
        self.created_at
    }
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }
}

impl fmt::Debug for VerticalPreparedIntent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerticalPreparedIntent")
            .field("preview", &self.preview)
            .field("root", &"[REDACTED_PATH]")
            .field("root_ref", &self.root_ref)
            .field("config_source", &self.config_source)
            .field("auth_source", &"[REDACTED_BASELINE]")
            .field("config_target", &self.config_target)
            .field("auth_target", &"[REDACTED]")
            .field("identity_version", &self.identity_version)
            .field("preset_id", &self.preset_id)
            .field("preset_version", &self.preset_version)
            .field("credential_id", &self.credential_id)
            .field("credential_kind", &self.credential_kind)
            .field("credential_backend", &self.credential_backend)
            .field("credential_schema_fingerprint", &"[REDACTED]")
            .field("credential_generation", &self.credential_generation)
            .field("credential_fingerprint", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

pub struct PreparedVerticalSwitch {
    plan: SwitchPlan,
    preview: VerticalPreview,
    credential: CredentialReference,
}

impl fmt::Debug for PreparedVerticalSwitch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedVerticalSwitch")
            .field("plan", &self.plan)
            .field("preview", &self.preview)
            .field("credential", &self.credential)
            .finish()
    }
}

impl PreparedVerticalSwitch {
    pub const fn plan(&self) -> &SwitchPlan {
        &self.plan
    }
    pub const fn preview(&self) -> &VerticalPreview {
        &self.preview
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedVerticalState {
    pub identity_id: IdentityId,
    pub provider_id: ProviderId,
    pub model_id: ModelId,
    pub config_hash: ContentHash,
    pub auth_fingerprint_prefix: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerticalExecutionResult {
    pub preview: VerticalPreview,
    pub transaction: SwitchTransactionRecord,
    pub verified: VerifiedVerticalState,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct VerticalSwitchPlanner;

impl VerticalSwitchPlanner {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_switch_with_material(
        &self,
        root: &Path,
        transaction_id: SwitchTransactionId,
        identity: &RuntimeIdentity,
        preset: &ModelPreset,
        credential: &CredentialReference,
        target_auth: &[u8],
        created_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<PreparedVerticalSwitch, VerticalClosureError> {
        let root = fs::canonicalize(root).map_err(|_| VerticalClosureError::IoFailure)?;
        let actual = match CodexAdapter::new().scan_explicit_root(&root) {
            ScanStatus::Ready(actual) => actual,
            ScanStatus::CompatibilityProtected(reason) => {
                return Err(VerticalClosureError::CompatibilityProtected(reason));
            }
        };
        ensure_identity_bundle(identity, preset, credential)?;
        let desired = DesiredManagedConfig {
            provider_id: identity.provider_id().clone(),
            provider_display_name: identity.provider_display_name().clone(),
            api_base_url: identity.api_base_url().clone(),
            model_id: preset.model_id().clone(),
        };
        let planned = CodexAdapter::new()
            .plan_config(&actual, &desired, credential)
            .map_err(VerticalClosureError::CompatibilityProtected)?;
        let ScanStatus::Ready(target) =
            CodexAdapter::new().scan_memory(&planned.target_bytes, target_auth)
        else {
            return Err(VerticalClosureError::InvalidTarget);
        };
        ensure_scanned_target(&target, identity, preset, credential)?;
        let source_auth = Zeroizing::new(
            fs::read(root.join("auth.json")).map_err(|_| VerticalClosureError::IoFailure)?,
        );
        if hash_bytes(&source_auth).as_str()
            != actual.authentication.credential_fingerprint.as_str()
        {
            return Err(VerticalClosureError::IoFailure);
        }
        let auth_source_hash = hash_bytes(&source_auth);
        let auth_target_hash = hash_bytes(target_auth);
        let preview = VerticalPreview {
            transaction_id: transaction_id.clone(),
            identity_id: identity.id().clone(),
            provider_id: identity.provider_id().clone(),
            model_id: preset.model_id().clone(),
            config_source: actual.config.baseline_sha256.clone(),
            config_target: planned.target_sha256.clone(),
            auth_source_prefix: short_hash(auth_source_hash.as_str()),
            auth_target_prefix: short_hash(auth_target_hash.as_str()),
            credential_fingerprint_prefix: short_hash(credential.credential_fingerprint().as_str()),
            diff: planned.diff.lines().to_vec(),
        };
        let plan = SwitchPlan::new(
            transaction_id,
            root,
            FileBaseline::present(
                u64::try_from(actual.config.original_bytes.len())
                    .map_err(|_| VerticalClosureError::InvalidTarget)?,
                actual.config.baseline_sha256.clone(),
            ),
            FileBaseline::present(
                u64::try_from(source_auth.len())
                    .map_err(|_| VerticalClosureError::InvalidTarget)?,
                auth_source_hash,
            ),
            planned.target_bytes,
            target_auth.to_vec(),
            identity.provider_id().clone(),
            preset.model_id().clone(),
            target.authentication.credential_fingerprint.clone(),
            created_at,
            expires_at,
        )?;
        Ok(PreparedVerticalSwitch {
            plan,
            preview,
            credential: credential.clone(),
        })
    }

    /// 从受控 CredentialStore 读取目标认证材料并返回真正的写前预览。
    #[allow(clippy::too_many_arguments)]
    pub fn preview_from_store<R, S>(
        &self,
        credential_repository: &mut R,
        store: &mut S,
        root: &Path,
        transaction_id: SwitchTransactionId,
        identity: &RuntimeIdentity,
        preset: &ModelPreset,
        credential_id: &codex_domain::CredentialRefId,
        created_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<VerticalPreparedIntent, VerticalClosureError>
    where
        R: CredentialReferenceRepository
            + CredentialRecoveryRepository
            + RuntimeIdentityRepository
            + ModelPresetRepository,
        S: CredentialStore,
    {
        if identity.credential().id() != credential_id {
            return Err(VerticalClosureError::InvalidTarget);
        }
        ensure_repository_bundle(credential_repository, identity, preset)?;
        let mut consumer = VerticalPreviewConsumer {
            planner: self,
            root,
            transaction_id,
            identity,
            preset,
            created_at,
            expires_at,
            result: None,
        };
        CredentialService::new(credential_repository, store)
            .read_bound_for_switch(credential_id, &mut consumer)?;
        consumer
            .result
            .take()
            .unwrap_or(Err(VerticalClosureError::InvalidTarget))
    }

    /// 重新取得 owner、重新读取并规划；只有与已批准意图逐字段完全一致才执行。
    #[allow(clippy::too_many_arguments)]
    pub fn execute_approved<R, S, C, W, F>(
        &self,
        credential_repository: &mut R,
        store: &mut S,
        switch_repository: &mut SqliteMetadataRepository,
        clock: &C,
        stability: &mut W,
        faults: &mut F,
        approved: &VerticalPreparedIntent,
        identity: &RuntimeIdentity,
        preset: &ModelPreset,
    ) -> Result<VerticalExecutionResult, VerticalClosureError>
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
        ensure_repository_bundle(credential_repository, identity, preset)
            .map_err(|_| VerticalClosureError::Switch(SwitchExecutionError::PlanStale))?;
        if identity.id() != approved.preview.identity_id()
            || identity.version() != approved.identity_version
            || preset.id() != &approved.preset_id
            || preset.version() != approved.preset_version
            || identity.credential().id() != &approved.credential_id
        {
            return Err(VerticalClosureError::Switch(
                SwitchExecutionError::PlanStale,
            ));
        }
        let mut consumer = ApprovedExecutionConsumer {
            planner: self,
            switch_repository,
            clock,
            stability,
            faults,
            approved,
            identity,
            preset,
            result: None,
        };
        CredentialService::new(credential_repository, store)
            .read_bound_for_switch(&approved.credential_id, &mut consumer)
            .map_err(map_approved_credential_error)?;
        consumer
            .result
            .take()
            .unwrap_or(Err(VerticalClosureError::InvalidTarget))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_restore(
        &self,
        root: &Path,
        transaction_id: SwitchTransactionId,
        mut target: BackupRestoreTarget,
        identity: &RuntimeIdentity,
        preset: &ModelPreset,
        credential: &CredentialReference,
        created_at: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<PreparedVerticalSwitch, VerticalClosureError> {
        let root = fs::canonicalize(root).map_err(|_| VerticalClosureError::IoFailure)?;
        ensure_identity_bundle(identity, preset, credential)?;
        let config = target
            .config
            .take()
            .ok_or(VerticalClosureError::InvalidTarget)?;
        let auth = Zeroizing::new(
            target
                .auth
                .take()
                .ok_or(VerticalClosureError::InvalidTarget)?,
        );
        let ScanStatus::Ready(scanned) = CodexAdapter::new().scan_memory(&config, &auth) else {
            return Err(VerticalClosureError::InvalidTarget);
        };
        ensure_scanned_target(&scanned, identity, preset, credential)?;
        let config_target = hash_bytes(&config);
        let auth_target = hash_bytes(&auth);
        let config_source = target
            .config_source
            .sha256
            .clone()
            .ok_or(VerticalClosureError::InvalidTarget)?;
        let auth_source = target
            .auth_source
            .sha256
            .clone()
            .ok_or(VerticalClosureError::InvalidTarget)?;
        let preview = VerticalPreview {
            transaction_id: transaction_id.clone(),
            identity_id: identity.id().clone(),
            provider_id: identity.provider_id().clone(),
            model_id: preset.model_id().clone(),
            config_source,
            config_target: config_target.clone(),
            auth_source_prefix: short_hash(auth_source.as_str()),
            auth_target_prefix: short_hash(auth_target.as_str()),
            credential_fingerprint_prefix: short_hash(credential.credential_fingerprint().as_str()),
            diff: vec!["config/authentication: restore bound joint snapshot [REDACTED]".to_owned()],
        };
        let plan = SwitchPlan::new_zeroizing_auth(
            transaction_id,
            root,
            target.config_source.clone(),
            target.auth_source.clone(),
            config,
            auth,
            identity.provider_id().clone(),
            preset.model_id().clone(),
            scanned.authentication.credential_fingerprint.clone(),
            created_at,
            expires_at,
        )?;
        Ok(PreparedVerticalSwitch {
            plan,
            preview,
            credential: credential.clone(),
        })
    }

    /// 执行恢复前重新验证 repository 引用、DPAPI generation 与备份认证目标完全一致。
    #[allow(clippy::too_many_arguments)]
    pub fn execute_restore_from_store<R, S, C, W, F>(
        &self,
        credential_repository: &mut R,
        store: &mut S,
        switch_repository: &mut SqliteMetadataRepository,
        clock: &C,
        stability: &mut W,
        faults: &mut F,
        prepared: &PreparedVerticalSwitch,
        identity: &RuntimeIdentity,
        preset: &ModelPreset,
    ) -> Result<VerticalExecutionResult, VerticalClosureError>
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
        ensure_repository_bundle(credential_repository, identity, preset)
            .map_err(|_| VerticalClosureError::Switch(SwitchExecutionError::PlanStale))?;
        let mut consumer = RestoreExecutionConsumer {
            planner: self,
            switch_repository,
            clock,
            stability,
            faults,
            prepared,
            identity,
            preset,
            result: None,
        };
        CredentialService::new(credential_repository, store)
            .read_bound_for_switch(prepared.credential.id(), &mut consumer)
            .map_err(map_approved_credential_error)?;
        consumer
            .result
            .take()
            .unwrap_or(Err(VerticalClosureError::InvalidTarget))
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_and_verify<C, W, F>(
        &self,
        repository: &mut SqliteMetadataRepository,
        clock: &C,
        stability: &mut W,
        faults: &mut F,
        prepared: &PreparedVerticalSwitch,
        identity: &RuntimeIdentity,
        preset: &ModelPreset,
        credential: &CredentialReference,
    ) -> Result<VerticalExecutionResult, VerticalClosureError>
    where
        C: Clock,
        W: StabilityWindow,
        F: FaultInjector,
    {
        let transaction =
            SwitchExecutor::new(repository, clock, stability, faults).execute(prepared.plan())?;
        let verified =
            self.verify_expected(prepared.plan().root(), identity, preset, credential)?;
        Ok(VerticalExecutionResult {
            preview: prepared.preview.clone(),
            transaction,
            verified,
        })
    }

    pub fn verify_expected(
        &self,
        root: &Path,
        identity: &RuntimeIdentity,
        preset: &ModelPreset,
        credential: &CredentialReference,
    ) -> Result<VerifiedVerticalState, VerticalClosureError> {
        ensure_identity_bundle(identity, preset, credential)?;
        let ScanStatus::Ready(actual) = CodexAdapter::new().scan_explicit_root(root) else {
            return Err(VerticalClosureError::InvalidTarget);
        };
        ensure_scanned_target(&actual, identity, preset, credential)?;
        Ok(VerifiedVerticalState {
            identity_id: identity.id().clone(),
            provider_id: actual.config.provider_id.clone(),
            model_id: actual.config.model_id.clone(),
            config_hash: actual.config.baseline_sha256.clone(),
            auth_fingerprint_prefix: short_hash(
                actual.authentication.credential_fingerprint.as_str(),
            ),
        })
    }
}

struct VerticalPreviewConsumer<'a> {
    planner: &'a VerticalSwitchPlanner,
    root: &'a Path,
    transaction_id: SwitchTransactionId,
    identity: &'a RuntimeIdentity,
    preset: &'a ModelPreset,
    created_at: UnixMillis,
    expires_at: UnixMillis,
    result: Option<Result<VerticalPreparedIntent, VerticalClosureError>>,
}

impl BoundSecretConsumer for VerticalPreviewConsumer<'_> {
    fn consume(
        &mut self,
        reference: &CredentialReference,
        secret: &[u8],
    ) -> Result<(), CredentialStoreError> {
        self.result = Some((|| {
            let prepared = self.planner.prepare_switch_with_material(
                self.root,
                self.transaction_id.clone(),
                self.identity,
                self.preset,
                reference,
                secret,
                self.created_at,
                self.expires_at,
            )?;
            Ok(intent_from_prepared(
                &prepared,
                self.identity,
                self.preset,
                reference,
            ))
        })());
        Ok(())
    }
}

struct ApprovedExecutionConsumer<'a, C, W, F> {
    planner: &'a VerticalSwitchPlanner,
    switch_repository: &'a mut SqliteMetadataRepository,
    clock: &'a C,
    stability: &'a mut W,
    faults: &'a mut F,
    approved: &'a VerticalPreparedIntent,
    identity: &'a RuntimeIdentity,
    preset: &'a ModelPreset,
    result: Option<Result<VerticalExecutionResult, VerticalClosureError>>,
}

impl<C, W, F> BoundSecretConsumer for ApprovedExecutionConsumer<'_, C, W, F>
where
    C: Clock,
    W: StabilityWindow,
    F: FaultInjector,
{
    fn consume(
        &mut self,
        reference: &CredentialReference,
        secret: &[u8],
    ) -> Result<(), CredentialStoreError> {
        self.result = Some((|| {
            ensure_repository_bundle(self.switch_repository, self.identity, self.preset)
                .map_err(|_| VerticalClosureError::Switch(SwitchExecutionError::PlanStale))?;
            let prepared = self
                .planner
                .prepare_switch_with_material(
                    &self.approved.root,
                    self.approved.preview.transaction_id().clone(),
                    self.identity,
                    self.preset,
                    reference,
                    secret,
                    self.approved.created_at,
                    self.approved.expires_at,
                )
                .map_err(|_| VerticalClosureError::Switch(SwitchExecutionError::PlanStale))?;
            let recalculated =
                intent_from_prepared(&prepared, self.identity, self.preset, reference);
            if recalculated != *self.approved {
                return Err(VerticalClosureError::Switch(
                    SwitchExecutionError::PlanStale,
                ));
            }
            ensure_repository_bundle(self.switch_repository, self.identity, self.preset)
                .map_err(|_| VerticalClosureError::Switch(SwitchExecutionError::PlanStale))?;
            self.planner.execute_and_verify(
                self.switch_repository,
                self.clock,
                self.stability,
                self.faults,
                &prepared,
                self.identity,
                self.preset,
                reference,
            )
        })());
        Ok(())
    }
}

struct RestoreExecutionConsumer<'a, C, W, F> {
    planner: &'a VerticalSwitchPlanner,
    switch_repository: &'a mut SqliteMetadataRepository,
    clock: &'a C,
    stability: &'a mut W,
    faults: &'a mut F,
    prepared: &'a PreparedVerticalSwitch,
    identity: &'a RuntimeIdentity,
    preset: &'a ModelPreset,
    result: Option<Result<VerticalExecutionResult, VerticalClosureError>>,
}

impl<C, W, F> BoundSecretConsumer for RestoreExecutionConsumer<'_, C, W, F>
where
    C: Clock,
    W: StabilityWindow,
    F: FaultInjector,
{
    fn consume(
        &mut self,
        reference: &CredentialReference,
        secret: &[u8],
    ) -> Result<(), CredentialStoreError> {
        self.result = Some((|| {
            ensure_repository_bundle(self.switch_repository, self.identity, self.preset)
                .map_err(|_| VerticalClosureError::Switch(SwitchExecutionError::PlanStale))?;
            if reference != &self.prepared.credential
                || hash_bytes(secret) != hash_bytes(self.prepared.plan.target_auth())
            {
                return Err(VerticalClosureError::Switch(
                    SwitchExecutionError::PlanStale,
                ));
            }
            self.planner.execute_and_verify(
                self.switch_repository,
                self.clock,
                self.stability,
                self.faults,
                self.prepared,
                self.identity,
                self.preset,
                reference,
            )
        })());
        Ok(())
    }
}

fn intent_from_prepared(
    prepared: &PreparedVerticalSwitch,
    identity: &RuntimeIdentity,
    preset: &ModelPreset,
    credential: &CredentialReference,
) -> VerticalPreparedIntent {
    let plan = prepared.plan();
    VerticalPreparedIntent {
        preview: prepared.preview.clone(),
        root: plan.root().to_path_buf(),
        root_ref: hash_bytes(plan.root().to_string_lossy().to_lowercase().as_bytes()),
        config_source: plan.config_source().clone(),
        auth_source: plan.auth_source().clone(),
        config_target: hash_bytes(plan.target_config()),
        auth_target: hash_bytes(plan.target_auth()),
        identity_version: identity.version(),
        preset_id: preset.id().clone(),
        preset_version: preset.version(),
        credential_id: credential.id().clone(),
        credential_kind: credential.kind(),
        credential_backend: credential.backend(),
        credential_schema_fingerprint: credential.schema_fingerprint().clone(),
        credential_generation: credential.version(),
        credential_fingerprint: credential.credential_fingerprint().clone(),
        created_at: plan.created_at(),
        expires_at: plan.expires_at(),
    }
}

fn ensure_repository_bundle<R>(
    repository: &R,
    identity: &RuntimeIdentity,
    preset: &ModelPreset,
) -> Result<(), VerticalClosureError>
where
    R: RuntimeIdentityRepository + ModelPresetRepository,
{
    let exact_identity = repository
        .get_runtime_identity(identity.id())
        .map_err(|_| VerticalClosureError::InvalidTarget)?
        .ok_or(VerticalClosureError::InvalidTarget)?;
    let exact_preset = repository
        .get_model_preset(preset.id())
        .map_err(|_| VerticalClosureError::InvalidTarget)?
        .ok_or(VerticalClosureError::InvalidTarget)?;
    if &exact_identity != identity || &exact_preset != preset {
        return Err(VerticalClosureError::InvalidTarget);
    }
    Ok(())
}

fn map_approved_credential_error(error: CredentialServiceError) -> VerticalClosureError {
    match error {
        CredentialServiceError::NotFound | CredentialServiceError::VersionConflict => {
            VerticalClosureError::Switch(SwitchExecutionError::PlanStale)
        }
        other => VerticalClosureError::Credential(other),
    }
}

fn ensure_identity_bundle(
    identity: &RuntimeIdentity,
    preset: &ModelPreset,
    credential: &CredentialReference,
) -> Result<(), VerticalClosureError> {
    if preset.identity_id() != identity.id()
        || identity.default_model_preset_id() != Some(preset.id())
        || identity.credential().id() != credential.id()
        || identity.credential().kind() != credential.kind()
        || identity.auth_mode() != AuthMode::from(credential.kind())
    {
        return Err(VerticalClosureError::InvalidTarget);
    }
    Ok(())
}

fn ensure_scanned_target(
    actual: &codex_application::ActualCodexState,
    identity: &RuntimeIdentity,
    preset: &ModelPreset,
    credential: &CredentialReference,
) -> Result<(), VerticalClosureError> {
    if actual.config.provider_id != *identity.provider_id()
        || actual.config.provider_display_name != *identity.provider_display_name()
        || actual.config.api_base_url != *identity.api_base_url()
        || actual.config.model_id != *preset.model_id()
        || actual.authentication.auth_mode != identity.auth_mode()
        || actual.authentication.credential_fingerprint != *credential.credential_fingerprint()
    {
        return Err(VerticalClosureError::InvalidTarget);
    }
    Ok(())
}

fn short_hash(value: &str) -> String {
    value.chars().take(8).collect()
}
