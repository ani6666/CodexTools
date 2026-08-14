use std::{fmt, path::Path};

use codex_domain::{
    AuthMode, ContentHash, CredentialFingerprint, CredentialReference, DomainError, EndpointUrl,
    EntityName, IdentityId, ManagedConfigPatch, ManagedConfigPatchId, ModelId, ModelPreset,
    ModelPresetId, ProviderId, RuntimeIdentity, SchemaFingerprint, UnixMillis,
};
use zeroize::Zeroizing;

use crate::{
    IdentityCandidateQuery, ManagedConfigPatchRepository, ModelPresetRepository, RepositoryError,
    RuntimeIdentityRepository,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LineEnding {
    None,
    Lf,
    CrLf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormatGeneration {
    ApiKeyBaseline,
    SyntheticOAuth,
    CurrentShape,
    CompatibleUnknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompatibilityReason {
    InvalidUtf8,
    MixedLineEndings,
    UnsupportedTomlSubset,
    DuplicateDefinition,
    MissingManagedField,
    UnknownAuthenticationShape,
    MissingConfig,
    MissingAuthentication,
    IoUnavailable,
}

impl fmt::Display for CompatibilityReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidUtf8 => "config encoding is unsupported",
            Self::MixedLineEndings => "config line endings are mixed",
            Self::UnsupportedTomlSubset => "config syntax is outside the supported subset",
            Self::DuplicateDefinition => "config contains duplicate or conflicting definitions",
            Self::MissingManagedField => "a managed config field is missing",
            Self::UnknownAuthenticationShape => "authentication shape is unsupported",
            Self::MissingConfig => "config.toml is missing",
            Self::MissingAuthentication => "auth.json is missing",
            Self::IoUnavailable => "the explicit Codex directory is unavailable",
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AuthenticationDescriptor {
    pub auth_mode: AuthMode,
    pub schema_fingerprint: SchemaFingerprint,
    pub credential_fingerprint: CredentialFingerprint,
}

impl fmt::Debug for AuthenticationDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticationDescriptor")
            .field("auth_mode", &self.auth_mode)
            .field("schema_fingerprint", &"[REDACTED]")
            .field("credential_fingerprint", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ScannedConfig {
    pub original_bytes: Zeroizing<Vec<u8>>,
    pub baseline_sha256: ContentHash,
    pub has_bom: bool,
    pub line_ending: LineEnding,
    pub generation: FormatGeneration,
    pub provider_id: ProviderId,
    pub provider_display_name: EntityName,
    pub api_base_url: EndpointUrl,
    pub model_id: ModelId,
}

impl fmt::Debug for ScannedConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScannedConfig")
            .field("config_bytes", &"[REDACTED_CONFIG_BYTES]")
            .field("baseline_sha256", &self.baseline_sha256)
            .field("has_bom", &self.has_bom)
            .field("line_ending", &self.line_ending)
            .field("generation", &self.generation)
            .field("provider_id", &self.provider_id)
            .field("provider_display_name", &self.provider_display_name)
            .field("api_base_url", &self.api_base_url)
            .field("model_id", &self.model_id)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActualCodexState {
    pub config: ScannedConfig,
    pub authentication: AuthenticationDescriptor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScanStatus {
    Ready(Box<ActualCodexState>),
    CompatibilityProtected(CompatibilityReason),
}

pub trait CodexStateSource {
    fn scan_explicit_root(&self, root: &Path) -> ScanStatus;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesiredManagedConfig {
    pub provider_id: ProviderId,
    pub provider_display_name: EntityName,
    pub api_base_url: EndpointUrl,
    pub model_id: ModelId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedFieldChange {
    pub path: String,
    pub before: String,
    pub after: String,
}

#[derive(Clone, Eq, PartialEq)]
pub struct RedactedDiff {
    lines: Vec<String>,
}

impl RedactedDiff {
    #[must_use]
    pub fn new(lines: Vec<String>) -> Self {
        Self { lines }
    }
    #[must_use]
    pub fn lines(&self) -> &[String] {
        &self.lines
    }
}

impl fmt::Debug for RedactedDiff {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("RedactedDiff")
            .field(&self.lines)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PlannedConfig {
    pub target_bytes: Zeroizing<Vec<u8>>,
    pub baseline_sha256: ContentHash,
    pub target_sha256: ContentHash,
    pub changes: Vec<ManagedFieldChange>,
    pub diff: RedactedDiff,
}

impl fmt::Debug for PlannedConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlannedConfig")
            .field("target_bytes", &"[REDACTED_BYTES]")
            .field("baseline_sha256", &self.baseline_sha256)
            .field("target_sha256", &self.target_sha256)
            .field("changes", &self.changes)
            .field("diff", &self.diff)
            .finish()
    }
}

pub trait ConfigPlanner {
    fn plan_config(
        &self,
        actual: &ActualCodexState,
        desired: &DesiredManagedConfig,
        credential: &CredentialReference,
    ) -> Result<PlannedConfig, CompatibilityReason>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationError {
    Domain,
    Repository(RepositoryError),
    CredentialMismatch,
}

impl From<DomainError> for ApplicationError {
    fn from(_: DomainError) -> Self {
        Self::Domain
    }
}
impl From<RepositoryError> for ApplicationError {
    fn from(value: RepositoryError) -> Self {
        Self::Repository(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityBundle {
    pub credential_to_create: Option<CredentialReference>,
    pub identity: RuntimeIdentity,
    pub preset: ModelPreset,
    pub patch: ManagedConfigPatch,
}

pub trait IdentityBundleRepository {
    fn create_identity_bundle(&mut self, bundle: &IdentityBundle) -> Result<(), RepositoryError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportIdentityInput {
    pub identity_id: IdentityId,
    pub identity_name: EntityName,
    pub preset_id: ModelPresetId,
    pub preset_name: EntityName,
    pub patch_id: ManagedConfigPatchId,
    pub credential: Option<CredentialReference>,
    pub credential_already_persisted: bool,
    pub now: UnixMillis,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportOutcome {
    Imported,
    CredentialCaptureRequired,
}

pub fn import_scanned_identity<R: IdentityBundleRepository>(
    repository: &mut R,
    actual: &ActualCodexState,
    input: ImportIdentityInput,
) -> Result<ImportOutcome, ApplicationError> {
    let Some(bundle) = build_scanned_identity_bundle(actual, input)? else {
        return Ok(ImportOutcome::CredentialCaptureRequired);
    };
    repository.create_identity_bundle(&bundle)?;
    Ok(ImportOutcome::Imported)
}

pub fn build_scanned_identity_bundle(
    actual: &ActualCodexState,
    input: ImportIdentityInput,
) -> Result<Option<IdentityBundle>, ApplicationError> {
    let Some(credential) = input.credential else {
        return Ok(None);
    };
    if AuthMode::from(credential.kind()) != actual.authentication.auth_mode
        || credential.credential_fingerprint() != &actual.authentication.credential_fingerprint
    {
        return Err(ApplicationError::CredentialMismatch);
    }
    let preset = ModelPreset::new(
        input.preset_id,
        input.identity_id.clone(),
        input.preset_name,
        actual.config.model_id.clone(),
        input.now,
    );
    let draft = RuntimeIdentity::new_draft(
        input.identity_id.clone(),
        input.identity_name,
        actual.config.provider_id.clone(),
        actual.config.provider_display_name.clone(),
        actual.config.api_base_url.clone(),
        None,
        credential.link(),
        input.now,
    )?;
    let identity = draft.set_default_preset(&preset, input.now)?;
    let patch = ManagedConfigPatch::new(
        input.patch_id,
        input.identity_id,
        actual.config.baseline_sha256.clone(),
        actual.config.baseline_sha256.clone(),
        input.now,
    );
    Ok(Some(IdentityBundle {
        credential_to_create: (!input.credential_already_persisted).then_some(credential),
        identity,
        preset,
        patch,
    }))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MatchStatus {
    UniqueMatch(IdentityId),
    Unmanaged,
    MultipleMatches,
    CompatibilityProtected(CompatibilityReason),
}

pub trait IdentityMatchRepository:
    RuntimeIdentityRepository + ModelPresetRepository + ManagedConfigPatchRepository
{
}
impl<T> IdentityMatchRepository for T where
    T: RuntimeIdentityRepository + ModelPresetRepository + ManagedConfigPatchRepository
{
}

pub fn match_actual_identity<R: IdentityMatchRepository>(
    repository: &R,
    status: &ScanStatus,
) -> Result<MatchStatus, RepositoryError> {
    let ScanStatus::Ready(actual) = status else {
        let ScanStatus::CompatibilityProtected(reason) = status else {
            unreachable!()
        };
        return Ok(MatchStatus::CompatibilityProtected(*reason));
    };
    let query = IdentityCandidateQuery::new(
        actual.config.provider_id.clone(),
        actual.config.api_base_url.clone(),
        actual.authentication.auth_mode,
        actual.authentication.credential_fingerprint.clone(),
    );
    let mut matches = Vec::new();
    for identity in repository.find_identity_candidates(&query)? {
        if identity.provider_display_name() != &actual.config.provider_display_name {
            continue;
        }
        let Some(preset_id) = identity.default_model_preset_id() else {
            continue;
        };
        let Some(preset) = repository.get_model_preset(preset_id)? else {
            continue;
        };
        if preset.model_id() != &actual.config.model_id {
            continue;
        }
        if repository
            .get_managed_config_patch(identity.id())?
            .is_none()
        {
            continue;
        }
        matches.push(identity.id().clone());
    }
    Ok(match matches.len() {
        0 => MatchStatus::Unmanaged,
        1 => MatchStatus::UniqueMatch(matches.remove(0)),
        _ => MatchStatus::MultipleMatches,
    })
}

#[cfg(test)]
mod planned_config_tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::{PlannedConfig, RedactedDiff};
    use codex_domain::ContentHash;
    use zeroize::Zeroizing;

    #[test]
    fn planned_config_debug_redacts_preserved_unknown_config_bytes() {
        let canary = "UNKNOWN_CONFIG_CANARY_VALUE_7QZ9";
        let plan = PlannedConfig {
            target_bytes: Zeroizing::new(format!("unknown_field = \"{canary}\"\n").into_bytes()),
            baseline_sha256: ContentHash::parse(&"a".repeat(64)).unwrap(),
            target_sha256: ContentHash::parse(&"b".repeat(64)).unwrap(),
            changes: Vec::new(),
            diff: RedactedDiff::new(Vec::new()),
        };

        let debug = format!("{plan:?}");
        assert!(!debug.contains(canary));
        assert!(debug.contains("[REDACTED_BYTES]"));
    }

    #[test]
    fn planned_config_keeps_target_bytes_zeroizing_through_unwind() {
        fn require_zeroizing(_: &Zeroizing<Vec<u8>>) {}

        let canary = "UNCLASSIFIED_CONFIG_CANARY_4M8P";
        let plan = PlannedConfig {
            target_bytes: Zeroizing::new(canary.as_bytes().to_vec()),
            baseline_sha256: ContentHash::parse(&"c".repeat(64)).unwrap(),
            target_sha256: ContentHash::parse(&"d".repeat(64)).unwrap(),
            changes: Vec::new(),
            diff: RedactedDiff::new(Vec::new()),
        };
        require_zeroizing(&plan.target_bytes);
        let result = catch_unwind(AssertUnwindSafe(move || {
            let _owned_until_unwind = plan;
            panic!("synthetic planned config unwind");
        }));
        let payload = result.unwrap_err();
        assert!(!format!("{payload:?}").contains(canary));
    }
}
