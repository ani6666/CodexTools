use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use codex_adapter::ControlledCodexAdapter;
use codex_application::{
    CaptureImportRequest, CaptureImportStatus, CompatibilityReason, ControlledCodexSource,
    ControlledRoot, ControlledScanId, ControlledScanStatus, ControlledSourceError,
    CreatePresetAndBindInput, MatchStatus, ModelPresetRepository, PresetBindingError,
    PresetBindingOutcome, PresetBindingService, RepositoryError, RuntimeIdentityRepository,
    ScanStatus, ScannedAuthConsumer, UpdatePresetAndBindInput, match_actual_identity,
};
use codex_domain::{
    AuthMode, CredentialRefId, EntityName, EntityVersion, IdentityId, IdentityStatus,
    ManagedConfigPatchId, ModelId, ModelPresetId, RuntimeIdentity, UnixMillis,
};
use local_infrastructure::{
    CaptureImportService, OpenRepositoryError, SqliteMetadataRepository,
    WindowsControlledRootReader,
};
use windows_platform::WindowsDpapiCredentialStore;

use crate::application_facade::{
    AuthModeDto, BackendImportResult, BackendPresetResult, BackendScanResult,
    CreatePresetAndBindRequest, IdentitySummaryDto, ImportStatusDto, M33Backend, M33BackendError,
    ModelPresetSummaryDto, ScanCandidateDto, ScanStateDto, UpdatePresetAndBindRequest,
};

#[derive(Clone, Debug)]
pub struct ProductionM33Backend {
    database_path: PathBuf,
    credential_root: PathBuf,
}

impl ProductionM33Backend {
    pub fn new(app_data_dir: impl AsRef<Path>) -> Result<Self, M33BackendError> {
        let app_data_dir = app_data_dir.as_ref();
        if !app_data_dir.is_absolute() {
            return Err(M33BackendError::Unavailable);
        }
        fs::create_dir_all(app_data_dir).map_err(|_| M33BackendError::Unavailable)?;
        Ok(Self {
            database_path: app_data_dir.join("metadata.sqlite3"),
            credential_root: app_data_dir.join("credentials"),
        })
    }

    fn repository(&self) -> Result<SqliteMetadataRepository, M33BackendError> {
        SqliteMetadataRepository::open(&self.database_path).map_err(map_open_error)
    }
}

impl M33Backend for ProductionM33Backend {
    fn scan_default_codex(&self) -> Result<BackendScanResult, M33BackendError> {
        let repository = self.repository()?;
        let source = ControlledCodexAdapter::new(WindowsControlledRootReader::default_codex());
        match CaptureImportService::new().scan(&source, ControlledRoot::DefaultCodex) {
            ControlledScanStatus::CompatibilityProtected(reason) => Ok(BackendScanResult {
                status: scan_state_from_compatibility(reason),
                candidate: None,
                existing_identity_id: None,
            }),
            ControlledScanStatus::Ready(summary) => {
                let mut matcher = ExistingIdentityMatcher {
                    repository: &repository,
                    result: None,
                };
                // 只在用户显式扫描后执行 exact rescan；auth 借用不会离开后端调用栈。
                match source.consume_confirmed(
                    ControlledRoot::DefaultCodex,
                    &summary.scan_id,
                    &mut matcher,
                ) {
                    Ok(()) => {}
                    Err(ControlledSourceError::ScanChanged | ControlledSourceError::Busy) => {
                        return Ok(BackendScanResult {
                            status: ScanStateDto::Conflict,
                            candidate: None,
                            existing_identity_id: None,
                        });
                    }
                    Err(ControlledSourceError::RecoveryRequired) => {
                        return Ok(BackendScanResult {
                            status: ScanStateDto::RecoveryRequired,
                            candidate: None,
                            existing_identity_id: None,
                        });
                    }
                    Err(ControlledSourceError::CompatibilityProtected(reason)) => {
                        return Ok(BackendScanResult {
                            status: scan_state_from_compatibility(reason),
                            candidate: None,
                            existing_identity_id: None,
                        });
                    }
                    Err(
                        ControlledSourceError::IoUnavailable
                        | ControlledSourceError::ConsumerRejected,
                    ) => {
                        return Err(M33BackendError::Unavailable);
                    }
                }
                let candidate = ScanCandidateDto {
                    scan_id: summary.scan_id.as_hash().as_str().to_owned(),
                    auth_mode: auth_mode(summary.auth_mode),
                };
                match matcher.result.unwrap_or(MatchStatus::MultipleMatches) {
                    MatchStatus::Unmanaged => Ok(BackendScanResult {
                        status: ScanStateDto::Candidate,
                        candidate: Some(candidate),
                        existing_identity_id: None,
                    }),
                    MatchStatus::UniqueMatch(identity_id) => Ok(BackendScanResult {
                        status: ScanStateDto::Duplicate,
                        candidate: Some(candidate),
                        existing_identity_id: Some(identity_id.as_str().to_owned()),
                    }),
                    MatchStatus::MultipleMatches => Ok(BackendScanResult {
                        status: ScanStateDto::Conflict,
                        candidate: None,
                        existing_identity_id: None,
                    }),
                    MatchStatus::CompatibilityProtected(reason) => Ok(BackendScanResult {
                        status: scan_state_from_compatibility(reason),
                        candidate: None,
                        existing_identity_id: None,
                    }),
                }
            }
        }
    }

    fn import_candidate(&self, scan_id: &str) -> Result<BackendImportResult, M33BackendError> {
        let mut repository = self.repository()?;
        let mut store = WindowsDpapiCredentialStore::new(&self.credential_root)
            .map_err(|_| M33BackendError::Unavailable)?;
        let source = ControlledCodexAdapter::new(WindowsControlledRootReader::default_codex());
        let scan_id = ControlledScanId::parse(scan_id).map_err(|_| M33BackendError::Validation)?;
        let identity_id = IdentityId::parse(&derived_uuid(scan_id.as_hash().as_str(), 2)?)
            .map_err(|_| M33BackendError::Internal)?;
        let request = CaptureImportRequest {
            root: ControlledRoot::DefaultCodex,
            scan_id,
            credential_id: CredentialRefId::parse(&derived_uuid(identity_id.as_str(), 1)?)
                .map_err(|_| M33BackendError::Internal)?,
            identity_id: identity_id.clone(),
            identity_name: EntityName::parse("本地 Codex 身份")
                .map_err(|_| M33BackendError::Internal)?,
            preset_id: ModelPresetId::parse(&derived_uuid(identity_id.as_str(), 3)?)
                .map_err(|_| M33BackendError::Internal)?,
            preset_name: EntityName::parse("默认模型").map_err(|_| M33BackendError::Internal)?,
            patch_id: ManagedConfigPatchId::parse(&derived_uuid(identity_id.as_str(), 4)?)
                .map_err(|_| M33BackendError::Internal)?,
            now: now()?,
        };
        match CaptureImportService::new().capture_import(
            &source,
            &mut repository,
            &mut store,
            request,
        ) {
            CaptureImportStatus::Imported(id) => Ok(BackendImportResult {
                status: ImportStatusDto::Imported,
                identity_id: id.as_str().to_owned(),
            }),
            CaptureImportStatus::AlreadyImported(id) => Ok(BackendImportResult {
                status: ImportStatusDto::Duplicate,
                identity_id: id.as_str().to_owned(),
            }),
            CaptureImportStatus::CompatibilityProtected(_) => {
                Err(M33BackendError::CompatibilityProtected)
            }
            CaptureImportStatus::Conflict => Err(M33BackendError::Conflict),
            CaptureImportStatus::RecoveryRequired(_) => Err(M33BackendError::RecoveryRequired),
        }
    }

    fn list_identities(&self) -> Result<Vec<IdentitySummaryDto>, M33BackendError> {
        self.repository()?
            .list_runtime_identities()
            .map(|items| items.iter().map(identity_summary).collect())
            .map_err(map_repository_error)
    }

    fn rename_identity(
        &self,
        identity_id: &str,
        expected_version: u64,
        name: &str,
    ) -> Result<IdentitySummaryDto, M33BackendError> {
        let identity_id =
            IdentityId::parse(identity_id).map_err(|_| M33BackendError::Validation)?;
        let expected =
            EntityVersion::new(expected_version).map_err(|_| M33BackendError::Validation)?;
        let name = EntityName::parse(name).map_err(|_| M33BackendError::Validation)?;
        let mut repository = self.repository()?;
        let identity = repository
            .get_runtime_identity(&identity_id)
            .map_err(map_repository_error)?
            .ok_or(M33BackendError::NotFound)?;
        if identity.version() != expected {
            return Err(M33BackendError::Conflict);
        }
        let renamed = identity
            .rename(name, now()?)
            .map_err(|_| M33BackendError::Validation)?;
        repository
            .update_runtime_identity(&renamed, expected)
            .map_err(map_repository_error)?;
        Ok(identity_summary(&renamed))
    }

    fn list_presets(
        &self,
        identity_id: &str,
    ) -> Result<Vec<ModelPresetSummaryDto>, M33BackendError> {
        let identity_id =
            IdentityId::parse(identity_id).map_err(|_| M33BackendError::Validation)?;
        let repository = self.repository()?;
        let identity = repository
            .get_runtime_identity(&identity_id)
            .map_err(map_repository_error)?
            .ok_or(M33BackendError::NotFound)?;
        repository
            .list_model_presets(&identity_id)
            .map_err(map_repository_error)
            .map(|presets| {
                presets
                    .iter()
                    .map(|preset| preset_summary(preset, identity.default_model_preset_id()))
                    .collect()
            })
    }

    fn create_preset_and_bind(
        &self,
        request: &CreatePresetAndBindRequest,
    ) -> Result<BackendPresetResult, M33BackendError> {
        let mut repository = self.repository()?;
        let outcome = PresetBindingService::new(&mut repository)
            .create_and_bind(CreatePresetAndBindInput {
                service_version: codex_application::M27_SERVICE_VERSION,
                identity_id: IdentityId::parse(request.identity_id.as_str())
                    .map_err(|_| M33BackendError::Validation)?,
                expected_identity_version: EntityVersion::new(request.expected_identity_version)
                    .map_err(|_| M33BackendError::Validation)?,
                preset_id: ModelPresetId::parse(request.preset_id.as_str())
                    .map_err(|_| M33BackendError::Validation)?,
                name: EntityName::parse(request.name.as_str())
                    .map_err(|_| M33BackendError::Validation)?,
                model_id: ModelId::parse(request.model_id.as_str())
                    .map_err(|_| M33BackendError::Validation)?,
                now: now()?,
            })
            .map_err(map_preset_error)?;
        Ok(binding_result(outcome))
    }

    fn update_preset_and_bind(
        &self,
        request: &UpdatePresetAndBindRequest,
    ) -> Result<BackendPresetResult, M33BackendError> {
        let mut repository = self.repository()?;
        let outcome = PresetBindingService::new(&mut repository)
            .update_and_bind(UpdatePresetAndBindInput {
                service_version: codex_application::M27_SERVICE_VERSION,
                identity_id: IdentityId::parse(request.identity_id.as_str())
                    .map_err(|_| M33BackendError::Validation)?,
                expected_identity_version: EntityVersion::new(request.expected_identity_version)
                    .map_err(|_| M33BackendError::Validation)?,
                preset_id: ModelPresetId::parse(request.preset_id.as_str())
                    .map_err(|_| M33BackendError::Validation)?,
                expected_preset_version: EntityVersion::new(request.expected_preset_version)
                    .map_err(|_| M33BackendError::Validation)?,
                name: EntityName::parse(request.name.as_str())
                    .map_err(|_| M33BackendError::Validation)?,
                model_id: ModelId::parse(request.model_id.as_str())
                    .map_err(|_| M33BackendError::Validation)?,
                now: now()?,
            })
            .map_err(map_preset_error)?;
        Ok(binding_result(outcome))
    }
}

struct ExistingIdentityMatcher<'a> {
    repository: &'a SqliteMetadataRepository,
    result: Option<MatchStatus>,
}

impl ScannedAuthConsumer for ExistingIdentityMatcher<'_> {
    fn consume(
        &mut self,
        actual: &codex_application::ActualCodexState,
        _auth: &mut [u8],
    ) -> Result<(), ControlledSourceError> {
        self.result = Some(
            match_actual_identity(
                self.repository,
                &ScanStatus::Ready(Box::new(actual.clone())),
            )
            .map_err(|_| ControlledSourceError::IoUnavailable)?,
        );
        Ok(())
    }
}

fn identity_summary(identity: &RuntimeIdentity) -> IdentitySummaryDto {
    IdentitySummaryDto {
        identity_id: identity.id().as_str().to_owned(),
        name: identity.name().as_str().to_owned(),
        provider_name: identity.provider_display_name().as_str().to_owned(),
        auth_mode: auth_mode(identity.auth_mode()),
        status: match identity.status() {
            IdentityStatus::Draft => "draft",
            IdentityStatus::Ready => "ready",
            IdentityStatus::Disabled => "disabled",
        }
        .to_owned(),
        default_preset_id: identity
            .default_model_preset_id()
            .map(|id| id.as_str().to_owned()),
        version: identity.version().value(),
    }
}

fn preset_summary(
    preset: &codex_domain::ModelPreset,
    default: Option<&ModelPresetId>,
) -> ModelPresetSummaryDto {
    ModelPresetSummaryDto {
        preset_id: preset.id().as_str().to_owned(),
        name: preset.name().as_str().to_owned(),
        model_id: preset.model_id().as_str().to_owned(),
        version: preset.version().value(),
        is_default: default == Some(preset.id()),
    }
}

fn binding_result(outcome: PresetBindingOutcome) -> BackendPresetResult {
    let summary = match outcome {
        PresetBindingOutcome::Applied(summary) | PresetBindingOutcome::AlreadyApplied(summary) => {
            summary
        }
    };
    BackendPresetResult {
        identity_version: summary.identity_version.value(),
        preset: ModelPresetSummaryDto {
            preset_id: summary.preset_id.as_str().to_owned(),
            name: summary.preset_name.as_str().to_owned(),
            model_id: summary.model_id.as_str().to_owned(),
            version: summary.preset_version.value(),
            is_default: true,
        },
    }
}

const fn auth_mode(mode: AuthMode) -> AuthModeDto {
    match mode {
        AuthMode::ApiKey => AuthModeDto::ApiKey,
        AuthMode::OAuth => AuthModeDto::OAuth,
    }
}

const fn scan_state_from_compatibility(reason: CompatibilityReason) -> ScanStateDto {
    match reason {
        CompatibilityReason::MissingConfig | CompatibilityReason::MissingAuthentication => {
            ScanStateDto::NotFound
        }
        _ => ScanStateDto::CompatibilityProtected,
    }
}

fn map_open_error(error: OpenRepositoryError) -> M33BackendError {
    match error {
        OpenRepositoryError::CorruptData => M33BackendError::RecoveryRequired,
        OpenRepositoryError::Migration(_) | OpenRepositoryError::StorageUnavailable => {
            M33BackendError::Unavailable
        }
    }
}

fn map_repository_error(error: RepositoryError) -> M33BackendError {
    match error {
        RepositoryError::NotFound(_) => M33BackendError::NotFound,
        RepositoryError::AlreadyExists(_)
        | RepositoryError::VersionConflict(_)
        | RepositoryError::ReferenceConflict(_) => M33BackendError::Conflict,
        RepositoryError::CorruptData => M33BackendError::RecoveryRequired,
        RepositoryError::StorageUnavailable => M33BackendError::Unavailable,
    }
}

fn map_preset_error(error: PresetBindingError) -> M33BackendError {
    match error {
        PresetBindingError::UnsupportedVersion | PresetBindingError::Validation => {
            M33BackendError::Validation
        }
        PresetBindingError::IdentityNotFound | PresetBindingError::PresetNotFound => {
            M33BackendError::NotFound
        }
        PresetBindingError::Conflict => M33BackendError::Conflict,
        PresetBindingError::RecoveryRequired => M33BackendError::RecoveryRequired,
        PresetBindingError::StorageUnavailable => M33BackendError::Unavailable,
        PresetBindingError::CorruptData => M33BackendError::RecoveryRequired,
    }
}

fn now() -> Result<UnixMillis, M33BackendError> {
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| M33BackendError::Unavailable)?
        .as_millis();
    let value = i64::try_from(value).map_err(|_| M33BackendError::Unavailable)?;
    UnixMillis::new(value).map_err(|_| M33BackendError::Unavailable)
}

fn derived_uuid(seed: &str, tag: u8) -> Result<String, M33BackendError> {
    let hex: String = seed
        .bytes()
        .filter(u8::is_ascii_hexdigit)
        .map(char::from)
        .collect();
    if hex.len() < 32 {
        return Err(M33BackendError::Validation);
    }
    let mut bytes = hex.as_bytes()[..32].to_vec();
    let first = (bytes[0] as char)
        .to_digit(16)
        .ok_or(M33BackendError::Validation)? as u8;
    bytes[0] = char::from_digit(u32::from(first ^ (tag & 0x0f)), 16)
        .ok_or(M33BackendError::Internal)? as u8;
    let value = String::from_utf8(bytes).map_err(|_| M33BackendError::Internal)?;
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
    use super::*;

    #[test]
    fn native_backend_lists_from_synthetic_app_data_without_scanning() {
        let unique = format!(
            "codextools-m33-native-smoke-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root = std::env::temp_dir().join(unique);
        fs::create_dir(&root).unwrap();
        {
            let backend = ProductionM33Backend::new(&root).unwrap();
            assert!(backend.list_identities().unwrap().is_empty());
            assert!(!root.join("credentials").exists());
        }
        fs::remove_dir_all(&root).unwrap();
    }
}
