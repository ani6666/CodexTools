use std::fmt;

use codex_domain::{
    DomainError, EntityName, EntityVersion, IdentityId, ModelId, ModelPreset, ModelPresetId,
    UnixMillis,
};

pub const M27_SERVICE_VERSION: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreatePresetAndBindInput {
    pub service_version: u16,
    pub identity_id: IdentityId,
    pub expected_identity_version: EntityVersion,
    pub preset_id: ModelPresetId,
    pub name: EntityName,
    pub model_id: ModelId,
    pub now: UnixMillis,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdatePresetAndBindInput {
    pub service_version: u16,
    pub identity_id: IdentityId,
    pub expected_identity_version: EntityVersion,
    pub preset_id: ModelPresetId,
    pub expected_preset_version: EntityVersion,
    pub name: EntityName,
    pub model_id: ModelId,
    pub now: UnixMillis,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreatePresetAndBindCommand {
    pub identity_id: IdentityId,
    pub expected_identity_version: EntityVersion,
    pub preset: ModelPreset,
    pub now: UnixMillis,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdatePresetAndBindCommand {
    pub identity_id: IdentityId,
    pub expected_identity_version: EntityVersion,
    pub preset_id: ModelPresetId,
    pub expected_preset_version: EntityVersion,
    pub name: EntityName,
    pub model_id: ModelId,
    pub now: UnixMillis,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PresetBindingSummary {
    pub identity_id: IdentityId,
    pub identity_version: EntityVersion,
    pub preset_id: ModelPresetId,
    pub preset_name: EntityName,
    pub model_id: ModelId,
    pub preset_version: EntityVersion,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PresetBindingOutcome {
    Applied(PresetBindingSummary),
    AlreadyApplied(PresetBindingSummary),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresetBindingEntity {
    Identity,
    Preset,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresetBindingRepositoryError {
    NotFound(PresetBindingEntity),
    Validation,
    Conflict,
    RecoveryRequired,
    StorageUnavailable,
    CorruptData,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresetBindingError {
    UnsupportedVersion,
    Validation,
    IdentityNotFound,
    PresetNotFound,
    Conflict,
    RecoveryRequired,
    StorageUnavailable,
    CorruptData,
}

impl fmt::Display for PresetBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedVersion => "preset binding service version is unsupported",
            Self::Validation => "preset metadata is invalid",
            Self::IdentityNotFound => "runtime identity was not found",
            Self::PresetNotFound => "model preset was not found",
            Self::Conflict => "preset binding conflict",
            Self::RecoveryRequired => "preset binding outcome requires recovery",
            Self::StorageUnavailable => "preset binding storage is unavailable",
            Self::CorruptData => "preset binding data is invalid",
        })
    }
}

impl std::error::Error for PresetBindingError {}

impl From<DomainError> for PresetBindingError {
    fn from(_: DomainError) -> Self {
        Self::Validation
    }
}

impl From<PresetBindingRepositoryError> for PresetBindingError {
    fn from(value: PresetBindingRepositoryError) -> Self {
        match value {
            PresetBindingRepositoryError::NotFound(PresetBindingEntity::Identity) => {
                Self::IdentityNotFound
            }
            PresetBindingRepositoryError::NotFound(PresetBindingEntity::Preset) => {
                Self::PresetNotFound
            }
            PresetBindingRepositoryError::Validation => Self::Validation,
            PresetBindingRepositoryError::Conflict => Self::Conflict,
            PresetBindingRepositoryError::RecoveryRequired => Self::RecoveryRequired,
            PresetBindingRepositoryError::StorageUnavailable => Self::StorageUnavailable,
            PresetBindingRepositoryError::CorruptData => Self::CorruptData,
        }
    }
}

pub trait PresetBindingRepository {
    fn create_preset_and_bind(
        &mut self,
        command: CreatePresetAndBindCommand,
    ) -> Result<PresetBindingOutcome, PresetBindingRepositoryError>;

    fn update_preset_and_bind(
        &mut self,
        command: UpdatePresetAndBindCommand,
    ) -> Result<PresetBindingOutcome, PresetBindingRepositoryError>;
}

pub struct PresetBindingService<'a, R> {
    repository: &'a mut R,
}

impl<'a, R: PresetBindingRepository> PresetBindingService<'a, R> {
    pub const fn new(repository: &'a mut R) -> Self {
        Self { repository }
    }

    pub fn create_and_bind(
        &mut self,
        input: CreatePresetAndBindInput,
    ) -> Result<PresetBindingOutcome, PresetBindingError> {
        validate_service_version(input.service_version)?;
        let preset = ModelPreset::new_managed(
            input.preset_id,
            input.identity_id.clone(),
            input.name,
            input.model_id,
            input.now,
        )?;
        self.repository
            .create_preset_and_bind(CreatePresetAndBindCommand {
                identity_id: input.identity_id,
                expected_identity_version: input.expected_identity_version,
                preset,
                now: input.now,
            })
            .map_err(Into::into)
    }

    pub fn update_and_bind(
        &mut self,
        input: UpdatePresetAndBindInput,
    ) -> Result<PresetBindingOutcome, PresetBindingError> {
        validate_service_version(input.service_version)?;
        ModelPreset::validate_managed_metadata(&input.name, &input.model_id)?;
        self.repository
            .update_preset_and_bind(UpdatePresetAndBindCommand {
                identity_id: input.identity_id,
                expected_identity_version: input.expected_identity_version,
                preset_id: input.preset_id,
                expected_preset_version: input.expected_preset_version,
                name: input.name,
                model_id: input.model_id,
                now: input.now,
            })
            .map_err(Into::into)
    }
}

fn validate_service_version(version: u16) -> Result<(), PresetBindingError> {
    if version != M27_SERVICE_VERSION {
        return Err(PresetBindingError::UnsupportedVersion);
    }
    Ok(())
}
