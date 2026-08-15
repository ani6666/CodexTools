#![forbid(unsafe_code)]
//! CodexTools 应用边界与基础设施端口。

use std::fmt;

use codex_domain::{
    AuthMode, CredentialFingerprint, CredentialRefId, CredentialReference, EndpointUrl,
    EntityVersion, IdentityId, ModelPreset, ModelPresetId, ProviderId, RuntimeIdentity,
};

pub mod codex;
pub use codex::*;
mod preset_binding;
pub use preset_binding::*;
mod capture_import;
pub use capture_import::*;
mod backup;
pub use backup::*;
mod credential_store;
pub use credential_store::*;
mod oauth;
pub use oauth::*;
mod switch;
pub use switch::*;

/// 仓储错误只暴露业务分类，不包含 SQL、路径或用户输入。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryError {
    NotFound(EntityKind),
    AlreadyExists(EntityKind),
    VersionConflict(EntityKind),
    ReferenceConflict(EntityKind),
    CorruptData,
    StorageUnavailable,
}

impl RepositoryError {
    #[must_use]
    pub const fn not_found(kind: EntityKind) -> Self {
        Self::NotFound(kind)
    }

    #[must_use]
    pub const fn already_exists(kind: EntityKind) -> Self {
        Self::AlreadyExists(kind)
    }

    #[must_use]
    pub const fn version_conflict(kind: EntityKind) -> Self {
        Self::VersionConflict(kind)
    }

    #[must_use]
    pub const fn reference_conflict(kind: EntityKind) -> Self {
        Self::ReferenceConflict(kind)
    }

    #[must_use]
    pub const fn corrupt_data() -> Self {
        Self::CorruptData
    }

    #[must_use]
    pub const fn storage_unavailable() -> Self {
        Self::StorageUnavailable
    }
}

impl fmt::Display for RepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(kind) => write!(formatter, "{kind} was not found"),
            Self::AlreadyExists(kind) => write!(formatter, "{kind} already exists"),
            Self::VersionConflict(kind) => write!(formatter, "{kind} version conflict"),
            Self::ReferenceConflict(kind) => write!(formatter, "{kind} reference conflict"),
            Self::CorruptData => formatter.write_str("repository data is invalid"),
            Self::StorageUnavailable => formatter.write_str("repository storage is unavailable"),
        }
    }
}

impl std::error::Error for RepositoryError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntityKind {
    CredentialReference,
    RuntimeIdentity,
    ModelPreset,
    ManagedConfigPatch,
    SwitchTransaction,
    BackupSet,
}

impl fmt::Display for EntityKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CredentialReference => "credential reference",
            Self::RuntimeIdentity => "runtime identity",
            Self::ModelPreset => "model preset",
            Self::ManagedConfigPatch => "managed config patch",
            Self::SwitchTransaction => "switch transaction",
            Self::BackupSet => "backup set",
        })
    }
}

pub trait ManagedConfigPatchRepository {
    fn create_managed_config_patch(
        &mut self,
        patch: &codex_domain::ManagedConfigPatch,
    ) -> Result<(), RepositoryError>;
    fn get_managed_config_patch(
        &self,
        identity_id: &IdentityId,
    ) -> Result<Option<codex_domain::ManagedConfigPatch>, RepositoryError>;
}

/// M2.2 唯一匹配使用的候选查询输入；本阶段不实现匹配决策。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityCandidateQuery {
    provider_id: ProviderId,
    api_base_url: EndpointUrl,
    auth_mode: AuthMode,
    credential_fingerprint: CredentialFingerprint,
}

impl IdentityCandidateQuery {
    #[must_use]
    pub const fn new(
        provider_id: ProviderId,
        api_base_url: EndpointUrl,
        auth_mode: AuthMode,
        credential_fingerprint: CredentialFingerprint,
    ) -> Self {
        Self {
            provider_id,
            api_base_url,
            auth_mode,
            credential_fingerprint,
        }
    }

    #[must_use]
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    #[must_use]
    pub const fn api_base_url(&self) -> &EndpointUrl {
        &self.api_base_url
    }

    #[must_use]
    pub const fn auth_mode(&self) -> AuthMode {
        self.auth_mode
    }

    #[must_use]
    pub const fn credential_fingerprint(&self) -> &CredentialFingerprint {
        &self.credential_fingerprint
    }
}

pub trait CredentialReferenceRepository {
    fn create_credential_reference(
        &mut self,
        reference: &CredentialReference,
    ) -> Result<(), RepositoryError>;
    fn get_credential_reference(
        &self,
        id: &CredentialRefId,
    ) -> Result<Option<CredentialReference>, RepositoryError>;
    fn list_credential_references(&self) -> Result<Vec<CredentialReference>, RepositoryError>;
    fn update_credential_reference(
        &mut self,
        reference: &CredentialReference,
        expected_version: EntityVersion,
    ) -> Result<(), RepositoryError>;
    fn delete_credential_reference(
        &mut self,
        id: &CredentialRefId,
        expected_version: EntityVersion,
    ) -> Result<(), RepositoryError>;
}

pub trait RuntimeIdentityRepository {
    fn create_runtime_identity(
        &mut self,
        identity: &RuntimeIdentity,
    ) -> Result<(), RepositoryError>;
    fn get_runtime_identity(
        &self,
        id: &IdentityId,
    ) -> Result<Option<RuntimeIdentity>, RepositoryError>;
    fn list_runtime_identities(&self) -> Result<Vec<RuntimeIdentity>, RepositoryError>;
    fn update_runtime_identity(
        &mut self,
        identity: &RuntimeIdentity,
        expected_version: EntityVersion,
    ) -> Result<(), RepositoryError>;
    fn delete_runtime_identity(
        &mut self,
        id: &IdentityId,
        expected_version: EntityVersion,
    ) -> Result<(), RepositoryError>;
    fn find_identity_candidates(
        &self,
        query: &IdentityCandidateQuery,
    ) -> Result<Vec<RuntimeIdentity>, RepositoryError>;
}

pub trait ModelPresetRepository {
    fn create_model_preset(&mut self, preset: &ModelPreset) -> Result<(), RepositoryError>;
    fn get_model_preset(&self, id: &ModelPresetId) -> Result<Option<ModelPreset>, RepositoryError>;
    fn list_model_presets(
        &self,
        identity_id: &IdentityId,
    ) -> Result<Vec<ModelPreset>, RepositoryError>;
    fn update_model_preset(
        &mut self,
        preset: &ModelPreset,
        expected_version: EntityVersion,
    ) -> Result<(), RepositoryError>;
    fn delete_model_preset(
        &mut self,
        id: &ModelPresetId,
        expected_version: EntityVersion,
    ) -> Result<(), RepositoryError>;
}
