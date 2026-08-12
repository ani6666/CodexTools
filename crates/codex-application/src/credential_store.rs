use std::fmt;

use std::path::PathBuf;

use crate::RepositoryError;
use codex_domain::{
    ContentHash, CredentialFingerprint, CredentialKind, CredentialRefId, EntityVersion,
    SchemaFingerprint, UnixMillis,
};

#[derive(Clone, Eq, PartialEq)]
pub struct CredentialEnvelopeBinding {
    id: CredentialRefId,
    kind: CredentialKind,
    schema_fingerprint: SchemaFingerprint,
    generation: EntityVersion,
}

impl CredentialEnvelopeBinding {
    #[must_use]
    pub const fn new(
        id: CredentialRefId,
        kind: CredentialKind,
        schema_fingerprint: SchemaFingerprint,
        generation: EntityVersion,
    ) -> Self {
        Self {
            id,
            kind,
            schema_fingerprint,
            generation,
        }
    }
    pub const fn id(&self) -> &CredentialRefId {
        &self.id
    }
    pub const fn kind(&self) -> CredentialKind {
        self.kind
    }
    pub const fn schema_fingerprint(&self) -> &SchemaFingerprint {
        &self.schema_fingerprint
    }
    pub const fn generation(&self) -> EntityVersion {
        self.generation
    }
}

impl fmt::Debug for CredentialEnvelopeBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialEnvelopeBinding")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("schema_fingerprint", &"[REDACTED]")
            .field("generation", &self.generation)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialStoreError {
    AlreadyExists,
    NotFound,
    VersionConflict,
    BindingMismatch,
    CorruptEnvelope,
    ProtectionFailed,
    IoFailure,
    RecoveryRequired,
}

impl fmt::Display for CredentialStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AlreadyExists => "credential material already exists",
            Self::NotFound => "credential material was not found",
            Self::VersionConflict => "credential material version conflict",
            Self::BindingMismatch => "credential material binding mismatch",
            Self::CorruptEnvelope => "credential envelope is invalid",
            Self::ProtectionFailed => "credential protection operation failed",
            Self::IoFailure => "credential material storage failed",
            Self::RecoveryRequired => "credential material recovery is required",
        })
    }
}
impl std::error::Error for CredentialStoreError {}

pub trait SecretConsumer {
    fn consume(&mut self, secret: &[u8]) -> Result<(), CredentialStoreError>;
}

/// 仅在凭据 owner 锁内接收经仓储复读确认的引用及短生命周期明文。
pub trait BoundSecretConsumer {
    fn consume(
        &mut self,
        reference: &codex_domain::CredentialReference,
        secret: &[u8],
    ) -> Result<(), CredentialStoreError>;
}

pub trait CredentialStore {
    fn begin_mutation(
        &mut self,
        _id: &CredentialRefId,
    ) -> Result<CredentialMutationOwner, CredentialStoreError> {
        Err(CredentialStoreError::RecoveryRequired)
    }
    fn end_mutation(
        &mut self,
        _owner: CredentialMutationOwner,
    ) -> Result<(), CredentialStoreError> {
        Err(CredentialStoreError::RecoveryRequired)
    }
    fn planned_material_ref(
        &self,
        _binding: &CredentialEnvelopeBinding,
    ) -> Result<PathBuf, CredentialStoreError> {
        Err(CredentialStoreError::RecoveryRequired)
    }
    fn create(
        &mut self,
        binding: &CredentialEnvelopeBinding,
        secret: &mut [u8],
    ) -> Result<(), CredentialStoreError>;
    fn read(
        &self,
        binding: &CredentialEnvelopeBinding,
        consumer: &mut dyn SecretConsumer,
    ) -> Result<(), CredentialStoreError>;
    fn rotate(
        &mut self,
        previous: &CredentialEnvelopeBinding,
        next: &CredentialEnvelopeBinding,
        secret: &mut [u8],
    ) -> Result<(), CredentialStoreError>;
    fn delete(&mut self, binding: &CredentialEnvelopeBinding) -> Result<(), CredentialStoreError>;
    fn inspect(
        &self,
        _binding: &CredentialEnvelopeBinding,
    ) -> Result<CredentialMaterialDiagnostic, CredentialStoreError> {
        Err(CredentialStoreError::RecoveryRequired)
    }
    fn inspect_delete_recovery(
        &self,
        _binding: &CredentialEnvelopeBinding,
    ) -> Result<CredentialMaterialDiagnostic, CredentialStoreError> {
        Err(CredentialStoreError::RecoveryRequired)
    }
    fn restore_delete_recovery(
        &mut self,
        _binding: &CredentialEnvelopeBinding,
    ) -> Result<(), CredentialStoreError> {
        Err(CredentialStoreError::RecoveryRequired)
    }
    fn rollback_rotation(
        &mut self,
        _previous: &CredentialEnvelopeBinding,
        _next: &CredentialEnvelopeBinding,
    ) -> Result<(), CredentialStoreError> {
        Err(CredentialStoreError::RecoveryRequired)
    }
}

/// 跨整个 service mutation 持有的非秘密所有权令牌。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialMutationOwner {
    credential_id: CredentialRefId,
    nonce: u64,
}

impl CredentialMutationOwner {
    #[must_use]
    pub const fn new(credential_id: CredentialRefId, nonce: u64) -> Self {
        Self {
            credential_id,
            nonce,
        }
    }
    pub const fn credential_id(&self) -> &CredentialRefId {
        &self.credential_id
    }
    pub const fn nonce(&self) -> u64 {
        self.nonce
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialMaterialDiagnostic {
    pub material_ref: PathBuf,
    pub material_hash: ContentHash,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialRecoveryOperation {
    Create,
    Rotate,
    Delete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialRecoveryPhase {
    Prepared,
    Published,
    MetadataPending,
    DeletePending,
    RecoveryRequired,
}

/// 非秘密的凭据恢复诊断；材料正文与完整凭据指纹不进入仓储。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRecoveryRecord {
    pub operation_id: String,
    pub credential_id: CredentialRefId,
    pub kind: CredentialKind,
    pub operation: CredentialRecoveryOperation,
    pub generation: EntityVersion,
    /// Planned non-secret credential fingerprint. `None` is read-only v8 legacy state.
    pub planned_credential_fingerprint: Option<CredentialFingerprint>,
    pub material_ref: PathBuf,
    pub material_hash: Option<ContentHash>,
    pub phase: CredentialRecoveryPhase,
    pub diagnostic_code: Option<String>,
    /// Immutable credential creation timestamp captured before metadata mutation.
    pub credential_created_at: UnixMillis,
    /// Credential update timestamp captured before metadata mutation.
    pub credential_updated_at: UnixMillis,
    /// Recovery journal creation timestamp; it is not a credential timestamp.
    pub created_at: UnixMillis,
    /// Recovery journal diagnostic update timestamp.
    pub updated_at: UnixMillis,
    pub version: EntityVersion,
}

pub trait CredentialRecoveryRepository {
    fn create_credential_recovery(
        &mut self,
        record: &CredentialRecoveryRecord,
    ) -> Result<(), RepositoryError>;
    fn get_credential_recovery(
        &self,
        operation_id: &str,
    ) -> Result<Option<CredentialRecoveryRecord>, RepositoryError>;
    fn list_credential_recoveries(
        &self,
        id: &CredentialRefId,
    ) -> Result<Vec<CredentialRecoveryRecord>, RepositoryError>;
    fn update_credential_recovery(
        &mut self,
        record: &CredentialRecoveryRecord,
        expected_version: EntityVersion,
    ) -> Result<(), RepositoryError>;
    fn delete_credential_recovery(
        &mut self,
        operation_id: &str,
        expected_version: EntityVersion,
    ) -> Result<(), RepositoryError>;
}
