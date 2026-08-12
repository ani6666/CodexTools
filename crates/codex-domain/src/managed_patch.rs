use crate::{
    ContentHash, DomainError, EntityVersion, IdentityId, ManagedConfigPatchId, UnixMillis,
};

pub const MANAGED_CONFIG_PATHS: [&str; 4] = [
    "model_provider",
    "model",
    "model_providers.<provider>.name",
    "model_providers.<provider>.base_url",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedConfigPatch {
    id: ManagedConfigPatchId,
    identity_id: IdentityId,
    baseline_sha256: ContentHash,
    target_sha256: ContentHash,
    created_at: UnixMillis,
    updated_at: UnixMillis,
    version: EntityVersion,
}

impl ManagedConfigPatch {
    pub fn new(
        id: ManagedConfigPatchId,
        identity_id: IdentityId,
        baseline_sha256: ContentHash,
        target_sha256: ContentHash,
        now: UnixMillis,
    ) -> Self {
        Self {
            id,
            identity_id,
            baseline_sha256,
            target_sha256,
            created_at: now,
            updated_at: now,
            version: EntityVersion::initial(),
        }
    }

    pub fn restore(
        id: ManagedConfigPatchId,
        identity_id: IdentityId,
        baseline_sha256: ContentHash,
        target_sha256: ContentHash,
        created_at: UnixMillis,
        updated_at: UnixMillis,
        version: EntityVersion,
    ) -> Result<Self, DomainError> {
        if updated_at < created_at {
            return Err(DomainError::TimestampOrder);
        }
        Ok(Self {
            id,
            identity_id,
            baseline_sha256,
            target_sha256,
            created_at,
            updated_at,
            version,
        })
    }

    pub const fn id(&self) -> &ManagedConfigPatchId {
        &self.id
    }
    pub const fn identity_id(&self) -> &IdentityId {
        &self.identity_id
    }
    pub const fn baseline_sha256(&self) -> &ContentHash {
        &self.baseline_sha256
    }
    pub const fn target_sha256(&self) -> &ContentHash {
        &self.target_sha256
    }
    pub const fn created_at(&self) -> UnixMillis {
        self.created_at
    }
    pub const fn updated_at(&self) -> UnixMillis {
        self.updated_at
    }
    pub const fn version(&self) -> EntityVersion {
        self.version
    }
}
