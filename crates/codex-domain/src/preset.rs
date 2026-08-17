use crate::{
    DomainError, EntityName, EntityVersion, IdentityId, ModelId, ModelPresetId, UnixMillis,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelPreset {
    id: ModelPresetId,
    identity_id: IdentityId,
    name: EntityName,
    model_id: ModelId,
    created_at: UnixMillis,
    updated_at: UnixMillis,
    version: EntityVersion,
}

impl ModelPreset {
    #[must_use]
    pub const fn new(
        id: ModelPresetId,
        identity_id: IdentityId,
        name: EntityName,
        model_id: ModelId,
        created_at: UnixMillis,
    ) -> Self {
        Self {
            id,
            identity_id,
            name,
            model_id,
            created_at,
            updated_at: created_at,
            version: EntityVersion::initial(),
        }
    }

    /// 构造可由身份管理界面编辑的安全预设元数据。
    pub fn new_managed(
        id: ModelPresetId,
        identity_id: IdentityId,
        name: EntityName,
        model_id: ModelId,
        created_at: UnixMillis,
    ) -> Result<Self, DomainError> {
        Self::validate_managed_metadata(&name, &model_id)?;
        Ok(Self::new(id, identity_id, name, model_id, created_at))
    }

    pub fn validate_managed_metadata(
        name: &EntityName,
        model_id: &ModelId,
    ) -> Result<(), DomainError> {
        name.ensure_preset_metadata_safe()?;
        model_id.ensure_preset_metadata_safe()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        id: ModelPresetId,
        identity_id: IdentityId,
        name: EntityName,
        model_id: ModelId,
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
            name,
            model_id,
            created_at,
            updated_at,
            version,
        })
    }

    pub fn rename(&self, name: EntityName, updated_at: UnixMillis) -> Result<Self, DomainError> {
        if updated_at < self.updated_at {
            return Err(DomainError::TimestampOrder);
        }
        Ok(Self {
            name,
            updated_at,
            version: self.version.next()?,
            ..self.clone()
        })
    }

    /// 同时更新 M2.7 允许编辑的非敏感字段，并保持归属与创建时间不变。
    pub fn update_metadata(
        &self,
        name: EntityName,
        model_id: ModelId,
        updated_at: UnixMillis,
    ) -> Result<Self, DomainError> {
        Self::validate_managed_metadata(&name, &model_id)?;
        if updated_at < self.updated_at {
            return Err(DomainError::TimestampOrder);
        }
        Ok(Self {
            name,
            model_id,
            updated_at,
            version: self.version.next()?,
            ..self.clone()
        })
    }

    #[must_use]
    pub const fn id(&self) -> &ModelPresetId {
        &self.id
    }

    #[must_use]
    pub const fn identity_id(&self) -> &IdentityId {
        &self.identity_id
    }

    #[must_use]
    pub const fn name(&self) -> &EntityName {
        &self.name
    }

    #[must_use]
    pub const fn model_id(&self) -> &ModelId {
        &self.model_id
    }

    #[must_use]
    pub const fn created_at(&self) -> UnixMillis {
        self.created_at
    }

    #[must_use]
    pub const fn updated_at(&self) -> UnixMillis {
        self.updated_at
    }

    #[must_use]
    pub const fn version(&self) -> EntityVersion {
        self.version
    }
}
