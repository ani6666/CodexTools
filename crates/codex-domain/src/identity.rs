use crate::{
    AuthMode, CredentialLink, DomainError, EndpointUrl, EntityName, EntityVersion, IdentityId,
    ModelPreset, ModelPresetId, ProviderId, UnixMillis,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityStatus {
    Draft,
    Ready,
    Disabled,
}

impl IdentityStatus {
    #[must_use]
    pub const fn as_storage_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Ready => "ready",
            Self::Disabled => "disabled",
        }
    }

    pub fn from_storage(value: &str) -> Result<Self, DomainError> {
        match value {
            "draft" => Ok(Self::Draft),
            "ready" => Ok(Self::Ready),
            "disabled" => Ok(Self::Disabled),
            _ => Err(DomainError::InvalidFormat),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeIdentity {
    id: IdentityId,
    name: EntityName,
    provider_id: ProviderId,
    provider_display_name: EntityName,
    api_base_url: EndpointUrl,
    management_url: Option<EndpointUrl>,
    auth_mode: AuthMode,
    credential: CredentialLink,
    default_model_preset_id: Option<ModelPresetId>,
    status: IdentityStatus,
    created_at: UnixMillis,
    updated_at: UnixMillis,
    version: EntityVersion,
}

impl RuntimeIdentity {
    #[allow(clippy::too_many_arguments)]
    pub fn new_draft(
        id: IdentityId,
        name: EntityName,
        provider_id: ProviderId,
        provider_display_name: EntityName,
        api_base_url: EndpointUrl,
        management_url: Option<EndpointUrl>,
        credential: CredentialLink,
        created_at: UnixMillis,
    ) -> Result<Self, DomainError> {
        let auth_mode = credential.kind().into();
        Self::restore(
            id,
            name,
            provider_id,
            provider_display_name,
            api_base_url,
            management_url,
            auth_mode,
            credential,
            None,
            IdentityStatus::Draft,
            created_at,
            created_at,
            EntityVersion::initial(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        id: IdentityId,
        name: EntityName,
        provider_id: ProviderId,
        provider_display_name: EntityName,
        api_base_url: EndpointUrl,
        management_url: Option<EndpointUrl>,
        auth_mode: AuthMode,
        credential: CredentialLink,
        default_model_preset_id: Option<ModelPresetId>,
        status: IdentityStatus,
        created_at: UnixMillis,
        updated_at: UnixMillis,
        version: EntityVersion,
    ) -> Result<Self, DomainError> {
        if auth_mode != AuthMode::from(credential.kind()) {
            return Err(DomainError::CredentialKindMismatch);
        }
        if updated_at < created_at {
            return Err(DomainError::TimestampOrder);
        }
        let valid_state = match status {
            IdentityStatus::Draft => default_model_preset_id.is_none(),
            IdentityStatus::Ready | IdentityStatus::Disabled => default_model_preset_id.is_some(),
        };
        if !valid_state {
            return Err(DomainError::IdentityStateMismatch);
        }
        Ok(Self {
            id,
            name,
            provider_id,
            provider_display_name,
            api_base_url,
            management_url,
            auth_mode,
            credential,
            default_model_preset_id,
            status,
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

    pub fn set_default_preset(
        &self,
        preset: &ModelPreset,
        updated_at: UnixMillis,
    ) -> Result<Self, DomainError> {
        if preset.identity_id() != &self.id {
            return Err(DomainError::PresetIdentityMismatch);
        }
        if updated_at < self.updated_at {
            return Err(DomainError::TimestampOrder);
        }
        Ok(Self {
            default_model_preset_id: Some(preset.id().clone()),
            status: IdentityStatus::Ready,
            updated_at,
            version: self.version.next()?,
            ..self.clone()
        })
    }

    pub fn disable(&self, updated_at: UnixMillis) -> Result<Self, DomainError> {
        if self.default_model_preset_id.is_none() {
            return Err(DomainError::IdentityStateMismatch);
        }
        if updated_at < self.updated_at {
            return Err(DomainError::TimestampOrder);
        }
        Ok(Self {
            status: IdentityStatus::Disabled,
            updated_at,
            version: self.version.next()?,
            ..self.clone()
        })
    }

    #[must_use]
    pub const fn id(&self) -> &IdentityId {
        &self.id
    }

    #[must_use]
    pub const fn name(&self) -> &EntityName {
        &self.name
    }

    #[must_use]
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    #[must_use]
    pub const fn provider_display_name(&self) -> &EntityName {
        &self.provider_display_name
    }

    #[must_use]
    pub const fn api_base_url(&self) -> &EndpointUrl {
        &self.api_base_url
    }

    #[must_use]
    pub const fn management_url(&self) -> Option<&EndpointUrl> {
        self.management_url.as_ref()
    }

    #[must_use]
    pub const fn auth_mode(&self) -> AuthMode {
        self.auth_mode
    }

    #[must_use]
    pub const fn credential(&self) -> &CredentialLink {
        &self.credential
    }

    #[must_use]
    pub const fn default_model_preset_id(&self) -> Option<&ModelPresetId> {
        self.default_model_preset_id.as_ref()
    }

    #[must_use]
    pub const fn status(&self) -> IdentityStatus {
        self.status
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
