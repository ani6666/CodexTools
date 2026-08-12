use std::fmt;

use crate::{
    CredentialFingerprint, CredentialRefId, DomainError, EntityVersion, SchemaFingerprint,
    UnixMillis,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialKind {
    ApiKey,
    OAuthBundle,
}

impl CredentialKind {
    #[must_use]
    pub const fn as_storage_str(self) -> &'static str {
        match self {
            Self::ApiKey => "api_key",
            Self::OAuthBundle => "oauth_bundle",
        }
    }

    pub fn from_storage(value: &str) -> Result<Self, DomainError> {
        match value {
            "api_key" => Ok(Self::ApiKey),
            "oauth_bundle" => Ok(Self::OAuthBundle),
            _ => Err(DomainError::InvalidFormat),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthMode {
    ApiKey,
    OAuth,
}

impl AuthMode {
    #[must_use]
    pub const fn as_storage_str(self) -> &'static str {
        match self {
            Self::ApiKey => "api_key",
            Self::OAuth => "oauth",
        }
    }

    pub fn from_storage(value: &str) -> Result<Self, DomainError> {
        match value {
            "api_key" => Ok(Self::ApiKey),
            "oauth" => Ok(Self::OAuth),
            _ => Err(DomainError::InvalidFormat),
        }
    }
}

impl From<CredentialKind> for AuthMode {
    fn from(value: CredentialKind) -> Self {
        match value {
            CredentialKind::ApiKey => Self::ApiKey,
            CredentialKind::OAuthBundle => Self::OAuth,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialBackend {
    WindowsDpapiCurrentUser,
}

impl CredentialBackend {
    #[must_use]
    pub const fn as_storage_str(self) -> &'static str {
        "windows_dpapi_current_user"
    }

    pub fn from_storage(value: &str) -> Result<Self, DomainError> {
        match value {
            "windows_dpapi_current_user" => Ok(Self::WindowsDpapiCurrentUser),
            _ => Err(DomainError::InvalidFormat),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialLink {
    id: CredentialRefId,
    kind: CredentialKind,
}

impl CredentialLink {
    #[must_use]
    pub const fn new(id: CredentialRefId, kind: CredentialKind) -> Self {
        Self { id, kind }
    }

    #[must_use]
    pub const fn id(&self) -> &CredentialRefId {
        &self.id
    }

    #[must_use]
    pub const fn kind(&self) -> CredentialKind {
        self.kind
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CredentialReference {
    id: CredentialRefId,
    kind: CredentialKind,
    backend: CredentialBackend,
    schema_fingerprint: SchemaFingerprint,
    credential_fingerprint: CredentialFingerprint,
    created_at: UnixMillis,
    updated_at: UnixMillis,
    version: EntityVersion,
}

impl CredentialReference {
    #[must_use]
    pub fn new(
        id: CredentialRefId,
        kind: CredentialKind,
        backend: CredentialBackend,
        schema_fingerprint: SchemaFingerprint,
        credential_fingerprint: CredentialFingerprint,
        created_at: UnixMillis,
    ) -> Self {
        Self {
            id,
            kind,
            backend,
            schema_fingerprint,
            credential_fingerprint,
            created_at,
            updated_at: created_at,
            version: EntityVersion::initial(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        id: CredentialRefId,
        kind: CredentialKind,
        backend: CredentialBackend,
        schema_fingerprint: SchemaFingerprint,
        credential_fingerprint: CredentialFingerprint,
        created_at: UnixMillis,
        updated_at: UnixMillis,
        version: EntityVersion,
    ) -> Result<Self, DomainError> {
        if updated_at < created_at {
            return Err(DomainError::TimestampOrder);
        }
        Ok(Self {
            id,
            kind,
            backend,
            schema_fingerprint,
            credential_fingerprint,
            created_at,
            updated_at,
            version,
        })
    }

    /// 轮换底层秘密后，只更新非秘密结构/内容指纹；引用 ID、类型与后端保持不变。
    pub fn rotate(
        &self,
        schema_fingerprint: SchemaFingerprint,
        credential_fingerprint: CredentialFingerprint,
        updated_at: UnixMillis,
    ) -> Result<Self, DomainError> {
        if updated_at < self.updated_at {
            return Err(DomainError::TimestampOrder);
        }
        Ok(Self {
            schema_fingerprint,
            credential_fingerprint,
            updated_at,
            version: self.version.next()?,
            ..self.clone()
        })
    }

    #[must_use]
    pub fn link(&self) -> CredentialLink {
        CredentialLink::new(self.id.clone(), self.kind)
    }

    #[must_use]
    pub const fn id(&self) -> &CredentialRefId {
        &self.id
    }

    #[must_use]
    pub const fn kind(&self) -> CredentialKind {
        self.kind
    }

    #[must_use]
    pub const fn backend(&self) -> CredentialBackend {
        self.backend
    }

    #[must_use]
    pub const fn schema_fingerprint(&self) -> &SchemaFingerprint {
        &self.schema_fingerprint
    }

    #[must_use]
    pub const fn credential_fingerprint(&self) -> &CredentialFingerprint {
        &self.credential_fingerprint
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

impl fmt::Debug for CredentialReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialReference")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("backend", &self.backend)
            .field("schema_fingerprint", &"[REDACTED]")
            .field("credential_fingerprint", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("version", &self.version)
            .finish()
    }
}

impl fmt::Display for CredentialReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "credential reference {} ({:?})",
            self.id.as_str(),
            self.kind
        )
    }
}
