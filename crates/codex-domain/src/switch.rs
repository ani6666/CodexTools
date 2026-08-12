use crate::{
    ContentHash, CredentialFingerprint, DomainError, EntityVersion, ModelId, ProviderId,
    SwitchTransactionId, UnixMillis,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileRole {
    Config,
    Authentication,
}

impl FileRole {
    #[must_use]
    pub const fn bit(self) -> u8 {
        match self {
            Self::Config => 1,
            Self::Authentication => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SwitchTransactionState {
    Planned,
    LockAcquired,
    SnapshotCreated,
    TargetsStaged,
    Replacing,
    TargetsReplaced,
    Verified,
    Committed,
    RollingBack,
    RolledBack,
    RecoveryRequired,
}

impl SwitchTransactionState {
    #[must_use]
    pub const fn as_storage_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::LockAcquired => "lock_acquired",
            Self::SnapshotCreated => "snapshot_created",
            Self::TargetsStaged => "targets_staged",
            Self::Replacing => "replacing",
            Self::TargetsReplaced => "targets_replaced",
            Self::Verified => "verified",
            Self::Committed => "committed",
            Self::RollingBack => "rolling_back",
            Self::RolledBack => "rolled_back",
            Self::RecoveryRequired => "recovery_required",
        }
    }

    pub fn parse_storage(value: &str) -> Result<Self, DomainError> {
        match value {
            "planned" => Ok(Self::Planned),
            "lock_acquired" => Ok(Self::LockAcquired),
            "snapshot_created" => Ok(Self::SnapshotCreated),
            "targets_staged" => Ok(Self::TargetsStaged),
            "replacing" => Ok(Self::Replacing),
            "targets_replaced" => Ok(Self::TargetsReplaced),
            "verified" => Ok(Self::Verified),
            "committed" => Ok(Self::Committed),
            "rolling_back" => Ok(Self::RollingBack),
            "rolled_back" => Ok(Self::RolledBack),
            "recovery_required" => Ok(Self::RecoveryRequired),
            _ => Err(DomainError::InvalidFormat),
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Committed | Self::RolledBack | Self::RecoveryRequired
        )
    }

    #[must_use]
    pub const fn accepts_completed_roles(self, completed_roles: u8) -> bool {
        if completed_roles > 3 {
            return false;
        }
        match self {
            Self::Planned | Self::LockAcquired | Self::SnapshotCreated | Self::TargetsStaged => {
                completed_roles == 0
            }
            Self::TargetsReplaced | Self::Verified | Self::Committed => completed_roles == 3,
            Self::Replacing | Self::RollingBack | Self::RolledBack | Self::RecoveryRequired => true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SwitchTransaction {
    id: SwitchTransactionId,
    root_ref: ContentHash,
    config_source: Option<ContentHash>,
    auth_source: Option<ContentHash>,
    config_target: ContentHash,
    auth_target: ContentHash,
    target_provider_id: ProviderId,
    target_model_id: ModelId,
    target_auth_fingerprint: CredentialFingerprint,
    state: SwitchTransactionState,
    completed_roles: u8,
    created_at: UnixMillis,
    updated_at: UnixMillis,
    version: EntityVersion,
}

impl SwitchTransaction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: SwitchTransactionId,
        root_ref: ContentHash,
        config_source: Option<ContentHash>,
        auth_source: Option<ContentHash>,
        config_target: ContentHash,
        auth_target: ContentHash,
        target_provider_id: ProviderId,
        target_model_id: ModelId,
        target_auth_fingerprint: CredentialFingerprint,
        now: UnixMillis,
    ) -> Self {
        Self {
            id,
            root_ref,
            config_source,
            auth_source,
            config_target,
            auth_target,
            target_provider_id,
            target_model_id,
            target_auth_fingerprint,
            state: SwitchTransactionState::Planned,
            completed_roles: 0,
            created_at: now,
            updated_at: now,
            version: EntityVersion::initial(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        id: SwitchTransactionId,
        root_ref: ContentHash,
        config_source: Option<ContentHash>,
        auth_source: Option<ContentHash>,
        config_target: ContentHash,
        auth_target: ContentHash,
        target_provider_id: ProviderId,
        target_model_id: ModelId,
        target_auth_fingerprint: CredentialFingerprint,
        state: SwitchTransactionState,
        completed_roles: u8,
        created_at: UnixMillis,
        updated_at: UnixMillis,
        version: EntityVersion,
    ) -> Result<Self, DomainError> {
        if updated_at < created_at || !state.accepts_completed_roles(completed_roles) {
            return Err(DomainError::TransactionStateMismatch);
        }
        Ok(Self {
            id,
            root_ref,
            config_source,
            auth_source,
            config_target,
            auth_target,
            target_provider_id,
            target_model_id,
            target_auth_fingerprint,
            state,
            completed_roles,
            created_at,
            updated_at,
            version,
        })
    }

    pub fn transition(
        &self,
        next: SwitchTransactionState,
        now: UnixMillis,
    ) -> Result<Self, DomainError> {
        let allowed = matches!(
            (self.state, next),
            (
                SwitchTransactionState::Planned,
                SwitchTransactionState::LockAcquired
            ) | (
                SwitchTransactionState::Planned,
                SwitchTransactionState::RolledBack
            ) | (
                SwitchTransactionState::LockAcquired,
                SwitchTransactionState::SnapshotCreated
            ) | (
                SwitchTransactionState::LockAcquired,
                SwitchTransactionState::RolledBack
            ) | (
                SwitchTransactionState::SnapshotCreated,
                SwitchTransactionState::TargetsStaged
            ) | (
                SwitchTransactionState::TargetsStaged,
                SwitchTransactionState::Replacing
            ) | (
                SwitchTransactionState::Replacing,
                SwitchTransactionState::TargetsReplaced
            ) | (
                SwitchTransactionState::TargetsReplaced,
                SwitchTransactionState::Verified
            ) | (
                SwitchTransactionState::Verified,
                SwitchTransactionState::Committed
            ) | (
                SwitchTransactionState::SnapshotCreated
                    | SwitchTransactionState::TargetsStaged
                    | SwitchTransactionState::Replacing
                    | SwitchTransactionState::TargetsReplaced
                    | SwitchTransactionState::Verified,
                SwitchTransactionState::RollingBack,
            ) | (
                SwitchTransactionState::RollingBack,
                SwitchTransactionState::RolledBack
            ) | (_, SwitchTransactionState::RecoveryRequired)
        ) && !self.state.is_terminal();
        if !allowed || now < self.updated_at || !next.accepts_completed_roles(self.completed_roles)
        {
            return Err(DomainError::TransactionStateMismatch);
        }
        let mut updated = self.clone();
        updated.state = next;
        updated.updated_at = now;
        updated.version = self.version.next()?;
        Ok(updated)
    }

    /// 快照创建后的状态或任何已替换角色都必须绑定快照 manifest。
    #[must_use]
    pub const fn requires_snapshot_manifest(&self) -> bool {
        self.completed_roles > 0
            || matches!(
                self.state,
                SwitchTransactionState::SnapshotCreated
                    | SwitchTransactionState::TargetsStaged
                    | SwitchTransactionState::Replacing
                    | SwitchTransactionState::TargetsReplaced
                    | SwitchTransactionState::Verified
                    | SwitchTransactionState::Committed
            )
    }

    /// 尚未创建快照的早期状态不得携带 manifest 引用。
    #[must_use]
    pub const fn forbids_snapshot_manifest(&self) -> bool {
        matches!(
            self.state,
            SwitchTransactionState::Planned | SwitchTransactionState::LockAcquired
        )
    }

    pub fn mark_replaced(&self, role: FileRole, now: UnixMillis) -> Result<Self, DomainError> {
        if self.state != SwitchTransactionState::Replacing
            || now < self.updated_at
            || self.completed_roles & role.bit() != 0
        {
            return Err(DomainError::TransactionStateMismatch);
        }
        let mut updated = self.clone();
        updated.completed_roles |= role.bit();
        updated.updated_at = now;
        updated.version = self.version.next()?;
        Ok(updated)
    }

    pub const fn id(&self) -> &SwitchTransactionId {
        &self.id
    }
    pub const fn root_ref(&self) -> &ContentHash {
        &self.root_ref
    }
    pub const fn config_source(&self) -> Option<&ContentHash> {
        self.config_source.as_ref()
    }
    pub const fn auth_source(&self) -> Option<&ContentHash> {
        self.auth_source.as_ref()
    }
    pub const fn config_target(&self) -> &ContentHash {
        &self.config_target
    }
    pub const fn auth_target(&self) -> &ContentHash {
        &self.auth_target
    }
    pub const fn target_provider_id(&self) -> &ProviderId {
        &self.target_provider_id
    }
    pub const fn target_model_id(&self) -> &ModelId {
        &self.target_model_id
    }
    pub const fn target_auth_fingerprint(&self) -> &CredentialFingerprint {
        &self.target_auth_fingerprint
    }
    pub const fn state(&self) -> SwitchTransactionState {
        self.state
    }
    pub const fn completed_roles(&self) -> u8 {
        self.completed_roles
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
