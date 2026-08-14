use std::{
    fmt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use codex_application::{
    BackupKind, BackupRecord, BackupRecoveryOperation, BackupRecoveryPhase, BackupRecoveryRecord,
    BackupRepository, BackupState, CaptureImportCredentialOrigin, CaptureImportDiagnostic,
    CaptureImportPhase, CaptureImportRecoveryRecord, CaptureImportRecoveryRepository,
    ControlledRoot, ControlledScanId, CredentialRecoveryOperation, CredentialRecoveryPhase,
    CredentialRecoveryRecord, CredentialRecoveryRepository, CredentialReferenceRepository,
    EntityKind, IdentityCandidateQuery, ModelPresetRepository, RepositoryError,
    RuntimeIdentityRepository, SwitchErrorCode, SwitchRecoveryDiagnostic, SwitchTransactionRecord,
    SwitchTransactionRepository,
};
use codex_domain::{
    AuthMode, ContentHash, CredentialBackend, CredentialFingerprint, CredentialKind,
    CredentialLink, CredentialRefId, CredentialReference, EndpointUrl, EntityName, EntityVersion,
    IdentityId, IdentityStatus, ManagedConfigPatchId, ModelId, ModelPreset, ModelPresetId,
    ProviderId, RuntimeIdentity, SchemaFingerprint, SwitchTransaction, SwitchTransactionId,
    SwitchTransactionState, UnixMillis,
};
use rusqlite::{
    Connection, Error as SqlError, ErrorCode, OptionalExtension, Row, TransactionBehavior, params,
};
use windows_platform::FileIdentity128;

use crate::migration::{LATEST_SCHEMA_VERSION, MigrationError, migrate};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenRepositoryError {
    Migration(MigrationError),
    StorageUnavailable,
    CorruptData,
}

impl fmt::Display for OpenRepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Migration(error) => write!(formatter, "{error}"),
            Self::StorageUnavailable => formatter.write_str("repository storage is unavailable"),
            Self::CorruptData => formatter.write_str("repository contains corrupt data"),
        }
    }
}

impl std::error::Error for OpenRepositoryError {}

pub struct SqliteMetadataRepository {
    pub(crate) connection: Connection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SensitiveTempRole {
    Config,
    Authentication,
}

impl SensitiveTempRole {
    pub(crate) const fn as_storage_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Authentication => "auth",
        }
    }
    fn parse(value: &str) -> Result<Self, rusqlite::Error> {
        match value {
            "config" => Ok(Self::Config),
            "auth" => Ok(Self::Authentication),
            _ => Err(rusqlite::Error::InvalidQuery),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SensitiveTempPhase {
    Target,
    Recovery,
}

impl SensitiveTempPhase {
    pub(crate) const fn as_storage_str(self) -> &'static str {
        match self {
            Self::Target => "target",
            Self::Recovery => "recovery",
        }
    }
    fn parse(value: &str) -> Result<Self, rusqlite::Error> {
        match value {
            "target" => Ok(Self::Target),
            "recovery" => Ok(Self::Recovery),
            _ => Err(rusqlite::Error::InvalidQuery),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SensitiveTempLifecycle {
    PrewriteDeleteArmed,
    Owned,
    Published,
    CleanupDeleteArmed,
}

impl SensitiveTempLifecycle {
    const fn as_storage_str(self) -> &'static str {
        match self {
            Self::PrewriteDeleteArmed => "prewrite_delete_armed",
            Self::Owned => "owned",
            Self::Published => "published",
            Self::CleanupDeleteArmed => "cleanup_delete_armed",
        }
    }
    fn parse(value: &str) -> Result<Self, rusqlite::Error> {
        match value {
            "prewrite_delete_armed" => Ok(Self::PrewriteDeleteArmed),
            "owned" => Ok(Self::Owned),
            "published" => Ok(Self::Published),
            "cleanup_delete_armed" => Ok(Self::CleanupDeleteArmed),
            _ => Err(rusqlite::Error::InvalidQuery),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SensitiveDestinationState {
    None,
    ReadonlyClearArmed,
    ReadonlyCleared,
}

impl SensitiveDestinationState {
    const fn as_storage_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ReadonlyClearArmed => "readonly_clear_armed",
            Self::ReadonlyCleared => "readonly_cleared",
        }
    }
    fn parse(value: &str) -> Result<Self, rusqlite::Error> {
        match value {
            "none" => Ok(Self::None),
            "readonly_clear_armed" => Ok(Self::ReadonlyClearArmed),
            "readonly_cleared" => Ok(Self::ReadonlyCleared),
            _ => Err(rusqlite::Error::InvalidQuery),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensitiveDestinationGuard {
    pub state: SensitiveDestinationState,
    pub identity: FileIdentity128,
    pub length: u64,
    pub hash_ref: ContentHash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensitiveTempOwnerRecord {
    pub transaction_id: SwitchTransactionId,
    pub root_ref: ContentHash,
    pub role: SensitiveTempRole,
    pub phase: SensitiveTempPhase,
    pub nonce: [u8; 16],
    pub temp_rel: String,
    pub publish_rel: String,
    pub identity: Option<FileIdentity128>,
    pub expected_length: u64,
    pub expected_hash: ContentHash,
    pub expected_readonly: bool,
    pub lifecycle: SensitiveTempLifecycle,
    pub destination_guard: Option<SensitiveDestinationGuard>,
    pub created_at: UnixMillis,
    pub updated_at: UnixMillis,
    pub version: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensitiveTempAnomaly {
    pub transaction_id: Option<SwitchTransactionId>,
    pub root_ref: ContentHash,
    pub role: SensitiveTempRole,
    pub phase: SensitiveTempPhase,
    pub canonical_rel_path: String,
    pub reason: String,
    pub observed_identity: Option<FileIdentity128>,
    pub observed_length: Option<u64>,
    pub created_at: UnixMillis,
    pub updated_at: UnixMillis,
    pub version: u64,
}

impl fmt::Debug for SqliteMetadataRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqliteMetadataRepository")
            .finish_non_exhaustive()
    }
}

impl SqliteMetadataRepository {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, OpenRepositoryError> {
        let mut connection =
            Connection::open(path).map_err(|_| OpenRepositoryError::StorageUnavailable)?;
        connection
            .execute_batch(
                "PRAGMA journal_mode = DELETE;
                 PRAGMA synchronous = FULL;
                 PRAGMA foreign_keys = ON;
                 PRAGMA busy_timeout = 5000;",
            )
            .map_err(|_| OpenRepositoryError::StorageUnavailable)?;
        let journal_mode: String = connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .map_err(|_| OpenRepositoryError::StorageUnavailable)?;
        let synchronous: i64 = connection
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .map_err(|_| OpenRepositoryError::StorageUnavailable)?;
        let foreign_keys: i64 = connection
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .map_err(|_| OpenRepositoryError::StorageUnavailable)?;
        if !journal_mode.eq_ignore_ascii_case("delete") || synchronous != 2 || foreign_keys != 1 {
            return Err(OpenRepositoryError::StorageUnavailable);
        }
        migrate(&mut connection).map_err(OpenRepositoryError::Migration)?;
        let repository = Self { connection };
        repository.audit_switch_transactions()?;
        repository.audit_capture_import_schema()?;
        Ok(repository)
    }

    pub fn create_sensitive_temp_owner(
        &mut self,
        owner: &SensitiveTempOwnerRecord,
    ) -> Result<(), RepositoryError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| RepositoryError::storage_unavailable())?;
        transaction.execute(
            "INSERT INTO switch_sensitive_temp_owners(
                transaction_id,root_ref,role,phase,nonce,temp_rel,publish_rel,identity_bound,
                volume_serial,file_id,expected_length,expected_sha256,expected_readonly,lifecycle,
                destination_state,destination_volume_serial,destination_file_id,destination_length,
                destination_readonly,destination_hash_ref,created_at_unix_ms,updated_at_unix_ms,version
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,NULL,NULL,NULL,NULL,NULL,?16,?17,?18)",
            params![
                owner.transaction_id.as_str(), owner.root_ref.as_str(), owner.role.as_storage_str(),
                owner.phase.as_storage_str(), owner.nonce.as_slice(), owner.temp_rel, owner.publish_rel,
                i64::from(owner.identity.is_some()), owner.identity.map(|value| value.volume_serial_number.to_be_bytes().to_vec()),
                owner.identity.map(|value| value.file_id.to_vec()), i64::try_from(owner.expected_length).map_err(|_| RepositoryError::corrupt_data())?,
                owner.expected_hash.as_str(), i64::from(owner.expected_readonly), owner.lifecycle.as_storage_str(),
                SensitiveDestinationState::None.as_storage_str(), owner.created_at.value(), owner.updated_at.value(),
                i64::try_from(owner.version).map_err(|_| RepositoryError::corrupt_data())?,
            ],
        ).map_err(|error| map_write_error(error, EntityKind::SwitchTransaction, None))?;
        transaction
            .commit()
            .map_err(|_| RepositoryError::storage_unavailable())
    }

    pub fn bind_sensitive_temp_owner_identity(
        &mut self,
        transaction_id: &SwitchTransactionId,
        phase: SensitiveTempPhase,
        role: SensitiveTempRole,
        identity: FileIdentity128,
        expected_version: u64,
        now: UnixMillis,
    ) -> Result<(), RepositoryError> {
        self.cas_sensitive_owner(
            "UPDATE switch_sensitive_temp_owners SET identity_bound=1,volume_serial=?1,file_id=?2,
                 updated_at_unix_ms=?3,version=version+1
             WHERE transaction_id=?4 AND phase=?5 AND role=?6 AND identity_bound=0
               AND lifecycle='prewrite_delete_armed' AND version=?7",
            params![
                identity.volume_serial_number.to_be_bytes().as_slice(),
                identity.file_id.as_slice(),
                now.value(),
                transaction_id.as_str(),
                phase.as_storage_str(),
                role.as_storage_str(),
                i64::try_from(expected_version).map_err(|_| RepositoryError::corrupt_data())?
            ],
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn transition_sensitive_temp_owner(
        &mut self,
        transaction_id: &SwitchTransactionId,
        phase: SensitiveTempPhase,
        role: SensitiveTempRole,
        from: SensitiveTempLifecycle,
        to: SensitiveTempLifecycle,
        expected_version: u64,
        now: UnixMillis,
    ) -> Result<(), RepositoryError> {
        self.cas_sensitive_owner(
            "UPDATE switch_sensitive_temp_owners SET lifecycle=?1,updated_at_unix_ms=?2,version=version+1
             WHERE transaction_id=?3 AND phase=?4 AND role=?5 AND lifecycle=?6 AND version=?7",
            params![to.as_storage_str(), now.value(), transaction_id.as_str(), phase.as_storage_str(), role.as_storage_str(), from.as_storage_str(), i64::try_from(expected_version).map_err(|_| RepositoryError::corrupt_data())?],
        )
    }

    fn cas_sensitive_owner<P: rusqlite::Params>(
        &mut self,
        sql: &str,
        params: P,
    ) -> Result<(), RepositoryError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| RepositoryError::storage_unavailable())?;
        let changed = transaction
            .execute(sql, params)
            .map_err(|_| RepositoryError::storage_unavailable())?;
        if changed != 1 {
            return Err(RepositoryError::version_conflict(
                EntityKind::SwitchTransaction,
            ));
        }
        transaction
            .commit()
            .map_err(|_| RepositoryError::storage_unavailable())
    }

    pub fn list_sensitive_temp_owners(
        &self,
        root_ref: &ContentHash,
    ) -> Result<Vec<SensitiveTempOwnerRecord>, RepositoryError> {
        let mut statement = self.connection.prepare(
            "SELECT transaction_id,root_ref,role,phase,nonce,temp_rel,publish_rel,identity_bound,
                    volume_serial,file_id,expected_length,expected_sha256,expected_readonly,lifecycle,
                    destination_state,destination_volume_serial,destination_file_id,destination_length,
                    destination_readonly,destination_hash_ref,created_at_unix_ms,updated_at_unix_ms,version
             FROM switch_sensitive_temp_owners WHERE root_ref=?1
             ORDER BY transaction_id,phase,role",
        ).map_err(|_| RepositoryError::storage_unavailable())?;
        let rows = statement
            .query_map([root_ref.as_str()], sensitive_temp_owner_from_row)
            .map_err(|_| RepositoryError::storage_unavailable())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| RepositoryError::corrupt_data())
    }

    pub fn get_sensitive_temp_owner(
        &self,
        transaction_id: &SwitchTransactionId,
        phase: SensitiveTempPhase,
        role: SensitiveTempRole,
    ) -> Result<Option<SensitiveTempOwnerRecord>, RepositoryError> {
        self.connection.query_row(
            "SELECT transaction_id,root_ref,role,phase,nonce,temp_rel,publish_rel,identity_bound,
                    volume_serial,file_id,expected_length,expected_sha256,expected_readonly,lifecycle,
                    destination_state,destination_volume_serial,destination_file_id,destination_length,
                    destination_readonly,destination_hash_ref,created_at_unix_ms,updated_at_unix_ms,version
             FROM switch_sensitive_temp_owners WHERE transaction_id=?1 AND phase=?2 AND role=?3",
            params![transaction_id.as_str(), phase.as_storage_str(), role.as_storage_str()],
            sensitive_temp_owner_from_row,
        ).optional().map_err(|_| RepositoryError::corrupt_data())
    }

    pub fn list_sensitive_temp_anomalies(
        &self,
        root_ref: &ContentHash,
    ) -> Result<Vec<SensitiveTempAnomaly>, RepositoryError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT transaction_id,root_ref,role,phase,canonical_rel_path,reason,
                    observed_volume_serial,observed_file_id,observed_length,
                    created_at_unix_ms,updated_at_unix_ms,version
             FROM switch_sensitive_temp_anomalies WHERE root_ref=?1
             ORDER BY canonical_rel_path",
            )
            .map_err(|_| RepositoryError::storage_unavailable())?;
        let rows = statement
            .query_map([root_ref.as_str()], sensitive_temp_anomaly_from_row)
            .map_err(|_| RepositoryError::storage_unavailable())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| RepositoryError::corrupt_data())
    }

    pub fn upsert_sensitive_temp_anomaly(
        &mut self,
        anomaly: &SensitiveTempAnomaly,
    ) -> Result<(), RepositoryError> {
        let observed_length = anomaly
            .observed_length
            .map(i64::try_from)
            .transpose()
            .map_err(|_| RepositoryError::corrupt_data())?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| RepositoryError::storage_unavailable())?;
        transaction
            .execute(
                "INSERT INTO switch_sensitive_temp_anomalies(
                transaction_id,root_ref,role,phase,canonical_rel_path,reason,
                observed_volume_serial,observed_file_id,observed_length,
                created_at_unix_ms,updated_at_unix_ms,version
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)
             ON CONFLICT(root_ref,canonical_rel_path) DO UPDATE SET
                reason=excluded.reason,
                observed_volume_serial=excluded.observed_volume_serial,
                observed_file_id=excluded.observed_file_id,
                observed_length=excluded.observed_length,
                updated_at_unix_ms=excluded.updated_at_unix_ms,
                version=switch_sensitive_temp_anomalies.version+1",
                params![
                    anomaly
                        .transaction_id
                        .as_ref()
                        .map(SwitchTransactionId::as_str),
                    anomaly.root_ref.as_str(),
                    anomaly.role.as_storage_str(),
                    anomaly.phase.as_storage_str(),
                    anomaly.canonical_rel_path,
                    anomaly.reason,
                    anomaly
                        .observed_identity
                        .map(|identity| identity.volume_serial_number.to_be_bytes().to_vec()),
                    anomaly
                        .observed_identity
                        .map(|identity| identity.file_id.to_vec()),
                    observed_length,
                    anomaly.created_at.value(),
                    anomaly.updated_at.value(),
                    i64::try_from(anomaly.version).map_err(|_| RepositoryError::corrupt_data())?,
                ],
            )
            .map_err(|_| RepositoryError::storage_unavailable())?;
        transaction
            .commit()
            .map_err(|_| RepositoryError::storage_unavailable())
    }

    pub fn delete_sensitive_temp_anomaly(
        &mut self,
        anomaly: &SensitiveTempAnomaly,
    ) -> Result<(), RepositoryError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| RepositoryError::storage_unavailable())?;
        let changed = transaction
            .execute(
                "DELETE FROM switch_sensitive_temp_anomalies
             WHERE root_ref=?1 AND canonical_rel_path=?2 AND version=?3",
                params![
                    anomaly.root_ref.as_str(),
                    anomaly.canonical_rel_path,
                    i64::try_from(anomaly.version).map_err(|_| RepositoryError::corrupt_data())?
                ],
            )
            .map_err(|_| RepositoryError::storage_unavailable())?;
        if changed != 1 {
            return Err(RepositoryError::version_conflict(
                EntityKind::SwitchTransaction,
            ));
        }
        transaction
            .commit()
            .map_err(|_| RepositoryError::storage_unavailable())
    }

    pub fn delete_sensitive_temp_owner(
        &mut self,
        owner: &SensitiveTempOwnerRecord,
    ) -> Result<(), RepositoryError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| RepositoryError::storage_unavailable())?;
        let changed = transaction
            .execute(
                "DELETE FROM switch_sensitive_temp_owners
             WHERE transaction_id=?1 AND phase=?2 AND role=?3 AND version=?4",
                params![
                    owner.transaction_id.as_str(),
                    owner.phase.as_storage_str(),
                    owner.role.as_storage_str(),
                    i64::try_from(owner.version).map_err(|_| RepositoryError::corrupt_data())?
                ],
            )
            .map_err(|_| RepositoryError::storage_unavailable())?;
        if changed != 1 {
            return Err(RepositoryError::version_conflict(
                EntityKind::SwitchTransaction,
            ));
        }
        transaction
            .commit()
            .map_err(|_| RepositoryError::storage_unavailable())
    }

    pub fn arm_destination_readonly_guard(
        &mut self,
        owner: &SensitiveTempOwnerRecord,
        destination: &SensitiveDestinationGuard,
        now: UnixMillis,
    ) -> Result<(), RepositoryError> {
        self.cas_sensitive_owner(
            "UPDATE switch_sensitive_temp_owners SET destination_state='readonly_clear_armed',
                destination_volume_serial=?1,destination_file_id=?2,destination_length=?3,
                destination_readonly=1,destination_hash_ref=?4,updated_at_unix_ms=?5,version=version+1
             WHERE transaction_id=?6 AND phase=?7 AND role=?8 AND lifecycle='owned'
               AND destination_state='none' AND version=?9",
            params![destination.identity.volume_serial_number.to_be_bytes().as_slice(), destination.identity.file_id.as_slice(), i64::try_from(destination.length).map_err(|_| RepositoryError::corrupt_data())?, destination.hash_ref.as_str(), now.value(), owner.transaction_id.as_str(), owner.phase.as_storage_str(), owner.role.as_storage_str(), i64::try_from(owner.version).map_err(|_| RepositoryError::corrupt_data())?],
        )
    }

    pub fn transition_destination_guard(
        &mut self,
        owner: &SensitiveTempOwnerRecord,
        from: SensitiveDestinationState,
        to: SensitiveDestinationState,
        now: UnixMillis,
    ) -> Result<(), RepositoryError> {
        let clear = to == SensitiveDestinationState::None;
        if clear {
            self.cas_sensitive_owner(
                "UPDATE switch_sensitive_temp_owners SET destination_state='none',destination_volume_serial=NULL,
                destination_file_id=NULL,destination_length=NULL,destination_readonly=NULL,
                destination_hash_ref=NULL,updated_at_unix_ms=?1,version=version+1
             WHERE transaction_id=?2 AND phase=?3 AND role=?4 AND destination_state=?5 AND version=?6",
                params![now.value(), owner.transaction_id.as_str(), owner.phase.as_storage_str(), owner.role.as_storage_str(), from.as_storage_str(), i64::try_from(owner.version).map_err(|_| RepositoryError::corrupt_data())?],
            )
        } else {
            self.cas_sensitive_owner(
                "UPDATE switch_sensitive_temp_owners SET destination_state=?7,updated_at_unix_ms=?1,version=version+1
             WHERE transaction_id=?2 AND phase=?3 AND role=?4 AND destination_state=?5 AND version=?6",
                params![now.value(), owner.transaction_id.as_str(), owner.phase.as_storage_str(), owner.role.as_storage_str(), from.as_storage_str(), i64::try_from(owner.version).map_err(|_| RepositoryError::corrupt_data())?, to.as_storage_str()],
            )
        }
    }

    pub fn mark_sensitive_owner_published_and_role(
        &mut self,
        owner: &SensitiveTempOwnerRecord,
        candidate: &SwitchTransactionRecord,
        expected_transaction_version: EntityVersion,
    ) -> Result<(), RepositoryError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| RepositoryError::storage_unavailable())?;
        let changed_owner = transaction.execute(
            "UPDATE switch_sensitive_temp_owners SET lifecycle='published',updated_at_unix_ms=?1,version=version+1
             WHERE transaction_id=?2 AND phase=?3 AND role=?4 AND lifecycle='owned'
               AND destination_state='none' AND version=?5",
            params![candidate.transaction.updated_at().value(), owner.transaction_id.as_str(), owner.phase.as_storage_str(), owner.role.as_storage_str(), i64::try_from(owner.version).map_err(|_| RepositoryError::corrupt_data())?],
        ).map_err(|_| RepositoryError::storage_unavailable())?;
        if changed_owner != 1 {
            return Err(RepositoryError::version_conflict(
                EntityKind::SwitchTransaction,
            ));
        }
        let value = &candidate.transaction;
        let changed_tx = transaction.execute(
            "UPDATE switch_transactions SET snapshot_manifest_sha256=?1,state=?2,completed_roles=?3,
                last_error_code=?4,updated_at_unix_ms=?5,version=?6 WHERE id=?7 AND version=?8",
            params![candidate.snapshot_manifest_hash.as_ref().map(ContentHash::as_str), value.state().as_storage_str(), i64::from(value.completed_roles()), candidate.last_error.map(SwitchErrorCode::as_storage_str), value.updated_at().value(), version_to_i64(value.version()), value.id().as_str(), version_to_i64(expected_transaction_version)],
        ).map_err(|_| RepositoryError::storage_unavailable())?;
        if changed_tx != 1 {
            return Err(RepositoryError::version_conflict(
                EntityKind::SwitchTransaction,
            ));
        }
        transaction
            .commit()
            .map_err(|_| RepositoryError::storage_unavailable())
    }

    pub fn finalize_rolled_back_with_recovery_owners(
        &mut self,
        candidate: &SwitchTransactionRecord,
        expected_transaction_version: EntityVersion,
    ) -> Result<(), RepositoryError> {
        if candidate.transaction.state() != SwitchTransactionState::RolledBack {
            return Err(RepositoryError::corrupt_data());
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| RepositoryError::storage_unavailable())?;
        let owner_shape: (i64, i64, i64, i64) = transaction
            .query_row(
                "SELECT COUNT(*),
                    SUM(CASE WHEN phase='recovery' AND lifecycle='published' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN role='config' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN role='auth' THEN 1 ELSE 0 END)
             FROM switch_sensitive_temp_owners WHERE transaction_id=?1",
                [candidate.transaction.id().as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(|_| RepositoryError::corrupt_data())?;
        if owner_shape != (2, 2, 1, 1) {
            return Err(RepositoryError::corrupt_data());
        }
        let removed = transaction
            .execute(
                "DELETE FROM switch_sensitive_temp_owners
             WHERE transaction_id=?1 AND phase='recovery' AND lifecycle='published'",
                [candidate.transaction.id().as_str()],
            )
            .map_err(|_| RepositoryError::storage_unavailable())?;
        if removed != 2 {
            return Err(RepositoryError::corrupt_data());
        }
        let value = &candidate.transaction;
        let changed = transaction.execute(
            "UPDATE switch_transactions SET snapshot_manifest_sha256=?1,state=?2,completed_roles=?3,
                last_error_code=?4,updated_at_unix_ms=?5,version=?6 WHERE id=?7 AND version=?8",
            params![candidate.snapshot_manifest_hash.as_ref().map(ContentHash::as_str), value.state().as_storage_str(), i64::from(value.completed_roles()), candidate.last_error.map(SwitchErrorCode::as_storage_str), value.updated_at().value(), version_to_i64(value.version()), value.id().as_str(), version_to_i64(expected_transaction_version)],
        ).map_err(|_| RepositoryError::storage_unavailable())?;
        if changed != 1 {
            return Err(RepositoryError::version_conflict(
                EntityKind::SwitchTransaction,
            ));
        }
        transaction
            .commit()
            .map_err(|_| RepositoryError::storage_unavailable())
    }

    pub fn schema_version(&self) -> Result<u32, RepositoryError> {
        self.connection
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .map_err(map_read_error)
    }

    pub fn foreign_keys_enabled(&self) -> Result<bool, RepositoryError> {
        self.connection
            .query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))
            .map(|value| value == 1)
            .map_err(map_read_error)
    }

    pub fn durable_journal_mode(&self) -> Result<String, RepositoryError> {
        self.connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .map_err(map_read_error)
    }

    pub fn durable_synchronous_level(&self) -> Result<i64, RepositoryError> {
        self.connection
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .map_err(map_read_error)
    }

    fn audit_switch_transactions(&self) -> Result<(), OpenRepositoryError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT id,root_ref,config_source_sha256,auth_source_sha256,config_target_sha256,auth_target_sha256,target_provider_id,target_model_id,target_auth_fingerprint,snapshot_manifest_sha256,state,completed_roles,last_error_code,created_at_unix_ms,updated_at_unix_ms,version FROM switch_transactions ORDER BY id",
            )
            .map_err(|_| OpenRepositoryError::CorruptData)?;
        let rows = statement
            .query_map([], switch_record_from_row)
            .map_err(|_| OpenRepositoryError::CorruptData)?;
        for row in rows {
            row.map_err(|_| OpenRepositoryError::CorruptData)?;
        }
        Ok(())
    }

    fn audit_capture_import_schema(&self) -> Result<(), OpenRepositoryError> {
        let version: i64 = self
            .connection
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .map_err(|_| OpenRepositoryError::CorruptData)?;
        if version < 11 {
            return Ok(());
        }
        let expected_schema =
            Connection::open_in_memory().map_err(|_| OpenRepositoryError::CorruptData)?;
        expected_schema
            .execute_batch(crate::migration::MIGRATION_0011_SQL)
            .map_err(|_| OpenRepositoryError::CorruptData)?;
        let actual_table_shape = capture_table_shape(&self.connection)?;
        let expected_table_shape = capture_table_shape(&expected_schema)?;
        let actual_index_shape = capture_index_shape(&self.connection)?;
        let expected_index_shape = capture_index_shape(&expected_schema)?;
        if actual_table_shape != expected_table_shape || actual_index_shape != expected_index_shape
        {
            return Err(OpenRepositoryError::CorruptData);
        }
        let expected_table =
            schema_object_sql(&expected_schema, "table", "capture_import_operations")?;
        let expected_index =
            schema_object_sql(&expected_schema, "index", "idx_capture_import_unfinished")?;
        let table_sql = schema_object_sql(&self.connection, "table", "capture_import_operations")?;
        let index_sql =
            schema_object_sql(&self.connection, "index", "idx_capture_import_unfinished")?;
        if tokenize_sql(&table_sql)? != tokenize_sql(&expected_table)?
            || tokenize_sql(&index_sql)? != tokenize_sql(&expected_index)?
        {
            return Err(OpenRepositoryError::CorruptData);
        }
        let mut statement = self
            .connection
            .prepare(
                "SELECT type,name,tbl_name,sql FROM sqlite_master
                 WHERE (tbl_name='capture_import_operations'
                        OR name='capture_import_operations'
                         OR type IN ('view','trigger'))
                    AND name NOT LIKE 'sqlite_autoindex_%'
                  ORDER BY type,name",
            )
            .map_err(|_| OpenRepositoryError::CorruptData)?;
        let objects = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            })
            .map_err(|_| OpenRepositoryError::CorruptData)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| OpenRepositoryError::CorruptData)?;
        let mut expected_object_count = 0;
        for (kind, name, table, sql) in &objects {
            match kind.as_str() {
                "table" => {
                    if name != "capture_import_operations"
                        || table != "capture_import_operations"
                        || sql.as_deref().is_none_or(|value| {
                            tokenize_sql(value).ok() != tokenize_sql(&expected_table).ok()
                        })
                    {
                        return Err(OpenRepositoryError::CorruptData);
                    }
                    expected_object_count += 1;
                }
                "index" => {
                    if name != "idx_capture_import_unfinished"
                        || table != "capture_import_operations"
                        || sql.as_deref().is_none_or(|value| {
                            tokenize_sql(value).ok() != tokenize_sql(&expected_index).ok()
                        })
                    {
                        return Err(OpenRepositoryError::CorruptData);
                    }
                    expected_object_count += 1;
                }
                "trigger" => {
                    let Some(sql) = sql.as_deref() else {
                        return Err(OpenRepositoryError::CorruptData);
                    };
                    if table == "capture_import_operations" || trigger_mutates_capture_ledger(sql)?
                    {
                        return Err(OpenRepositoryError::CorruptData);
                    }
                }
                "view" => {
                    let Some(sql) = sql.as_deref() else {
                        return Err(OpenRepositoryError::CorruptData);
                    };
                    if sql_references_identifier(sql, "capture_import_operations")? {
                        return Err(OpenRepositoryError::CorruptData);
                    }
                }
                _ => return Err(OpenRepositoryError::CorruptData),
            }
        }
        if expected_object_count != 2 {
            return Err(OpenRepositoryError::CorruptData);
        }
        audit_capture_constraints(&self.connection)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SqlToken {
    Identifier(String),
    StringLiteral(String),
    Atom(String),
    Symbol(char),
}

fn tokenize_sql(value: &str) -> Result<Vec<SqlToken>, OpenRepositoryError> {
    let bytes = value.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            byte if byte.is_ascii_whitespace() => index += 1,
            b'-' if bytes.get(index + 1) == Some(&b'-') => {
                index += 2;
                while index < bytes.len() && !matches!(bytes[index], b'\r' | b'\n') {
                    index += 1;
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                index += 2;
                while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/')
                {
                    index += 1;
                }
                if index + 1 >= bytes.len() {
                    return Err(OpenRepositoryError::CorruptData);
                }
                index += 2;
            }
            b'\'' => {
                let start = index;
                index += 1;
                loop {
                    if index >= bytes.len() {
                        return Err(OpenRepositoryError::CorruptData);
                    }
                    if bytes[index] == b'\'' {
                        if bytes.get(index + 1) == Some(&b'\'') {
                            index += 2;
                        } else {
                            index += 1;
                            break;
                        }
                    } else {
                        index += 1;
                    }
                }
                tokens.push(SqlToken::StringLiteral(value[start..index].to_owned()));
            }
            b'"' | b'`' => {
                let delimiter = bytes[index];
                index += 1;
                let mut identifier = String::new();
                loop {
                    if index >= bytes.len() {
                        return Err(OpenRepositoryError::CorruptData);
                    }
                    if bytes[index] == delimiter {
                        if bytes.get(index + 1) == Some(&delimiter) {
                            identifier.push(char::from(delimiter));
                            index += 2;
                        } else {
                            index += 1;
                            break;
                        }
                    } else {
                        identifier.push(char::from(bytes[index]));
                        index += 1;
                    }
                }
                tokens.push(SqlToken::Identifier(identifier.to_ascii_lowercase()));
            }
            b'[' => {
                index += 1;
                let start = index;
                while index < bytes.len() && bytes[index] != b']' {
                    index += 1;
                }
                if index >= bytes.len() {
                    return Err(OpenRepositoryError::CorruptData);
                }
                tokens.push(SqlToken::Identifier(
                    value[start..index].to_ascii_lowercase(),
                ));
                index += 1;
            }
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start = index;
                index += 1;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'_' | b'$'))
                {
                    index += 1;
                }
                tokens.push(SqlToken::Identifier(
                    value[start..index].to_ascii_lowercase(),
                ));
            }
            byte if byte.is_ascii_digit() => {
                let start = index;
                index += 1;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric()
                        || matches!(bytes[index], b'.' | b'+' | b'-'))
                {
                    index += 1;
                }
                tokens.push(SqlToken::Atom(value[start..index].to_ascii_lowercase()));
            }
            b';' => index += 1,
            other if other.is_ascii() => {
                tokens.push(SqlToken::Symbol(char::from(other)));
                index += 1;
            }
            _ => return Err(OpenRepositoryError::CorruptData),
        }
    }
    Ok(tokens)
}

fn schema_object_sql(
    connection: &Connection,
    kind: &str,
    name: &str,
) -> Result<String, OpenRepositoryError> {
    connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type=?1 AND name=?2",
            params![kind, name],
            |row| row.get(0),
        )
        .map_err(|_| OpenRepositoryError::CorruptData)
}

type TableColumnShape = (i64, String, String, i64, Option<String>, i64, i64);
type IndexShape = (
    String,
    i64,
    String,
    i64,
    Vec<(i64, i64, Option<String>, i64, String, i64)>,
);

fn capture_table_shape(
    connection: &Connection,
) -> Result<(i64, Vec<TableColumnShape>), OpenRepositoryError> {
    let strict = connection
        .query_row(
            "SELECT strict FROM pragma_table_list WHERE schema='main' AND name='capture_import_operations'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| OpenRepositoryError::CorruptData)?;
    let mut statement = connection
        .prepare(
            "SELECT cid,name,type,\"notnull\",dflt_value,pk,hidden
             FROM pragma_table_xinfo('capture_import_operations') ORDER BY cid",
        )
        .map_err(|_| OpenRepositoryError::CorruptData)?;
    let columns = statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        })
        .map_err(|_| OpenRepositoryError::CorruptData)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| OpenRepositoryError::CorruptData)?;
    Ok((strict, columns))
}

fn capture_index_shape(connection: &Connection) -> Result<Vec<IndexShape>, OpenRepositoryError> {
    let mut list = connection
        .prepare(
            "SELECT name, \"unique\", origin, partial
             FROM pragma_index_list('capture_import_operations') ORDER BY name",
        )
        .map_err(|_| OpenRepositoryError::CorruptData)?;
    let indexes = list
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .map_err(|_| OpenRepositoryError::CorruptData)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| OpenRepositoryError::CorruptData)?;
    indexes
        .into_iter()
        .map(|(name, unique, origin, partial)| {
            let mut detail = connection
                .prepare(
                    "SELECT seqno,cid,name,desc,coll,\"key\"
                     FROM pragma_index_xinfo(?1) ORDER BY seqno",
                )
                .map_err(|_| OpenRepositoryError::CorruptData)?;
            let columns = detail
                .query_map([&name], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                })
                .map_err(|_| OpenRepositoryError::CorruptData)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| OpenRepositoryError::CorruptData)?;
            Ok((name, unique, origin, partial, columns))
        })
        .collect()
}

fn sql_references_identifier(sql: &str, expected: &str) -> Result<bool, OpenRepositoryError> {
    Ok(tokenize_sql(sql)?
        .iter()
        .any(|token| matches!(token, SqlToken::Identifier(value) if value == expected)))
}

fn trigger_mutates_capture_ledger(sql: &str) -> Result<bool, OpenRepositoryError> {
    let tokens = tokenize_sql(sql)?;
    for (index, token) in tokens.iter().enumerate() {
        let SqlToken::Identifier(keyword) = token else {
            continue;
        };
        let target_start = match keyword.as_str() {
            "insert" => {
                let mut cursor = index + 1;
                if identifier_equals(tokens.get(cursor), "or") {
                    cursor += 2;
                }
                if !identifier_equals(tokens.get(cursor), "into") {
                    continue;
                }
                cursor + 1
            }
            "replace" => {
                let cursor = index + 1;
                if identifier_equals(tokens.get(cursor), "into") {
                    cursor + 1
                } else {
                    cursor
                }
            }
            "update" => {
                let mut cursor = index + 1;
                if identifier_equals(tokens.get(cursor), "or") {
                    cursor += 2;
                }
                cursor
            }
            "delete" => {
                if !identifier_equals(tokens.get(index + 1), "from") {
                    continue;
                }
                index + 2
            }
            _ => continue,
        };
        if target_identifier(&tokens, target_start)
            .is_some_and(|value| value.eq_ignore_ascii_case("capture_import_operations"))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn identifier_equals(token: Option<&SqlToken>, expected: &str) -> bool {
    matches!(token, Some(SqlToken::Identifier(value)) if value == expected)
}

fn target_identifier(tokens: &[SqlToken], start: usize) -> Option<&str> {
    let SqlToken::Identifier(first) = tokens.get(start)? else {
        return None;
    };
    if matches!(tokens.get(start + 1), Some(SqlToken::Symbol('.'))) {
        let SqlToken::Identifier(second) = tokens.get(start + 2)? else {
            return None;
        };
        Some(second)
    } else {
        Some(first)
    }
}

fn audit_capture_constraints(connection: &Connection) -> Result<(), OpenRepositoryError> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OpenRepositoryError::CorruptData)?
        .as_nanos();
    let operation_id = format!("schema-audit-{}-{nonce:x}", std::process::id());
    let suffix = nonce & 0xffff_ffff_ffff;
    let credential_id = format!("00000001-0000-4000-8000-{suffix:012x}");
    let identity_id = format!("00000002-0000-4000-8000-{suffix:012x}");
    let preset_id = format!("00000003-0000-4000-8000-{suffix:012x}");
    let patch_id = format!("00000004-0000-4000-8000-{suffix:012x}");
    connection
        .execute_batch("SAVEPOINT codextools_capture_schema_audit")
        .map_err(|_| OpenRepositoryError::CorruptData)?;
    let result = (|| {
        connection
            .execute(
                "INSERT INTO capture_import_operations (
                operation_id,root_selector,scan_id,credential_id,identity_id,identity_name,
                preset_id,preset_name,patch_id,auth_mode,auth_schema_fingerprint,
                credential_origin,credential_backend,credential_schema_fingerprint,
                credential_fingerprint,credential_version,credential_created_at_unix_ms,
                credential_updated_at_unix_ms,provider_id,provider_display_name,api_base_url,
                model_id,config_hash,phase,diagnostic_code,created_at_unix_ms,
                updated_at_unix_ms,version
             ) VALUES (
                ?1,'default_codex',?2,?3,?4,'Schema Audit',?5,'Schema Audit',?6,'api_key',?7,
                'created','windows_dpapi_current_user',?7,?7,1,1,1,'provider','Provider',
                'https://HOST/v1','model',?7,'prepared',NULL,1,1,1
             )",
                params![
                    operation_id,
                    "a".repeat(64),
                    credential_id,
                    identity_id,
                    preset_id,
                    patch_id,
                    "b".repeat(64),
                ],
            )
            .map_err(|_| OpenRepositoryError::CorruptData)?;
        for sql in [
            "UPDATE capture_import_operations SET operation_id='' WHERE operation_id=?1",
            "UPDATE capture_import_operations SET root_selector='other' WHERE operation_id=?1",
            "UPDATE capture_import_operations SET scan_id=printf('%063s ', '') WHERE operation_id=?1",
            "UPDATE capture_import_operations SET credential_id='00000000-0000-4000-8000-00000000000z' WHERE operation_id=?1",
            "UPDATE capture_import_operations SET identity_name=' ' WHERE operation_id=?1",
            "UPDATE capture_import_operations SET preset_name=' ' WHERE operation_id=?1",
            "UPDATE capture_import_operations SET auth_mode='other' WHERE operation_id=?1",
            "UPDATE capture_import_operations SET credential_origin='other' WHERE operation_id=?1",
            "UPDATE capture_import_operations SET credential_backend='other' WHERE operation_id=?1",
            "UPDATE capture_import_operations SET credential_version=0 WHERE operation_id=?1",
            "UPDATE capture_import_operations SET credential_created_at_unix_ms=-1 WHERE operation_id=?1",
            "UPDATE capture_import_operations SET credential_updated_at_unix_ms=0 WHERE operation_id=?1",
            "UPDATE capture_import_operations SET provider_id='' WHERE operation_id=?1",
            "UPDATE capture_import_operations SET provider_display_name=' ' WHERE operation_id=?1",
            "UPDATE capture_import_operations SET api_base_url='' WHERE operation_id=?1",
            "UPDATE capture_import_operations SET model_id='' WHERE operation_id=?1",
            "UPDATE capture_import_operations SET phase='other' WHERE operation_id=?1",
            "UPDATE capture_import_operations SET diagnostic_code='other' WHERE operation_id=?1",
            "UPDATE capture_import_operations SET created_at_unix_ms=-1 WHERE operation_id=?1",
            "UPDATE capture_import_operations SET updated_at_unix_ms=0 WHERE operation_id=?1",
            "UPDATE capture_import_operations SET version=0 WHERE operation_id=?1",
        ] {
            if !matches!(
                connection.execute(sql, [&operation_id]),
                Err(SqlError::SqliteFailure(error, _)) if error.code == ErrorCode::ConstraintViolation
            ) {
                return Err(OpenRepositoryError::CorruptData);
            }
        }
        Ok(())
    })();
    let rollback = connection.execute_batch(
        "ROLLBACK TO codextools_capture_schema_audit; RELEASE codextools_capture_schema_audit",
    );
    if rollback.is_err() {
        return Err(OpenRepositoryError::CorruptData);
    }
    result
}

impl CredentialReferenceRepository for SqliteMetadataRepository {
    fn create_credential_reference(
        &mut self,
        reference: &CredentialReference,
    ) -> Result<(), RepositoryError> {
        self.connection
            .execute(
                "INSERT INTO credential_references (
                     id, kind, platform_backend, schema_fingerprint, credential_fingerprint,
                     created_at_unix_ms, updated_at_unix_ms, version
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    reference.id().as_str(),
                    reference.kind().as_storage_str(),
                    reference.backend().as_storage_str(),
                    reference.schema_fingerprint().as_str(),
                    reference.credential_fingerprint().as_str(),
                    reference.created_at().value(),
                    reference.updated_at().value(),
                    version_to_i64(reference.version()),
                ],
            )
            .map_err(|error| map_write_error(error, EntityKind::CredentialReference, None))?;
        Ok(())
    }

    fn get_credential_reference(
        &self,
        id: &CredentialRefId,
    ) -> Result<Option<CredentialReference>, RepositoryError> {
        self.connection
            .query_row(
                "SELECT id, kind, platform_backend, schema_fingerprint, credential_fingerprint,
                        created_at_unix_ms, updated_at_unix_ms, version
                 FROM credential_references WHERE id = ?1",
                [id.as_str()],
                credential_from_row,
            )
            .optional()
            .map_err(map_read_error)
    }

    fn list_credential_references(&self) -> Result<Vec<CredentialReference>, RepositoryError> {
        query_many(
            &self.connection,
            "SELECT id, kind, platform_backend, schema_fingerprint, credential_fingerprint,
                    created_at_unix_ms, updated_at_unix_ms, version
             FROM credential_references ORDER BY created_at_unix_ms, id",
            [],
            credential_from_row,
        )
    }

    fn update_credential_reference(
        &mut self,
        reference: &CredentialReference,
        expected_version: EntityVersion,
    ) -> Result<(), RepositoryError> {
        ensure_next_version(
            reference.version(),
            expected_version,
            EntityKind::CredentialReference,
        )?;
        let result = self.connection.execute(
            "UPDATE credential_references SET
                 schema_fingerprint = ?2, credential_fingerprint = ?3,
                 updated_at_unix_ms = ?4, version = ?5
             WHERE id = ?1 AND kind = ?6 AND platform_backend = ?7
               AND created_at_unix_ms = ?8 AND version = ?9",
            params![
                reference.id().as_str(),
                reference.schema_fingerprint().as_str(),
                reference.credential_fingerprint().as_str(),
                reference.updated_at().value(),
                version_to_i64(reference.version()),
                reference.kind().as_storage_str(),
                reference.backend().as_storage_str(),
                reference.created_at().value(),
                version_to_i64(expected_version),
            ],
        );
        finish_update(
            &self.connection,
            result,
            "credential_references",
            reference.id().as_str(),
            EntityKind::CredentialReference,
            None,
        )
    }

    fn delete_credential_reference(
        &mut self,
        id: &CredentialRefId,
        expected_version: EntityVersion,
    ) -> Result<(), RepositoryError> {
        let result = self.connection.execute(
            "DELETE FROM credential_references WHERE id = ?1 AND version = ?2",
            params![id.as_str(), version_to_i64(expected_version)],
        );
        finish_delete(
            &self.connection,
            result,
            "credential_references",
            id.as_str(),
            EntityKind::CredentialReference,
        )
    }
}

impl RuntimeIdentityRepository for SqliteMetadataRepository {
    fn create_runtime_identity(
        &mut self,
        identity: &RuntimeIdentity,
    ) -> Result<(), RepositoryError> {
        self.connection
            .execute(
                "INSERT INTO runtime_identities (
                     id, name, provider_id, provider_display_name, api_base_url, management_url,
                     auth_mode, credential_ref_id, default_model_preset_id, status,
                     created_at_unix_ms, updated_at_unix_ms, version
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                identity_params(identity),
            )
            .map_err(|error| {
                map_write_error(
                    error,
                    EntityKind::RuntimeIdentity,
                    Some(EntityKind::CredentialReference),
                )
            })?;
        Ok(())
    }

    fn get_runtime_identity(
        &self,
        id: &IdentityId,
    ) -> Result<Option<RuntimeIdentity>, RepositoryError> {
        self.connection
            .query_row(
                &format!("{} WHERE id = ?1", identity_select()),
                [id.as_str()],
                identity_from_row,
            )
            .optional()
            .map_err(map_read_error)
    }

    fn list_runtime_identities(&self) -> Result<Vec<RuntimeIdentity>, RepositoryError> {
        query_many(
            &self.connection,
            &format!("{} ORDER BY created_at_unix_ms, id", identity_select()),
            [],
            identity_from_row,
        )
    }

    fn update_runtime_identity(
        &mut self,
        identity: &RuntimeIdentity,
        expected_version: EntityVersion,
    ) -> Result<(), RepositoryError> {
        ensure_next_version(
            identity.version(),
            expected_version,
            EntityKind::RuntimeIdentity,
        )?;
        let result = self.connection.execute(
            "UPDATE runtime_identities SET
                 name = ?2, provider_id = ?3, provider_display_name = ?4, api_base_url = ?5,
                 management_url = ?6, auth_mode = ?7, credential_ref_id = ?8,
                 default_model_preset_id = ?9, status = ?10, created_at_unix_ms = ?11,
                 updated_at_unix_ms = ?12, version = ?13
             WHERE id = ?1 AND version = ?14",
            rusqlite::params_from_iter(identity_params(identity).into_iter().chain([
                rusqlite::types::Value::Integer(version_to_i64(expected_version)),
            ])),
        );
        finish_update(
            &self.connection,
            result,
            "runtime_identities",
            identity.id().as_str(),
            EntityKind::RuntimeIdentity,
            Some(EntityKind::ModelPreset),
        )
    }

    fn delete_runtime_identity(
        &mut self,
        id: &IdentityId,
        expected_version: EntityVersion,
    ) -> Result<(), RepositoryError> {
        let result = self.connection.execute(
            "DELETE FROM runtime_identities WHERE id = ?1 AND version = ?2",
            params![id.as_str(), version_to_i64(expected_version)],
        );
        finish_delete(
            &self.connection,
            result,
            "runtime_identities",
            id.as_str(),
            EntityKind::RuntimeIdentity,
        )
    }

    fn find_identity_candidates(
        &self,
        query: &IdentityCandidateQuery,
    ) -> Result<Vec<RuntimeIdentity>, RepositoryError> {
        query_many(
            &self.connection,
            &format!(
                "{} JOIN credential_references c ON c.id = runtime_identities.credential_ref_id
                 WHERE runtime_identities.provider_id = ?1
                   AND runtime_identities.api_base_url = ?2
                   AND runtime_identities.auth_mode = ?3
                   AND c.credential_fingerprint = ?4
                 ORDER BY runtime_identities.created_at_unix_ms, runtime_identities.id",
                identity_select()
            ),
            params![
                query.provider_id().as_str(),
                query.api_base_url().as_str(),
                query.auth_mode().as_storage_str(),
                query.credential_fingerprint().as_str(),
            ],
            identity_from_row,
        )
    }
}

impl ModelPresetRepository for SqliteMetadataRepository {
    fn create_model_preset(&mut self, preset: &ModelPreset) -> Result<(), RepositoryError> {
        self.connection
            .execute(
                "INSERT INTO model_presets (
                     id, identity_id, name, model_id, created_at_unix_ms, updated_at_unix_ms, version
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                preset_params(preset),
            )
            .map_err(|error| {
                map_write_error(
                    error,
                    EntityKind::ModelPreset,
                    Some(EntityKind::RuntimeIdentity),
                )
            })?;
        Ok(())
    }

    fn get_model_preset(&self, id: &ModelPresetId) -> Result<Option<ModelPreset>, RepositoryError> {
        self.connection
            .query_row(
                &format!("{} WHERE id = ?1", preset_select()),
                [id.as_str()],
                preset_from_row,
            )
            .optional()
            .map_err(map_read_error)
    }

    fn list_model_presets(
        &self,
        identity_id: &IdentityId,
    ) -> Result<Vec<ModelPreset>, RepositoryError> {
        query_many(
            &self.connection,
            &format!(
                "{} WHERE identity_id = ?1 ORDER BY name, id",
                preset_select()
            ),
            [identity_id.as_str()],
            preset_from_row,
        )
    }

    fn update_model_preset(
        &mut self,
        preset: &ModelPreset,
        expected_version: EntityVersion,
    ) -> Result<(), RepositoryError> {
        ensure_next_version(preset.version(), expected_version, EntityKind::ModelPreset)?;
        let result = self.connection.execute(
            "UPDATE model_presets SET identity_id = ?2, name = ?3, model_id = ?4,
                 created_at_unix_ms = ?5, updated_at_unix_ms = ?6, version = ?7
             WHERE id = ?1 AND version = ?8",
            rusqlite::params_from_iter(preset_params(preset).into_iter().chain([
                rusqlite::types::Value::Integer(version_to_i64(expected_version)),
            ])),
        );
        finish_update(
            &self.connection,
            result,
            "model_presets",
            preset.id().as_str(),
            EntityKind::ModelPreset,
            Some(EntityKind::RuntimeIdentity),
        )
    }

    fn delete_model_preset(
        &mut self,
        id: &ModelPresetId,
        expected_version: EntityVersion,
    ) -> Result<(), RepositoryError> {
        let result = self.connection.execute(
            "DELETE FROM model_presets WHERE id = ?1 AND version = ?2",
            params![id.as_str(), version_to_i64(expected_version)],
        );
        finish_delete(
            &self.connection,
            result,
            "model_presets",
            id.as_str(),
            EntityKind::ModelPreset,
        )
    }
}

fn identity_select() -> &'static str {
    "SELECT runtime_identities.id, runtime_identities.name, runtime_identities.provider_id,
            runtime_identities.provider_display_name, runtime_identities.api_base_url,
            runtime_identities.management_url, runtime_identities.auth_mode,
            runtime_identities.credential_ref_id, runtime_identities.default_model_preset_id,
            runtime_identities.status, runtime_identities.created_at_unix_ms,
            runtime_identities.updated_at_unix_ms, runtime_identities.version
     FROM runtime_identities"
}

fn preset_select() -> &'static str {
    "SELECT id, identity_id, name, model_id, created_at_unix_ms, updated_at_unix_ms, version
     FROM model_presets"
}

fn identity_params(identity: &RuntimeIdentity) -> [rusqlite::types::Value; 13] {
    use rusqlite::types::Value;
    [
        Value::Text(identity.id().as_str().to_owned()),
        Value::Text(identity.name().as_str().to_owned()),
        Value::Text(identity.provider_id().as_str().to_owned()),
        Value::Text(identity.provider_display_name().as_str().to_owned()),
        Value::Text(identity.api_base_url().as_str().to_owned()),
        identity
            .management_url()
            .map_or(Value::Null, |value| Value::Text(value.as_str().to_owned())),
        Value::Text(identity.auth_mode().as_storage_str().to_owned()),
        Value::Text(identity.credential().id().as_str().to_owned()),
        identity
            .default_model_preset_id()
            .map_or(Value::Null, |value| Value::Text(value.as_str().to_owned())),
        Value::Text(identity.status().as_storage_str().to_owned()),
        Value::Integer(identity.created_at().value()),
        Value::Integer(identity.updated_at().value()),
        Value::Integer(version_to_i64(identity.version())),
    ]
}

fn preset_params(preset: &ModelPreset) -> [rusqlite::types::Value; 7] {
    use rusqlite::types::Value;
    [
        Value::Text(preset.id().as_str().to_owned()),
        Value::Text(preset.identity_id().as_str().to_owned()),
        Value::Text(preset.name().as_str().to_owned()),
        Value::Text(preset.model_id().as_str().to_owned()),
        Value::Integer(preset.created_at().value()),
        Value::Integer(preset.updated_at().value()),
        Value::Integer(version_to_i64(preset.version())),
    ]
}

fn credential_from_row(row: &Row<'_>) -> rusqlite::Result<CredentialReference> {
    CredentialReference::restore(
        parse(row, 0, CredentialRefId::parse)?,
        parse(row, 1, CredentialKind::from_storage)?,
        parse(row, 2, CredentialBackend::from_storage)?,
        parse(row, 3, SchemaFingerprint::parse)?,
        parse(row, 4, CredentialFingerprint::parse)?,
        parse_i64(row, 5, UnixMillis::new)?,
        parse_i64(row, 6, UnixMillis::new)?,
        parse_version(row, 7)?,
    )
    .map_err(|error| conversion_error(0, error))
}

fn identity_from_row(row: &Row<'_>) -> rusqlite::Result<RuntimeIdentity> {
    let credential_id = parse(row, 7, CredentialRefId::parse)?;
    let auth_mode = parse(row, 6, AuthMode::from_storage)?;
    let credential_kind = match auth_mode {
        AuthMode::ApiKey => CredentialKind::ApiKey,
        AuthMode::OAuth => CredentialKind::OAuthBundle,
    };
    let management_url = row
        .get::<_, Option<String>>(5)?
        .map(|value| EndpointUrl::parse(&value).map_err(|error| conversion_error(5, error)))
        .transpose()?;
    let default_model = row
        .get::<_, Option<String>>(8)?
        .map(|value| ModelPresetId::parse(&value).map_err(|error| conversion_error(8, error)))
        .transpose()?;
    RuntimeIdentity::restore(
        parse(row, 0, IdentityId::parse)?,
        parse(row, 1, EntityName::parse)?,
        parse(row, 2, ProviderId::parse)?,
        parse(row, 3, EntityName::parse)?,
        parse(row, 4, EndpointUrl::parse)?,
        management_url,
        auth_mode,
        CredentialLink::new(credential_id, credential_kind),
        default_model,
        parse(row, 9, IdentityStatus::from_storage)?,
        parse_i64(row, 10, UnixMillis::new)?,
        parse_i64(row, 11, UnixMillis::new)?,
        parse_version(row, 12)?,
    )
    .map_err(|error| conversion_error(0, error))
}

fn preset_from_row(row: &Row<'_>) -> rusqlite::Result<ModelPreset> {
    ModelPreset::restore(
        parse(row, 0, ModelPresetId::parse)?,
        parse(row, 1, IdentityId::parse)?,
        parse(row, 2, EntityName::parse)?,
        parse(row, 3, ModelId::parse)?,
        parse_i64(row, 4, UnixMillis::new)?,
        parse_i64(row, 5, UnixMillis::new)?,
        parse_version(row, 6)?,
    )
    .map_err(|error| conversion_error(0, error))
}

fn parse<T>(
    row: &Row<'_>,
    index: usize,
    parser: impl FnOnce(&str) -> Result<T, codex_domain::DomainError>,
) -> rusqlite::Result<T> {
    let value: String = row.get(index)?;
    parser(&value).map_err(|error| conversion_error(index, error))
}

fn parse_i64<T>(
    row: &Row<'_>,
    index: usize,
    parser: impl FnOnce(i64) -> Result<T, codex_domain::DomainError>,
) -> rusqlite::Result<T> {
    parser(row.get(index)?).map_err(|error| conversion_error(index, error))
}

fn parse_version(row: &Row<'_>, index: usize) -> rusqlite::Result<EntityVersion> {
    let value: i64 = row.get(index)?;
    let value = u64::try_from(value).map_err(|error| conversion_error(index, error))?;
    EntityVersion::new(value).map_err(|error| conversion_error(index, error))
}

fn conversion_error(
    index: usize,
    error: impl std::error::Error + Send + Sync + 'static,
) -> SqlError {
    SqlError::FromSqlConversionFailure(index, rusqlite::types::Type::Text, Box::new(error))
}

fn query_many<P, F, T>(
    connection: &Connection,
    sql: &str,
    params: P,
    mapper: F,
) -> Result<Vec<T>, RepositoryError>
where
    P: rusqlite::Params,
    F: FnMut(&Row<'_>) -> rusqlite::Result<T>,
{
    let mut statement = connection.prepare(sql).map_err(map_read_error)?;
    let rows = statement
        .query_map(params, mapper)
        .map_err(map_read_error)?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(map_read_error)
}

fn ensure_next_version(
    actual: EntityVersion,
    expected: EntityVersion,
    kind: EntityKind,
) -> Result<(), RepositoryError> {
    if expected.next().ok() == Some(actual) {
        Ok(())
    } else {
        Err(RepositoryError::version_conflict(kind))
    }
}

fn finish_update(
    connection: &Connection,
    result: rusqlite::Result<usize>,
    table: &str,
    id: &str,
    kind: EntityKind,
    reference_kind: Option<EntityKind>,
) -> Result<(), RepositoryError> {
    match result {
        Ok(1) => Ok(()),
        Ok(0) => missing_or_version(connection, table, id, kind),
        Ok(_) => Err(RepositoryError::storage_unavailable()),
        Err(error) => Err(map_write_error(error, kind, reference_kind)),
    }
}

fn finish_delete(
    connection: &Connection,
    result: rusqlite::Result<usize>,
    table: &str,
    id: &str,
    kind: EntityKind,
) -> Result<(), RepositoryError> {
    match result {
        Ok(1) => Ok(()),
        Ok(0) => missing_or_version(connection, table, id, kind),
        Ok(_) => Err(RepositoryError::storage_unavailable()),
        Err(error) => Err(map_write_error(error, kind, Some(kind))),
    }
}

fn missing_or_version(
    connection: &Connection,
    table: &str,
    id: &str,
    kind: EntityKind,
) -> Result<(), RepositoryError> {
    let sql = format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE id = ?1)");
    let exists: bool = connection
        .query_row(&sql, [id], |row| row.get(0))
        .map_err(map_read_error)?;
    if exists {
        Err(RepositoryError::version_conflict(kind))
    } else {
        Err(RepositoryError::not_found(kind))
    }
}

fn map_read_error(error: SqlError) -> RepositoryError {
    match error {
        SqlError::FromSqlConversionFailure(..) | SqlError::InvalidColumnType(..) => {
            RepositoryError::corrupt_data()
        }
        _ => RepositoryError::storage_unavailable(),
    }
}

pub(crate) fn map_write_error(
    error: SqlError,
    kind: EntityKind,
    reference_kind: Option<EntityKind>,
) -> RepositoryError {
    if let SqlError::SqliteFailure(details, _) = error {
        if details.code == ErrorCode::ConstraintViolation {
            return match details.extended_code {
                787 | 1811 => RepositoryError::reference_conflict(reference_kind.unwrap_or(kind)),
                1555 | 2067 => RepositoryError::already_exists(kind),
                _ => RepositoryError::corrupt_data(),
            };
        }
    }
    RepositoryError::storage_unavailable()
}

fn version_to_i64(version: EntityVersion) -> i64 {
    i64::try_from(version.value()).expect("validated entity version fits SQLite INTEGER")
}

impl BackupRepository for SqliteMetadataRepository {
    fn create_backup(&mut self, record: &BackupRecord) -> Result<(), RepositoryError> {
        self.connection.execute(
            "INSERT INTO backup_sets(id,root_ref,kind,sequence,manifest_sha256,material_ref,transaction_id,state,created_at_unix_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                record.id,
                record.root_ref.as_str(),
                match record.kind { BackupKind::Permanent => "permanent", BackupKind::History => "history" },
                i64::try_from(record.sequence).map_err(|_| RepositoryError::corrupt_data())?,
                record.manifest_hash.as_str(),
                record.material_ref.to_string_lossy(),
                record.transaction_id.as_ref().map(SwitchTransactionId::as_str),
                match record.state { BackupState::Ready => "ready", BackupState::Protected => "protected" },
                record.created_at.value(),
            ],
        ).map_err(|error| map_write_error(error, EntityKind::BackupSet, Some(EntityKind::SwitchTransaction)))?;
        Ok(())
    }

    fn get_backup(&self, id: &str) -> Result<Option<BackupRecord>, RepositoryError> {
        self.connection
            .query_row(
                "SELECT id,root_ref,kind,sequence,manifest_sha256,material_ref,transaction_id,state,created_at_unix_ms FROM backup_sets WHERE id=?1",
                [id],
                backup_record_from_row,
            )
            .optional()
            .map_err(|_| RepositoryError::corrupt_data())
    }

    fn list_backups(&self, root_ref: &ContentHash) -> Result<Vec<BackupRecord>, RepositoryError> {
        let mut statement = self.connection.prepare(
            "SELECT id,root_ref,kind,sequence,manifest_sha256,material_ref,transaction_id,state,created_at_unix_ms
             FROM backup_sets WHERE root_ref=?1 ORDER BY kind,sequence,id"
        ).map_err(|_| RepositoryError::storage_unavailable())?;
        let rows = statement
            .query_map([root_ref.as_str()], backup_record_from_row)
            .map_err(|_| RepositoryError::storage_unavailable())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| RepositoryError::corrupt_data())
    }

    fn delete_backup(&mut self, id: &str) -> Result<(), RepositoryError> {
        let changed = self
            .connection
            .execute("DELETE FROM backup_sets WHERE id=?1", [id])
            .map_err(|error| {
                map_write_error(
                    error,
                    EntityKind::BackupSet,
                    Some(EntityKind::SwitchTransaction),
                )
            })?;
        if changed == 0 {
            return Err(RepositoryError::not_found(EntityKind::BackupSet));
        }
        Ok(())
    }

    fn create_backup_recovery(
        &mut self,
        record: &BackupRecoveryRecord,
    ) -> Result<(), RepositoryError> {
        let backup = &record.backup;
        self.connection.execute(
            "INSERT INTO backup_recovery_operations(operation_id,root_ref,operation,phase,backup_id,kind,sequence,manifest_sha256,material_ref,pending_ref,transaction_id,backup_state,backup_created_at_unix_ms,diagnostic_code)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            params![
                record.operation_id,
                backup.root_ref.as_str(),
                backup_recovery_operation_str(record.operation),
                backup_recovery_phase_str(record.phase),
                backup.id,
                match backup.kind { BackupKind::Permanent => "permanent", BackupKind::History => "history" },
                i64::try_from(backup.sequence).map_err(|_| RepositoryError::corrupt_data())?,
                backup.manifest_hash.as_str(),
                backup.material_ref.to_string_lossy(),
                record.pending_ref.as_ref().map(|path| path.to_string_lossy()),
                backup.transaction_id.as_ref().map(SwitchTransactionId::as_str),
                match backup.state { BackupState::Ready => "ready", BackupState::Protected => "protected" },
                backup.created_at.value(),
                record.diagnostic_code,
            ],
        ).map_err(|error| map_write_error(error, EntityKind::BackupSet, Some(EntityKind::SwitchTransaction)))?;
        Ok(())
    }

    fn list_backup_recoveries(
        &self,
        root_ref: &ContentHash,
    ) -> Result<Vec<BackupRecoveryRecord>, RepositoryError> {
        let mut statement = self.connection.prepare(
            "SELECT operation_id,operation,phase,backup_id,root_ref,kind,sequence,manifest_sha256,material_ref,pending_ref,transaction_id,backup_state,backup_created_at_unix_ms,diagnostic_code
             FROM backup_recovery_operations WHERE root_ref=?1 ORDER BY operation_id"
        ).map_err(|_| RepositoryError::storage_unavailable())?;
        let rows = statement
            .query_map([root_ref.as_str()], backup_recovery_from_row)
            .map_err(|_| RepositoryError::storage_unavailable())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| RepositoryError::corrupt_data())
    }

    fn update_backup_recovery(
        &mut self,
        operation_id: &str,
        phase: BackupRecoveryPhase,
        diagnostic_code: Option<&str>,
    ) -> Result<(), RepositoryError> {
        let changed = self.connection.execute(
            "UPDATE backup_recovery_operations SET phase=?2,diagnostic_code=?3 WHERE operation_id=?1",
            params![operation_id, backup_recovery_phase_str(phase), diagnostic_code],
        ).map_err(|_| RepositoryError::storage_unavailable())?;
        if changed == 0 {
            return Err(RepositoryError::not_found(EntityKind::BackupSet));
        }
        Ok(())
    }

    fn delete_backup_recovery(&mut self, operation_id: &str) -> Result<(), RepositoryError> {
        let changed = self
            .connection
            .execute(
                "DELETE FROM backup_recovery_operations WHERE operation_id=?1",
                [operation_id],
            )
            .map_err(|_| RepositoryError::storage_unavailable())?;
        if changed == 0 {
            return Err(RepositoryError::not_found(EntityKind::BackupSet));
        }
        Ok(())
    }
}

fn backup_recovery_operation_str(value: BackupRecoveryOperation) -> &'static str {
    match value {
        BackupRecoveryOperation::Publish => "publish",
        BackupRecoveryOperation::Delete => "delete",
    }
}

fn backup_recovery_phase_str(value: BackupRecoveryPhase) -> &'static str {
    match value {
        BackupRecoveryPhase::Prepared => "prepared",
        BackupRecoveryPhase::Validated => "validated",
        BackupRecoveryPhase::Published => "published",
        BackupRecoveryPhase::Renamed => "renamed",
        BackupRecoveryPhase::MetadataDeleted => "metadata_deleted",
        BackupRecoveryPhase::RecoveryRequired => "recovery_required",
    }
}

fn backup_recovery_from_row(row: &Row<'_>) -> rusqlite::Result<BackupRecoveryRecord> {
    let operation = match row.get::<_, String>(1)?.as_str() {
        "publish" => BackupRecoveryOperation::Publish,
        "delete" => BackupRecoveryOperation::Delete,
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    let phase = match row.get::<_, String>(2)?.as_str() {
        "prepared" => BackupRecoveryPhase::Prepared,
        "validated" => BackupRecoveryPhase::Validated,
        "published" => BackupRecoveryPhase::Published,
        "renamed" => BackupRecoveryPhase::Renamed,
        "metadata_deleted" => BackupRecoveryPhase::MetadataDeleted,
        "recovery_required" => BackupRecoveryPhase::RecoveryRequired,
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    let material_ref = PathBuf::from(row.get::<_, String>(8)?);
    let pending_ref = row.get::<_, Option<String>>(9)?.map(PathBuf::from);
    if !repository_safe_relative(&material_ref)
        || pending_ref
            .as_ref()
            .is_some_and(|path| !repository_safe_relative(path))
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let backup = BackupRecord {
        id: row.get(3)?,
        root_ref: ContentHash::parse(&row.get::<_, String>(4)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        kind: match row.get::<_, String>(5)?.as_str() {
            "permanent" => BackupKind::Permanent,
            "history" => BackupKind::History,
            _ => return Err(rusqlite::Error::InvalidQuery),
        },
        sequence: u64::try_from(row.get::<_, i64>(6)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        manifest_hash: ContentHash::parse(&row.get::<_, String>(7)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        material_ref,
        transaction_id: row
            .get::<_, Option<String>>(10)?
            .map(|value| {
                SwitchTransactionId::parse(&value).map_err(|_| rusqlite::Error::InvalidQuery)
            })
            .transpose()?,
        state: match row.get::<_, String>(11)?.as_str() {
            "ready" => BackupState::Ready,
            "protected" => BackupState::Protected,
            _ => return Err(rusqlite::Error::InvalidQuery),
        },
        created_at: UnixMillis::new(row.get(12)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
    };
    Ok(BackupRecoveryRecord {
        operation_id: row.get(0)?,
        operation,
        phase,
        backup,
        pending_ref,
        diagnostic_code: row.get(13)?,
    })
}

fn repository_safe_relative(path: &Path) -> bool {
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

impl CredentialRecoveryRepository for SqliteMetadataRepository {
    fn create_credential_recovery(
        &mut self,
        record: &CredentialRecoveryRecord,
    ) -> Result<(), RepositoryError> {
        if !repository_safe_relative(&record.material_ref)
            || record.planned_credential_fingerprint.is_none()
            || !credential_recovery_material_state_is_valid(record)
        {
            return Err(RepositoryError::corrupt_data());
        }
        self.connection.execute(
            "INSERT INTO credential_recovery_operations(operation_id,credential_id,kind,operation,generation,material_ref,material_sha256,phase,diagnostic_code,credential_created_at_unix_ms,credential_updated_at_unix_ms,created_at_unix_ms,updated_at_unix_ms,version,planned_credential_fingerprint,legacy_unbound) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,0)",
            params![record.operation_id, record.credential_id.as_str(), credential_kind_str(record.kind), credential_recovery_operation_str(record.operation), version_to_i64(record.generation), record.material_ref.to_string_lossy(), record.material_hash.as_ref().map(ContentHash::as_str), credential_recovery_phase_str(record.phase), record.diagnostic_code, record.credential_created_at.value(), record.credential_updated_at.value(), record.created_at.value(), record.updated_at.value(), version_to_i64(record.version), record.planned_credential_fingerprint.as_ref().map(CredentialFingerprint::as_str)],
        ).map_err(|error| map_write_error(error, EntityKind::CredentialReference, None))?;
        Ok(())
    }

    fn get_credential_recovery(
        &self,
        operation_id: &str,
    ) -> Result<Option<CredentialRecoveryRecord>, RepositoryError> {
        self.connection.query_row(
            "SELECT operation_id,credential_id,kind,operation,generation,material_ref,material_sha256,phase,diagnostic_code,credential_created_at_unix_ms,credential_updated_at_unix_ms,created_at_unix_ms,updated_at_unix_ms,version,planned_credential_fingerprint,legacy_unbound FROM credential_recovery_operations WHERE operation_id=?1",
            [operation_id], credential_recovery_from_row,
        ).optional().map_err(|_| RepositoryError::corrupt_data())
    }

    fn list_credential_recoveries(
        &self,
        id: &CredentialRefId,
    ) -> Result<Vec<CredentialRecoveryRecord>, RepositoryError> {
        let mut statement = self.connection.prepare("SELECT operation_id,credential_id,kind,operation,generation,material_ref,material_sha256,phase,diagnostic_code,credential_created_at_unix_ms,credential_updated_at_unix_ms,created_at_unix_ms,updated_at_unix_ms,version,planned_credential_fingerprint,legacy_unbound FROM credential_recovery_operations WHERE credential_id=?1 ORDER BY generation,operation_id").map_err(|_| RepositoryError::storage_unavailable())?;
        let rows = statement
            .query_map([id.as_str()], credential_recovery_from_row)
            .map_err(|_| RepositoryError::storage_unavailable())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| RepositoryError::corrupt_data())
    }

    fn update_credential_recovery(
        &mut self,
        record: &CredentialRecoveryRecord,
        expected_version: EntityVersion,
    ) -> Result<(), RepositoryError> {
        if !repository_safe_relative(&record.material_ref)
            || !credential_recovery_material_state_is_valid(record)
        {
            return Err(RepositoryError::corrupt_data());
        }
        let changed = self.connection.execute("UPDATE credential_recovery_operations SET material_ref=?2,material_sha256=?3,phase=?4,diagnostic_code=?5,updated_at_unix_ms=?6,version=?7 WHERE operation_id=?1 AND version=?8", params![record.operation_id, record.material_ref.to_string_lossy(), record.material_hash.as_ref().map(ContentHash::as_str), credential_recovery_phase_str(record.phase), record.diagnostic_code, record.updated_at.value(), version_to_i64(record.version), version_to_i64(expected_version)]).map_err(|_| RepositoryError::storage_unavailable())?;
        if changed == 0 {
            return Err(RepositoryError::version_conflict(
                EntityKind::CredentialReference,
            ));
        }
        Ok(())
    }

    fn delete_credential_recovery(
        &mut self,
        operation_id: &str,
        expected_version: EntityVersion,
    ) -> Result<(), RepositoryError> {
        let changed = self
            .connection
            .execute(
                "DELETE FROM credential_recovery_operations WHERE operation_id=?1 AND version=?2",
                params![operation_id, version_to_i64(expected_version)],
            )
            .map_err(|_| RepositoryError::storage_unavailable())?;
        if changed == 0 {
            return Err(RepositoryError::version_conflict(
                EntityKind::CredentialReference,
            ));
        }
        Ok(())
    }
}

impl CaptureImportRecoveryRepository for SqliteMetadataRepository {
    fn create_capture_import_recovery(
        &mut self,
        record: &CaptureImportRecoveryRecord,
    ) -> Result<(), RepositoryError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| RepositoryError::storage_unavailable())?;
        transaction
            .execute(
                "INSERT INTO capture_import_operations(
                    operation_id,root_selector,scan_id,credential_id,identity_id,identity_name,
                    preset_id,preset_name,patch_id,auth_mode,auth_schema_fingerprint,
                    credential_origin,credential_backend,credential_schema_fingerprint,
                    credential_fingerprint,credential_version,credential_created_at_unix_ms,
                    credential_updated_at_unix_ms,provider_id,provider_display_name,api_base_url,
                    model_id,config_hash,phase,diagnostic_code,created_at_unix_ms,
                    updated_at_unix_ms,version
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28)",
                params![
                    record.operation_id,
                    record.root.as_storage_str(),
                    record.scan_id.as_hash().as_str(),
                    record.credential_id.as_str(),
                    record.identity_id.as_str(),
                    record.identity_name.as_str(),
                    record.preset_id.as_str(),
                    record.preset_name.as_str(),
                    record.patch_id.as_str(),
                    record.auth_mode.as_storage_str(),
                    record.auth_schema_fingerprint.as_str(),
                    capture_import_origin_str(record.credential_origin),
                    record.credential_backend.as_storage_str(),
                    record.credential_schema_fingerprint.as_str(),
                    record.credential_fingerprint.as_str(),
                    version_to_i64(record.credential_version),
                    record.credential_created_at.value(),
                    record.credential_updated_at.value(),
                    record.provider_id.as_str(),
                    record.provider_display_name.as_str(),
                    record.api_base_url.as_str(),
                    record.model_id.as_str(),
                    record.config_hash.as_str(),
                    capture_import_phase_str(record.phase),
                    record.diagnostic.map(capture_import_diagnostic_str),
                    record.created_at.value(),
                    record.updated_at.value(),
                    version_to_i64(record.version),
                ],
            )
            .map_err(|error| map_write_error(error, EntityKind::RuntimeIdentity, None))?;
        if get_capture_import_recovery_on(&transaction, &record.operation_id)?.as_ref()
            != Some(record)
        {
            return Err(RepositoryError::corrupt_data());
        }
        transaction
            .commit()
            .map_err(|_| RepositoryError::storage_unavailable())
    }

    fn get_capture_import_recovery(
        &self,
        operation_id: &str,
    ) -> Result<Option<CaptureImportRecoveryRecord>, RepositoryError> {
        get_capture_import_recovery_on(&self.connection, operation_id)
    }

    fn update_capture_import_recovery(
        &mut self,
        record: &CaptureImportRecoveryRecord,
        expected_version: EntityVersion,
    ) -> Result<(), RepositoryError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| RepositoryError::storage_unavailable())?;
        let changed = transaction
            .execute(
                "UPDATE capture_import_operations
                 SET phase=?2,diagnostic_code=?3,updated_at_unix_ms=?4,version=?5
                 WHERE operation_id=?1 AND version=?6",
                params![
                    record.operation_id,
                    capture_import_phase_str(record.phase),
                    record.diagnostic.map(capture_import_diagnostic_str),
                    record.updated_at.value(),
                    version_to_i64(record.version),
                    version_to_i64(expected_version),
                ],
            )
            .map_err(|_| RepositoryError::storage_unavailable())?;
        if changed == 0 {
            return Err(RepositoryError::version_conflict(
                EntityKind::RuntimeIdentity,
            ));
        }
        if get_capture_import_recovery_on(&transaction, &record.operation_id)?.as_ref()
            != Some(record)
        {
            return Err(RepositoryError::corrupt_data());
        }
        transaction
            .commit()
            .map_err(|_| RepositoryError::storage_unavailable())
    }

    fn delete_capture_import_recovery(
        &mut self,
        operation_id: &str,
        expected_version: EntityVersion,
    ) -> Result<(), RepositoryError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| RepositoryError::storage_unavailable())?;
        let changed = transaction
            .execute(
                "DELETE FROM capture_import_operations WHERE operation_id=?1 AND version=?2",
                params![operation_id, version_to_i64(expected_version)],
            )
            .map_err(|_| RepositoryError::storage_unavailable())?;
        if changed == 0 {
            return Err(RepositoryError::version_conflict(
                EntityKind::RuntimeIdentity,
            ));
        }
        if get_capture_import_recovery_on(&transaction, operation_id)?.is_some() {
            return Err(RepositoryError::corrupt_data());
        }
        transaction
            .commit()
            .map_err(|_| RepositoryError::storage_unavailable())
    }
}

fn get_capture_import_recovery_on(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<CaptureImportRecoveryRecord>, RepositoryError> {
    connection
        .query_row(
            "SELECT operation_id,root_selector,scan_id,credential_id,identity_id,identity_name,
                    preset_id,preset_name,patch_id,auth_mode,auth_schema_fingerprint,
                    credential_origin,credential_backend,credential_schema_fingerprint,
                    credential_fingerprint,credential_version,credential_created_at_unix_ms,
                    credential_updated_at_unix_ms,provider_id,provider_display_name,api_base_url,
                    model_id,config_hash,phase,diagnostic_code,created_at_unix_ms,
                    updated_at_unix_ms,version
             FROM capture_import_operations WHERE operation_id=?1",
            [operation_id],
            capture_import_recovery_from_row,
        )
        .optional()
        .map_err(|_| RepositoryError::corrupt_data())
}

fn capture_import_recovery_from_row(
    row: &Row<'_>,
) -> rusqlite::Result<CaptureImportRecoveryRecord> {
    let auth_mode = match row.get::<_, String>(9)?.as_str() {
        "api_key" => AuthMode::ApiKey,
        "oauth" => AuthMode::OAuth,
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    let credential_origin = match row.get::<_, String>(11)?.as_str() {
        "created" => CaptureImportCredentialOrigin::Created,
        "reused" => CaptureImportCredentialOrigin::Reused,
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    let credential_backend = CredentialBackend::from_storage(&row.get::<_, String>(12)?)
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let phase = match row.get::<_, String>(23)?.as_str() {
        "prepared" => CaptureImportPhase::Prepared,
        "credential_ready" => CaptureImportPhase::CredentialReady,
        "bundle_ready" => CaptureImportPhase::BundleReady,
        "recovery_required" => CaptureImportPhase::RecoveryRequired,
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    let diagnostic = row
        .get::<_, Option<String>>(24)?
        .map(|value| match value.as_str() {
            "journal_unavailable" => Ok(CaptureImportDiagnostic::JournalUnavailable),
            "credential_pending" => Ok(CaptureImportDiagnostic::CredentialPending),
            "bundle_pending" => Ok(CaptureImportDiagnostic::BundlePending),
            "cleanup_pending" => Ok(CaptureImportDiagnostic::CleanupPending),
            "inconsistent_state" => Ok(CaptureImportDiagnostic::InconsistentState),
            _ => Err(rusqlite::Error::InvalidQuery),
        })
        .transpose()?;
    Ok(CaptureImportRecoveryRecord {
        operation_id: row.get(0)?,
        root: ControlledRoot::from_storage(&row.get::<_, String>(1)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        scan_id: ControlledScanId::parse(&row.get::<_, String>(2)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        credential_id: CredentialRefId::parse(&row.get::<_, String>(3)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        identity_id: IdentityId::parse(&row.get::<_, String>(4)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        identity_name: EntityName::parse(&row.get::<_, String>(5)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        preset_id: ModelPresetId::parse(&row.get::<_, String>(6)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        preset_name: EntityName::parse(&row.get::<_, String>(7)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        patch_id: ManagedConfigPatchId::parse(&row.get::<_, String>(8)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        auth_mode,
        auth_schema_fingerprint: SchemaFingerprint::parse(&row.get::<_, String>(10)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        credential_origin,
        credential_backend,
        credential_schema_fingerprint: SchemaFingerprint::parse(&row.get::<_, String>(13)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        credential_fingerprint: CredentialFingerprint::parse(&row.get::<_, String>(14)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        credential_version: EntityVersion::new(row.get::<_, u64>(15)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        credential_created_at: UnixMillis::new(row.get(16)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        credential_updated_at: UnixMillis::new(row.get(17)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        provider_id: ProviderId::parse(&row.get::<_, String>(18)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        provider_display_name: EntityName::parse(&row.get::<_, String>(19)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        api_base_url: EndpointUrl::parse(&row.get::<_, String>(20)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        model_id: ModelId::parse(&row.get::<_, String>(21)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        config_hash: ContentHash::parse(&row.get::<_, String>(22)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        phase,
        diagnostic,
        created_at: UnixMillis::new(row.get(25)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
        updated_at: UnixMillis::new(row.get(26)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
        version: EntityVersion::new(row.get::<_, u64>(27)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
    })
}

const fn capture_import_phase_str(value: CaptureImportPhase) -> &'static str {
    match value {
        CaptureImportPhase::Prepared => "prepared",
        CaptureImportPhase::CredentialReady => "credential_ready",
        CaptureImportPhase::BundleReady => "bundle_ready",
        CaptureImportPhase::RecoveryRequired => "recovery_required",
    }
}

const fn capture_import_origin_str(value: CaptureImportCredentialOrigin) -> &'static str {
    match value {
        CaptureImportCredentialOrigin::Created => "created",
        CaptureImportCredentialOrigin::Reused => "reused",
    }
}

const fn capture_import_diagnostic_str(value: CaptureImportDiagnostic) -> &'static str {
    match value {
        CaptureImportDiagnostic::JournalUnavailable => "journal_unavailable",
        CaptureImportDiagnostic::CredentialPending => "credential_pending",
        CaptureImportDiagnostic::BundlePending => "bundle_pending",
        CaptureImportDiagnostic::CleanupPending => "cleanup_pending",
        CaptureImportDiagnostic::InconsistentState => "inconsistent_state",
    }
}

fn credential_kind_str(kind: CredentialKind) -> &'static str {
    match kind {
        CredentialKind::ApiKey => "api_key",
        CredentialKind::OAuthBundle => "oauth_bundle",
    }
}
fn credential_recovery_operation_str(value: CredentialRecoveryOperation) -> &'static str {
    match value {
        CredentialRecoveryOperation::Create => "create",
        CredentialRecoveryOperation::Rotate => "rotate",
        CredentialRecoveryOperation::Delete => "delete",
    }
}
fn credential_recovery_phase_str(value: CredentialRecoveryPhase) -> &'static str {
    match value {
        CredentialRecoveryPhase::Prepared => "prepared",
        CredentialRecoveryPhase::Published => "published",
        CredentialRecoveryPhase::MetadataPending => "metadata_pending",
        CredentialRecoveryPhase::DeletePending => "delete_pending",
        CredentialRecoveryPhase::RecoveryRequired => "recovery_required",
    }
}

fn credential_recovery_from_row(row: &Row<'_>) -> rusqlite::Result<CredentialRecoveryRecord> {
    let material_ref = PathBuf::from(row.get::<_, String>(5)?);
    if !repository_safe_relative(&material_ref) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let record = CredentialRecoveryRecord {
        operation_id: row.get(0)?,
        credential_id: CredentialRefId::parse(&row.get::<_, String>(1)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        kind: match row.get::<_, String>(2)?.as_str() {
            "api_key" => CredentialKind::ApiKey,
            "oauth_bundle" => CredentialKind::OAuthBundle,
            _ => return Err(rusqlite::Error::InvalidQuery),
        },
        operation: match row.get::<_, String>(3)?.as_str() {
            "create" => CredentialRecoveryOperation::Create,
            "rotate" => CredentialRecoveryOperation::Rotate,
            "delete" => CredentialRecoveryOperation::Delete,
            _ => return Err(rusqlite::Error::InvalidQuery),
        },
        generation: EntityVersion::new(
            u64::try_from(row.get::<_, i64>(4)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
        )
        .map_err(|_| rusqlite::Error::InvalidQuery)?,
        planned_credential_fingerprint: row
            .get::<_, Option<String>>(14)?
            .map(|value| {
                CredentialFingerprint::parse(&value).map_err(|_| rusqlite::Error::InvalidQuery)
            })
            .transpose()?,
        material_ref,
        material_hash: row
            .get::<_, Option<String>>(6)?
            .map(|value| ContentHash::parse(&value).map_err(|_| rusqlite::Error::InvalidQuery))
            .transpose()?,
        phase: match row.get::<_, String>(7)?.as_str() {
            "prepared" => CredentialRecoveryPhase::Prepared,
            "published" => CredentialRecoveryPhase::Published,
            "metadata_pending" => CredentialRecoveryPhase::MetadataPending,
            "delete_pending" => CredentialRecoveryPhase::DeletePending,
            "recovery_required" => CredentialRecoveryPhase::RecoveryRequired,
            _ => return Err(rusqlite::Error::InvalidQuery),
        },
        diagnostic_code: row.get(8)?,
        credential_created_at: UnixMillis::new(row.get(9)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        credential_updated_at: UnixMillis::new(row.get(10)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        created_at: UnixMillis::new(row.get(11)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
        updated_at: UnixMillis::new(row.get(12)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
        version: EntityVersion::new(
            u64::try_from(row.get::<_, i64>(13)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
        )
        .map_err(|_| rusqlite::Error::InvalidQuery)?,
    };
    let legacy_unbound = row.get::<_, i64>(15)?;
    if (legacy_unbound == 0 && record.planned_credential_fingerprint.is_none())
        || (legacy_unbound == 1 && record.planned_credential_fingerprint.is_some())
        || !matches!(legacy_unbound, 0 | 1)
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    if !credential_recovery_material_state_is_valid(&record) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(record)
}

fn credential_recovery_material_state_is_valid(record: &CredentialRecoveryRecord) -> bool {
    record.credential_updated_at >= record.credential_created_at
        && ((record.phase == CredentialRecoveryPhase::Prepared && record.material_hash.is_none())
            || (record.phase != CredentialRecoveryPhase::Prepared
                && record.material_hash.is_some()))
}

fn backup_record_from_row(row: &Row<'_>) -> Result<BackupRecord, rusqlite::Error> {
    let material = PathBuf::from(row.get::<_, String>(5)?);
    if material.is_absolute()
        || material
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(BackupRecord {
        id: row.get(0)?,
        root_ref: ContentHash::parse(&row.get::<_, String>(1)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        kind: match row.get::<_, String>(2)?.as_str() {
            "permanent" => BackupKind::Permanent,
            "history" => BackupKind::History,
            _ => return Err(rusqlite::Error::InvalidQuery),
        },
        sequence: u64::try_from(row.get::<_, i64>(3)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        manifest_hash: ContentHash::parse(&row.get::<_, String>(4)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        material_ref: material,
        transaction_id: row
            .get::<_, Option<String>>(6)?
            .map(|value| {
                SwitchTransactionId::parse(&value).map_err(|_| rusqlite::Error::InvalidQuery)
            })
            .transpose()?,
        state: match row.get::<_, String>(7)?.as_str() {
            "ready" => BackupState::Ready,
            "protected" => BackupState::Protected,
            _ => return Err(rusqlite::Error::InvalidQuery),
        },
        created_at: UnixMillis::new(row.get(8)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
    })
}

fn sensitive_temp_owner_from_row(
    row: &Row<'_>,
) -> Result<SensitiveTempOwnerRecord, rusqlite::Error> {
    let nonce = fixed_blob::<16>(row, 4)?;
    let identity_bound = row.get::<_, i64>(7)?;
    let identity = match identity_bound {
        0 => {
            if row.get::<_, Option<Vec<u8>>>(8)?.is_some()
                || row.get::<_, Option<Vec<u8>>>(9)?.is_some()
            {
                return Err(rusqlite::Error::InvalidQuery);
            }
            None
        }
        1 => Some(FileIdentity128 {
            volume_serial_number: u64::from_be_bytes(
                fixed_optional_blob::<8>(row, 8)?.ok_or(rusqlite::Error::InvalidQuery)?,
            ),
            file_id: fixed_optional_blob::<16>(row, 9)?.ok_or(rusqlite::Error::InvalidQuery)?,
        }),
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    let destination_state = SensitiveDestinationState::parse(&row.get::<_, String>(14)?)?;
    let destination_guard = if destination_state == SensitiveDestinationState::None {
        None
    } else {
        Some(SensitiveDestinationGuard {
            state: destination_state,
            identity: FileIdentity128 {
                volume_serial_number: u64::from_be_bytes(
                    fixed_optional_blob::<8>(row, 15)?.ok_or(rusqlite::Error::InvalidQuery)?,
                ),
                file_id: fixed_optional_blob::<16>(row, 16)?
                    .ok_or(rusqlite::Error::InvalidQuery)?,
            },
            length: u64::try_from(row.get::<_, i64>(17)?)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            hash_ref: ContentHash::parse(&row.get::<_, String>(19)?)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
        })
    };
    Ok(SensitiveTempOwnerRecord {
        transaction_id: SwitchTransactionId::parse(&row.get::<_, String>(0)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        root_ref: ContentHash::parse(&row.get::<_, String>(1)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        role: SensitiveTempRole::parse(&row.get::<_, String>(2)?)?,
        phase: SensitiveTempPhase::parse(&row.get::<_, String>(3)?)?,
        nonce,
        temp_rel: row.get(5)?,
        publish_rel: row.get(6)?,
        identity,
        expected_length: u64::try_from(row.get::<_, i64>(10)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        expected_hash: ContentHash::parse(&row.get::<_, String>(11)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        expected_readonly: match row.get::<_, i64>(12)? {
            0 => false,
            1 => true,
            _ => return Err(rusqlite::Error::InvalidQuery),
        },
        lifecycle: SensitiveTempLifecycle::parse(&row.get::<_, String>(13)?)?,
        destination_guard,
        created_at: UnixMillis::new(row.get(20)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
        updated_at: UnixMillis::new(row.get(21)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
        version: u64::try_from(row.get::<_, i64>(22)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
    })
}

fn sensitive_temp_anomaly_from_row(row: &Row<'_>) -> Result<SensitiveTempAnomaly, rusqlite::Error> {
    let volume = fixed_optional_blob::<8>(row, 6)?;
    let file_id = fixed_optional_blob::<16>(row, 7)?;
    let observed_identity = match (volume, file_id) {
        (None, None) => None,
        (Some(volume), Some(file_id)) => Some(FileIdentity128 {
            volume_serial_number: u64::from_be_bytes(volume),
            file_id,
        }),
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    Ok(SensitiveTempAnomaly {
        transaction_id: row
            .get::<_, Option<String>>(0)?
            .map(|value| {
                SwitchTransactionId::parse(&value).map_err(|_| rusqlite::Error::InvalidQuery)
            })
            .transpose()?,
        root_ref: ContentHash::parse(&row.get::<_, String>(1)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        role: SensitiveTempRole::parse(&row.get::<_, String>(2)?)?,
        phase: SensitiveTempPhase::parse(&row.get::<_, String>(3)?)?,
        canonical_rel_path: row.get(4)?,
        reason: row.get(5)?,
        observed_identity,
        observed_length: row
            .get::<_, Option<i64>>(8)?
            .map(|value| u64::try_from(value).map_err(|_| rusqlite::Error::InvalidQuery))
            .transpose()?,
        created_at: UnixMillis::new(row.get(9)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
        updated_at: UnixMillis::new(row.get(10)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
        version: u64::try_from(row.get::<_, i64>(11)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
    })
}

fn fixed_blob<const N: usize>(row: &Row<'_>, index: usize) -> Result<[u8; N], rusqlite::Error> {
    row.get::<_, Vec<u8>>(index)?
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)
}

fn fixed_optional_blob<const N: usize>(
    row: &Row<'_>,
    index: usize,
) -> Result<Option<[u8; N]>, rusqlite::Error> {
    row.get::<_, Option<Vec<u8>>>(index)?
        .map(|value| value.try_into().map_err(|_| rusqlite::Error::InvalidQuery))
        .transpose()
}

impl SwitchTransactionRepository for SqliteMetadataRepository {
    fn create_switch_transaction(
        &mut self,
        record: &SwitchTransactionRecord,
    ) -> Result<(), RepositoryError> {
        let transaction = &record.transaction;
        self.connection.execute(
            "INSERT INTO switch_transactions (id,root_ref,config_source_sha256,auth_source_sha256,config_target_sha256,auth_target_sha256,target_provider_id,target_model_id,target_auth_fingerprint,snapshot_manifest_sha256,state,completed_roles,last_error_code,created_at_unix_ms,updated_at_unix_ms,version) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
            params![
                transaction.id().as_str(), transaction.root_ref().as_str(),
                transaction.config_source().map(ContentHash::as_str), transaction.auth_source().map(ContentHash::as_str),
                transaction.config_target().as_str(), transaction.auth_target().as_str(), transaction.target_provider_id().as_str(), transaction.target_model_id().as_str(), transaction.target_auth_fingerprint().as_str(), record.snapshot_manifest_hash.as_ref().map(ContentHash::as_str), transaction.state().as_storage_str(),
                i64::from(transaction.completed_roles()), record.last_error.map(SwitchErrorCode::as_storage_str),
                transaction.created_at().value(), transaction.updated_at().value(), version_to_i64(transaction.version())
            ],
        ).map_err(|error| map_write_error(error, EntityKind::SwitchTransaction, None))?;
        Ok(())
    }

    fn update_switch_transaction(
        &mut self,
        record: &SwitchTransactionRecord,
        expected_version: EntityVersion,
    ) -> Result<(), RepositoryError> {
        let transaction = &record.transaction;
        let changed = self.connection.execute(
            "UPDATE switch_transactions SET snapshot_manifest_sha256=?1,state=?2,completed_roles=?3,last_error_code=?4,updated_at_unix_ms=?5,version=?6 WHERE id=?7 AND version=?8",
            params![record.snapshot_manifest_hash.as_ref().map(ContentHash::as_str),transaction.state().as_storage_str(),i64::from(transaction.completed_roles()),record.last_error.map(SwitchErrorCode::as_storage_str),transaction.updated_at().value(),version_to_i64(transaction.version()),transaction.id().as_str(),version_to_i64(expected_version)],
        ).map_err(|error| map_write_error(error, EntityKind::SwitchTransaction, None))?;
        if changed == 0 {
            return Err(RepositoryError::version_conflict(
                EntityKind::SwitchTransaction,
            ));
        }
        Ok(())
    }

    fn get_switch_transaction(
        &self,
        id: &SwitchTransactionId,
    ) -> Result<Option<SwitchTransactionRecord>, RepositoryError> {
        self.connection.query_row(
            "SELECT id,root_ref,config_source_sha256,auth_source_sha256,config_target_sha256,auth_target_sha256,target_provider_id,target_model_id,target_auth_fingerprint,snapshot_manifest_sha256,state,completed_roles,last_error_code,created_at_unix_ms,updated_at_unix_ms,version FROM switch_transactions WHERE id=?1",
            [id.as_str()], switch_record_from_row,
        ).optional().map_err(|_| RepositoryError::corrupt_data())
    }

    fn list_unfinished_switch_transactions(
        &self,
        root_ref: &ContentHash,
    ) -> Result<Vec<SwitchTransactionRecord>, RepositoryError> {
        let mut statement = self.connection.prepare(
            "SELECT id,root_ref,config_source_sha256,auth_source_sha256,config_target_sha256,auth_target_sha256,target_provider_id,target_model_id,target_auth_fingerprint,snapshot_manifest_sha256,state,completed_roles,last_error_code,created_at_unix_ms,updated_at_unix_ms,version FROM switch_transactions WHERE root_ref=?1 AND state NOT IN ('committed','rolled_back','recovery_required') ORDER BY created_at_unix_ms,id"
        ).map_err(|_| RepositoryError::storage_unavailable())?;
        let rows = statement
            .query_map([root_ref.as_str()], switch_record_from_row)
            .map_err(|_| RepositoryError::storage_unavailable())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| RepositoryError::corrupt_data())
    }

    fn list_blocking_switch_transactions(
        &self,
        root_ref: &ContentHash,
    ) -> Result<Vec<SwitchTransactionRecord>, RepositoryError> {
        let mut statement = self.connection.prepare(
            "SELECT id,root_ref,config_source_sha256,auth_source_sha256,config_target_sha256,auth_target_sha256,target_provider_id,target_model_id,target_auth_fingerprint,snapshot_manifest_sha256,state,completed_roles,last_error_code,created_at_unix_ms,updated_at_unix_ms,version FROM switch_transactions WHERE root_ref=?1 AND state NOT IN ('committed','rolled_back') ORDER BY created_at_unix_ms,id"
        ).map_err(|_| RepositoryError::storage_unavailable())?;
        let rows = statement
            .query_map([root_ref.as_str()], switch_record_from_row)
            .map_err(|_| RepositoryError::storage_unavailable())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| RepositoryError::corrupt_data())
    }

    fn list_recovery_required_diagnostics(
        &self,
        root_ref: &ContentHash,
    ) -> Result<Vec<SwitchRecoveryDiagnostic>, RepositoryError> {
        let records = {
            let mut statement = self.connection.prepare(
                "SELECT id,root_ref,config_source_sha256,auth_source_sha256,config_target_sha256,auth_target_sha256,target_provider_id,target_model_id,target_auth_fingerprint,snapshot_manifest_sha256,state,completed_roles,last_error_code,created_at_unix_ms,updated_at_unix_ms,version FROM switch_transactions WHERE root_ref=?1 AND state='recovery_required' ORDER BY created_at_unix_ms,id"
            ).map_err(|_| RepositoryError::storage_unavailable())?;
            let rows = statement
                .query_map([root_ref.as_str()], switch_record_from_row)
                .map_err(|_| RepositoryError::storage_unavailable())?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|_| RepositoryError::corrupt_data())?
        };
        Ok(records
            .into_iter()
            .map(|record| SwitchRecoveryDiagnostic {
                material_ref: PathBuf::from(".codextools-transactions")
                    .join(record.transaction.id().as_str()),
                record,
            })
            .collect())
    }
}

fn optional_hash(value: Option<String>) -> Result<Option<ContentHash>, rusqlite::Error> {
    value
        .map(|value| ContentHash::parse(&value).map_err(|_| rusqlite::Error::InvalidQuery))
        .transpose()
}

fn switch_record_from_row(row: &Row<'_>) -> Result<SwitchTransactionRecord, rusqlite::Error> {
    let state = SwitchTransactionState::parse_storage(&row.get::<_, String>(10)?)
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let transaction = SwitchTransaction::restore(
        SwitchTransactionId::parse(&row.get::<_, String>(0)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        ContentHash::parse(&row.get::<_, String>(1)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
        optional_hash(row.get(2)?)?,
        optional_hash(row.get(3)?)?,
        ContentHash::parse(&row.get::<_, String>(4)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
        ContentHash::parse(&row.get::<_, String>(5)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
        ProviderId::parse(&row.get::<_, String>(6)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
        ModelId::parse(&row.get::<_, String>(7)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
        CredentialFingerprint::parse(&row.get::<_, String>(8)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        state,
        row.get::<_, u8>(11)?,
        UnixMillis::new(row.get(13)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
        UnixMillis::new(row.get(14)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
        EntityVersion::new(row.get::<_, u64>(15)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
    )
    .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let last_error = row
        .get::<_, Option<String>>(12)?
        .map(|value| SwitchErrorCode::parse_storage(&value))
        .transpose()
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let snapshot_manifest_hash = optional_hash(row.get(9)?)?;
    if (transaction.requires_snapshot_manifest() && snapshot_manifest_hash.is_none())
        || (transaction.forbids_snapshot_manifest() && snapshot_manifest_hash.is_some())
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(SwitchTransactionRecord {
        transaction,
        last_error,
        snapshot_manifest_hash,
    })
}

#[allow(dead_code)]
const _: u32 = LATEST_SCHEMA_VERSION;
