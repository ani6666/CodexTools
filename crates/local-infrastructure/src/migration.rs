use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

pub const LATEST_SCHEMA_VERSION: u32 = 10;
pub const MIGRATION_0001_SQL: &str = include_str!("../migrations/0001_identity_core.sql");
pub const MIGRATION_0002_SQL: &str = include_str!("../migrations/0002_managed_config_patch.sql");
pub const MIGRATION_0003_SQL: &str = include_str!("../migrations/0003_switch_transaction.sql");
pub const MIGRATION_0004_SQL: &str = include_str!("../migrations/0004_switch_root_guard.sql");
pub const MIGRATION_0005_SQL: &str = include_str!("../migrations/0005_credential_backup.sql");
pub const MIGRATION_0006_SQL: &str = include_str!("../migrations/0006_backup_recovery.sql");
pub const MIGRATION_0007_SQL: &str = include_str!("../migrations/0007_m24_r3_recovery_guards.sql");
pub const MIGRATION_0008_SQL: &str =
    include_str!("../migrations/0008_credential_recovery_timestamps.sql");
pub const MIGRATION_0009_SQL: &str =
    include_str!("../migrations/0009_credential_recovery_planned_fingerprint.sql");
pub const MIGRATION_0010_SQL: &str =
    include_str!("../migrations/0010_switch_sensitive_temp_owner.sql");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationError {
    FutureVersion { found: u32, supported: u32 },
    Failed,
}

impl std::fmt::Display for MigrationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FutureVersion { found, supported } => {
                write!(
                    formatter,
                    "database schema version {found} exceeds supported version {supported}"
                )
            }
            Self::Failed => formatter.write_str("database migration failed"),
        }
    }
}

impl std::error::Error for MigrationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MigrationFailurePoint {
    None,
    AfterSchema,
    AfterPatchSchema,
    AfterSwitchSchema,
    AfterSwitchRootGuard,
    AfterCredentialBackup,
    AfterBackupRecovery,
    AfterM24R3RecoveryGuards,
    AfterCredentialRecoveryTimestamps,
    AfterCredentialRecoveryPlannedFingerprint,
    AfterSensitiveTempOwnerSchema,
}

pub(crate) fn migrate(connection: &mut Connection) -> Result<(), MigrationError> {
    migrate_internal(connection, MigrationFailurePoint::None)
}

#[cfg(test)]
pub(crate) fn migrate_for_test(
    connection: &mut Connection,
    failure_point: MigrationFailurePoint,
) -> Result<(), MigrationError> {
    migrate_internal(connection, failure_point)
}

fn migrate_internal(
    connection: &mut Connection,
    failure_point: MigrationFailurePoint,
) -> Result<(), MigrationError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| MigrationError::Failed)?;
    transaction
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                 version INTEGER PRIMARY KEY,
                 name TEXT NOT NULL UNIQUE,
                 applied_at_unix_ms INTEGER NOT NULL CHECK(applied_at_unix_ms >= 0)
             ) STRICT;",
        )
        .map_err(|_| MigrationError::Failed)?;

    let current: Option<u32> = transaction
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .optional()
        .map_err(|_| MigrationError::Failed)?
        .flatten();
    let current = current.unwrap_or(0);
    if current > LATEST_SCHEMA_VERSION {
        return Err(MigrationError::FutureVersion {
            found: current,
            supported: LATEST_SCHEMA_VERSION,
        });
    }

    if current < 1 {
        transaction
            .execute_batch(MIGRATION_0001_SQL)
            .map_err(|_| MigrationError::Failed)?;
        if failure_point == MigrationFailurePoint::AfterSchema {
            return Err(MigrationError::Failed);
        }
        let applied_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MigrationError::Failed)?
            .as_millis();
        let applied_at = i64::try_from(applied_at).map_err(|_| MigrationError::Failed)?;
        transaction
            .execute(
                "INSERT INTO schema_migrations(version, name, applied_at_unix_ms) VALUES (?1, ?2, ?3)",
                (1_u32, "identity_core", applied_at),
            )
            .map_err(|_| MigrationError::Failed)?;
    }

    if current < 2 {
        transaction
            .execute_batch(MIGRATION_0002_SQL)
            .map_err(|_| MigrationError::Failed)?;
        if failure_point == MigrationFailurePoint::AfterPatchSchema {
            return Err(MigrationError::Failed);
        }
        let applied_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MigrationError::Failed)?
            .as_millis();
        let applied_at = i64::try_from(applied_at).map_err(|_| MigrationError::Failed)?;
        transaction
            .execute(
                "INSERT INTO schema_migrations(version, name, applied_at_unix_ms) VALUES (?1, ?2, ?3)",
                (2_u32, "managed_config_patch", applied_at),
            )
            .map_err(|_| MigrationError::Failed)?;
    }

    if current < 3 {
        transaction
            .execute_batch(MIGRATION_0003_SQL)
            .map_err(|_| MigrationError::Failed)?;
        if failure_point == MigrationFailurePoint::AfterSwitchSchema {
            return Err(MigrationError::Failed);
        }
        let applied_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MigrationError::Failed)?
            .as_millis();
        let applied_at = i64::try_from(applied_at).map_err(|_| MigrationError::Failed)?;
        transaction.execute("INSERT INTO schema_migrations(version, name, applied_at_unix_ms) VALUES (?1, ?2, ?3)",(3_u32,"switch_transaction",applied_at)).map_err(|_| MigrationError::Failed)?;
    }

    if current < 4 {
        transaction
            .execute_batch(MIGRATION_0004_SQL)
            .map_err(|_| MigrationError::Failed)?;
        if failure_point == MigrationFailurePoint::AfterSwitchRootGuard {
            return Err(MigrationError::Failed);
        }
        let applied_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MigrationError::Failed)?
            .as_millis();
        let applied_at = i64::try_from(applied_at).map_err(|_| MigrationError::Failed)?;
        transaction.execute("INSERT INTO schema_migrations(version, name, applied_at_unix_ms) VALUES (?1, ?2, ?3)",(4_u32,"switch_root_guard",applied_at)).map_err(|_| MigrationError::Failed)?;
    }

    if current < 5 {
        transaction
            .execute_batch(MIGRATION_0005_SQL)
            .map_err(|_| MigrationError::Failed)?;
        if failure_point == MigrationFailurePoint::AfterCredentialBackup {
            return Err(MigrationError::Failed);
        }
        let applied_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MigrationError::Failed)?
            .as_millis();
        let applied_at = i64::try_from(applied_at).map_err(|_| MigrationError::Failed)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, name, applied_at_unix_ms) VALUES (?1, ?2, ?3)",
            (5_u32, "credential_backup", applied_at),
        ).map_err(|_| MigrationError::Failed)?;
    }

    if current < 6 {
        transaction
            .execute_batch(MIGRATION_0006_SQL)
            .map_err(|_| MigrationError::Failed)?;
        if failure_point == MigrationFailurePoint::AfterBackupRecovery {
            return Err(MigrationError::Failed);
        }
        let applied_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MigrationError::Failed)?
            .as_millis();
        let applied_at = i64::try_from(applied_at).map_err(|_| MigrationError::Failed)?;
        transaction
            .execute(
                "INSERT INTO schema_migrations(version, name, applied_at_unix_ms) VALUES (?1, ?2, ?3)",
                (6_u32, "backup_recovery", applied_at),
            )
            .map_err(|_| MigrationError::Failed)?;
    }

    if current < 7 {
        transaction
            .execute_batch(MIGRATION_0007_SQL)
            .map_err(|_| MigrationError::Failed)?;
        if failure_point == MigrationFailurePoint::AfterM24R3RecoveryGuards {
            return Err(MigrationError::Failed);
        }
        let applied_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MigrationError::Failed)?
            .as_millis();
        let applied_at = i64::try_from(applied_at).map_err(|_| MigrationError::Failed)?;
        transaction
            .execute(
                "INSERT INTO schema_migrations(version, name, applied_at_unix_ms) VALUES (?1, ?2, ?3)",
                (7_u32, "m24_r3_recovery_guards", applied_at),
            )
            .map_err(|_| MigrationError::Failed)?;
    }

    if current < 8 {
        transaction
            .execute_batch(MIGRATION_0008_SQL)
            .map_err(|_| MigrationError::Failed)?;
        if failure_point == MigrationFailurePoint::AfterCredentialRecoveryTimestamps {
            return Err(MigrationError::Failed);
        }
        let applied_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MigrationError::Failed)?
            .as_millis();
        let applied_at = i64::try_from(applied_at).map_err(|_| MigrationError::Failed)?;
        transaction
            .execute(
                "INSERT INTO schema_migrations(version, name, applied_at_unix_ms) VALUES (?1, ?2, ?3)",
                (8_u32, "credential_recovery_timestamps", applied_at),
            )
            .map_err(|_| MigrationError::Failed)?;
    }

    if current < 9 {
        transaction
            .execute_batch(MIGRATION_0009_SQL)
            .map_err(|_| MigrationError::Failed)?;
        if failure_point == MigrationFailurePoint::AfterCredentialRecoveryPlannedFingerprint {
            return Err(MigrationError::Failed);
        }
        let applied_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MigrationError::Failed)?
            .as_millis();
        let applied_at = i64::try_from(applied_at).map_err(|_| MigrationError::Failed)?;
        transaction
            .execute(
                "INSERT INTO schema_migrations(version, name, applied_at_unix_ms) VALUES (?1, ?2, ?3)",
                (9_u32, "credential_recovery_planned_fingerprint", applied_at),
            )
            .map_err(|_| MigrationError::Failed)?;
    }

    if current < 10 {
        transaction
            .execute_batch(MIGRATION_0010_SQL)
            .map_err(|_| MigrationError::Failed)?;
        if failure_point == MigrationFailurePoint::AfterSensitiveTempOwnerSchema {
            return Err(MigrationError::Failed);
        }
        let applied_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MigrationError::Failed)?
            .as_millis();
        let applied_at = i64::try_from(applied_at).map_err(|_| MigrationError::Failed)?;
        transaction
            .execute(
                "INSERT INTO schema_migrations(version, name, applied_at_unix_ms) VALUES (?1, ?2, ?3)",
                (10_u32, "switch_sensitive_temp_owner", applied_at),
            )
            .map_err(|_| MigrationError::Failed)?;
    }

    transaction.commit().map_err(|_| MigrationError::Failed)
}
