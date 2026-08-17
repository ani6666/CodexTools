use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::migration::{
    LATEST_SCHEMA_VERSION, MIGRATION_0006_SQL, MIGRATION_0007_SQL, MIGRATION_0008_SQL,
    MigrationFailurePoint, migrate_for_test,
};
use rusqlite::{Connection, params};

#[test]
fn migration_failure_rolls_back_all_schema_changes() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "codextools-m21-migration-{}-{nonce}.sqlite3",
        std::process::id()
    ));
    let mut connection = Connection::open(&path).unwrap();
    let result = migrate_for_test(&mut connection, MigrationFailurePoint::AfterSchema);
    assert!(result.is_err());

    let table_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(table_count, 0);
    drop(connection);
    remove_sqlite_files(&path);
    assert!(!path.exists());
}

#[test]
fn second_migration_failure_rolls_back_patch_schema() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "codextools-m22-migration-{}-{nonce}.sqlite3",
        std::process::id()
    ));
    let mut connection = Connection::open(&path).unwrap();
    migrate_for_test(&mut connection, MigrationFailurePoint::None).unwrap();
    demote_v10(&connection);
    connection
        .execute(
            "DELETE FROM schema_migrations WHERE version IN (2,3,4,5,6,7,8,9)",
            [],
        )
        .unwrap();
    connection
        .execute_batch(
            "DROP TABLE credential_recovery_operations; DROP TABLE backup_recovery_operations; DROP TABLE backup_sets; DROP TABLE switch_transactions; DROP TABLE managed_config_patches;",
        )
        .unwrap();
    let result = migrate_for_test(&mut connection, MigrationFailurePoint::AfterPatchSchema);
    assert!(result.is_err());
    let exists:i64=connection.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='managed_config_patches'",[],|row|row.get(0)).unwrap();
    assert_eq!(exists, 0);
    drop(connection);
    remove_sqlite_files(&path);
    assert!(!path.exists());
}

#[test]
fn third_migration_failure_rolls_back_switch_schema() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "codextools-m23-migration-{}-{nonce}.sqlite3",
        std::process::id()
    ));
    let mut connection = Connection::open(&path).unwrap();
    migrate_for_test(&mut connection, MigrationFailurePoint::None).unwrap();
    demote_v10(&connection);
    connection
        .execute(
            "DELETE FROM schema_migrations WHERE version IN (3,4,5,6,7,8,9)",
            [],
        )
        .unwrap();
    connection
        .execute_batch("DROP TABLE credential_recovery_operations; DROP TABLE backup_recovery_operations; DROP TABLE backup_sets; DROP TABLE switch_transactions;")
        .unwrap();
    let result = migrate_for_test(&mut connection, MigrationFailurePoint::AfterSwitchSchema);
    assert!(result.is_err());
    let exists: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='switch_transactions'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(exists, 0);
    drop(connection);
    remove_sqlite_files(&path);
    assert!(!path.exists());
}

#[test]
fn fourth_migration_failure_rolls_back_root_guard_schema() {
    let path = temporary_database_path("m23-root-guard-failure");
    let mut connection = Connection::open(&path).unwrap();
    migrate_for_test(&mut connection, MigrationFailurePoint::None).unwrap();
    demote_to_v3(&connection);

    let result = migrate_for_test(&mut connection, MigrationFailurePoint::AfterSwitchRootGuard);
    assert!(result.is_err());
    assert_eq!(schema_version(&connection), 3);
    assert_eq!(
        schema_object_count(&connection, "ux_switch_transactions_active_root"),
        0
    );
    assert_eq!(
        schema_object_count(&connection, "trg_switch_snapshot_binding_insert"),
        0
    );
    assert_eq!(
        schema_object_count(&connection, "trg_switch_snapshot_binding_update"),
        0
    );
    drop(connection);
    remove_sqlite_files(&path);
}

#[test]
fn v3_upgrade_adds_one_active_transaction_slot_per_root() {
    let path = temporary_database_path("m23-v3-upgrade");
    let mut connection = Connection::open(&path).unwrap();
    migrate_for_test(&mut connection, MigrationFailurePoint::None).unwrap();
    demote_to_v3(&connection);
    insert_switch_row(
        &connection,
        "11111111-1111-4111-8111-111111111111",
        "planned",
    );

    migrate_for_test(&mut connection, MigrationFailurePoint::None).unwrap();
    assert_eq!(
        schema_version(&connection),
        i64::from(LATEST_SCHEMA_VERSION)
    );
    assert_eq!(
        schema_object_count(&connection, "ux_switch_transactions_active_root"),
        1
    );
    assert!(
        insert_switch_row_result(
            &connection,
            "22222222-2222-4222-8222-222222222222",
            "planned"
        )
        .is_err()
    );
    drop(connection);
    remove_sqlite_files(&path);
}

#[test]
fn v3_upgrade_with_duplicate_active_roots_fails_closed_atomically() {
    let path = temporary_database_path("m23-v3-duplicate-root");
    let mut connection = Connection::open(&path).unwrap();
    migrate_for_test(&mut connection, MigrationFailurePoint::None).unwrap();
    demote_to_v3(&connection);
    insert_switch_row(
        &connection,
        "11111111-1111-4111-8111-111111111111",
        "planned",
    );
    insert_switch_row(
        &connection,
        "22222222-2222-4222-8222-222222222222",
        "rolling_back",
    );

    assert!(migrate_for_test(&mut connection, MigrationFailurePoint::None).is_err());
    assert_eq!(schema_version(&connection), 3);
    assert_eq!(
        schema_object_count(&connection, "ux_switch_transactions_active_root"),
        0
    );
    assert_eq!(
        schema_object_count(&connection, "trg_switch_snapshot_binding_insert"),
        0
    );
    assert_eq!(
        schema_object_count(&connection, "trg_switch_snapshot_binding_update"),
        0
    );
    let rows: i64 = connection
        .query_row("SELECT COUNT(*) FROM switch_transactions", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(rows, 2);
    drop(connection);
    remove_sqlite_files(&path);
}

fn temporary_database_path(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "codextools-{label}-{}-{nonce}.sqlite3",
        std::process::id()
    ))
}

fn demote_to_v3(connection: &Connection) {
    demote_v10(connection);
    connection
        .execute_batch(
            "DROP TABLE credential_recovery_operations;
             DROP TABLE backup_recovery_operations;
             DROP TABLE backup_sets;
             DROP TRIGGER trg_switch_snapshot_binding_update;
             DROP TRIGGER trg_switch_snapshot_binding_insert;
             DROP INDEX ux_switch_transactions_active_root;
             DELETE FROM schema_migrations WHERE version IN (4,5,6,7,8,9);",
        )
        .unwrap();
}

#[test]
fn fifth_migration_failure_rolls_back_backup_schema() {
    let path = temporary_database_path("m24-backup-failure");
    let mut connection = Connection::open(&path).unwrap();
    migrate_for_test(&mut connection, MigrationFailurePoint::None).unwrap();
    demote_v10(&connection);
    connection
        .execute_batch(
            "DROP TABLE credential_recovery_operations;
             DROP TABLE backup_recovery_operations;
             DROP TABLE backup_sets;
             DELETE FROM schema_migrations WHERE version IN (5,6,7,8,9);",
        )
        .unwrap();

    let result = migrate_for_test(
        &mut connection,
        MigrationFailurePoint::AfterCredentialBackup,
    );
    assert!(result.is_err());
    assert_eq!(schema_version(&connection), 4);
    assert_eq!(schema_object_count(&connection, "backup_sets"), 0);
    assert_eq!(
        schema_object_count(&connection, "ux_backup_sets_permanent_root"),
        0
    );
    drop(connection);
    remove_sqlite_files(&path);
}

#[test]
fn v4_upgrade_adds_versioned_backup_metadata_and_is_repeatable() {
    let path = temporary_database_path("m24-v4-upgrade");
    let mut connection = Connection::open(&path).unwrap();
    migrate_for_test(&mut connection, MigrationFailurePoint::None).unwrap();
    demote_v10(&connection);
    connection
        .execute_batch(
            "DROP TABLE credential_recovery_operations;
             DROP TABLE backup_recovery_operations;
             DROP TABLE backup_sets;
             DELETE FROM schema_migrations WHERE version IN (5,6,7,8,9);",
        )
        .unwrap();

    migrate_for_test(&mut connection, MigrationFailurePoint::None).unwrap();
    migrate_for_test(&mut connection, MigrationFailurePoint::None).unwrap();
    assert_eq!(
        schema_version(&connection),
        i64::from(LATEST_SCHEMA_VERSION)
    );
    assert_eq!(schema_object_count(&connection, "backup_sets"), 1);
    assert_eq!(
        schema_object_count(&connection, "ux_backup_sets_permanent_root"),
        1
    );
    drop(connection);
    remove_sqlite_files(&path);
}

#[test]
fn v5_upgrade_adds_recovery_journals_atomically_and_is_repeatable() {
    let path = temporary_database_path("m24-v5-recovery-upgrade");
    let mut connection = Connection::open(&path).unwrap();
    migrate_for_test(&mut connection, MigrationFailurePoint::None).unwrap();
    demote_v10(&connection);
    connection
        .execute_batch(
            "DROP TABLE credential_recovery_operations;
         DROP TABLE backup_recovery_operations;
         DELETE FROM schema_migrations WHERE version IN (6,7,8,9);",
        )
        .unwrap();
    assert!(migrate_for_test(&mut connection, MigrationFailurePoint::AfterBackupRecovery).is_err());
    assert_eq!(schema_version(&connection), 5);
    assert_eq!(
        schema_object_count(&connection, "backup_recovery_operations"),
        0
    );
    assert_eq!(
        schema_object_count(&connection, "credential_recovery_operations"),
        0
    );
    migrate_for_test(&mut connection, MigrationFailurePoint::None).unwrap();
    migrate_for_test(&mut connection, MigrationFailurePoint::None).unwrap();
    assert_eq!(
        schema_version(&connection),
        i64::from(LATEST_SCHEMA_VERSION)
    );
    assert_eq!(
        schema_object_count(&connection, "backup_recovery_operations"),
        1
    );
    assert_eq!(
        schema_object_count(&connection, "credential_recovery_operations"),
        1
    );
    drop(connection);
    remove_sqlite_files(&path);
}

fn schema_version(connection: &Connection) -> i64 {
    connection
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .unwrap()
}

fn schema_object_count(connection: &Connection, name: &str) -> i64 {
    connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = ?1",
            [name],
            |row| row.get(0),
        )
        .unwrap()
}

#[test]
fn v7_upgrade_adds_credential_single_owner_guard_and_fails_closed_on_duplicates() {
    let mut connection = Connection::open_in_memory().unwrap();
    migrate_for_test(&mut connection, MigrationFailurePoint::None).unwrap();
    demote_to_v6_recovery(&connection);
    migrate_for_test(&mut connection, MigrationFailurePoint::None).unwrap();
    assert_eq!(
        schema_version(&connection),
        i64::from(LATEST_SCHEMA_VERSION)
    );
    assert_eq!(
        schema_object_count(&connection, "ux_credential_recovery_active"),
        1
    );

    demote_to_v6_recovery(&connection);
    let hash = "a".repeat(64);
    for operation_id in ["race-a", "race-b"] {
        connection.execute(
            "INSERT INTO credential_recovery_operations(operation_id,credential_id,kind,operation,generation,material_ref,material_sha256,phase,diagnostic_code,created_at_unix_ms,updated_at_unix_ms,version)
             VALUES (?1,'91919191-9191-4191-8191-919191919191','api_key','rotate',2,?2,?3,'published',NULL,1,1,1)",
            (operation_id, format!("91919191/{operation_id}"), &hash),
        ).unwrap();
    }
    assert!(migrate_for_test(&mut connection, MigrationFailurePoint::None).is_err());
    assert_eq!(schema_version(&connection), 6);
    assert_eq!(
        schema_object_count(&connection, "ux_credential_recovery_active"),
        0
    );
    let rows: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM credential_recovery_operations WHERE credential_id='91919191-9191-4191-8191-919191919191'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rows, 2);
}

fn demote_to_v6_recovery(connection: &Connection) {
    demote_v10(connection);
    connection
        .execute_batch(
            "DROP TABLE credential_recovery_operations;
             DROP TABLE backup_recovery_operations;
             DELETE FROM schema_migrations WHERE version IN (7,8,9);",
        )
        .unwrap();
    connection.execute_batch(MIGRATION_0006_SQL).unwrap();
}

fn demote_v10(connection: &Connection) {
    connection
        .execute_batch(
            "DROP TABLE capture_import_operations;
         DELETE FROM schema_migrations WHERE version=11;
         DROP TRIGGER switch_sensitive_temp_owner_blocks_terminal;
         DROP TABLE switch_sensitive_temp_anomalies;
         DROP TABLE switch_sensitive_temp_owners;
         DELETE FROM schema_migrations WHERE version=10;",
        )
        .unwrap();
}

fn demote_to_v7_recovery(connection: &Connection) {
    demote_to_v6_recovery(connection);
    connection.execute_batch(MIGRATION_0007_SQL).unwrap();
    connection
        .execute(
            "INSERT INTO schema_migrations(version,name,applied_at_unix_ms) VALUES (7,'m24_r3_recovery_guards',1)",
            [],
        )
        .unwrap();
}

fn demote_to_v8_recovery(connection: &Connection) {
    demote_to_v7_recovery(connection);
    connection.execute_batch(MIGRATION_0008_SQL).unwrap();
    connection
        .execute(
            "INSERT INTO schema_migrations(version,name,applied_at_unix_ms) VALUES (8,'credential_recovery_timestamps',1)",
            [],
        )
        .unwrap();
}

#[test]
fn v8_upgrade_binds_distinct_credential_timestamps_and_is_atomic() {
    let mut connection = Connection::open_in_memory().unwrap();
    migrate_for_test(&mut connection, MigrationFailurePoint::None).unwrap();
    demote_to_v7_recovery(&connection);
    let hash = "a".repeat(64);
    connection.execute(
        "INSERT INTO credential_references(id,kind,platform_backend,schema_fingerprint,credential_fingerprint,created_at_unix_ms,updated_at_unix_ms,version)
         VALUES ('92929292-9292-4292-8292-929292929292','api_key','windows_dpapi_current_user',?1,?1,10,20,2)",
        [&hash],
    ).unwrap();
    connection.execute(
        "INSERT INTO credential_recovery_operations(operation_id,credential_id,kind,operation,generation,material_ref,material_sha256,phase,diagnostic_code,created_at_unix_ms,updated_at_unix_ms,version)
         VALUES ('v8-rotate','92929292-9292-4292-8292-929292929292','api_key','rotate',2,'92929292/generation-2.dpapi',?1,'published',NULL,20,20,1)",
        [&hash],
    ).unwrap();
    connection.execute(
        "INSERT INTO credential_recovery_operations(operation_id,credential_id,kind,operation,generation,material_ref,material_sha256,phase,diagnostic_code,created_at_unix_ms,updated_at_unix_ms,version)
         VALUES ('v8-create-recovery','94949494-9494-4494-8494-949494949494','api_key','create',1,'94949494/generation-1.dpapi',?1,'recovery_required','credential_metadata_create',10,30,2)",
        [&hash],
    ).unwrap();

    assert!(
        migrate_for_test(
            &mut connection,
            MigrationFailurePoint::AfterCredentialRecoveryTimestamps,
        )
        .is_err()
    );
    assert_eq!(schema_version(&connection), 7);
    assert_eq!(
        connection.query_row("SELECT COUNT(*) FROM pragma_table_info('credential_recovery_operations') WHERE name='credential_created_at_unix_ms'", [], |row| row.get::<_, i64>(0)).unwrap(),
        0
    );

    migrate_for_test(&mut connection, MigrationFailurePoint::None).unwrap();
    migrate_for_test(&mut connection, MigrationFailurePoint::None).unwrap();
    assert_eq!(
        schema_version(&connection),
        i64::from(LATEST_SCHEMA_VERSION)
    );
    let timestamps = connection.query_row(
        "SELECT credential_created_at_unix_ms,credential_updated_at_unix_ms,created_at_unix_ms,updated_at_unix_ms FROM credential_recovery_operations WHERE operation_id='v8-rotate'",
        [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?, row.get::<_, i64>(3)?)),
    ).unwrap();
    assert_eq!(timestamps, (10, 20, 20, 20));
    let create_timestamps = connection.query_row(
        "SELECT credential_created_at_unix_ms,credential_updated_at_unix_ms,created_at_unix_ms,updated_at_unix_ms FROM credential_recovery_operations WHERE operation_id='v8-create-recovery'",
        [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?, row.get::<_, i64>(3)?)),
    ).unwrap();
    assert_eq!(create_timestamps, (10, 10, 10, 30));
}

#[test]
fn v8_upgrade_rejects_ambiguous_delete_pending_without_metadata() {
    let mut connection = Connection::open_in_memory().unwrap();
    migrate_for_test(&mut connection, MigrationFailurePoint::None).unwrap();
    demote_to_v7_recovery(&connection);
    let hash = "b".repeat(64);
    connection.execute(
        "INSERT INTO credential_recovery_operations(operation_id,credential_id,kind,operation,generation,material_ref,material_sha256,phase,diagnostic_code,created_at_unix_ms,updated_at_unix_ms,version)
         VALUES ('v8-ambiguous-delete','93939393-9393-4393-8393-939393939393','api_key','delete',2,'93939393/generation-2.dpapi',?1,'delete_pending',NULL,10,10,1)",
        [&hash],
    ).unwrap();
    assert!(migrate_for_test(&mut connection, MigrationFailurePoint::None).is_err());
    assert_eq!(schema_version(&connection), 7);
    assert_eq!(connection.query_row("SELECT COUNT(*) FROM credential_recovery_operations WHERE operation_id='v8-ambiguous-delete'", [], |row| row.get::<_, i64>(0)).unwrap(), 1);
}

#[test]
fn v9_upgrade_binds_exact_rows_preserves_legacy_recovery_and_is_atomic() {
    let mut connection = Connection::open_in_memory().unwrap();
    migrate_for_test(&mut connection, MigrationFailurePoint::None).unwrap();
    demote_to_v8_recovery(&connection);
    let exact_hash = "c".repeat(64);
    let legacy_hash = "d".repeat(64);
    connection.execute(
        "INSERT INTO credential_references(id,kind,platform_backend,schema_fingerprint,credential_fingerprint,created_at_unix_ms,updated_at_unix_ms,version)
         VALUES ('95959595-9595-4595-8595-959595959595','api_key','windows_dpapi_current_user',?1,?1,10,20,2)",
        [&exact_hash],
    ).unwrap();
    connection.execute(
        "INSERT INTO credential_recovery_operations(operation_id,credential_id,kind,operation,generation,material_ref,material_sha256,phase,diagnostic_code,credential_created_at_unix_ms,credential_updated_at_unix_ms,created_at_unix_ms,updated_at_unix_ms,version)
         VALUES ('v9-exact','95959595-9595-4595-8595-959595959595','api_key','rotate',2,'95959595/generation-2.dpapi',?1,'published',NULL,10,20,20,20,1)",
        [&exact_hash],
    ).unwrap();
    connection.execute(
        "INSERT INTO credential_recovery_operations(operation_id,credential_id,kind,operation,generation,material_ref,material_sha256,phase,diagnostic_code,credential_created_at_unix_ms,credential_updated_at_unix_ms,created_at_unix_ms,updated_at_unix_ms,version)
         VALUES ('v9-legacy','96969696-9696-4696-8696-969696969696','api_key','create',1,'96969696/generation-1.dpapi',?1,'recovery_required','credential_metadata_create',30,30,30,31,2)",
        [&legacy_hash],
    ).unwrap();

    assert!(
        migrate_for_test(
            &mut connection,
            MigrationFailurePoint::AfterCredentialRecoveryPlannedFingerprint,
        )
        .is_err()
    );
    assert_eq!(schema_version(&connection), 8);
    assert_eq!(connection.query_row("SELECT COUNT(*) FROM pragma_table_info('credential_recovery_operations') WHERE name='planned_credential_fingerprint'", [], |row| row.get::<_, i64>(0)).unwrap(), 0);

    migrate_for_test(&mut connection, MigrationFailurePoint::None).unwrap();
    migrate_for_test(&mut connection, MigrationFailurePoint::None).unwrap();
    assert_eq!(
        schema_version(&connection),
        i64::from(LATEST_SCHEMA_VERSION)
    );
    let exact = connection.query_row(
        "SELECT planned_credential_fingerprint,legacy_unbound FROM credential_recovery_operations WHERE operation_id='v9-exact'",
        [],
        |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, i64>(1)?)),
    ).unwrap();
    assert_eq!(exact, (Some(exact_hash.clone()), 0));
    let legacy = connection.query_row(
        "SELECT planned_credential_fingerprint,legacy_unbound FROM credential_recovery_operations WHERE operation_id='v9-legacy'",
        [],
        |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, i64>(1)?)),
    ).unwrap();
    assert_eq!(legacy, (None, 1));
    assert!(connection.execute(
        "UPDATE credential_recovery_operations SET planned_credential_fingerprint=?1 WHERE operation_id='v9-exact'",
        [&legacy_hash],
    ).is_err());
    assert!(connection.execute(
        "INSERT INTO credential_recovery_operations(operation_id,credential_id,kind,operation,generation,material_ref,material_sha256,phase,diagnostic_code,credential_created_at_unix_ms,credential_updated_at_unix_ms,created_at_unix_ms,updated_at_unix_ms,version)
         VALUES ('v9-unbound-new','97979797-9797-4797-8797-979797979797','api_key','create',1,'97979797/generation-1.dpapi',?1,'published',NULL,40,40,40,40,1)",
        [&legacy_hash],
    ).is_err());
}

#[test]
fn v10_switch_sensitive_temp_owner_schema_is_durable_and_atomic() {
    let mut connection = Connection::open_in_memory().unwrap();
    migrate_for_test(&mut connection, MigrationFailurePoint::None).unwrap();

    assert_eq!(
        schema_version(&connection),
        i64::from(LATEST_SCHEMA_VERSION)
    );
    for table in [
        "switch_sensitive_temp_owners",
        "switch_sensitive_temp_anomalies",
    ] {
        let found = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name=?1",
                [table],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        assert_eq!(found, 1, "missing v10 table {table}");
    }

    let mut v9 = Connection::open_in_memory().unwrap();
    migrate_for_test(&mut v9, MigrationFailurePoint::None).unwrap();
    v9.execute_batch(
        "DROP TABLE capture_import_operations;
         DELETE FROM schema_migrations WHERE version=11;
         DELETE FROM schema_migrations WHERE version=10;
         DROP TRIGGER switch_sensitive_temp_owner_blocks_terminal;
         DROP TABLE switch_sensitive_temp_anomalies;
         DROP TABLE switch_sensitive_temp_owners;",
    )
    .unwrap();
    assert!(
        migrate_for_test(
            &mut v9,
            MigrationFailurePoint::AfterSensitiveTempOwnerSchema,
        )
        .is_err()
    );
    assert_eq!(schema_version(&v9), 9);
    assert_eq!(
        v9.query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name='switch_sensitive_temp_owners'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap(),
        0
    );
    migrate_for_test(&mut v9, MigrationFailurePoint::None).unwrap();
    assert_eq!(schema_version(&v9), i64::from(LATEST_SCHEMA_VERSION));
}

#[test]
fn v11_capture_import_recovery_schema_is_atomic_and_repeatable() {
    let mut connection = Connection::open_in_memory().unwrap();
    migrate_for_test(&mut connection, MigrationFailurePoint::None).unwrap();
    connection
        .execute_batch(
            "DROP TABLE capture_import_operations;
             DELETE FROM schema_migrations WHERE version=11;",
        )
        .unwrap();

    assert!(
        migrate_for_test(
            &mut connection,
            MigrationFailurePoint::AfterCaptureImportRecovery,
        )
        .is_err()
    );
    assert_eq!(schema_version(&connection), 10);
    assert_eq!(
        schema_object_count(&connection, "capture_import_operations"),
        0
    );

    migrate_for_test(&mut connection, MigrationFailurePoint::None).unwrap();
    migrate_for_test(&mut connection, MigrationFailurePoint::None).unwrap();
    assert_eq!(
        schema_version(&connection),
        i64::from(LATEST_SCHEMA_VERSION)
    );
    assert_eq!(
        schema_object_count(&connection, "capture_import_operations"),
        1
    );
    assert_eq!(
        schema_object_count(&connection, "idx_capture_import_unfinished"),
        1
    );
}

fn insert_switch_row(connection: &Connection, id: &str, state: &str) {
    insert_switch_row_result(connection, id, state).unwrap();
}

fn insert_switch_row_result(
    connection: &Connection,
    id: &str,
    state: &str,
) -> rusqlite::Result<usize> {
    let hash = "a".repeat(64);
    connection.execute(
        "INSERT INTO switch_transactions(
            id, root_ref, config_source_sha256, auth_source_sha256,
            config_target_sha256, auth_target_sha256, target_provider_id,
            target_model_id, target_auth_fingerprint, snapshot_manifest_sha256,
            state, completed_roles, last_error_code, created_at_unix_ms,
            updated_at_unix_ms, version
         ) VALUES (?1, ?2, ?2, ?2, ?2, ?2, 'sample', 'gpt-SAMPLE-1', ?2,
                   NULL, ?3, 0, NULL, 1, 1, 1)",
        params![id, hash, state],
    )
}

fn remove_sqlite_files(path: &Path) {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let candidate = PathBuf::from(format!("{}{}", path.display(), suffix));
        let _ = fs::remove_file(candidate);
    }
}
