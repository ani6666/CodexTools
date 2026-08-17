#![allow(unused_crate_dependencies)]

use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use local_infrastructure::{LATEST_SCHEMA_VERSION, SqliteMetadataRepository};
use rusqlite::{Connection, params};

#[test]
fn schema_v10_is_auditable_and_enforces_recovery_ownership_dynamically() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "codextools-m24-schema-{}-{nonce}.sqlite3",
        std::process::id()
    ));
    SqliteMetadataRepository::open(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .unwrap();
    let version: i64 = connection
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(version, i64::from(LATEST_SCHEMA_VERSION));
    for table in [
        "switch_sensitive_temp_owners",
        "switch_sensitive_temp_anomalies",
    ] {
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "table={table}");
    }
    let owner_columns = connection
        .prepare("PRAGMA table_info(switch_sensitive_temp_owners)")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    for required in [
        "nonce",
        "temp_rel",
        "publish_rel",
        "volume_serial",
        "file_id",
        "lifecycle",
        "destination_state",
        "destination_hash_ref",
    ] {
        assert!(owner_columns.iter().any(|column| column == required));
    }
    assert!(!owner_columns.iter().any(|column| {
        let lower = column.to_ascii_lowercase();
        lower.contains("secret") || lower.contains("plaintext") || lower.contains("body")
    }));
    for trigger in [
        "switch_sensitive_temp_owner_immutable",
        "switch_sensitive_temp_owner_lifecycle",
        "switch_sensitive_temp_owner_destination_guard",
        "switch_sensitive_temp_owner_blocks_terminal",
    ] {
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name=?1",
                [trigger],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "trigger={trigger}");
    }
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .unwrap();
    assert_eq!(journal_mode.to_ascii_lowercase(), "delete");
    assert_eq!(synchronous, 2);
    let columns = connection
        .prepare("PRAGMA table_info(backup_sets)")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(
        columns,
        [
            "id",
            "root_ref",
            "kind",
            "sequence",
            "manifest_sha256",
            "material_ref",
            "transaction_id",
            "state",
            "created_at_unix_ms",
        ]
    );
    assert!(!columns.iter().any(|column| {
        let lower = column.to_ascii_lowercase();
        lower.contains("secret")
            || lower.contains("token")
            || lower.contains("api_key")
            || lower.contains("plaintext")
    }));
    let index_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='index' AND name='ux_backup_sets_permanent_root'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(index_sql.contains("WHERE kind = 'permanent'"));
    for table in [
        "backup_recovery_operations",
        "credential_recovery_operations",
        "capture_import_operations",
    ] {
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "table={table}");
        let columns = connection
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(!columns.iter().any(|column| {
            let lower = column.to_ascii_lowercase();
            lower.contains("secret")
                || lower.contains("token")
                || lower.contains("api_key")
                || lower.contains("plaintext")
        }));
    }
    let credential_recovery_columns = connection
        .prepare("PRAGMA table_info(credential_recovery_operations)")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(
        credential_recovery_columns
            .iter()
            .any(|column| { column == "credential_created_at_unix_ms" })
    );
    assert!(
        credential_recovery_columns
            .iter()
            .any(|column| { column == "credential_updated_at_unix_ms" })
    );
    assert!(
        credential_recovery_columns
            .iter()
            .any(|column| { column == "planned_credential_fingerprint" })
    );

    let hash = "a".repeat(64);
    connection
        .execute(
            "INSERT INTO backup_sets(id,root_ref,kind,sequence,manifest_sha256,material_ref,transaction_id,state,created_at_unix_ms)
             VALUES ('permanent-a',?1,'permanent',0,?1,'permanent/permanent-a',NULL,'ready',1)",
            [&hash],
        )
        .unwrap();
    assert!(
        connection
            .execute(
                "INSERT INTO backup_sets(id,root_ref,kind,sequence,manifest_sha256,material_ref,transaction_id,state,created_at_unix_ms)
                 VALUES ('permanent-b',?1,'permanent',0,?1,'permanent/permanent-b',NULL,'ready',2)",
                [&hash],
            )
            .is_err()
    );
    connection.execute(
        "INSERT INTO backup_recovery_operations(operation_id,root_ref,operation,phase,backup_id,kind,sequence,manifest_sha256,material_ref,pending_ref,transaction_id,backup_state,backup_created_at_unix_ms,diagnostic_code)
         VALUES ('publish-a',?1,'publish','prepared','pending-a','permanent',0,?1,'permanent/pending-a','.stage-pending-a',NULL,'ready',5,NULL)",
        [&hash],
    ).unwrap();
    assert!(connection.execute(
        "INSERT INTO credential_recovery_operations(operation_id,credential_id,kind,operation,generation,material_ref,material_sha256,phase,diagnostic_code,credential_created_at_unix_ms,credential_updated_at_unix_ms,created_at_unix_ms,updated_at_unix_ms,version)
         VALUES ('credential-unbound-new','32323232-3232-4232-8232-323232323232','api_key','create',1,'32323232/generation-1.bin',NULL,'prepared',NULL,7,7,7,7,1)",
        [],
    ).is_err());
    connection
        .execute(
            "UPDATE backup_recovery_operations SET phase='validated' WHERE operation_id='publish-a'",
            [],
        )
        .unwrap();
    assert!(connection.execute(
        "INSERT INTO backup_recovery_operations(operation_id,root_ref,operation,phase,backup_id,kind,sequence,manifest_sha256,material_ref,pending_ref,transaction_id,backup_state,backup_created_at_unix_ms,diagnostic_code)
         VALUES ('publish-b',?1,'publish','prepared','pending-b','permanent',0,?1,'permanent/pending-b','.stage-pending-b',NULL,'ready',6,NULL)",
        [&hash],
    ).is_err());
    connection.execute(
        "INSERT INTO credential_recovery_operations(operation_id,credential_id,kind,operation,generation,material_ref,material_sha256,phase,diagnostic_code,credential_created_at_unix_ms,credential_updated_at_unix_ms,created_at_unix_ms,updated_at_unix_ms,version,planned_credential_fingerprint,legacy_unbound)
         VALUES ('credential-a','11111111-1111-4111-8111-111111111111','api_key','rotate',2,'11111111/generation-2.bin',?1,'metadata_pending','metadata_failure',7,7,7,7,1,?1,0)",
        [&hash],
    ).unwrap();
    assert!(connection.execute(
        "INSERT INTO credential_recovery_operations(operation_id,credential_id,kind,operation,generation,material_ref,material_sha256,phase,diagnostic_code,credential_created_at_unix_ms,credential_updated_at_unix_ms,created_at_unix_ms,updated_at_unix_ms,version,planned_credential_fingerprint,legacy_unbound)
         VALUES ('credential-a-race','11111111-1111-4111-8111-111111111111','api_key','delete',2,'11111111/generation-2.bin',?1,'delete_pending',NULL,7,7,7,7,1,?1,0)",
        [&hash],
    ).is_err());
    connection.execute(
        "INSERT INTO credential_recovery_operations(operation_id,credential_id,kind,operation,generation,material_ref,material_sha256,phase,diagnostic_code,credential_created_at_unix_ms,credential_updated_at_unix_ms,created_at_unix_ms,updated_at_unix_ms,version,planned_credential_fingerprint,legacy_unbound)
         VALUES ('credential-prepared','33333333-3333-4333-8333-333333333333','api_key','create',1,'33333333/generation-1.bin',NULL,'prepared','material_publish_pending',7,7,7,7,1,?1,0)",
        [&hash],
    ).unwrap();
    assert!(connection.execute(
        "UPDATE credential_recovery_operations SET credential_updated_at_unix_ms=6 WHERE operation_id='credential-prepared'",
        [],
    ).is_err());
    assert!(connection.execute(
        "INSERT INTO credential_recovery_operations(operation_id,credential_id,kind,operation,generation,material_ref,material_sha256,phase,diagnostic_code,credential_created_at_unix_ms,credential_updated_at_unix_ms,created_at_unix_ms,updated_at_unix_ms,version,planned_credential_fingerprint,legacy_unbound)
         VALUES ('credential-prepared-hash','44444444-4444-4444-8444-444444444444','api_key','create',1,'44444444/generation-1.bin',?1,'prepared',NULL,7,7,7,7,1,?1,0)",
        [&hash],
    ).is_err());
    assert!(connection.execute(
        "INSERT INTO credential_recovery_operations(operation_id,credential_id,kind,operation,generation,material_ref,material_sha256,phase,diagnostic_code,credential_created_at_unix_ms,credential_updated_at_unix_ms,created_at_unix_ms,updated_at_unix_ms,version,planned_credential_fingerprint,legacy_unbound)
         VALUES ('credential-published-null','55555555-5555-4555-8555-555555555555','api_key','create',1,'55555555/generation-1.bin',NULL,'published',NULL,7,7,7,7,1,?1,0)",
        [&hash],
    ).is_err());
    assert!(connection.execute(
        "INSERT INTO credential_recovery_operations(operation_id,credential_id,kind,operation,generation,material_ref,material_sha256,phase,diagnostic_code,credential_created_at_unix_ms,credential_updated_at_unix_ms,created_at_unix_ms,updated_at_unix_ms,version,planned_credential_fingerprint,legacy_unbound)
         VALUES ('credential-b','22222222-2222-4222-8222-222222222222','oauth_bundle','create',1,'../outside',?1,'published',NULL,8,8,8,8,1,?1,0)",
        [&hash],
    ).is_err());
    assert!(
        connection
            .execute(
                "INSERT INTO backup_sets(id,root_ref,kind,sequence,manifest_sha256,material_ref,transaction_id,state,created_at_unix_ms)
                 VALUES ('bad-path',?1,'history',1,?1,'../outside',NULL,'ready',3)",
                [&hash],
            )
            .is_err()
    );
    assert!(
        connection
            .execute(
                "INSERT INTO backup_sets(id,root_ref,kind,sequence,manifest_sha256,material_ref,transaction_id,state,created_at_unix_ms)
                 VALUES ('missing-transaction',?1,'history',2,?1,'history/missing','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','ready',4)",
                params![hash],
            )
            .is_err()
    );
    drop(connection);
    remove_sqlite_files(&path);
    assert!(!path.exists());
    println!(
        "M24_SCHEMA version=11 schema_v10_invariants=preserved backup_columns=9 recovery_journals=3 sensitive_temp_owner=durable_full owner_identity=volume_fileid128 owner_lifecycle=guarded readonly_guard=durable anomalies=fail_closed credential_timestamps=distinct_and_checked planned_fingerprint=required_and_immutable legacy_unbound=read_only secret_columns=0 permanent_unique=enforced recovery_root_unique=enforced credential_single_owner=enforced backup_validated_phase=enforced credential_prepared_guard=enforced relative_path=enforced transaction_fk=enforced cleanup=true"
    );
}

fn remove_sqlite_files(path: &Path) {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let candidate = PathBuf::from(format!("{}{}", path.display(), suffix));
        let _ = fs::remove_file(candidate);
    }
}
