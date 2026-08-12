#![allow(unused_crate_dependencies)]

use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use codex_adapter::hash_bytes;
use codex_application::{SwitchTransactionRecord, SwitchTransactionRepository};
use codex_domain::{
    CredentialFingerprint, ModelId, ProviderId, SwitchTransaction, SwitchTransactionId,
    SwitchTransactionState, UnixMillis,
};
use local_infrastructure::{
    SensitiveDestinationGuard, SensitiveDestinationState, SensitiveTempLifecycle,
    SensitiveTempOwnerRecord, SensitiveTempPhase, SensitiveTempRole, SqliteMetadataRepository,
};
use rusqlite::Connection;
use windows_platform::FileIdentity128;

struct TempDb(PathBuf);
impl TempDb {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        Self(std::env::temp_dir().join(format!(
            "codextools-owner-schema-{}-{nonce}.sqlite3",
            std::process::id()
        )))
    }
}
impl Drop for TempDb {
    fn drop(&mut self) {
        for suffix in ["", "-journal", "-wal", "-shm"] {
            let _ = fs::remove_file(format!("{}{}", self.0.display(), suffix));
        }
    }
}

fn switch_record() -> SwitchTransactionRecord {
    let hash = hash_bytes(b"OWNER-SCHEMA-NONSECRET");
    SwitchTransactionRecord {
        transaction: SwitchTransaction::new(
            SwitchTransactionId::parse("f1000000-0000-4000-8000-000000000001").unwrap(),
            hash.clone(),
            Some(hash.clone()),
            Some(hash.clone()),
            hash.clone(),
            hash.clone(),
            ProviderId::parse("sample").unwrap(),
            ModelId::parse("gpt-SAMPLE-1").unwrap(),
            CredentialFingerprint::parse(hash.as_str()).unwrap(),
            UnixMillis::new(1).unwrap(),
        ),
        last_error: None,
        snapshot_manifest_hash: None,
    }
}

#[test]
fn v10_owner_lifecycle_guard_and_terminal_blocker_are_cas_durable() {
    let db = TempDb::new();
    let mut repository = SqliteMetadataRepository::open(&db.0).unwrap();
    assert_eq!(
        repository
            .durable_journal_mode()
            .unwrap()
            .to_ascii_lowercase(),
        "delete"
    );
    assert_eq!(repository.durable_synchronous_level().unwrap(), 2);
    let mut tx_record = switch_record();
    repository.create_switch_transaction(&tx_record).unwrap();
    let nonce = [1_u8; 16];
    let mut owner = SensitiveTempOwnerRecord {
        transaction_id: tx_record.transaction.id().clone(),
        root_ref: tx_record.transaction.root_ref().clone(),
        role: SensitiveTempRole::Authentication,
        phase: SensitiveTempPhase::Target,
        nonce,
        temp_rel: format!(
            ".auth.json.{}.{}.stage",
            tx_record.transaction.id().as_str(),
            "01".repeat(16)
        ),
        publish_rel: "auth.json".to_owned(),
        identity: None,
        expected_length: 37,
        expected_hash: hash_bytes(b"OWNER-TARGET-NONSECRET"),
        expected_readonly: true,
        lifecycle: SensitiveTempLifecycle::PrewriteDeleteArmed,
        destination_guard: None,
        created_at: UnixMillis::new(2).unwrap(),
        updated_at: UnixMillis::new(2).unwrap(),
        version: 1,
    };
    repository.create_sensitive_temp_owner(&owner).unwrap();
    let identity = FileIdentity128 {
        volume_serial_number: 7,
        file_id: [9; 16],
    };
    repository
        .bind_sensitive_temp_owner_identity(
            &owner.transaction_id,
            owner.phase,
            owner.role,
            identity,
            1,
            UnixMillis::new(3).unwrap(),
        )
        .unwrap();
    owner.identity = Some(identity);
    owner.version = 2;
    repository
        .transition_sensitive_temp_owner(
            &owner.transaction_id,
            owner.phase,
            owner.role,
            SensitiveTempLifecycle::PrewriteDeleteArmed,
            SensitiveTempLifecycle::Owned,
            owner.version,
            UnixMillis::new(4).unwrap(),
        )
        .unwrap();
    owner.lifecycle = SensitiveTempLifecycle::Owned;
    owner.version = 3;

    let expected_version = tx_record.transaction.version();
    tx_record.transaction = tx_record
        .transaction
        .transition(
            SwitchTransactionState::RolledBack,
            UnixMillis::new(5).unwrap(),
        )
        .unwrap();
    assert!(
        repository
            .update_switch_transaction(&tx_record, expected_version)
            .is_err()
    );

    let guard = SensitiveDestinationGuard {
        state: SensitiveDestinationState::ReadonlyClearArmed,
        identity: FileIdentity128 {
            volume_serial_number: 7,
            file_id: [8; 16],
        },
        length: 11,
        hash_ref: hash_bytes(b"OLD-LIVE-NONSECRET"),
    };
    repository
        .arm_destination_readonly_guard(&owner, &guard, UnixMillis::new(5).unwrap())
        .unwrap();
    owner.destination_guard = Some(guard);
    owner.version = 4;
    repository
        .transition_destination_guard(
            &owner,
            SensitiveDestinationState::ReadonlyClearArmed,
            SensitiveDestinationState::ReadonlyCleared,
            UnixMillis::new(6).unwrap(),
        )
        .unwrap();
    owner.destination_guard.as_mut().unwrap().state = SensitiveDestinationState::ReadonlyCleared;
    owner.version = 5;

    let connection = Connection::open(&db.0).unwrap();
    assert!(connection.execute(
        "UPDATE switch_sensitive_temp_owners SET nonce=zeroblob(16) WHERE transaction_id=?1",
        [owner.transaction_id.as_str()],
    ).is_err());
    drop(connection);

    repository
        .transition_destination_guard(
            &owner,
            SensitiveDestinationState::ReadonlyCleared,
            SensitiveDestinationState::None,
            UnixMillis::new(7).unwrap(),
        )
        .unwrap();
    owner.destination_guard = None;
    owner.version = 6;
    repository
        .transition_sensitive_temp_owner(
            &owner.transaction_id,
            owner.phase,
            owner.role,
            SensitiveTempLifecycle::Owned,
            SensitiveTempLifecycle::CleanupDeleteArmed,
            owner.version,
            UnixMillis::new(8).unwrap(),
        )
        .unwrap();
    owner.lifecycle = SensitiveTempLifecycle::CleanupDeleteArmed;
    owner.version = 7;
    repository.delete_sensitive_temp_owner(&owner).unwrap();
    repository
        .update_switch_transaction(&tx_record, expected_version)
        .unwrap();
    assert!(
        repository
            .list_sensitive_temp_owners(tx_record.transaction.root_ref())
            .unwrap()
            .is_empty()
    );
}
