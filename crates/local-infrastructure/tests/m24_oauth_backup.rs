#![allow(unused_crate_dependencies)]

use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use codex_application::{
    BackupKind, BackupRepository, BackupStoreError, CredentialReferenceRepository, FileBaseline,
    OAuthCaptureError,
};
use codex_domain::{CredentialRefId, SwitchTransactionId, UnixMillis};
use local_infrastructure::{
    BackupFaultPoint, BackupService, NoBackupFaults, OAuthCaptureRequest, OAuthCaptureService,
    SqliteMetadataRepository, SystemOAuthProcessRunner,
};
use windows_platform::WindowsDpapiCredentialStore;

const CONFIG: &[u8] = b"model = \"gpt-SAMPLE-1\"\nmodel_provider = \"sample\"\n[model_providers.sample]\nname = \"Sample Provider\"\nbase_url = \"https://HOST/v1\"\n";
const AUTH: &[u8] = b"{\"OPENAI_API_KEY\":\"TOKEN\"}\n";

struct TempArea {
    root: PathBuf,
}
impl TempArea {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "codextools-m24-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        Self { root }
    }
    fn live(&self) -> PathBuf {
        let path = self.root.join("live");
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("config.toml"), CONFIG).unwrap();
        fs::write(path.join("auth.json"), AUTH).unwrap();
        path
    }
}
impl Drop for TempArea {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn helper() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_m24-oauth-helper"))
}

#[test]
fn oauth_helper_state_matrix_cleans_capture_and_changes_no_existing_credential_on_failure() {
    let cases = [
        ("success", Ok(())),
        ("cancel", Err(OAuthCaptureError::Cancelled)),
        ("timeout", Err(OAuthCaptureError::TimedOut)),
        ("abnormal", Err(OAuthCaptureError::ProcessFailed)),
        ("no_auth", Err(OAuthCaptureError::MissingAuthentication)),
        ("unknown", Err(OAuthCaptureError::CompatibilityProtected)),
        ("outside", Err(OAuthCaptureError::OutsideWriteDetected)),
    ];
    for (index, (mode, expected)) in cases.into_iter().enumerate() {
        let area = TempArea::new(&format!("oauth-{mode}"));
        let audit = area.root.join("audit");
        fs::create_dir(&audit).unwrap();
        fs::write(audit.join("sentinel.txt"), b"UNCHANGED").unwrap();
        let mut repository =
            SqliteMetadataRepository::open(area.root.join("metadata.sqlite3")).unwrap();
        let mut store = WindowsDpapiCredentialStore::new(area.root.join("credentials")).unwrap();
        let mut runner = SystemOAuthProcessRunner;
        let result = OAuthCaptureService::capture(
            &mut repository,
            &mut store,
            &mut runner,
            OAuthCaptureRequest {
                executable: helper(),
                audit_root: audit.clone(),
                capture_id: format!("case-{index}"),
                mode: mode.to_owned(),
                timeout: Duration::from_millis(100),
                credential_id: CredentialRefId::parse(&format!(
                    "{:08x}-1111-4111-8111-111111111111",
                    index + 1
                ))
                .unwrap(),
                now: UnixMillis::new(100 + index as i64).unwrap(),
                minimal_config: CONFIG.to_vec(),
            },
        );
        let succeeded = result.is_ok();
        match expected {
            Ok(()) => {
                let reference = result.as_ref().unwrap();
                assert_eq!(reference.kind(), codex_domain::CredentialKind::OAuthBundle);
                assert_eq!(repository.list_credential_references().unwrap().len(), 1);
            }
            Err(error) => {
                assert_eq!(result, Err(error), "mode={mode}");
                assert!(repository.list_credential_references().unwrap().is_empty());
                let credential_root = area.root.join("credentials");
                assert!(
                    !credential_root.exists()
                        || fs::read_dir(&credential_root).unwrap().all(|entry| {
                            entry.is_ok_and(|entry| entry.file_name().to_string_lossy() == ".locks")
                        })
                );
            }
        }
        assert_eq!(fs::read(audit.join("sentinel.txt")).unwrap(), b"UNCHANGED");
        assert!(!fs::read_dir(&audit).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("capture-")
        }));
        let marker = oauth_runtime_marker();
        for path in files_recursive(&area.root) {
            let bytes = fs::read(path).unwrap();
            assert!(!bytes.windows(marker.len()).any(|window| window == marker));
        }
        println!(
            "M24_OAUTH mode={mode} result={} capture_residue=0",
            if succeeded { "stored" } else { "unchanged" }
        );
    }
}

fn oauth_runtime_marker() -> Vec<u8> {
    let mut marker = Vec::from(&b"sk-"[..]);
    marker.extend(std::iter::repeat_n(b'O', 40));
    marker
}

#[test]
fn oauth_capture_id_cannot_escape_explicit_audit_root() {
    let area = TempArea::new("oauth-capture-boundary");
    let audit = area.root.join("audit");
    fs::create_dir(&audit).unwrap();
    let mut repository =
        SqliteMetadataRepository::open(area.root.join("metadata.sqlite3")).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(area.root.join("credentials")).unwrap();
    let mut runner = SystemOAuthProcessRunner;
    let result = OAuthCaptureService::capture(
        &mut repository,
        &mut store,
        &mut runner,
        OAuthCaptureRequest {
            executable: helper(),
            audit_root: audit.clone(),
            capture_id: "../outside".to_owned(),
            mode: "success".to_owned(),
            timeout: Duration::from_millis(100),
            credential_id: CredentialRefId::parse("99999999-9999-4999-8999-999999999999").unwrap(),
            now: UnixMillis::new(1).unwrap(),
            minimal_config: CONFIG.to_vec(),
        },
    );
    assert_eq!(result, Err(OAuthCaptureError::IoFailure));
    assert_eq!(fs::read_dir(&audit).unwrap().count(), 0);
    assert!(repository.list_credential_references().unwrap().is_empty());
    println!("M24_OAUTH_BOUNDARY capture_id_escape=rejected process_started=false");
}

#[test]
fn permanent_and_twelve_history_backups_rotate_deterministically() {
    let area = TempArea::new("backup-rotation");
    let live = area.live();
    let marker = oauth_runtime_marker();
    let mut secret_auth = Vec::from(&b"{\"OPENAI_API_KEY\":\""[..]);
    secret_auth.extend_from_slice(&marker);
    secret_auth.extend_from_slice(b"\"}\n");
    fs::write(live.join("auth.json"), secret_auth).unwrap();
    let backups = area.root.join("backups");
    let mut repository =
        SqliteMetadataRepository::open(area.root.join("metadata.sqlite3")).unwrap();
    {
        let mut faults = NoBackupFaults;
        let mut service = BackupService::new(&mut repository, &mut faults);
        let permanent = service
            .create_permanent(&live, &backups, "first-import", UnixMillis::new(1).unwrap())
            .unwrap();
        let permanent_again = service
            .create_permanent(
                &live,
                &backups,
                "ignored-second-id",
                UnixMillis::new(2).unwrap(),
            )
            .unwrap();
        assert_eq!(permanent.id, permanent_again.id);
        for sequence in 1..=12_u64 {
            service
                .create_history(
                    &live,
                    &backups,
                    &format!("history-{sequence}"),
                    None,
                    sequence == 1,
                    UnixMillis::new(10 + sequence as i64).unwrap(),
                )
                .unwrap_or_else(|error| panic!("sequence={sequence} error={error}"));
        }
    }
    let root_ref = codex_adapter::hash_bytes(
        fs::canonicalize(&live)
            .unwrap()
            .to_string_lossy()
            .to_lowercase()
            .as_bytes(),
    );
    let records = repository.list_backups(&root_ref).unwrap();
    assert_eq!(
        records
            .iter()
            .filter(|record| record.kind == BackupKind::Permanent)
            .count(),
        1
    );
    let history = records
        .iter()
        .filter(|record| record.kind == BackupKind::History)
        .collect::<Vec<_>>();
    assert_eq!(history.len(), 10);
    assert!(history.iter().any(|record| record.id == "history-1"));
    assert!(
        !history
            .iter()
            .any(|record| record.id == "history-2" || record.id == "history-3")
    );
    for path in files_recursive(&backups) {
        let bytes = fs::read(path).unwrap();
        assert!(!bytes.windows(marker.len()).any(|window| window == marker));
    }
    println!(
        "M24_BACKUP permanent=1 history=10 generated=12 protected_history_1=retained evicted=2,3 auth_plaintext=false"
    );
}

#[test]
fn backup_fault_matrix_keeps_complete_old_or_new_sets() {
    for (index, point) in [
        BackupFaultPoint::ConfigWrite,
        BackupFaultPoint::AuthEncryption,
        BackupFaultPoint::AuthWrite,
        BackupFaultPoint::ManifestWrite,
        BackupFaultPoint::Publish,
        BackupFaultPoint::Metadata,
    ]
    .into_iter()
    .enumerate()
    {
        let area = TempArea::new(&format!("backup-fault-{index}"));
        let live = area.live();
        let backups = area.root.join("backups");
        let mut repository =
            SqliteMetadataRepository::open(area.root.join("metadata.sqlite3")).unwrap();
        let mut faults = OneFault(Some(point));
        let result = BackupService::new(&mut repository, &mut faults).create_permanent(
            &live,
            &backups,
            &format!("fault-{index}"),
            UnixMillis::new(1).unwrap(),
        );
        assert!(result.is_err());
        let root_ref = codex_adapter::hash_bytes(
            fs::canonicalize(&live)
                .unwrap()
                .to_string_lossy()
                .to_lowercase()
                .as_bytes(),
        );
        let rows = repository.list_backups(&root_ref).unwrap();
        if point == BackupFaultPoint::Metadata {
            assert_eq!(result, Err(BackupStoreError::RecoveryRequired));
            assert!(
                files_recursive(&backups)
                    .iter()
                    .any(|path| path.ends_with("manifest.v2"))
            );
        } else {
            assert!(rows.is_empty());
            assert!(
                !backups.exists()
                    || !files_recursive(&backups)
                        .iter()
                        .any(|path| path.ends_with("manifest.v2"))
            );
        }
        println!(
            "M24_BACKUP_FAULT point={point:?} database_rows={} complete_or_absent=true",
            rows.len()
        );
    }
}

#[test]
fn rotation_failure_preserves_complete_new_set_and_retry_reaches_limit() {
    let area = TempArea::new("backup-rotation-fault");
    let live = area.live();
    let backups = area.root.join("backups");
    let mut repository =
        SqliteMetadataRepository::open(area.root.join("metadata.sqlite3")).unwrap();
    {
        let mut faults = NoBackupFaults;
        let mut service = BackupService::new(&mut repository, &mut faults);
        for sequence in 1..=10_u64 {
            service
                .create_history(
                    &live,
                    &backups,
                    &format!("stable-{sequence}"),
                    None,
                    false,
                    UnixMillis::new(sequence as i64).unwrap(),
                )
                .unwrap();
        }
    }
    let mut fault = OneFault(Some(BackupFaultPoint::RotationDelete));
    let result = BackupService::new(&mut repository, &mut fault).create_history(
        &live,
        &backups,
        "faulted-11",
        None,
        false,
        UnixMillis::new(11).unwrap(),
    );
    assert_eq!(result, Err(BackupStoreError::RecoveryRequired));
    let root_ref = root_reference(&live);
    let eleven = repository.list_backups(&root_ref).unwrap();
    assert_eq!(eleven.len(), 11);
    assert!(eleven.iter().all(|record| {
        backups
            .join(&record.material_ref)
            .join("manifest.v2")
            .is_file()
    }));
    {
        let mut faults = NoBackupFaults;
        BackupService::new(&mut repository, &mut faults)
            .create_history(
                &live,
                &backups,
                "retry-12",
                None,
                false,
                UnixMillis::new(12).unwrap(),
            )
            .unwrap();
    }
    assert_eq!(repository.list_backups(&root_ref).unwrap().len(), 10);
    println!(
        "M24_BACKUP_ROTATION_FAULT before=10 fault_result=recovery_required complete_set=11 retry_result=10"
    );
}

#[test]
fn unfinished_transaction_referenced_history_is_not_rotated() {
    let area = TempArea::new("backup-transaction-protection");
    let live = area.live();
    let backups = area.root.join("backups");
    let database = area.root.join("metadata.sqlite3");
    SqliteMetadataRepository::open(&database).unwrap();
    let transaction_id =
        SwitchTransactionId::parse("88888888-8888-4888-8888-888888888888").unwrap();
    insert_planned_transaction(&database, transaction_id.as_str());
    let mut repository = SqliteMetadataRepository::open(&database).unwrap();
    let mut faults = NoBackupFaults;
    let mut service = BackupService::new(&mut repository, &mut faults);
    for sequence in 1..=12_u64 {
        service
            .create_history(
                &live,
                &backups,
                &format!("transaction-{sequence}"),
                (sequence == 1).then(|| transaction_id.clone()),
                false,
                UnixMillis::new(sequence as i64).unwrap(),
            )
            .unwrap();
    }
    let records = repository.list_backups(&root_reference(&live)).unwrap();
    assert_eq!(records.len(), 10);
    assert!(records.iter().any(|record| record.id == "transaction-1"));
    assert!(
        !records
            .iter()
            .any(|record| { record.id == "transaction-2" || record.id == "transaction-3" })
    );
    println!(
        "M24_BACKUP_TRANSACTION_PROTECTION unfinished_reference=retained history=10 evicted=2,3"
    );
}

#[test]
fn backup_restore_planning_reuses_lock_and_plan_stale_boundary() {
    let area = TempArea::new("backup-restore-plan");
    let live = area.live();
    let backups = area.root.join("backups");
    let mut repository =
        SqliteMetadataRepository::open(area.root.join("metadata.sqlite3")).unwrap();
    let mut faults = NoBackupFaults;
    let mut service = BackupService::new(&mut repository, &mut faults);
    set_readonly(&live.join("config.toml"), true);
    set_readonly(&live.join("auth.json"), true);
    let permanent = service
        .create_permanent(
            &live,
            &backups,
            "restore-source",
            UnixMillis::new(1).unwrap(),
        )
        .unwrap();
    set_readonly(&live.join("config.toml"), false);
    set_readonly(&live.join("auth.json"), false);
    fs::write(
        live.join("config.toml"),
        CONFIG.replace_ascii(b"gpt-SAMPLE-1", b"gpt-TARGET-1"),
    )
    .unwrap();
    let config_now = fs::read(live.join("config.toml")).unwrap();
    let auth_now = fs::read(live.join("auth.json")).unwrap();
    let expected_config = FileBaseline::present(
        config_now.len() as u64,
        codex_adapter::hash_bytes(&config_now),
    );
    let expected_auth =
        FileBaseline::present(auth_now.len() as u64, codex_adapter::hash_bytes(&auth_now));
    let target = service
        .plan_restore(
            &live,
            &backups,
            &permanent,
            &expected_config,
            &expected_auth,
            UnixMillis::new(1).unwrap(),
            UnixMillis::new(10).unwrap(),
            UnixMillis::new(2).unwrap(),
        )
        .unwrap();
    assert_eq!(target.config.as_deref(), Some(CONFIG));
    assert_eq!(target.auth.as_deref(), Some(AUTH));
    assert!(target.config_readonly);
    assert!(target.auth_readonly);
    assert!(matches!(
        service.plan_restore(
            &live,
            &backups,
            &permanent,
            &expected_config,
            &expected_auth,
            UnixMillis::new(1).unwrap(),
            UnixMillis::new(2).unwrap(),
            UnixMillis::new(2).unwrap()
        ),
        Err(BackupStoreError::PlanStale)
    ));
    fs::write(
        live.join("auth.json"),
        b"{\"OPENAI_API_KEY\":\"TOKEN-EXTERNAL\"}\n",
    )
    .unwrap();
    assert!(matches!(
        service.plan_restore(
            &live,
            &backups,
            &permanent,
            &expected_config,
            &expected_auth,
            UnixMillis::new(1).unwrap(),
            UnixMillis::new(10).unwrap(),
            UnixMillis::new(3).unwrap()
        ),
        Err(BackupStoreError::PlanStale)
    ));
    println!(
        "M24_BACKUP_RESTORE explicit_root_lock=true target_loaded=true expired=plan_stale external_change=plan_stale live_overwrite=false"
    );
}

#[test]
fn permanent_idempotency_rejects_corrupt_encrypted_material() {
    let area = TempArea::new("backup-permanent-corruption");
    let live = area.live();
    let backups = area.root.join("backups");
    let mut repository =
        SqliteMetadataRepository::open(area.root.join("metadata.sqlite3")).unwrap();
    let mut faults = NoBackupFaults;
    let mut service = BackupService::new(&mut repository, &mut faults);
    let record = service
        .create_permanent(
            &live,
            &backups,
            "permanent-corrupt",
            UnixMillis::new(1).unwrap(),
        )
        .unwrap();
    let auth_path = backups.join(&record.material_ref).join("auth.dpapi");
    let mut encrypted = fs::read(&auth_path).unwrap();
    *encrypted.last_mut().unwrap() ^= 0x55;
    fs::write(auth_path, encrypted).unwrap();
    assert_eq!(
        service.create_permanent(
            &live,
            &backups,
            "ignored-new-id",
            UnixMillis::new(2).unwrap()
        ),
        Err(BackupStoreError::CorruptMaterial)
    );
    println!("M24_BACKUP_PERMANENT idempotent=true corrupt_material=rejected");
}

struct OneFault(Option<BackupFaultPoint>);
impl local_infrastructure::BackupFaults for OneFault {
    fn fail(&mut self, point: BackupFaultPoint) -> bool {
        if self.0 == Some(point) {
            self.0 = None;
            true
        } else {
            false
        }
    }
}

fn files_recursive(root: &Path) -> Vec<PathBuf> {
    fn visit(path: &Path, files: &mut Vec<PathBuf>) {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    visit(&path, files);
                } else {
                    files.push(path);
                }
            }
        }
    }
    let mut files = Vec::new();
    visit(root, &mut files);
    files
}

fn root_reference(live: &Path) -> codex_domain::ContentHash {
    codex_adapter::hash_bytes(
        fs::canonicalize(live)
            .unwrap()
            .to_string_lossy()
            .to_lowercase()
            .as_bytes(),
    )
}

fn insert_planned_transaction(database: &Path, id: &str) {
    let connection = rusqlite::Connection::open(database).unwrap();
    let hash = "a".repeat(64);
    connection
        .execute(
            "INSERT INTO switch_transactions(
                id, root_ref, config_source_sha256, auth_source_sha256,
                config_target_sha256, auth_target_sha256, target_provider_id,
                target_model_id, target_auth_fingerprint, snapshot_manifest_sha256,
                state, completed_roles, last_error_code, created_at_unix_ms,
                updated_at_unix_ms, version
             ) VALUES (?1, ?2, ?2, ?2, ?2, ?2, 'sample', 'gpt-SAMPLE-1', ?2,
                       NULL, 'planned', 0, NULL, 1, 1, 1)",
            rusqlite::params![id, hash],
        )
        .unwrap();
}

fn set_readonly(path: &Path, readonly: bool) {
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_readonly(readonly);
    fs::set_permissions(path, permissions).unwrap();
}

trait ReplaceAscii {
    fn replace_ascii(&self, from: &[u8], to: &[u8]) -> Vec<u8>;
}
impl ReplaceAscii for [u8] {
    fn replace_ascii(&self, from: &[u8], to: &[u8]) -> Vec<u8> {
        let position = self
            .windows(from.len())
            .position(|window| window == from)
            .unwrap();
        let mut value = Vec::new();
        value.extend_from_slice(&self[..position]);
        value.extend_from_slice(to);
        value.extend_from_slice(&self[position + from.len()..]);
        value
    }
}
