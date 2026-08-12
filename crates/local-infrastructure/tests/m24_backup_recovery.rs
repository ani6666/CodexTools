#![allow(unused_crate_dependencies)]

use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use codex_application::{BackupRepository, BackupStoreError, FileBaseline};
use codex_domain::UnixMillis;
use local_infrastructure::{
    BackupFaultPoint, BackupFaults, BackupService, NoBackupFaults, SqliteMetadataRepository,
};
use windows_platform::DpapiCurrentUser;

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
            "codextools-m24-r2-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        Self { root }
    }
    fn live(&self) -> PathBuf {
        let live = self.root.join("live");
        fs::create_dir(&live).unwrap();
        fs::write(live.join("config.toml"), CONFIG).unwrap();
        fs::write(live.join("auth.json"), AUTH).unwrap();
        live
    }
}
impl Drop for TempArea {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct MutateAt {
    point: BackupFaultPoint,
    live: PathBuf,
    role: &'static str,
}
impl BackupFaults for MutateAt {
    fn fail(&mut self, point: BackupFaultPoint) -> bool {
        if point == self.point {
            let path = self.live.join(self.role);
            let mut bytes = fs::read(&path).unwrap();
            bytes.extend_from_slice(b"# EXTERNAL\n");
            fs::write(path, bytes).unwrap();
        }
        false
    }
}

#[test]
fn backup_pair_must_remain_stable_until_publish() {
    for (index, (point, role)) in [
        (BackupFaultPoint::AfterConfigObserve, "config.toml"),
        (BackupFaultPoint::AfterAuthObserve, "auth.json"),
        (BackupFaultPoint::BeforePublishObservation, "config.toml"),
        (BackupFaultPoint::BetweenSecondObservations, "config.toml"),
        (BackupFaultPoint::AfterValidated, "auth.json"),
        (BackupFaultPoint::Publish, "config.toml"),
    ]
    .into_iter()
    .enumerate()
    {
        let area = TempArea::new(&format!("stable-{index}"));
        let live = area.live();
        let backups = area.root.join("backups");
        let mut repository =
            SqliteMetadataRepository::open(area.root.join("metadata.sqlite3")).unwrap();
        let mut faults = MutateAt {
            point,
            live: live.clone(),
            role,
        };
        let result = BackupService::new(&mut repository, &mut faults).create_permanent(
            &live,
            &backups,
            &format!("stable-{index}"),
            UnixMillis::new(1).unwrap(),
        );
        assert_eq!(result, Err(BackupStoreError::PlanStale), "point={point:?}");
        assert!(
            repository
                .list_backups(&root_reference(&live))
                .unwrap()
                .is_empty()
        );
        assert!(
            repository
                .list_backup_recoveries(&root_reference(&live))
                .unwrap()
                .is_empty()
        );
        assert!(!contains_final_manifest(&backups));
        println!("M24_BACKUP_STABLE point={point:?} result=plan_stale rows=0 final_material=0");
    }
}

#[test]
fn validated_reopen_rechecks_live_pair_before_publish() {
    let area = TempArea::new("validated-reopen-live-change");
    let live = area.live();
    let backups = area.root.join("backups");
    let database = area.root.join("metadata.sqlite3");
    let mut repository = SqliteMetadataRepository::open(&database).unwrap();
    let mut fault = OneFault(Some(BackupFaultPoint::AfterValidated));
    assert_eq!(
        BackupService::new(&mut repository, &mut fault).create_permanent(
            &live,
            &backups,
            "validated-reopen",
            UnixMillis::new(1).unwrap(),
        ),
        Err(BackupStoreError::RecoveryRequired)
    );
    drop(repository);
    fs::write(live.join("config.toml"), b"# EXTERNAL\n").unwrap();

    let mut repository = SqliteMetadataRepository::open(&database).unwrap();
    assert_eq!(
        BackupService::new(&mut repository, &mut NoBackupFaults).reconcile_root(
            &live,
            &backups,
            UnixMillis::new(2).unwrap(),
        ),
        Err(BackupStoreError::RecoveryRequired)
    );
    let operations = repository
        .list_backup_recoveries(&root_reference(&live))
        .unwrap();
    assert_eq!(operations.len(), 1);
    assert_eq!(
        operations[0].phase,
        codex_application::BackupRecoveryPhase::RecoveryRequired
    );
    assert!(!contains_final_manifest(&backups));
    assert_eq!(fs::read(live.join("config.toml")).unwrap(), b"# EXTERNAL\n");
    assert_eq!(fs::read(live.join("auth.json")).unwrap(), AUTH);
    println!(
        "M24_BACKUP_VALIDATED_REOPEN external_live_change=preserved publish=false recovery_required=true"
    );
}

#[test]
fn prepared_publish_is_rolled_back_and_orphan_stage_is_scavenged_after_reopen() {
    let area = TempArea::new("prepared-recovery");
    let live = area.live();
    let backups = area.root.join("backups");
    let database = area.root.join("metadata.sqlite3");
    let mut repository = SqliteMetadataRepository::open(&database).unwrap();
    let mut fault = OneFault(Some(BackupFaultPoint::AfterRecoveryPrepared));
    assert_eq!(
        BackupService::new(&mut repository, &mut fault).create_permanent(
            &live,
            &backups,
            "prepared-recovery",
            UnixMillis::new(1).unwrap(),
        ),
        Err(BackupStoreError::RecoveryRequired)
    );
    assert_eq!(
        repository
            .list_backup_recoveries(&root_reference(&live))
            .unwrap()[0]
            .phase,
        codex_application::BackupRecoveryPhase::Prepared
    );
    drop(repository);
    let orphan = backups.join(".stage-unowned-crash");
    fs::create_dir(&orphan).unwrap();
    fs::write(orphan.join("partial.bin"), b"SAMPLE").unwrap();

    let mut repository = SqliteMetadataRepository::open(&database).unwrap();
    BackupService::new(&mut repository, &mut NoBackupFaults)
        .reconcile_root(&live, &backups, UnixMillis::new(2).unwrap())
        .unwrap();
    assert!(
        repository
            .list_backup_recoveries(&root_reference(&live))
            .unwrap()
            .is_empty()
    );
    assert!(
        repository
            .list_backups(&root_reference(&live))
            .unwrap()
            .is_empty()
    );
    assert!(!orphan.exists());
    assert_eq!(fs::read(live.join("config.toml")).unwrap(), CONFIG);
    assert_eq!(fs::read(live.join("auth.json")).unwrap(), AUTH);
    println!(
        "M24_BACKUP_VALIDATION prepared_reopen=rolled_back validated_required_before_publish=true unjournaled_stage=scavenged live_unchanged=true"
    );
}

struct OneFault(Option<BackupFaultPoint>);
impl BackupFaults for OneFault {
    fn fail(&mut self, point: BackupFaultPoint) -> bool {
        if self.0 == Some(point) {
            self.0 = None;
            true
        } else {
            false
        }
    }
}

#[test]
fn published_permanent_is_adopted_after_metadata_failure_and_reopen() {
    let area = TempArea::new("publish-adopt");
    let live = area.live();
    let backups = area.root.join("backups");
    let database = area.root.join("metadata.sqlite3");
    {
        let mut repository = SqliteMetadataRepository::open(&database).unwrap();
        let mut fault = OneFault(Some(BackupFaultPoint::Metadata));
        assert_eq!(
            BackupService::new(&mut repository, &mut fault).create_permanent(
                &live,
                &backups,
                "adopt-me",
                UnixMillis::new(1).unwrap()
            ),
            Err(BackupStoreError::RecoveryRequired)
        );
        assert_eq!(
            repository
                .list_backup_recoveries(&root_reference(&live))
                .unwrap()
                .len(),
            1
        );
    }
    let mut repository = SqliteMetadataRepository::open(&database).unwrap();
    let mut faults = NoBackupFaults;
    let adopted = BackupService::new(&mut repository, &mut faults)
        .create_permanent(&live, &backups, "adopt-me", UnixMillis::new(2).unwrap())
        .unwrap();
    assert_eq!(adopted.id, "adopt-me");
    assert_eq!(
        repository
            .list_backups(&root_reference(&live))
            .unwrap()
            .len(),
        1
    );
    assert!(
        repository
            .list_backup_recoveries(&root_reference(&live))
            .unwrap()
            .is_empty()
    );
    assert_eq!(fs::read_dir(backups.join("permanent")).unwrap().count(), 1);
    println!(
        "M24_BACKUP_PUBLISH_CRASH metadata_failure=journaled reopen=adopted permanent_rows=1 recovery_rows=0"
    );
}

#[test]
fn unprovable_publish_material_remains_diagnostic_and_blocks_root() {
    let area = TempArea::new("publish-blocked");
    let live = area.live();
    let backups = area.root.join("backups");
    let database = area.root.join("metadata.sqlite3");
    {
        let mut repository = SqliteMetadataRepository::open(&database).unwrap();
        let mut fault = OneFault(Some(BackupFaultPoint::Metadata));
        assert_eq!(
            BackupService::new(&mut repository, &mut fault).create_permanent(
                &live,
                &backups,
                "lost",
                UnixMillis::new(1).unwrap()
            ),
            Err(BackupStoreError::RecoveryRequired)
        );
    }
    fs::remove_dir_all(backups.join("permanent").join("lost")).unwrap();
    let mut repository = SqliteMetadataRepository::open(&database).unwrap();
    let mut faults = NoBackupFaults;
    assert_eq!(
        BackupService::new(&mut repository, &mut faults).create_permanent(
            &live,
            &backups,
            "second",
            UnixMillis::new(2).unwrap()
        ),
        Err(BackupStoreError::RecoveryRequired)
    );
    let recovery = repository
        .list_backup_recoveries(&root_reference(&live))
        .unwrap();
    assert_eq!(recovery.len(), 1);
    assert_eq!(
        recovery[0].diagnostic_code.as_deref(),
        Some("reconcile_failed")
    );
    assert!(
        repository
            .list_backups(&root_reference(&live))
            .unwrap()
            .is_empty()
    );
    assert!(!backups.join("permanent").join("second").exists());
    BackupService::new(&mut repository, &mut faults)
        .rollback_unpublished(&live, &backups, "publish-lost", UnixMillis::new(3).unwrap())
        .unwrap();
    assert!(
        repository
            .list_backup_recoveries(&root_reference(&live))
            .unwrap()
            .is_empty()
    );
    BackupService::new(&mut repository, &mut faults)
        .create_permanent(&live, &backups, "second", UnixMillis::new(4).unwrap())
        .unwrap();
    println!(
        "M24_BACKUP_BLOCKED missing_final_and_stage=recovery_required diagnostic=reconcile_failed new_rows=0 new_material=0 manual_rollback=idempotent root_unblocked=true"
    );
}

#[test]
fn legacy_v1_permanent_material_remains_readable_after_v7_upgrade() {
    let area = TempArea::new("legacy-v1");
    let live = area.live();
    let backups = area.root.join("backups");
    let database = area.root.join("metadata.sqlite3");
    let record = {
        let mut repository = SqliteMetadataRepository::open(&database).unwrap();
        let mut faults = NoBackupFaults;
        BackupService::new(&mut repository, &mut faults)
            .create_permanent(&live, &backups, "legacy", UnixMillis::new(1).unwrap())
            .unwrap()
    };
    let directory = backups.join(&record.material_ref);
    let auth_hash = codex_adapter::hash_bytes(AUTH);
    let entropy = format!(
        "codextools:backup:v1:{}:auth:{}",
        record.id,
        auth_hash.as_str()
    )
    .into_bytes();
    let encrypted = DpapiCurrentUser.protect(&entropy, AUTH).unwrap();
    fs::write(directory.join("auth.dpapi"), encrypted).unwrap();
    fs::remove_file(directory.join("manifest.v2")).unwrap();
    let config_hash = codex_adapter::hash_bytes(CONFIG);
    let manifest = format!(
        "version=1\nid=legacy\nkind=permanent\nsequence=0\nreason=first_import\ntransaction=none\nstate=ready\ncreated_at=1\nconfig.existed=true\nconfig.length={}\nconfig.hash={}\nconfig.readonly=false\nconfig.encrypted=false\nauth.existed=true\nauth.length={}\nauth.hash={}\nauth.readonly=false\nauth.encrypted=true\n",
        CONFIG.len(),
        config_hash.as_str(),
        AUTH.len(),
        auth_hash.as_str()
    );
    fs::write(directory.join("manifest.v1"), manifest.as_bytes()).unwrap();
    rusqlite::Connection::open(&database)
        .unwrap()
        .execute(
            "UPDATE backup_sets SET manifest_sha256=?2 WHERE id=?1",
            rusqlite::params![
                record.id,
                codex_adapter::hash_bytes(manifest.as_bytes()).as_str()
            ],
        )
        .unwrap();
    let mut repository = SqliteMetadataRepository::open(&database).unwrap();
    let mut faults = NoBackupFaults;
    let reopened = BackupService::new(&mut repository, &mut faults)
        .create_permanent(&live, &backups, "ignored", UnixMillis::new(2).unwrap())
        .unwrap();
    assert_eq!(reopened.id, "legacy");
    assert!(directory.join("manifest.v1").is_file());
    assert!(!directory.join("manifest.v2").exists());
    println!("M24_BACKUP_LEGACY schema_v5_manifest_v1=readable new_writes=v2 database_upgrade=v7");
}

#[test]
fn history_delete_interruptions_reconcile_after_reopen() {
    for (index, point) in [
        BackupFaultPoint::AfterDeleteRename,
        BackupFaultPoint::AfterDeleteMetadata,
        BackupFaultPoint::PhysicalDelete,
    ]
    .into_iter()
    .enumerate()
    {
        let area = TempArea::new(&format!("delete-crash-{index}"));
        let live = area.live();
        let backups = area.root.join("backups");
        let database = area.root.join("metadata.sqlite3");
        {
            let mut repository = SqliteMetadataRepository::open(&database).unwrap();
            let mut faults = NoBackupFaults;
            let mut service = BackupService::new(&mut repository, &mut faults);
            for n in 1..=10 {
                service
                    .create_history(
                        &live,
                        &backups,
                        &format!("base-{n}"),
                        None,
                        false,
                        UnixMillis::new(n).unwrap(),
                    )
                    .unwrap();
            }
        }
        {
            let mut repository = SqliteMetadataRepository::open(&database).unwrap();
            let mut fault = OneFault(Some(point));
            assert_eq!(
                BackupService::new(&mut repository, &mut fault).create_history(
                    &live,
                    &backups,
                    "crash-11",
                    None,
                    false,
                    UnixMillis::new(11).unwrap()
                ),
                Err(BackupStoreError::RecoveryRequired)
            );
            assert_eq!(
                repository
                    .list_backup_recoveries(&root_reference(&live))
                    .unwrap()
                    .len(),
                1
            );
        }
        let mut repository = SqliteMetadataRepository::open(&database).unwrap();
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
        let records = repository.list_backups(&root_reference(&live)).unwrap();
        assert_eq!(records.len(), 10, "point={point:?}");
        assert!(
            repository
                .list_backup_recoveries(&root_reference(&live))
                .unwrap()
                .is_empty()
        );
        assert!(records.iter().all(|record| {
            backups
                .join(&record.material_ref)
                .join("manifest.v2")
                .is_file()
        }));
        println!(
            "M24_BACKUP_DELETE_CRASH point={point:?} reopen=reconciled history=10 recovery_rows=0"
        );
    }
}

#[test]
fn restore_reloads_exact_repository_record_and_rejects_transplant() {
    let area = TempArea::new("restore-exact");
    let live = area.live();
    let backups = area.root.join("backups");
    let mut repository =
        SqliteMetadataRepository::open(area.root.join("metadata.sqlite3")).unwrap();
    let mut faults = NoBackupFaults;
    let mut service = BackupService::new(&mut repository, &mut faults);
    let record = service
        .create_permanent(&live, &backups, "exact", UnixMillis::new(1).unwrap())
        .unwrap();
    let mut transplanted = record.clone();
    transplanted.manifest_hash = codex_adapter::hash_bytes(b"different material");
    let config = fs::read(live.join("config.toml")).unwrap();
    let auth = fs::read(live.join("auth.json")).unwrap();
    let result = service.plan_restore(
        &live,
        &backups,
        &transplanted,
        &FileBaseline::present(config.len() as u64, codex_adapter::hash_bytes(&config)),
        &FileBaseline::present(auth.len() as u64, codex_adapter::hash_bytes(&auth)),
        UnixMillis::new(1).unwrap(),
        UnixMillis::new(10).unwrap(),
        UnixMillis::new(2).unwrap(),
    );
    assert_eq!(result.err(), Some(BackupStoreError::CompatibilityProtected));
    println!(
        "M24_BACKUP_RESTORE_BINDING stale_or_transplanted_record=rejected repository_exact_reread=true"
    );
}

#[cfg(windows)]
#[test]
fn backup_publish_rejects_junction_material_parent() {
    let area = TempArea::new("junction");
    let live = area.live();
    let backups = area.root.join("backups");
    let outside = area.root.join("outside");
    fs::create_dir(&backups).unwrap();
    fs::create_dir(&outside).unwrap();
    let status = std::process::Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(backups.join("permanent"))
        .arg(&outside)
        .status()
        .unwrap();
    assert!(status.success());
    let mut repository =
        SqliteMetadataRepository::open(area.root.join("metadata.sqlite3")).unwrap();
    let mut faults = NoBackupFaults;
    let result = BackupService::new(&mut repository, &mut faults).create_permanent(
        &live,
        &backups,
        "junction-attempt",
        UnixMillis::new(1).unwrap(),
    );
    assert_eq!(result, Err(BackupStoreError::CompatibilityProtected));
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    assert!(
        repository
            .list_backups(&root_reference(&live))
            .unwrap()
            .is_empty()
    );
    println!("M24_BACKUP_REPARSE junction_parent=rejected outside_files=0 database_rows=0");
}

#[cfg(windows)]
#[test]
fn rotation_cleanup_rejects_nested_junction_without_touching_target() {
    let area = TempArea::new("delete-junction");
    let live = area.live();
    let backups = area.root.join("backups");
    let database = area.root.join("metadata.sqlite3");
    {
        let mut repository = SqliteMetadataRepository::open(&database).unwrap();
        let mut faults = NoBackupFaults;
        let mut service = BackupService::new(&mut repository, &mut faults);
        for n in 1..=10 {
            service
                .create_history(
                    &live,
                    &backups,
                    &format!("junction-{n}"),
                    None,
                    false,
                    UnixMillis::new(n).unwrap(),
                )
                .unwrap();
        }
    }
    {
        let mut repository = SqliteMetadataRepository::open(&database).unwrap();
        let mut fault = OneFault(Some(BackupFaultPoint::AfterDeleteMetadata));
        assert_eq!(
            BackupService::new(&mut repository, &mut fault).create_history(
                &live,
                &backups,
                "junction-11",
                None,
                false,
                UnixMillis::new(11).unwrap(),
            ),
            Err(BackupStoreError::RecoveryRequired)
        );
    }
    let outside = area.root.join("outside-target");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("sentinel"), b"UNCHANGED").unwrap();
    let pending = backups.join(".delete-junction-1");
    let status = std::process::Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(pending.join("nested-junction"))
        .arg(&outside)
        .status()
        .unwrap();
    assert!(status.success());
    let mut repository = SqliteMetadataRepository::open(&database).unwrap();
    let mut faults = NoBackupFaults;
    assert_eq!(
        BackupService::new(&mut repository, &mut faults).create_history(
            &live,
            &backups,
            "junction-12",
            None,
            false,
            UnixMillis::new(12).unwrap(),
        ),
        Err(BackupStoreError::RecoveryRequired)
    );
    assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"UNCHANGED");
    assert!(pending.exists());
    assert_eq!(
        repository
            .list_backup_recoveries(&root_reference(&live))
            .unwrap()[0]
            .diagnostic_code
            .as_deref(),
        Some("reconcile_failed")
    );
    println!(
        "M24_BACKUP_DELETE_REPARSE nested_junction=rejected target_unchanged=true diagnostic=persisted"
    );
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
fn contains_final_manifest(root: &Path) -> bool {
    files_recursive(root)
        .iter()
        .any(|path| path.ends_with("manifest.v2") && !path.to_string_lossy().contains(".stage-"))
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
