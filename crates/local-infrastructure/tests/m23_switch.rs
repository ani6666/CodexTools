#![allow(unused_crate_dependencies)]

use std::{
    cell::Cell,
    fs,
    io::{self, BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Barrier},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use codex_adapter::{CodexAdapter, hash_bytes};
use codex_application::{
    Clock, EntityKind, FileBaseline, RepositoryError, ScanStatus, StabilityWindow, SwitchErrorCode,
    SwitchExecutionError, SwitchPlan, SwitchTransactionRecord, SwitchTransactionRepository,
};
use codex_domain::{
    EntityVersion, ModelId, ProviderId, SwitchTransaction, SwitchTransactionId,
    SwitchTransactionState, UnixMillis,
};
use local_infrastructure::{
    CrossProcessWriteLock, FaultDisposition, FaultInjector, FaultPoint, LockDiagnostic,
    OpenRepositoryError, SensitiveTempIo, SqliteMetadataRepository, SwitchExecutor,
};
use rusqlite::Connection;
use windows_platform::SensitiveTempFile;
use zeroize::Zeroizing;

struct TempRoot {
    root: PathBuf,
    db: PathBuf,
}
impl TempRoot {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "codextools-m23-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/g1-api-key");
        fs::copy(fixture.join("config.toml"), root.join("config.toml")).unwrap();
        fs::copy(fixture.join("auth.json"), root.join("auth.json")).unwrap();
        let db = root.join("metadata.sqlite3");
        Self { root, db }
    }
    fn pair(&self) -> (Vec<u8>, Vec<u8>) {
        (
            fs::read(self.root.join("config.toml")).unwrap(),
            fs::read(self.root.join("auth.json")).unwrap(),
        )
    }
}
impl Drop for TempRoot {
    fn drop(&mut self) {
        make_tree_writable(&self.root);
        let _ = fs::remove_dir_all(&self.root);
    }
}
#[allow(clippy::permissions_set_readonly_false)]
fn make_tree_writable(root: &Path) {
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                make_tree_writable(&path)
            } else if let Ok(metadata) = fs::metadata(&path) {
                let mut permissions = metadata.permissions();
                permissions.set_readonly(false);
                let _ = fs::set_permissions(path, permissions);
            }
        }
    }
}

struct FixedClock(i64);
impl Clock for FixedClock {
    fn now(&self) -> UnixMillis {
        UnixMillis::new(self.0).unwrap()
    }
}
struct ExpiringClock {
    calls: Cell<usize>,
    valid_calls: usize,
}
impl ExpiringClock {
    fn after(valid_calls: usize) -> Self {
        Self {
            calls: Cell::new(0),
            valid_calls,
        }
    }
}
impl Clock for ExpiringClock {
    fn now(&self) -> UnixMillis {
        let next = self.calls.get() + 1;
        self.calls.set(next);
        UnixMillis::new(if next <= self.valid_calls { 150 } else { 200 }).unwrap()
    }
}
struct NoWait;
impl StabilityWindow for NoWait {
    fn between_observations(&mut self, _: &Path) -> Result<(), SwitchExecutionError> {
        Ok(())
    }
}
struct MutateWindow;
impl StabilityWindow for MutateWindow {
    fn between_observations(&mut self, root: &Path) -> Result<(), SwitchExecutionError> {
        let mut value = fs::read_to_string(root.join("config.toml")).unwrap();
        value.push_str("external_change = \"KEEP_EXTERNAL\"\n");
        fs::write(root.join("config.toml"), value).unwrap();
        Ok(())
    }
}

#[derive(Default)]
struct ScriptedFault {
    points: Vec<(FaultPoint, FaultDisposition)>,
}
impl ScriptedFault {
    fn fail(point: FaultPoint) -> Self {
        Self {
            points: vec![(point, FaultDisposition::Fail)],
        }
    }
    fn interrupt(point: FaultPoint) -> Self {
        Self {
            points: vec![(point, FaultDisposition::Interrupt)],
        }
    }
}
impl FaultInjector for ScriptedFault {
    fn check(&mut self, point: FaultPoint) -> Option<FaultDisposition> {
        self.points
            .iter()
            .position(|entry| entry.0 == point)
            .map(|index| self.points.remove(index).1)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SensitiveIoBoundary {
    ShortThenFail(usize),
    Write,
    Flush,
    Sync,
    Reread,
    RenameReportedErrorAfterSuccess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SensitiveIoTarget {
    Stage,
    Recovery,
}

struct InjectedSensitiveIo {
    boundary: SensitiveIoBoundary,
    target: SensitiveIoTarget,
    active: bool,
    short_completed: bool,
    fail_remove: bool,
    replace_before_remove: bool,
    replacement_done: bool,
    config_role: bool,
}

impl InjectedSensitiveIo {
    fn new(boundary: SensitiveIoBoundary, target: SensitiveIoTarget) -> Self {
        Self {
            boundary,
            target,
            active: false,
            short_completed: false,
            fail_remove: false,
            replace_before_remove: false,
            replacement_done: false,
            config_role: false,
        }
    }

    fn with_remove_failure(mut self) -> Self {
        self.fail_remove = true;
        self
    }

    fn with_external_replacement(mut self) -> Self {
        self.replace_before_remove = true;
        self
    }

    fn for_config(mut self) -> Self {
        self.config_role = true;
        self
    }
}

impl SensitiveTempIo for InjectedSensitiveIo {
    fn write(&mut self, file: &mut SensitiveTempFile, bytes: &[u8]) -> io::Result<usize> {
        let name = file.basename();
        let phase_matches = match self.target {
            SensitiveIoTarget::Stage => name.ends_with(".stage"),
            SensitiveIoTarget::Recovery => name.ends_with(".recovery"),
        };
        self.active = if self.config_role {
            name.starts_with(".config.toml.")
        } else {
            name.starts_with(".auth.json.")
        } && phase_matches;
        if !self.active {
            return file.write_once(bytes);
        }
        match self.boundary {
            SensitiveIoBoundary::ShortThenFail(limit) if !self.short_completed => {
                self.short_completed = true;
                file.write_once(&bytes[..limit.min(bytes.len())])
            }
            SensitiveIoBoundary::ShortThenFail(_) | SensitiveIoBoundary::Write => {
                Err(io::Error::other("injected sensitive write failure"))
            }
            _ => file.write_once(bytes),
        }
    }

    fn flush(&mut self, file: &mut SensitiveTempFile) -> io::Result<()> {
        if self.active && self.boundary == SensitiveIoBoundary::Flush {
            Err(io::Error::other("injected sensitive flush failure"))
        } else {
            file.flush()
        }
    }

    fn sync_all(&mut self, file: &SensitiveTempFile) -> io::Result<()> {
        if self.active && self.boundary == SensitiveIoBoundary::Sync {
            Err(io::Error::other("injected sensitive sync failure"))
        } else {
            file.sync_all()
        }
    }

    fn reread(&mut self, file: &mut SensitiveTempFile) -> io::Result<Zeroizing<Vec<u8>>> {
        if self.active && self.boundary == SensitiveIoBoundary::Reread {
            Err(io::Error::other("injected sensitive reread failure"))
        } else {
            file.reread(16 * 1024 * 1024)
        }
    }

    fn arm_delete_on_close(&mut self, file: &mut SensitiveTempFile) -> io::Result<()> {
        if self.active && self.fail_remove {
            Err(io::Error::other("injected sensitive cleanup failure"))
        } else {
            if self.active && self.replace_before_remove && !self.replacement_done {
                self.replacement_done = true;
                let error = fs::remove_file(file.final_path()?).unwrap_err();
                if error.raw_os_error() != Some(32) {
                    return Err(io::Error::other("owned handle did not deny replacement"));
                }
            }
            file.arm_delete_on_close()
        }
    }

    fn rename_relative(
        &mut self,
        file: &mut SensitiveTempFile,
        root: &windows_platform::RootNamespacePin,
        publish_basename: &str,
    ) -> io::Result<()> {
        file.rename_relative(root, publish_basename)?;
        if self.active && self.boundary == SensitiveIoBoundary::RenameReportedErrorAfterSuccess {
            Err(io::Error::other(
                "injected error reported after successful rename syscall",
            ))
        } else {
            Ok(())
        }
    }
}

struct MutateLiveAt {
    root: PathBuf,
    point: FaultPoint,
    role: &'static str,
    bytes: Vec<u8>,
    triggered: bool,
}
impl FaultInjector for MutateLiveAt {
    fn check(&mut self, point: FaultPoint) -> Option<FaultDisposition> {
        if point == self.point && !self.triggered {
            fs::write(self.root.join(self.role), &self.bytes).unwrap();
            self.triggered = true;
        }
        None
    }
}

struct RollbackLockProbe {
    root: PathBuf,
    fail_at: Option<FaultPoint>,
    probed: Vec<(FaultPoint, i32, String)>,
}

struct CorruptSnapshotThenFail {
    root: PathBuf,
    id: String,
}
impl FaultInjector for CorruptSnapshotThenFail {
    fn check(&mut self, point: FaultPoint) -> Option<FaultDisposition> {
        if point == FaultPoint::AfterConfigReplace {
            fs::write(
                self.root
                    .join(".codextools-transactions")
                    .join(&self.id)
                    .join("snapshot.manifest"),
                "corrupt",
            )
            .unwrap();
            return Some(FaultDisposition::Fail);
        }
        None
    }
}
impl FaultInjector for RollbackLockProbe {
    fn check(&mut self, point: FaultPoint) -> Option<FaultDisposition> {
        if self.fail_at == Some(point) {
            self.fail_at = None;
            return Some(FaultDisposition::Fail);
        }
        if matches!(
            point,
            FaultPoint::RollbackConfig | FaultPoint::RollbackAuthentication
        ) {
            let output = Command::new(env!("CARGO_BIN_EXE_m23-lock-probe"))
                .arg(&self.root)
                .arg("0")
                .output()
                .unwrap();
            self.probed.push((
                point,
                output.status.code().unwrap_or(-1),
                String::from_utf8(output.stdout).unwrap().trim().to_owned(),
            ));
        }
        None
    }
}

fn plan(root: &TempRoot, id: &str, auth: Vec<u8>) -> SwitchPlan {
    let (source_config, source_auth) = root.pair();
    let target_config = String::from_utf8(source_config.clone())
        .unwrap()
        .replace("gpt-SAMPLE-1", "gpt-TARGET-1")
        .replace("Sample Provider", "Target Provider")
        .replace("https://HOST/v1", "https://TARGET/v2")
        .into_bytes();
    let ScanStatus::Ready(target) = CodexAdapter::new().scan_memory(&target_config, &auth) else {
        panic!("target must scan")
    };
    SwitchPlan::new(
        SwitchTransactionId::parse(id).unwrap(),
        fs::canonicalize(&root.root).unwrap(),
        FileBaseline::present(source_config.len() as u64, hash_bytes(&source_config)),
        FileBaseline::present(source_auth.len() as u64, hash_bytes(&source_auth)),
        target_config,
        auth,
        ProviderId::parse("sample").unwrap(),
        ModelId::parse("gpt-TARGET-1").unwrap(),
        target.authentication.credential_fingerprint.clone(),
        UnixMillis::new(100).unwrap(),
        UnixMillis::new(200).unwrap(),
    )
    .unwrap()
}

fn planned_record(plan: &SwitchPlan, now: UnixMillis) -> SwitchTransactionRecord {
    let root_ref = hash_bytes(
        fs::canonicalize(plan.root())
            .unwrap()
            .to_string_lossy()
            .to_lowercase()
            .as_bytes(),
    );
    SwitchTransactionRecord {
        transaction: SwitchTransaction::new(
            plan.id().clone(),
            root_ref,
            plan.config_source().sha256.clone(),
            plan.auth_source().sha256.clone(),
            hash_bytes(plan.target_config()),
            hash_bytes(plan.target_auth()),
            plan.provider_id().clone(),
            plan.model_id().clone(),
            plan.auth_fingerprint().clone(),
            now,
        ),
        last_error: None,
        snapshot_manifest_hash: None,
    }
}

fn execute<F: FaultInjector>(
    root: &TempRoot,
    plan: &SwitchPlan,
    faults: &mut F,
) -> Result<codex_application::SwitchTransactionRecord, SwitchExecutionError> {
    let mut repo = SqliteMetadataRepository::open(&root.db).unwrap();
    let clock = FixedClock(150);
    let mut wait = NoWait;
    SwitchExecutor::new(&mut repo, &clock, &mut wait, faults).execute(plan)
}

fn execute_with_sensitive_io<F: FaultInjector, I: SensitiveTempIo>(
    root: &TempRoot,
    plan: &SwitchPlan,
    faults: &mut F,
    sensitive_io: I,
) -> Result<codex_application::SwitchTransactionRecord, SwitchExecutionError> {
    let mut repo = SqliteMetadataRepository::open(&root.db).unwrap();
    let clock = FixedClock(150);
    let mut wait = NoWait;
    SwitchExecutor::new_with_sensitive_temp_io(&mut repo, &clock, &mut wait, faults, sensitive_io)
        .execute(plan)
}
fn record(root: &TempRoot, id: &str) -> codex_application::SwitchTransactionRecord {
    let repo = SqliteMetadataRepository::open(&root.db).unwrap();
    repo.get_switch_transaction(&SwitchTransactionId::parse(id).unwrap())
        .unwrap()
        .unwrap()
}
fn assert_pair(root: &TempRoot, expected: &(Vec<u8>, Vec<u8>)) {
    assert_eq!(&root.pair(), expected)
}

#[allow(clippy::permissions_set_readonly_false)]
fn set_readonly(path: &Path, readonly: bool) {
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_readonly(readonly);
    fs::set_permissions(path, permissions).unwrap();
}

fn is_readonly(path: &Path) -> bool {
    fs::metadata(path).unwrap().permissions().readonly()
}

fn transaction_material_state(root: &TempRoot, id: &str) -> Vec<(String, String, u64, bool)> {
    let directory = root.root.join(".codextools-transactions").join(id);
    let mut paths = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    paths.extend(
        fs::read_dir(&root.root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.is_file()
                    && path
                        .file_name()
                        .is_some_and(|name| name.to_string_lossy().contains(id))
            }),
    );
    let mut state = paths
        .into_iter()
        .map(|path| {
            let bytes = fs::read(&path).unwrap();
            (
                path.strip_prefix(&root.root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
                hash_bytes(&bytes).as_str().to_owned(),
                bytes.len() as u64,
                is_readonly(&path),
            )
        })
        .collect::<Vec<_>>();
    state.sort();
    state
}

fn recursive_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files
}

fn runtime_auth_with_marker(label: &str) -> (Vec<u8>, Vec<u8>) {
    let marker = ["M2", "SENSITIVE", label, "RUNTIME"].join("_").into_bytes();
    let auth = format!(
        "{{\"OPENAI_API_KEY\":\"{}\"}}",
        String::from_utf8(marker.clone()).unwrap()
    )
    .into_bytes();
    (auth, marker)
}

fn count_marker_outside_live_auth(root: &TempRoot, marker: &[u8]) -> usize {
    recursive_files(&root.root)
        .into_iter()
        .filter(|path| path != &root.root.join("auth.json"))
        .filter_map(|path| fs::read(path).ok())
        .filter(|bytes| bytes.windows(marker.len()).any(|window| window == marker))
        .count()
}

fn sensitive_orphans(root: &TempRoot) -> Vec<PathBuf> {
    recursive_files(&root.root)
        .into_iter()
        .filter(|path| {
            path.file_name().is_some_and(|name| {
                let name = name.to_string_lossy();
                name.starts_with(".auth.json.")
                    && (name.ends_with(".stage") || name.ends_with(".recovery"))
            })
        })
        .collect()
}

fn owned_temp_paths(root: &TempRoot) -> Vec<PathBuf> {
    recursive_files(&root.root)
        .into_iter()
        .filter(|path| {
            path.file_name().is_some_and(|name| {
                let name = name.to_string_lossy();
                (name.starts_with(".auth.json.") || name.starts_with(".config.toml."))
                    && (name.ends_with(".stage") || name.ends_with(".recovery"))
            })
        })
        .collect()
}

fn fragment_hits_outside_live_auth(root: &TempRoot, fragments: &[&[u8]]) -> usize {
    recursive_files(&root.root)
        .into_iter()
        .filter(|path| path != &root.root.join("auth.json"))
        .filter_map(|path| fs::read(path).ok())
        .filter(|bytes| {
            fragments.iter().any(|fragment| {
                !fragment.is_empty()
                    && bytes
                        .windows(fragment.len())
                        .any(|window| window == *fragment)
            })
        })
        .count()
}

#[test]
fn terminate_process_partial_and_post_rename_crashes_reopen_without_sensitive_residue() {
    for (index, mode) in [
        "create-return",
        "clear-return",
        "partial-first",
        "partial-half",
        "partial-near",
        "rename",
    ]
    .into_iter()
    .enumerate()
    {
        let root = TempRoot::new(&format!("hard-crash-{mode}"));
        let (auth, marker) = runtime_auth_with_marker(&format!("HARD_CRASH_{mode}_{index}"));
        let partial = match mode {
            "partial-first" => 1,
            "partial-half" => auth.len() / 2,
            "partial-near" => auth.len() - 1,
            _ => 0,
        };
        let mut child = Command::new(env!("CARGO_BIN_EXE_m23-sensitive-temp-crash"))
            .arg(&root.root)
            .arg(&root.db)
            .arg(match mode {
                "create-return" => "create-return",
                "clear-return" => "clear-return",
                "rename" => "rename",
                _ => "partial",
            })
            .arg(partial.to_string())
            .env(
                "CODEXTOOLS_SYNTHETIC_AUTH",
                String::from_utf8(auth).unwrap(),
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut ready = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        assert!(ready.starts_with("READY phase="), "{mode}: {ready}");
        child.kill().unwrap();
        let status = child.wait().unwrap();
        assert!(!status.success());

        let mut repository = SqliteMetadataRepository::open(&root.db).unwrap();
        let mut wait = NoWait;
        let mut faults = ScriptedFault::default();
        let recovered =
            SwitchExecutor::new(&mut repository, &FixedClock(160), &mut wait, &mut faults)
                .recover_root(&root.root)
                .unwrap();
        assert_eq!(recovered.len(), 1, "{mode}");
        assert_eq!(
            recovered[0].transaction.state(),
            SwitchTransactionState::RolledBack,
            "{mode}"
        );
        assert!(
            repository
                .list_sensitive_temp_owners(recovered[0].transaction.root_ref())
                .unwrap()
                .is_empty()
        );
        drop(repository);
        assert!(sensitive_orphans(&root).is_empty(), "{mode}");
        let third = marker.len() / 3;
        let fragments = [
            &marker[..third],
            &marker[third..third * 2],
            &marker[third * 2..],
        ];
        assert_eq!(
            fragment_hits_outside_live_auth(&root, &fragments),
            0,
            "{mode}"
        );
        println!("HARD_CRASH mode={mode} terminated=true reopen=rolled_back owners=0 fragments=0");
    }
}

#[test]
fn owned_auth_stage_cleans_real_short_write_and_io_failures() {
    let cases = [
        ("short-first", SensitiveIoBoundary::ShortThenFail(1)),
        ("short-half", SensitiveIoBoundary::ShortThenFail(18)),
        ("short-near", SensitiveIoBoundary::ShortThenFail(35)),
        ("write", SensitiveIoBoundary::Write),
        ("flush", SensitiveIoBoundary::Flush),
        ("sync", SensitiveIoBoundary::Sync),
        ("reread", SensitiveIoBoundary::Reread),
    ];
    for (index, (label, boundary)) in cases.into_iter().enumerate() {
        let root = TempRoot::new(label);
        let (auth, marker) = runtime_auth_with_marker(label);
        let id = format!("a1000000-0000-4000-8000-{index:012}");
        let switch_plan = plan(&root, &id, auth);
        let result = execute_with_sensitive_io(
            &root,
            &switch_plan,
            &mut ScriptedFault::default(),
            InjectedSensitiveIo::new(boundary, SensitiveIoTarget::Stage),
        );
        assert_eq!(result, Err(SwitchExecutionError::IoFailure), "{label}");
        assert_eq!(
            record(&root, &id).transaction.state(),
            SwitchTransactionState::RolledBack,
            "{label}"
        );
        let orphans = sensitive_orphans(&root);
        let marker_count = count_marker_outside_live_auth(&root, &marker);
        println!(
            "CASE={label} RESULT=Err(IoFailure) STATE=rolled_back ORPHAN={} MARKER={marker_count}",
            orphans.len()
        );
        assert!(orphans.is_empty(), "{label}");
        assert_eq!(marker_count, 0, "{label}");
    }
}

#[test]
fn owned_auth_recovery_stage_cleans_real_short_write_and_io_failures() {
    let cases = [
        ("short-first", SensitiveIoBoundary::ShortThenFail(1)),
        ("short-half", SensitiveIoBoundary::ShortThenFail(18)),
        ("short-near", SensitiveIoBoundary::ShortThenFail(35)),
        ("write", SensitiveIoBoundary::Write),
        ("flush", SensitiveIoBoundary::Flush),
        ("sync", SensitiveIoBoundary::Sync),
        ("reread", SensitiveIoBoundary::Reread),
    ];
    for (index, (label, boundary)) in cases.into_iter().enumerate() {
        let root = TempRoot::new(&format!("recovery-{label}"));
        let (auth, marker) = runtime_auth_with_marker(&format!("RECOVERY_{label}"));
        let id = format!("a2000000-0000-4000-8000-{index:012}");
        let switch_plan = plan(&root, &id, auth);
        let result = execute_with_sensitive_io(
            &root,
            &switch_plan,
            &mut ScriptedFault::fail(FaultPoint::OriginalPathVerify),
            InjectedSensitiveIo::new(boundary, SensitiveIoTarget::Recovery),
        );
        assert_eq!(
            result,
            Err(SwitchExecutionError::RecoveryRequired),
            "{label}"
        );
        assert_eq!(
            record(&root, &id).transaction.state(),
            SwitchTransactionState::RollingBack,
            "{label}"
        );
        let orphans = sensitive_orphans(&root);
        let marker_count = count_marker_outside_live_auth(&root, &marker);
        println!(
            "CASE=recovery-{label} RESULT=Err(RecoveryRequired) STATE=rolling_back ORPHAN={} MARKER={marker_count}",
            orphans.len()
        );
        assert!(orphans.is_empty(), "{label}");
        assert_eq!(marker_count, 0, "{label}");
    }
}

#[test]
fn config_target_and_recovery_use_the_same_handle_owner_without_fragment_residue() {
    for (index, target) in [SensitiveIoTarget::Stage, SensitiveIoTarget::Recovery]
        .into_iter()
        .enumerate()
    {
        let root = TempRoot::new(&format!("config-owner-{target:?}"));
        let sentinel = format!(
            "CONFIG_FRAGMENT_SENTINEL_{:032X}",
            0xC0DEC0DE_u128 + index as u128
        );
        let mut source_config = fs::read(root.root.join("config.toml")).unwrap();
        source_config.extend_from_slice(format!("\n# {sentinel}\n").as_bytes());
        fs::write(root.root.join("config.toml"), &source_config).unwrap();
        let id = format!("a2400000-0000-4000-8000-{index:012}");
        let switch_plan = plan(&root, &id, br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec());
        let limit = match target {
            SensitiveIoTarget::Stage => switch_plan.target_config().len() - 1,
            SensitiveIoTarget::Recovery => source_config.len() - 1,
        };
        let mut faults = match target {
            SensitiveIoTarget::Stage => ScriptedFault::default(),
            SensitiveIoTarget::Recovery => ScriptedFault::fail(FaultPoint::OriginalPathVerify),
        };
        let _ = execute_with_sensitive_io(
            &root,
            &switch_plan,
            &mut faults,
            InjectedSensitiveIo::new(SensitiveIoBoundary::ShortThenFail(limit), target)
                .for_config(),
        );
        let fragment = sentinel.as_bytes();
        let third = fragment.len() / 3;
        let fragments = [
            &fragment[..third],
            &fragment[third..third * 2],
            &fragment[third * 2..],
        ];
        let owned_temp_paths = owned_temp_paths(&root);
        let hits = owned_temp_paths
            .iter()
            .filter_map(|path| fs::read(path).ok())
            .filter(|bytes| {
                fragments
                    .iter()
                    .any(|part| bytes.windows(part.len()).any(|window| window == *part))
            })
            .count();
        assert_eq!(hits, 0, "{target:?}");
        assert!(owned_temp_paths.is_empty(), "{target:?}");
    }
    println!("CONFIG_OWNER target=clean recovery=clean fragments=0 orphan=0");
}

#[test]
fn rename_reported_error_after_success_is_resolved_from_same_handle_before_db_publish() {
    let root = TempRoot::new("rename-false-after-success-target");
    let (auth, _) = runtime_auth_with_marker("RENAME_FALSE_TARGET");
    let id = "a2500000-0000-4000-8000-000000000001";
    let switch_plan = plan(&root, id, auth);
    let completed = execute_with_sensitive_io(
        &root,
        &switch_plan,
        &mut ScriptedFault::default(),
        InjectedSensitiveIo::new(
            SensitiveIoBoundary::RenameReportedErrorAfterSuccess,
            SensitiveIoTarget::Stage,
        ),
    )
    .unwrap();
    assert_eq!(
        completed.transaction.state(),
        SwitchTransactionState::Committed
    );
    let repository = SqliteMetadataRepository::open(&root.db).unwrap();
    assert!(
        repository
            .list_sensitive_temp_owners(completed.transaction.root_ref())
            .unwrap()
            .is_empty()
    );
    drop(repository);
    assert!(sensitive_orphans(&root).is_empty());

    let root = TempRoot::new("rename-false-after-success-recovery");
    let source = root.pair();
    let (auth, _) = runtime_auth_with_marker("RENAME_FALSE_RECOVERY");
    let id = "a2500000-0000-4000-8000-000000000002";
    let switch_plan = plan(&root, id, auth);
    let _ = execute_with_sensitive_io(
        &root,
        &switch_plan,
        &mut ScriptedFault::fail(FaultPoint::OriginalPathVerify),
        InjectedSensitiveIo::new(
            SensitiveIoBoundary::RenameReportedErrorAfterSuccess,
            SensitiveIoTarget::Recovery,
        ),
    );
    assert_eq!(
        record(&root, id).transaction.state(),
        SwitchTransactionState::RolledBack
    );
    assert_pair(&root, &source);
    assert!(sensitive_orphans(&root).is_empty());
    println!(
        "RENAME_FALSE target=same_handle_committed recovery=same_handle_rolled_back owners=0 orphan=0"
    );
}

#[test]
fn cleanup_failure_is_diagnostic_and_reopen_reconciles_owned_auth_stage() {
    let root = TempRoot::new("stage-cleanup-reopen");
    let (auth, marker) = runtime_auth_with_marker("STAGE_CLEANUP_REOPEN");
    let id = "a3000000-0000-4000-8000-000000000001";
    let switch_plan = plan(&root, id, auth);
    let result = execute_with_sensitive_io(
        &root,
        &switch_plan,
        &mut ScriptedFault::default(),
        InjectedSensitiveIo::new(
            SensitiveIoBoundary::ShortThenFail(18),
            SensitiveIoTarget::Stage,
        )
        .with_remove_failure(),
    );
    assert_eq!(result, Err(SwitchExecutionError::RecoveryRequired));
    assert_eq!(
        record(&root, id).transaction.state(),
        SwitchTransactionState::SnapshotCreated
    );
    assert_eq!(sensitive_orphans(&root).len(), 1);
    let repo = SqliteMetadataRepository::open(&root.db).unwrap();
    let tx = record(&root, id);
    assert_eq!(
        repo.list_sensitive_temp_owners(tx.transaction.root_ref())
            .unwrap()
            .len(),
        2
    );
    drop(repo);

    let mut repository = SqliteMetadataRepository::open(&root.db).unwrap();
    let mut wait = NoWait;
    let mut faults = ScriptedFault::default();
    let recovered = SwitchExecutor::new(&mut repository, &FixedClock(160), &mut wait, &mut faults)
        .recover_root(&root.root)
        .unwrap();
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        recovered[0].transaction.state(),
        SwitchTransactionState::RolledBack
    );
    assert!(sensitive_orphans(&root).is_empty());
    assert_eq!(count_marker_outside_live_auth(&root, &marker), 0);
    println!(
        "CASE=stage-cleanup-reopen INITIAL=RecoveryRequired REOPEN=converged ORPHAN=0 MARKER=0"
    );
}

#[test]
fn cleanup_failure_during_recovery_reopens_from_rolling_back() {
    let root = TempRoot::new("recovery-cleanup-reopen");
    let source = root.pair();
    let (auth, marker) = runtime_auth_with_marker("RECOVERY_CLEANUP_REOPEN");
    let id = "a4000000-0000-4000-8000-000000000001";
    let switch_plan = plan(&root, id, auth);
    let result = execute_with_sensitive_io(
        &root,
        &switch_plan,
        &mut ScriptedFault::fail(FaultPoint::OriginalPathVerify),
        InjectedSensitiveIo::new(
            SensitiveIoBoundary::ShortThenFail(18),
            SensitiveIoTarget::Recovery,
        )
        .with_remove_failure(),
    );
    assert_eq!(result, Err(SwitchExecutionError::RecoveryRequired));
    assert_eq!(
        record(&root, id).transaction.state(),
        SwitchTransactionState::RollingBack
    );
    assert_eq!(sensitive_orphans(&root).len(), 1);

    let mut repository = SqliteMetadataRepository::open(&root.db).unwrap();
    let mut wait = NoWait;
    let mut faults = ScriptedFault::default();
    let recovered = SwitchExecutor::new(&mut repository, &FixedClock(160), &mut wait, &mut faults)
        .recover_root(&root.root)
        .unwrap();
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        recovered[0].transaction.state(),
        SwitchTransactionState::RolledBack
    );
    assert_pair(&root, &source);
    assert!(sensitive_orphans(&root).is_empty());
    assert_eq!(count_marker_outside_live_auth(&root, &marker), 0);
    println!(
        "CASE=recovery-cleanup-reopen INITIAL=rolling_back REOPEN=rolled_back ORPHAN=0 MARKER=0"
    );
}

#[test]
fn open_owned_handle_prevents_external_replacement_and_cleans_exact_object() {
    let root = TempRoot::new("external-temp-replacement");
    let (auth, _) = runtime_auth_with_marker("EXTERNAL_REPLACEMENT");
    let id = "a5000000-0000-4000-8000-000000000001";
    let switch_plan = plan(&root, id, auth);
    let result = execute_with_sensitive_io(
        &root,
        &switch_plan,
        &mut ScriptedFault::default(),
        InjectedSensitiveIo::new(
            SensitiveIoBoundary::ShortThenFail(18),
            SensitiveIoTarget::Stage,
        )
        .with_external_replacement(),
    );
    assert_eq!(result, Err(SwitchExecutionError::IoFailure));
    assert!(sensitive_orphans(&root).is_empty());
    assert_eq!(
        record(&root, id).transaction.state(),
        SwitchTransactionState::RolledBack
    );
    println!(
        "CASE=external-replacement WHILE_HANDLE_OPEN=sharing_violation OWNED_TEMP_CLEANED=true"
    );
}

#[test]
fn committed_switch_cleans_transaction_material_and_verifies_target() {
    let root = TempRoot::new("commit");
    let source = root.pair();
    let switch_plan = plan(
        &root,
        "11111111-1111-4111-8111-111111111111",
        br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec(),
    );
    let target = (
        switch_plan.target_config().to_vec(),
        switch_plan.target_auth().to_vec(),
    );
    let completed = execute(&root, &switch_plan, &mut ScriptedFault::default()).unwrap();
    assert_eq!(
        completed.transaction.state(),
        SwitchTransactionState::Committed
    );
    assert_pair(&root, &target);
    assert_ne!(source, target);
    println!(
        "M23_HASH source_config={} source_auth={} target_config={} target_auth={} final=target state=committed",
        hash_bytes(&source.0).as_str(),
        hash_bytes(&source.1).as_str(),
        hash_bytes(&target.0).as_str(),
        hash_bytes(&target.1).as_str()
    );
    let directory = root
        .root
        .join(".codextools-transactions")
        .join(switch_plan.id().as_str());
    assert!(
        !directory.exists(),
        "terminal transaction material must be removed"
    );
}

#[test]
fn interrupted_snapshot_never_persists_authentication_plaintext() {
    let root = TempRoot::new("encrypted-auth-snapshot");
    let id = "11111111-1111-4111-8111-111111111111";
    let marker = format!("{}{}", "sk-", "Q7mN2vX9pL4cR8tW5yB3dF6hJ1kS0zAa");
    let source_marker = format!("{{\"OPENAI_API_KEY\":\"{marker}\"}}").into_bytes();
    fs::write(root.root.join("auth.json"), &source_marker).unwrap();
    let switch_plan = plan(&root, id, br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec());
    assert_eq!(
        execute(
            &root,
            &switch_plan,
            &mut ScriptedFault::interrupt(FaultPoint::AfterSnapshotManifest)
        ),
        Err(SwitchExecutionError::Interrupted)
    );
    let material = fs::read(
        root.root
            .join(".codextools-transactions")
            .join(id)
            .join("snapshot-auth.bin"),
    )
    .unwrap();
    assert!(
        !material
            .windows(source_marker.len())
            .any(|window| window == source_marker.as_slice()),
        "transaction auth snapshot persisted the live authentication plaintext"
    );
}

#[test]
fn authentication_snapshot_corruption_and_cross_transaction_substitution_fail_closed() {
    let first = TempRoot::new("snapshot-binding-first");
    let second = TempRoot::new("snapshot-binding-second");
    let first_id = "11111111-1111-4111-8111-111111111111";
    let second_id = "22222222-2222-4222-8222-222222222222";
    for (root, id) in [(&first, first_id), (&second, second_id)] {
        let switch_plan = plan(root, id, br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec());
        assert_eq!(
            execute(
                root,
                &switch_plan,
                &mut ScriptedFault::interrupt(FaultPoint::AfterSnapshotManifest)
            ),
            Err(SwitchExecutionError::Interrupted)
        );
    }
    let first_envelope = first
        .root
        .join(".codextools-transactions")
        .join(first_id)
        .join("snapshot-auth.bin");
    let second_envelope = second
        .root
        .join(".codextools-transactions")
        .join(second_id)
        .join("snapshot-auth.bin");
    fs::copy(&first_envelope, &second_envelope).unwrap();
    let live_before = second.pair();
    let mut repo = SqliteMetadataRepository::open(&second.db).unwrap();
    let mut wait = NoWait;
    let mut faults = ScriptedFault::default();
    let recovered = SwitchExecutor::new(&mut repo, &FixedClock(160), &mut wait, &mut faults)
        .recover_root(&second.root)
        .unwrap();
    assert_eq!(
        recovered[0].transaction.state(),
        SwitchTransactionState::RecoveryRequired
    );
    assert_pair(&second, &live_before);

    let corrupt = TempRoot::new("snapshot-binding-corrupt");
    let corrupt_id = "33333333-3333-4333-8333-333333333333";
    let switch_plan = plan(
        &corrupt,
        corrupt_id,
        br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec(),
    );
    assert_eq!(
        execute(
            &corrupt,
            &switch_plan,
            &mut ScriptedFault::interrupt(FaultPoint::AfterSnapshotManifest)
        ),
        Err(SwitchExecutionError::Interrupted)
    );
    let path = corrupt
        .root
        .join(".codextools-transactions")
        .join(corrupt_id)
        .join("snapshot-auth.bin");
    let mut envelope = fs::read(&path).unwrap();
    let last = envelope.len() - 1;
    envelope[last] ^= 0x5a;
    fs::write(path, envelope).unwrap();
    let live_before = corrupt.pair();
    let mut repo = SqliteMetadataRepository::open(&corrupt.db).unwrap();
    let mut wait = NoWait;
    let mut faults = ScriptedFault::default();
    let recovered = SwitchExecutor::new(&mut repo, &FixedClock(160), &mut wait, &mut faults)
        .recover_root(&corrupt.root)
        .unwrap();
    assert_eq!(
        recovered[0].transaction.state(),
        SwitchTransactionState::RecoveryRequired
    );
    assert_pair(&corrupt, &live_before);
}

#[test]
fn terminal_cleanup_faults_reopen_and_converge_without_material() {
    let cleanup_points = [
        FaultPoint::TerminalCleanupAuthenticationSnapshot,
        FaultPoint::TerminalCleanupConfigSnapshot,
        FaultPoint::TerminalCleanupAuthenticationStage,
        FaultPoint::TerminalCleanupConfigStage,
        FaultPoint::TerminalCleanupManifest,
        FaultPoint::TerminalCleanupDirectory,
    ];
    for (index, point) in cleanup_points.into_iter().enumerate() {
        for rolled_back in [false, true] {
            let root = TempRoot::new(&format!("cleanup-{index}-{rolled_back}"));
            let id = format!(
                "{:08x}-1111-4111-8111-111111111111",
                0xc0 + index * 2 + usize::from(rolled_back)
            );
            let switch_plan = plan(&root, &id, br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec());
            let mut points = vec![(point, FaultDisposition::Fail)];
            if rolled_back {
                points.insert(0, (FaultPoint::BeforeConfigReplace, FaultDisposition::Fail));
            }
            assert_eq!(
                execute(&root, &switch_plan, &mut ScriptedFault { points }),
                Err(SwitchExecutionError::RecoveryRequired)
            );
            assert_eq!(
                record(&root, &id).transaction.state(),
                if rolled_back {
                    SwitchTransactionState::RolledBack
                } else {
                    SwitchTransactionState::Committed
                }
            );
            assert!(root.root.join(".codextools-transactions").exists());
            let mut repo = SqliteMetadataRepository::open(&root.db).unwrap();
            let mut wait = NoWait;
            let mut faults = ScriptedFault::default();
            assert!(
                SwitchExecutor::new(&mut repo, &FixedClock(160), &mut wait, &mut faults)
                    .recover_root(&root.root)
                    .unwrap()
                    .is_empty()
            );
            assert!(!root.root.join(".codextools-transactions").exists());
        }
    }
}

#[test]
fn plan_stale() {
    let root = TempRoot::new("stale");
    let source = root.pair();
    let stale_plan = plan(
        &root,
        "11111111-1111-4111-8111-111111111111",
        br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec(),
    );
    let mut repo = SqliteMetadataRepository::open(&root.db).unwrap();
    let clock = FixedClock(150);
    let mut wait = MutateWindow;
    let mut faults = ScriptedFault::default();
    let result =
        SwitchExecutor::new(&mut repo, &clock, &mut wait, &mut faults).execute(&stale_plan);
    assert_eq!(result, Err(SwitchExecutionError::PlanStale));
    let changed = root.pair();
    assert_ne!(changed.0, source.0);
    assert_eq!(changed.1, source.1);
    assert!(
        String::from_utf8(changed.0)
            .unwrap()
            .contains("KEEP_EXTERNAL")
    );
    let expired = plan(
        &root,
        "22222222-2222-4222-8222-222222222222",
        br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec(),
    );
    let late = FixedClock(200);
    let mut wait = NoWait;
    let mut faults = ScriptedFault::default();
    let mut repo = SqliteMetadataRepository::open(&root.db).unwrap();
    assert_eq!(
        SwitchExecutor::new(&mut repo, &late, &mut wait, &mut faults).execute(&expired),
        Err(SwitchExecutionError::PlanStale)
    );
}

#[test]
fn plan_expiry_is_rechecked_under_lock_and_before_replacing() {
    for (index, valid_calls) in [3, 4, 7].into_iter().enumerate() {
        let root = TempRoot::new(&format!("expiry-{index}"));
        let source = root.pair();
        let id = format!("{:08x}-1111-4111-8111-111111111111", index + 0x80);
        let switch_plan = plan(&root, &id, br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec());
        let mut repo = SqliteMetadataRepository::open(&root.db).unwrap();
        let clock = ExpiringClock::after(valid_calls);
        let mut wait = NoWait;
        let mut faults = ScriptedFault::default();
        assert_eq!(
            SwitchExecutor::new(&mut repo, &clock, &mut wait, &mut faults).execute(&switch_plan),
            Err(SwitchExecutionError::PlanStale),
            "valid_calls={valid_calls}"
        );
        assert_pair(&root, &source);
        assert_eq!(
            record(&root, &id).transaction.state(),
            SwitchTransactionState::RolledBack
        );
        println!("M23_PLAN_EXPIRY valid_clock_calls={valid_calls} final=source state=rolled_back");
    }
}

#[test]
fn external_mutation_matrix_is_never_silently_overwritten() {
    let cases = [
        (FaultPoint::AfterSnapshotManifest, "config.toml", false),
        (FaultPoint::AfterStageConfig, "config.toml", false),
        (FaultPoint::AfterStageAuthentication, "auth.json", false),
        (FaultPoint::BeforeConfigReplace, "config.toml", false),
        (FaultPoint::AfterConfigReplace, "auth.json", true),
        (FaultPoint::BeforeAuthenticationReplace, "auth.json", true),
        (FaultPoint::AfterAuthenticationReplace, "config.toml", true),
        (FaultPoint::OriginalPathVerify, "auth.json", true),
    ];
    for (index, (point, role, replacing_started)) in cases.into_iter().enumerate() {
        let root = TempRoot::new(&format!("external-{index}"));
        let source = root.pair();
        let id = format!("{:08x}-1111-4111-8111-111111111111", index + 0x90);
        let switch_plan = plan(&root, &id, br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec());
        let marker = format!("EXTERNAL-{index}-{role}").into_bytes();
        let mut faults = MutateLiveAt {
            root: root.root.clone(),
            point,
            role,
            bytes: marker.clone(),
            triggered: false,
        };
        let mut repo = SqliteMetadataRepository::open(&root.db).unwrap();
        let clock = FixedClock(150);
        let mut wait = NoWait;
        let result =
            SwitchExecutor::new(&mut repo, &clock, &mut wait, &mut faults).execute(&switch_plan);
        assert!(faults.triggered, "{point:?}");
        assert_eq!(
            result,
            Err(if replacing_started {
                SwitchExecutionError::RecoveryRequired
            } else {
                SwitchExecutionError::PlanStale
            }),
            "{point:?}"
        );
        assert_eq!(fs::read(root.root.join(role)).unwrap(), marker, "{point:?}");
        assert_ne!(
            record(&root, &id).transaction.state(),
            SwitchTransactionState::Committed
        );
        if !replacing_started {
            let actual = root.pair();
            if role == "config.toml" {
                assert_eq!(actual.1, source.1);
            } else {
                assert_eq!(actual.0, source.0);
            }
        }
        println!("M23_EXTERNAL point={point:?} role={role} retained=true committed=false");
    }
}

#[test]
fn fault_matrix_never_commits_mixed_files() {
    let points = [
        FaultPoint::BeforeLock,
        FaultPoint::AfterLock,
        FaultPoint::SnapshotConfig,
        FaultPoint::SnapshotAuthentication,
        FaultPoint::SnapshotManifest,
        FaultPoint::AfterSnapshotManifest,
        FaultPoint::StageConfigWrite,
        FaultPoint::StageConfigFlush,
        FaultPoint::StageConfigReread,
        FaultPoint::AfterStageConfig,
        FaultPoint::StageAuthenticationWrite,
        FaultPoint::StageAuthenticationFlush,
        FaultPoint::StageAuthenticationReread,
        FaultPoint::AfterStageAuthentication,
        FaultPoint::StagedTargetParse,
        FaultPoint::BeforeConfigReplace,
        FaultPoint::AfterConfigMakeWritable,
        FaultPoint::AfterConfigReplace,
        FaultPoint::BeforeAuthenticationReplace,
        FaultPoint::AfterAuthenticationMakeWritable,
        FaultPoint::AfterAuthenticationReplace,
        FaultPoint::OriginalPathVerify,
        FaultPoint::BeforeCommittedState,
    ];
    for (index, point) in points.into_iter().enumerate() {
        let root = TempRoot::new(&format!("fault-{index}"));
        let source = root.pair();
        let id = format!("{:08x}-1111-4111-8111-111111111111", index + 1);
        let plan = plan(&root, &id, br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec());
        let result = execute(&root, &plan, &mut ScriptedFault::fail(point));
        assert_eq!(
            result,
            Err(SwitchExecutionError::InjectedFailure),
            "{point:?}"
        );
        assert_pair(&root, &source);
        if point == FaultPoint::BeforeLock {
            let repository = SqliteMetadataRepository::open(&root.db).unwrap();
            assert!(
                repository
                    .get_switch_transaction(&SwitchTransactionId::parse(&id).unwrap())
                    .unwrap()
                    .is_none()
            );
            assert!(!root.root.join(".codextools-transactions").exists());
            println!(
                "M23_FAULT point={point:?} final=source state=not_created config={} auth={}",
                hash_bytes(&source.0).as_str(),
                hash_bytes(&source.1).as_str()
            );
            continue;
        }
        assert_eq!(
            record(&root, &id).transaction.state(),
            SwitchTransactionState::RolledBack,
            "{point:?}"
        );
        println!(
            "M23_FAULT point={point:?} final=source state=rolled_back config={} auth={}",
            hash_bytes(&source.0).as_str(),
            hash_bytes(&source.1).as_str()
        );
    }
}

#[test]
fn interrupted_reopen_recovery_is_idempotent() {
    let root = TempRoot::new("recover");
    let source = root.pair();
    let id = "11111111-1111-4111-8111-111111111111";
    let plan = plan(&root, id, br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec());
    assert_eq!(
        execute(
            &root,
            &plan,
            &mut ScriptedFault::interrupt(FaultPoint::AfterConfigReplace)
        ),
        Err(SwitchExecutionError::Interrupted)
    );
    assert_ne!(root.pair(), source);
    let mut repo = SqliteMetadataRepository::open(&root.db).unwrap();
    let clock = FixedClock(160);
    let mut wait = NoWait;
    let mut faults = ScriptedFault::default();
    let mut executor = SwitchExecutor::new(&mut repo, &clock, &mut wait, &mut faults);
    let recovered = executor.recover_root(&root.root).unwrap();
    assert_eq!(recovered.len(), 1);
    assert_eq!(
        recovered[0].transaction.state(),
        SwitchTransactionState::RolledBack
    );
    assert_pair(&root, &source);
    println!(
        "M23_RECOVERY interrupted_after=config final=source state=rolled_back config={} auth={}",
        hash_bytes(&source.0).as_str(),
        hash_bytes(&source.1).as_str()
    );
    assert!(executor.recover_root(&root.root).unwrap().is_empty());
    assert_pair(&root, &source);
}

#[test]
fn target_complete_interruption_is_revalidated_and_committed() {
    for (index, point) in [
        FaultPoint::OriginalPathVerify,
        FaultPoint::BeforeCommittedState,
    ]
    .into_iter()
    .enumerate()
    {
        let root = TempRoot::new(&format!("recover-target-{index}"));
        let id = "11111111-1111-4111-8111-111111111111";
        let switch_plan = plan(&root, id, br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec());
        let target = (
            switch_plan.target_config().to_vec(),
            switch_plan.target_auth().to_vec(),
        );
        assert_eq!(
            execute(&root, &switch_plan, &mut ScriptedFault::interrupt(point)),
            Err(SwitchExecutionError::Interrupted)
        );
        assert_pair(&root, &target);
        println!(
            "M23_RECOVERY point={point:?} final=target state=committed config={} auth={}",
            hash_bytes(&target.0).as_str(),
            hash_bytes(&target.1).as_str()
        );
        let mut repo = SqliteMetadataRepository::open(&root.db).unwrap();
        let clock = FixedClock(160);
        let mut wait = NoWait;
        let mut faults = ScriptedFault::default();
        let recovered = SwitchExecutor::new(&mut repo, &clock, &mut wait, &mut faults)
            .recover_root(&root.root)
            .unwrap();
        assert_eq!(
            recovered[0].transaction.state(),
            SwitchTransactionState::Committed
        );
        assert_pair(&root, &target);
    }
}

#[test]
fn corrupt_snapshot_and_rollback_fault_enter_recovery_required() {
    let root = TempRoot::new("corrupt");
    let id = "11111111-1111-4111-8111-111111111111";
    let plan = plan(&root, id, br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec());
    assert_eq!(
        execute(
            &root,
            &plan,
            &mut ScriptedFault::interrupt(FaultPoint::AfterConfigReplace)
        ),
        Err(SwitchExecutionError::Interrupted)
    );
    fs::write(
        root.root
            .join(".codextools-transactions")
            .join(id)
            .join("snapshot.manifest"),
        "corrupt",
    )
    .unwrap();
    let mut repo = SqliteMetadataRepository::open(&root.db).unwrap();
    let clock = FixedClock(160);
    let mut wait = NoWait;
    let mut faults = ScriptedFault::default();
    let recovered = SwitchExecutor::new(&mut repo, &clock, &mut wait, &mut faults)
        .recover_root(&root.root)
        .unwrap();
    assert_eq!(
        recovered[0].transaction.state(),
        SwitchTransactionState::RecoveryRequired
    );
    assert!(
        root.root
            .join(".codextools-transactions")
            .join(id)
            .join("snapshot-config.bin")
            .exists()
    );
}

#[test]
fn sqlite_final_commit_failure_rolls_back_complete_source() {
    let root = TempRoot::new("db-fail");
    let source = root.pair();
    let id = "11111111-1111-4111-8111-111111111111";
    let plan = plan(&root, id, br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec());
    {
        let repo = SqliteMetadataRepository::open(&root.db).unwrap();
        drop(repo);
        let connection = Connection::open(&root.db).unwrap();
        connection.execute_batch("CREATE TRIGGER fail_committed BEFORE UPDATE ON switch_transactions WHEN NEW.state='committed' BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    }
    assert_eq!(
        execute(&root, &plan, &mut ScriptedFault::default()),
        Err(SwitchExecutionError::RepositoryFailure)
    );
    assert_pair(&root, &source);
    assert_eq!(
        record(&root, id).transaction.state(),
        SwitchTransactionState::RolledBack
    );
}

#[test]
fn rollback_holds_cross_process_lock_until_terminal_state() {
    for (index, trigger_commit_failure) in [false, true].into_iter().enumerate() {
        let root = TempRoot::new(&format!("rollback-lock-{index}"));
        let source = root.pair();
        let id = format!("{:08x}-1111-4111-8111-111111111111", index + 0xa0);
        let switch_plan = plan(&root, &id, br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec());
        if trigger_commit_failure {
            let repo = SqliteMetadataRepository::open(&root.db).unwrap();
            drop(repo);
            Connection::open(&root.db).unwrap().execute_batch("CREATE TRIGGER fail_committed_lock BEFORE UPDATE ON switch_transactions WHEN NEW.state='committed' BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
        }
        let mut faults = RollbackLockProbe {
            root: root.root.clone(),
            fail_at: (!trigger_commit_failure).then_some(FaultPoint::AfterConfigReplace),
            probed: Vec::new(),
        };
        let result = execute(&root, &switch_plan, &mut faults);
        assert_eq!(
            result,
            Err(if trigger_commit_failure {
                SwitchExecutionError::RepositoryFailure
            } else {
                SwitchExecutionError::InjectedFailure
            })
        );
        assert_eq!(faults.probed.len(), 2);
        for (point, code, stdout) in &faults.probed {
            assert_eq!((*code, stdout.as_str()), (2, "LOCK_CONTENDED"), "{point:?}");
            println!(
                "M23_ROLLBACK_LOCK point={point:?} stdout={stdout} exit={code} terminal_persisted=false"
            );
        }
        assert_pair(&root, &source);
        assert_eq!(
            record(&root, &id).transaction.state(),
            SwitchTransactionState::RolledBack
        );
        let available = Command::new(env!("CARGO_BIN_EXE_m23-lock-probe"))
            .arg(&root.root)
            .arg("0")
            .output()
            .unwrap();
        assert_eq!(available.status.code(), Some(0));
        assert_eq!(
            String::from_utf8(available.stdout).unwrap().trim(),
            "LOCK_ACQUIRED"
        );
        println!(
            "M23_ROLLBACK_LOCK final=rolled_back stdout=LOCK_ACQUIRED exit=0 commit_failure={trigger_commit_failure}"
        );
    }
}

#[test]
fn absent_auth_is_created_and_rollback_restores_absence() {
    for (label, fault) in [
        ("commit", None),
        ("rollback", Some(FaultPoint::AfterConfigReplace)),
    ] {
        let root = TempRoot::new(&format!("absent-{label}"));
        fs::remove_file(root.root.join("auth.json")).unwrap();
        let source_config = fs::read(root.root.join("config.toml")).unwrap();
        let target_config = String::from_utf8(source_config.clone())
            .unwrap()
            .replace("gpt-SAMPLE-1", "gpt-TARGET-1")
            .replace("Sample Provider", "Target Provider")
            .replace("https://HOST/v1", "https://TARGET/v2")
            .into_bytes();
        let target_auth = br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec();
        let ScanStatus::Ready(target) =
            CodexAdapter::new().scan_memory(&target_config, &target_auth)
        else {
            panic!()
        };
        let id = "11111111-1111-4111-8111-111111111111";
        let switch_plan = SwitchPlan::new(
            SwitchTransactionId::parse(id).unwrap(),
            fs::canonicalize(&root.root).unwrap(),
            FileBaseline::present(source_config.len() as u64, hash_bytes(&source_config)),
            FileBaseline::absent(),
            target_config.clone(),
            target_auth.clone(),
            ProviderId::parse("sample").unwrap(),
            ModelId::parse("gpt-TARGET-1").unwrap(),
            target.authentication.credential_fingerprint.clone(),
            UnixMillis::new(100).unwrap(),
            UnixMillis::new(200).unwrap(),
        )
        .unwrap();
        if let Some(point) = fault {
            assert_eq!(
                execute(&root, &switch_plan, &mut ScriptedFault::fail(point)),
                Err(SwitchExecutionError::InjectedFailure)
            );
            assert_eq!(
                fs::read(root.root.join("config.toml")).unwrap(),
                source_config
            );
            assert!(!root.root.join("auth.json").exists());
            println!("M23_ABSENT role=auth source=absent final=absent state=rolled_back");
        } else {
            execute(&root, &switch_plan, &mut ScriptedFault::default()).unwrap();
            assert_eq!(
                fs::read(root.root.join("config.toml")).unwrap(),
                target_config
            );
            assert_eq!(fs::read(root.root.join("auth.json")).unwrap(), target_auth);
            println!(
                "M23_ABSENT role=auth source=absent final=present state=committed target_auth={}",
                hash_bytes(&target_auth).as_str()
            );
        }
    }
}

#[test]
fn pre_v10_unknown_stage_is_read_only_blocked_and_actual_files_remain_source() {
    let root = TempRoot::new("stage-collision");
    let source = root.pair();
    let id = "11111111-1111-4111-8111-111111111111";
    let switch_plan = plan(&root, id, br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec());
    let collision = root.root.join(format!(".config.toml.{id}.stage"));
    let opaque = b"PRE_V10_OPAQUE_FIXTURE";
    fs::write(&collision, opaque).unwrap();
    let before_length = fs::metadata(&collision).unwrap().len();
    let before_hash = hash_bytes(&fs::read(&collision).unwrap());
    assert_eq!(
        execute(&root, &switch_plan, &mut ScriptedFault::default()),
        Err(SwitchExecutionError::RecoveryRequired)
    );
    assert_pair(&root, &source);
    assert_eq!(fs::metadata(&collision).unwrap().len(), before_length);
    assert_eq!(hash_bytes(&fs::read(&collision).unwrap()), before_hash);
    let mut repository = SqliteMetadataRepository::open(&root.db).unwrap();
    let root_ref = hash_bytes(
        fs::canonicalize(&root.root)
            .unwrap()
            .to_string_lossy()
            .to_lowercase()
            .as_bytes(),
    );
    assert_eq!(
        repository
            .list_sensitive_temp_anomalies(&root_ref)
            .unwrap()
            .len(),
        1
    );
    drop(repository);
    fs::remove_file(&collision).unwrap();
    let committed = execute(&root, &switch_plan, &mut ScriptedFault::default()).unwrap();
    assert_eq!(
        committed.transaction.state(),
        SwitchTransactionState::Committed
    );
    repository = SqliteMetadataRepository::open(&root.db).unwrap();
    assert!(
        repository
            .list_sensitive_temp_anomalies(&root_ref)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn pre_v10_reparse_stage_is_diagnosed_without_following_or_deleting_target() {
    let root = TempRoot::new("pre-v10-reparse");
    let source = root.pair();
    let outside = root.root.with_extension("pre-v10-reparse-target");
    fs::create_dir_all(&outside).unwrap();
    let sentinel = outside.join("sentinel.bin");
    fs::write(&sentinel, b"NONSECRET-SENTINEL").unwrap();
    let sentinel_hash = hash_bytes(&fs::read(&sentinel).unwrap());
    let id = "21111111-1111-4111-8111-111111111111";
    let link = root.root.join(format!(".auth.json.{id}.recovery"));
    let output = Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&link)
        .arg(&outside)
        .output()
        .unwrap();
    assert!(output.status.success());
    let switch_plan = plan(&root, id, br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec());
    assert_eq!(
        execute(&root, &switch_plan, &mut ScriptedFault::default()),
        Err(SwitchExecutionError::RecoveryRequired)
    );
    assert_pair(&root, &source);
    assert_eq!(hash_bytes(&fs::read(&sentinel).unwrap()), sentinel_hash);
    assert!(link.exists());
    let repository = SqliteMetadataRepository::open(&root.db).unwrap();
    let root_ref = hash_bytes(
        fs::canonicalize(&root.root)
            .unwrap()
            .to_string_lossy()
            .to_lowercase()
            .as_bytes(),
    );
    let anomalies = repository.list_sensitive_temp_anomalies(&root_ref).unwrap();
    assert_eq!(anomalies.len(), 1);
    assert_eq!(anomalies[0].reason, "reparse");
    drop(repository);
    fs::remove_dir(&link).unwrap();
    fs::remove_dir_all(&outside).unwrap();
}

#[test]
fn rollback_role_failure_enters_recovery_required_with_snapshot_material() {
    for (index, rollback_point) in [
        FaultPoint::RollbackConfig,
        FaultPoint::RollbackAuthentication,
    ]
    .into_iter()
    .enumerate()
    {
        let root = TempRoot::new(&format!("rollback-fault-{index}"));
        let id = format!("{:08x}-1111-4111-8111-111111111111", index + 0xb0);
        let switch_plan = plan(&root, &id, br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec());
        let mut faults = ScriptedFault {
            points: vec![
                (FaultPoint::AfterConfigReplace, FaultDisposition::Fail),
                (rollback_point, FaultDisposition::Fail),
            ],
        };
        assert_eq!(
            execute(&root, &switch_plan, &mut faults),
            Err(SwitchExecutionError::RecoveryRequired)
        );
        assert_eq!(
            record(&root, &id).transaction.state(),
            if rollback_point == FaultPoint::RollbackConfig {
                SwitchTransactionState::RecoveryRequired
            } else {
                SwitchTransactionState::RollingBack
            }
        );
        let snapshot = root.root.join(".codextools-transactions").join(&id);
        assert!(snapshot.join("snapshot.manifest").exists());
        assert!(snapshot.join("snapshot-auth.bin").exists());
    }
}

#[test]
fn coherent_snapshot_tamper_is_rejected_before_live_files_change() {
    let root = TempRoot::new("coherent-tamper");
    let id = "11111111-1111-4111-8111-111111111111";
    let switch_plan = plan(&root, id, br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec());
    assert_eq!(
        execute(
            &root,
            &switch_plan,
            &mut ScriptedFault::interrupt(FaultPoint::AfterConfigReplace)
        ),
        Err(SwitchExecutionError::Interrupted)
    );
    let live_before = root.pair();
    let directory = root.root.join(".codextools-transactions").join(id);
    let tampered = b"coherent snapshot tamper";
    fs::write(directory.join("snapshot-config.bin"), tampered).unwrap();
    let manifest_path = directory.join("snapshot.manifest");
    let manifest = fs::read_to_string(&manifest_path).unwrap();
    let original_hash = record(&root, id)
        .transaction
        .config_source()
        .unwrap()
        .as_str()
        .to_owned();
    let manifest = manifest
        .replace(
            &format!("config.length={}", switch_plan.config_source().length),
            &format!("config.length={}", tampered.len()),
        )
        .replace(
            &format!("config.sha256={original_hash}"),
            &format!("config.sha256={}", hash_bytes(tampered).as_str()),
        );
    fs::write(manifest_path, manifest).unwrap();
    let mut repo = SqliteMetadataRepository::open(&root.db).unwrap();
    let clock = FixedClock(160);
    let mut wait = NoWait;
    let mut faults = ScriptedFault::default();
    let recovered = SwitchExecutor::new(&mut repo, &clock, &mut wait, &mut faults)
        .recover_root(&root.root)
        .unwrap();
    assert_eq!(
        recovered[0].transaction.state(),
        SwitchTransactionState::RecoveryRequired
    );
    assert_pair(&root, &live_before);
    println!("M23_SNAPSHOT_TAMPER live_unchanged=true state=recovery_required");
}

#[test]
fn recovery_preserves_unknown_external_bytes_after_process_interruption() {
    let root = TempRoot::new("recovery-external");
    let id = "11111111-1111-4111-8111-111111111111";
    let switch_plan = plan(&root, id, br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec());
    assert_eq!(
        execute(
            &root,
            &switch_plan,
            &mut ScriptedFault::interrupt(FaultPoint::AfterConfigReplace)
        ),
        Err(SwitchExecutionError::Interrupted)
    );
    let external = b"EXTERNAL_AFTER_INTERRUPT".to_vec();
    fs::write(root.root.join("auth.json"), &external).unwrap();
    let live_before = root.pair();
    let mut repo = SqliteMetadataRepository::open(&root.db).unwrap();
    let clock = FixedClock(160);
    let mut wait = NoWait;
    let mut faults = ScriptedFault::default();
    let recovered = SwitchExecutor::new(&mut repo, &clock, &mut wait, &mut faults)
        .recover_root(&root.root)
        .unwrap();
    assert_eq!(
        recovered[0].transaction.state(),
        SwitchTransactionState::RecoveryRequired
    );
    assert_pair(&root, &live_before);
    assert_eq!(fs::read(root.root.join("auth.json")).unwrap(), external);
    println!("M23_RECOVERY_EXTERNAL retained=true state=recovery_required");
}

#[test]
fn recovery_required_blocks_all_new_switches_for_the_same_root() {
    enum LiveCase {
        Source,
        Target,
        ExternalMixed,
    }
    for (index, case) in [LiveCase::Source, LiveCase::Target, LiveCase::ExternalMixed]
        .into_iter()
        .enumerate()
    {
        let root = TempRoot::new(&format!("recovery-block-{index}"));
        let source = root.pair();
        let first_id = format!("{:08x}-1111-4111-8111-111111111111", index + 0xd0);
        let first_plan = plan(&root, &first_id, br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec());
        let target = (
            first_plan.target_config().to_vec(),
            first_plan.target_auth().to_vec(),
        );
        let mut faults = ScriptedFault {
            points: vec![
                (FaultPoint::AfterConfigReplace, FaultDisposition::Fail),
                (FaultPoint::RollbackConfig, FaultDisposition::Fail),
            ],
        };
        assert_eq!(
            execute(&root, &first_plan, &mut faults),
            Err(SwitchExecutionError::RecoveryRequired)
        );
        assert_eq!(
            record(&root, &first_id).transaction.state(),
            SwitchTransactionState::RecoveryRequired
        );
        let root_ref = hash_bytes(
            fs::canonicalize(&root.root)
                .unwrap()
                .to_string_lossy()
                .to_lowercase()
                .as_bytes(),
        );
        let repo = SqliteMetadataRepository::open(&root.db).unwrap();
        let diagnostics = repo.list_recovery_required_diagnostics(&root_ref).unwrap();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].record.transaction.id().as_str(), first_id);
        assert_eq!(
            diagnostics[0].material_ref,
            PathBuf::from(".codextools-transactions").join(&first_id)
        );
        drop(repo);
        match case {
            LiveCase::Source => {
                fs::write(root.root.join("config.toml"), &source.0).unwrap();
                fs::write(root.root.join("auth.json"), &source.1).unwrap();
            }
            LiveCase::Target => {
                fs::write(root.root.join("config.toml"), &target.0).unwrap();
                fs::write(root.root.join("auth.json"), &target.1).unwrap();
            }
            LiveCase::ExternalMixed => {
                let mut external = target.0.clone();
                external.extend_from_slice(b"external_review_field = \"KEEP\"\n");
                fs::write(root.root.join("config.toml"), external).unwrap();
                fs::write(root.root.join("auth.json"), &source.1).unwrap();
            }
        }
        let live_before = root.pair();
        let material_before = transaction_material_state(&root, &first_id);
        let rows_before: i64 = Connection::open(&root.db)
            .unwrap()
            .query_row("SELECT COUNT(*) FROM switch_transactions", [], |row| {
                row.get(0)
            })
            .unwrap();
        let second_id = format!("{:08x}-2222-4222-8222-222222222222", index + 0xe0);
        let second_plan = plan(&root, &second_id, br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec());
        assert_eq!(
            execute(&root, &second_plan, &mut ScriptedFault::default()),
            Err(SwitchExecutionError::RecoveryRequired)
        );
        assert_pair(&root, &live_before);
        assert_eq!(
            transaction_material_state(&root, &first_id),
            material_before
        );
        assert!(
            !root
                .root
                .join(".codextools-transactions")
                .join(&second_id)
                .exists()
        );
        let rows_after: i64 = Connection::open(&root.db)
            .unwrap()
            .query_row("SELECT COUNT(*) FROM switch_transactions", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(rows_after, rows_before);
        println!(
            "M23_ROOT_BLOCK case={index} second=recovery_required rows_unchanged=true live_unchanged=true material_unchanged=true"
        );
    }
}

#[test]
fn dual_connection_old_precheck_race_has_one_database_root_slot() {
    let root = TempRoot::new("dual-connection-root-slot");
    let source = root.pair();
    let first_plan = plan(
        &root,
        "11111111-5555-4555-8555-555555555555",
        br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec(),
    );
    let second_plan = plan(
        &root,
        "22222222-5555-4555-8555-555555555555",
        br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec(),
    );
    SqliteMetadataRepository::open(&root.db).unwrap();
    let root_ref = hash_bytes(
        fs::canonicalize(&root.root)
            .unwrap()
            .to_string_lossy()
            .to_lowercase()
            .as_bytes(),
    );
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for switch_plan in [first_plan, second_plan] {
        let db = root.db.clone();
        let root_ref = root_ref.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let mut repository = SqliteMetadataRepository::open(&db).unwrap();
            assert!(
                repository
                    .list_blocking_switch_transactions(&root_ref)
                    .unwrap()
                    .is_empty()
            );
            barrier.wait();
            repository.create_switch_transaction(&planned_record(
                &switch_plan,
                UnixMillis::new(150).unwrap(),
            ))
        }));
    }
    let results = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| {
                **result
                    == Err(RepositoryError::AlreadyExists(
                        EntityKind::SwitchTransaction,
                    ))
            })
            .count(),
        1
    );
    let mut repository = SqliteMetadataRepository::open(&root.db).unwrap();
    let winner = repository
        .list_blocking_switch_transactions(&root_ref)
        .unwrap()
        .pop()
        .unwrap();
    let rolled_back = SwitchTransactionRecord {
        transaction: winner
            .transaction
            .transition(
                SwitchTransactionState::RolledBack,
                UnixMillis::new(151).unwrap(),
            )
            .unwrap(),
        last_error: Some(SwitchErrorCode::Busy),
        snapshot_manifest_hash: None,
    };
    repository
        .update_switch_transaction(&rolled_back, EntityVersion::initial())
        .unwrap();
    let connection = Connection::open(&root.db).unwrap();
    let rows: i64 = connection
        .query_row("SELECT COUNT(*) FROM switch_transactions", [], |row| {
            row.get(0)
        })
        .unwrap();
    let planned: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM switch_transactions WHERE state='planned'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rows, 1);
    assert_eq!(planned, 0);
    drop(connection);
    drop(repository);
    assert_pair(&root, &source);
    assert!(!root.root.join(".codextools-transactions").exists());
    println!(
        "M23_ROOT_RACE prechecks=2 admitted=1 rejected=1 final_rolled_back=1 planned=0 materials=0 live=source"
    );
}

#[test]
fn contended_execute_creates_no_transaction_or_material() {
    let root = TempRoot::new("contended-execute-no-row");
    let source = root.pair();
    let switch_plan = plan(
        &root,
        "11111111-8888-4888-8888-888888888888",
        br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec(),
    );
    SqliteMetadataRepository::open(&root.db).unwrap();
    let mut lock = CrossProcessWriteLock::try_acquire(
        &fs::canonicalize(&root.root).unwrap(),
        UnixMillis::new(140).unwrap(),
    )
    .unwrap();
    assert_eq!(
        execute(&root, &switch_plan, &mut ScriptedFault::default()),
        Err(SwitchExecutionError::Busy)
    );
    let rows: i64 = Connection::open(&root.db)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM switch_transactions", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(rows, 0);
    assert_pair(&root, &source);
    assert!(!root.root.join(".codextools-transactions").exists());
    lock.release().unwrap();
    println!("M23_ROOT_LOCK_CONTENDED result=busy rows=0 materials=0 live=source");
}

#[test]
fn database_rejects_two_nonterminal_transactions_for_one_root() {
    let root = TempRoot::new("root-partial-unique");
    let first_plan = plan(
        &root,
        "11111111-6666-4666-8666-666666666666",
        br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec(),
    );
    let second_plan = plan(
        &root,
        "22222222-6666-4666-8666-666666666666",
        br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec(),
    );
    let mut first = SqliteMetadataRepository::open(&root.db).unwrap();
    let mut second = SqliteMetadataRepository::open(&root.db).unwrap();
    first
        .create_switch_transaction(&planned_record(&first_plan, UnixMillis::new(150).unwrap()))
        .unwrap();
    assert_eq!(
        second.create_switch_transaction(&planned_record(
            &second_plan,
            UnixMillis::new(150).unwrap()
        )),
        Err(RepositoryError::AlreadyExists(
            EntityKind::SwitchTransaction
        ))
    );
    let connection = Connection::open(&root.db).unwrap();
    connection
        .execute(
            "UPDATE switch_transactions SET state='recovery_required' WHERE id=?1",
            [first_plan.id().as_str()],
        )
        .unwrap();
    assert_eq!(
        second.create_switch_transaction(&planned_record(
            &second_plan,
            UnixMillis::new(150).unwrap()
        )),
        Err(RepositoryError::AlreadyExists(
            EntityKind::SwitchTransaction
        ))
    );
    println!("M23_ROOT_UNIQUE planned_conflict=true recovery_required_conflict=true");
}

#[test]
fn early_rolling_back_crash_recovery_is_hash_only_and_never_writes_live() {
    for (index, mutate_live) in [false, true].into_iter().enumerate() {
        let root = TempRoot::new(&format!("early-rolling-{index}"));
        let source = root.pair();
        let id = format!("{:08x}-7777-4777-8777-777777777777", index + 1);
        let switch_plan = plan(&root, &id, br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec());
        let planned = planned_record(&switch_plan, UnixMillis::new(150).unwrap());
        let mut repository = SqliteMetadataRepository::open(&root.db).unwrap();
        repository.create_switch_transaction(&planned).unwrap();
        Connection::open(&root.db)
            .unwrap()
            .execute(
                "UPDATE switch_transactions
                 SET state='rolling_back', last_error_code='injected_failure',
                     updated_at_unix_ms=151, version=2
                 WHERE id=?1",
                [switch_plan.id().as_str()],
            )
            .unwrap();
        if mutate_live {
            fs::write(root.root.join("config.toml"), b"UNKNOWN_EXTERNAL_CONTENT").unwrap();
        }
        let live_before = root.pair();
        let clock = FixedClock(160);
        let mut window = NoWait;
        let mut faults = ScriptedFault::default();
        let recovered = SwitchExecutor::new(&mut repository, &clock, &mut window, &mut faults)
            .recover_root(&root.root)
            .unwrap();
        assert_eq!(
            recovered[0].transaction.state(),
            if mutate_live {
                SwitchTransactionState::RecoveryRequired
            } else {
                SwitchTransactionState::RolledBack
            }
        );
        assert_pair(&root, &live_before);
        if !mutate_live {
            assert_pair(&root, &source);
        }
        println!(
            "M23_EARLY_ROLLING source_match={} final={} live_unchanged=true manifest=absent roles=0",
            !mutate_live,
            if mutate_live {
                "recovery_required"
            } else {
                "rolled_back"
            }
        );
    }
}

#[test]
fn readonly_is_preserved_by_commit_and_rollback() {
    for (index, fail_at) in [None, Some(FaultPoint::AfterConfigReplace)]
        .into_iter()
        .enumerate()
    {
        let root = TempRoot::new(&format!("readonly-final-{index}"));
        let source = root.pair();
        set_readonly(&root.root.join("config.toml"), true);
        set_readonly(&root.root.join("auth.json"), true);
        let id = format!("{:08x}-3333-4333-8333-333333333333", index + 0xf0);
        let switch_plan = plan(&root, &id, br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec());
        let result = execute(
            &root,
            &switch_plan,
            &mut fail_at.map_or_else(ScriptedFault::default, ScriptedFault::fail),
        );
        if fail_at.is_some() {
            assert_eq!(result, Err(SwitchExecutionError::InjectedFailure));
            assert_pair(&root, &source);
        } else {
            assert_eq!(
                result.unwrap().transaction.state(),
                SwitchTransactionState::Committed
            );
        }
        assert!(is_readonly(&root.root.join("config.toml")));
        assert!(is_readonly(&root.root.join("auth.json")));
        println!(
            "M23_READONLY final={} config=true auth=true",
            if fail_at.is_some() {
                "source"
            } else {
                "target"
            }
        );
    }
}

#[test]
fn recovery_never_proves_source_or_target_with_wrong_readonly_state() {
    let root = TempRoot::new("readonly-source-interrupt");
    set_readonly(&root.root.join("config.toml"), true);
    set_readonly(&root.root.join("auth.json"), true);
    let id = "11111111-4444-4444-8444-444444444444";
    let switch_plan = plan(&root, id, br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec());
    assert_eq!(
        execute(
            &root,
            &switch_plan,
            &mut ScriptedFault::interrupt(FaultPoint::AfterConfigMakeWritable),
        ),
        Err(SwitchExecutionError::Interrupted)
    );
    assert!(is_readonly(&root.root.join("config.toml")));
    let mut repo = SqliteMetadataRepository::open(&root.db).unwrap();
    let clock = FixedClock(160);
    let mut wait = NoWait;
    let mut faults = ScriptedFault::default();
    let recovered = SwitchExecutor::new(&mut repo, &clock, &mut wait, &mut faults)
        .recover_root(&root.root)
        .unwrap();
    assert_eq!(
        recovered[0].transaction.state(),
        SwitchTransactionState::RolledBack
    );
    assert!(is_readonly(&root.root.join("config.toml")));
    println!("M23_READONLY_RECOVERY prepublish_guard_restored=true final=rolled_back");

    let root = TempRoot::new("readonly-target-interrupt");
    set_readonly(&root.root.join("config.toml"), true);
    set_readonly(&root.root.join("auth.json"), true);
    let id = "22222222-4444-4444-8444-444444444444";
    let switch_plan = plan(&root, id, br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec());
    assert_eq!(
        execute(
            &root,
            &switch_plan,
            &mut ScriptedFault::interrupt(FaultPoint::OriginalPathVerify),
        ),
        Err(SwitchExecutionError::Interrupted)
    );
    set_readonly(&root.root.join("config.toml"), false);
    let mut repo = SqliteMetadataRepository::open(&root.db).unwrap();
    let clock = FixedClock(160);
    let mut wait = NoWait;
    let mut faults = ScriptedFault::default();
    let recovered = SwitchExecutor::new(&mut repo, &clock, &mut wait, &mut faults)
        .recover_root(&root.root)
        .unwrap();
    assert_eq!(
        recovered[0].transaction.state(),
        SwitchTransactionState::RecoveryRequired
    );
    assert!(!is_readonly(&root.root.join("config.toml")));
    println!("M23_READONLY_RECOVERY target_bytes_permission_changed=recovery_required");
}

#[test]
fn rollback_failure_contract_reports_recovery_required() {
    let root = TempRoot::new("rollback-repository-failure");
    let id = "11111111-1111-4111-8111-111111111111";
    let switch_plan = plan(&root, id, br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec());
    {
        let repo = SqliteMetadataRepository::open(&root.db).unwrap();
        drop(repo);
        Connection::open(&root.db).unwrap().execute_batch("CREATE TRIGGER fail_rolling_back BEFORE UPDATE ON switch_transactions WHEN NEW.state='rolling_back' BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    }
    assert_eq!(
        execute(
            &root,
            &switch_plan,
            &mut ScriptedFault::fail(FaultPoint::AfterConfigReplace)
        ),
        Err(SwitchExecutionError::RecoveryRequired)
    );
    assert_eq!(
        record(&root, id).transaction.state(),
        SwitchTransactionState::RecoveryRequired
    );
    println!("M23_ROLLBACK_ERROR origin=repository_update returned=recovery_required");
}

#[test]
fn snapshot_invalid_during_rollback_reports_recovery_required() {
    let root = TempRoot::new("rollback-snapshot-invalid");
    let id = "11111111-1111-4111-8111-111111111111";
    let switch_plan = plan(&root, id, br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec());
    let mut faults = CorruptSnapshotThenFail {
        root: root.root.clone(),
        id: id.to_owned(),
    };
    assert_eq!(
        execute(&root, &switch_plan, &mut faults),
        Err(SwitchExecutionError::RecoveryRequired)
    );
    assert_eq!(
        record(&root, id).transaction.state(),
        SwitchTransactionState::RecoveryRequired
    );
    println!("M23_ROLLBACK_ERROR origin=snapshot_invalid returned=recovery_required");
}

#[test]
fn compatibility_protected_target_does_not_create_transaction_or_file_material() {
    let root = TempRoot::new("compatibility");
    let source = root.pair();
    let valid_auth = br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec();
    let valid_config = source.0.clone();
    let ScanStatus::Ready(target) = CodexAdapter::new().scan_memory(&valid_config, &valid_auth)
    else {
        panic!()
    };
    let invalid_config = b"model = [1]\n".to_vec();
    let switch_plan = SwitchPlan::new(
        SwitchTransactionId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
        fs::canonicalize(&root.root).unwrap(),
        FileBaseline::present(source.0.len() as u64, hash_bytes(&source.0)),
        FileBaseline::present(source.1.len() as u64, hash_bytes(&source.1)),
        invalid_config,
        valid_auth,
        ProviderId::parse("sample").unwrap(),
        ModelId::parse("gpt-TARGET-1").unwrap(),
        target.authentication.credential_fingerprint.clone(),
        UnixMillis::new(100).unwrap(),
        UnixMillis::new(200).unwrap(),
    )
    .unwrap();
    let result = execute(&root, &switch_plan, &mut ScriptedFault::default());
    assert!(matches!(
        result,
        Err(SwitchExecutionError::CompatibilityProtected(_))
    ));
    assert_pair(&root, &source);
    assert!(!root.root.join(".codextools-transactions").exists());
    let connection = Connection::open(&root.db).unwrap();
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM switch_transactions", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn transaction_repository_rejects_stale_version_and_corrupt_state() {
    let root = TempRoot::new("repository");
    let id = "11111111-1111-4111-8111-111111111111";
    let switch_plan = plan(&root, id, br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec());
    assert_eq!(
        execute(
            &root,
            &switch_plan,
            &mut ScriptedFault::interrupt(FaultPoint::AfterLock)
        ),
        Err(SwitchExecutionError::Interrupted)
    );
    let mut repo = SqliteMetadataRepository::open(&root.db).unwrap();
    let current = repo
        .get_switch_transaction(&SwitchTransactionId::parse(id).unwrap())
        .unwrap()
        .unwrap();
    let updated = current
        .transaction
        .transition(
            SwitchTransactionState::SnapshotCreated,
            UnixMillis::new(160).unwrap(),
        )
        .unwrap();
    let candidate = SwitchTransactionRecord {
        transaction: updated,
        last_error: None,
        snapshot_manifest_hash: current.snapshot_manifest_hash.clone(),
    };
    assert_eq!(
        repo.update_switch_transaction(&candidate, EntityVersion::initial()),
        Err(RepositoryError::VersionConflict(
            EntityKind::SwitchTransaction
        ))
    );
    drop(repo);
    let connection = Connection::open(&root.db).unwrap();
    connection.execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE switch_transactions SET state='future_state';").unwrap();
    drop(connection);
    assert!(matches!(
        SqliteMetadataRepository::open(&root.db),
        Err(OpenRepositoryError::CorruptData)
    ));
}

#[test]
fn sqlite_rejects_invalid_state_role_combinations() {
    let root = TempRoot::new("state-role-sql");
    let id = "11111111-1111-4111-8111-111111111111";
    let switch_plan = plan(&root, id, br#"{"OPENAI_API_KEY":"TOKEN"}"#.to_vec());
    execute(&root, &switch_plan, &mut ScriptedFault::default()).unwrap();
    let connection = Connection::open(&root.db).unwrap();
    assert!(
        connection
            .execute(
                "UPDATE switch_transactions SET completed_roles=0 WHERE id=?1",
                [id],
            )
            .is_err()
    );
    drop(connection);
    let repo = SqliteMetadataRepository::open(&root.db).unwrap();
    assert_eq!(
        repo.get_switch_transaction(&SwitchTransactionId::parse(id).unwrap())
            .unwrap()
            .unwrap()
            .transaction
            .completed_roles(),
        3
    );
    drop(repo);
    let connection = Connection::open(&root.db).unwrap();
    connection
        .execute_batch(
            "PRAGMA ignore_check_constraints=ON; UPDATE switch_transactions SET completed_roles=0 WHERE state='committed';",
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        SqliteMetadataRepository::open(&root.db),
        Err(OpenRepositoryError::CorruptData)
    ));
}

#[test]
fn second_process_observes_lock_contended() {
    let root = TempRoot::new("lock");
    let binary = env!("CARGO_BIN_EXE_m23-lock-probe");
    let mut first = Command::new(binary)
        .arg(&root.root)
        .arg("stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut reader = BufReader::new(first.stdout.take().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "LOCK_ACQUIRED");
    let second = Command::new(binary)
        .arg(&root.root)
        .arg("0")
        .output()
        .unwrap();
    assert_eq!(second.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(second.stdout).unwrap().trim(),
        "LOCK_CONTENDED"
    );
    first.stdin.take().unwrap().write_all(b"release\n").unwrap();
    assert!(first.wait().unwrap().success());
    let LockDiagnostic::Owner(owner) = CrossProcessWriteLock::read_diagnostic(&root.root) else {
        panic!()
    };
    assert!(owner.is_stale(UnixMillis::new(1_000).unwrap(), 100));
    fs::write(
        root.root.join(".codextools-write.lock"),
        "corrupt stale metadata",
    )
    .unwrap();
    assert_eq!(
        CrossProcessWriteLock::read_diagnostic(&root.root),
        LockDiagnostic::Corrupt
    );
    let mut lock = CrossProcessWriteLock::try_acquire(
        &fs::canonicalize(&root.root).unwrap(),
        UnixMillis::new(200).unwrap(),
    )
    .unwrap();
    assert_eq!(lock.owner().process_id, std::process::id());
    assert!(matches!(
        CrossProcessWriteLock::read_diagnostic(&root.root),
        LockDiagnostic::Owner(_)
    ));
    lock.release().unwrap();
    lock.release().unwrap();
}

#[test]
fn secret_bytes_are_absent_from_database_manifest_debug_and_errors() {
    let root = TempRoot::new("secret");
    let marker = format!("{}{}", "sk-", "Z".repeat(24));
    let auth = format!("{{\"OPENAI_API_KEY\":\"{marker}\"}}").into_bytes();
    let id = "11111111-1111-4111-8111-111111111111";
    let plan = plan(&root, id, auth);
    let debug = format!("{plan:?}");
    assert!(!debug.contains(&marker));
    execute(&root, &plan, &mut ScriptedFault::default()).unwrap();
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let path = PathBuf::from(format!("{}{}", root.db.display(), suffix));
        if path.exists() {
            let bytes = fs::read(path).unwrap();
            assert!(
                !bytes
                    .windows(marker.len())
                    .any(|window| window == marker.as_bytes())
            );
        }
    }
    let live_auth = root.root.join("auth.json");
    assert!(!root.root.join(".codextools-transactions").exists());
    for path in recursive_files(&root.root) {
        if path == live_auth {
            continue;
        }
        let bytes = fs::read(&path).unwrap();
        assert!(
            !bytes
                .windows(marker.len())
                .any(|window| window == marker.as_bytes()),
            "secret marker persisted outside the exact live auth role: {}",
            path.display()
        );
    }
}
