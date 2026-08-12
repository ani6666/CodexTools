#![allow(unused_crate_dependencies)]

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use codex_application::{
    CredentialReferenceRepository, OAuthCaptureError, OAuthProcessOutcome, OAuthProcessRunner,
};
use codex_domain::{CredentialRefId, UnixMillis};
use local_infrastructure::{
    OAuthCaptureRequest, OAuthCaptureService, SqliteMetadataRepository, SystemOAuthProcessRunner,
};
use windows_platform::WindowsDpapiCredentialStore;

const CONFIG: &[u8] = b"model = \"gpt-SAMPLE-1\"\nmodel_provider = \"sample\"\n[model_providers.sample]\nname = \"Sample Provider\"\nbase_url = \"https://HOST/v1\"\n";

struct TempArea(PathBuf);

impl TempArea {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "codextools-m24-oauth-job-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempArea {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn helper() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_m24-oauth-helper"))
}

fn capture(
    area: &TempArea,
    mode: &str,
    timeout: Duration,
) -> Result<codex_domain::CredentialReference, OAuthCaptureError> {
    let audit = area.0.join("audit");
    fs::create_dir_all(&audit).unwrap();
    let mut repository = SqliteMetadataRepository::open(area.0.join("metadata.sqlite3")).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(area.0.join("credentials")).unwrap();
    let mut runner = SystemOAuthProcessRunner;
    OAuthCaptureService::capture(
        &mut repository,
        &mut store,
        &mut runner,
        OAuthCaptureRequest {
            executable: helper(),
            audit_root: audit,
            capture_id: "job-case".to_owned(),
            mode: mode.to_owned(),
            timeout,
            credential_id: CredentialRefId::parse("77777777-7777-4777-8777-777777777777").unwrap(),
            now: UnixMillis::new(7).unwrap(),
            minimal_config: CONFIG.to_vec(),
        },
    )
}

struct WaitErrorRunner {
    outside: Option<PathBuf>,
}

struct UnconfirmedTreeRunner;
impl OAuthProcessRunner for UnconfirmedTreeRunner {
    fn run(
        &mut self,
        _executable: &Path,
        capture_root: &Path,
        _audit_root: &Path,
        _mode: &str,
        _timeout: Duration,
    ) -> Result<OAuthProcessOutcome, OAuthCaptureError> {
        fs::write(capture_root.join("diagnostic.txt"), b"SAMPLE").unwrap();
        Err(OAuthCaptureError::ProcessTreeUnconfirmed)
    }
}

struct ActiveUnconfirmedTreeRunner {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}
impl ActiveUnconfirmedTreeRunner {
    fn new() -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(false)),
            handle: None,
        }
    }
    fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            handle.join().unwrap();
        }
    }
}
impl OAuthProcessRunner for ActiveUnconfirmedTreeRunner {
    fn run(
        &mut self,
        _executable: &Path,
        capture_root: &Path,
        audit_root: &Path,
        _mode: &str,
        _timeout: Duration,
    ) -> Result<OAuthProcessOutcome, OAuthCaptureError> {
        let stop = Arc::clone(&self.stop);
        let started = Arc::new(Barrier::new(2));
        let child_started = Arc::clone(&started);
        let capture = capture_root.to_path_buf();
        let outside = audit_root.join("unconfirmed-active-outside.txt");
        self.handle = Some(thread::spawn(move || {
            let mut counter = 0_u64;
            let _ = fs::write(capture.join("active-diagnostic.txt"), b"SAMPLE");
            let _ = fs::write(&outside, b"SAMPLE");
            child_started.wait();
            while !stop.load(Ordering::SeqCst) {
                counter = counter.wrapping_add(1);
                let _ = fs::write(capture.join("active-diagnostic.txt"), counter.to_string());
                thread::sleep(Duration::from_millis(1));
            }
        }));
        started.wait();
        Err(OAuthCaptureError::ProcessTreeUnconfirmed)
    }
}

impl OAuthProcessRunner for WaitErrorRunner {
    fn run(
        &mut self,
        _executable: &Path,
        _capture_root: &Path,
        _audit_root: &Path,
        _mode: &str,
        _timeout: Duration,
    ) -> Result<OAuthProcessOutcome, OAuthCaptureError> {
        if let Some(path) = &self.outside {
            fs::write(path, b"SAMPLE").unwrap();
        }
        Err(OAuthCaptureError::ProcessFailed)
    }
}

#[test]
fn unconfirmed_process_tree_preserves_diagnostic_and_skips_unsafe_cleanup() {
    let area = TempArea::new("tree-unconfirmed");
    let audit = area.0.join("audit");
    fs::create_dir_all(&audit).unwrap();
    let mut repository = SqliteMetadataRepository::open(area.0.join("metadata.sqlite3")).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(area.0.join("credentials")).unwrap();
    let result = OAuthCaptureService::capture(
        &mut repository,
        &mut store,
        &mut UnconfirmedTreeRunner,
        OAuthCaptureRequest {
            executable: helper(),
            audit_root: audit.clone(),
            capture_id: "tree-unconfirmed".to_owned(),
            mode: "SAMPLE".to_owned(),
            timeout: Duration::from_millis(1),
            credential_id: CredentialRefId::parse("79797979-7979-4979-8979-797979797979").unwrap(),
            now: UnixMillis::new(9).unwrap(),
            minimal_config: CONFIG.to_vec(),
        },
    );
    assert_eq!(result, Err(OAuthCaptureError::ProcessTreeUnconfirmed));
    assert!(
        audit
            .join("capture-tree-unconfirmed/diagnostic.txt")
            .is_file()
    );
    assert!(repository.list_credential_references().unwrap().is_empty());
    println!(
        "M24_OAUTH_UNCONFIRMED tree_terminated=false audit_skipped=true cleanup_skipped=true diagnostic_preserved=true credential_unchanged=true"
    );
}

#[test]
fn active_unconfirmed_tree_returns_before_audit_and_preserves_capture() {
    let area = TempArea::new("active-tree-unconfirmed");
    let audit = area.0.join("audit");
    fs::create_dir_all(&audit).unwrap();
    let mut repository = SqliteMetadataRepository::open(area.0.join("metadata.sqlite3")).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(area.0.join("credentials")).unwrap();
    let mut runner = ActiveUnconfirmedTreeRunner::new();
    let result = OAuthCaptureService::capture(
        &mut repository,
        &mut store,
        &mut runner,
        OAuthCaptureRequest {
            executable: helper(),
            audit_root: audit.clone(),
            capture_id: "active-tree-unconfirmed".to_owned(),
            mode: "SAMPLE".to_owned(),
            timeout: Duration::from_millis(1),
            credential_id: CredentialRefId::parse("7a7a7a7a-7a7a-4a7a-8a7a-7a7a7a7a7a7a").unwrap(),
            now: UnixMillis::new(10).unwrap(),
            minimal_config: CONFIG.to_vec(),
        },
    );
    runner.stop();
    assert_eq!(result, Err(OAuthCaptureError::ProcessTreeUnconfirmed));
    assert!(
        audit
            .join("capture-active-tree-unconfirmed/active-diagnostic.txt")
            .is_file()
    );
    assert!(audit.join("unconfirmed-active-outside.txt").is_file());
    assert!(repository.list_credential_references().unwrap().is_empty());
    println!(
        "M24_OAUTH_UNCONFIRMED_ACTIVE background_write=true audit_called=false cleanup_called=false error_preserved=true credential_unchanged=true"
    );
}

#[test]
fn wait_error_still_performs_capture_and_outside_audit_before_cleanup() {
    for (index, mutate_outside) in [false, true].into_iter().enumerate() {
        let area = TempArea::new(&format!("wait-error-{index}"));
        let audit = area.0.join("audit");
        fs::create_dir_all(&audit).unwrap();
        let mut repository =
            SqliteMetadataRepository::open(area.0.join("metadata.sqlite3")).unwrap();
        let mut store = WindowsDpapiCredentialStore::new(area.0.join("credentials")).unwrap();
        let mut runner = WaitErrorRunner {
            outside: mutate_outside.then(|| audit.join("wait-error-outside.txt")),
        };
        let result = OAuthCaptureService::capture(
            &mut repository,
            &mut store,
            &mut runner,
            OAuthCaptureRequest {
                executable: helper(),
                audit_root: audit.clone(),
                capture_id: format!("wait-error-{index}"),
                mode: "SAMPLE".to_owned(),
                timeout: Duration::from_millis(1),
                credential_id: CredentialRefId::parse("78787878-7878-4878-8878-787878787878")
                    .unwrap(),
                now: UnixMillis::new(8).unwrap(),
                minimal_config: CONFIG.to_vec(),
            },
        );
        assert_eq!(
            result,
            Err(if mutate_outside {
                OAuthCaptureError::OutsideWriteDetected
            } else {
                OAuthCaptureError::ProcessFailed
            })
        );
        assert!(!audit.join(format!("capture-wait-error-{index}")).exists());
        assert!(repository.list_credential_references().unwrap().is_empty());
    }
    println!(
        "M24_OAUTH_WAIT_ERROR unchanged=process_failed outside_change=detected capture_audited=true cleanup=complete credential_unchanged=true"
    );
}

#[test]
fn descendant_tree_is_terminated_before_audit_and_cleanup_for_every_outcome() {
    let cases = [
        ("descendant-success", Ok(())),
        ("descendant-timeout", Err(OAuthCaptureError::TimedOut)),
        ("descendant-cancel", Err(OAuthCaptureError::Cancelled)),
        ("descendant-abnormal", Err(OAuthCaptureError::ProcessFailed)),
    ];
    for (mode, expected) in cases {
        let area = TempArea::new(mode);
        fs::create_dir_all(area.0.join("audit")).unwrap();
        fs::write(area.0.join("audit/sentinel.txt"), b"UNCHANGED").unwrap();
        let timeout = if mode == "descendant-timeout" {
            Duration::from_millis(100)
        } else {
            Duration::from_secs(2)
        };
        let result = capture(&area, mode, timeout);
        assert_eq!(
            result.as_ref().map(|_| ()),
            expected.as_ref().map(|_| ()),
            "mode={mode}"
        );
        thread::sleep(Duration::from_millis(550));
        assert!(!area.0.join("audit/descendant-late-write.txt").exists());
        assert!(!area.0.join("audit/capture-job-case").exists());
        assert_eq!(
            fs::read(area.0.join("audit/sentinel.txt")).unwrap(),
            b"UNCHANGED"
        );
        let repository = SqliteMetadataRepository::open(area.0.join("metadata.sqlite3")).unwrap();
        assert_eq!(
            repository.list_credential_references().unwrap().len(),
            usize::from(expected.is_ok())
        );
        println!(
            "M24_OAUTH_JOB mode={mode} tree_terminated=true late_write=false capture_residue=0"
        );
    }
}

#[test]
fn helper_environment_is_cleared_except_for_explicit_minimum() {
    let area = TempArea::new("environment");
    let result = capture(&area, "env-clear", Duration::from_secs(1));
    assert!(result.is_ok());
    println!("M24_OAUTH_ENV inherited_secret_names=false path_inherited=false codex_home=explicit");
}

#[test]
fn outside_audit_detects_empty_directory_changes() {
    let area = TempArea::new("outside-directory");
    assert_eq!(
        capture(&area, "outside-directory", Duration::from_secs(1)),
        Err(OAuthCaptureError::OutsideWriteDetected)
    );
    println!("M24_OAUTH_OUTSIDE directory_change=detected credential_unchanged=true");
}

#[test]
fn outside_audit_detects_reparse_point_changes_without_following_them() {
    let area = TempArea::new("outside-reparse");
    fs::create_dir_all(area.0.join("audit/reparse-target")).unwrap();
    fs::write(
        area.0.join("audit/reparse-target/sentinel.txt"),
        b"UNCHANGED",
    )
    .unwrap();
    assert_eq!(
        capture(&area, "outside-reparse", Duration::from_secs(2)),
        Err(OAuthCaptureError::OutsideWriteDetected)
    );
    assert_eq!(
        fs::read(area.0.join("audit/reparse-target/sentinel.txt")).unwrap(),
        b"UNCHANGED"
    );
    println!("M24_OAUTH_OUTSIDE reparse_change=detected target_not_followed=true");
}

#[test]
fn auth_reparse_point_is_compatibility_protected_and_not_followed() {
    let area = TempArea::new("auth-junction");
    let target = area.0.join("audit/junction-target");
    fs::create_dir_all(&target).unwrap();
    fs::write(target.join("sentinel.txt"), b"UNCHANGED").unwrap();
    assert_eq!(
        capture(&area, "auth-junction", Duration::from_secs(2)),
        Err(OAuthCaptureError::CompatibilityProtected)
    );
    assert_eq!(fs::read(target.join("sentinel.txt")).unwrap(), b"UNCHANGED");
    assert!(!area.0.join("audit/capture-job-case").exists());
    println!("M24_OAUTH_REPARSE auth_junction=rejected target_unchanged=true capture_residue=0");
}

#[test]
fn capture_root_reparse_replacement_is_detected_before_audit_or_auth_read() {
    let area = TempArea::new("capture-root-junction");
    let target = area.0.join("audit/capture-root-target");
    fs::create_dir_all(&target).unwrap();
    fs::write(target.join("sentinel.txt"), b"UNCHANGED").unwrap();
    assert_eq!(
        capture(&area, "capture-root-junction", Duration::from_secs(2)),
        Err(OAuthCaptureError::OutsideWriteDetected)
    );
    assert_eq!(fs::read(target.join("sentinel.txt")).unwrap(), b"UNCHANGED");
    assert!(!area.0.join("audit/capture-job-case").exists());
    println!(
        "M24_OAUTH_CAPTURE_ROOT junction_replacement=detected before_audit_auth=true target_unchanged=true"
    );
}

#[allow(dead_code)]
fn _path_is_beneath(root: &Path, candidate: &Path) -> bool {
    candidate.starts_with(root)
}
