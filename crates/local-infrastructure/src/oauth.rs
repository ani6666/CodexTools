use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

use codex_application::{
    CredentialStore, OAuthCaptureError, OAuthProcessOutcome, OAuthProcessRunner, ScanStatus,
};
use codex_domain::{AuthMode, CredentialRefId, CredentialReference, UnixMillis};
use zeroize::Zeroize;

use crate::CredentialService;

pub struct OAuthCaptureRequest {
    pub executable: PathBuf,
    pub audit_root: PathBuf,
    pub capture_id: String,
    pub mode: String,
    pub timeout: Duration,
    pub credential_id: CredentialRefId,
    pub now: UnixMillis,
    pub minimal_config: Vec<u8>,
}

#[derive(Default)]
pub struct SystemOAuthProcessRunner;

impl OAuthProcessRunner for SystemOAuthProcessRunner {
    fn run(
        &mut self,
        executable: &Path,
        capture_root: &Path,
        audit_root: &Path,
        mode: &str,
        timeout: Duration,
    ) -> Result<OAuthProcessOutcome, OAuthCaptureError> {
        let arguments = [
            OsString::from(mode),
            capture_root.as_os_str().to_owned(),
            audit_root.as_os_str().to_owned(),
        ];
        let mut environment = vec![(
            OsString::from("CODEX_HOME"),
            capture_root.as_os_str().to_owned(),
        )];
        for key in ["SystemRoot", "WINDIR", "ComSpec", "TEMP", "TMP"] {
            if let Some(value) = std::env::var_os(key) {
                environment.push((OsString::from(key), value));
            }
        }
        let child =
            windows_platform::WindowsJobProcess::spawn(executable, &arguments, &environment)
                .map_err(|_| OAuthCaptureError::ProcessFailed)?;
        match child.wait(timeout).map_err(|error| {
            if error.tree_terminated() {
                OAuthCaptureError::ProcessFailed
            } else {
                OAuthCaptureError::ProcessTreeUnconfirmed
            }
        })? {
            windows_platform::JobProcessExit::TimedOut => Ok(OAuthProcessOutcome::TimedOut),
            windows_platform::JobProcessExit::Exited(0) => Ok(OAuthProcessOutcome::Succeeded),
            windows_platform::JobProcessExit::Exited(2) => Ok(OAuthProcessOutcome::Cancelled),
            windows_platform::JobProcessExit::Exited(_) => {
                Ok(OAuthProcessOutcome::ExitedUnsuccessfully)
            }
        }
    }
}

pub struct OAuthCaptureService;

impl OAuthCaptureService {
    pub fn capture<R, S, P>(
        repository: &mut R,
        store: &mut S,
        runner: &mut P,
        request: OAuthCaptureRequest,
    ) -> Result<CredentialReference, OAuthCaptureError>
    where
        R: codex_application::CredentialReferenceRepository
            + codex_application::CredentialRecoveryRepository,
        S: CredentialStore,
        P: OAuthProcessRunner,
    {
        let audit_root = canonical_explicit_directory(&request.audit_root)?;
        if request.capture_id.is_empty()
            || request.capture_id.len() > 80
            || !request
                .capture_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(OAuthCaptureError::IoFailure);
        }
        let capture_root = audit_root.join(format!("capture-{}", request.capture_id));
        fs::create_dir(&capture_root).map_err(|_| OAuthCaptureError::IoFailure)?;
        let expected_capture_root = validate_capture_root(&audit_root, &capture_root)?;
        let result = Self::capture_inner(
            repository,
            store,
            runner,
            &request,
            &audit_root,
            &capture_root,
            &expected_capture_root,
        );
        if matches!(result, Err(OAuthCaptureError::ProcessTreeUnconfirmed)) {
            return result;
        }
        let cleanup = remove_tree_no_follow(&capture_root);
        if cleanup.is_err() {
            return Err(OAuthCaptureError::IoFailure);
        }
        if capture_root.exists() {
            return Err(OAuthCaptureError::IoFailure);
        }
        result
    }

    fn capture_inner<R, S, P>(
        repository: &mut R,
        store: &mut S,
        runner: &mut P,
        request: &OAuthCaptureRequest,
        audit_root: &Path,
        capture_root: &Path,
        expected_capture_root: &Path,
    ) -> Result<CredentialReference, OAuthCaptureError>
    where
        R: codex_application::CredentialReferenceRepository
            + codex_application::CredentialRecoveryRepository,
        S: CredentialStore,
        P: OAuthProcessRunner,
    {
        let before = tree_hashes_outside(audit_root, capture_root)?;
        let config_path = capture_root.join("config.toml");
        let mut config_file =
            File::create(&config_path).map_err(|_| OAuthCaptureError::IoFailure)?;
        config_file
            .write_all(&request.minimal_config)
            .map_err(|_| OAuthCaptureError::IoFailure)?;
        config_file
            .flush()
            .map_err(|_| OAuthCaptureError::IoFailure)?;
        config_file
            .sync_all()
            .map_err(|_| OAuthCaptureError::IoFailure)?;
        drop(config_file);

        let outcome = runner.run(
            &request.executable,
            capture_root,
            audit_root,
            &request.mode,
            request.timeout,
        );
        if matches!(outcome, Err(OAuthCaptureError::ProcessTreeUnconfirmed)) {
            return Err(OAuthCaptureError::ProcessTreeUnconfirmed);
        }
        let observed_capture_root = validate_capture_root(audit_root, capture_root)
            .map_err(|_| OAuthCaptureError::OutsideWriteDetected)?;
        if observed_capture_root != expected_capture_root {
            return Err(OAuthCaptureError::OutsideWriteDetected);
        }
        let after = tree_hashes_outside(audit_root, capture_root)?;
        if before != after {
            return Err(OAuthCaptureError::OutsideWriteDetected);
        }
        let outcome = outcome?;
        match outcome {
            OAuthProcessOutcome::Succeeded => {}
            OAuthProcessOutcome::Cancelled => return Err(OAuthCaptureError::Cancelled),
            OAuthProcessOutcome::TimedOut => return Err(OAuthCaptureError::TimedOut),
            OAuthProcessOutcome::ExitedUnsuccessfully => {
                return Err(OAuthCaptureError::ProcessFailed);
            }
        }
        let auth_path = capture_root.join("auth.json");
        match fs::symlink_metadata(&auth_path) {
            Ok(metadata) if is_reparse(&metadata) => {
                return Err(OAuthCaptureError::CompatibilityProtected);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(OAuthCaptureError::MissingAuthentication);
            }
            Err(_) => return Err(OAuthCaptureError::IoFailure),
        }
        let mut auth = windows_platform::secure_read_contained_file(
            expected_capture_root,
            &auth_path,
            1024 * 1024,
        )
        .map_err(|_| OAuthCaptureError::CompatibilityProtected)?;
        let scan = codex_adapter::CodexAdapter::new().scan_memory(&request.minimal_config, &auth);
        if !matches!(scan, ScanStatus::Ready(ref state) if state.authentication.auth_mode == AuthMode::OAuth)
        {
            auth.zeroize();
            return Err(OAuthCaptureError::CompatibilityProtected);
        }
        let result = CredentialService::new(repository, store)
            .create_oauth_bundle(request.credential_id.clone(), &mut auth, request.now)
            .map_err(|_| OAuthCaptureError::CredentialFailure);
        auth.zeroize();
        result
    }
}

fn canonical_explicit_directory(path: &Path) -> Result<PathBuf, OAuthCaptureError> {
    if !path.is_absolute() {
        return Err(OAuthCaptureError::IoFailure);
    }
    fs::create_dir_all(path).map_err(|_| OAuthCaptureError::IoFailure)?;
    fs::canonicalize(path).map_err(|_| OAuthCaptureError::IoFailure)
}

fn validate_capture_root(
    audit_root: &Path,
    capture_root: &Path,
) -> Result<PathBuf, OAuthCaptureError> {
    let canonical = windows_platform::secure_validate_contained_directory(audit_root, capture_root)
        .map_err(|_| OAuthCaptureError::CompatibilityProtected)?;
    if canonical.parent() != Some(audit_root) {
        return Err(OAuthCaptureError::CompatibilityProtected);
    }
    Ok(canonical)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TreeEntryFingerprint {
    kind: u8,
    length: u64,
    readonly: bool,
    content: codex_domain::ContentHash,
}

fn tree_hashes_outside(
    root: &Path,
    excluded: &Path,
) -> Result<BTreeMap<PathBuf, TreeEntryFingerprint>, OAuthCaptureError> {
    fn visit(
        root: &Path,
        current: &Path,
        excluded: &Path,
        map: &mut BTreeMap<PathBuf, TreeEntryFingerprint>,
    ) -> Result<(), OAuthCaptureError> {
        for entry in fs::read_dir(current).map_err(|_| OAuthCaptureError::IoFailure)? {
            let entry = entry.map_err(|_| OAuthCaptureError::IoFailure)?;
            let path = entry.path();
            if path == excluded || path.starts_with(excluded) {
                continue;
            }
            let kind = entry
                .file_type()
                .map_err(|_| OAuthCaptureError::IoFailure)?;
            let metadata = fs::symlink_metadata(&path).map_err(|_| OAuthCaptureError::IoFailure)?;
            let relative = path
                .strip_prefix(root)
                .map_err(|_| OAuthCaptureError::IoFailure)?
                .to_path_buf();
            if is_reparse(&metadata) {
                let target = fs::canonicalize(&path)
                    .unwrap_or_else(|_| path.clone())
                    .to_string_lossy()
                    .to_lowercase();
                map.insert(
                    relative,
                    TreeEntryFingerprint {
                        kind: 3,
                        length: metadata.len(),
                        readonly: metadata.permissions().readonly(),
                        content: codex_adapter::hash_bytes(target.as_bytes()),
                    },
                );
            } else if kind.is_dir() {
                map.insert(
                    relative,
                    TreeEntryFingerprint {
                        kind: 1,
                        length: 0,
                        readonly: metadata.permissions().readonly(),
                        content: codex_adapter::hash_bytes(b"directory"),
                    },
                );
                visit(root, &path, excluded, map)?;
            } else if kind.is_file() {
                let bytes = fs::read(&path).map_err(|_| OAuthCaptureError::IoFailure)?;
                map.insert(
                    relative,
                    TreeEntryFingerprint {
                        kind: 2,
                        length: metadata.len(),
                        readonly: metadata.permissions().readonly(),
                        content: codex_adapter::hash_bytes(&bytes),
                    },
                );
            } else {
                return Err(OAuthCaptureError::OutsideWriteDetected);
            }
        }
        Ok(())
    }
    let mut map = BTreeMap::new();
    visit(root, root, excluded, &mut map)?;
    Ok(map)
}

fn remove_tree_no_follow(path: &Path) -> Result<(), std::io::Error> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if is_reparse(&metadata) {
        return fs::remove_dir(path).or_else(|_| fs::remove_file(path));
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            remove_tree_no_follow(&entry?.path())?;
        }
        fs::remove_dir(path)
    } else {
        fs::remove_file(path)
    }
}

#[cfg(windows)]
fn is_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}
