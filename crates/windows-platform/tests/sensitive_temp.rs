#![cfg(windows)]

use codex_adapter as _;
use codex_application as _;
use codex_domain as _;
use zeroize as _;

use std::{
    fs::{self, OpenOptions},
    os::windows::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

use windows_platform::{
    RootNamespacePin, SensitiveHandleState, SensitiveTempFile, probe_sensitive_temp_capabilities,
};

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "codextools-sensitive-temp-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn delete_on_close_clear_close_survival_and_rearm_are_handle_bound() {
    let area = TempRoot::new("delete-on-close");
    let pin = RootNamespacePin::acquire(&area.0).unwrap();
    probe_sensitive_temp_capabilities(&pin).unwrap();

    let mut file = SensitiveTempFile::create_delete_armed(&pin, ".probe-owner").unwrap();
    assert_eq!(file.state(), SensitiveHandleState::PrewriteDeleteArmed);
    assert!(file.delete_pending().unwrap());
    let identity = file.identity();
    file.clear_delete_on_close(&pin).unwrap();
    assert_eq!(file.state(), SensitiveHandleState::Owned);
    assert!(!file.delete_pending().unwrap());
    drop(file);

    let mut reopened = SensitiveTempFile::reopen_owned(&pin, ".probe-owner", identity).unwrap();
    assert_eq!(reopened.identity(), identity);
    reopened.arm_delete_on_close().unwrap();
    assert!(reopened.delete_pending().unwrap());
    drop(reopened);
    assert!(!area.0.join(".probe-owner").exists());
}

#[test]
fn root_pin_denies_namespace_rename_until_drop() {
    let area = TempRoot::new("root-pin");
    let renamed = area.0.with_extension("renamed");
    let pin = RootNamespacePin::acquire(&area.0).unwrap();
    let error = fs::rename(&area.0, &renamed).unwrap_err();
    assert_eq!(error.raw_os_error(), Some(32));
    drop(pin);
    fs::rename(&area.0, &renamed).unwrap();
    fs::rename(&renamed, &area.0).unwrap();
}

#[test]
fn root_pin_denies_ancestor_rename_and_rejects_unc_or_verbatim_input() {
    let outer = TempRoot::new("ancestor-pin");
    let root = outer.0.join("root");
    fs::create_dir(&root).unwrap();
    let renamed = outer.0.with_extension("renamed");
    let pin = RootNamespacePin::acquire(&root).unwrap();
    let error = fs::rename(&outer.0, &renamed).unwrap_err();
    assert!(matches!(error.raw_os_error(), Some(5) | Some(32)));
    assert!(root.is_dir());
    drop(pin);
    let canonical = fs::canonicalize(&root).unwrap();
    assert_eq!(
        RootNamespacePin::acquire(&canonical).unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
    assert_eq!(
        RootNamespacePin::acquire(Path::new(r"\\HOST\share\TARGET"))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidData
    );
}

#[test]
fn identity_mismatch_and_rename_false_keep_unknown_or_source_untouched() {
    let area = TempRoot::new("identity-rename-false");
    let pin = RootNamespacePin::acquire(&area.0).unwrap();
    let mut owned = SensitiveTempFile::create_delete_armed(&pin, ".identity-owner").unwrap();
    let identity = owned.identity();
    owned.clear_delete_on_close(&pin).unwrap();
    drop(owned);
    fs::remove_file(area.0.join(".identity-owner")).unwrap();
    fs::write(area.0.join(".identity-owner"), b"UNKNOWN-NONSECRET").unwrap();
    assert!(SensitiveTempFile::reopen_owned(&pin, ".identity-owner", identity).is_err());
    assert_eq!(
        fs::read(area.0.join(".identity-owner")).unwrap(),
        b"UNKNOWN-NONSECRET"
    );
    fs::remove_file(area.0.join(".identity-owner")).unwrap();

    fs::write(area.0.join("target"), b"TARGET-NONSECRET").unwrap();
    let held_target = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(area.0.join("target"))
        .unwrap();
    let mut source = SensitiveTempFile::create_delete_armed(&pin, ".rename-source").unwrap();
    source.clear_delete_on_close(&pin).unwrap();
    source.write_once(b"SOURCE-NONSECRET").unwrap();
    let error = source.rename_relative(&pin, "target").unwrap_err();
    assert!(matches!(error.raw_os_error(), Some(5) | Some(32)));
    assert_eq!(source.state(), SensitiveHandleState::RenameFailedUnknown);
    assert_eq!(source.final_basename().unwrap(), ".rename-source");
    assert_eq!(
        fs::read(area.0.join("target")).unwrap(),
        b"TARGET-NONSECRET"
    );
    drop(held_target);
    source.arm_delete_on_close().unwrap();
}
