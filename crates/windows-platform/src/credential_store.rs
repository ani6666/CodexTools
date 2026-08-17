use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(windows)]
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

use codex_application::{
    CredentialEnvelopeBinding, CredentialMaterialDiagnostic, CredentialMutationOwner,
    CredentialStore, CredentialStoreError, SecretConsumer,
};
use codex_domain::CredentialRefId;
use zeroize::Zeroize;

use crate::{DpapiCurrentUser, secure_read_contained_file};

const ENVELOPE_VERSION: u32 = 1;
const MAGIC: &[u8] = b"CODEXTOOLS-CREDENTIAL\n";
const MAX_SECRET_BYTES: usize = 1024 * 1024;
const MAX_ENVELOPE_BYTES: usize = MAX_SECRET_BYTES + 64 * 1024;
const FILE_ATTRIBUTE_REPARSE_POINT_VALUE: u32 = 0x0000_0400;
const FILE_FLAG_OPEN_REPARSE_POINT_VALUE: u32 = 0x0020_0000;
static UNIQUE_NONCE: AtomicU64 = AtomicU64::new(1);

pub struct WindowsDpapiCredentialStore {
    root: PathBuf,
    lock_root: PathBuf,
    protector: DpapiCurrentUser,
    workflow_lock: Option<WorkflowLock>,
    successful_read_count: AtomicU64,
}

impl WindowsDpapiCredentialStore {
    pub fn new(root: impl AsRef<Path>) -> Result<Self, CredentialStoreError> {
        let root = root.as_ref();
        if !root.is_absolute() {
            return Err(CredentialStoreError::IoFailure);
        }
        reject_reparse(root)?;
        fs::create_dir_all(root).map_err(|_| CredentialStoreError::IoFailure)?;
        reject_reparse(root)?;
        let root = fs::canonicalize(root).map_err(|_| CredentialStoreError::IoFailure)?;
        let lock_root = root.join(".locks");
        Ok(Self {
            root,
            lock_root,
            protector: DpapiCurrentUser,
            workflow_lock: None,
            successful_read_count: AtomicU64::new(0),
        })
    }

    /// 当前适配器实例完成的受控解密读取次数；仅用于非秘密诊断与验收。
    pub fn successful_read_count(&self) -> u64 {
        self.successful_read_count.load(Ordering::Relaxed)
    }

    pub fn material_path(&self, binding: &CredentialEnvelopeBinding) -> PathBuf {
        self.root
            .join(binding.id().as_str())
            .join(format!("generation-{}.dpapi", binding.generation().value()))
    }

    fn acquire_lock(
        &self,
        binding: &CredentialEnvelopeBinding,
    ) -> Result<CredentialMutationLock, CredentialStoreError> {
        self.acquire_lock_id(binding.id())
    }

    fn acquire_lock_id(
        &self,
        id: &CredentialRefId,
    ) -> Result<CredentialMutationLock, CredentialStoreError> {
        if self
            .workflow_lock
            .as_ref()
            .is_some_and(|held| &held.credential_id == id)
        {
            return Ok(CredentialMutationLock { file: None });
        }
        self.ensure_lock_root()?;
        reject_reparse(&self.lock_root)?;
        let path = self.lock_root.join(format!("{}.lock", id.as_str()));
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true);
        #[cfg(windows)]
        options
            .share_mode(1)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT_VALUE);
        let file = options.open(&path).map_err(|error| {
            if matches!(
                error.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::WouldBlock
            ) || matches!(error.raw_os_error(), Some(32 | 33))
            {
                CredentialStoreError::VersionConflict
            } else {
                CredentialStoreError::IoFailure
            }
        })?;
        reject_reparse_file(&file)?;
        Ok(CredentialMutationLock { file: Some(file) })
    }

    fn ensure_lock_root(&self) -> Result<(), CredentialStoreError> {
        reject_reparse(&self.lock_root)?;
        fs::create_dir(&self.lock_root)
            .or_else(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    Ok(())
                } else {
                    Err(error)
                }
            })
            .map_err(|_| CredentialStoreError::IoFailure)?;
        reject_reparse(&self.lock_root)?;
        if fs::canonicalize(&self.lock_root)
            .map_err(|_| CredentialStoreError::IoFailure)?
            .parent()
            != Some(self.root.as_path())
        {
            return Err(CredentialStoreError::IoFailure);
        }
        Ok(())
    }

    fn credential_directory(
        &self,
        binding: &CredentialEnvelopeBinding,
    ) -> Result<PathBuf, CredentialStoreError> {
        let directory = self.root.join(binding.id().as_str());
        reject_reparse(&directory)?;
        if directory.exists() {
            let canonical =
                fs::canonicalize(&directory).map_err(|_| CredentialStoreError::IoFailure)?;
            if canonical.parent() != Some(self.root.as_path()) {
                return Err(CredentialStoreError::IoFailure);
            }
        }
        Ok(directory)
    }

    fn ensure_credential_directory(
        &self,
        binding: &CredentialEnvelopeBinding,
    ) -> Result<PathBuf, CredentialStoreError> {
        let directory = self.credential_directory(binding)?;
        fs::create_dir(&directory)
            .or_else(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    Ok(())
                } else {
                    Err(error)
                }
            })
            .map_err(|_| CredentialStoreError::IoFailure)?;
        reject_reparse(&directory)?;
        let canonical =
            fs::canonicalize(&directory).map_err(|_| CredentialStoreError::IoFailure)?;
        if canonical.parent() != Some(self.root.as_path()) {
            return Err(CredentialStoreError::IoFailure);
        }
        Ok(directory)
    }

    fn current_generation(
        &self,
        binding: &CredentialEnvelopeBinding,
    ) -> Result<Option<u64>, CredentialStoreError> {
        let directory = self.credential_directory(binding)?;
        if !directory.exists() {
            return Ok(None);
        }
        let mut current = None;
        for entry in fs::read_dir(directory).map_err(|_| CredentialStoreError::IoFailure)? {
            let entry = entry.map_err(|_| CredentialStoreError::IoFailure)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(CredentialStoreError::CorruptEnvelope);
            };
            let Some(generation) = name
                .strip_prefix("generation-")
                .and_then(|name| name.strip_suffix(".dpapi"))
                .and_then(|value| value.parse::<u64>().ok())
            else {
                if !name.starts_with('.') {
                    return Err(CredentialStoreError::CorruptEnvelope);
                }
                continue;
            };
            current = Some(current.map_or(generation, |value: u64| value.max(generation)));
        }
        Ok(current)
    }

    fn write_generation(
        &self,
        binding: &CredentialEnvelopeBinding,
        secret: &mut [u8],
    ) -> Result<(), CredentialStoreError> {
        if secret.is_empty() || secret.len() > MAX_SECRET_BYTES {
            return Err(CredentialStoreError::CorruptEnvelope);
        }
        let directory = self.ensure_credential_directory(binding)?;
        let final_path = self.material_path(binding);
        if final_path.exists() {
            return Err(CredentialStoreError::AlreadyExists);
        }
        let entropy = binding_entropy(binding);
        let protected = self.protector.protect(&entropy, secret)?;
        secret.zeroize();
        let envelope = encode_envelope(binding, &protected)?;
        if envelope.len() > MAX_ENVELOPE_BYTES {
            return Err(CredentialStoreError::CorruptEnvelope);
        }
        let (stage, mut file) = create_unique_stage(&directory, binding.generation().value())?;
        let mut stage_guard = StageGuard {
            path: Some(stage.clone()),
        };
        let result = (|| {
            file.write_all(&envelope)
                .map_err(|_| CredentialStoreError::IoFailure)?;
            file.flush().map_err(|_| CredentialStoreError::IoFailure)?;
            file.sync_all()
                .map_err(|_| CredentialStoreError::IoFailure)?;
            drop(file);
            if fs::hard_link(&stage, &final_path).is_err() {
                return if final_path.exists() {
                    Err(CredentialStoreError::AlreadyExists)
                } else {
                    Err(CredentialStoreError::IoFailure)
                };
            }
            Ok(())
        })();
        if stage_guard.cleanup().is_err() {
            return Err(CredentialStoreError::RecoveryRequired);
        }
        result
    }

    fn load_envelope(
        &self,
        binding: &CredentialEnvelopeBinding,
    ) -> Result<Vec<u8>, CredentialStoreError> {
        let directory = self.credential_directory(binding)?;
        if !directory.exists() {
            return Err(CredentialStoreError::NotFound);
        }
        let bytes = self.load_raw_envelope(binding)?;
        decode_envelope(binding, &bytes)
    }

    fn load_raw_envelope(
        &self,
        binding: &CredentialEnvelopeBinding,
    ) -> Result<Vec<u8>, CredentialStoreError> {
        let path = self.material_path(binding);
        secure_read_contained_file(&self.root, &path, MAX_ENVELOPE_BYTES as u64).map_err(|error| {
            match error.kind() {
                std::io::ErrorKind::NotFound => CredentialStoreError::NotFound,
                std::io::ErrorKind::InvalidData => CredentialStoreError::CorruptEnvelope,
                _ => CredentialStoreError::IoFailure,
            }
        })
    }

    fn validate_envelope(
        &self,
        binding: &CredentialEnvelopeBinding,
    ) -> Result<(), CredentialStoreError> {
        self.validate_envelope_path(binding, &self.material_path(binding))
    }

    fn validate_envelope_path(
        &self,
        binding: &CredentialEnvelopeBinding,
        path: &Path,
    ) -> Result<(), CredentialStoreError> {
        let bytes = secure_read_contained_file(&self.root, path, MAX_ENVELOPE_BYTES as u64)
            .map_err(map_secure_read_error)?;
        let protected = decode_envelope(binding, &bytes)?;
        let entropy = binding_entropy(binding);
        self.protector.unprotect(&entropy, &protected, |plaintext| {
            if plaintext.is_empty() || plaintext.len() > MAX_SECRET_BYTES {
                Err(CredentialStoreError::CorruptEnvelope)
            } else {
                Ok(())
            }
        })
    }

    fn cleanup_stages(
        &self,
        binding: &CredentialEnvelopeBinding,
    ) -> Result<(), CredentialStoreError> {
        let directory = self.credential_directory(binding)?;
        if !directory.exists() {
            return Ok(());
        }
        let prefix = format!(".generation-{}-", binding.generation().value());
        for entry in fs::read_dir(&directory).map_err(|_| CredentialStoreError::IoFailure)? {
            let entry = entry.map_err(|_| CredentialStoreError::IoFailure)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(CredentialStoreError::RecoveryRequired);
            };
            if !name.starts_with(&prefix) || !name.ends_with(".stage") {
                continue;
            }
            let path = entry.path();
            let metadata =
                fs::symlink_metadata(&path).map_err(|_| CredentialStoreError::RecoveryRequired)?;
            if !metadata.is_file() || metadata_is_reparse(&metadata) {
                return Err(CredentialStoreError::RecoveryRequired);
            }
            fs::remove_file(path).map_err(|_| CredentialStoreError::RecoveryRequired)?;
        }
        Ok(())
    }

    fn diagnostic_for_path(
        &self,
        binding: &CredentialEnvelopeBinding,
        path: &Path,
    ) -> Result<CredentialMaterialDiagnostic, CredentialStoreError> {
        self.validate_envelope_path(binding, path)?;
        let envelope = secure_read_contained_file(&self.root, path, MAX_ENVELOPE_BYTES as u64)
            .map_err(map_secure_read_error)?;
        Ok(CredentialMaterialDiagnostic {
            material_ref: self
                .material_path(binding)
                .strip_prefix(&self.root)
                .map_err(|_| CredentialStoreError::IoFailure)?
                .to_path_buf(),
            material_hash: codex_adapter::hash_bytes(&envelope),
        })
    }
}

impl CredentialStore for WindowsDpapiCredentialStore {
    fn begin_mutation(
        &mut self,
        id: &CredentialRefId,
    ) -> Result<CredentialMutationOwner, CredentialStoreError> {
        if self.workflow_lock.is_some() {
            return Err(CredentialStoreError::VersionConflict);
        }
        let lock = self.acquire_lock_id(id)?;
        let nonce = UNIQUE_NONCE.fetch_add(1, Ordering::Relaxed);
        self.workflow_lock = Some(WorkflowLock {
            credential_id: id.clone(),
            nonce,
            _file: lock.file,
        });
        Ok(CredentialMutationOwner::new(id.clone(), nonce))
    }

    fn end_mutation(&mut self, owner: CredentialMutationOwner) -> Result<(), CredentialStoreError> {
        let Some(held) = self.workflow_lock.take() else {
            return Err(CredentialStoreError::RecoveryRequired);
        };
        if held.credential_id != *owner.credential_id() || held.nonce != owner.nonce() {
            self.workflow_lock = Some(held);
            return Err(CredentialStoreError::RecoveryRequired);
        }
        drop(held);
        Ok(())
    }
    fn planned_material_ref(
        &self,
        binding: &CredentialEnvelopeBinding,
    ) -> Result<PathBuf, CredentialStoreError> {
        let path = self.material_path(binding);
        path.strip_prefix(&self.root)
            .map(Path::to_path_buf)
            .map_err(|_| CredentialStoreError::IoFailure)
    }

    fn create(
        &mut self,
        binding: &CredentialEnvelopeBinding,
        secret: &mut [u8],
    ) -> Result<(), CredentialStoreError> {
        let result = (|| {
            let _lock = self.acquire_lock(binding)?;
            self.cleanup_stages(binding)?;
            if binding.generation().value() != 1 || self.current_generation(binding)?.is_some() {
                return Err(CredentialStoreError::AlreadyExists);
            }
            self.write_generation(binding, secret)
        })();
        secret.zeroize();
        result
    }

    fn read(
        &self,
        binding: &CredentialEnvelopeBinding,
        consumer: &mut dyn SecretConsumer,
    ) -> Result<(), CredentialStoreError> {
        let _lock = self.acquire_lock(binding)?;
        self.cleanup_stages(binding)?;
        let protected = self.load_envelope(binding)?;
        let entropy = binding_entropy(binding);
        let result = self.protector.unprotect(&entropy, &protected, |plaintext| {
            if plaintext.is_empty() || plaintext.len() > MAX_SECRET_BYTES {
                return Err(CredentialStoreError::CorruptEnvelope);
            }
            consumer.consume(plaintext)
        });
        if result.is_ok() {
            self.successful_read_count.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    fn rotate(
        &mut self,
        previous: &CredentialEnvelopeBinding,
        next: &CredentialEnvelopeBinding,
        secret: &mut [u8],
    ) -> Result<(), CredentialStoreError> {
        let result = (|| {
            if previous.id() != next.id()
                || previous.kind() != next.kind()
                || previous.schema_fingerprint() != next.schema_fingerprint()
            {
                return Err(CredentialStoreError::BindingMismatch);
            }
            if next.generation().value() != previous.generation().value() + 1 {
                return Err(CredentialStoreError::VersionConflict);
            }
            let _lock = self.acquire_lock(previous)?;
            self.cleanup_stages(next)?;
            if self.current_generation(previous)? != Some(previous.generation().value()) {
                return Err(CredentialStoreError::VersionConflict);
            }
            self.validate_envelope(previous)?;
            if self.material_path(next).exists() {
                return Err(CredentialStoreError::VersionConflict);
            }
            self.write_generation(next, secret)
        })();
        secret.zeroize();
        result
    }

    fn delete(&mut self, binding: &CredentialEnvelopeBinding) -> Result<(), CredentialStoreError> {
        let _lock = self.acquire_lock(binding)?;
        let directory = self.credential_directory(binding)?;
        let quarantine = delete_quarantine(&self.root, binding);
        if quarantine.exists() {
            if directory.exists() {
                return Err(CredentialStoreError::RecoveryRequired);
            }
            self.validate_envelope_path(
                binding,
                &quarantine.join(format!("generation-{}.dpapi", binding.generation().value())),
            )?;
            return remove_tree_no_follow(&quarantine)
                .map_err(|_| CredentialStoreError::RecoveryRequired);
        }
        if !directory.exists() {
            return Err(CredentialStoreError::NotFound);
        }
        if self.current_generation(binding)? != Some(binding.generation().value()) {
            return Err(CredentialStoreError::VersionConflict);
        }
        self.validate_envelope(binding)?;
        fs::rename(&directory, &quarantine).map_err(|_| CredentialStoreError::IoFailure)?;
        if let Err(error) = reject_reparse(&quarantine) {
            let _ = fs::rename(&quarantine, &directory);
            return Err(error);
        }
        let canonical =
            fs::canonicalize(&quarantine).map_err(|_| CredentialStoreError::IoFailure)?;
        if canonical.parent() != Some(self.root.as_path()) {
            let _ = fs::rename(&quarantine, &directory);
            return Err(CredentialStoreError::IoFailure);
        }
        remove_tree_no_follow(&quarantine).map_err(|_| CredentialStoreError::RecoveryRequired)
    }

    fn inspect(
        &self,
        binding: &CredentialEnvelopeBinding,
    ) -> Result<CredentialMaterialDiagnostic, CredentialStoreError> {
        let _lock = self.acquire_lock(binding)?;
        self.cleanup_stages(binding)?;
        self.diagnostic_for_path(binding, &self.material_path(binding))
    }

    fn inspect_delete_recovery(
        &self,
        binding: &CredentialEnvelopeBinding,
    ) -> Result<CredentialMaterialDiagnostic, CredentialStoreError> {
        let _lock = self.acquire_lock(binding)?;
        let directory = self.credential_directory(binding)?;
        let quarantine = delete_quarantine(&self.root, binding);
        match (directory.exists(), quarantine.exists()) {
            (true, false) => self.diagnostic_for_path(binding, &self.material_path(binding)),
            (false, true) => self.diagnostic_for_path(
                binding,
                &quarantine.join(format!("generation-{}.dpapi", binding.generation().value())),
            ),
            (false, false) => Err(CredentialStoreError::NotFound),
            (true, true) => Err(CredentialStoreError::RecoveryRequired),
        }
    }

    fn restore_delete_recovery(
        &mut self,
        binding: &CredentialEnvelopeBinding,
    ) -> Result<(), CredentialStoreError> {
        let _lock = self.acquire_lock(binding)?;
        let directory = self.credential_directory(binding)?;
        let quarantine = delete_quarantine(&self.root, binding);
        match (directory.exists(), quarantine.exists()) {
            (true, false) => {
                self.diagnostic_for_path(binding, &self.material_path(binding))?;
                Ok(())
            }
            (false, true) => {
                self.diagnostic_for_path(
                    binding,
                    &quarantine.join(format!("generation-{}.dpapi", binding.generation().value())),
                )?;
                fs::rename(&quarantine, &directory)
                    .map_err(|_| CredentialStoreError::RecoveryRequired)?;
                self.diagnostic_for_path(binding, &self.material_path(binding))?;
                Ok(())
            }
            _ => Err(CredentialStoreError::RecoveryRequired),
        }
    }

    fn rollback_rotation(
        &mut self,
        previous: &CredentialEnvelopeBinding,
        next: &CredentialEnvelopeBinding,
    ) -> Result<(), CredentialStoreError> {
        if previous.id() != next.id()
            || previous.kind() != next.kind()
            || previous.schema_fingerprint() != next.schema_fingerprint()
            || next.generation().value() != previous.generation().value() + 1
        {
            return Err(CredentialStoreError::BindingMismatch);
        }
        let _lock = self.acquire_lock(next)?;
        let next_path = self.material_path(next);
        let quarantine = rollback_quarantine(&next_path, next);
        if quarantine.exists() {
            if next_path.exists() {
                return Err(CredentialStoreError::RecoveryRequired);
            }
            self.validate_envelope(previous)?;
            self.validate_envelope_path(next, &quarantine)?;
            fs::remove_file(&quarantine).map_err(|_| CredentialStoreError::RecoveryRequired)?;
            return if self.current_generation(previous)? == Some(previous.generation().value()) {
                Ok(())
            } else {
                Err(CredentialStoreError::RecoveryRequired)
            };
        }
        if self.current_generation(previous)? == Some(previous.generation().value())
            && !next_path.exists()
        {
            self.validate_envelope(previous)?;
            return Ok(());
        }
        if self.current_generation(next)? != Some(next.generation().value()) {
            return Err(CredentialStoreError::VersionConflict);
        }
        self.validate_envelope(previous)?;
        self.validate_envelope(next)?;
        fs::rename(&next_path, &quarantine).map_err(|_| CredentialStoreError::IoFailure)?;
        if let Err(error) = reject_reparse(&quarantine) {
            let _ = fs::rename(&quarantine, &next_path);
            return Err(error);
        }
        fs::remove_file(&quarantine).map_err(|_| CredentialStoreError::RecoveryRequired)?;
        if self.current_generation(previous)? != Some(previous.generation().value()) {
            return Err(CredentialStoreError::RecoveryRequired);
        }
        Ok(())
    }
}

fn map_secure_read_error(error: std::io::Error) -> CredentialStoreError {
    match error.kind() {
        std::io::ErrorKind::NotFound => CredentialStoreError::NotFound,
        std::io::ErrorKind::InvalidData => CredentialStoreError::CorruptEnvelope,
        _ => CredentialStoreError::IoFailure,
    }
}

struct CredentialMutationLock {
    file: Option<File>,
}

struct WorkflowLock {
    credential_id: CredentialRefId,
    nonce: u64,
    _file: Option<File>,
}

struct StageGuard {
    path: Option<PathBuf>,
}
impl StageGuard {
    fn cleanup(&mut self) -> std::io::Result<()> {
        if let Some(path) = self.path.take() {
            fs::remove_file(path)?;
        }
        Ok(())
    }
}
impl Drop for StageGuard {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

fn delete_quarantine(root: &Path, binding: &CredentialEnvelopeBinding) -> PathBuf {
    root.join(format!(
        ".delete-{}-generation-{}",
        binding.id().as_str(),
        binding.generation().value()
    ))
}

fn rollback_quarantine(path: &Path, binding: &CredentialEnvelopeBinding) -> PathBuf {
    path.with_file_name(format!(
        ".rollback-generation-{}",
        binding.generation().value()
    ))
}

fn create_unique_stage(
    directory: &Path,
    generation: u64,
) -> Result<(PathBuf, File), CredentialStoreError> {
    for _ in 0..32 {
        let path = directory.join(format!(".generation-{generation}-{}.stage", unique_nonce()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(windows)]
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT_VALUE);
        match options.open(&path) {
            Ok(file) => {
                reject_reparse_file(&file)?;
                return Ok((path, file));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(CredentialStoreError::IoFailure),
        }
    }
    Err(CredentialStoreError::IoFailure)
}

fn unique_nonce() -> u128 {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    time ^ ((u128::from(std::process::id())) << 64)
        ^ u128::from(UNIQUE_NONCE.fetch_add(1, Ordering::Relaxed))
}

fn reject_reparse(path: &Path) -> Result<(), CredentialStoreError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(CredentialStoreError::IoFailure),
    };
    #[cfg(windows)]
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT_VALUE != 0 {
        return Err(CredentialStoreError::IoFailure);
    }
    #[cfg(not(windows))]
    if metadata.file_type().is_symlink() {
        return Err(CredentialStoreError::IoFailure);
    }
    Ok(())
}

fn reject_reparse_file(file: &File) -> Result<(), CredentialStoreError> {
    #[cfg(windows)]
    if file
        .metadata()
        .map_err(|_| CredentialStoreError::IoFailure)?
        .file_attributes()
        & FILE_ATTRIBUTE_REPARSE_POINT_VALUE
        != 0
    {
        return Err(CredentialStoreError::IoFailure);
    }
    Ok(())
}

fn remove_tree_no_follow(path: &Path) -> Result<(), std::io::Error> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata_is_reparse(&metadata) {
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
fn metadata_is_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT_VALUE != 0
}

#[cfg(not(windows))]
fn metadata_is_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn binding_entropy(binding: &CredentialEnvelopeBinding) -> Vec<u8> {
    format!(
        "codextools:v1:{}:{}:{}:{}",
        binding.id().as_str(),
        binding.kind().as_storage_str(),
        binding.schema_fingerprint().as_str(),
        binding.generation().value()
    )
    .into_bytes()
}

fn encode_envelope(
    binding: &CredentialEnvelopeBinding,
    protected: &[u8],
) -> Result<Vec<u8>, CredentialStoreError> {
    let header = format!(
        "version={ENVELOPE_VERSION}\nid={}\nkind={}\nschema={}\ngeneration={}\nlength={}\n\n",
        binding.id().as_str(),
        binding.kind().as_storage_str(),
        binding.schema_fingerprint().as_str(),
        binding.generation().value(),
        protected.len()
    );
    let mut bytes = Vec::with_capacity(MAGIC.len() + header.len() + protected.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(header.as_bytes());
    bytes.extend_from_slice(protected);
    Ok(bytes)
}

fn decode_envelope(
    binding: &CredentialEnvelopeBinding,
    bytes: &[u8],
) -> Result<Vec<u8>, CredentialStoreError> {
    if !bytes.starts_with(MAGIC) {
        return Err(CredentialStoreError::CorruptEnvelope);
    }
    let rest = &bytes[MAGIC.len()..];
    let split = rest
        .windows(2)
        .position(|pair| pair == b"\n\n")
        .ok_or(CredentialStoreError::CorruptEnvelope)?;
    let header =
        std::str::from_utf8(&rest[..split]).map_err(|_| CredentialStoreError::CorruptEnvelope)?;
    let payload = &rest[split + 2..];
    let expected = [
        ("version", ENVELOPE_VERSION.to_string()),
        ("id", binding.id().as_str().to_owned()),
        ("kind", binding.kind().as_storage_str().to_owned()),
        ("schema", binding.schema_fingerprint().as_str().to_owned()),
        ("generation", binding.generation().value().to_string()),
        ("length", payload.len().to_string()),
    ];
    let lines = header.lines().collect::<Vec<_>>();
    if lines.len() != expected.len() {
        return Err(CredentialStoreError::CorruptEnvelope);
    }
    for ((key, value), line) in expected.iter().zip(lines) {
        if line != format!("{key}={value}") {
            return Err(CredentialStoreError::BindingMismatch);
        }
    }
    Ok(payload.to_vec())
}
