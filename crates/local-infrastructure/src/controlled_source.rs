use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use codex_adapter::{ControlledRootReader, StableSnapshotConsumer, hash_bytes};
use codex_application::{
    CompatibilityReason, ControlledRoot, ControlledRootResolver, ControlledSourceError,
};
use codex_domain::UnixMillis;
use windows_platform::{PinnedLiveFile, RootNamespacePin};
use zeroize::Zeroizing;

const MAX_CONFIG: u64 = 1024 * 1024;
const MAX_AUTH: u64 = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct WindowsControlledRootReader<R = DefaultCodexRootResolver> {
    resolver: R,
}

impl WindowsControlledRootReader<DefaultCodexRootResolver> {
    #[must_use]
    pub const fn default_codex() -> Self {
        Self {
            resolver: DefaultCodexRootResolver,
        }
    }
}

impl<R> WindowsControlledRootReader<R> {
    #[must_use]
    pub const fn new(resolver: R) -> Self {
        Self { resolver }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultCodexRootResolver;

impl ControlledRootResolver for DefaultCodexRootResolver {
    fn resolve(&self, root: ControlledRoot) -> Result<PathBuf, ControlledSourceError> {
        match root {
            ControlledRoot::DefaultCodex => windows_platform::default_codex_root()
                .map_err(|_| ControlledSourceError::IoUnavailable),
        }
    }
}

fn map_read_error(error: &std::io::Error) -> ControlledSourceError {
    if matches!(
        error.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidData
    ) {
        ControlledSourceError::CompatibilityProtected(CompatibilityReason::IoUnavailable)
    } else {
        ControlledSourceError::IoUnavailable
    }
}

fn evidence(
    root: windows_platform::FileIdentity128,
    config: &PinnedLiveFile,
    auth: &PinnedLiveFile,
    config_bytes: &[u8],
    auth_bytes: &[u8],
) -> Vec<u8> {
    let mut value = Vec::with_capacity(152);
    value.extend_from_slice(&root.volume_serial_number.to_be_bytes());
    value.extend_from_slice(&root.file_id);
    for (file, bytes) in [(config, config_bytes), (auth, auth_bytes)] {
        let identity = file.identity();
        value.extend_from_slice(&identity.volume_serial_number.to_be_bytes());
        value.extend_from_slice(&identity.file_id);
        value.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        value.extend_from_slice(hash_bytes(bytes).as_str().as_bytes());
    }
    value
}

impl<R: ControlledRootResolver> ControlledRootReader for WindowsControlledRootReader<R> {
    fn read_stable(
        &self,
        root: ControlledRoot,
        consumer: &mut dyn StableSnapshotConsumer,
    ) -> Result<(), ControlledSourceError> {
        let path = self.resolver.resolve(root)?;
        read_stable_path(&path, consumer)
    }
}

fn read_stable_path(
    path: &Path,
    consumer: &mut dyn StableSnapshotConsumer,
) -> Result<(), ControlledSourceError> {
    let initial_root = RootNamespacePin::acquire(path).map_err(|error| map_read_error(&error))?;
    let canonical_root = initial_root.final_path().to_path_buf();
    drop(initial_root);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .and_then(|value| UnixMillis::new(value).ok())
        .ok_or(ControlledSourceError::IoUnavailable)?;
    let _lock = crate::CrossProcessWriteLock::try_acquire(&canonical_root, now).map_err(
        |error| match error {
            codex_application::SwitchExecutionError::Busy => ControlledSourceError::Busy,
            _ => ControlledSourceError::IoUnavailable,
        },
    )?;
    let root = RootNamespacePin::acquire_canonical(&canonical_root)
        .map_err(|error| map_read_error(&error))?;
    if !root
        .relative_directory_is_empty(".codextools-transactions")
        .map_err(|error| map_read_error(&error))?
    {
        return Err(ControlledSourceError::RecoveryRequired);
    }
    let mut config = PinnedLiveFile::open_stable_read(&root, "config.toml")
        .map_err(|error| map_read_error(&error))?;
    let mut auth = PinnedLiveFile::open_stable_read(&root, "auth.json")
        .map_err(|error| map_read_error(&error))?;
    let config_length = config.length().map_err(|error| map_read_error(&error))?;
    let auth_length = auth.length().map_err(|error| map_read_error(&error))?;
    let mut config_bytes = config
        .reread(MAX_CONFIG)
        .map_err(|error| map_read_error(&error))?;
    let mut auth_bytes = auth
        .reread(MAX_AUTH)
        .map_err(|error| map_read_error(&error))?;
    root.verify_identity()
        .map_err(|error| map_read_error(&error))?;
    config
        .verify_identity(&root)
        .map_err(|error| map_read_error(&error))?;
    auth.verify_identity(&root)
        .map_err(|error| map_read_error(&error))?;
    if config.length().map_err(|error| map_read_error(&error))? != config_length
        || auth.length().map_err(|error| map_read_error(&error))? != auth_length
    {
        return Err(ControlledSourceError::ScanChanged);
    }
    let second_config = config
        .reread(MAX_CONFIG)
        .map_err(|error| map_read_error(&error))?;
    let second_auth: Zeroizing<Vec<u8>> = auth
        .reread(MAX_AUTH)
        .map_err(|error| map_read_error(&error))?;
    if *config_bytes != *second_config || *auth_bytes != *second_auth {
        return Err(ControlledSourceError::ScanChanged);
    }
    let evidence = evidence(root.identity(), &config, &auth, &config_bytes, &auth_bytes);
    consumer.consume(&mut config_bytes, &mut auth_bytes, &evidence)
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        panic::{AssertUnwindSafe, catch_unwind},
        rc::Rc,
    };

    use codex_adapter::StableSnapshotConsumer;
    use zeroize::Zeroize;

    use super::*;

    struct RejectingConsumer;

    impl StableSnapshotConsumer for RejectingConsumer {
        fn consume(
            &mut self,
            _config: &mut [u8],
            _auth: &mut [u8],
            _evidence: &[u8],
        ) -> Result<(), ControlledSourceError> {
            Err(ControlledSourceError::ConsumerRejected)
        }
    }

    struct ObservedSecret {
        bytes: Zeroizing<Vec<u8>>,
        zeroized: Rc<Cell<bool>>,
    }

    struct ObservedBuffer {
        bytes: Zeroizing<Vec<u8>>,
        zeroized: Rc<Cell<bool>>,
    }

    impl Drop for ObservedBuffer {
        fn drop(&mut self) {
            self.bytes.zeroize();
            self.zeroized.set(self.bytes.iter().all(|byte| *byte == 0));
        }
    }

    impl Drop for ObservedSecret {
        fn drop(&mut self) {
            self.bytes.zeroize();
            self.zeroized.set(self.bytes.iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn owned_stable_auth_buffer_zeroizes_on_consumer_error_and_unwind() {
        let rejected = Rc::new(Cell::new(false));
        {
            let mut secret = ObservedSecret {
                bytes: Zeroizing::new(b"synthetic-owned-auth".to_vec()),
                zeroized: rejected.clone(),
            };
            let result =
                RejectingConsumer.consume(&mut [], &mut secret.bytes, b"evidence");
            assert_eq!(result, Err(ControlledSourceError::ConsumerRejected));
        }
        assert!(rejected.get());

        let unwound = Rc::new(Cell::new(false));
        let observed = unwound.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _secret = ObservedSecret {
                bytes: Zeroizing::new(b"synthetic-unwind-auth".to_vec()),
                zeroized: observed,
            };
            panic!("synthetic stable reader unwind");
        }));
        assert!(result.is_err());
        assert!(unwound.get());
    }

    #[test]
    fn owned_stable_config_buffer_zeroizes_on_rejection_and_unwind() {
        let rejected = Rc::new(Cell::new(false));
        {
            let mut config = ObservedBuffer {
                bytes: Zeroizing::new(
                    b"unknown = \"-----BEGIN PRIVATE KEY-----\"".to_vec(),
                ),
                zeroized: rejected.clone(),
            };
            let mut auth = b"{}".to_vec();
            let result = RejectingConsumer.consume(&mut config.bytes, &mut auth, b"evidence");
            assert_eq!(result, Err(ControlledSourceError::ConsumerRejected));
        }
        assert!(rejected.get());

        let unwound = Rc::new(Cell::new(false));
        let observed = unwound.clone();
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _config = ObservedBuffer {
                bytes: Zeroizing::new(b"synthetic-config-unwind".to_vec()),
                zeroized: observed,
            };
            panic!("synthetic stable config unwind");
        }));
        assert!(result.is_err());
        assert!(unwound.get());
    }
}
