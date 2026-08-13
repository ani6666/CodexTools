#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FileIdentity128 {
    pub volume_serial_number: u64,
    pub file_id: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SensitiveHandleState {
    PrewriteDeleteArmed,
    Owned,
    MaybePublished,
    RenameFailedUnknown,
    Published,
    CleanupDeleteArmed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelativePathObservation {
    Absent,
    SameOwnerId {
        identity: FileIdentity128,
        length: u64,
        readonly: bool,
    },
    OtherId {
        identity: FileIdentity128,
        length: u64,
        readonly: bool,
    },
    Reparse,
    QueryError(i32),
}

#[cfg(windows)]
mod imp {
    use std::{
        ffi::OsStr,
        fs::File,
        io::{self, Read, Seek, SeekFrom, Write},
        mem::{offset_of, size_of},
        os::windows::{
            ffi::OsStrExt,
            fs::MetadataExt,
            io::{AsRawHandle, FromRawHandle},
        },
        path::{Component, Path, PathBuf},
        ptr,
        time::{SystemTime, UNIX_EPOCH},
    };

    use windows_sys::Win32::{
        Foundation::{
            ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, GENERIC_READ, GENERIC_WRITE, HANDLE,
            INVALID_HANDLE_VALUE,
        },
        Storage::FileSystem::{
            CREATE_NEW, CreateFileW, DELETE, FILE_ADD_FILE, FILE_ATTRIBUTE_NORMAL,
            FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_BASIC_INFO,
            FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
            FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO_EX,
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_DELETE_ON_CLOSE, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_ID_INFO, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_RENAME_INFO,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO,
            FILE_TRAVERSE, FILE_WRITE_ATTRIBUTES, FileBasicInfo, FileDispositionInfoEx, FileIdInfo,
            FileStandardInfo, GetFileInformationByHandleEx, GetFinalPathNameByHandleW,
            OPEN_EXISTING, SYNCHRONIZE, SetFileInformationByHandle,
        },
    };
    use zeroize::Zeroizing;

    use super::{FileIdentity128, RelativePathObservation, SensitiveHandleState};

    const FILE_RENAME_FLAG_REPLACE_IF_EXISTS: u32 = 0x0000_0001;
    const FILE_RENAME_FLAG_POSIX_SEMANTICS: u32 = 0x0000_0002;
    const FILE_NAME_NORMALIZED: u32 = 0;
    const VOLUME_NAME_DOS: u32 = 0;
    const MAX_HANDLE_READ: u64 = 16 * 1024 * 1024;
    const FILE_RENAME_INFORMATION_EX: i32 = 65;
    const FILE_LINK_INFO_CLASS: i32 = 11;

    #[repr(C)]
    struct IoStatusBlock {
        status_or_pointer: usize,
        information: usize,
    }

    #[repr(C)]
    struct FileLinkInfoBuffer {
        replace_if_exists: i32,
        root_directory: HANDLE,
        file_name_length: u32,
        file_name: [u16; 1],
    }

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtSetInformationFile(
            file_handle: HANDLE,
            io_status_block: *mut IoStatusBlock,
            file_information: *const core::ffi::c_void,
            length: u32,
            file_information_class: i32,
        ) -> i32;
        fn RtlNtStatusToDosError(status: i32) -> u32;
    }

    #[derive(Debug)]
    pub struct RootNamespacePin {
        file: File,
        root_path: PathBuf,
        final_path: PathBuf,
        identity: FileIdentity128,
    }

    impl RootNamespacePin {
        pub fn acquire(root: &Path) -> io::Result<Self> {
            validate_explicit_root(root)?;
            let direct = create_file(
                root,
                FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            )?;
            let direct_metadata = direct.metadata()?;
            if !direct_metadata.is_dir()
                || direct_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            {
                return Err(invalid_data("root path is a reparse directory"));
            }
            let canonical = std::fs::canonicalize(root)?;
            let pin = Self::acquire_canonical(&canonical)?;
            if file_identity(&direct)? != pin.identity {
                return Err(invalid_data("root path identity changed during pin"));
            }
            Ok(pin)
        }

        pub fn acquire_canonical(canonical: &Path) -> io::Result<Self> {
            validate_canonical_root(canonical)?;
            let file = create_file(
                canonical,
                FILE_LIST_DIRECTORY
                    | FILE_ADD_FILE
                    | FILE_TRAVERSE
                    | FILE_READ_ATTRIBUTES
                    | GENERIC_WRITE
                    | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            )?;
            let metadata = file.metadata()?;
            if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            {
                return Err(invalid_data("root is not a non-reparse directory"));
            }
            let identity = file_identity(&file)?;
            let final_path = final_path(&file)?;
            let parent = final_path
                .parent()
                .ok_or_else(|| invalid_data("root has no parent"))?;
            if parent == final_path {
                return Err(invalid_data(
                    "filesystem root is not a supported switch root",
                ));
            }
            Ok(Self {
                file,
                root_path: canonical.to_path_buf(),
                final_path,
                identity,
            })
        }

        #[must_use]
        pub const fn identity(&self) -> FileIdentity128 {
            self.identity
        }

        #[must_use]
        pub fn root_path(&self) -> &Path {
            &self.root_path
        }

        #[must_use]
        pub fn final_path(&self) -> &Path {
            &self.final_path
        }

        fn raw(&self) -> HANDLE {
            self.file.as_raw_handle() as HANDLE
        }

        pub fn verify_identity(&self) -> io::Result<()> {
            if file_identity(&self.file)? != self.identity {
                return Err(invalid_data("root identity changed"));
            }
            Ok(())
        }

        pub fn relative_directory_is_empty(&self, basename: &str) -> io::Result<bool> {
            validate_basename(basename)?;
            self.verify_identity()?;
            let path = self.final_path.join(basename);
            match std::fs::symlink_metadata(&path) {
                Ok(metadata) => {
                    if !metadata.is_dir()
                        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                    {
                        return Err(invalid_data("relative path is not a plain directory"));
                    }
                    Ok(std::fs::read_dir(path)?.next().transpose()?.is_none())
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
                Err(error) => Err(error),
            }
        }

        pub fn observe_relative(
            &self,
            basename: &str,
            expected: FileIdentity128,
        ) -> RelativePathObservation {
            if validate_basename(basename).is_err() || self.verify_identity().is_err() {
                return RelativePathObservation::QueryError(-1);
            }
            let path = self.final_path.join(basename);
            let file = match create_file(
                &path,
                GENERIC_READ | DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            ) {
                Ok(file) => file,
                Err(error) => {
                    return match error.raw_os_error().map(|value| value as u32) {
                        Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) => {
                            RelativePathObservation::Absent
                        }
                        _ => {
                            RelativePathObservation::QueryError(error.raw_os_error().unwrap_or(-1))
                        }
                    };
                }
            };
            let metadata = match file.metadata() {
                Ok(value) => value,
                Err(error) => {
                    return RelativePathObservation::QueryError(error.raw_os_error().unwrap_or(-1));
                }
            };
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return RelativePathObservation::Reparse;
            }
            if verify_parent_identity(&file, self).is_err() {
                return RelativePathObservation::QueryError(-1);
            }
            let identity = match file_identity(&file) {
                Ok(value) => value,
                Err(error) => {
                    return RelativePathObservation::QueryError(error.raw_os_error().unwrap_or(-1));
                }
            };
            if identity == expected {
                RelativePathObservation::SameOwnerId {
                    identity,
                    length: metadata.len(),
                    readonly: metadata.permissions().readonly(),
                }
            } else {
                RelativePathObservation::OtherId {
                    identity,
                    length: metadata.len(),
                    readonly: metadata.permissions().readonly(),
                }
            }
        }
    }

    #[derive(Debug)]
    pub struct SensitiveTempFile {
        file: Option<File>,
        basename: String,
        delete_lease_basename: Option<String>,
        identity: FileIdentity128,
        state: SensitiveHandleState,
    }

    impl SensitiveTempFile {
        pub fn create_delete_armed(root: &RootNamespacePin, basename: &str) -> io::Result<Self> {
            Self::create_delete_armed_with_post_create(root, basename, || Ok(()))
        }

        /// Calls `post_create` immediately after the real `CreateFileW` returns and before the
        /// first subsequent system call. The switch crash helper uses this exact boundary to prove
        /// that creation itself is delete-armed; production callers use `create_delete_armed`.
        pub fn create_delete_armed_with_post_create<F>(
            root: &RootNamespacePin,
            basename: &str,
            mut post_create: F,
        ) -> io::Result<Self>
        where
            F: FnMut() -> io::Result<()>,
        {
            validate_basename(basename)?;
            root.verify_identity()?;
            let delete_lease_basename = format!("{basename}.delete-on-close");
            validate_basename(&delete_lease_basename)?;
            let path = root.final_path.join(&delete_lease_basename);
            let file = create_file(
                &path,
                GENERIC_READ
                    | GENERIC_WRITE
                    | DELETE
                    | FILE_READ_ATTRIBUTES
                    | FILE_WRITE_ATTRIBUTES
                    | SYNCHRONIZE,
                0,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE | FILE_FLAG_OPEN_REPARSE_POINT,
            )?;
            post_create()?;
            // `FILE_FLAG_DELETE_ON_CLOSE` makes the successful create and initial delete-pending
            // state one kernel operation. The durable prewrite owner already exists, and the
            // handle stays armed until its identity is durably bound below. Setting POSIX
            // disposition here would prevent the hard-link handoff used to clear the immutable
            // create option without a path fallback. The hard-crash probe verifies this flag by
            // terminating at `post_create` and observing that this lease name is absent.
            let identity = file_identity(&file)?;
            let mut value = Self {
                identity,
                file: Some(file),
                basename: basename.to_owned(),
                delete_lease_basename: Some(delete_lease_basename.clone()),
                state: SensitiveHandleState::PrewriteDeleteArmed,
            };
            if let Err(error) = verify_parent_identity(value.file()?, root) {
                let _ = value.arm_delete_on_close();
                return Err(error);
            }
            if value.final_basename()? != delete_lease_basename {
                let _ = value.arm_delete_on_close();
                return Err(invalid_data("new sensitive temp final name mismatch"));
            }
            Ok(value)
        }

        pub fn reopen_owned(
            root: &RootNamespacePin,
            basename: &str,
            expected: FileIdentity128,
        ) -> io::Result<Self> {
            validate_basename(basename)?;
            root.verify_identity()?;
            let file = create_file(
                &root.final_path.join(basename),
                GENERIC_READ
                    | GENERIC_WRITE
                    | DELETE
                    | FILE_READ_ATTRIBUTES
                    | FILE_WRITE_ATTRIBUTES
                    | SYNCHRONIZE,
                0,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
            )?;
            let metadata = file.metadata()?;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                || verify_parent_identity(&file, root).is_err()
                || file_identity(&file)? != expected
            {
                return Err(invalid_data("sensitive temp identity mismatch"));
            }
            Ok(Self {
                file: Some(file),
                basename: basename.to_owned(),
                delete_lease_basename: None,
                identity: expected,
                state: SensitiveHandleState::Owned,
            })
        }

        #[must_use]
        pub const fn identity(&self) -> FileIdentity128 {
            self.identity
        }

        #[must_use]
        pub const fn state(&self) -> SensitiveHandleState {
            self.state
        }

        #[must_use]
        pub fn basename(&self) -> &str {
            &self.basename
        }

        pub fn delete_pending(&self) -> io::Result<bool> {
            if self.state == SensitiveHandleState::PrewriteDeleteArmed {
                Ok(self.file.is_some() && self.delete_lease_basename.is_some())
            } else {
                Ok(standard_info(self.file()?)?.DeletePending)
            }
        }

        pub fn clear_delete_on_close(&mut self, root: &RootNamespacePin) -> io::Result<()> {
            if self.state != SensitiveHandleState::PrewriteDeleteArmed
                || self.delete_lease_basename.is_none()
            {
                return Err(invalid_data("sensitive temp is not prewrite delete-armed"));
            }
            root.verify_identity()?;
            create_link_relative(self.file()?, root, &self.basename)?;
            // The original name carries the immutable CreateOptions delete-on-close bit. Closing
            // that handle removes only that link; the root-relative hard link survives with the
            // same Volume/FileId and is reopened without delete-on-close. A crash after link
            // creation therefore leaves only the durable owner's deterministic temp path.
            drop(self.file.take());
            let reopened = Self::reopen_owned(root, &self.basename, self.identity)?;
            self.file = reopened.file;
            self.delete_lease_basename = None;
            self.state = SensitiveHandleState::Owned;
            if self.delete_pending()? || self.final_basename()? != self.basename {
                return Err(invalid_data(
                    "delete-on-close transfer did not survive close",
                ));
            }
            Ok(())
        }

        pub fn arm_delete_on_close(&mut self) -> io::Result<()> {
            set_disposition(
                self.file()?,
                FILE_DISPOSITION_FLAG_DELETE
                    | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
                    | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
            )?;
            if !self.delete_pending()? {
                return Err(invalid_data("delete-on-close could not be armed"));
            }
            self.state = SensitiveHandleState::CleanupDeleteArmed;
            Ok(())
        }

        pub fn write_once(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.file_mut()?.write(bytes)
        }

        pub fn flush(&mut self) -> io::Result<()> {
            self.file_mut()?.flush()
        }

        pub fn sync_all(&self) -> io::Result<()> {
            self.file()?.sync_all()
        }

        pub fn reread(&mut self, maximum_size: u64) -> io::Result<Zeroizing<Vec<u8>>> {
            let info = standard_info(self.file()?)?;
            let length =
                u64::try_from(info.EndOfFile).map_err(|_| invalid_data("negative file length"))?;
            if length > maximum_size.min(MAX_HANDLE_READ) {
                return Err(invalid_data("sensitive temp exceeds bounded read"));
            }
            self.file_mut()?.seek(SeekFrom::Start(0))?;
            let mut bytes = Zeroizing::new(Vec::with_capacity(length as usize));
            Read::by_ref(self.file_mut()?)
                .take(length.saturating_add(1))
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 != length {
                return Err(invalid_data("sensitive temp short reread"));
            }
            Ok(bytes)
        }

        pub fn set_readonly(&self, readonly: bool) -> io::Result<()> {
            set_readonly(self.file()?, readonly)
        }

        pub fn readonly(&self) -> io::Result<bool> {
            Ok(basic_info(self.file()?)?.FileAttributes & FILE_ATTRIBUTE_READONLY != 0)
        }

        pub fn length(&self) -> io::Result<u64> {
            u64::try_from(standard_info(self.file()?)?.EndOfFile)
                .map_err(|_| invalid_data("negative file length"))
        }

        pub fn final_basename(&self) -> io::Result<String> {
            final_path(self.file()?)?
                .file_name()
                .and_then(OsStr::to_str)
                .map(str::to_owned)
                .ok_or_else(|| invalid_data("handle has no UTF-8 basename"))
        }

        pub fn final_path(&self) -> io::Result<PathBuf> {
            final_path(self.file()?)
        }

        pub fn rename_relative(
            &mut self,
            root: &RootNamespacePin,
            publish_basename: &str,
        ) -> io::Result<()> {
            validate_basename(publish_basename)?;
            root.verify_identity()?;
            let utf16: Vec<u16> = OsStr::new(publish_basename).encode_wide().collect();
            let header = offset_of!(FILE_RENAME_INFO, FileName);
            let byte_len = utf16
                .len()
                .checked_mul(size_of::<u16>())
                .ok_or_else(|| invalid_data("rename length overflow"))?;
            let total = header
                .checked_add(byte_len)
                .ok_or_else(|| invalid_data("rename buffer overflow"))?;
            let words = total.div_ceil(size_of::<usize>());
            let mut buffer = vec![0_usize; words];
            let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
            unsafe {
                (*info).Anonymous.Flags =
                    FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS;
                (*info).RootDirectory = root.raw();
                (*info).FileNameLength =
                    u32::try_from(byte_len).map_err(|_| invalid_data("rename name too long"))?;
                ptr::copy_nonoverlapping(
                    utf16.as_ptr(),
                    (*info).FileName.as_mut_ptr(),
                    utf16.len(),
                );
            }
            let mut io_status = IoStatusBlock {
                status_or_pointer: 0,
                information: 0,
            };
            let status = unsafe {
                NtSetInformationFile(
                    self.file()?.as_raw_handle() as HANDLE,
                    &mut io_status,
                    info.cast(),
                    u32::try_from(total).map_err(|_| invalid_data("rename buffer too large"))?,
                    FILE_RENAME_INFORMATION_EX,
                )
            };
            if status < 0 {
                self.state = SensitiveHandleState::RenameFailedUnknown;
                let dos = unsafe { RtlNtStatusToDosError(status) };
                return Err(io::Error::from_raw_os_error(dos as i32));
            }
            self.state = SensitiveHandleState::MaybePublished;
            Ok(())
        }

        pub fn confirm_published(&mut self) -> io::Result<()> {
            if self.state != SensitiveHandleState::MaybePublished {
                return Err(invalid_data("handle is not maybe-published"));
            }
            self.state = SensitiveHandleState::Published;
            Ok(())
        }

        pub fn resolve_failed_rename_as_published(
            &mut self,
            publish_basename: &str,
        ) -> io::Result<()> {
            validate_basename(publish_basename)?;
            if self.state != SensitiveHandleState::RenameFailedUnknown
                || self.final_basename()? != publish_basename
                || file_identity(self.file()?)? != self.identity
            {
                return Err(invalid_data(
                    "failed rename outcome is not the expected published object",
                ));
            }
            self.state = SensitiveHandleState::MaybePublished;
            Ok(())
        }

        fn file(&self) -> io::Result<&File> {
            self.file
                .as_ref()
                .ok_or_else(|| invalid_data("sensitive temp handle is closed"))
        }

        fn file_mut(&mut self) -> io::Result<&mut File> {
            self.file
                .as_mut()
                .ok_or_else(|| invalid_data("sensitive temp handle is closed"))
        }
    }

    #[derive(Debug)]
    pub struct PinnedLiveFile {
        file: File,
        basename: String,
        identity: FileIdentity128,
    }

    impl PinnedLiveFile {
        pub fn open(root: &RootNamespacePin, basename: &str) -> io::Result<Self> {
            validate_basename(basename)?;
            root.verify_identity()?;
            let file = create_file(
                &root.final_path.join(basename),
                GENERIC_READ | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_DELETE,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
            )?;
            let metadata = file.metadata()?;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(invalid_data("live target is a reparse point"));
            }
            verify_parent_identity(&file, root)?;
            let identity = file_identity(&file)?;
            Ok(Self {
                file,
                basename: basename.to_owned(),
                identity,
            })
        }

        /// 为受控联合快照持有只读且禁止写入/删除共享的稳定句柄。
        pub fn open_stable_read(root: &RootNamespacePin, basename: &str) -> io::Result<Self> {
            validate_basename(basename)?;
            root.verify_identity()?;
            let file = create_file(
                &root.final_path.join(basename),
                GENERIC_READ | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_SHARE_READ,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
            )?;
            let metadata = file.metadata()?;
            if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            {
                return Err(invalid_data("stable input is not a non-reparse file"));
            }
            verify_parent_identity(&file, root)?;
            let identity = file_identity(&file)?;
            Ok(Self {
                file,
                basename: basename.to_owned(),
                identity,
            })
        }

        pub fn verify_identity(&self, root: &RootNamespacePin) -> io::Result<()> {
            root.verify_identity()?;
            verify_parent_identity(&self.file, root)?;
            if file_identity(&self.file)? != self.identity {
                return Err(invalid_data("stable input identity changed"));
            }
            Ok(())
        }

        pub fn open_for_delete(
            root: &RootNamespacePin,
            basename: &str,
            expected: FileIdentity128,
        ) -> io::Result<Self> {
            validate_basename(basename)?;
            root.verify_identity()?;
            let file = create_file(
                &root.final_path.join(basename),
                GENERIC_READ | DELETE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
                0,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
            )?;
            let metadata = file.metadata()?;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(invalid_data("live delete target is a reparse point"));
            }
            verify_parent_identity(&file, root)?;
            let identity = file_identity(&file)?;
            if identity != expected {
                return Err(invalid_data("live delete identity mismatch"));
            }
            Ok(Self {
                file,
                basename: basename.to_owned(),
                identity,
            })
        }

        pub fn open_delete_intent(root: &RootNamespacePin, basename: &str) -> io::Result<Self> {
            validate_basename(basename)?;
            root.verify_identity()?;
            let file = create_file(
                &root.final_path.join(basename),
                GENERIC_READ | DELETE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
                0,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
            )?;
            let metadata = file.metadata()?;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(invalid_data("live delete target is a reparse point"));
            }
            verify_parent_identity(&file, root)?;
            let identity = file_identity(&file)?;
            Ok(Self {
                file,
                basename: basename.to_owned(),
                identity,
            })
        }

        #[must_use]
        pub const fn identity(&self) -> FileIdentity128 {
            self.identity
        }

        #[must_use]
        pub fn basename(&self) -> &str {
            &self.basename
        }

        pub fn length(&self) -> io::Result<u64> {
            u64::try_from(standard_info(&self.file)?.EndOfFile)
                .map_err(|_| invalid_data("negative live length"))
        }

        pub fn readonly(&self) -> io::Result<bool> {
            Ok(basic_info(&self.file)?.FileAttributes & FILE_ATTRIBUTE_READONLY != 0)
        }

        pub fn reread(&mut self, maximum_size: u64) -> io::Result<Zeroizing<Vec<u8>>> {
            let length = self.length()?;
            if length > maximum_size.min(MAX_HANDLE_READ) {
                return Err(invalid_data("live file exceeds bounded read"));
            }
            self.file.seek(SeekFrom::Start(0))?;
            let mut bytes = Zeroizing::new(Vec::with_capacity(length as usize));
            Read::by_ref(&mut self.file)
                .take(length.saturating_add(1))
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 != length {
                return Err(invalid_data("live file short reread"));
            }
            Ok(bytes)
        }

        pub fn set_readonly(&self, readonly: bool) -> io::Result<()> {
            set_readonly(&self.file, readonly)
        }

        pub fn arm_delete_on_close(&self) -> io::Result<()> {
            set_disposition(
                &self.file,
                FILE_DISPOSITION_FLAG_DELETE
                    | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
                    | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
            )
        }
    }

    pub fn probe_sensitive_temp_capabilities(root: &RootNamespacePin) -> io::Result<()> {
        root.verify_identity()?;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| invalid_data("clock before epoch"))?
            .as_nanos();
        let survival_name = format!(".codextools-probe-{}-{nonce}-survival", std::process::id());
        let mut survival = SensitiveTempFile::create_delete_armed(root, &survival_name)?;
        if !survival.delete_pending()? {
            return Err(unsupported("delete-on-close not pending"));
        }
        let identity = survival.identity();
        survival
            .clear_delete_on_close(root)
            .map_err(|_| unsupported("delete-on-close cannot be cleared"))?;
        if survival.delete_pending()? {
            return Err(unsupported("delete-on-close clear not observable"));
        }
        drop(survival);
        let mut survival = SensitiveTempFile::reopen_owned(root, &survival_name, identity)
            .map_err(|_| unsupported("cleared delete-on-close did not survive close"))?;
        survival
            .arm_delete_on_close()
            .map_err(|_| unsupported("delete-on-close cannot be rearmed"))?;
        drop(survival);
        if !matches!(
            root.observe_relative(&survival_name, identity),
            RelativePathObservation::Absent
        ) {
            return Err(unsupported("rearmed delete-on-close did not remove file"));
        }

        let target_name = format!("ctprobe-{}-{nonce}-target", std::process::id());
        let source_name = format!("ctprobe-{}-{nonce}-source", std::process::id());
        let mut target = SensitiveTempFile::create_delete_armed(root, &target_name)?;
        target.clear_delete_on_close(root)?;
        target.write_all(b"probe-old")?;
        target.flush()?;
        target.sync_all()?;
        target.set_readonly(true)?;
        let target_identity = target.identity();
        drop(target);
        let old = PinnedLiveFile::open(root, &target_name)?;
        if old.identity() != target_identity || !old.readonly()? {
            return Err(unsupported("readonly target probe could not be pinned"));
        }
        old.set_readonly(false)?;
        if old.readonly()? {
            return Err(unsupported("readonly target cannot be cleared by handle"));
        }
        let mut source = SensitiveTempFile::create_delete_armed(root, &source_name)?;
        source.clear_delete_on_close(root)?;
        source.write_all(b"probe-new")?;
        source.flush()?;
        source.sync_all()?;
        let source_identity = source.identity();
        if let Err(error) = source.rename_relative(root, &target_name) {
            let _ = source.arm_delete_on_close();
            return Err(error);
        }
        if source.state() != SensitiveHandleState::MaybePublished
            || source.identity() != source_identity
            || source.final_basename()? != target_name
        {
            let _ = source.arm_delete_on_close();
            return Err(unsupported(
                "guarded readonly POSIX relative rename is unavailable",
            ));
        }
        drop(old);
        source.set_readonly(false)?;
        source.arm_delete_on_close()?;
        drop(source);
        if !matches!(
            root.observe_relative(&target_name, source_identity),
            RelativePathObservation::Absent
        ) {
            return Err(unsupported("rename capability probe residue remains"));
        }
        Ok(())
    }

    impl Write for SensitiveTempFile {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.file_mut()?.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.file_mut()?.flush()
        }
    }

    fn validate_explicit_root(path: &Path) -> io::Result<()> {
        if !path.is_absolute() {
            return Err(invalid_data("root must be absolute"));
        }
        match path.components().next() {
            Some(Component::Prefix(prefix)) => {
                use std::path::Prefix;
                match prefix.kind() {
                    Prefix::Disk(_) => {}
                    Prefix::VerbatimDisk(_)
                    | Prefix::UNC(_, _)
                    | Prefix::VerbatimUNC(_, _)
                    | Prefix::Verbatim(_)
                    | Prefix::DeviceNS(_) => {
                        return Err(invalid_data(
                            "UNC, verbatim, and device roots are unsupported",
                        ));
                    }
                }
            }
            _ => return Err(invalid_data("root has no drive prefix")),
        }
        Ok(())
    }

    fn validate_canonical_root(path: &Path) -> io::Result<()> {
        if !path.is_absolute() {
            return Err(invalid_data("canonical root must be absolute"));
        }
        match path.components().next() {
            Some(Component::Prefix(prefix)) => {
                use std::path::Prefix;
                if !matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) {
                    return Err(invalid_data("canonical root is not a local disk path"));
                }
            }
            _ => return Err(invalid_data("canonical root has no drive prefix")),
        }
        Ok(())
    }

    fn validate_basename(name: &str) -> io::Result<()> {
        if name.is_empty()
            || name.len() > 240
            || !name.is_ascii()
            || name == "."
            || name == ".."
            || name.ends_with('.')
            || name.ends_with(' ')
            || name.contains(['\\', '/', ':'])
            || name.bytes().any(|value| value < 0x20)
        {
            return Err(invalid_data("invalid relative basename"));
        }
        let upper = name.to_ascii_uppercase();
        let stem = upper.split('.').next().unwrap_or_default();
        if matches!(
            stem,
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        ) {
            return Err(invalid_data("device basename is unsupported"));
        }
        Ok(())
    }

    fn create_file(
        path: &Path,
        access: u32,
        share: u32,
        disposition: u32,
        flags: u32,
    ) -> io::Result<File> {
        let wide = wide_path(path)?;
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                access,
                share,
                ptr::null(),
                disposition,
                flags,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_handle(handle as _) })
    }

    fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        if wide.contains(&0) {
            return Err(invalid_data("path contains NUL"));
        }
        wide.push(0);
        Ok(wide)
    }

    fn file_identity(file: &File) -> io::Result<FileIdentity128> {
        let mut info = FILE_ID_INFO::default();
        let result = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle() as HANDLE,
                FileIdInfo,
                (&mut info as *mut FILE_ID_INFO).cast(),
                size_of::<FILE_ID_INFO>() as u32,
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(FileIdentity128 {
            volume_serial_number: info.VolumeSerialNumber,
            file_id: info.FileId.Identifier,
        })
    }

    fn standard_info(file: &File) -> io::Result<FILE_STANDARD_INFO> {
        let mut info = FILE_STANDARD_INFO::default();
        let result = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle() as HANDLE,
                FileStandardInfo,
                (&mut info as *mut FILE_STANDARD_INFO).cast(),
                size_of::<FILE_STANDARD_INFO>() as u32,
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(info)
    }

    fn basic_info(file: &File) -> io::Result<FILE_BASIC_INFO> {
        let mut info = FILE_BASIC_INFO::default();
        let result = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle() as HANDLE,
                FileBasicInfo,
                (&mut info as *mut FILE_BASIC_INFO).cast(),
                size_of::<FILE_BASIC_INFO>() as u32,
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(info)
    }

    fn set_readonly(file: &File, readonly: bool) -> io::Result<()> {
        let mut info = basic_info(file)?;
        if readonly {
            info.FileAttributes |= FILE_ATTRIBUTE_READONLY;
        } else {
            info.FileAttributes &= !FILE_ATTRIBUTE_READONLY;
        }
        let result = unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle() as HANDLE,
                FileBasicInfo,
                (&info as *const FILE_BASIC_INFO).cast(),
                size_of::<FILE_BASIC_INFO>() as u32,
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        if (basic_info(file)?.FileAttributes & FILE_ATTRIBUTE_READONLY != 0) != readonly {
            return Err(invalid_data("readonly update did not persist"));
        }
        Ok(())
    }

    fn set_disposition(file: &File, flags: u32) -> io::Result<()> {
        let info = FILE_DISPOSITION_INFO_EX { Flags: flags };
        let result = unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle() as HANDLE,
                FileDispositionInfoEx,
                (&info as *const FILE_DISPOSITION_INFO_EX).cast(),
                size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn create_link_relative(
        file: &File,
        root: &RootNamespacePin,
        basename: &str,
    ) -> io::Result<()> {
        validate_basename(basename)?;
        root.verify_identity()?;
        let utf16: Vec<u16> = OsStr::new(basename).encode_wide().collect();
        let header = offset_of!(FileLinkInfoBuffer, file_name);
        let byte_len = utf16
            .len()
            .checked_mul(size_of::<u16>())
            .ok_or_else(|| invalid_data("link length overflow"))?;
        let total = header
            .checked_add(byte_len)
            .ok_or_else(|| invalid_data("link buffer overflow"))?;
        let words = total.div_ceil(size_of::<usize>());
        let mut buffer = vec![0_usize; words];
        let info = buffer.as_mut_ptr().cast::<FileLinkInfoBuffer>();
        unsafe {
            (*info).replace_if_exists = 0;
            (*info).root_directory = root.raw();
            (*info).file_name_length =
                u32::try_from(byte_len).map_err(|_| invalid_data("link name too long"))?;
            ptr::copy_nonoverlapping(utf16.as_ptr(), (*info).file_name.as_mut_ptr(), utf16.len());
        }
        let mut io_status = IoStatusBlock {
            status_or_pointer: 0,
            information: 0,
        };
        let status = unsafe {
            NtSetInformationFile(
                file.as_raw_handle() as HANDLE,
                &mut io_status,
                info.cast(),
                u32::try_from(total).map_err(|_| invalid_data("link buffer too large"))?,
                FILE_LINK_INFO_CLASS,
            )
        };
        if status < 0 {
            let dos = unsafe { RtlNtStatusToDosError(status) };
            return Err(io::Error::from_raw_os_error(dos as i32));
        }
        Ok(())
    }

    fn final_path(file: &File) -> io::Result<PathBuf> {
        let required = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle() as HANDLE,
                ptr::null_mut(),
                0,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        };
        if required == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buffer = vec![0_u16; required as usize + 1];
        let written = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle() as HANDLE,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        };
        if written == 0 || written as usize >= buffer.len() {
            return Err(io::Error::last_os_error());
        }
        buffer.truncate(written as usize);
        Ok(PathBuf::from(
            String::from_utf16(&buffer).map_err(|_| invalid_data("final path is not UTF-16"))?,
        ))
    }

    fn verify_parent_identity(file: &File, root: &RootNamespacePin) -> io::Result<()> {
        let path = final_path(file)?;
        let parent = path
            .parent()
            .ok_or_else(|| invalid_data("file has no final parent"))?;
        let parent_handle = create_file(
            parent,
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        )?;
        let metadata = parent_handle.metadata()?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || file_identity(&parent_handle)? != root.identity
        {
            return Err(invalid_data(
                "sensitive temp final parent identity mismatch",
            ));
        }
        Ok(())
    }

    fn invalid_data(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }
    fn unsupported(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::Unsupported, message)
    }
}

#[cfg(windows)]
pub use imp::{
    PinnedLiveFile, RootNamespacePin, SensitiveTempFile, probe_sensitive_temp_capabilities,
};

#[cfg(not(windows))]
mod imp_non_windows {
    use super::{FileIdentity128, SensitiveHandleState};
    use std::{io, path::Path};

    #[derive(Debug)]
    pub struct RootNamespacePin;
    impl RootNamespacePin {
        pub fn acquire(_: &Path) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Windows sensitive-temp support is required",
            ))
        }
        pub fn acquire_canonical(_: &Path) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Windows sensitive-temp support is required",
            ))
        }
        pub fn final_path(&self) -> &Path {
            Path::new("")
        }
        pub fn relative_directory_is_empty(&self, _: &str) -> io::Result<bool> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Windows root-relative directory validation is required",
            ))
        }
    }
    #[derive(Debug)]
    pub struct SensitiveTempFile;
    impl SensitiveTempFile {
        pub const fn state(&self) -> SensitiveHandleState {
            SensitiveHandleState::RenameFailedUnknown
        }
        pub const fn identity(&self) -> FileIdentity128 {
            FileIdentity128 {
                volume_serial_number: 0,
                file_id: [0; 16],
            }
        }
    }
    #[derive(Debug)]
    pub struct PinnedLiveFile;
    impl PinnedLiveFile {
        pub fn open_stable_read(_: &RootNamespacePin, _: &str) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Windows stable handles are required",
            ))
        }
        pub fn verify_identity(&self, _: &RootNamespacePin) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Windows stable handles are required",
            ))
        }
        pub const fn identity(&self) -> FileIdentity128 {
            FileIdentity128 {
                volume_serial_number: 0,
                file_id: [0; 16],
            }
        }
        pub fn length(&self) -> io::Result<u64> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Windows stable handles are required",
            ))
        }
        pub fn reread(&mut self, _: u64) -> io::Result<zeroize::Zeroizing<Vec<u8>>> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Windows stable handles are required",
            ))
        }
    }
    pub fn probe_sensitive_temp_capabilities(_: &RootNamespacePin) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows sensitive-temp support is required",
        ))
    }
}

#[cfg(not(windows))]
pub use imp_non_windows::{
    PinnedLiveFile, RootNamespacePin, SensitiveTempFile, probe_sensitive_temp_capabilities,
};
