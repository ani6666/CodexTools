use std::{io, path::Path};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecureFileIdentity {
    pub volume_serial_number: u32,
    pub file_index: u64,
}

#[cfg(windows)]
pub fn secure_file_identity(file: &std::fs::File) -> io::Result<SecureFileIdentity> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let mut information = unsafe { std::mem::zeroed::<BY_HANDLE_FILE_INFORMATION>() };
    let result = unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut information) };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(SecureFileIdentity {
        volume_serial_number: information.dwVolumeSerialNumber,
        file_index: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
    })
}

#[cfg(not(windows))]
pub fn secure_file_identity(file: &std::fs::File) -> io::Result<SecureFileIdentity> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    Ok(SecureFileIdentity {
        volume_serial_number: u32::try_from(metadata.dev()).unwrap_or(u32::MAX),
        file_index: metadata.ino(),
    })
}

#[cfg(windows)]
pub fn secure_read_contained_file(
    canonical_root: &Path,
    candidate: &Path,
    maximum_size: u64,
) -> io::Result<Vec<u8>> {
    use std::{
        fs::OpenOptions,
        io::Read,
        os::windows::{
            fs::{MetadataExt, OpenOptionsExt},
            io::AsRawHandle,
        },
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    if !canonical_root.is_absolute() || !candidate.is_absolute() {
        return Err(invalid_path());
    }
    let root = std::fs::canonicalize(canonical_root)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(candidate)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.len() > maximum_size
    {
        return Err(invalid_path());
    }

    let final_path = final_path_for_handle(file.as_raw_handle())?;
    if !windows_path_is_beneath(&root, &final_path) {
        return Err(invalid_path());
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(maximum_size.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum_size {
        return Err(invalid_path());
    }
    Ok(bytes)
}

#[cfg(windows)]
pub fn secure_validate_contained_directory(
    canonical_root: &Path,
    candidate: &Path,
) -> io::Result<std::path::PathBuf> {
    use std::{
        fs::OpenOptions,
        os::windows::{
            fs::{MetadataExt, OpenOptionsExt},
            io::AsRawHandle,
        },
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    if !canonical_root.is_absolute() || !candidate.is_absolute() {
        return Err(invalid_path());
    }
    let root = std::fs::canonicalize(canonical_root)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(candidate)?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(invalid_path());
    }
    let final_path = final_path_for_handle(directory.as_raw_handle())?;
    if !windows_path_is_beneath(&root, &final_path) {
        return Err(invalid_path());
    }
    Ok(final_path)
}

#[cfg(windows)]
fn final_path_for_handle(
    handle: std::os::windows::io::RawHandle,
) -> io::Result<std::path::PathBuf> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW, VOLUME_NAME_DOS,
    };
    let required = unsafe {
        GetFinalPathNameByHandleW(
            handle,
            std::ptr::null_mut(),
            0,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    };
    if required == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut final_path = vec![0_u16; required as usize + 1];
    let written = unsafe {
        GetFinalPathNameByHandleW(
            handle,
            final_path.as_mut_ptr(),
            final_path.len() as u32,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    };
    if written == 0 || written as usize >= final_path.len() {
        return Err(io::Error::last_os_error());
    }
    final_path.truncate(written as usize);
    Ok(std::path::PathBuf::from(
        String::from_utf16(&final_path).map_err(|_| invalid_path())?,
    ))
}

#[cfg(windows)]
fn windows_path_is_beneath(root: &Path, candidate: &Path) -> bool {
    let mut root = root.to_string_lossy().replace('/', "\\").to_lowercase();
    let candidate = candidate
        .to_string_lossy()
        .replace('/', "\\")
        .to_lowercase();
    while root.ends_with('\\') {
        root.pop();
    }
    candidate.len() > root.len()
        && candidate.starts_with(&root)
        && candidate.as_bytes().get(root.len()) == Some(&b'\\')
}

fn invalid_path() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "path containment check failed")
}

#[cfg(not(windows))]
pub fn secure_read_contained_file(
    _canonical_root: &Path,
    _candidate: &Path,
    _maximum_size: u64,
) -> io::Result<Vec<u8>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Windows handle-based path validation is required",
    ))
}

#[cfg(not(windows))]
pub fn secure_validate_contained_directory(
    _canonical_root: &Path,
    _candidate: &Path,
) -> io::Result<std::path::PathBuf> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Windows handle-based path validation is required",
    ))
}
