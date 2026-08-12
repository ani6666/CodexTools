#![deny(unsafe_op_in_unsafe_fn)]
//! Windows 专用适配器。DPAPI FFI 仅封装在本 crate 的审计边界内。

mod credential_store;
mod dpapi;
mod job;
mod secure_path;
mod sensitive_temp;

pub use credential_store::WindowsDpapiCredentialStore;
pub use dpapi::DpapiCurrentUser;
pub use job::{JobProcessExit, JobProcessWaitError, WindowsJobProcess, detach_std_child};
pub use secure_path::{
    SecureFileIdentity, secure_file_identity, secure_read_contained_file,
    secure_validate_contained_directory,
};
pub use sensitive_temp::{
    FileIdentity128, PinnedLiveFile, RelativePathObservation, RootNamespacePin,
    SensitiveHandleState, SensitiveTempFile, probe_sensitive_temp_capabilities,
};
