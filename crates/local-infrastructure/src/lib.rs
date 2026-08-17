#![forbid(unsafe_code)]
//! CodexTools SQLite 与本地基础设施实现。

mod backup;
mod capture_import;
mod controlled_source;
mod credential_service;
mod http_transport;
mod import;
mod migration;
mod oauth;
mod preset_binding;
mod repository;
mod switch;
mod vertical;

pub use backup::{
    BackupFaultPoint, BackupFaults, BackupRestoreTarget, BackupService, NoBackupFaults,
};
pub use capture_import::{
    CaptureImportFaultPoint, CaptureImportFaults, CaptureImportRepository, CaptureImportService,
    NoCaptureImportFaults,
};
pub use controlled_source::{DefaultCodexRootResolver, WindowsControlledRootReader};
pub use credential_service::{
    CredentialService, CredentialServiceError, ScopedCredentialError,
    credential_material_schema_fingerprint,
};
pub use http_transport::{NativeHttpTransport, SystemDnsResolver};
pub use migration::{
    LATEST_SCHEMA_VERSION, MIGRATION_0001_SQL, MIGRATION_0002_SQL, MIGRATION_0003_SQL,
    MIGRATION_0004_SQL, MIGRATION_0005_SQL, MIGRATION_0006_SQL, MIGRATION_0007_SQL,
    MIGRATION_0008_SQL, MIGRATION_0009_SQL, MIGRATION_0010_SQL, MIGRATION_0011_SQL, MigrationError,
};
pub use oauth::{OAuthCaptureRequest, OAuthCaptureService, SystemOAuthProcessRunner};
pub use preset_binding::{NoPresetBindingFaults, PresetBindingFaultPoint, PresetBindingFaults};
pub use repository::{
    OpenRepositoryError, SensitiveDestinationGuard, SensitiveDestinationState,
    SensitiveTempAnomaly, SensitiveTempLifecycle, SensitiveTempOwnerRecord, SensitiveTempPhase,
    SensitiveTempRole, SqliteMetadataRepository,
};
pub use switch::{
    CrossProcessWriteLock, FaultDisposition, FaultInjector, FaultPoint, LockDiagnostic,
    LockOwnerInfo, OwnedSensitiveTempIdentity, SensitiveTempIo, StdSensitiveTempIo, SwitchExecutor,
    SystemClock, ThreadStabilityWindow,
};
pub use vertical::{
    PreparedVerticalSwitch, VerifiedVerticalState, VerticalClosureError, VerticalExecutionResult,
    VerticalPreparedIntent, VerticalPreview, VerticalSwitchPlanner,
};

#[cfg(test)]
use codex_adapter as _;

#[cfg(test)]
mod migration_tests;
