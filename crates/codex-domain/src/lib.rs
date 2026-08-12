#![forbid(unsafe_code)]
//! CodexTools 的无 UI、无 I/O 领域核心。

mod credential;
mod error;
mod identity;
mod managed_patch;
mod preset;
mod switch;
mod value;

pub use credential::{
    AuthMode, CredentialBackend, CredentialKind, CredentialLink, CredentialReference,
};
pub use error::DomainError;
pub use identity::{IdentityStatus, RuntimeIdentity};
pub use managed_patch::{MANAGED_CONFIG_PATHS, ManagedConfigPatch};
pub use preset::ModelPreset;
pub use switch::{FileRole, SwitchTransaction, SwitchTransactionState};
pub use value::{
    ContentHash, CredentialFingerprint, CredentialRefId, EndpointUrl, EntityName, EntityVersion,
    IdentityId, ManagedConfigPatchId, ModelId, ModelPresetId, ProviderId, SchemaFingerprint,
    SwitchTransactionId, UnixMillis,
};

/// 当前核心实现所达到的里程碑阶段。
pub const M2_STAGE: &str = "M2.3";

/// 返回当前核心实现阶段，供内部调试入口与验证脚本读取。
#[must_use]
pub const fn m2_stage() -> &'static str {
    M2_STAGE
}
