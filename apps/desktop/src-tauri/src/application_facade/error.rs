use std::fmt;

use codex_application::{
    ApplicationError, BackupStoreError, CredentialStoreError, OAuthCaptureError, RepositoryError,
    SwitchExecutionError,
};
use local_infrastructure::{CredentialServiceError, VerticalClosureError};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Validation,
    NotFound,
    Conflict,
    PlanStale,
    CompatibilityProtected,
    Cancelled,
    RecoveryRequired,
    Unavailable,
    Internal,
}

impl ErrorCode {
    #[must_use]
    pub const fn message_key(self) -> &'static str {
        match self {
            Self::Validation => "error.validation",
            Self::NotFound => "error.not_found",
            Self::Conflict => "error.conflict",
            Self::PlanStale => "error.plan_stale",
            Self::CompatibilityProtected => "error.compatibility_protected",
            Self::Cancelled => "error.cancelled",
            Self::RecoveryRequired => "error.recovery_required",
            Self::Unavailable => "error.unavailable",
            Self::Internal => "error.internal",
        }
    }

    #[must_use]
    pub const fn message_zh_cn(self) -> &'static str {
        match self {
            Self::Validation => "请求参数无效。",
            Self::NotFound => "请求的资源不存在。",
            Self::Conflict => "当前状态与请求冲突。",
            Self::PlanStale => "操作计划已失效，请重新预览。",
            Self::CompatibilityProtected => "当前状态受兼容性保护。",
            Self::Cancelled => "操作已取消。",
            Self::RecoveryRequired => "操作需要恢复后才能继续。",
            Self::Unavailable => "本地服务暂时不可用。",
            Self::Internal => "发生内部错误。",
        }
    }

    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(self, Self::Conflict | Self::PlanStale | Self::Unavailable)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ErrorEnvelope {
    pub schema_version: u16,
    pub code: ErrorCode,
    pub message_zh_cn: String,
    pub message_key: String,
    pub retryable: bool,
}

impl ErrorEnvelope {
    #[must_use]
    pub fn from_code(code: ErrorCode) -> Self {
        Self {
            schema_version: super::M31_CONTRACT_VERSION,
            code,
            message_zh_cn: code.message_zh_cn().to_owned(),
            message_key: code.message_key().to_owned(),
            retryable: code.retryable(),
        }
    }
}

impl fmt::Display for ErrorEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message_zh_cn)
    }
}

impl std::error::Error for ErrorEnvelope {}

impl From<RepositoryError> for ErrorEnvelope {
    fn from(error: RepositoryError) -> Self {
        let code = match error {
            RepositoryError::NotFound(_) => ErrorCode::NotFound,
            RepositoryError::AlreadyExists(_)
            | RepositoryError::VersionConflict(_)
            | RepositoryError::ReferenceConflict(_) => ErrorCode::Conflict,
            RepositoryError::CorruptData => ErrorCode::Internal,
            RepositoryError::StorageUnavailable => ErrorCode::Unavailable,
        };
        Self::from_code(code)
    }
}

impl From<SwitchExecutionError> for ErrorEnvelope {
    fn from(error: SwitchExecutionError) -> Self {
        let code = match error {
            SwitchExecutionError::Busy => ErrorCode::Conflict,
            SwitchExecutionError::PlanStale => ErrorCode::PlanStale,
            SwitchExecutionError::CompatibilityProtected(_) => ErrorCode::CompatibilityProtected,
            SwitchExecutionError::InvalidPlan => ErrorCode::Validation,
            SwitchExecutionError::SnapshotInvalid | SwitchExecutionError::RecoveryRequired => {
                ErrorCode::RecoveryRequired
            }
            SwitchExecutionError::IoFailure | SwitchExecutionError::RepositoryFailure => {
                ErrorCode::Unavailable
            }
            SwitchExecutionError::InjectedFailure | SwitchExecutionError::Interrupted => {
                ErrorCode::Internal
            }
        };
        Self::from_code(code)
    }
}

impl From<CredentialServiceError> for ErrorEnvelope {
    fn from(error: CredentialServiceError) -> Self {
        let code = match error {
            CredentialServiceError::AlreadyExists
            | CredentialServiceError::VersionConflict
            | CredentialServiceError::ReferenceConflict => ErrorCode::Conflict,
            CredentialServiceError::NotFound => ErrorCode::NotFound,
            CredentialServiceError::InvalidSecret => ErrorCode::Validation,
            CredentialServiceError::StoreFailure | CredentialServiceError::RepositoryFailure => {
                ErrorCode::Unavailable
            }
            CredentialServiceError::RecoveryRequired => ErrorCode::RecoveryRequired,
        };
        Self::from_code(code)
    }
}

impl From<VerticalClosureError> for ErrorEnvelope {
    fn from(error: VerticalClosureError) -> Self {
        match error {
            VerticalClosureError::CompatibilityProtected(_) => {
                Self::from_code(ErrorCode::CompatibilityProtected)
            }
            VerticalClosureError::InvalidTarget => Self::from_code(ErrorCode::Validation),
            VerticalClosureError::IoFailure => Self::from_code(ErrorCode::Unavailable),
            VerticalClosureError::Credential(error) => error.into(),
            VerticalClosureError::Switch(error) => error.into(),
        }
    }
}

impl From<ApplicationError> for ErrorEnvelope {
    fn from(error: ApplicationError) -> Self {
        match error {
            ApplicationError::Domain => Self::from_code(ErrorCode::Validation),
            ApplicationError::Repository(error) => error.into(),
            ApplicationError::CredentialMismatch => Self::from_code(ErrorCode::Conflict),
        }
    }
}

impl From<CredentialStoreError> for ErrorEnvelope {
    fn from(error: CredentialStoreError) -> Self {
        let code = match error {
            CredentialStoreError::AlreadyExists | CredentialStoreError::VersionConflict => {
                ErrorCode::Conflict
            }
            CredentialStoreError::NotFound => ErrorCode::NotFound,
            CredentialStoreError::RecoveryRequired => ErrorCode::RecoveryRequired,
            CredentialStoreError::BindingMismatch | CredentialStoreError::CorruptEnvelope => {
                ErrorCode::Internal
            }
            CredentialStoreError::ProtectionFailed | CredentialStoreError::IoFailure => {
                ErrorCode::Unavailable
            }
        };
        Self::from_code(code)
    }
}

impl From<BackupStoreError> for ErrorEnvelope {
    fn from(error: BackupStoreError) -> Self {
        let code = match error {
            BackupStoreError::AlreadyExists => ErrorCode::Conflict,
            BackupStoreError::NotFound => ErrorCode::NotFound,
            BackupStoreError::PlanStale => ErrorCode::PlanStale,
            BackupStoreError::CompatibilityProtected => ErrorCode::CompatibilityProtected,
            BackupStoreError::RecoveryRequired | BackupStoreError::CorruptMaterial => {
                ErrorCode::RecoveryRequired
            }
            BackupStoreError::IoFailure | BackupStoreError::RepositoryFailure => {
                ErrorCode::Unavailable
            }
        };
        Self::from_code(code)
    }
}

impl From<OAuthCaptureError> for ErrorEnvelope {
    fn from(error: OAuthCaptureError) -> Self {
        let code = match error {
            OAuthCaptureError::Cancelled => ErrorCode::Cancelled,
            OAuthCaptureError::CompatibilityProtected => ErrorCode::CompatibilityProtected,
            OAuthCaptureError::MissingAuthentication => ErrorCode::NotFound,
            OAuthCaptureError::ProcessTreeUnconfirmed => ErrorCode::RecoveryRequired,
            OAuthCaptureError::TimedOut
            | OAuthCaptureError::ProcessFailed
            | OAuthCaptureError::CredentialFailure
            | OAuthCaptureError::IoFailure => ErrorCode::Unavailable,
            OAuthCaptureError::OutsideWriteDetected => ErrorCode::CompatibilityProtected,
        };
        Self::from_code(code)
    }
}
