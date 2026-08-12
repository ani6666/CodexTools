use std::fmt;

/// 领域输入或状态违反不变量。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainError {
    EmptyValue,
    ValueTooLong,
    InvalidFormat,
    SecretLikeInput,
    InvalidTimestamp,
    TimestampOrder,
    InvalidVersion,
    VersionOverflow,
    CredentialKindMismatch,
    IdentityStateMismatch,
    PresetIdentityMismatch,
    TransactionStateMismatch,
}

impl fmt::Display for DomainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptyValue => "value is empty",
            Self::ValueTooLong => "value exceeds its length limit",
            Self::InvalidFormat => "value format is invalid",
            Self::SecretLikeInput => "secret-like input is not accepted in metadata",
            Self::InvalidTimestamp => "timestamp is invalid",
            Self::TimestampOrder => "timestamp order is invalid",
            Self::InvalidVersion => "entity version is invalid",
            Self::VersionOverflow => "entity version overflow",
            Self::CredentialKindMismatch => "credential kind does not match authentication mode",
            Self::IdentityStateMismatch => "identity state is inconsistent",
            Self::PresetIdentityMismatch => "model preset belongs to another identity",
            Self::TransactionStateMismatch => "switch transaction state transition is invalid",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for DomainError {}
