use crate::DomainError;

fn contains_secret_like(value: &str) -> bool {
    contains_high_confidence_secret_bytes(value.as_bytes())
}

/// 字节级高置信检测，供需要检查原始配置缓冲区的 M2/M3 边界复用。
#[must_use]
pub fn contains_high_confidence_secret_bytes(bytes: &[u8]) -> bool {
    let looks_like_openai = contains_prefixed_run(bytes, b"sk-", 20, |byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
    });
    let looks_like_github = bytes.windows(4).enumerate().any(|(index, prefix)| {
        prefix[0..2] == *b"gh"
            && b"pousr".contains(&prefix[2])
            && prefix[3] == b'_'
            && run_length(&bytes[index + 4..], |byte| byte.is_ascii_alphanumeric()) >= 20
    });
    let looks_like_aws = contains_prefixed_run(bytes, b"AKIA", 16, |byte| {
        byte.is_ascii_uppercase() || byte.is_ascii_digit()
    });
    let looks_like_jwt = contains_jwt(bytes);
    let looks_like_private_key = [
        "PRIVATE KEY",
        "RSA PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
        "EC PRIVATE KEY",
        "DSA PRIVATE KEY",
    ]
    .iter()
    .any(|label| {
        let header = format!("-----BEGIN {label}-----");
        bytes
            .windows(header.len())
            .any(|window| window == header.as_bytes())
    });
    looks_like_openai
        || looks_like_github
        || looks_like_aws
        || looks_like_jwt
        || looks_like_private_key
}

/// 判断输入是否匹配高置信秘密形态，供跨 crate 边界复用同一规则。
///
/// 该函数只返回布尔结果，不保留或回显输入正文。
pub fn contains_high_confidence_secret(value: &str) -> bool {
    contains_secret_like(value)
}

fn contains_prefixed_run(
    bytes: &[u8],
    prefix: &[u8],
    minimum_run: usize,
    allowed: impl Fn(u8) -> bool + Copy,
) -> bool {
    bytes
        .windows(prefix.len())
        .enumerate()
        .any(|(index, candidate)| {
            candidate == prefix
                && run_length(&bytes[index + prefix.len()..], allowed) >= minimum_run
        })
}

fn run_length(bytes: &[u8], allowed: impl Fn(u8) -> bool) -> usize {
    bytes
        .iter()
        .copied()
        .take_while(|byte| allowed(*byte))
        .count()
}

fn contains_jwt(bytes: &[u8]) -> bool {
    bytes.windows(3).enumerate().any(|(index, prefix)| {
        if prefix != b"eyJ" {
            return false;
        }
        let allowed = |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-');
        let first = run_length(&bytes[index + 3..], allowed);
        if first < 8 {
            return false;
        }
        let second_start = index + 3 + first;
        if bytes.get(second_start) != Some(&b'.') {
            return false;
        }
        let second = run_length(&bytes[second_start + 1..], allowed);
        if second < 8 {
            return false;
        }
        let third_start = second_start + 1 + second;
        bytes.get(third_start) == Some(&b'.') && run_length(&bytes[third_start + 1..], allowed) >= 8
    })
}

fn validate_metadata(value: &str, maximum_chars: usize) -> Result<&str, DomainError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(DomainError::EmptyValue);
    }
    if trimmed.chars().count() > maximum_chars {
        return Err(DomainError::ValueTooLong);
    }
    if trimmed.chars().any(char::is_control) {
        return Err(DomainError::InvalidFormat);
    }
    if contains_secret_like(trimmed) {
        return Err(DomainError::SecretLikeInput);
    }
    Ok(trimmed)
}

fn validate_uuid(value: &str) -> Result<(), DomainError> {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return Err(DomainError::InvalidFormat);
    }
    for (index, byte) in bytes.iter().copied().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            if byte != b'-' {
                return Err(DomainError::InvalidFormat);
            }
        } else if !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase() {
            return Err(DomainError::InvalidFormat);
        }
    }
    Ok(())
}

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: &str) -> Result<Self, DomainError> {
                validate_uuid(value)?;
                Ok(Self(value.to_owned()))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

id_type!(IdentityId);
id_type!(CredentialRefId);
id_type!(ModelPresetId);
id_type!(ManagedConfigPatchId);
id_type!(SwitchTransactionId);

/// 用户可见名称，限制为 1..=80 个字符且不接受疑似秘密。
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EntityName(String);

impl EntityName {
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        Ok(Self(validate_metadata(value, 80)?.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn ensure_preset_metadata_safe(&self) -> Result<(), DomainError> {
        if self.0.contains(['/', '\\']) || looks_like_rooted_path(&self.0) {
            return Err(DomainError::InvalidFormat);
        }
        Ok(())
    }
}

/// Codex Provider 标识。
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderId(String);

impl ProviderId {
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        let value = validate_metadata(value, 64)?;
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(DomainError::InvalidFormat);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 供应商模型标识。
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ModelId(String);

impl ModelId {
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        let value = validate_metadata(value, 128)?;
        if !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        }) {
            return Err(DomainError::InvalidFormat);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn ensure_preset_metadata_safe(&self) -> Result<(), DomainError> {
        let value = self.0.as_str();
        if looks_like_rooted_path(value)
            || value.starts_with("~/")
            || value.ends_with('/')
            || value.contains("//")
            || value
                .split('/')
                .any(|segment| matches!(segment, "." | ".."))
        {
            return Err(DomainError::InvalidFormat);
        }
        Ok(())
    }
}

fn looks_like_rooted_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    value.starts_with(['/', '\\'])
        || (bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'/' | b'\\'))
}

/// 不包含查询、片段或用户信息的 HTTP(S) 端点。
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EndpointUrl(String);

impl EndpointUrl {
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        let value = validate_metadata(value, 2_048)?;
        let remainder = value
            .strip_prefix("https://")
            .or_else(|| value.strip_prefix("http://"))
            .ok_or(DomainError::InvalidFormat)?;
        let host = remainder.split('/').next().unwrap_or_default();
        if host.is_empty()
            || value.bytes().any(|byte| byte.is_ascii_whitespace())
            || value.contains(['?', '#', '@'])
        {
            return Err(DomainError::InvalidFormat);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate_fingerprint(value: &str) -> Result<(), DomainError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(DomainError::InvalidFormat);
    }
    Ok(())
}

macro_rules! fingerprint_type {
    ($name:ident) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: &str) -> Result<Self, DomainError> {
                validate_fingerprint(value)?;
                Ok(Self(value.to_owned()))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

fingerprint_type!(SchemaFingerprint);
fingerprint_type!(CredentialFingerprint);
fingerprint_type!(ContentHash);

/// Unix epoch 毫秒时间戳。
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UnixMillis(i64);

impl UnixMillis {
    pub fn new(value: i64) -> Result<Self, DomainError> {
        if value < 0 {
            return Err(DomainError::InvalidTimestamp);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn value(self) -> i64 {
        self.0
    }
}

/// 用于乐观并发控制的单调实体版本。
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EntityVersion(u64);

impl EntityVersion {
    #[must_use]
    pub const fn initial() -> Self {
        Self(1)
    }

    pub fn new(value: u64) -> Result<Self, DomainError> {
        if value == 0 || value > i64::MAX as u64 {
            return Err(DomainError::InvalidVersion);
        }
        Ok(Self(value))
    }

    pub fn next(self) -> Result<Self, DomainError> {
        Self::new(self.0.checked_add(1).ok_or(DomainError::VersionOverflow)?)
    }

    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}
