#![forbid(unsafe_code)]
//! 只读取调用方显式提供的 Codex 目录，并只在内存中生成配置计划。

mod hash;
mod json;
mod toml;

use std::{fs, path::Path};

use codex_application::{
    ActualCodexState, AuthenticationDescriptor, CodexStateSource, CompatibilityReason,
    ConfigPlanner, DesiredManagedConfig, FormatGeneration, ManagedFieldChange, PlannedConfig,
    RedactedDiff, ScanStatus, ScannedConfig,
};
use codex_domain::{
    AuthMode, ContentHash, CredentialFingerprint, CredentialReference, EndpointUrl, EntityName,
    ModelId, ProviderId, SchemaFingerprint,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct CodexAdapter;

fn contains_high_confidence_secret(bytes: &[u8]) -> bool {
    fn run(bytes: &[u8], allowed: impl Fn(u8) -> bool) -> usize {
        bytes.iter().copied().take_while(|b| allowed(*b)).count()
    }
    let prefixed = |prefix: &[u8], minimum: usize, allowed: fn(u8) -> bool| {
        bytes
            .windows(prefix.len())
            .enumerate()
            .any(|(index, value)| {
                value == prefix && run(&bytes[index + prefix.len()..], allowed) >= minimum
            })
    };
    let token = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-');
    prefixed(b"sk-", 20, token)
        || bytes.windows(4).enumerate().any(|(index, value)| {
            value[0..2] == *b"gh"
                && b"pousr".contains(&value[2])
                && value[3] == b'_'
                && run(&bytes[index + 4..], |b| b.is_ascii_alphanumeric()) >= 20
        })
        || prefixed(b"AKIA", 16, |b| {
            b.is_ascii_uppercase() || b.is_ascii_digit()
        })
        || bytes.windows(3).enumerate().any(|(index, value)| {
            if value != b"eyJ" {
                return false;
            }
            let first = run(&bytes[index + 3..], token);
            let p1 = index + 3 + first;
            if first < 8 || bytes.get(p1) != Some(&b'.') {
                return false;
            }
            let second = run(&bytes[p1 + 1..], token);
            let p2 = p1 + 1 + second;
            second >= 8 && bytes.get(p2) == Some(&b'.') && run(&bytes[p2 + 1..], token) >= 8
        })
        || ["", "RSA ", "OPENSSH ", "EC ", "DSA "].iter().any(|label| {
            let mut header = b"-----BEGIN ".to_vec();
            header.extend_from_slice(label.as_bytes());
            header.extend_from_slice(b"PRIVATE KEY-----");
            bytes.windows(header.len()).any(|value| value == header)
        })
}

impl CodexAdapter {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    pub fn scan_explicit_root(&self, root: &Path) -> ScanStatus {
        <Self as CodexStateSource>::scan_explicit_root(self, root)
    }

    pub fn plan_config(
        &self,
        actual: &ActualCodexState,
        desired: &DesiredManagedConfig,
        credential: &CredentialReference,
    ) -> Result<PlannedConfig, CompatibilityReason> {
        <Self as ConfigPlanner>::plan_config(self, actual, desired, credential)
    }
}

#[must_use]
pub fn hash_bytes(value: &[u8]) -> ContentHash {
    ContentHash::parse(&hash::sha256_hex(value)).expect("SHA-256 is lowercase hexadecimal")
}

impl CodexAdapter {
    #[must_use]
    pub fn scan_memory(&self, config: &[u8], auth: &[u8]) -> ScanStatus {
        scan_bytes(config.to_vec(), auth.to_vec())
    }
}

fn scan_bytes(config: Vec<u8>, auth: Vec<u8>) -> ScanStatus {
    if contains_high_confidence_secret(&config) {
        return ScanStatus::CompatibilityProtected(CompatibilityReason::UnsupportedTomlSubset);
    }
    let parsed = match toml::parse(&config) {
        Ok(v) => v,
        Err(r) => return ScanStatus::CompatibilityProtected(r),
    };
    let string = |path: &str| {
        parsed
            .assignments
            .get(path)
            .map(|a| a.value.as_str())
            .ok_or(CompatibilityReason::MissingManagedField)
    };
    let provider = match string("model_provider")
        .and_then(|v| ProviderId::parse(v).map_err(|_| CompatibilityReason::UnsupportedTomlSubset))
    {
        Ok(v) => v,
        Err(r) => return ScanStatus::CompatibilityProtected(r),
    };
    let provider_path = format!("model_providers.{}", provider.as_str());
    let provider_name = match string(&format!("{provider_path}.name"))
        .and_then(|v| EntityName::parse(v).map_err(|_| CompatibilityReason::UnsupportedTomlSubset))
    {
        Ok(v) => v,
        Err(r) => return ScanStatus::CompatibilityProtected(r),
    };
    let base = match string(&format!("{provider_path}.base_url"))
        .and_then(|v| EndpointUrl::parse(v).map_err(|_| CompatibilityReason::UnsupportedTomlSubset))
    {
        Ok(v) => v,
        Err(r) => return ScanStatus::CompatibilityProtected(r),
    };
    let model = match string("model")
        .and_then(|v| ModelId::parse(v).map_err(|_| CompatibilityReason::UnsupportedTomlSubset))
    {
        Ok(v) => v,
        Err(r) => return ScanStatus::CompatibilityProtected(r),
    };
    let (mode, schema) = match json::classify(&auth) {
        Ok(v) => v,
        Err(r) => return ScanStatus::CompatibilityProtected(r),
    };
    let auth_mode = if mode == "api_key" {
        AuthMode::ApiKey
    } else {
        AuthMode::OAuth
    };
    let generation = match (auth_mode, parsed.has_bom, parsed.line_ending) {
        (AuthMode::OAuth, false, codex_application::LineEnding::CrLf) => {
            FormatGeneration::SyntheticOAuth
        }
        (AuthMode::ApiKey, true, codex_application::LineEnding::Lf) => {
            FormatGeneration::CurrentShape
        }
        (AuthMode::ApiKey, false, codex_application::LineEnding::Lf) => {
            FormatGeneration::ApiKeyBaseline
        }
        _ => FormatGeneration::CompatibleUnknown,
    };
    ScanStatus::Ready(Box::new(ActualCodexState {
        config: ScannedConfig {
            original_bytes: config.clone(),
            baseline_sha256: hash_bytes(&config),
            has_bom: parsed.has_bom,
            line_ending: parsed.line_ending,
            generation,
            provider_id: provider,
            provider_display_name: provider_name,
            api_base_url: base,
            model_id: model,
        },
        authentication: AuthenticationDescriptor {
            auth_mode,
            schema_fingerprint: SchemaFingerprint::parse(&hash::sha256_hex(schema.as_bytes()))
                .expect("hash"),
            credential_fingerprint: CredentialFingerprint::parse(&hash::sha256_hex(&auth))
                .expect("hash"),
        },
    }))
}

impl CodexStateSource for CodexAdapter {
    fn scan_explicit_root(&self, root: &Path) -> ScanStatus {
        if !root.is_dir() {
            return ScanStatus::CompatibilityProtected(CompatibilityReason::IoUnavailable);
        }
        let config = match fs::read(root.join("config.toml")) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return ScanStatus::CompatibilityProtected(CompatibilityReason::MissingConfig);
            }
            Err(_) => {
                return ScanStatus::CompatibilityProtected(CompatibilityReason::IoUnavailable);
            }
        };
        let auth = match fs::read(root.join("auth.json")) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return ScanStatus::CompatibilityProtected(
                    CompatibilityReason::MissingAuthentication,
                );
            }
            Err(_) => {
                return ScanStatus::CompatibilityProtected(CompatibilityReason::IoUnavailable);
            }
        };
        scan_bytes(config, auth)
    }
}

impl ConfigPlanner for CodexAdapter {
    fn plan_config(
        &self,
        actual: &ActualCodexState,
        desired: &DesiredManagedConfig,
        credential: &CredentialReference,
    ) -> Result<PlannedConfig, CompatibilityReason> {
        let parsed = toml::parse(&actual.config.original_bytes)?;
        let provider_path = format!("model_providers.{}", desired.provider_id.as_str());
        let replacements: Vec<(String, String)> = vec![
            ("model_provider".into(), desired.provider_id.as_str().into()),
            ("model".into(), desired.model_id.as_str().into()),
            (
                format!("{provider_path}.name"),
                desired.provider_display_name.as_str().into(),
            ),
            (
                format!("{provider_path}.base_url"),
                desired.api_base_url.as_str().into(),
            ),
        ];
        let mut changes = Vec::new();
        for (path, after) in &replacements {
            let before = parsed
                .assignments
                .get(path)
                .ok_or(CompatibilityReason::MissingManagedField)?
                .value
                .clone();
            if before != *after {
                changes.push(ManagedFieldChange {
                    path: path.clone(),
                    before,
                    after: after.clone(),
                })
            }
        }
        let target = toml::replace_strings(&parsed, &replacements)?;
        let target_hash = hash_bytes(&target);
        let mut lines = changes
            .iter()
            .map(|c| format!("{}: {} -> {}", c.path, c.before, c.after))
            .collect::<Vec<_>>();
        let fingerprint = &credential.credential_fingerprint().as_str()[..8];
        lines.push(format!(
            "authentication: {:?} ref={} backend={:?} fingerprint={}… [REDACTED]",
            credential.kind(),
            credential.id().as_str(),
            credential.backend(),
            fingerprint
        ));
        Ok(PlannedConfig {
            target_bytes: target,
            baseline_sha256: actual.config.baseline_sha256.clone(),
            target_sha256: target_hash,
            changes,
            diff: RedactedDiff::new(lines),
        })
    }
}
