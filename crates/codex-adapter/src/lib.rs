#![forbid(unsafe_code)]
//! 只读取调用方显式提供的 Codex 目录，并只在内存中生成配置计划。

mod hash;
mod json;
mod toml;

use std::{fs, path::Path};

use codex_application::{
    ActualCodexState, AuthenticationDescriptor, CodexStateSource, CompatibilityReason,
    ConfigPlanner, ControlledCodexSource, ControlledRoot, ControlledScanId, ControlledScanStatus,
    ControlledScanSummary, ControlledSourceError, DesiredManagedConfig, FormatGeneration,
    ManagedFieldChange, PlannedConfig, RedactedDiff, ScanStatus, ScannedAuthConsumer,
    ScannedConfig,
};
use codex_domain::{
    AuthMode, ContentHash, CredentialFingerprint, CredentialReference, EndpointUrl, EntityName,
    ModelId, ProviderId, SchemaFingerprint, contains_high_confidence_secret_bytes,
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, Default)]
pub struct CodexAdapter;

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
        scan_slices(config, auth)
    }
}

fn scan_bytes(config: Vec<u8>, auth: Vec<u8>) -> ScanStatus {
    let config = Zeroizing::new(config);
    let auth = SensitiveAuth::new(auth);
    scan_slices(&config, &auth)
}

fn scan_slices(config: &[u8], auth: &[u8]) -> ScanStatus {
    if contains_high_confidence_secret_bytes(config) {
        return ScanStatus::CompatibilityProtected(CompatibilityReason::UnsupportedTomlSubset);
    }
    let parsed = match toml::parse(config) {
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
    let (mode, schema) = match json::classify(auth) {
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
            original_bytes: config.to_vec(),
            baseline_sha256: hash_bytes(config),
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
            credential_fingerprint: CredentialFingerprint::parse(&hash::sha256_hex(auth))
                .expect("hash"),
        },
    }))
}

pub trait StableSnapshotConsumer {
    fn consume(
        &mut self,
        config: &mut [u8],
        auth: &mut [u8],
        evidence: &[u8],
    ) -> Result<(), ControlledSourceError>;
}

pub trait ControlledRootReader {
    fn read_stable(
        &self,
        root: ControlledRoot,
        consumer: &mut dyn StableSnapshotConsumer,
    ) -> Result<(), ControlledSourceError>;
}

#[derive(Clone, Debug)]
pub struct ControlledCodexAdapter<R> {
    resolver: R,
}

impl<R> ControlledCodexAdapter<R> {
    #[must_use]
    pub const fn new(resolver: R) -> Self {
        Self { resolver }
    }
}

fn controlled_scan_id(actual: &ActualCodexState, evidence: &[u8]) -> ControlledScanId {
    let mut digest = hash::Sha256::new();
    digest.update(actual.config.baseline_sha256.as_str().as_bytes());
    digest.update(b":");
    digest.update(
        actual
            .authentication
            .credential_fingerprint
            .as_str()
            .as_bytes(),
    );
    digest.update(b":");
    digest.update(evidence);
    let value = digest
        .finish()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    ControlledScanId::from_hash(ContentHash::parse(&value).expect("SHA-256 scan id"))
}

struct SensitiveAuth {
    bytes: Vec<u8>,
    #[cfg(test)]
    observer: Option<std::rc::Rc<std::cell::Cell<bool>>>,
}

impl SensitiveAuth {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            #[cfg(test)]
            observer: None,
        }
    }

    #[cfg(test)]
    fn observed(bytes: Vec<u8>, observer: std::rc::Rc<std::cell::Cell<bool>>) -> Self {
        Self {
            bytes,
            observer: Some(observer),
        }
    }
}

impl std::ops::Deref for SensitiveAuth {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl std::ops::DerefMut for SensitiveAuth {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bytes
    }
}

impl Drop for SensitiveAuth {
    fn drop(&mut self) {
        self.bytes.zeroize();
        #[cfg(test)]
        if let Some(observer) = &self.observer {
            observer.set(self.bytes.iter().all(|byte| *byte == 0));
        }
    }
}

impl<R: ControlledRootReader> ControlledCodexSource for ControlledCodexAdapter<R> {
    fn scan(&self, root: ControlledRoot) -> ControlledScanStatus {
        struct Scanner(Option<ControlledScanStatus>);
        impl StableSnapshotConsumer for Scanner {
            fn consume(
                &mut self,
                config: &mut [u8],
                auth: &mut [u8],
                evidence: &[u8],
            ) -> Result<(), ControlledSourceError> {
                self.0 = Some(match scan_slices(config, auth) {
                    ScanStatus::Ready(actual) => {
                        ControlledScanStatus::Ready(ControlledScanSummary {
                            scan_id: controlled_scan_id(&actual, evidence),
                            auth_mode: actual.authentication.auth_mode,
                        })
                    }
                    ScanStatus::CompatibilityProtected(reason) => {
                        ControlledScanStatus::CompatibilityProtected(reason)
                    }
                });
                Ok(())
            }
        }
        let mut scanner = Scanner(None);
        match self.resolver.read_stable(root, &mut scanner) {
            Ok(()) => scanner
                .0
                .unwrap_or(ControlledScanStatus::CompatibilityProtected(
                    CompatibilityReason::IoUnavailable,
                )),
            Err(ControlledSourceError::CompatibilityProtected(reason)) => {
                ControlledScanStatus::CompatibilityProtected(reason)
            }
            Err(_) => {
                ControlledScanStatus::CompatibilityProtected(CompatibilityReason::IoUnavailable)
            }
        }
    }

    fn consume_confirmed(
        &self,
        root: ControlledRoot,
        expected: &ControlledScanId,
        consumer: &mut dyn ScannedAuthConsumer,
    ) -> Result<(), ControlledSourceError> {
        struct Confirmer<'a> {
            expected: &'a ControlledScanId,
            consumer: &'a mut dyn ScannedAuthConsumer,
        }
        impl StableSnapshotConsumer for Confirmer<'_> {
            fn consume(
                &mut self,
                config: &mut [u8],
                auth: &mut [u8],
                evidence: &[u8],
            ) -> Result<(), ControlledSourceError> {
                let actual = match scan_slices(config, auth) {
                    ScanStatus::Ready(actual) => actual,
                    ScanStatus::CompatibilityProtected(reason) => {
                        return Err(ControlledSourceError::CompatibilityProtected(reason));
                    }
                };
                if &controlled_scan_id(&actual, evidence) != self.expected {
                    return Err(ControlledSourceError::ScanChanged);
                }
                self.consumer.consume(&actual, auth)
            }
        }
        self.resolver
            .read_stable(root, &mut Confirmer { expected, consumer })
    }
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

#[cfg(test)]
mod controlled_tests {
    use std::{
        cell::Cell,
        panic::{AssertUnwindSafe, catch_unwind},
        rc::Rc,
    };

    use codex_application::{ControlledSourceError, ScannedAuthConsumer};

    use super::{ActualCodexState, SensitiveAuth, scan_slices};

    struct PanickingConsumer;

    impl ScannedAuthConsumer for PanickingConsumer {
        fn consume(
            &mut self,
            _actual: &ActualCodexState,
            _auth: &mut [u8],
        ) -> Result<(), ControlledSourceError> {
            panic!("synthetic consumer panic")
        }
    }

    #[test]
    fn sensitive_auth_zeroizes_during_unwind() {
        let zeroized = Rc::new(Cell::new(false));
        let observed = zeroized.clone();
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut auth = SensitiveAuth::observed(
                b"synthetic-auth-buffer-with-secret-shape".to_vec(),
                observed,
            );
            let codex_application::ScanStatus::Ready(actual) = scan_slices(
                b"model = \"gpt-SAMPLE\"\nmodel_provider = \"sample\"\n[model_providers.sample]\nname = \"Sample\"\nbase_url = \"https://HOST/v1\"\n",
                b"{\"OPENAI_API_KEY\":\"SAMPLE_VALUE\"}",
            ) else {
                panic!("synthetic state must scan")
            };
            PanickingConsumer.consume(&actual, &mut auth).unwrap();
        }));
        assert!(result.is_err());
        assert!(zeroized.get());
    }
}
