use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use codex_adapter::CodexAuthorizationParser;
use codex_application::{
    CancelDisposition, CancellationController, DiscoverModelsInput, DiscoverModelsOutcome,
    DiscoveryErrorCode, M28_SERVICE_VERSION, ProbeConnectionInput, ProbeConnectionOutcome,
    SafeModelDiscoveryService,
};
use codex_domain::{CredentialRefId, EndpointPolicy, EntityVersion, IdentityId};
use local_infrastructure::{NativeHttpTransport, SqliteMetadataRepository, SystemDnsResolver};
use windows_platform::WindowsDpapiCredentialStore;

use crate::application_facade::{
    CancellationOutcome, DiscoverModelsRequest, EndpointPolicyDto, M35Backend, M35BackendError,
    ModelCandidateDto, ProbeConnectionRequest,
};

pub const MAX_ACTIVE_OPERATIONS: usize = 32;

#[derive(Debug)]
pub struct ProductionM35Backend {
    database_path: PathBuf,
    credential_root: PathBuf,
    operations: Arc<Mutex<HashMap<String, Arc<CancellationController>>>>,
}

impl ProductionM35Backend {
    pub fn new(app_data_dir: impl AsRef<Path>) -> Result<Self, M35BackendError> {
        let app_data_dir = app_data_dir.as_ref();
        if !app_data_dir.is_absolute() {
            return Err(M35BackendError::Unavailable);
        }
        fs::create_dir_all(app_data_dir).map_err(|_| M35BackendError::Unavailable)?;
        Ok(Self {
            database_path: app_data_dir.join("metadata.sqlite3"),
            credential_root: app_data_dir.join("credentials"),
            operations: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn register(&self, operation_id: &str) -> Result<OperationGuard, M35BackendError> {
        let mut operations = self
            .operations
            .lock()
            .map_err(|_| M35BackendError::Internal)?;
        if operations.len() >= MAX_ACTIVE_OPERATIONS || operations.contains_key(operation_id) {
            return Err(M35BackendError::Conflict);
        }
        let controller = Arc::new(CancellationController::new());
        operations.insert(operation_id.to_owned(), controller.clone());
        Ok(OperationGuard {
            operation_id: operation_id.to_owned(),
            controller,
            operations: self.operations.clone(),
        })
    }

    fn service_parts(
        &self,
    ) -> Result<(SqliteMetadataRepository, WindowsDpapiCredentialStore), M35BackendError> {
        let repository = SqliteMetadataRepository::open(&self.database_path)
            .map_err(|_| M35BackendError::Unavailable)?;
        let credential_store = WindowsDpapiCredentialStore::new(&self.credential_root)
            .map_err(|_| M35BackendError::Unavailable)?;
        Ok((repository, credential_store))
    }
}

struct OperationGuard {
    operation_id: String,
    controller: Arc<CancellationController>,
    operations: Arc<Mutex<HashMap<String, Arc<CancellationController>>>>,
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        if let Ok(mut operations) = self.operations.lock() {
            if operations
                .get(&self.operation_id)
                .is_some_and(|current| Arc::ptr_eq(current, &self.controller))
            {
                operations.remove(&self.operation_id);
            }
        }
    }
}

impl M35Backend for ProductionM35Backend {
    fn probe_connection(&self, request: &ProbeConnectionRequest) -> Result<bool, M35BackendError> {
        let guard = self.register(request.operation_id.as_str())?;
        let (repository, credential_store) = self.service_parts()?;
        let resolver = SystemDnsResolver;
        let parser = CodexAuthorizationParser::new();
        let mut transport = NativeHttpTransport::new();
        let mut service = SafeModelDiscoveryService::new(
            &repository,
            &credential_store,
            &resolver,
            &parser,
            &mut transport,
        );
        let input = ProbeConnectionInput {
            service_version: M28_SERVICE_VERSION,
            identity_id: parse_identity(request.identity_id.as_str())?,
            credential_ref_id: parse_credential(request.credential_ref_id.as_str())?,
            expected_identity_version: parse_version(request.expected_identity_version)?,
            endpoint_policy: endpoint_policy(request.endpoint_policy),
            operation_id: request.operation_id.as_str().to_owned(),
        };
        match service
            .probe_connection(&input, guard.controller.as_ref())
            .map_err(map_error)?
        {
            ProbeConnectionOutcome::Reachable(summary) => Ok(summary.api_compatible),
            ProbeConnectionOutcome::Cancelled => Err(M35BackendError::Cancelled),
        }
    }

    fn discover_models(
        &self,
        request: &DiscoverModelsRequest,
    ) -> Result<Vec<ModelCandidateDto>, M35BackendError> {
        let guard = self.register(request.operation_id.as_str())?;
        let (repository, credential_store) = self.service_parts()?;
        let resolver = SystemDnsResolver;
        let parser = CodexAuthorizationParser::new();
        let mut transport = NativeHttpTransport::new();
        let mut service = SafeModelDiscoveryService::new(
            &repository,
            &credential_store,
            &resolver,
            &parser,
            &mut transport,
        );
        let input = DiscoverModelsInput {
            service_version: M28_SERVICE_VERSION,
            identity_id: parse_identity(request.identity_id.as_str())?,
            credential_ref_id: parse_credential(request.credential_ref_id.as_str())?,
            expected_identity_version: parse_version(request.expected_identity_version)?,
            endpoint_policy: endpoint_policy(request.endpoint_policy),
            operation_id: request.operation_id.as_str().to_owned(),
        };
        match service
            .discover_models(&input, guard.controller.as_ref())
            .map_err(map_error)?
        {
            DiscoverModelsOutcome::Models(models) => Ok(models
                .into_iter()
                .map(|model| ModelCandidateDto {
                    model_id: model.id().as_str().to_owned(),
                    display_name: model.display_name().map(|name| name.as_str().to_owned()),
                })
                .collect()),
            DiscoverModelsOutcome::Cancelled => Err(M35BackendError::Cancelled),
        }
    }

    fn cancel_operation(&self, operation_id: &str) -> Option<CancellationOutcome> {
        let controller = self.operations.lock().ok()?.get(operation_id).cloned()?;
        Some(match controller.cancel() {
            CancelDisposition::Cancelled => CancellationOutcome::Requested,
            CancelDisposition::AlreadyCancelled => CancellationOutcome::AlreadyRequested,
            CancelDisposition::TooLate => CancellationOutcome::TooLate,
        })
    }

    fn cancel_all(&self) {
        let controllers = self
            .operations
            .lock()
            .map(|operations| operations.values().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        for controller in controllers {
            let _ = controller.cancel();
        }
    }

    fn active_operation_count(&self) -> usize {
        self.operations
            .lock()
            .map(|items| items.len())
            .unwrap_or(MAX_ACTIVE_OPERATIONS)
    }
}

fn parse_identity(value: &str) -> Result<IdentityId, M35BackendError> {
    IdentityId::parse(value).map_err(|_| M35BackendError::Validation)
}
fn parse_credential(value: &str) -> Result<CredentialRefId, M35BackendError> {
    CredentialRefId::parse(value).map_err(|_| M35BackendError::Validation)
}
fn parse_version(value: u64) -> Result<EntityVersion, M35BackendError> {
    EntityVersion::new(value).map_err(|_| M35BackendError::Validation)
}
const fn endpoint_policy(value: EndpointPolicyDto) -> EndpointPolicy {
    match value {
        EndpointPolicyDto::PublicHttps => EndpointPolicy::PublicHttps,
        EndpointPolicyDto::LoopbackDevelopment => EndpointPolicy::LoopbackDevelopment,
    }
}
const fn map_error(error: DiscoveryErrorCode) -> M35BackendError {
    match error {
        DiscoveryErrorCode::Validation => M35BackendError::Validation,
        DiscoveryErrorCode::NotFound => M35BackendError::NotFound,
        DiscoveryErrorCode::Conflict => M35BackendError::Conflict,
        DiscoveryErrorCode::AuthRequired => M35BackendError::AuthRequired,
        DiscoveryErrorCode::Forbidden => M35BackendError::Forbidden,
        DiscoveryErrorCode::RateLimited => M35BackendError::RateLimited,
        DiscoveryErrorCode::Timeout => M35BackendError::Timeout,
        DiscoveryErrorCode::TlsFailure => M35BackendError::TlsFailure,
        DiscoveryErrorCode::NetworkUnavailable => M35BackendError::NetworkUnavailable,
        DiscoveryErrorCode::InvalidResponse => M35BackendError::InvalidResponse,
        DiscoveryErrorCode::ResponseTooLarge => M35BackendError::ResponseTooLarge,
        DiscoveryErrorCode::CompatibilityProtected => M35BackendError::CompatibilityProtected,
        DiscoveryErrorCode::Cancelled => M35BackendError::Cancelled,
        DiscoveryErrorCode::Internal => M35BackendError::Internal,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        process::Command,
        sync::atomic::{AtomicU64, Ordering},
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };

    use codex_adapter::CodexAdapter;
    use codex_application::{
        CredentialEnvelopeBinding, CredentialReferenceRepository, CredentialStore,
        ImportIdentityInput, ImportOutcome, RuntimeIdentityRepository, import_scanned_identity,
    };
    use codex_domain::{
        CredentialBackend, CredentialKind, CredentialRefId, CredentialReference, EntityName,
        IdentityId, ManagedConfigPatchId, ModelPresetId, UnixMillis,
    };

    use super::*;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    struct TempArea(PathBuf);
    impl TempArea {
        fn new() -> Self {
            let root = std::env::temp_dir();
            for _ in 0..128 {
                let stamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos();
                let path = root.join(format!(
                    "codextools-m35-native-{}-{stamp}-{}",
                    std::process::id(),
                    NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("synthetic temp create failed: {error}"),
                }
            }
            panic!("synthetic temp allocation exhausted")
        }
    }
    impl Drop for TempArea {
        fn drop(&mut self) {
            if self.0.parent() == Some(std::env::temp_dir().as_path())
                && self.0.file_name().is_some_and(|name| {
                    name.to_string_lossy().starts_with("codextools-m35-native-")
                })
            {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
    }

    fn run_isolated_production_backend_fixture() {
        let area = TempArea::new();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0_u8; 4096];
                let count = stream.read(&mut request).unwrap();
                assert!(
                    String::from_utf8_lossy(&request[..count])
                        .contains("Authorization: Bearer SAMPLE_VALUE")
                );
                let body = br#"{"data":[{"id":"model-b","name":"Model B"},{"id":"model-a"}]}"#;
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                stream.write_all(body).unwrap();
            }
        });

        let database = area.0.join("metadata.sqlite3");
        let credential_root = area.0.join("credentials");
        let mut repository = SqliteMetadataRepository::open(&database).unwrap();
        let mut store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();
        let credential_id = CredentialRefId::parse("31313131-3131-4131-8131-313131313131").unwrap();
        let config = format!(
            "model = \"model-a\"\nmodel_provider = \"synthetic\"\n[model_providers.synthetic]\nname = \"Synthetic\"\nbase_url = \"http://127.0.0.1:{port}/v1\"\n"
        );
        let mut document = br#"{"OPENAI_API_KEY":"SAMPLE_VALUE"}"#.to_vec();
        let codex_application::ScanStatus::Ready(actual) =
            CodexAdapter::new().scan_memory(config.as_bytes(), &document)
        else {
            panic!("synthetic scan must be supported")
        };
        let reference = CredentialReference::new(
            credential_id.clone(),
            CredentialKind::ApiKey,
            CredentialBackend::WindowsDpapiCurrentUser,
            actual.authentication.schema_fingerprint.clone(),
            actual.authentication.credential_fingerprint.clone(),
            UnixMillis::new(1).unwrap(),
        );
        repository.create_credential_reference(&reference).unwrap();
        store
            .create(
                &CredentialEnvelopeBinding::new(
                    reference.id().clone(),
                    reference.kind(),
                    reference.schema_fingerprint().clone(),
                    reference.version(),
                ),
                &mut document,
            )
            .unwrap();
        document.fill(0);
        let identity_id = IdentityId::parse("41414141-4141-4141-8141-414141414141").unwrap();
        assert_eq!(
            reference.schema_fingerprint(),
            &actual.authentication.schema_fingerprint
        );
        assert_eq!(
            reference.credential_fingerprint(),
            &actual.authentication.credential_fingerprint
        );
        assert_eq!(
            import_scanned_identity(
                &mut repository,
                &actual,
                ImportIdentityInput {
                    identity_id: identity_id.clone(),
                    identity_name: EntityName::parse("Synthetic M35").unwrap(),
                    preset_id: ModelPresetId::parse("51515151-5151-4151-8151-515151515151")
                        .unwrap(),
                    preset_name: EntityName::parse("Synthetic preset").unwrap(),
                    patch_id: ManagedConfigPatchId::parse("61616161-6161-4161-8161-616161616161")
                        .unwrap(),
                    credential: Some(reference.clone()),
                    credential_already_persisted: true,
                    now: UnixMillis::new(2).unwrap(),
                },
            )
            .unwrap(),
            ImportOutcome::Imported
        );
        let persisted_reference = repository
            .get_credential_reference(&credential_id)
            .unwrap()
            .unwrap();
        assert_eq!(persisted_reference, reference);
        let persisted_identity = repository
            .get_runtime_identity(&identity_id)
            .unwrap()
            .unwrap();
        assert_eq!(persisted_identity.credential().id(), reference.id());
        assert_eq!(persisted_identity.credential().kind(), reference.kind());
        let identity_version = persisted_identity.version().value();
        drop(store);
        drop(repository);

        let backend = ProductionM35Backend::new(&area.0).unwrap();
        let request = ProbeConnectionRequest {
            schema_version: 1,
            correlation_id: crate::application_facade::SafeIdentifier::parse("native-corr")
                .unwrap(),
            identity_id: crate::application_facade::SafeIdentifier::parse(identity_id.as_str())
                .unwrap(),
            credential_ref_id: crate::application_facade::SafeIdentifier::parse(
                credential_id.as_str(),
            )
            .unwrap(),
            expected_identity_version: identity_version,
            endpoint_policy: EndpointPolicyDto::LoopbackDevelopment,
            operation_id: crate::application_facade::SafeIdentifier::parse("native-probe").unwrap(),
        };
        assert!(backend.probe_connection(&request).unwrap());
        let models = backend
            .discover_models(&DiscoverModelsRequest {
                schema_version: request.schema_version,
                correlation_id: request.correlation_id.clone(),
                identity_id: request.identity_id.clone(),
                credential_ref_id: request.credential_ref_id.clone(),
                expected_identity_version: request.expected_identity_version,
                endpoint_policy: request.endpoint_policy,
                operation_id: crate::application_facade::SafeIdentifier::parse("native-discover")
                    .unwrap(),
            })
            .unwrap();
        assert_eq!(
            models
                .iter()
                .map(|model| model.model_id.as_str())
                .collect::<Vec<_>>(),
            ["model-a", "model-b"]
        );
        server.join().unwrap();
    }

    #[test]
    fn production_backend_native_child_entry() {
        if std::env::var_os("CODEXTOOLS_M35_NATIVE_CHILD").is_none() {
            return;
        }
        run_isolated_production_backend_fixture();
    }

    #[test]
    fn production_backend_uses_fresh_process_isolated_sqlite_dpapi_and_loopback_transport() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "m35_backend::tests::production_backend_native_child_entry",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("CODEXTOOLS_M35_NATIVE_CHILD", "1")
            .env_remove("CODEX_HOME")
            .env_remove("HTTP_PROXY")
            .env_remove("HTTPS_PROXY")
            .env_remove("ALL_PROXY")
            .output()
            .unwrap();
        assert!(output.status.success(), "fresh process fixture failed");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stdout.contains("SAMPLE_VALUE"));
        assert!(!stderr.contains("SAMPLE_VALUE"));
    }
}
