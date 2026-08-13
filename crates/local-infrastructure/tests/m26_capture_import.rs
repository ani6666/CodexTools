#![allow(unused_crate_dependencies)]

use std::{
    cell::Cell,
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use codex_adapter::{ControlledCodexAdapter, hash_bytes};
use codex_application::{
    CaptureImportDiagnostic, CaptureImportRecoveryRepository, CaptureImportRequest,
    CaptureImportStatus, ControlledCodexSource, ControlledRoot, ControlledRootResolver,
    ControlledScanStatus, ControlledSourceError, CredentialEnvelopeBinding,
    CredentialMaterialDiagnostic, CredentialMutationOwner, CredentialRecoveryRepository,
    CredentialReferenceRepository, CredentialStore, CredentialStoreError,
    ManagedConfigPatchRepository, ModelPresetRepository, RuntimeIdentityRepository, SecretConsumer,
};
use codex_domain::{
    CredentialBackend, CredentialFingerprint, CredentialKind, CredentialRefId, CredentialReference,
    EndpointUrl, EntityName, IdentityId, ManagedConfigPatchId, ModelId, ModelPreset, ModelPresetId,
    ProviderId, RuntimeIdentity, SchemaFingerprint, UnixMillis,
};
use local_infrastructure::{
    CaptureImportFaultPoint, CaptureImportFaults, CaptureImportService, CredentialService,
    CredentialServiceError, CrossProcessWriteLock, OpenRepositoryError, SqliteMetadataRepository,
    WindowsControlledRootReader,
};
use windows_platform::WindowsDpapiCredentialStore;
use zeroize::Zeroize;

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

struct TempArea {
    root: PathBuf,
    codex_root: PathBuf,
    database: PathBuf,
}

impl TempArea {
    fn new(label: &str, auth: &[u8]) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "codextools-m26-{label}-{}-{nonce}-{sequence}",
            std::process::id()
        ));
        let codex_root = root.join("controlled-root");
        fs::create_dir_all(&codex_root).unwrap();
        fs::write(codex_root.join("config.toml"), config()).unwrap();
        fs::write(codex_root.join("auth.json"), auth).unwrap();
        Self {
            database: root.join("metadata.sqlite3"),
            root,
            codex_root,
        }
    }
}

impl Drop for TempArea {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Clone)]
struct SyntheticResolver(PathBuf);

impl ControlledRootResolver for SyntheticResolver {
    fn resolve(&self, _root: ControlledRoot) -> Result<PathBuf, ControlledSourceError> {
        Ok(self.0.clone())
    }
}

struct StableProbeConsumer {
    operation: Box<dyn FnOnce()>,
}

impl codex_adapter::StableSnapshotConsumer for StableProbeConsumer {
    fn consume(
        &mut self,
        _config: &mut [u8],
        _auth: &mut [u8],
        _evidence: &[u8],
    ) -> Result<(), ControlledSourceError> {
        let operation = std::mem::replace(&mut self.operation, Box::new(|| {}));
        operation();
        Ok(())
    }
}

#[derive(Clone)]
struct StoredMaterial {
    binding: CredentialEnvelopeBinding,
    secret: Vec<u8>,
}

impl Drop for StoredMaterial {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[derive(Default)]
struct FakeCredentialStore {
    materials: BTreeMap<CredentialRefId, StoredMaterial>,
    mutation: Option<CredentialMutationOwner>,
    nonce: u64,
    fail_create_once: bool,
    fail_release_once: bool,
    fail_read_once: Cell<bool>,
    fail_inspect_once: Cell<bool>,
    fail_delete_once: bool,
    delete_calls: usize,
}

impl FakeCredentialStore {
    fn material(&self, id: &CredentialRefId) -> Option<&[u8]> {
        self.materials
            .get(id)
            .map(|stored| stored.secret.as_slice())
    }
}

impl CredentialStore for FakeCredentialStore {
    fn begin_mutation(
        &mut self,
        id: &CredentialRefId,
    ) -> Result<CredentialMutationOwner, CredentialStoreError> {
        if self.mutation.is_some() {
            return Err(CredentialStoreError::RecoveryRequired);
        }
        self.nonce += 1;
        let owner = CredentialMutationOwner::new(id.clone(), self.nonce);
        self.mutation = Some(owner.clone());
        Ok(owner)
    }

    fn end_mutation(&mut self, owner: CredentialMutationOwner) -> Result<(), CredentialStoreError> {
        if self.mutation.as_ref() != Some(&owner) {
            return Err(CredentialStoreError::RecoveryRequired);
        }
        self.mutation = None;
        if self.fail_release_once {
            self.fail_release_once = false;
            return Err(CredentialStoreError::RecoveryRequired);
        }
        Ok(())
    }

    fn planned_material_ref(
        &self,
        binding: &CredentialEnvelopeBinding,
    ) -> Result<PathBuf, CredentialStoreError> {
        Ok(PathBuf::from(binding.id().as_str())
            .join(format!("generation-{}.fake", binding.generation().value())))
    }

    fn create(
        &mut self,
        binding: &CredentialEnvelopeBinding,
        secret: &mut [u8],
    ) -> Result<(), CredentialStoreError> {
        if self.fail_create_once {
            self.fail_create_once = false;
            secret.fill(0);
            return Err(CredentialStoreError::IoFailure);
        }
        if let Some(existing) = self.materials.get(binding.id()) {
            let result = if &existing.binding == binding {
                CredentialStoreError::AlreadyExists
            } else {
                CredentialStoreError::BindingMismatch
            };
            secret.fill(0);
            return Err(result);
        }
        let stored = StoredMaterial {
            binding: binding.clone(),
            secret: secret.to_vec(),
        };
        secret.fill(0);
        self.materials.insert(binding.id().clone(), stored);
        Ok(())
    }

    fn read(
        &self,
        binding: &CredentialEnvelopeBinding,
        consumer: &mut dyn SecretConsumer,
    ) -> Result<(), CredentialStoreError> {
        if self.fail_read_once.replace(false) {
            return Err(CredentialStoreError::IoFailure);
        }
        let stored = self
            .materials
            .get(binding.id())
            .ok_or(CredentialStoreError::NotFound)?;
        if &stored.binding != binding {
            return Err(CredentialStoreError::BindingMismatch);
        }
        consumer.consume(&stored.secret)
    }

    fn rotate(
        &mut self,
        previous: &CredentialEnvelopeBinding,
        next: &CredentialEnvelopeBinding,
        secret: &mut [u8],
    ) -> Result<(), CredentialStoreError> {
        let stored = self
            .materials
            .get(previous.id())
            .ok_or(CredentialStoreError::NotFound)?;
        if &stored.binding != previous || previous.id() != next.id() {
            secret.fill(0);
            return Err(CredentialStoreError::BindingMismatch);
        }
        let replacement = StoredMaterial {
            binding: next.clone(),
            secret: secret.to_vec(),
        };
        secret.fill(0);
        self.materials.insert(next.id().clone(), replacement);
        Ok(())
    }

    fn delete(&mut self, binding: &CredentialEnvelopeBinding) -> Result<(), CredentialStoreError> {
        self.delete_calls += 1;
        if self.fail_delete_once {
            self.fail_delete_once = false;
            return Err(CredentialStoreError::IoFailure);
        }
        let stored = self
            .materials
            .get(binding.id())
            .ok_or(CredentialStoreError::NotFound)?;
        if &stored.binding != binding {
            return Err(CredentialStoreError::BindingMismatch);
        }
        let mut removed = self.materials.remove(binding.id()).unwrap();
        removed.secret.fill(0);
        Ok(())
    }

    fn inspect(
        &self,
        binding: &CredentialEnvelopeBinding,
    ) -> Result<CredentialMaterialDiagnostic, CredentialStoreError> {
        if self.fail_inspect_once.replace(false) {
            return Err(CredentialStoreError::IoFailure);
        }
        let stored = self
            .materials
            .get(binding.id())
            .ok_or(CredentialStoreError::NotFound)?;
        if &stored.binding != binding {
            return Err(CredentialStoreError::BindingMismatch);
        }
        Ok(CredentialMaterialDiagnostic {
            material_ref: self.planned_material_ref(binding)?,
            material_hash: hash_bytes(&stored.secret),
        })
    }
}

struct OneShotFault(Option<CaptureImportFaultPoint>);

impl CaptureImportFaults for OneShotFault {
    fn interrupt(&mut self, point: CaptureImportFaultPoint) -> bool {
        if self.0 == Some(point) {
            self.0 = None;
            true
        } else {
            false
        }
    }
}

struct InsertPresetConflictFault {
    database: PathBuf,
    preset_id: ModelPresetId,
    identity_id: IdentityId,
    fired: bool,
}

impl CaptureImportFaults for InsertPresetConflictFault {
    fn interrupt(&mut self, point: CaptureImportFaultPoint) -> bool {
        if point == CaptureImportFaultPoint::BeforeBundleCommit && !self.fired {
            self.fired = true;
            let connection = rusqlite::Connection::open(&self.database).unwrap();
            connection
                .execute(
                    "INSERT INTO model_presets
                     (id,identity_id,name,model_id,created_at_unix_ms,updated_at_unix_ms,version)
                     VALUES (?1,?2,'racing preset','gpt-racing',3,3,1)",
                    [self.preset_id.as_str(), self.identity_id.as_str()],
                )
                .unwrap();
        }
        false
    }
}

#[derive(Clone, Copy)]
enum CredentialContenderAction {
    Create,
    Rotate,
    Delete,
}

struct CredentialContenderFault {
    database: PathBuf,
    credential_root: PathBuf,
    credential_id: CredentialRefId,
    action: CredentialContenderAction,
    result: Option<Result<(), CredentialServiceError>>,
}

struct StaleJournalFault {
    database: PathBuf,
    fired: bool,
}

impl CaptureImportFaults for StaleJournalFault {
    fn interrupt(&mut self, point: CaptureImportFaultPoint) -> bool {
        if point == CaptureImportFaultPoint::AfterJournalPrepared && !self.fired {
            self.fired = true;
            let connection = rusqlite::Connection::open(&self.database).unwrap();
            connection
                .execute(
                    "UPDATE capture_import_operations
                     SET version=version+1
                     WHERE phase='prepared'",
                    [],
                )
                .unwrap();
        }
        false
    }
}

impl CaptureImportFaults for CredentialContenderFault {
    fn interrupt(&mut self, point: CaptureImportFaultPoint) -> bool {
        if point != CaptureImportFaultPoint::BeforeBundleCommit || self.result.is_some() {
            return false;
        }
        let mut repository = SqliteMetadataRepository::open(&self.database).unwrap();
        let mut store = WindowsDpapiCredentialStore::new(&self.credential_root).unwrap();
        let mut next_secret = Vec::from(&b"sk-"[..]);
        next_secret.extend((0..40).map(|index| b'A' + (index % 26)));
        let result = match self.action {
            CredentialContenderAction::Create => {
                CredentialService::new(&mut repository, &mut store)
                    .create_api_key(
                        self.credential_id.clone(),
                        &mut next_secret,
                        UnixMillis::new(4).unwrap(),
                    )
                    .map(|_| ())
            }
            CredentialContenderAction::Rotate => {
                CredentialService::new(&mut repository, &mut store)
                    .rotate_credential(
                        &self.credential_id,
                        codex_domain::EntityVersion::initial(),
                        &mut next_secret,
                        UnixMillis::new(4).unwrap(),
                    )
                    .map(|_| ())
            }
            CredentialContenderAction::Delete => {
                CredentialService::new(&mut repository, &mut store)
                    .delete_credential(&self.credential_id, codex_domain::EntityVersion::initial())
            }
        };
        next_secret.zeroize();
        self.result = Some(result);
        false
    }
}

fn config() -> &'static [u8] {
    b"model = \"gpt-SAMPLE-1\"\nmodel_provider = \"sample\"\n[model_providers.sample]\nname = \"Sample Provider\"\nbase_url = \"https://HOST/v1\"\n"
}

fn api_key_auth(suffix: u8) -> Vec<u8> {
    let mut key = Vec::from(&b"sk-"[..]);
    key.extend((0..40).map(|index| b'A' + (index % 26)));
    key.push(suffix);
    let mut auth = Vec::from(&b"{\"OPENAI_API_KEY\":\""[..]);
    auth.extend_from_slice(&key);
    auth.extend_from_slice(b"\"}\n");
    auth
}

fn oauth_auth(suffix: &str) -> Vec<u8> {
    format!(
        "{{\"tokens\":{{\"id_token\":\"ID_{suffix}\",\"access_token\":\"ACCESS_{suffix}\",\"refresh_token\":\"REFRESH_{suffix}\",\"account_id\":\"ACCOUNT_{suffix}\"}}}}\n"
    )
    .into_bytes()
}

fn scan_id(source: &impl ControlledCodexSource) -> codex_application::ControlledScanId {
    let ControlledScanStatus::Ready(summary) = source.scan(ControlledRoot::DefaultCodex) else {
        panic!("synthetic controlled root must scan")
    };
    summary.scan_id
}

fn controlled_source(
    root: PathBuf,
) -> ControlledCodexAdapter<WindowsControlledRootReader<SyntheticResolver>> {
    ControlledCodexAdapter::new(WindowsControlledRootReader::new(SyntheticResolver(root)))
}

fn request(source: &impl ControlledCodexSource, offset: u8) -> CaptureImportRequest {
    let id = |prefix: u8| format!("{prefix:02x}{offset:02x}0000-0000-4000-8000-000000000001");
    CaptureImportRequest {
        root: ControlledRoot::DefaultCodex,
        scan_id: scan_id(source),
        credential_id: CredentialRefId::parse(&id(0x11)).unwrap(),
        identity_id: IdentityId::parse(&id(0x22)).unwrap(),
        identity_name: EntityName::parse("隔离身份").unwrap(),
        preset_id: ModelPresetId::parse(&id(0x33)).unwrap(),
        preset_name: EntityName::parse("隔离模型").unwrap(),
        patch_id: ManagedConfigPatchId::parse(&id(0x44)).unwrap(),
        now: UnixMillis::new(1_000 + i64::from(offset)).unwrap(),
    }
}

fn assert_complete(
    repository: &SqliteMetadataRepository,
    store: &FakeCredentialStore,
    request: &CaptureImportRequest,
    auth: &[u8],
) {
    let reference = repository
        .get_credential_reference(&request.credential_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        reference.credential_fingerprint().as_str(),
        hash_bytes(auth).as_str()
    );
    assert_eq!(store.material(&request.credential_id), Some(auth));
    let identity = repository
        .get_runtime_identity(&request.identity_id)
        .unwrap()
        .unwrap();
    assert_eq!(identity.credential().id(), &request.credential_id);
    assert_eq!(identity.default_model_preset_id(), Some(&request.preset_id));
    assert!(
        repository
            .get_model_preset(&request.preset_id)
            .unwrap()
            .is_some()
    );
    assert!(
        repository
            .get_managed_config_patch(&request.identity_id)
            .unwrap()
            .is_some()
    );
    assert!(
        repository
            .get_capture_import_recovery(&format!(
                "capture-import:{}",
                request.identity_id.as_str()
            ))
            .unwrap()
            .is_none()
    );
}

fn cleanup_dpapi_import(
    database: &PathBuf,
    credential_root: &PathBuf,
    request: &CaptureImportRequest,
) {
    let connection = rusqlite::Connection::open(database).unwrap();
    connection
        .execute(
            "DELETE FROM managed_config_patches WHERE identity_id=?1",
            [request.identity_id.as_str()],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE runtime_identities
             SET status='draft', default_model_preset_id=NULL
             WHERE id=?1",
            [request.identity_id.as_str()],
        )
        .unwrap();
    connection
        .execute(
            "DELETE FROM model_presets WHERE identity_id=?1",
            [request.identity_id.as_str()],
        )
        .unwrap();
    connection
        .execute(
            "DELETE FROM runtime_identities WHERE id=?1",
            [request.identity_id.as_str()],
        )
        .unwrap();
    drop(connection);
    let mut repository = SqliteMetadataRepository::open(database).unwrap();
    if let Some(reference) = repository
        .get_credential_reference(&request.credential_id)
        .unwrap()
    {
        let mut store = WindowsDpapiCredentialStore::new(credential_root).unwrap();
        CredentialService::new(&mut repository, &mut store)
            .delete_credential(reference.id(), reference.version())
            .unwrap();
    }
}

#[test]
fn m26_public_contract_is_path_free_and_secret_free() {
    let request = CaptureImportRequest {
        root: ControlledRoot::DefaultCodex,
        scan_id: "a".repeat(64).parse().unwrap(),
        credential_id: CredentialRefId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
        identity_id: IdentityId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
        identity_name: EntityName::parse("隔离身份").unwrap(),
        preset_id: ModelPresetId::parse("33333333-3333-4333-8333-333333333333").unwrap(),
        preset_name: EntityName::parse("隔离模型").unwrap(),
        patch_id: ManagedConfigPatchId::parse("44444444-4444-4444-8444-444444444444").unwrap(),
        now: UnixMillis::new(1_000).unwrap(),
    };

    let debug = format!("{request:?}");
    assert!(!debug.contains("auth.json"));
    assert!(!debug.contains("config.toml"));
    assert!(!debug.contains("sk-"));
    assert_eq!(std::mem::size_of::<CaptureImportService>(), 0);
    let _outward_status: Option<CaptureImportStatus> = None;
    let _scan_status: Option<ControlledScanStatus> = None;
}

#[test]
fn api_key_and_oauth_capture_import_are_consistent_and_idempotent() {
    for (label, auth, offset) in [
        ("api-key", api_key_auth(b'Z'), 1_u8),
        ("oauth", oauth_auth("SYNTHETIC"), 2_u8),
    ] {
        let area = TempArea::new(label, &auth);
        let source = controlled_source(area.codex_root.clone());
        let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
        let mut store = FakeCredentialStore::default();
        let request = request(&source, offset);

        assert_eq!(
            CaptureImportService::new().capture_import(
                &source,
                &mut repository,
                &mut store,
                request.clone(),
            ),
            CaptureImportStatus::Imported(request.identity_id.clone())
        );
        assert_complete(&repository, &store, &request, &auth);

        drop(repository);
        let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
        assert_eq!(
            CaptureImportService::new().capture_import(
                &source,
                &mut repository,
                &mut store,
                request.clone(),
            ),
            CaptureImportStatus::AlreadyImported(request.identity_id.clone())
        );
        assert_complete(&repository, &store, &request, &auth);
    }
}

#[test]
fn every_cross_resource_crash_cut_reopens_and_converges() {
    for (index, point) in [
        CaptureImportFaultPoint::AfterJournalPrepared,
        CaptureImportFaultPoint::AfterCredentialReady,
        CaptureImportFaultPoint::AfterBundleCommitted,
        CaptureImportFaultPoint::BeforeJournalCleanup,
    ]
    .into_iter()
    .enumerate()
    {
        let auth = api_key_auth(b'K' + u8::try_from(index).unwrap());
        let area = TempArea::new("crash-cut", &auth);
        let source = controlled_source(area.codex_root.clone());
        let request = request(&source, 10 + u8::try_from(index).unwrap());
        let mut store = FakeCredentialStore::default();
        {
            let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
            let result = CaptureImportService::new().capture_import_with_faults(
                &source,
                &mut repository,
                &mut store,
                request.clone(),
                &mut OneShotFault(Some(point)),
            );
            assert!(matches!(result, CaptureImportStatus::RecoveryRequired(_)));
            if matches!(
                point,
                CaptureImportFaultPoint::AfterCredentialReady
                    | CaptureImportFaultPoint::AfterBundleCommitted
                    | CaptureImportFaultPoint::BeforeJournalCleanup
            ) {
                assert_eq!(store.delete_calls, 0);
            }
        }

        if point == CaptureImportFaultPoint::AfterBundleCommitted {
            fs::write(area.codex_root.join("auth.json"), api_key_auth(b'Z')).unwrap();
        }

        let mut reopened = SqliteMetadataRepository::open(&area.database).unwrap();
        let result = CaptureImportService::new().capture_import(
            &source,
            &mut reopened,
            &mut store,
            request.clone(),
        );
        assert!(matches!(
            result,
            CaptureImportStatus::Imported(_) | CaptureImportStatus::AlreadyImported(_)
        ));
        assert_complete(&reopened, &store, &request, &auth);
    }
}

#[test]
fn capture_failure_remains_explained_and_retryable() {
    let auth = api_key_auth(b'Q');
    let area = TempArea::new("capture-failure", &auth);
    let source = controlled_source(area.codex_root.clone());
    let request = request(&source, 30);
    let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
    let mut store = FakeCredentialStore {
        fail_create_once: true,
        ..FakeCredentialStore::default()
    };

    assert_eq!(
        CaptureImportService::new().capture_import(
            &source,
            &mut repository,
            &mut store,
            request.clone(),
        ),
        CaptureImportStatus::RecoveryRequired(CaptureImportDiagnostic::CredentialPending)
    );
    assert!(
        repository
            .get_capture_import_recovery(&format!(
                "capture-import:{}",
                request.identity_id.as_str()
            ))
            .unwrap()
            .is_some()
    );
    assert!(store.material(&request.credential_id).is_none());
    assert!(
        repository
            .get_runtime_identity(&request.identity_id)
            .unwrap()
            .is_none()
    );

    drop(repository);
    let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
    assert!(matches!(
        CaptureImportService::new().capture_import(
            &source,
            &mut repository,
            &mut store,
            request.clone(),
        ),
        CaptureImportStatus::Imported(_) | CaptureImportStatus::AlreadyImported(_)
    ));
    assert_complete(&repository, &store, &request, &auth);
}

#[test]
fn store_inspect_and_read_faults_are_recoverable_without_identity_or_secret_leak() {
    for inspect_fault in [true, false] {
        let auth = api_key_auth(if inspect_fault { b'E' } else { b'F' });
        let area = TempArea::new("store-fault", &auth);
        let source = controlled_source(area.codex_root.clone());
        let request = request(&source, if inspect_fault { 76 } else { 77 });
        let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
        let mut store = FakeCredentialStore::default();
        if inspect_fault {
            store.fail_inspect_once.set(true);
        } else {
            // First read occurs when the freshly published material is verified under owner.
            store.fail_read_once.set(true);
        }
        assert!(matches!(
            CaptureImportService::new().capture_import(
                &source,
                &mut repository,
                &mut store,
                request.clone(),
            ),
            CaptureImportStatus::RecoveryRequired(_)
        ));
        assert!(
            repository
                .get_runtime_identity(&request.identity_id)
                .unwrap()
                .is_none()
        );
        drop(repository);
        let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
        assert!(matches!(
            CaptureImportService::new().capture_import(
                &source,
                &mut repository,
                &mut store,
                request.clone(),
            ),
            CaptureImportStatus::Imported(_) | CaptureImportStatus::AlreadyImported(_)
        ));
        assert_complete(&repository, &store, &request, &auth);
    }
}

#[test]
fn repository_phase_metadata_and_bundle_faults_reopen_and_converge() {
    for (index, (name, trigger, expected)) in [
        (
            "journal-create",
            "CREATE TRIGGER m26_fault BEFORE INSERT ON capture_import_operations
             BEGIN SELECT RAISE(ABORT,'m26 journal create'); END",
            CaptureImportDiagnostic::JournalUnavailable,
        ),
        (
            "journal-update",
            "CREATE TRIGGER m26_fault BEFORE UPDATE ON capture_import_operations
             BEGIN SELECT RAISE(ABORT,'m26 journal update'); END",
            CaptureImportDiagnostic::JournalUnavailable,
        ),
        (
            "journal-delete",
            "CREATE TRIGGER m26_fault BEFORE DELETE ON capture_import_operations
             BEGIN SELECT RAISE(ABORT,'m26 journal delete'); END",
            CaptureImportDiagnostic::CleanupPending,
        ),
        (
            "credential-metadata",
            "CREATE TRIGGER m26_fault BEFORE INSERT ON credential_references
             BEGIN SELECT RAISE(ABORT,'m26 credential metadata'); END",
            CaptureImportDiagnostic::CredentialPending,
        ),
        (
            "bundle-commit",
            "CREATE TRIGGER m26_fault BEFORE INSERT ON runtime_identities
             BEGIN SELECT RAISE(ABORT,'m26 bundle commit'); END",
            CaptureImportDiagnostic::BundlePending,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let auth = api_key_auth(b'G' + u8::try_from(index).unwrap());
        let area = TempArea::new(name, &auth);
        let source = controlled_source(area.codex_root.clone());
        let request = request(&source, 90 + u8::try_from(index).unwrap());
        let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
        let connection = rusqlite::Connection::open(&area.database).unwrap();
        connection.execute_batch(trigger).unwrap();
        drop(connection);
        let mut store = FakeCredentialStore::default();
        assert_eq!(
            CaptureImportService::new().capture_import(
                &source,
                &mut repository,
                &mut store,
                request.clone(),
            ),
            CaptureImportStatus::RecoveryRequired(expected),
            "{name}"
        );
        assert_eq!(
            repository
                .get_runtime_identity(&request.identity_id)
                .unwrap()
                .is_some(),
            name == "journal-delete",
            "{name}"
        );
        drop(repository);
        let connection = rusqlite::Connection::open(&area.database).unwrap();
        connection.execute("DROP TRIGGER m26_fault", []).unwrap();
        drop(connection);
        let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
        let result = if name == "journal-delete" {
            CaptureImportService::new().recover_capture_import(
                &mut repository,
                &mut store,
                &request.identity_id,
            )
        } else {
            CaptureImportService::new().capture_import(
                &source,
                &mut repository,
                &mut store,
                request.clone(),
            )
        };
        assert!(
            matches!(
                result,
                CaptureImportStatus::Imported(_) | CaptureImportStatus::AlreadyImported(_)
            ),
            "{name}: {result:?}"
        );
        assert_complete(&repository, &store, &request, &auth);
    }

    let auth = api_key_auth(b'M');
    let area = TempArea::new("journal-cas-stale", &auth);
    let source = controlled_source(area.codex_root.clone());
    let request = request(&source, 95);
    let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
    let mut store = FakeCredentialStore::default();
    assert_eq!(
        CaptureImportService::new().capture_import_with_faults(
            &source,
            &mut repository,
            &mut store,
            request.clone(),
            &mut StaleJournalFault {
                database: area.database.clone(),
                fired: false,
            },
        ),
        CaptureImportStatus::RecoveryRequired(CaptureImportDiagnostic::JournalUnavailable)
    );
    drop(repository);
    let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
    assert!(matches!(
        CaptureImportService::new().capture_import(
            &source,
            &mut repository,
            &mut store,
            request.clone(),
        ),
        CaptureImportStatus::Imported(_) | CaptureImportStatus::AlreadyImported(_)
    ));
    assert_complete(&repository, &store, &request, &auth);
}

#[test]
fn scan_change_compatibility_and_same_id_different_material_fail_closed() {
    let auth = api_key_auth(b'X');
    let area = TempArea::new("scan-change", &auth);
    let source = controlled_source(area.codex_root.clone());
    let stale_request = request(&source, 40);
    let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
    let mut store = FakeCredentialStore::default();

    fs::write(area.codex_root.join("auth.json"), api_key_auth(b'Y')).unwrap();
    assert_eq!(
        CaptureImportService::new().capture_import(
            &source,
            &mut repository,
            &mut store,
            stale_request.clone(),
        ),
        CaptureImportStatus::Conflict
    );
    assert!(store.materials.is_empty());
    let count: i64 = rusqlite::Connection::open(&area.database)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM capture_import_operations",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);

    fs::remove_file(area.codex_root.join("auth.json")).unwrap();
    assert!(matches!(
        CaptureImportService::new().scan(&source, ControlledRoot::DefaultCodex),
        ControlledScanStatus::CompatibilityProtected(_)
    ));

    fs::write(area.codex_root.join("auth.json"), &auth).unwrap();
    let exact_request = request(&source, 41);
    assert!(matches!(
        CaptureImportService::new().capture_import(
            &source,
            &mut repository,
            &mut store,
            exact_request.clone(),
        ),
        CaptureImportStatus::Imported(_)
    ));
    fs::write(area.codex_root.join("auth.json"), api_key_auth(b'Z')).unwrap();
    let different = CaptureImportRequest {
        scan_id: scan_id(&source),
        ..exact_request.clone()
    };
    assert_eq!(
        CaptureImportService::new()
            .capture_import(&source, &mut repository, &mut store, different,),
        CaptureImportStatus::Conflict
    );
    assert_complete(&repository, &store, &exact_request, &auth);
}

#[test]
fn schema_tamper_and_outward_canaries_do_not_leak_secret_or_path() {
    let auth = api_key_auth(b'W');
    let area = TempArea::new("canary", &auth);
    let source = controlled_source(area.codex_root.clone());
    let request = request(&source, 50);
    let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
    let mut store = FakeCredentialStore::default();
    let marker = String::from_utf8(auth.clone()).unwrap();
    let real_path = area.codex_root.to_string_lossy().into_owned();

    let status = CaptureImportService::new().capture_import_with_faults(
        &source,
        &mut repository,
        &mut store,
        request.clone(),
        &mut OneShotFault(Some(CaptureImportFaultPoint::BeforeJournalCleanup)),
    );
    for outward in [
        format!("{status:?}"),
        format!("{request:?}"),
        format!("{:?}", source.scan(ControlledRoot::DefaultCodex)),
        ControlledSourceError::ScanChanged.to_string(),
    ] {
        assert!(!outward.contains(&marker));
        assert!(!outward.contains("sk-"));
        assert!(!outward.contains(&real_path));
        assert!(!outward.contains("auth.json"));
    }
    let recovery = repository
        .get_capture_import_recovery(&format!("capture-import:{}", request.identity_id.as_str()))
        .unwrap()
        .unwrap();
    let recovery_debug = format!("{recovery:?}");
    assert!(!recovery_debug.contains(&marker));
    assert!(!recovery_debug.contains(&real_path));
    let recovery_display = format!(
        "{}:{:?}:{:?}",
        recovery.operation_id, recovery.phase, recovery.diagnostic
    );
    assert!(!recovery_display.contains(&marker));
    assert!(!recovery_display.contains(&real_path));
    let event_fixture = format!("capture-import:{}:{status:?}", request.identity_id.as_str());
    assert!(!event_fixture.contains(&marker));
    assert!(!event_fixture.contains(&real_path));
    let database_bytes = fs::read(&area.database).unwrap();
    assert!(
        !database_bytes
            .windows(auth.len())
            .any(|window| window == auth)
    );
    assert!(
        !database_bytes
            .windows(real_path.len())
            .any(|window| window == real_path.as_bytes())
    );
    for path in [
        area.root.join("credentials"),
        area.root.join("logs"),
        area.root.join("events"),
    ] {
        if path.exists() {
            for entry in fs::read_dir(path).unwrap() {
                let bytes = fs::read(entry.unwrap().path()).unwrap_or_default();
                assert!(!bytes.windows(auth.len()).any(|window| window == auth));
                assert!(
                    !bytes
                        .windows(real_path.len())
                        .any(|window| window == real_path.as_bytes())
                );
            }
        }
    }

    drop(repository);
    let connection = rusqlite::Connection::open(&area.database).unwrap();
    connection
        .execute(
            "UPDATE credential_references SET schema_fingerprint=?2 WHERE id=?1",
            [request.credential_id.as_str(), &"f".repeat(64)],
        )
        .unwrap();
    drop(connection);
    let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
    assert_eq!(
        CaptureImportService::new().capture_import(&source, &mut repository, &mut store, request,),
        CaptureImportStatus::RecoveryRequired(CaptureImportDiagnostic::InconsistentState)
    );
}

fn existing_credential(id: CredentialRefId) -> CredentialReference {
    CredentialReference::new(
        id,
        CredentialKind::ApiKey,
        CredentialBackend::WindowsDpapiCurrentUser,
        SchemaFingerprint::parse(&"a".repeat(64)).unwrap(),
        CredentialFingerprint::parse(&"b".repeat(64)).unwrap(),
        UnixMillis::new(1).unwrap(),
    )
}

#[test]
fn ledger_v11_with_any_capture_schema_tamper_fails_closed_on_open() {
    for (index, tamper) in [
        "DROP INDEX idx_capture_import_unfinished",
        "DROP TABLE capture_import_operations",
        "ALTER TABLE capture_import_operations RENAME COLUMN phase TO weakened_phase",
        "ALTER INDEX idx_capture_import_unfinished RENAME TO weakened_capture_index",
        "CREATE TABLE capture_import_weakened AS SELECT * FROM capture_import_operations;
         DROP TABLE capture_import_operations;
         ALTER TABLE capture_import_weakened RENAME TO capture_import_operations",
        "PRAGMA writable_schema=ON;
         UPDATE sqlite_master SET sql=replace(sql, 'CHECK(version >= 1)', 'CHECK(version >= 0)')
         WHERE type='table' AND name='capture_import_operations';
         PRAGMA writable_schema=OFF",
    ]
    .into_iter()
    .enumerate()
    {
        let auth = api_key_auth(b'T' + u8::try_from(index).unwrap());
        let area = TempArea::new("ledger-tamper", &auth);
        drop(SqliteMetadataRepository::open(&area.database).unwrap());
        let connection = rusqlite::Connection::open(&area.database).unwrap();
        if tamper.starts_with("ALTER INDEX") {
            connection
                .execute("DROP INDEX idx_capture_import_unfinished", [])
                .unwrap();
            connection
                .execute(
                    "CREATE INDEX weakened_capture_index
                     ON capture_import_operations(phase, operation_id)",
                    [],
                )
                .unwrap();
        } else {
            connection.execute_batch(tamper).unwrap();
        }
        let ledger: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version=11",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(ledger, 1);
        drop(connection);
        assert!(
            matches!(
                SqliteMetadataRepository::open(&area.database),
                Err(OpenRepositoryError::CorruptData)
            ),
            "tamper accepted: {tamper}"
        );
    }
}

#[test]
fn same_bytes_with_new_file_id_is_not_the_confirmed_scan() {
    let auth = api_key_auth(b'I');
    let area = TempArea::new("identity-replace", &auth);
    let source = controlled_source(area.codex_root.clone());
    let request = request(&source, 60);
    let config_replacement = area.codex_root.join("config.replacement");
    let auth_replacement = area.codex_root.join("auth.replacement");
    fs::write(&config_replacement, config()).unwrap();
    fs::write(&auth_replacement, &auth).unwrap();
    fs::rename(&config_replacement, area.codex_root.join("config.toml")).unwrap();
    fs::rename(&auth_replacement, area.codex_root.join("auth.json")).unwrap();
    let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
    let mut store = FakeCredentialStore::default();
    assert_eq!(
        CaptureImportService::new().capture_import(&source, &mut repository, &mut store, request),
        CaptureImportStatus::Conflict
    );
    assert!(store.materials.is_empty());
}

#[cfg(windows)]
#[test]
fn controlled_root_reparse_is_rejected_without_following_target() {
    let auth = api_key_auth(b'J');
    let target = TempArea::new("reparse-target", &auth);
    let link = target.root.join("codex-link");
    let status = std::process::Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&link)
        .arg(&target.codex_root)
        .status()
        .unwrap();
    assert!(status.success());
    let source = controlled_source(link);
    assert!(matches!(
        source.scan(ControlledRoot::DefaultCodex),
        ControlledScanStatus::CompatibilityProtected(_)
    ));
}

#[test]
fn controlled_config_and_auth_reparse_are_rejected() {
    for target_name in ["config.toml", "auth.json"] {
        let auth = api_key_auth(b'J');
        let area = TempArea::new("file-reparse", &auth);
        let target = area.root.join(format!("{target_name}.target"));
        fs::copy(area.codex_root.join(target_name), &target).unwrap();
        fs::remove_file(area.codex_root.join(target_name)).unwrap();
        let output = Command::new("cmd.exe")
            .args([
                "/d",
                "/c",
                "mklink",
                area.codex_root.join(target_name).to_str().unwrap(),
                target.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let source = controlled_source(area.codex_root.clone());
        assert!(matches!(
            source.scan(ControlledRoot::DefaultCodex),
            ControlledScanStatus::CompatibilityProtected(_)
        ));
    }
}

#[test]
fn pinned_pair_blocks_config_and_auth_replacement_until_consumer_returns() {
    for target_name in ["config.toml", "auth.json"] {
        let auth = api_key_auth(b'B');
        let area = TempArea::new("stable-sharing", &auth);
        let reader = WindowsControlledRootReader::new(SyntheticResolver(area.codex_root.clone()));
        let target = area.codex_root.join(target_name);
        let replacement = area.codex_root.join(format!("{target_name}.replacement"));
        fs::write(&replacement, fs::read(&target).unwrap()).unwrap();
        let target_for_operation = target.clone();
        let replacement_for_operation = replacement.clone();
        let mut consumer = StableProbeConsumer {
            operation: Box::new(move || {
                assert!(fs::rename(&replacement_for_operation, &target_for_operation).is_err());
                assert!(
                    fs::OpenOptions::new()
                        .write(true)
                        .open(&target_for_operation)
                        .is_err()
                );
            }),
        };
        codex_adapter::ControlledRootReader::read_stable(
            &reader,
            ControlledRoot::DefaultCodex,
            &mut consumer,
        )
        .unwrap();
        fs::rename(&replacement, &target).unwrap();
    }
}

#[test]
fn scan_id_binds_root_identity_even_for_identical_pair_bytes() {
    let auth = api_key_auth(b'N');
    let first = TempArea::new("root-evidence-first", &auth);
    let second = TempArea::new("root-evidence-second", &auth);
    let first_source = controlled_source(first.codex_root.clone());
    let second_source = controlled_source(second.codex_root.clone());
    assert_ne!(scan_id(&first_source), scan_id(&second_source));
}

#[test]
fn preset_id_conflict_before_bundle_does_not_leave_orphan_credential_or_journal() {
    let auth = api_key_auth(b'O');
    let area = TempArea::new("orphan-conflict", &auth);
    let source = controlled_source(area.codex_root.clone());
    let request = request(&source, 70);
    let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
    let reference = existing_credential(
        CredentialRefId::parse("90909090-9090-4090-8090-909090909090").unwrap(),
    );
    repository.create_credential_reference(&reference).unwrap();
    let identity = RuntimeIdentity::new_draft(
        IdentityId::parse("80808080-8080-4080-8080-808080808080").unwrap(),
        EntityName::parse("既有身份").unwrap(),
        ProviderId::parse("existing-provider").unwrap(),
        EntityName::parse("Existing Provider").unwrap(),
        EndpointUrl::parse("https://HOST/existing").unwrap(),
        None,
        reference.link(),
        UnixMillis::new(1).unwrap(),
    )
    .unwrap();
    repository.create_runtime_identity(&identity).unwrap();
    let conflicting_preset = ModelPreset::new(
        request.preset_id.clone(),
        identity.id().clone(),
        EntityName::parse("既有预设").unwrap(),
        ModelId::parse("gpt-existing").unwrap(),
        UnixMillis::new(2).unwrap(),
    );
    repository.create_model_preset(&conflicting_preset).unwrap();
    let mut store = FakeCredentialStore::default();
    assert_eq!(
        CaptureImportService::new().capture_import(
            &source,
            &mut repository,
            &mut store,
            request.clone(),
        ),
        CaptureImportStatus::Conflict
    );
    assert!(
        repository
            .get_credential_reference(&request.credential_id)
            .unwrap()
            .is_none()
    );
    assert!(store.material(&request.credential_id).is_none());
    assert!(
        repository
            .get_capture_import_recovery(&format!(
                "capture-import:{}",
                request.identity_id.as_str()
            ))
            .unwrap()
            .is_none()
    );
}

#[test]
fn preset_conflict_after_capture_is_durably_rolled_back_on_retry() {
    let auth = api_key_auth(b'R');
    let area = TempArea::new("post-capture-conflict", &auth);
    let source = controlled_source(area.codex_root.clone());
    let request = request(&source, 71);
    let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
    let other_reference = existing_credential(
        CredentialRefId::parse("91919191-9191-4191-8191-919191919191").unwrap(),
    );
    repository
        .create_credential_reference(&other_reference)
        .unwrap();
    let other_identity = RuntimeIdentity::new_draft(
        IdentityId::parse("81818181-8181-4181-8181-818181818181").unwrap(),
        EntityName::parse("竞态身份").unwrap(),
        ProviderId::parse("racing-provider").unwrap(),
        EntityName::parse("Racing Provider").unwrap(),
        EndpointUrl::parse("https://HOST/racing").unwrap(),
        None,
        other_reference.link(),
        UnixMillis::new(1).unwrap(),
    )
    .unwrap();
    repository.create_runtime_identity(&other_identity).unwrap();
    let mut store = FakeCredentialStore::default();
    let mut fault = InsertPresetConflictFault {
        database: area.database.clone(),
        preset_id: request.preset_id.clone(),
        identity_id: other_identity.id().clone(),
        fired: false,
    };
    assert_eq!(
        CaptureImportService::new().capture_import_with_faults(
            &source,
            &mut repository,
            &mut store,
            request.clone(),
            &mut fault,
        ),
        CaptureImportStatus::RecoveryRequired(CaptureImportDiagnostic::InconsistentState)
    );
    assert!(store.material(&request.credential_id).is_some());
    assert!(
        repository
            .get_credential_reference(&request.credential_id)
            .unwrap()
            .is_some()
    );
    assert!(
        repository
            .get_runtime_identity(&request.identity_id)
            .unwrap()
            .is_none()
    );

    drop(repository);
    let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
    assert_eq!(
        CaptureImportService::new().recover_capture_import(
            &mut repository,
            &mut store,
            &request.identity_id,
        ),
        CaptureImportStatus::Conflict
    );
    assert!(store.material(&request.credential_id).is_none());
    assert!(
        repository
            .get_credential_reference(&request.credential_id)
            .unwrap()
            .is_none()
    );
    assert!(
        repository
            .get_capture_import_recovery(&format!(
                "capture-import:{}",
                request.identity_id.as_str()
            ))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        repository
            .get_model_preset(&request.preset_id)
            .unwrap()
            .unwrap()
            .identity_id(),
        other_identity.id()
    );
}

#[test]
fn rollback_store_delete_failure_remains_durable_and_recoverable() {
    let auth = api_key_auth(b'D');
    let area = TempArea::new("rollback-delete-fault", &auth);
    let source = controlled_source(area.codex_root.clone());
    let request = request(&source, 78);
    let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
    let other_reference = existing_credential(
        CredentialRefId::parse("92929292-9292-4292-8292-929292929292").unwrap(),
    );
    repository
        .create_credential_reference(&other_reference)
        .unwrap();
    let other_identity = RuntimeIdentity::new_draft(
        IdentityId::parse("82828282-8282-4282-8282-828282828282").unwrap(),
        EntityName::parse("删除故障身份").unwrap(),
        ProviderId::parse("delete-fault-provider").unwrap(),
        EntityName::parse("Delete Fault Provider").unwrap(),
        EndpointUrl::parse("https://HOST/delete-fault").unwrap(),
        None,
        other_reference.link(),
        UnixMillis::new(1).unwrap(),
    )
    .unwrap();
    repository.create_runtime_identity(&other_identity).unwrap();
    let mut store = FakeCredentialStore::default();
    let mut fault = InsertPresetConflictFault {
        database: area.database.clone(),
        preset_id: request.preset_id.clone(),
        identity_id: other_identity.id().clone(),
        fired: false,
    };
    assert_eq!(
        CaptureImportService::new().capture_import_with_faults(
            &source,
            &mut repository,
            &mut store,
            request.clone(),
            &mut fault,
        ),
        CaptureImportStatus::RecoveryRequired(CaptureImportDiagnostic::InconsistentState)
    );
    store.fail_delete_once = true;
    assert_eq!(
        CaptureImportService::new().recover_capture_import(
            &mut repository,
            &mut store,
            &request.identity_id,
        ),
        CaptureImportStatus::RecoveryRequired(CaptureImportDiagnostic::InconsistentState)
    );
    assert!(
        repository
            .get_credential_reference(&request.credential_id)
            .unwrap()
            .is_none()
    );
    assert!(store.material(&request.credential_id).is_some());
    assert_eq!(
        repository
            .list_credential_recoveries(&request.credential_id)
            .unwrap()
            .len(),
        1
    );
    drop(repository);
    let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
    assert_eq!(
        CaptureImportService::new().recover_capture_import(
            &mut repository,
            &mut store,
            &request.identity_id,
        ),
        CaptureImportStatus::Conflict
    );
    assert!(store.material(&request.credential_id).is_none());
    assert!(
        repository
            .list_credential_recoveries(&request.credential_id)
            .unwrap()
            .is_empty()
    );
    assert!(
        repository
            .get_capture_import_recovery(&format!(
                "capture-import:{}",
                request.identity_id.as_str()
            ))
            .unwrap()
            .is_none()
    );
}

#[test]
fn owner_release_failure_never_reports_imported_and_reopen_converges() {
    let auth = api_key_auth(b'L');
    let area = TempArea::new("owner-release", &auth);
    let source = controlled_source(area.codex_root.clone());
    let request = request(&source, 72);
    let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
    let mut store = FakeCredentialStore {
        fail_release_once: true,
        ..FakeCredentialStore::default()
    };
    assert!(matches!(
        CaptureImportService::new().capture_import(
            &source,
            &mut repository,
            &mut store,
            request.clone(),
        ),
        CaptureImportStatus::RecoveryRequired(_)
    ));
    assert!(
        repository
            .get_runtime_identity(&request.identity_id)
            .unwrap()
            .is_some()
    );
    drop(repository);
    let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
    assert_eq!(
        CaptureImportService::new().capture_import(
            &source,
            &mut repository,
            &mut store,
            request.clone(),
        ),
        CaptureImportStatus::AlreadyImported(request.identity_id.clone())
    );
    assert_complete(&repository, &store, &request, &auth);
}

#[test]
fn scoped_capture_panic_zeroizes_auth_and_releases_owner() {
    let auth = api_key_auth(b'W');
    let area = TempArea::new("scoped-panic", &auth);
    let source = controlled_source(area.codex_root.clone());
    let request = request(&source, 79);
    let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
    let mut store = FakeCredentialStore::default();
    let mut owned_auth = auth.clone();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: Result<(), local_infrastructure::ScopedCredentialError<()>> =
            CredentialService::new(&mut repository, &mut store).capture_auth_document_scoped(
                request.credential_id.clone(),
                CredentialKind::ApiKey,
                &mut owned_auth,
                request.now,
                |_repository, _store, _credential| panic!("synthetic scoped panic"),
            );
    }));
    assert!(panic.is_err());
    assert!(owned_auth.iter().all(|byte| *byte == 0));
    let owner = store.begin_mutation(&request.credential_id).unwrap();
    store.end_mutation(owner).unwrap();
}

#[test]
fn dpapi_owner_covers_exact_verify_and_bundle_commit_against_all_mutations() {
    for (index, action) in [
        CredentialContenderAction::Create,
        CredentialContenderAction::Rotate,
        CredentialContenderAction::Delete,
    ]
    .into_iter()
    .enumerate()
    {
        let auth = api_key_auth(b'U' + u8::try_from(index).unwrap());
        let area = TempArea::new("dpapi-linearization", &auth);
        let credential_root = area.root.join("credentials");
        let source = controlled_source(area.codex_root.clone());
        let request = request(&source, 73 + u8::try_from(index).unwrap());
        let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
        let mut store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();
        let mut fault = CredentialContenderFault {
            database: area.database.clone(),
            credential_root: credential_root.clone(),
            credential_id: request.credential_id.clone(),
            action,
            result: None,
        };
        assert_eq!(
            CaptureImportService::new().capture_import_with_faults(
                &source,
                &mut repository,
                &mut store,
                request.clone(),
                &mut fault,
            ),
            CaptureImportStatus::Imported(request.identity_id.clone())
        );
        assert_eq!(
            fault.result,
            Some(Err(CredentialServiceError::VersionConflict))
        );
        let reference = repository
            .get_credential_reference(&request.credential_id)
            .unwrap()
            .unwrap();
        assert_eq!(reference.version(), codex_domain::EntityVersion::initial());
        assert_eq!(
            reference.credential_fingerprint().as_str(),
            hash_bytes(&auth).as_str()
        );

        drop(repository);
        let connection = rusqlite::Connection::open(&area.database).unwrap();
        connection
            .execute(
                "DELETE FROM managed_config_patches WHERE identity_id=?1",
                [request.identity_id.as_str()],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE runtime_identities
                 SET status='draft', default_model_preset_id=NULL
                 WHERE id=?1",
                [request.identity_id.as_str()],
            )
            .unwrap();
        connection
            .execute(
                "DELETE FROM model_presets WHERE identity_id=?1",
                [request.identity_id.as_str()],
            )
            .unwrap();
        connection
            .execute(
                "DELETE FROM runtime_identities WHERE id=?1",
                [request.identity_id.as_str()],
            )
            .unwrap();
        drop(connection);
        let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
        CredentialService::new(&mut repository, &mut store)
            .delete_credential(reference.id(), reference.version())
            .unwrap();
    }
}

#[test]
fn terminated_dpapi_helpers_reopen_and_converge_at_every_persistent_cut() {
    for (index, point) in [
        "after-journal",
        "after-credential",
        "before-bundle",
        "after-bundle",
        "before-cleanup",
    ]
    .into_iter()
    .enumerate()
    {
        let auth = api_key_auth(b'A' + u8::try_from(index).unwrap());
        let area = TempArea::new("dpapi-hard-crash", &auth);
        let credential_root = area.root.join("credentials");
        let source = controlled_source(area.codex_root.clone());
        let request = request(&source, 80 + u8::try_from(index).unwrap());
        let mut child = Command::new(env!("CARGO_BIN_EXE_m26-capture-import-crash"))
            .arg("crash")
            .arg(&area.codex_root)
            .arg(&area.database)
            .arg(&credential_root)
            .arg(point)
            .arg((80 + u8::try_from(index).unwrap()).to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut ready = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        assert!(ready.starts_with("READY point="), "{point}: {ready}");
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());

        let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
        let mut store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();
        let status = CaptureImportService::new().capture_import(
            &source,
            &mut repository,
            &mut store,
            request.clone(),
        );
        assert!(
            matches!(
                status,
                CaptureImportStatus::Imported(_) | CaptureImportStatus::AlreadyImported(_)
            ),
            "{point}: {status:?}"
        );
        let reference = repository
            .get_credential_reference(&request.credential_id)
            .unwrap()
            .unwrap();
        assert_eq!(reference.version(), codex_domain::EntityVersion::initial());
        assert_eq!(
            reference.credential_fingerprint().as_str(),
            hash_bytes(&auth).as_str()
        );
        assert!(
            repository
                .get_runtime_identity(&request.identity_id)
                .unwrap()
                .is_some()
        );
        assert!(
            repository
                .get_capture_import_recovery(&format!(
                    "capture-import:{}",
                    request.identity_id.as_str()
                ))
                .unwrap()
                .is_none()
        );
        drop(repository);
        cleanup_dpapi_import(&area.database, &credential_root, &request);
    }
}

#[test]
fn second_process_rotate_is_blocked_while_capture_owner_holds_bundle_boundary() {
    let auth = api_key_auth(b'P');
    let area = TempArea::new("dpapi-cross-process-owner", &auth);
    let credential_root = area.root.join("credentials");
    let source = controlled_source(area.codex_root.clone());
    let request = request(&source, 86);
    let mut capture = Command::new(env!("CARGO_BIN_EXE_m26-capture-import-crash"))
        .arg("crash")
        .arg(&area.codex_root)
        .arg(&area.database)
        .arg(&credential_root)
        .arg("before-bundle")
        .arg("86")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut ready = String::new();
    BufReader::new(capture.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert!(ready.starts_with("READY point="), "{ready}");

    let contender = Command::new(env!("CARGO_BIN_EXE_m26-capture-import-crash"))
        .arg("contend")
        .arg(&area.database)
        .arg(&credential_root)
        .arg(request.credential_id.as_str())
        .arg("rotate")
        .output()
        .unwrap();
    assert_eq!(contender.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(contender.stdout).unwrap().trim(),
        "CONTENDER_VERSION_CONFLICT"
    );
    capture.kill().unwrap();
    assert!(!capture.wait().unwrap().success());

    let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();
    assert!(matches!(
        CaptureImportService::new().capture_import(
            &source,
            &mut repository,
            &mut store,
            request.clone(),
        ),
        CaptureImportStatus::Imported(_) | CaptureImportStatus::AlreadyImported(_)
    ));
    assert_eq!(
        repository
            .get_credential_reference(&request.credential_id)
            .unwrap()
            .unwrap()
            .version(),
        codex_domain::EntityVersion::initial()
    );
    drop(repository);
    cleanup_dpapi_import(&area.database, &credential_root, &request);
}

#[test]
fn two_capture_processes_converge_without_rotation_or_orphans() {
    let auth = api_key_auth(b'2');
    let area = TempArea::new("two-capture-processes", &auth);
    let credential_root = area.root.join("credentials");
    let source = controlled_source(area.codex_root.clone());
    let request = request(&source, 96);
    let binary = env!("CARGO_BIN_EXE_m26-capture-import-crash");
    let spawn = || {
        Command::new(binary)
            .arg("import")
            .arg(&area.codex_root)
            .arg(&area.database)
            .arg(&credential_root)
            .arg("96")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    let first = spawn();
    let second = spawn();
    let first = first.wait_with_output().unwrap();
    let second = second.wait_with_output().unwrap();
    let outputs = [first, second];
    assert!(
        outputs.iter().any(|output| output.status.success()),
        "{} | {}",
        String::from_utf8_lossy(&outputs[0].stdout),
        String::from_utf8_lossy(&outputs[1].stdout)
    );
    assert!(outputs.iter().all(|output| {
        matches!(output.status.code(), Some(0 | 2 | 3 | 4))
            && !String::from_utf8_lossy(&output.stdout).contains("UNEXPECTED")
    }));

    let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();
    assert!(matches!(
        CaptureImportService::new().capture_import(
            &source,
            &mut repository,
            &mut store,
            request.clone(),
        ),
        CaptureImportStatus::Imported(_) | CaptureImportStatus::AlreadyImported(_)
    ));
    let reference = repository
        .get_credential_reference(&request.credential_id)
        .unwrap()
        .unwrap();
    assert_eq!(reference.version(), codex_domain::EntityVersion::initial());
    assert_eq!(
        reference.credential_fingerprint().as_str(),
        hash_bytes(&auth).as_str()
    );
    assert!(
        repository
            .list_credential_recoveries(&request.credential_id)
            .unwrap()
            .is_empty()
    );
    assert!(
        repository
            .get_capture_import_recovery(&format!(
                "capture-import:{}",
                request.identity_id.as_str()
            ))
            .unwrap()
            .is_none()
    );
    drop(repository);
    cleanup_dpapi_import(&area.database, &credential_root, &request);
}

#[test]
fn controlled_scan_fails_closed_while_switch_root_lock_is_held() {
    let auth = api_key_auth(b'6');
    let area = TempArea::new("switch-root-lock", &auth);
    let source = controlled_source(area.codex_root.clone());
    let _lock = CrossProcessWriteLock::try_acquire(
        &area.codex_root,
        UnixMillis::new(20_000).unwrap(),
    )
    .unwrap();

    assert!(matches!(
        source.scan(ControlledRoot::DefaultCodex),
        ControlledScanStatus::CompatibilityProtected(_)
    ));
}

#[test]
fn conflicted_capture_never_deletes_a_preexisting_exact_credential() {
    let auth = api_key_auth(b'7');
    let area = TempArea::new("preexisting-exact-rollback", &auth);
    let source = controlled_source(area.codex_root.clone());
    let request = request(&source, 97);
    let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
    let mut store = FakeCredentialStore::default();
    let mut preexisting = auth.clone();
    let original = CredentialService::new(&mut repository, &mut store)
        .capture_auth_document(
            request.credential_id.clone(),
            CredentialKind::ApiKey,
            &mut preexisting,
            request.now,
        )
        .unwrap();
    let other_reference = existing_credential(
        CredentialRefId::parse("97979797-9797-4797-8797-979797979797").unwrap(),
    );
    repository
        .create_credential_reference(&other_reference)
        .unwrap();
    let other_identity = RuntimeIdentity::new_draft(
        IdentityId::parse("98989898-9898-4898-8898-989898989898").unwrap(),
        EntityName::parse("既有冲突身份").unwrap(),
        ProviderId::parse("preexisting-conflict-provider").unwrap(),
        EntityName::parse("Preexisting Conflict Provider").unwrap(),
        EndpointUrl::parse("https://HOST/preexisting-conflict").unwrap(),
        None,
        other_reference.link(),
        UnixMillis::new(1).unwrap(),
    )
    .unwrap();
    repository.create_runtime_identity(&other_identity).unwrap();
    let mut fault = InsertPresetConflictFault {
        database: area.database.clone(),
        preset_id: request.preset_id.clone(),
        identity_id: other_identity.id().clone(),
        fired: false,
    };

    assert_eq!(
        CaptureImportService::new().capture_import_with_faults(
            &source,
            &mut repository,
            &mut store,
            request.clone(),
            &mut fault,
        ),
        CaptureImportStatus::RecoveryRequired(CaptureImportDiagnostic::InconsistentState)
    );
    assert_eq!(
        CaptureImportService::new().recover_capture_import(
            &mut repository,
            &mut store,
            &request.identity_id,
        ),
        CaptureImportStatus::Conflict
    );
    assert_eq!(
        repository
            .get_credential_reference(&request.credential_id)
            .unwrap(),
        Some(original)
    );
    assert_eq!(store.material(&request.credential_id), Some(auth.as_slice()));
    assert_eq!(store.delete_calls, 0);
}

#[test]
fn dpapi_reused_credential_rollback_reopen_and_rotation_never_delete_preexisting_material() {
    for (index, rotate_before_recovery) in [false, true].into_iter().enumerate() {
        let auth = api_key_auth(b'R' + u8::try_from(index).unwrap());
        let area = TempArea::new("dpapi-reused-rollback", &auth);
        let credential_root = area.root.join("credentials");
        let source = controlled_source(area.codex_root.clone());
        let request = request(&source, 100 + u8::try_from(index).unwrap());
        let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
        let mut store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();
        let mut preexisting = auth.clone();
        CredentialService::new(&mut repository, &mut store)
            .capture_auth_document(
                request.credential_id.clone(),
                CredentialKind::ApiKey,
                &mut preexisting,
                request.now,
            )
            .unwrap();
        let other_reference = existing_credential(
            CredentialRefId::parse(&format!(
                "a{index}a0a0a0-a0a0-4a0a-8a0a-a0a0a0a0a0a0"
            ))
            .unwrap(),
        );
        repository
            .create_credential_reference(&other_reference)
            .unwrap();
        let other_identity = RuntimeIdentity::new_draft(
            IdentityId::parse(&format!("b{index}b0b0b0-b0b0-4b0b-8b0b-b0b0b0b0b0b0")).unwrap(),
            EntityName::parse("DPAPI reuse conflict").unwrap(),
            ProviderId::parse("dpapi-reuse-conflict").unwrap(),
            EntityName::parse("DPAPI Reuse Conflict").unwrap(),
            EndpointUrl::parse("https://HOST/dpapi-reuse-conflict").unwrap(),
            None,
            other_reference.link(),
            UnixMillis::new(1).unwrap(),
        )
        .unwrap();
        repository.create_runtime_identity(&other_identity).unwrap();
        let mut fault = InsertPresetConflictFault {
            database: area.database.clone(),
            preset_id: request.preset_id.clone(),
            identity_id: other_identity.id().clone(),
            fired: false,
        };
        assert_eq!(
            CaptureImportService::new().capture_import_with_faults(
                &source,
                &mut repository,
                &mut store,
                request.clone(),
                &mut fault,
            ),
            CaptureImportStatus::RecoveryRequired(CaptureImportDiagnostic::InconsistentState)
        );
        if rotate_before_recovery {
            let mut replacement = Vec::from(&b"sk-"[..]);
            replacement.extend((0..40).map(|offset| b'Z' - (offset % 26)));
            CredentialService::new(&mut repository, &mut store)
                .rotate_credential(
                    &request.credential_id,
                    codex_domain::EntityVersion::initial(),
                    &mut replacement,
                    UnixMillis::new(request.now.value() + 1).unwrap(),
                )
                .unwrap();
        }
        drop(repository);
        drop(store);
        let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
        let mut store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();
        let status = CaptureImportService::new().recover_capture_import(
            &mut repository,
            &mut store,
            &request.identity_id,
        );
        assert_eq!(
            status,
            if rotate_before_recovery {
                CaptureImportStatus::RecoveryRequired(CaptureImportDiagnostic::InconsistentState)
            } else {
                CaptureImportStatus::Conflict
            }
        );
        let reference = repository
            .get_credential_reference(&request.credential_id)
            .unwrap()
            .unwrap();
        assert_eq!(reference.version().value(), if rotate_before_recovery { 2 } else { 1 });
    }
}

#[test]
fn capture_schema_rejects_unknown_trigger_without_removing_v11_ledger() {
    for (index, sql) in [
        "CREATE TRIGGER capture_insert AFTER INSERT ON capture_import_operations BEGIN DELETE FROM capture_import_operations WHERE operation_id=NEW.operation_id; END;",
        "CREATE TRIGGER capture_update AFTER UPDATE ON capture_import_operations BEGIN DELETE FROM capture_import_operations WHERE operation_id=NEW.operation_id; END;",
        "CREATE TRIGGER capture_delete AFTER DELETE ON capture_import_operations BEGIN SELECT 1; END;",
        "CREATE INDEX capture_extra_index ON capture_import_operations(identity_id, phase);",
        "CREATE VIEW capture_import_view AS SELECT operation_id FROM capture_import_operations;",
    ]
    .into_iter()
    .enumerate()
    {
        let auth = api_key_auth(b'8' + u8::try_from(index).unwrap());
        let area = TempArea::new("capture-object-audit", &auth);
        SqliteMetadataRepository::open(&area.database).unwrap();
        let connection = rusqlite::Connection::open(&area.database).unwrap();
        connection.execute_batch(sql).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM schema_migrations WHERE version=11",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        drop(connection);
        assert!(matches!(
            SqliteMetadataRepository::open(&area.database),
            Err(OpenRepositoryError::CorruptData)
        ));
    }
}

#[test]
fn captured_api_key_rotation_remains_an_auth_document_for_vertical_consumers() {
    let auth = api_key_auth(b'9');
    let area = TempArea::new("capture-rotate-format", &auth);
    let source = controlled_source(area.codex_root.clone());
    let request = request(&source, 99);
    let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
    let mut store = FakeCredentialStore::default();
    assert_eq!(
        CaptureImportService::new().capture_import(
            &source,
            &mut repository,
            &mut store,
            request.clone(),
        ),
        CaptureImportStatus::Imported(request.identity_id.clone())
    );
    let mut replacement = Vec::from(&b"sk-"[..]);
    replacement.extend((0..40).map(|index| b'Z' - (index % 26)));
    let rotated = CredentialService::new(&mut repository, &mut store)
        .rotate_credential(
            &request.credential_id,
            codex_domain::EntityVersion::initial(),
            &mut replacement,
            UnixMillis::new(request.now.value() + 1).unwrap(),
        )
        .unwrap();
    let material = store.material(&request.credential_id).unwrap();
    assert!(matches!(
        codex_adapter::CodexAdapter::new().scan_memory(config(), material),
        codex_application::ScanStatus::Ready(actual)
            if actual.authentication.auth_mode == codex_domain::AuthMode::ApiKey
                && actual.authentication.credential_fingerprint
                    == *rotated.credential_fingerprint()
    ));
}
