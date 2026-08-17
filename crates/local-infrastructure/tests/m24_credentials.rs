#![allow(unused_crate_dependencies)]

use std::{
    fs,
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use codex_adapter::hash_bytes;
use codex_application::{
    CredentialEnvelopeBinding, CredentialMaterialDiagnostic, CredentialMutationOwner,
    CredentialRecoveryOperation, CredentialRecoveryPhase, CredentialRecoveryRecord,
    CredentialRecoveryRepository, CredentialReferenceRepository, CredentialStore,
    CredentialStoreError, RepositoryError, RuntimeIdentityRepository, SecretConsumer,
};
use codex_domain::{
    CredentialKind, CredentialRefId, EndpointUrl, EntityName, EntityVersion, IdentityId,
    ProviderId, RuntimeIdentity, SchemaFingerprint, UnixMillis,
};
use local_infrastructure::{
    CredentialService, CredentialServiceError, SqliteMetadataRepository,
    credential_material_schema_fingerprint,
};
use windows_platform::WindowsDpapiCredentialStore;

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

struct TempArea {
    root: PathBuf,
}
impl TempArea {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "codextools-m24-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        Self { root }
    }
}
impl Drop for TempArea {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct HashConsumer {
    hash: Option<codex_domain::ContentHash>,
    length: usize,
}

struct PanickingConsumer;
impl SecretConsumer for PanickingConsumer {
    fn consume(&mut self, _: &[u8]) -> Result<(), CredentialStoreError> {
        panic!("SAMPLE consumer panic")
    }
}
impl SecretConsumer for HashConsumer {
    fn consume(&mut self, secret: &[u8]) -> Result<(), CredentialStoreError> {
        self.hash = Some(hash_bytes(secret));
        self.length = secret.len();
        Ok(())
    }
}

fn binding(
    id: &str,
    kind: CredentialKind,
    schema: char,
    version: u64,
) -> CredentialEnvelopeBinding {
    CredentialEnvelopeBinding::new(
        CredentialRefId::parse(id).unwrap(),
        kind,
        SchemaFingerprint::parse(&schema.to_string().repeat(64)).unwrap(),
        EntityVersion::new(version).unwrap(),
    )
}

fn runtime_secret() -> Vec<u8> {
    let mut value = Vec::from(&b"sk-"[..]);
    value.extend((0..40).map(|index| b'A' + (index % 26)));
    value
}

fn api_key_document(secret: &[u8]) -> Vec<u8> {
    let mut document = Vec::from(&b"{\"OPENAI_API_KEY\":\""[..]);
    document.extend_from_slice(secret);
    document.extend_from_slice(b"\"}\n");
    document
}

struct PausingReadStore {
    inner: WindowsDpapiCredentialStore,
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
}
impl CredentialStore for PausingReadStore {
    fn begin_mutation(
        &mut self,
        id: &CredentialRefId,
    ) -> Result<CredentialMutationOwner, CredentialStoreError> {
        self.inner.begin_mutation(id)
    }
    fn end_mutation(&mut self, owner: CredentialMutationOwner) -> Result<(), CredentialStoreError> {
        self.inner.end_mutation(owner)
    }
    fn planned_material_ref(
        &self,
        binding: &CredentialEnvelopeBinding,
    ) -> Result<PathBuf, CredentialStoreError> {
        self.inner.planned_material_ref(binding)
    }
    fn create(
        &mut self,
        binding: &CredentialEnvelopeBinding,
        secret: &mut [u8],
    ) -> Result<(), CredentialStoreError> {
        self.inner.create(binding, secret)
    }
    fn read(
        &self,
        binding: &CredentialEnvelopeBinding,
        consumer: &mut dyn SecretConsumer,
    ) -> Result<(), CredentialStoreError> {
        self.entered.wait();
        self.release.wait();
        self.inner.read(binding, consumer)
    }
    fn rotate(
        &mut self,
        previous: &CredentialEnvelopeBinding,
        next: &CredentialEnvelopeBinding,
        secret: &mut [u8],
    ) -> Result<(), CredentialStoreError> {
        self.inner.rotate(previous, next, secret)
    }
    fn delete(&mut self, binding: &CredentialEnvelopeBinding) -> Result<(), CredentialStoreError> {
        self.inner.delete(binding)
    }
    fn inspect(
        &self,
        binding: &CredentialEnvelopeBinding,
    ) -> Result<CredentialMaterialDiagnostic, CredentialStoreError> {
        self.inner.inspect(binding)
    }
    fn rollback_rotation(
        &mut self,
        previous: &CredentialEnvelopeBinding,
        next: &CredentialEnvelopeBinding,
    ) -> Result<(), CredentialStoreError> {
        self.inner.rollback_rotation(previous, next)
    }
}

struct RotationOrderingConsumer {
    rotation_complete: Arc<AtomicBool>,
    consumed_after_rotation: bool,
}
impl SecretConsumer for RotationOrderingConsumer {
    fn consume(&mut self, _secret: &[u8]) -> Result<(), CredentialStoreError> {
        self.consumed_after_rotation = self.rotation_complete.load(Ordering::SeqCst);
        Ok(())
    }
}

#[test]
fn read_for_switch_holds_owner_across_metadata_and_defers_consumer_until_freshness_proven() {
    let area = TempArea::new("read-rotate-ordering");
    let database = area.root.join("metadata.sqlite3");
    let credential_root = area.root.join("credentials");
    let id = CredentialRefId::parse("12121212-1212-4212-8212-121212121212").unwrap();
    let first = {
        let mut repository = SqliteMetadataRepository::open(&database).unwrap();
        let mut store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();
        CredentialService::new(&mut repository, &mut store)
            .create_api_key(
                id.clone(),
                &mut runtime_secret(),
                UnixMillis::new(1).unwrap(),
            )
            .unwrap()
    };

    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let rotation_complete = Arc::new(AtomicBool::new(false));
    let first_version = first.version();
    let reader = {
        let database = database.clone();
        let credential_root = credential_root.clone();
        let id = id.clone();
        let entered = Arc::clone(&entered);
        let release = Arc::clone(&release);
        let rotation_complete = Arc::clone(&rotation_complete);
        thread::spawn(move || {
            let mut repository = SqliteMetadataRepository::open(database).unwrap();
            let mut store = PausingReadStore {
                inner: WindowsDpapiCredentialStore::new(credential_root).unwrap(),
                entered,
                release,
            };
            let mut consumer = RotationOrderingConsumer {
                rotation_complete,
                consumed_after_rotation: false,
            };
            let result = CredentialService::new(&mut repository, &mut store)
                .read_for_switch(&id, &mut consumer);
            (result, consumer.consumed_after_rotation)
        })
    };
    entered.wait();
    let (rotated_tx, rotated_rx) = mpsc::channel();
    let rotator = {
        let database = database.clone();
        let credential_root = credential_root.clone();
        let id = id.clone();
        let rotation_complete = Arc::clone(&rotation_complete);
        thread::spawn(move || {
            let mut repository = SqliteMetadataRepository::open(database).unwrap();
            let mut store = WindowsDpapiCredentialStore::new(credential_root).unwrap();
            let mut next_secret = runtime_secret();
            next_secret.push(b'Z');
            let result = CredentialService::new(&mut repository, &mut store).rotate_credential(
                &id,
                first_version,
                &mut next_secret,
                UnixMillis::new(2).unwrap(),
            );
            if result.is_ok() {
                rotation_complete.store(true, Ordering::SeqCst);
            }
            let _ = rotated_tx.send(result);
        })
    };
    let rotated_early = rotated_rx
        .recv_timeout(std::time::Duration::from_millis(250))
        .ok();
    let completed_before_release = rotated_early.as_ref().is_some_and(Result::is_ok);
    release.wait();
    let (read_result, consumed_after_rotation) = reader.join().unwrap();
    let initial_rotate_result = rotated_early.or_else(|| rotated_rx.recv().ok()).unwrap();
    rotator.join().unwrap();

    assert!(read_result.is_ok());
    assert!(!completed_before_release);
    assert!(!consumed_after_rotation);
    if initial_rotate_result.is_err() {
        let mut repository = SqliteMetadataRepository::open(&database).unwrap();
        let mut store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();
        let mut retry_secret = runtime_secret();
        retry_secret.push(b'Z');
        CredentialService::new(&mut repository, &mut store)
            .rotate_credential(
                &id,
                first_version,
                &mut retry_secret,
                UnixMillis::new(2).unwrap(),
            )
            .unwrap();
    }
    println!(
        "M24_CREDENTIAL_READ_ORDER metadata_v1_pause=true rotate_blocked_by_owner=true stale_consumer=false metadata_exact_reread=true"
    );
}

#[test]
fn read_consumer_panic_releases_owner_before_resuming_unwind() {
    let area = TempArea::new("read-consumer-panic");
    let database = area.root.join("metadata.sqlite3");
    let credential_root = area.root.join("credentials");
    let id = CredentialRefId::parse("21212121-2121-4121-8121-212121212121").unwrap();
    let mut repository = SqliteMetadataRepository::open(&database).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();
    CredentialService::new(&mut repository, &mut store)
        .create_api_key(
            id.clone(),
            &mut runtime_secret(),
            UnixMillis::new(1).unwrap(),
        )
        .unwrap();
    let panic = catch_unwind(AssertUnwindSafe(|| {
        CredentialService::new(&mut repository, &mut store)
            .read_for_switch(&id, &mut PanickingConsumer)
            .unwrap();
    }));
    assert!(panic.is_err());
    let mut consumer = HashConsumer {
        hash: None,
        length: 0,
    };
    CredentialService::new(&mut repository, &mut store)
        .read_for_switch(&id, &mut consumer)
        .unwrap();
    assert!(consumer.hash.is_some());
    println!("M24_CREDENTIAL_READ_PANIC owner_released=true buffered_secret_zeroized=true");
}

#[test]
fn dpapi_current_user_round_trip_and_binding_fail_closed() {
    let area = TempArea::new("dpapi");
    let mut store = WindowsDpapiCredentialStore::new(area.root.join("credentials")).unwrap();
    let first = binding(
        "11111111-1111-4111-8111-111111111111",
        CredentialKind::ApiKey,
        'a',
        1,
    );
    let mut secret = runtime_secret();
    let expected_hash = hash_bytes(&secret);
    let marker = secret.clone();
    store.create(&first, &mut secret).unwrap();
    assert!(secret.iter().all(|byte| *byte == 0));
    let envelope = fs::read(store.material_path(&first)).unwrap();
    assert!(
        !envelope
            .windows(marker.len())
            .any(|window| window == marker)
    );
    let mut consumer = HashConsumer {
        hash: None,
        length: 0,
    };
    store.read(&first, &mut consumer).unwrap();
    assert_eq!(consumer.hash, Some(expected_hash));
    let mut duplicate = runtime_secret();
    assert_eq!(
        store.create(&first, &mut duplicate),
        Err(CredentialStoreError::AlreadyExists)
    );
    assert!(duplicate.iter().all(|byte| *byte == 0));

    let wrong_kind = binding(
        "11111111-1111-4111-8111-111111111111",
        CredentialKind::OAuthBundle,
        'a',
        1,
    );
    assert_eq!(
        store.read(&wrong_kind, &mut consumer),
        Err(CredentialStoreError::BindingMismatch)
    );
    let wrong_schema = binding(
        "11111111-1111-4111-8111-111111111111",
        CredentialKind::ApiKey,
        'b',
        1,
    );
    assert_eq!(
        store.read(&wrong_schema, &mut consumer),
        Err(CredentialStoreError::BindingMismatch)
    );

    let next = binding(
        "11111111-1111-4111-8111-111111111111",
        CredentialKind::ApiKey,
        'a',
        2,
    );
    store.rotate(&first, &next, &mut runtime_secret()).unwrap();
    let mut concurrent = runtime_secret();
    assert_eq!(
        store.rotate(&first, &next, &mut concurrent),
        Err(CredentialStoreError::VersionConflict)
    );
    assert!(concurrent.iter().all(|byte| *byte == 0));
    let generation_three = binding(
        "11111111-1111-4111-8111-111111111111",
        CredentialKind::ApiKey,
        'a',
        3,
    );
    fs::copy(
        store.material_path(&next),
        store.material_path(&generation_three),
    )
    .unwrap();
    assert_eq!(
        store.read(&generation_three, &mut consumer),
        Err(CredentialStoreError::BindingMismatch)
    );

    let second = binding(
        "22222222-2222-4222-8222-222222222222",
        CredentialKind::ApiKey,
        'b',
        1,
    );
    store.create(&second, &mut runtime_secret()).unwrap();
    let second_envelope = fs::read(store.material_path(&second)).unwrap();
    fs::copy(store.material_path(&first), store.material_path(&second)).unwrap();
    assert_eq!(
        store.read(&second, &mut consumer),
        Err(CredentialStoreError::BindingMismatch)
    );
    fs::write(store.material_path(&second), second_envelope).unwrap();

    let mut damaged = fs::read(store.material_path(&first)).unwrap();
    let last = damaged.last_mut().unwrap();
    *last ^= 0x5a;
    fs::write(store.material_path(&first), damaged).unwrap();
    assert_eq!(
        store.read(&first, &mut consumer),
        Err(CredentialStoreError::ProtectionFailed)
    );

    let oauth = binding(
        "77777777-7777-4777-8777-777777777777",
        CredentialKind::OAuthBundle,
        'c',
        1,
    );
    let mut oauth_material = br#"{"tokens":{"id_token":"TOKEN","access_token":"TOKEN","refresh_token":"TOKEN","account_id":"ACCOUNT"}}"#.to_vec();
    let oauth_hash = hash_bytes(&oauth_material);
    store.create(&oauth, &mut oauth_material).unwrap();
    store.read(&oauth, &mut consumer).unwrap();
    assert_eq!(consumer.hash, Some(oauth_hash));
    let oauth_next = binding(
        "77777777-7777-4777-8777-777777777777",
        CredentialKind::OAuthBundle,
        'c',
        2,
    );
    let mut oauth_rotated = br#"{"tokens":{"id_token":"TOKEN","access_token":"TOKEN","refresh_token":"TOKEN","account_id":"ACCOUNT-2"}}"#.to_vec();
    let oauth_rotated_hash = hash_bytes(&oauth_rotated);
    store
        .rotate(&oauth, &oauth_next, &mut oauth_rotated)
        .unwrap();
    store.read(&oauth_next, &mut consumer).unwrap();
    assert_eq!(consumer.hash, Some(oauth_rotated_hash));
    store.delete(&oauth_next).unwrap();
    store.delete(&second).unwrap();
    assert_eq!(store.delete(&second), Err(CredentialStoreError::NotFound));
    println!(
        "M24_DPAPI current_user_round_trip=true api_key=true oauth_bundle=true plaintext_in_envelope=false id_kind_schema_generation_binding=rejected corruption=rejected concurrent_rotate=rejected"
    );
}

#[test]
fn credential_mutations_validate_current_envelope_binding_and_serialize() {
    let area = TempArea::new("credential-binding-mutations");
    let root = area.root.join("credentials");
    let id = "88888888-8888-4888-8888-888888888888";
    let first = binding(id, CredentialKind::ApiKey, 'a', 1);
    let mut store = WindowsDpapiCredentialStore::new(&root).unwrap();
    store.create(&first, &mut runtime_secret()).unwrap();

    let wrong_kind = binding(id, CredentialKind::OAuthBundle, 'a', 1);
    assert_eq!(
        store.delete(&wrong_kind),
        Err(CredentialStoreError::BindingMismatch)
    );
    assert!(store.material_path(&first).is_file());
    let wrong_schema = binding(id, CredentialKind::ApiKey, 'b', 1);
    assert_eq!(
        store.delete(&wrong_schema),
        Err(CredentialStoreError::BindingMismatch)
    );
    assert!(store.material_path(&first).is_file());

    let wrong_schema_next = binding(id, CredentialKind::ApiKey, 'b', 2);
    let mut replacement = runtime_secret();
    assert_eq!(
        store.rotate(&wrong_schema, &wrong_schema_next, &mut replacement),
        Err(CredentialStoreError::BindingMismatch)
    );
    assert!(replacement.iter().all(|byte| *byte == 0));
    assert!(!store.material_path(&wrong_schema_next).exists());

    let original_envelope = fs::read(store.material_path(&first)).unwrap();
    let mut replacement = runtime_secret();
    assert_eq!(
        store.rotate(&first, &wrong_schema_next, &mut replacement),
        Err(CredentialStoreError::BindingMismatch)
    );
    assert!(replacement.iter().all(|byte| *byte == 0));
    assert_eq!(
        fs::read(store.material_path(&first)).unwrap(),
        original_envelope
    );
    assert!(!store.material_path(&wrong_schema_next).exists());

    let mut damaged = fs::read(store.material_path(&first)).unwrap();
    *damaged.last_mut().unwrap() ^= 0x33;
    fs::write(store.material_path(&first), &damaged).unwrap();
    let next = binding(id, CredentialKind::ApiKey, 'a', 2);
    let mut replacement = runtime_secret();
    assert_eq!(
        store.rotate(&first, &next, &mut replacement),
        Err(CredentialStoreError::ProtectionFailed)
    );
    assert!(replacement.iter().all(|byte| *byte == 0));
    assert!(!store.material_path(&next).exists());

    fs::remove_dir_all(root.join(id)).unwrap();
    store.create(&first, &mut runtime_secret()).unwrap();
    store.rotate(&first, &next, &mut runtime_secret()).unwrap();
    assert_eq!(
        store.delete(&first),
        Err(CredentialStoreError::VersionConflict)
    );
    assert!(store.material_path(&next).is_file());

    let concurrent_id = "99999999-9999-4999-8999-999999999999";
    let concurrent_first = binding(concurrent_id, CredentialKind::ApiKey, 'c', 1);
    let concurrent_next = binding(concurrent_id, CredentialKind::ApiKey, 'c', 2);
    store
        .create(&concurrent_first, &mut runtime_secret())
        .unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let rotate_root = root.clone();
    let rotate_barrier = Arc::clone(&barrier);
    let rotate_previous = concurrent_first.clone();
    let rotate_next = concurrent_next.clone();
    let rotate = thread::spawn(move || {
        let mut store = WindowsDpapiCredentialStore::new(rotate_root).unwrap();
        let mut secret = runtime_secret();
        rotate_barrier.wait();
        store.rotate(&rotate_previous, &rotate_next, &mut secret)
    });
    let delete_root = root.clone();
    let delete_barrier = Arc::clone(&barrier);
    let delete_binding = concurrent_first.clone();
    let delete = thread::spawn(move || {
        let mut store = WindowsDpapiCredentialStore::new(delete_root).unwrap();
        delete_barrier.wait();
        store.delete(&delete_binding)
    });
    let rotate_result = rotate.join().unwrap();
    let delete_result = delete.join().unwrap();
    assert_ne!(rotate_result.is_ok(), delete_result.is_ok());
    assert!(
        !(root.join(concurrent_id).exists()
            && !store.material_path(&concurrent_next).is_file()
            && !store.material_path(&concurrent_first).is_file())
    );
    println!(
        "M24_CREDENTIAL_BINDING wrong_kind_delete=rejected wrong_schema_delete=rejected wrong_schema_rotate=rejected corrupt_previous_rotate=rejected stale_delete=rejected concurrent_rotate_delete=serialized"
    );
}

#[test]
fn credential_quarantine_reopen_reconcile_is_idempotent() {
    let area = TempArea::new("credential-quarantine-recovery");
    let root = area.root.join("credentials");
    let id = "89898989-8989-4989-8989-898989898989";
    let first = binding(id, CredentialKind::ApiKey, 'a', 1);
    let next = binding(id, CredentialKind::ApiKey, 'a', 2);
    let mut store = WindowsDpapiCredentialStore::new(&root).unwrap();
    store.create(&first, &mut runtime_secret()).unwrap();
    store.rotate(&first, &next, &mut runtime_secret()).unwrap();

    let next_path = store.material_path(&next);
    let rollback_quarantine = next_path.with_file_name(".rollback-generation-2");
    fs::rename(&next_path, &rollback_quarantine).unwrap();
    #[cfg(windows)]
    let held = fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&rollback_quarantine)
        .unwrap();
    #[cfg(windows)]
    assert_eq!(
        store.rollback_rotation(&first, &next),
        Err(CredentialStoreError::RecoveryRequired)
    );
    #[cfg(windows)]
    drop(held);
    drop(store);
    let mut store = WindowsDpapiCredentialStore::new(&root).unwrap();
    let wrong_previous = binding(id, CredentialKind::ApiKey, 'b', 1);
    let wrong_next = binding(id, CredentialKind::ApiKey, 'b', 2);
    assert_eq!(
        store.rollback_rotation(&wrong_previous, &wrong_next),
        Err(CredentialStoreError::BindingMismatch)
    );
    assert!(rollback_quarantine.exists());
    store.rollback_rotation(&first, &next).unwrap();
    assert!(!rollback_quarantine.exists());
    store.rollback_rotation(&first, &next).unwrap();

    let directory = root.join(id);
    let delete_quarantine = root.join(format!(".delete-{id}-generation-1"));
    fs::rename(&directory, &delete_quarantine).unwrap();
    #[cfg(windows)]
    let held = fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(delete_quarantine.join("generation-1.dpapi"))
        .unwrap();
    #[cfg(windows)]
    assert_eq!(
        store.delete(&first),
        Err(CredentialStoreError::RecoveryRequired)
    );
    #[cfg(windows)]
    drop(held);
    drop(store);
    let mut store = WindowsDpapiCredentialStore::new(&root).unwrap();
    let wrong_delete = binding(id, CredentialKind::ApiKey, 'b', 1);
    assert_eq!(
        store.delete(&wrong_delete),
        Err(CredentialStoreError::BindingMismatch)
    );
    assert!(delete_quarantine.exists());
    store.delete(&first).unwrap();
    assert!(!delete_quarantine.exists());
    assert!(!directory.exists());
    println!(
        "M24_CREDENTIAL_QUARANTINE rollback_rename_interrupt=reconciled rollback_after_physical_delete=idempotent delete_rename_interrupt=reconciled quarantine_binding=verified physical_delete_failure=retry_converged orphan=0"
    );
}

fn create_delete_quarantine_recovery(
    database: &Path,
    credential_root: &Path,
    id_text: &str,
    operation_id: &str,
) -> (CredentialRecoveryRecord, CredentialEnvelopeBinding) {
    let id = CredentialRefId::parse(id_text).unwrap();
    let mut repository = SqliteMetadataRepository::open(database).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(credential_root).unwrap();
    let reference = CredentialService::new(&mut repository, &mut store)
        .create_api_key(
            id.clone(),
            &mut runtime_secret(),
            UnixMillis::new(10).unwrap(),
        )
        .unwrap();
    let binding = CredentialEnvelopeBinding::new(
        id.clone(),
        reference.kind(),
        reference.schema_fingerprint().clone(),
        reference.version(),
    );
    let material = store.inspect(&binding).unwrap();
    let record = CredentialRecoveryRecord {
        operation_id: operation_id.to_owned(),
        credential_id: id.clone(),
        kind: reference.kind(),
        operation: CredentialRecoveryOperation::Delete,
        generation: reference.version(),
        planned_credential_fingerprint: Some(reference.credential_fingerprint().clone()),
        material_ref: material.material_ref,
        material_hash: Some(material.material_hash),
        phase: CredentialRecoveryPhase::RecoveryRequired,
        diagnostic_code: Some("delete_quarantine_pending".to_owned()),
        credential_created_at: reference.created_at(),
        credential_updated_at: reference.updated_at(),
        created_at: UnixMillis::new(10).unwrap(),
        updated_at: UnixMillis::new(11).unwrap(),
        version: EntityVersion::initial(),
    };
    repository.create_credential_recovery(&record).unwrap();
    repository
        .delete_credential_reference(&id, reference.version())
        .unwrap();
    let directory = credential_root.join(id.as_str());
    let quarantine = credential_root.join(format!(
        ".delete-{}-generation-{}",
        id.as_str(),
        reference.version().value()
    ));
    fs::rename(directory, quarantine).unwrap();
    (record, binding)
}

#[test]
fn delete_quarantine_service_recovery_adopt_rollback_cleanup_are_bound_and_idempotent() {
    let area = TempArea::new("delete-quarantine-service-recovery");
    let database = area.root.join("metadata.sqlite3");
    let credential_root = area.root.join("credentials");

    let (mut adopt_record, _) = create_delete_quarantine_recovery(
        &database,
        &credential_root,
        "13131313-1313-4313-8313-131313131313",
        "delete-adopt",
    );
    {
        let mut owner_store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();
        let owner = owner_store
            .begin_mutation(&adopt_record.credential_id)
            .unwrap();
        let mut contender_repository = SqliteMetadataRepository::open(&database).unwrap();
        let before = contender_repository
            .get_credential_recovery("delete-adopt")
            .unwrap()
            .unwrap();
        let mut contender_store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();
        assert_eq!(
            CredentialService::new(&mut contender_repository, &mut contender_store)
                .adopt_recovery("delete-adopt", UnixMillis::new(11).unwrap()),
            Err(CredentialServiceError::VersionConflict)
        );
        assert_eq!(
            contender_repository
                .get_credential_recovery("delete-adopt")
                .unwrap()
                .unwrap(),
            before
        );
        owner_store.end_mutation(owner).unwrap();
    }
    {
        let store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();
        let wrong_binding = binding(
            adopt_record.credential_id.as_str(),
            adopt_record.kind,
            'b',
            adopt_record.generation.value(),
        );
        assert_eq!(
            store.inspect_delete_recovery(&wrong_binding),
            Err(CredentialStoreError::BindingMismatch)
        );
    }
    let correct_hash = adopt_record.material_hash.clone();
    let previous = adopt_record.version;
    adopt_record.material_hash = Some(hash_bytes(b"SAMPLE-WRONG-HASH"));
    adopt_record.version = previous.next().unwrap();
    {
        let mut repository = SqliteMetadataRepository::open(&database).unwrap();
        repository
            .update_credential_recovery(&adopt_record, previous)
            .unwrap();
        let mut store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();
        assert_eq!(
            CredentialService::new(&mut repository, &mut store)
                .adopt_recovery("delete-adopt", UnixMillis::new(12).unwrap()),
            Err(CredentialServiceError::RecoveryRequired)
        );
    }
    let wrong_version = adopt_record.version;
    adopt_record.material_hash = correct_hash;
    adopt_record.version = wrong_version.next().unwrap();
    {
        let mut repository = SqliteMetadataRepository::open(&database).unwrap();
        repository
            .update_credential_recovery(&adopt_record, wrong_version)
            .unwrap();
        let mut store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();
        let restored = CredentialService::new(&mut repository, &mut store)
            .adopt_recovery("delete-adopt", UnixMillis::new(13).unwrap())
            .unwrap();
        assert_eq!(restored.id(), &adopt_record.credential_id);
        assert!(
            repository
                .get_credential_recovery("delete-adopt")
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .material_path(&CredentialEnvelopeBinding::new(
                    restored.id().clone(),
                    restored.kind(),
                    restored.schema_fingerprint().clone(),
                    restored.version(),
                ))
                .is_file()
        );
    }

    let (rollback_record, _) = create_delete_quarantine_recovery(
        &database,
        &credential_root,
        "14141414-1414-4414-8414-141414141414",
        "delete-rollback",
    );
    {
        let mut repository = SqliteMetadataRepository::open(&database).unwrap();
        let mut store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();
        CredentialService::new(&mut repository, &mut store)
            .rollback_recovery("delete-rollback", UnixMillis::new(14).unwrap())
            .unwrap();
        assert!(
            repository
                .get_credential_reference(&rollback_record.credential_id)
                .unwrap()
                .is_some()
        );
        assert!(
            repository
                .get_credential_recovery("delete-rollback")
                .unwrap()
                .is_none()
        );
    }

    let (cleanup_record, _) = create_delete_quarantine_recovery(
        &database,
        &credential_root,
        "15151515-1515-4515-8515-151515151515",
        "delete-cleanup",
    );
    {
        let mut repository = SqliteMetadataRepository::open(&database).unwrap();
        let mut store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();
        CredentialService::new(&mut repository, &mut store)
            .cleanup_recovery("delete-cleanup")
            .unwrap();
        assert!(
            repository
                .get_credential_reference(&cleanup_record.credential_id)
                .unwrap()
                .is_none()
        );
        assert!(
            repository
                .get_credential_recovery("delete-cleanup")
                .unwrap()
                .is_none()
        );
    }
    let (completed_record, completed_binding) = create_delete_quarantine_recovery(
        &database,
        &credential_root,
        "16161616-1616-4616-8616-161616161616",
        "delete-completed-before-journal-clear",
    );
    {
        let mut store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();
        store.delete(&completed_binding).unwrap();
        let mut repository = SqliteMetadataRepository::open(&database).unwrap();
        CredentialService::new(&mut repository, &mut store)
            .cleanup_recovery("delete-completed-before-journal-clear")
            .unwrap();
        assert!(
            repository
                .get_credential_reference(&completed_record.credential_id)
                .unwrap()
                .is_none()
        );
        assert!(
            repository
                .get_credential_recovery("delete-completed-before-journal-clear")
                .unwrap()
                .is_none()
        );
    }
    println!(
        "M24_CREDENTIAL_DELETE_RECOVERY owner_held_contender=rejected shared_intent_unchanged=true wrong_binding=rejected wrong_hash=rejected adopt=restored rollback=restored cleanup=deleted physical_delete_journal=idempotent orphan=0"
    );
}

#[test]
fn credential_store_bounds_envelopes_and_rejects_reparse_material_paths() {
    let area = TempArea::new("credential-path-hardening");
    let root = area.root.join("credentials");
    let mut store = WindowsDpapiCredentialStore::new(&root).unwrap();
    let id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    let first = binding(id, CredentialKind::ApiKey, 'a', 1);
    store.create(&first, &mut runtime_secret()).unwrap();
    let material = store.material_path(&first);
    let mut oversized = fs::read(&material).unwrap();
    oversized.extend(std::iter::repeat_n(b'X', 1024 * 1024 + 65537));
    fs::write(&material, oversized).unwrap();
    let mut consumer = HashConsumer {
        hash: None,
        length: 0,
    };
    assert_eq!(
        store.read(&first, &mut consumer),
        Err(CredentialStoreError::CorruptEnvelope)
    );

    let stage_residue = fs::read_dir(root.join(id))
        .unwrap()
        .filter_map(Result::ok)
        .any(|entry| entry.file_name().to_string_lossy().ends_with(".stage"));
    assert!(!stage_residue);

    let stage_binding = binding(
        "abababab-abab-4bab-8bab-abababababab",
        CredentialKind::ApiKey,
        'a',
        1,
    );
    store.create(&stage_binding, &mut runtime_secret()).unwrap();
    let stage_path = root
        .join(stage_binding.id().as_str())
        .join(".generation-1-reopen.stage");
    fs::write(&stage_path, b"stage-residue").unwrap();
    #[cfg(windows)]
    let held_stage = fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&stage_path)
        .unwrap();
    #[cfg(windows)]
    assert_eq!(
        store.inspect(&stage_binding),
        Err(CredentialStoreError::RecoveryRequired)
    );
    #[cfg(windows)]
    drop(held_stage);
    store.inspect(&stage_binding).unwrap();
    assert!(!stage_path.exists());

    let linked_root = area.root.join("linked-credential-root");
    let root_target = area.root.join("root-target");
    fs::create_dir(&root_target).unwrap();
    create_junction(&linked_root, &root_target);
    assert!(matches!(
        WindowsDpapiCredentialStore::new(&linked_root),
        Err(CredentialStoreError::IoFailure)
    ));
    fs::remove_dir(&linked_root).unwrap();
    assert!(root_target.is_dir());

    let junction_id = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
    let junction_binding = binding(junction_id, CredentialKind::ApiKey, 'e', 1);
    let material_target = area.root.join("material-target");
    fs::create_dir(&material_target).unwrap();
    let junction = root.join(junction_id);
    create_junction(&junction, &material_target);
    let mut secret = runtime_secret();
    assert_eq!(
        store.create(&junction_binding, &mut secret),
        Err(CredentialStoreError::IoFailure)
    );
    assert!(secret.iter().all(|byte| *byte == 0));
    assert!(fs::read_dir(&material_target).unwrap().next().is_none());
    fs::remove_dir(&junction).unwrap();
    assert!(material_target.is_dir());

    let delete_id = "ffffffff-ffff-4fff-8fff-ffffffffffff";
    let delete_binding = binding(delete_id, CredentialKind::ApiKey, 'f', 1);
    store
        .create(&delete_binding, &mut runtime_secret())
        .unwrap();
    let external_target = area.root.join("external-delete-target");
    fs::create_dir(&external_target).unwrap();
    fs::write(external_target.join("sentinel.txt"), b"SAMPLE").unwrap();
    create_junction(
        &root.join(delete_id).join(".external-junction"),
        &external_target,
    );
    store.delete(&delete_binding).unwrap();
    assert_eq!(
        fs::read(external_target.join("sentinel.txt")).unwrap(),
        b"SAMPLE"
    );
    println!(
        "M24_CREDENTIAL_PATH envelope_read_bounded=true unique_stage_cleanup=true stage_cleanup_reopen=scavenged root_junction=rejected credential_junction=rejected internal_junction_target=preserved delete_containment=canonical_root"
    );
}

#[cfg(windows)]
fn create_junction(link: &Path, target: &Path) {
    let status = Command::new("cmd")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .status()
        .unwrap();
    assert!(status.success());
}

#[cfg(not(windows))]
fn create_junction(link: &Path, target: &Path) {
    std::os::unix::fs::symlink(target, link).unwrap();
}

#[test]
fn credential_service_applies_format_gate_without_claiming_entropy_and_zeroizes() {
    struct RejectingStore;
    impl CredentialStore for RejectingStore {
        fn begin_mutation(
            &mut self,
            id: &CredentialRefId,
        ) -> Result<CredentialMutationOwner, CredentialStoreError> {
            Ok(CredentialMutationOwner::new(id.clone(), 1))
        }
        fn end_mutation(
            &mut self,
            _owner: CredentialMutationOwner,
        ) -> Result<(), CredentialStoreError> {
            Ok(())
        }
        fn planned_material_ref(
            &self,
            binding: &CredentialEnvelopeBinding,
        ) -> Result<PathBuf, CredentialStoreError> {
            Ok(PathBuf::from(binding.id().as_str())
                .join(format!("generation-{}.dpapi", binding.generation().value())))
        }

        fn create(
            &mut self,
            _: &CredentialEnvelopeBinding,
            _: &mut [u8],
        ) -> Result<(), CredentialStoreError> {
            Err(CredentialStoreError::IoFailure)
        }
        fn read(
            &self,
            _: &CredentialEnvelopeBinding,
            _: &mut dyn SecretConsumer,
        ) -> Result<(), CredentialStoreError> {
            Err(CredentialStoreError::NotFound)
        }
        fn rotate(
            &mut self,
            _: &CredentialEnvelopeBinding,
            _: &CredentialEnvelopeBinding,
            _: &mut [u8],
        ) -> Result<(), CredentialStoreError> {
            Err(CredentialStoreError::IoFailure)
        }
        fn delete(&mut self, _: &CredentialEnvelopeBinding) -> Result<(), CredentialStoreError> {
            Err(CredentialStoreError::IoFailure)
        }
    }

    let area = TempArea::new("credential-service-zeroize");
    let mut repository =
        SqliteMetadataRepository::open(area.root.join("metadata.sqlite3")).unwrap();
    let mut store = RejectingStore;
    let mut short = b"short-value".to_vec();
    assert_eq!(
        CredentialService::new(&mut repository, &mut store).create_api_key(
            CredentialRefId::parse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").unwrap(),
            &mut short,
            UnixMillis::new(1).unwrap(),
        ),
        Err(CredentialServiceError::InvalidSecret)
    );
    assert!(short.iter().all(|byte| *byte == 0));
    let mut repeated = vec![b'R'; 64];
    assert_eq!(
        CredentialService::new(&mut repository, &mut store).create_api_key(
            CredentialRefId::parse("dddddddd-dddd-4ddd-8ddd-dddddddddddd").unwrap(),
            &mut repeated,
            UnixMillis::new(2).unwrap(),
        ),
        Err(CredentialServiceError::InvalidSecret)
    );
    assert!(repeated.iter().all(|byte| *byte == 0));
    let mut patterned = Vec::from(&b"sk-"[..]);
    patterned.extend_from_slice(&b"AB12".repeat(16));
    assert_eq!(
        CredentialService::new(&mut repository, &mut store).create_api_key(
            CredentialRefId::parse("15151515-1515-4515-8515-151515151515").unwrap(),
            &mut patterned,
            UnixMillis::new(3).unwrap(),
        ),
        Err(CredentialServiceError::InvalidSecret)
    );
    assert!(patterned.iter().all(|byte| *byte == 0));
    let mut missing_provider_prefix = runtime_secret();
    missing_provider_prefix[..3].copy_from_slice(b"zz-");
    assert_eq!(
        CredentialService::new(&mut repository, &mut store).create_api_key(
            CredentialRefId::parse("16161616-1616-4616-8616-161616161616").unwrap(),
            &mut missing_provider_prefix,
            UnixMillis::new(3).unwrap(),
        ),
        Err(CredentialServiceError::InvalidSecret)
    );
    assert!(missing_provider_prefix.iter().all(|byte| *byte == 0));
    let mut valid = runtime_secret();
    assert_eq!(
        CredentialService::new(&mut repository, &mut store).create_api_key(
            CredentialRefId::parse("cccccccc-cccc-4ccc-8ccc-cccccccccccc").unwrap(),
            &mut valid,
            UnixMillis::new(4).unwrap(),
        ),
        Err(CredentialServiceError::StoreFailure)
    );
    assert!(valid.iter().all(|byte| *byte == 0));
    println!(
        "M24_API_KEY_POLICY format_gate_only=true entropy_proven=false deterministic_valid_shape=accepted_by_validator fingerprint=unkeyed_sha256_compatibility existing_read_compatible=true service_finally_zeroize=true"
    );
}

#[test]
fn api_key_create_rotate_read_delete_and_reference_boundary() {
    let area = TempArea::new("credential-e2e");
    let database = area.root.join("metadata.sqlite3");
    let mut repository = SqliteMetadataRepository::open(&database).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(area.root.join("credentials")).unwrap();
    let id = CredentialRefId::parse("33333333-3333-4333-8333-333333333333").unwrap();
    let second = {
        let mut service = CredentialService::new(&mut repository, &mut store);
        let mut first_secret = runtime_secret();
        let first_hash = hash_bytes(&api_key_document(&first_secret));
        let first = service
            .create_api_key(id.clone(), &mut first_secret, UnixMillis::new(10).unwrap())
            .unwrap();
        let mut consumer = HashConsumer {
            hash: None,
            length: 0,
        };
        service.read_for_switch(&id, &mut consumer).unwrap();
        assert_eq!(consumer.hash, Some(first_hash));
        let mut second_secret = runtime_secret();
        second_secret.push(b'2');
        let second_hash = hash_bytes(&api_key_document(&second_secret));
        let second = service
            .rotate_credential(
                &id,
                first.version(),
                &mut second_secret,
                UnixMillis::new(20).unwrap(),
            )
            .unwrap();
        assert_eq!(second.version().value(), 2);
        service.read_for_switch(&id, &mut consumer).unwrap();
        assert_eq!(consumer.hash, Some(second_hash));
        let mut stale_secret = runtime_secret();
        assert_eq!(
            service.rotate_credential(
                &id,
                first.version(),
                &mut stale_secret,
                UnixMillis::new(30).unwrap()
            ),
            Err(CredentialServiceError::VersionConflict)
        );
        assert!(stale_secret.iter().all(|byte| *byte == 0));
        second
    };

    let identity = RuntimeIdentity::new_draft(
        IdentityId::parse("44444444-4444-4444-8444-444444444444").unwrap(),
        EntityName::parse("Credential user").unwrap(),
        ProviderId::parse("sample").unwrap(),
        EntityName::parse("Sample Provider").unwrap(),
        EndpointUrl::parse("https://HOST/v1").unwrap(),
        None,
        second.link(),
        UnixMillis::new(20).unwrap(),
    )
    .unwrap();
    repository.create_runtime_identity(&identity).unwrap();
    {
        let mut service = CredentialService::new(&mut repository, &mut store);
        assert_eq!(
            service.delete_credential(&id, second.version()),
            Err(CredentialServiceError::ReferenceConflict)
        );
    }
    repository
        .delete_runtime_identity(identity.id(), identity.version())
        .unwrap();
    CredentialService::new(&mut repository, &mut store)
        .delete_credential(&id, second.version())
        .unwrap();
    assert!(!area.root.join("credentials").join(id.as_str()).exists());
    println!(
        "M24_API_KEY create=true rotate=true read_for_switch=true fk_delete_guard=true delete=true"
    );
}

struct FailingRepository<'a> {
    inner: &'a mut SqliteMetadataRepository,
    fail_create: bool,
    fail_update: bool,
    fail_recovery_create: bool,
    fail_recovery_update: bool,
    fail_recovery_delete: bool,
}
impl CredentialReferenceRepository for FailingRepository<'_> {
    fn create_credential_reference(
        &mut self,
        value: &codex_domain::CredentialReference,
    ) -> Result<(), RepositoryError> {
        if self.fail_create {
            Err(RepositoryError::StorageUnavailable)
        } else {
            self.inner.create_credential_reference(value)
        }
    }
    fn get_credential_reference(
        &self,
        id: &CredentialRefId,
    ) -> Result<Option<codex_domain::CredentialReference>, RepositoryError> {
        self.inner.get_credential_reference(id)
    }
    fn list_credential_references(
        &self,
    ) -> Result<Vec<codex_domain::CredentialReference>, RepositoryError> {
        self.inner.list_credential_references()
    }
    fn update_credential_reference(
        &mut self,
        value: &codex_domain::CredentialReference,
        version: EntityVersion,
    ) -> Result<(), RepositoryError> {
        if self.fail_update {
            Err(RepositoryError::StorageUnavailable)
        } else {
            self.inner.update_credential_reference(value, version)
        }
    }
    fn delete_credential_reference(
        &mut self,
        id: &CredentialRefId,
        version: EntityVersion,
    ) -> Result<(), RepositoryError> {
        self.inner.delete_credential_reference(id, version)
    }
}

impl CredentialRecoveryRepository for FailingRepository<'_> {
    fn create_credential_recovery(
        &mut self,
        record: &CredentialRecoveryRecord,
    ) -> Result<(), RepositoryError> {
        if self.fail_recovery_create {
            Err(RepositoryError::StorageUnavailable)
        } else {
            self.inner.create_credential_recovery(record)
        }
    }

    fn get_credential_recovery(
        &self,
        operation_id: &str,
    ) -> Result<Option<CredentialRecoveryRecord>, RepositoryError> {
        self.inner.get_credential_recovery(operation_id)
    }

    fn list_credential_recoveries(
        &self,
        id: &CredentialRefId,
    ) -> Result<Vec<CredentialRecoveryRecord>, RepositoryError> {
        self.inner.list_credential_recoveries(id)
    }

    fn update_credential_recovery(
        &mut self,
        record: &CredentialRecoveryRecord,
        expected_version: EntityVersion,
    ) -> Result<(), RepositoryError> {
        if self.fail_recovery_update {
            Err(RepositoryError::StorageUnavailable)
        } else {
            self.inner
                .update_credential_recovery(record, expected_version)
        }
    }

    fn delete_credential_recovery(
        &mut self,
        operation_id: &str,
        expected_version: EntityVersion,
    ) -> Result<(), RepositoryError> {
        if self.fail_recovery_delete {
            Err(RepositoryError::StorageUnavailable)
        } else {
            self.inner
                .delete_credential_recovery(operation_id, expected_version)
        }
    }
}

struct DeleteFailingStore<'a> {
    inner: &'a mut WindowsDpapiCredentialStore,
}
impl CredentialStore for DeleteFailingStore<'_> {
    fn begin_mutation(
        &mut self,
        id: &CredentialRefId,
    ) -> Result<CredentialMutationOwner, CredentialStoreError> {
        self.inner.begin_mutation(id)
    }
    fn end_mutation(&mut self, owner: CredentialMutationOwner) -> Result<(), CredentialStoreError> {
        self.inner.end_mutation(owner)
    }
    fn planned_material_ref(
        &self,
        binding: &CredentialEnvelopeBinding,
    ) -> Result<PathBuf, CredentialStoreError> {
        self.inner.planned_material_ref(binding)
    }

    fn create(
        &mut self,
        binding: &CredentialEnvelopeBinding,
        secret: &mut [u8],
    ) -> Result<(), CredentialStoreError> {
        self.inner.create(binding, secret)
    }

    fn read(
        &self,
        binding: &CredentialEnvelopeBinding,
        consumer: &mut dyn SecretConsumer,
    ) -> Result<(), CredentialStoreError> {
        self.inner.read(binding, consumer)
    }

    fn rotate(
        &mut self,
        previous: &CredentialEnvelopeBinding,
        next: &CredentialEnvelopeBinding,
        secret: &mut [u8],
    ) -> Result<(), CredentialStoreError> {
        self.inner.rotate(previous, next, secret)
    }

    fn delete(&mut self, _: &CredentialEnvelopeBinding) -> Result<(), CredentialStoreError> {
        Err(CredentialStoreError::IoFailure)
    }

    fn inspect(
        &self,
        binding: &CredentialEnvelopeBinding,
    ) -> Result<CredentialMaterialDiagnostic, CredentialStoreError> {
        self.inner.inspect(binding)
    }

    fn rollback_rotation(
        &mut self,
        previous: &CredentialEnvelopeBinding,
        next: &CredentialEnvelopeBinding,
    ) -> Result<(), CredentialStoreError> {
        self.inner.rollback_rotation(previous, next)
    }
}

fn prepare_create_terminal_recovery(
    database: &Path,
    credential_root: &Path,
    id_text: &str,
) -> CredentialRecoveryRecord {
    let id = CredentialRefId::parse(id_text).unwrap();
    let mut repository = SqliteMetadataRepository::open(database).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(credential_root).unwrap();
    {
        let mut failing = FailingRepository {
            inner: &mut repository,
            fail_create: true,
            fail_update: false,
            fail_recovery_create: false,
            fail_recovery_update: false,
            fail_recovery_delete: false,
        };
        assert_eq!(
            CredentialService::new(&mut failing, &mut store).create_api_key(
                id.clone(),
                &mut runtime_secret(),
                UnixMillis::new(30).unwrap(),
            ),
            Err(CredentialServiceError::RecoveryRequired)
        );
    }
    repository
        .list_credential_recoveries(&id)
        .unwrap()
        .pop()
        .unwrap()
}

fn prepare_delete_terminal_recovery(
    database: &Path,
    credential_root: &Path,
    id_text: &str,
) -> CredentialRecoveryRecord {
    let id = CredentialRefId::parse(id_text).unwrap();
    let mut repository = SqliteMetadataRepository::open(database).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(credential_root).unwrap();
    let reference = CredentialService::new(&mut repository, &mut store)
        .create_api_key(
            id.clone(),
            &mut runtime_secret(),
            UnixMillis::new(40).unwrap(),
        )
        .unwrap();
    {
        let mut failing_store = DeleteFailingStore { inner: &mut store };
        assert_eq!(
            CredentialService::new(&mut repository, &mut failing_store)
                .delete_credential(&id, reference.version()),
            Err(CredentialServiceError::RecoveryRequired)
        );
    }
    repository
        .list_credential_recoveries(&id)
        .unwrap()
        .pop()
        .unwrap()
}

#[test]
fn terminal_recovery_side_effects_retry_after_journal_clear_failure() {
    let create_adopt_area = TempArea::new("terminal-create-adopt");
    let create_adopt_database = create_adopt_area.root.join("metadata.sqlite3");
    let create_adopt_root = create_adopt_area.root.join("credentials");
    let create_adopt = prepare_create_terminal_recovery(
        &create_adopt_database,
        &create_adopt_root,
        "17171717-1717-4717-8717-171717171717",
    );
    {
        let mut repository = SqliteMetadataRepository::open(&create_adopt_database).unwrap();
        let mut store = WindowsDpapiCredentialStore::new(&create_adopt_root).unwrap();
        let mut failing = FailingRepository {
            inner: &mut repository,
            fail_create: false,
            fail_update: false,
            fail_recovery_create: false,
            fail_recovery_update: false,
            fail_recovery_delete: true,
        };
        assert_eq!(
            CredentialService::new(&mut failing, &mut store)
                .adopt_recovery(&create_adopt.operation_id, UnixMillis::new(31).unwrap()),
            Err(CredentialServiceError::RecoveryRequired)
        );
        assert!(
            repository
                .get_credential_reference(&create_adopt.credential_id)
                .unwrap()
                .is_some()
        );
    }
    let create_adopt_converged = {
        let mut repository = SqliteMetadataRepository::open(&create_adopt_database).unwrap();
        let mut store = WindowsDpapiCredentialStore::new(&create_adopt_root).unwrap();
        let result = CredentialService::new(&mut repository, &mut store)
            .adopt_recovery(&create_adopt.operation_id, UnixMillis::new(32).unwrap());
        result.is_ok()
            && repository
                .get_credential_recovery(&create_adopt.operation_id)
                .unwrap()
                .is_none()
            && repository
                .get_credential_reference(&create_adopt.credential_id)
                .unwrap()
                .is_some()
            && create_adopt_root.join(create_adopt.material_ref).is_file()
    };

    let delete_adopt_area = TempArea::new("terminal-delete-adopt");
    let delete_adopt_database = delete_adopt_area.root.join("metadata.sqlite3");
    let delete_adopt_root = delete_adopt_area.root.join("credentials");
    let delete_adopt = prepare_delete_terminal_recovery(
        &delete_adopt_database,
        &delete_adopt_root,
        "18181818-1818-4818-8818-181818181818",
    );
    {
        let mut repository = SqliteMetadataRepository::open(&delete_adopt_database).unwrap();
        let mut store = WindowsDpapiCredentialStore::new(&delete_adopt_root).unwrap();
        let mut failing = FailingRepository {
            inner: &mut repository,
            fail_create: false,
            fail_update: false,
            fail_recovery_create: false,
            fail_recovery_update: false,
            fail_recovery_delete: true,
        };
        assert_eq!(
            CredentialService::new(&mut failing, &mut store)
                .adopt_recovery(&delete_adopt.operation_id, UnixMillis::new(41).unwrap()),
            Err(CredentialServiceError::RecoveryRequired)
        );
    }
    let delete_adopt_converged = {
        let mut repository = SqliteMetadataRepository::open(&delete_adopt_database).unwrap();
        let mut store = WindowsDpapiCredentialStore::new(&delete_adopt_root).unwrap();
        let result = CredentialService::new(&mut repository, &mut store)
            .adopt_recovery(&delete_adopt.operation_id, UnixMillis::new(42).unwrap());
        result.is_ok()
            && repository
                .get_credential_recovery(&delete_adopt.operation_id)
                .unwrap()
                .is_none()
            && repository
                .get_credential_reference(&delete_adopt.credential_id)
                .unwrap()
                .is_some()
            && delete_adopt_root.join(delete_adopt.material_ref).is_file()
    };

    let delete_rollback_area = TempArea::new("terminal-delete-rollback");
    let delete_rollback_database = delete_rollback_area.root.join("metadata.sqlite3");
    let delete_rollback_root = delete_rollback_area.root.join("credentials");
    let delete_rollback = prepare_delete_terminal_recovery(
        &delete_rollback_database,
        &delete_rollback_root,
        "19191919-1919-4919-8919-191919191919",
    );
    {
        let mut repository = SqliteMetadataRepository::open(&delete_rollback_database).unwrap();
        let mut store = WindowsDpapiCredentialStore::new(&delete_rollback_root).unwrap();
        let mut failing = FailingRepository {
            inner: &mut repository,
            fail_create: false,
            fail_update: false,
            fail_recovery_create: false,
            fail_recovery_update: false,
            fail_recovery_delete: true,
        };
        assert_eq!(
            CredentialService::new(&mut failing, &mut store)
                .rollback_recovery(&delete_rollback.operation_id, UnixMillis::new(41).unwrap()),
            Err(CredentialServiceError::RecoveryRequired)
        );
    }
    let delete_rollback_converged = {
        let mut repository = SqliteMetadataRepository::open(&delete_rollback_database).unwrap();
        let mut store = WindowsDpapiCredentialStore::new(&delete_rollback_root).unwrap();
        let result = CredentialService::new(&mut repository, &mut store)
            .rollback_recovery(&delete_rollback.operation_id, UnixMillis::new(42).unwrap());
        result.is_ok()
            && repository
                .get_credential_recovery(&delete_rollback.operation_id)
                .unwrap()
                .is_none()
            && repository
                .get_credential_reference(&delete_rollback.credential_id)
                .unwrap()
                .is_some()
            && delete_rollback_root
                .join(delete_rollback.material_ref)
                .is_file()
    };

    let create_rollback_area = TempArea::new("terminal-create-rollback");
    let create_rollback_database = create_rollback_area.root.join("metadata.sqlite3");
    let create_rollback_root = create_rollback_area.root.join("credentials");
    let create_rollback = prepare_create_terminal_recovery(
        &create_rollback_database,
        &create_rollback_root,
        "20202020-2020-4020-8020-202020202020",
    );
    let create_rollback_material = create_rollback_root
        .join(create_rollback.credential_id.as_str())
        .join(format!(
            "generation-{}.dpapi",
            create_rollback.generation.value()
        ));
    {
        let mut repository = SqliteMetadataRepository::open(&create_rollback_database).unwrap();
        let mut store = WindowsDpapiCredentialStore::new(&create_rollback_root).unwrap();
        let mut failing = FailingRepository {
            inner: &mut repository,
            fail_create: false,
            fail_update: false,
            fail_recovery_create: false,
            fail_recovery_update: false,
            fail_recovery_delete: true,
        };
        assert_eq!(
            CredentialService::new(&mut failing, &mut store)
                .rollback_recovery(&create_rollback.operation_id, UnixMillis::new(31).unwrap()),
            Err(CredentialServiceError::RecoveryRequired)
        );
        assert!(!create_rollback_material.exists());
    }
    let create_rollback_converged = {
        let mut repository = SqliteMetadataRepository::open(&create_rollback_database).unwrap();
        let mut store = WindowsDpapiCredentialStore::new(&create_rollback_root).unwrap();
        let result = CredentialService::new(&mut repository, &mut store)
            .rollback_recovery(&create_rollback.operation_id, UnixMillis::new(32).unwrap());
        result.is_ok()
            && repository
                .get_credential_recovery(&create_rollback.operation_id)
                .unwrap()
                .is_none()
            && repository
                .get_credential_reference(&create_rollback.credential_id)
                .unwrap()
                .is_none()
            && !create_rollback_material.exists()
    };
    println!(
        "M24_CREDENTIAL_TERMINAL_RETRY_STATE create_adopt={create_adopt_converged} delete_adopt={delete_adopt_converged} delete_rollback={delete_rollback_converged} create_rollback={create_rollback_converged}"
    );
    assert!(
        create_adopt_converged
            && delete_adopt_converged
            && delete_rollback_converged
            && create_rollback_converged,
        "terminal recovery retry matrix did not converge"
    );
    println!(
        "M24_CREDENTIAL_TERMINAL_RETRY create_adopt=converged delete_adopt=converged delete_rollback=converged create_rollback=converged journal=0 orphan=0"
    );
}

#[test]
fn delete_recovery_preserves_rotated_credential_timestamps_across_reopen() {
    let area = TempArea::new("delete-rotated-timestamps");
    let database = area.root.join("metadata.sqlite3");
    let credential_root = area.root.join("credentials");
    let id = CredentialRefId::parse("21212121-2121-4121-8121-212121212121").unwrap();
    let mut repository = SqliteMetadataRepository::open(&database).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();
    let first = CredentialService::new(&mut repository, &mut store)
        .create_api_key(
            id.clone(),
            &mut runtime_secret(),
            UnixMillis::new(10).unwrap(),
        )
        .unwrap();
    let mut rotated_secret = runtime_secret();
    rotated_secret.push(b'R');
    let deleted = CredentialService::new(&mut repository, &mut store)
        .rotate_credential(
            &id,
            first.version(),
            &mut rotated_secret,
            UnixMillis::new(20).unwrap(),
        )
        .unwrap();
    assert_ne!(deleted.created_at(), deleted.updated_at());

    let binding = CredentialEnvelopeBinding::new(
        id.clone(),
        deleted.kind(),
        deleted.schema_fingerprint().clone(),
        deleted.version(),
    );
    let material = store.inspect(&binding).unwrap();
    let operation_id = format!(
        "credential:{}:delete:{}",
        id.as_str(),
        deleted.version().value()
    );
    let crash_record = CredentialRecoveryRecord {
        operation_id: operation_id.clone(),
        credential_id: id.clone(),
        kind: deleted.kind(),
        operation: CredentialRecoveryOperation::Delete,
        generation: deleted.version(),
        planned_credential_fingerprint: Some(deleted.credential_fingerprint().clone()),
        material_ref: material.material_ref,
        material_hash: Some(material.material_hash),
        phase: CredentialRecoveryPhase::DeletePending,
        diagnostic_code: None,
        credential_created_at: deleted.created_at(),
        credential_updated_at: deleted.updated_at(),
        created_at: UnixMillis::new(21).unwrap(),
        updated_at: UnixMillis::new(21).unwrap(),
        version: EntityVersion::initial(),
    };
    repository
        .create_credential_recovery(&crash_record)
        .unwrap();
    repository
        .delete_credential_reference(&id, deleted.version())
        .unwrap();
    drop(repository);
    drop(store);

    let mut repository = SqliteMetadataRepository::open(&database).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();
    {
        let mut failing = FailingRepository {
            inner: &mut repository,
            fail_create: false,
            fail_update: false,
            fail_recovery_create: false,
            fail_recovery_update: false,
            fail_recovery_delete: true,
        };
        assert_eq!(
            CredentialService::new(&mut failing, &mut store)
                .adopt_recovery(&operation_id, UnixMillis::new(30).unwrap()),
            Err(CredentialServiceError::RecoveryRequired)
        );
    }
    let side_effect_reference = repository.get_credential_reference(&id).unwrap().unwrap();
    assert_eq!(side_effect_reference, deleted);
    drop(repository);
    drop(store);

    let mut repository = SqliteMetadataRepository::open(&database).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();
    let restored = CredentialService::new(&mut repository, &mut store)
        .adopt_recovery(&operation_id, UnixMillis::new(31).unwrap())
        .unwrap();
    assert_eq!(restored.id(), deleted.id());
    assert_eq!(restored.kind(), deleted.kind());
    assert_eq!(restored.backend(), deleted.backend());
    assert_eq!(restored.schema_fingerprint(), deleted.schema_fingerprint());
    assert_eq!(
        restored.credential_fingerprint(),
        deleted.credential_fingerprint()
    );
    assert_eq!(restored.version(), deleted.version());
    assert_eq!(restored.created_at(), deleted.created_at());
    assert_eq!(restored.updated_at(), deleted.updated_at());
    assert!(
        repository
            .get_credential_recovery(&operation_id)
            .unwrap()
            .is_none()
    );

    let material = store.inspect(&binding).unwrap();
    let rollback_record = CredentialRecoveryRecord {
        operation_id: operation_id.clone(),
        credential_id: id.clone(),
        kind: deleted.kind(),
        operation: CredentialRecoveryOperation::Delete,
        generation: deleted.version(),
        planned_credential_fingerprint: Some(deleted.credential_fingerprint().clone()),
        material_ref: material.material_ref,
        material_hash: Some(material.material_hash),
        phase: CredentialRecoveryPhase::DeletePending,
        diagnostic_code: None,
        credential_created_at: deleted.created_at(),
        credential_updated_at: deleted.updated_at(),
        created_at: UnixMillis::new(32).unwrap(),
        updated_at: UnixMillis::new(32).unwrap(),
        version: EntityVersion::initial(),
    };
    repository
        .create_credential_recovery(&rollback_record)
        .unwrap();
    repository
        .delete_credential_reference(&id, deleted.version())
        .unwrap();
    drop(repository);
    drop(store);

    let mut repository = SqliteMetadataRepository::open(&database).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();
    CredentialService::new(&mut repository, &mut store)
        .rollback_recovery(&operation_id, UnixMillis::new(33).unwrap())
        .unwrap();
    assert_eq!(
        repository.get_credential_reference(&id).unwrap().unwrap(),
        deleted
    );
    assert!(
        repository
            .get_credential_recovery(&operation_id)
            .unwrap()
            .is_none()
    );

    let material = store.inspect(&binding).unwrap();
    let mut mismatched_intent = rollback_record;
    mismatched_intent.material_ref = material.material_ref;
    mismatched_intent.material_hash = Some(material.material_hash);
    mismatched_intent.credential_updated_at = deleted.created_at();
    repository
        .create_credential_recovery(&mismatched_intent)
        .unwrap();
    assert_eq!(
        CredentialService::new(&mut repository, &mut store)
            .delete_credential(&id, deleted.version()),
        Err(CredentialServiceError::RecoveryRequired)
    );
    assert_eq!(
        repository.get_credential_reference(&id).unwrap().unwrap(),
        deleted
    );
    assert!(store.inspect(&binding).is_ok());
    println!(
        "M24_DELETE_TIMESTAMP_RECOVERY rotated=true adopt_exact=true rollback_exact=true clear_failure_reopen=true mismatched_intent=protected journal_orphan=0"
    );
}

#[test]
fn rotate_adopt_consumes_bound_reference_and_retries_exactly_after_clear_failure() {
    let area = TempArea::new("rotate-adopt-bound-reference");
    let database = area.root.join("metadata.sqlite3");
    let credential_root = area.root.join("credentials");
    let id = CredentialRefId::parse("26262626-2626-4626-8626-262626262626").unwrap();
    let mut repository = SqliteMetadataRepository::open(&database).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();
    let first = CredentialService::new(&mut repository, &mut store)
        .create_api_key(
            id.clone(),
            &mut runtime_secret(),
            UnixMillis::new(10).unwrap(),
        )
        .unwrap();
    let mut replacement = runtime_secret();
    replacement.push(b'W');
    {
        let mut failing = FailingRepository {
            inner: &mut repository,
            fail_create: false,
            fail_update: true,
            fail_recovery_create: false,
            fail_recovery_update: false,
            fail_recovery_delete: false,
        };
        assert_eq!(
            CredentialService::new(&mut failing, &mut store).rotate_credential(
                &id,
                first.version(),
                &mut replacement,
                UnixMillis::new(20).unwrap(),
            ),
            Err(CredentialServiceError::RecoveryRequired)
        );
    }
    let recovery = repository
        .list_credential_recoveries(&id)
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(recovery.credential_created_at, first.created_at());
    assert_eq!(recovery.credential_updated_at, UnixMillis::new(20).unwrap());
    let expected = first
        .rotate(
            first.schema_fingerprint().clone(),
            recovery.planned_credential_fingerprint.clone().unwrap(),
            recovery.credential_updated_at,
        )
        .unwrap();

    {
        let mut failing = FailingRepository {
            inner: &mut repository,
            fail_create: false,
            fail_update: false,
            fail_recovery_create: false,
            fail_recovery_update: false,
            fail_recovery_delete: true,
        };
        assert_eq!(
            CredentialService::new(&mut failing, &mut store)
                .adopt_recovery(&recovery.operation_id, UnixMillis::new(30).unwrap()),
            Err(CredentialServiceError::RecoveryRequired)
        );
    }
    let side_effect_reference = repository.get_credential_reference(&id).unwrap().unwrap();
    assert_eq!(side_effect_reference, expected);
    assert!(
        repository
            .get_credential_recovery(&recovery.operation_id)
            .unwrap()
            .is_some()
    );
    drop(repository);
    drop(store);

    let mut repository = SqliteMetadataRepository::open(&database).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();
    let retried = CredentialService::new(&mut repository, &mut store)
        .adopt_recovery(&recovery.operation_id, UnixMillis::new(40).unwrap())
        .unwrap();
    assert_eq!(retried, expected);
    assert_eq!(
        repository.get_credential_reference(&id).unwrap().unwrap(),
        expected
    );
    assert!(
        repository
            .get_credential_recovery(&recovery.operation_id)
            .unwrap()
            .is_none()
    );
    println!(
        "M24_ROTATE_ADOPT_BOUND_REFERENCE planned_time=consumed adopt_now=diagnostic_only clear_failure_retry=exact journal=0 orphan=0"
    );
}

#[test]
fn rotate_adopt_rejects_any_persistable_committed_reference_deviation() {
    let mutations: [(&str, &str); 4] = [
        (
            "created_at",
            "UPDATE credential_references SET created_at_unix_ms=9 WHERE id=?1",
        ),
        (
            "updated_at",
            "UPDATE credential_references SET updated_at_unix_ms=21 WHERE id=?1",
        ),
        (
            "schema",
            "UPDATE credential_references SET schema_fingerprint=printf('%064x', 15) WHERE id=?1",
        ),
        (
            "kind",
            "UPDATE credential_references SET kind='oauth_bundle' WHERE id=?1",
        ),
    ];

    for (index, (label, mutation)) in mutations.into_iter().enumerate() {
        let area = TempArea::new(&format!("rotate-adopt-mismatch-{label}"));
        let database = area.root.join("metadata.sqlite3");
        let credential_root = area.root.join("credentials");
        let id =
            CredentialRefId::parse(&format!("27272727-2727-4727-8727-27272727272{}", index + 1))
                .unwrap();
        let mut repository = SqliteMetadataRepository::open(&database).unwrap();
        let mut store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();
        let first = CredentialService::new(&mut repository, &mut store)
            .create_api_key(
                id.clone(),
                &mut runtime_secret(),
                UnixMillis::new(10).unwrap(),
            )
            .unwrap();
        let mut replacement = runtime_secret();
        replacement.push(b'W' + index as u8);
        {
            let mut failing = FailingRepository {
                inner: &mut repository,
                fail_create: false,
                fail_update: true,
                fail_recovery_create: false,
                fail_recovery_update: false,
                fail_recovery_delete: false,
            };
            assert_eq!(
                CredentialService::new(&mut failing, &mut store).rotate_credential(
                    &id,
                    first.version(),
                    &mut replacement,
                    UnixMillis::new(20).unwrap(),
                ),
                Err(CredentialServiceError::RecoveryRequired)
            );
        }
        let recovery = repository
            .list_credential_recoveries(&id)
            .unwrap()
            .pop()
            .unwrap();
        {
            let mut failing = FailingRepository {
                inner: &mut repository,
                fail_create: false,
                fail_update: false,
                fail_recovery_create: false,
                fail_recovery_update: false,
                fail_recovery_delete: true,
            };
            assert_eq!(
                CredentialService::new(&mut failing, &mut store)
                    .adopt_recovery(&recovery.operation_id, UnixMillis::new(30).unwrap()),
                Err(CredentialServiceError::RecoveryRequired)
            );
        }
        drop(repository);
        drop(store);

        let connection = rusqlite::Connection::open(&database).unwrap();
        assert_eq!(connection.execute(mutation, [id.as_str()]).unwrap(), 1);
        drop(connection);
        let mut repository = SqliteMetadataRepository::open(&database).unwrap();
        let mut store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();
        let mismatched = repository.get_credential_reference(&id).unwrap().unwrap();
        assert_eq!(
            CredentialService::new(&mut repository, &mut store)
                .adopt_recovery(&recovery.operation_id, UnixMillis::new(40).unwrap()),
            Err(CredentialServiceError::RecoveryRequired),
            "{label} deviation was accepted"
        );
        assert_eq!(
            repository.get_credential_reference(&id).unwrap().unwrap(),
            mismatched
        );
        assert_eq!(
            repository
                .get_credential_recovery(&recovery.operation_id)
                .unwrap()
                .unwrap(),
            recovery
        );
    }

    let backend_area = TempArea::new("rotate-adopt-backend-check");
    let database = backend_area.root.join("metadata.sqlite3");
    let id = CredentialRefId::parse("28282828-2828-4828-8828-282828282828").unwrap();
    let mut repository = SqliteMetadataRepository::open(&database).unwrap();
    let mut store =
        WindowsDpapiCredentialStore::new(backend_area.root.join("credentials")).unwrap();
    CredentialService::new(&mut repository, &mut store)
        .create_api_key(
            id.clone(),
            &mut runtime_secret(),
            UnixMillis::new(10).unwrap(),
        )
        .unwrap();
    drop(repository);
    drop(store);
    let connection = rusqlite::Connection::open(&database).unwrap();
    assert!(
        connection
            .execute(
                "UPDATE credential_references SET platform_backend='unsupported' WHERE id=?1",
                [id.as_str()],
            )
            .is_err()
    );
    println!(
        "M24_ROTATE_ADOPT_EXACT_RETRY created_at=protected updated_at=protected schema=protected kind=protected backend=schema_rejected journal=retained"
    );
}

#[test]
fn credential_recovery_api_adopts_rolls_back_and_cleans_up_idempotently() {
    let area = TempArea::new("credential-recovery-api");
    let mut repository =
        SqliteMetadataRepository::open(area.root.join("metadata.sqlite3")).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(area.root.join("credentials")).unwrap();

    let rotate_id = CredentialRefId::parse("12121212-1212-4212-8212-121212121212").unwrap();
    let first = CredentialService::new(&mut repository, &mut store)
        .create_api_key(
            rotate_id.clone(),
            &mut runtime_secret(),
            UnixMillis::new(10).unwrap(),
        )
        .unwrap();
    let mut replacement = runtime_secret();
    replacement.push(b'Z');
    {
        let mut failing = FailingRepository {
            inner: &mut repository,
            fail_create: false,
            fail_update: true,
            fail_recovery_create: false,
            fail_recovery_update: false,
            fail_recovery_delete: false,
        };
        assert_eq!(
            CredentialService::new(&mut failing, &mut store).rotate_credential(
                &rotate_id,
                first.version(),
                &mut replacement,
                UnixMillis::new(11).unwrap(),
            ),
            Err(CredentialServiceError::RecoveryRequired)
        );
    }
    let operation = repository
        .list_credential_recoveries(&rotate_id)
        .unwrap()
        .pop()
        .unwrap();
    CredentialService::new(&mut repository, &mut store)
        .rollback_recovery(&operation.operation_id, UnixMillis::new(12).unwrap())
        .unwrap();
    assert!(
        repository
            .list_credential_recoveries(&rotate_id)
            .unwrap()
            .is_empty()
    );
    assert!(
        area.root
            .join("credentials")
            .join(rotate_id.as_str())
            .join("generation-1.dpapi")
            .is_file()
    );
    assert!(
        !area
            .root
            .join("credentials")
            .join(rotate_id.as_str())
            .join("generation-2.dpapi")
            .exists()
    );

    let clear_id = CredentialRefId::parse("14141414-1414-4414-8414-141414141414").unwrap();
    let clear_first = CredentialService::new(&mut repository, &mut store)
        .create_api_key(
            clear_id.clone(),
            &mut runtime_secret(),
            UnixMillis::new(15).unwrap(),
        )
        .unwrap();
    let mut clear_secret = runtime_secret();
    clear_secret.push(b'Q');
    {
        let mut failing = FailingRepository {
            inner: &mut repository,
            fail_create: false,
            fail_update: false,
            fail_recovery_create: false,
            fail_recovery_update: false,
            fail_recovery_delete: true,
        };
        assert_eq!(
            CredentialService::new(&mut failing, &mut store).rotate_credential(
                &clear_id,
                clear_first.version(),
                &mut clear_secret,
                UnixMillis::new(16).unwrap(),
            ),
            Err(CredentialServiceError::RecoveryRequired)
        );
    }
    assert_eq!(
        repository
            .get_credential_reference(&clear_id)
            .unwrap()
            .unwrap()
            .version()
            .value(),
        2
    );
    assert_eq!(
        repository
            .list_credential_recoveries(&clear_id)
            .unwrap()
            .len(),
        1
    );
    drop(repository);
    drop(store);
    let mut repository =
        SqliteMetadataRepository::open(area.root.join("metadata.sqlite3")).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(area.root.join("credentials")).unwrap();
    let mut clear_retry = runtime_secret();
    clear_retry.push(b'Q');
    let clear_second = CredentialService::new(&mut repository, &mut store)
        .rotate_credential(
            &clear_id,
            clear_first.version(),
            &mut clear_retry,
            UnixMillis::new(17).unwrap(),
        )
        .unwrap();
    assert_eq!(clear_second.version().value(), 2);
    assert!(
        repository
            .list_credential_recoveries(&clear_id)
            .unwrap()
            .is_empty()
    );

    let delete_id = CredentialRefId::parse("13131313-1313-4313-8313-131313131313").unwrap();
    let deleted = CredentialService::new(&mut repository, &mut store)
        .create_api_key(
            delete_id.clone(),
            &mut runtime_secret(),
            UnixMillis::new(20).unwrap(),
        )
        .unwrap();
    {
        let mut failing_store = DeleteFailingStore { inner: &mut store };
        assert_eq!(
            CredentialService::new(&mut repository, &mut failing_store)
                .delete_credential(&delete_id, deleted.version()),
            Err(CredentialServiceError::RecoveryRequired)
        );
    }
    assert!(
        repository
            .get_credential_reference(&delete_id)
            .unwrap()
            .is_none()
    );
    let operation = repository
        .list_credential_recoveries(&delete_id)
        .unwrap()
        .pop()
        .unwrap();
    let restored = CredentialService::new(&mut repository, &mut store)
        .adopt_recovery(&operation.operation_id, UnixMillis::new(21).unwrap())
        .unwrap();
    assert_eq!(restored.version(), deleted.version());
    assert!(
        repository
            .list_credential_recoveries(&delete_id)
            .unwrap()
            .is_empty()
    );

    {
        let mut failing_store = DeleteFailingStore { inner: &mut store };
        assert_eq!(
            CredentialService::new(&mut repository, &mut failing_store)
                .delete_credential(&delete_id, restored.version()),
            Err(CredentialServiceError::RecoveryRequired)
        );
    }
    let operation = repository
        .list_credential_recoveries(&delete_id)
        .unwrap()
        .pop()
        .unwrap();
    CredentialService::new(&mut repository, &mut store)
        .cleanup_recovery(&operation.operation_id)
        .unwrap();
    assert!(
        repository
            .list_credential_recoveries(&delete_id)
            .unwrap()
            .is_empty()
    );
    assert!(
        !area
            .root
            .join("credentials")
            .join(delete_id.as_str())
            .exists()
    );
    println!(
        "M24_CREDENTIAL_RECOVERY rotate_rollback=idempotent rotate_metadata_committed_clear_failed=reopen_retry_cleared delete_adopt=metadata_restored delete_cleanup=material_removed diagnostics=cleared"
    );
}

#[test]
fn destructive_create_recovery_preserves_replaced_same_binding_material_after_reopen() {
    for (index, cleanup) in [false, true].into_iter().enumerate() {
        let area = TempArea::new("recovery-replaced-material");
        let database = area.root.join("metadata.sqlite3");
        let credential_root = area.root.join("credentials");
        let id_text = format!("3{index}303030-3030-4030-8030-303030303030");
        let recovery = prepare_create_terminal_recovery(&database, &credential_root, &id_text);
        let binding = CredentialEnvelopeBinding::new(
            recovery.credential_id.clone(),
            recovery.kind,
            credential_material_schema_fingerprint(recovery.kind),
            recovery.generation,
        );
        let mut replacement = runtime_secret();
        replacement.push(b'X' + u8::try_from(index).unwrap());
        let replacement_hash = hash_bytes(&replacement);

        {
            let mut store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();
            store.delete(&binding).unwrap();
            store.create(&binding, &mut replacement).unwrap();
        }
        assert!(replacement.iter().all(|byte| *byte == 0));

        let mut repository = SqliteMetadataRepository::open(&database).unwrap();
        let mut store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();
        let result = if cleanup {
            CredentialService::new(&mut repository, &mut store)
                .cleanup_recovery(&recovery.operation_id)
        } else {
            CredentialService::new(&mut repository, &mut store)
                .rollback_recovery(&recovery.operation_id, UnixMillis::new(31).unwrap())
        };
        assert_eq!(result, Err(CredentialServiceError::RecoveryRequired));
        assert!(
            repository
                .get_credential_recovery(&recovery.operation_id)
                .unwrap()
                .is_some()
        );
        let mut consumer = HashConsumer {
            hash: None,
            length: 0,
        };
        store.read(&binding, &mut consumer).unwrap();
        assert_eq!(consumer.hash, Some(replacement_hash));
    }
}

#[test]
fn destructive_create_recovery_requires_exact_material_reference_and_hash() {
    for (index, column) in ["material_ref", "material_sha256"].into_iter().enumerate() {
        let area = TempArea::new("recovery-stale-evidence");
        let database = area.root.join("metadata.sqlite3");
        let credential_root = area.root.join("credentials");
        let id_text = format!("4{index}404040-4040-4040-8040-404040404040");
        let recovery = prepare_create_terminal_recovery(&database, &credential_root, &id_text);
        let binding = CredentialEnvelopeBinding::new(
            recovery.credential_id.clone(),
            recovery.kind,
            credential_material_schema_fingerprint(recovery.kind),
            recovery.generation,
        );
        let original = {
            let store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();
            store.inspect(&binding).unwrap()
        };
        let connection = rusqlite::Connection::open(&database).unwrap();
        match column {
            "material_ref" => connection
                .execute(
                    "UPDATE credential_recovery_operations SET material_ref='stale/generation-1.dpapi' WHERE operation_id=?1",
                    [&recovery.operation_id],
                )
                .unwrap(),
            "material_sha256" => connection
                .execute(
                    "UPDATE credential_recovery_operations SET material_sha256=?2 WHERE operation_id=?1",
                    (&recovery.operation_id, "0".repeat(64)),
                )
                .unwrap(),
            _ => unreachable!(),
        };
        drop(connection);

        let mut repository = SqliteMetadataRepository::open(&database).unwrap();
        let mut store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();
        assert_eq!(
            CredentialService::new(&mut repository, &mut store)
                .cleanup_recovery(&recovery.operation_id),
            Err(CredentialServiceError::RecoveryRequired),
            "stale {column} must not authorize deletion"
        );
        assert_eq!(store.inspect(&binding).unwrap(), original);
        assert!(
            repository
                .get_credential_recovery(&recovery.operation_id)
                .unwrap()
                .is_some()
        );
    }
}

#[test]
fn credential_fault_matrix_preserves_old_usable_generation_or_recovery_material() {
    let area = TempArea::new("credential-faults");
    let mut repository =
        SqliteMetadataRepository::open(area.root.join("metadata.sqlite3")).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(area.root.join("credentials")).unwrap();
    let journal_blocked_id =
        CredentialRefId::parse("56565656-5656-4656-8656-565656565656").unwrap();
    {
        let mut failing = FailingRepository {
            inner: &mut repository,
            fail_create: false,
            fail_update: false,
            fail_recovery_create: true,
            fail_recovery_update: false,
            fail_recovery_delete: false,
        };
        assert_eq!(
            CredentialService::new(&mut failing, &mut store).create_api_key(
                journal_blocked_id.clone(),
                &mut runtime_secret(),
                UnixMillis::new(1).unwrap(),
            ),
            Err(CredentialServiceError::RepositoryFailure)
        );
    }
    assert!(
        !area
            .root
            .join("credentials")
            .join(journal_blocked_id.as_str())
            .exists()
    );
    let publish_journal_id =
        CredentialRefId::parse("57575757-5757-4757-8757-575757575757").unwrap();
    {
        let mut failing = FailingRepository {
            inner: &mut repository,
            fail_create: false,
            fail_update: false,
            fail_recovery_create: false,
            fail_recovery_update: true,
            fail_recovery_delete: false,
        };
        assert_eq!(
            CredentialService::new(&mut failing, &mut store).create_api_key(
                publish_journal_id.clone(),
                &mut runtime_secret(),
                UnixMillis::new(1).unwrap(),
            ),
            Err(CredentialServiceError::RecoveryRequired)
        );
    }
    let prepared = repository
        .list_credential_recoveries(&publish_journal_id)
        .unwrap();
    assert_eq!(prepared.len(), 1);
    assert_eq!(
        prepared[0].phase,
        codex_application::CredentialRecoveryPhase::Prepared
    );
    assert!(prepared[0].material_hash.is_none());
    assert!(
        area.root
            .join("credentials")
            .join(publish_journal_id.as_str())
            .join("generation-1.dpapi")
            .is_file()
    );
    drop(repository);
    drop(store);
    let mut repository =
        SqliteMetadataRepository::open(area.root.join("metadata.sqlite3")).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(area.root.join("credentials")).unwrap();
    let adopted_publish = CredentialService::new(&mut repository, &mut store)
        .create_api_key(
            publish_journal_id.clone(),
            &mut runtime_secret(),
            UnixMillis::new(2).unwrap(),
        )
        .unwrap();
    assert_eq!(adopted_publish.version().value(), 1);
    assert!(
        repository
            .list_credential_recoveries(&publish_journal_id)
            .unwrap()
            .is_empty()
    );
    let orphan_id = CredentialRefId::parse("55555555-5555-4555-8555-555555555555").unwrap();
    {
        let mut failing = FailingRepository {
            inner: &mut repository,
            fail_create: true,
            fail_update: false,
            fail_recovery_create: false,
            fail_recovery_update: false,
            fail_recovery_delete: false,
        };
        assert_eq!(
            CredentialService::new(&mut failing, &mut store).create_api_key(
                orphan_id.clone(),
                &mut runtime_secret(),
                UnixMillis::new(1).unwrap()
            ),
            Err(CredentialServiceError::RecoveryRequired)
        );
    }
    assert!(
        area.root
            .join("credentials")
            .join(orphan_id.as_str())
            .join("generation-1.dpapi")
            .is_file()
    );
    let diagnostics = repository.list_credential_recoveries(&orphan_id).unwrap();
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        diagnostics[0].phase,
        codex_application::CredentialRecoveryPhase::RecoveryRequired
    );
    let diagnostic_text = format!("{:?}", diagnostics[0]);
    let marker = runtime_secret();
    assert!(!diagnostic_text.contains(std::str::from_utf8(&marker).unwrap()));
    drop(repository);
    drop(store);
    let mut repository =
        SqliteMetadataRepository::open(area.root.join("metadata.sqlite3")).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(area.root.join("credentials")).unwrap();
    let adopted = CredentialService::new(&mut repository, &mut store)
        .create_api_key(
            orphan_id.clone(),
            &mut runtime_secret(),
            UnixMillis::new(2).unwrap(),
        )
        .unwrap();
    assert_eq!(adopted.version().value(), 1);
    assert!(
        repository
            .list_credential_recoveries(&orphan_id)
            .unwrap()
            .is_empty()
    );

    let id = CredentialRefId::parse("66666666-6666-4666-8666-666666666666").unwrap();
    let first = CredentialService::new(&mut repository, &mut store)
        .create_api_key(
            id.clone(),
            &mut runtime_secret(),
            UnixMillis::new(2).unwrap(),
        )
        .unwrap();
    let mut rotated = runtime_secret();
    rotated.push(b'X');
    {
        let mut failing = FailingRepository {
            inner: &mut repository,
            fail_create: false,
            fail_update: true,
            fail_recovery_create: false,
            fail_recovery_update: false,
            fail_recovery_delete: false,
        };
        assert_eq!(
            CredentialService::new(&mut failing, &mut store).rotate_credential(
                &id,
                first.version(),
                &mut rotated,
                UnixMillis::new(3).unwrap()
            ),
            Err(CredentialServiceError::RecoveryRequired)
        );
    }
    let persisted = repository.get_credential_reference(&id).unwrap().unwrap();
    assert_eq!(persisted.version(), first.version());
    let mut consumer = HashConsumer {
        hash: None,
        length: 0,
    };
    store
        .read(
            &CredentialEnvelopeBinding::new(
                id.clone(),
                first.kind(),
                first.schema_fingerprint().clone(),
                first.version(),
            ),
            &mut consumer,
        )
        .unwrap();
    assert!(
        area.root
            .join("credentials")
            .join(id.as_str())
            .join("generation-2.dpapi")
            .is_file()
    );
    let diagnostics = repository.list_credential_recoveries(&id).unwrap();
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        diagnostics[0].phase,
        codex_application::CredentialRecoveryPhase::RecoveryRequired
    );
    drop(repository);
    drop(store);
    let mut repository =
        SqliteMetadataRepository::open(area.root.join("metadata.sqlite3")).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(area.root.join("credentials")).unwrap();
    let mut retry = runtime_secret();
    retry.push(b'X');
    let adopted_rotation = CredentialService::new(&mut repository, &mut store)
        .rotate_credential(
            &id,
            first.version(),
            &mut retry,
            UnixMillis::new(4).unwrap(),
        )
        .unwrap();
    assert_eq!(adopted_rotation.version().value(), 2);
    assert!(
        repository
            .list_credential_recoveries(&id)
            .unwrap()
            .is_empty()
    );
    let db = fs::read(database_path(&area.root)).unwrap();
    let marker = runtime_secret();
    assert!(!db.windows(marker.len()).any(|window| window == marker));
    println!(
        "M24_CREDENTIAL_FAULT journal_unavailable=filesystem_unchanged publish_journal=prepared_reopen_adopt create_metadata=persistent_recovery rotate_metadata=persistent_recovery reopen_adopt=idempotent diagnostics=redacted sqlite_secret=false"
    );
}

#[test]
fn credential_service_mutations_have_cross_connection_single_ownership() {
    let area = TempArea::new("credential-service-concurrency");
    let database = area.root.join("metadata.sqlite3");
    let credential_root = area.root.join("credentials");
    drop(SqliteMetadataRepository::open(&database).unwrap());
    let id = CredentialRefId::parse("58585858-5858-4858-8858-585858585858").unwrap();

    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for suffix in *b"XY" {
        let database = database.clone();
        let credential_root = credential_root.clone();
        let id = id.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let mut repository = SqliteMetadataRepository::open(database).unwrap();
            let mut store = WindowsDpapiCredentialStore::new(credential_root).unwrap();
            let mut secret = runtime_secret();
            secret.push(suffix);
            barrier.wait();
            CredentialService::new(&mut repository, &mut store).create_api_key(
                id,
                &mut secret,
                UnixMillis::new(10).unwrap(),
            )
        }));
    }
    barrier.wait();
    let create_results = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        create_results
            .iter()
            .filter(|result| result.is_ok())
            .count(),
        1
    );

    let repository = SqliteMetadataRepository::open(&database).unwrap();
    let first = repository.get_credential_reference(&id).unwrap().unwrap();
    assert!(
        repository
            .list_credential_recoveries(&id)
            .unwrap()
            .is_empty()
    );
    drop(repository);

    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for suffix in *b"RS" {
        let database = database.clone();
        let credential_root = credential_root.clone();
        let id = id.clone();
        let barrier = Arc::clone(&barrier);
        let version = first.version();
        handles.push(thread::spawn(move || {
            let mut repository = SqliteMetadataRepository::open(database).unwrap();
            let mut store = WindowsDpapiCredentialStore::new(credential_root).unwrap();
            let mut secret = runtime_secret();
            secret.push(suffix);
            barrier.wait();
            CredentialService::new(&mut repository, &mut store).rotate_credential(
                &id,
                version,
                &mut secret,
                UnixMillis::new(11).unwrap(),
            )
        }));
    }
    barrier.wait();
    let rotate_results = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        rotate_results
            .iter()
            .filter(|result| result.is_ok())
            .count(),
        1
    );

    let repository = SqliteMetadataRepository::open(&database).unwrap();
    let second = repository.get_credential_reference(&id).unwrap().unwrap();
    assert_eq!(second.version().value(), 2);
    assert!(
        repository
            .list_credential_recoveries(&id)
            .unwrap()
            .is_empty()
    );
    drop(repository);

    let barrier = Arc::new(Barrier::new(3));
    let rotate_barrier = Arc::clone(&barrier);
    let rotate_database = database.clone();
    let rotate_root = credential_root.clone();
    let rotate_id = id.clone();
    let rotate_version = second.version();
    let rotate = thread::spawn(move || {
        let mut repository = SqliteMetadataRepository::open(rotate_database).unwrap();
        let mut store = WindowsDpapiCredentialStore::new(rotate_root).unwrap();
        let mut secret = runtime_secret();
        secret.push(b'T');
        rotate_barrier.wait();
        CredentialService::new(&mut repository, &mut store).rotate_credential(
            &rotate_id,
            rotate_version,
            &mut secret,
            UnixMillis::new(12).unwrap(),
        )
    });
    let delete_barrier = Arc::clone(&barrier);
    let delete_database = database.clone();
    let delete_root = credential_root.clone();
    let delete_id = id.clone();
    let delete_version = second.version();
    let delete = thread::spawn(move || {
        let mut repository = SqliteMetadataRepository::open(delete_database).unwrap();
        let mut store = WindowsDpapiCredentialStore::new(delete_root).unwrap();
        delete_barrier.wait();
        CredentialService::new(&mut repository, &mut store)
            .delete_credential(&delete_id, delete_version)
    });
    barrier.wait();
    let rotate_result = rotate.join().unwrap();
    let delete_result = delete.join().unwrap();
    assert_eq!(
        usize::from(rotate_result.is_ok()) + usize::from(delete_result.is_ok()),
        1
    );

    let repository = SqliteMetadataRepository::open(&database).unwrap();
    assert!(
        repository
            .list_credential_recoveries(&id)
            .unwrap()
            .is_empty()
    );
    let metadata = repository.get_credential_reference(&id).unwrap();
    match metadata {
        Some(reference) => {
            assert_eq!(reference.version().value(), 3);
            let store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();
            assert!(
                store
                    .inspect(&CredentialEnvelopeBinding::new(
                        id.clone(),
                        reference.kind(),
                        reference.schema_fingerprint().clone(),
                        reference.version(),
                    ))
                    .is_ok()
            );
        }
        None => assert!(!credential_root.join(id.as_str()).exists()),
    }
    println!(
        "M24_CREDENTIAL_SERVICE_CONCURRENCY create_create=single_owner rotate_rotate=single_owner rotate_delete=single_owner shared_intent_cleared_by_loser=false reopen_converged=true"
    );
}

#[test]
fn reused_create_and_rotate_intents_reject_different_secret_without_losing_recovery() {
    let area = TempArea::new("credential-reused-intent-secret");
    let database = area.root.join("metadata.sqlite3");
    let credential_root = area.root.join("credentials");
    let mut repository = SqliteMetadataRepository::open(&database).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();

    let create_prepared_id =
        CredentialRefId::parse("22222222-2222-4222-8222-222222222222").unwrap();
    let create_original = runtime_secret();
    {
        let mut failing = FailingRepository {
            inner: &mut repository,
            fail_create: false,
            fail_update: false,
            fail_recovery_create: false,
            fail_recovery_update: true,
            fail_recovery_delete: false,
        };
        assert_eq!(
            CredentialService::new(&mut failing, &mut store).create_api_key(
                create_prepared_id.clone(),
                &mut create_original.clone(),
                UnixMillis::new(10).unwrap(),
            ),
            Err(CredentialServiceError::RecoveryRequired)
        );
    }
    let create_prepared = repository
        .list_credential_recoveries(&create_prepared_id)
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(create_prepared.phase, CredentialRecoveryPhase::Prepared);
    assert!(create_prepared.material_hash.is_none());
    let create_prepared_material =
        fs::read(credential_root.join(&create_prepared.material_ref)).unwrap();
    let mut different = create_original.clone();
    different.push(b'Q');
    assert_eq!(
        CredentialService::new(&mut repository, &mut store).create_api_key(
            create_prepared_id.clone(),
            &mut different,
            UnixMillis::new(11).unwrap(),
        ),
        Err(CredentialServiceError::RecoveryRequired)
    );
    assert_eq!(
        repository
            .get_credential_recovery(&create_prepared.operation_id)
            .unwrap()
            .unwrap(),
        create_prepared
    );
    assert_eq!(
        fs::read(credential_root.join(&create_prepared.material_ref)).unwrap(),
        create_prepared_material
    );
    assert!(
        repository
            .get_credential_reference(&create_prepared_id)
            .unwrap()
            .is_none()
    );
    CredentialService::new(&mut repository, &mut store)
        .create_api_key(
            create_prepared_id.clone(),
            &mut create_original.clone(),
            UnixMillis::new(12).unwrap(),
        )
        .unwrap();

    let create_published_id =
        CredentialRefId::parse("23232323-2323-4323-8323-232323232323").unwrap();
    let create_published_original = runtime_secret();
    {
        let mut failing = FailingRepository {
            inner: &mut repository,
            fail_create: true,
            fail_update: false,
            fail_recovery_create: false,
            fail_recovery_update: false,
            fail_recovery_delete: false,
        };
        assert_eq!(
            CredentialService::new(&mut failing, &mut store).create_api_key(
                create_published_id.clone(),
                &mut create_published_original.clone(),
                UnixMillis::new(20).unwrap(),
            ),
            Err(CredentialServiceError::RecoveryRequired)
        );
    }
    let create_published = repository
        .list_credential_recoveries(&create_published_id)
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(
        create_published.phase,
        CredentialRecoveryPhase::RecoveryRequired
    );
    assert!(create_published.material_hash.is_some());
    let create_published_material =
        fs::read(credential_root.join(&create_published.material_ref)).unwrap();
    let mut different = create_published_original.clone();
    different.push(b'R');
    assert_eq!(
        CredentialService::new(&mut repository, &mut store).create_api_key(
            create_published_id.clone(),
            &mut different,
            UnixMillis::new(21).unwrap(),
        ),
        Err(CredentialServiceError::RecoveryRequired)
    );
    assert_eq!(
        repository
            .get_credential_recovery(&create_published.operation_id)
            .unwrap()
            .unwrap(),
        create_published
    );
    assert_eq!(
        fs::read(credential_root.join(&create_published.material_ref)).unwrap(),
        create_published_material
    );
    CredentialService::new(&mut repository, &mut store)
        .create_api_key(
            create_published_id.clone(),
            &mut create_published_original.clone(),
            UnixMillis::new(22).unwrap(),
        )
        .unwrap();

    let rotate_prepared_id =
        CredentialRefId::parse("24242424-2424-4424-8424-242424242424").unwrap();
    let rotate_prepared_base = CredentialService::new(&mut repository, &mut store)
        .create_api_key(
            rotate_prepared_id.clone(),
            &mut runtime_secret(),
            UnixMillis::new(30).unwrap(),
        )
        .unwrap();
    let mut rotate_prepared_original = runtime_secret();
    rotate_prepared_original.push(b'S');
    {
        let mut failing = FailingRepository {
            inner: &mut repository,
            fail_create: false,
            fail_update: false,
            fail_recovery_create: false,
            fail_recovery_update: true,
            fail_recovery_delete: false,
        };
        assert_eq!(
            CredentialService::new(&mut failing, &mut store).rotate_credential(
                &rotate_prepared_id,
                rotate_prepared_base.version(),
                &mut rotate_prepared_original.clone(),
                UnixMillis::new(31).unwrap(),
            ),
            Err(CredentialServiceError::RecoveryRequired)
        );
    }
    let rotate_prepared = repository
        .list_credential_recoveries(&rotate_prepared_id)
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(rotate_prepared.phase, CredentialRecoveryPhase::Prepared);
    assert!(rotate_prepared.material_hash.is_none());
    let rotate_prepared_material =
        fs::read(credential_root.join(&rotate_prepared.material_ref)).unwrap();
    let mut different = rotate_prepared_original.clone();
    different.push(b'T');
    assert_eq!(
        CredentialService::new(&mut repository, &mut store).rotate_credential(
            &rotate_prepared_id,
            rotate_prepared_base.version(),
            &mut different,
            UnixMillis::new(32).unwrap(),
        ),
        Err(CredentialServiceError::RecoveryRequired)
    );
    assert_eq!(
        repository
            .get_credential_recovery(&rotate_prepared.operation_id)
            .unwrap()
            .unwrap(),
        rotate_prepared
    );
    assert_eq!(
        fs::read(credential_root.join(&rotate_prepared.material_ref)).unwrap(),
        rotate_prepared_material
    );
    assert_eq!(
        repository
            .get_credential_reference(&rotate_prepared_id)
            .unwrap()
            .unwrap(),
        rotate_prepared_base
    );
    CredentialService::new(&mut repository, &mut store)
        .rotate_credential(
            &rotate_prepared_id,
            rotate_prepared_base.version(),
            &mut rotate_prepared_original.clone(),
            UnixMillis::new(33).unwrap(),
        )
        .unwrap();

    let rotate_published_id =
        CredentialRefId::parse("25252525-2525-4525-8525-252525252525").unwrap();
    let rotate_published_base = CredentialService::new(&mut repository, &mut store)
        .create_api_key(
            rotate_published_id.clone(),
            &mut runtime_secret(),
            UnixMillis::new(40).unwrap(),
        )
        .unwrap();
    let mut rotate_published_original = runtime_secret();
    rotate_published_original.push(b'U');
    {
        let mut failing = FailingRepository {
            inner: &mut repository,
            fail_create: false,
            fail_update: true,
            fail_recovery_create: false,
            fail_recovery_update: false,
            fail_recovery_delete: false,
        };
        assert_eq!(
            CredentialService::new(&mut failing, &mut store).rotate_credential(
                &rotate_published_id,
                rotate_published_base.version(),
                &mut rotate_published_original.clone(),
                UnixMillis::new(41).unwrap(),
            ),
            Err(CredentialServiceError::RecoveryRequired)
        );
    }
    let rotate_published = repository
        .list_credential_recoveries(&rotate_published_id)
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(
        rotate_published.phase,
        CredentialRecoveryPhase::RecoveryRequired
    );
    assert!(rotate_published.material_hash.is_some());
    let rotate_published_material =
        fs::read(credential_root.join(&rotate_published.material_ref)).unwrap();
    let mut different = rotate_published_original.clone();
    different.push(b'V');
    assert_eq!(
        CredentialService::new(&mut repository, &mut store).rotate_credential(
            &rotate_published_id,
            rotate_published_base.version(),
            &mut different,
            UnixMillis::new(42).unwrap(),
        ),
        Err(CredentialServiceError::RecoveryRequired)
    );
    assert_eq!(
        repository
            .get_credential_recovery(&rotate_published.operation_id)
            .unwrap()
            .unwrap(),
        rotate_published
    );
    assert_eq!(
        fs::read(credential_root.join(&rotate_published.material_ref)).unwrap(),
        rotate_published_material
    );
    assert_eq!(
        repository
            .get_credential_reference(&rotate_published_id)
            .unwrap()
            .unwrap(),
        rotate_published_base
    );
    CredentialService::new(&mut repository, &mut store)
        .rotate_credential(
            &rotate_published_id,
            rotate_published_base.version(),
            &mut rotate_published_original.clone(),
            UnixMillis::new(43).unwrap(),
        )
        .unwrap();

    for id in [
        create_prepared_id,
        create_published_id,
        rotate_prepared_id,
        rotate_published_id,
    ] {
        assert!(
            repository
                .list_credential_recoveries(&id)
                .unwrap()
                .is_empty()
        );
        assert!(repository.get_credential_reference(&id).unwrap().is_some());
    }
    println!(
        "M24_REUSED_INTENT_SECRET create_prepared=protected create_published=protected rotate_prepared=protected rotate_published=protected original_retry=converged journal=0 orphan=0"
    );
}

fn database_path(root: &Path) -> PathBuf {
    root.join("metadata.sqlite3")
}
