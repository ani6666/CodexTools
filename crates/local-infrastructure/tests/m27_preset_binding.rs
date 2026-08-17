#![allow(unused_crate_dependencies)]

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Barrier,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use codex_application::{
    CreatePresetAndBindCommand, CreatePresetAndBindInput, CredentialReferenceRepository,
    M27_SERVICE_VERSION, ModelPresetRepository, PresetBindingError, PresetBindingOutcome,
    PresetBindingRepositoryError, PresetBindingService, RuntimeIdentityRepository,
    UpdatePresetAndBindCommand, UpdatePresetAndBindInput,
};
use codex_domain::{
    CredentialBackend, CredentialFingerprint, CredentialKind, CredentialRefId, CredentialReference,
    DomainError, EndpointUrl, EntityName, EntityVersion, IdentityId, ModelId, ModelPreset,
    ModelPresetId, ProviderId, RuntimeIdentity, SchemaFingerprint, UnixMillis,
};
use local_infrastructure::{
    PresetBindingFaultPoint, PresetBindingFaults, SqliteMetadataRepository,
};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

struct TempDatabase(PathBuf);

impl TempDatabase {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "codextools-m27-{}-{nonce}-{sequence}.sqlite3",
            std::process::id()
        )))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDatabase {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let _ = fs::remove_file(format!("{}{}", self.0.display(), suffix));
        }
    }
}

fn time(value: i64) -> UnixMillis {
    UnixMillis::new(value).expect("valid time")
}

fn version(value: u64) -> EntityVersion {
    EntityVersion::new(value).expect("valid version")
}

fn identity_id() -> IdentityId {
    IdentityId::parse("11111111-1111-4111-8111-111111111111").unwrap()
}

fn preset_id() -> ModelPresetId {
    ModelPresetId::parse("33333333-3333-4333-8333-333333333333").unwrap()
}

fn credential() -> CredentialReference {
    CredentialReference::new(
        CredentialRefId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
        CredentialKind::ApiKey,
        CredentialBackend::WindowsDpapiCurrentUser,
        SchemaFingerprint::parse(&"a".repeat(64)).unwrap(),
        CredentialFingerprint::parse(&"b".repeat(64)).unwrap(),
        time(1_000),
    )
}

fn draft_identity(credential: &CredentialReference) -> RuntimeIdentity {
    RuntimeIdentity::new_draft(
        identity_id(),
        EntityName::parse("日常身份").unwrap(),
        ProviderId::parse("sample-provider").unwrap(),
        EntityName::parse("Sample Provider").unwrap(),
        EndpointUrl::parse("https://HOST/v1").unwrap(),
        None,
        credential.link(),
        time(1_000),
    )
    .unwrap()
}

fn seeded_repository(database: &TempDatabase) -> SqliteMetadataRepository {
    let credential = credential();
    let identity = draft_identity(&credential);
    let mut repository = SqliteMetadataRepository::open(database.path()).unwrap();
    repository.create_credential_reference(&credential).unwrap();
    repository.create_runtime_identity(&identity).unwrap();
    repository
}

fn create_input() -> CreatePresetAndBindInput {
    CreatePresetAndBindInput {
        service_version: M27_SERVICE_VERSION,
        identity_id: identity_id(),
        expected_identity_version: version(1),
        preset_id: preset_id(),
        name: EntityName::parse("日常").unwrap(),
        model_id: ModelId::parse("sample/gpt-v1").unwrap(),
        now: time(2_000),
    }
}

fn create_command() -> CreatePresetAndBindCommand {
    let input = create_input();
    CreatePresetAndBindCommand {
        identity_id: input.identity_id.clone(),
        expected_identity_version: input.expected_identity_version,
        preset: ModelPreset::new_managed(
            input.preset_id,
            input.identity_id,
            input.name,
            input.model_id,
            input.now,
        )
        .unwrap(),
        now: input.now,
    }
}

fn update_input(name: &str, model: &str) -> UpdatePresetAndBindInput {
    UpdatePresetAndBindInput {
        service_version: M27_SERVICE_VERSION,
        identity_id: identity_id(),
        expected_identity_version: version(2),
        preset_id: preset_id(),
        expected_preset_version: version(1),
        name: EntityName::parse(name).unwrap(),
        model_id: ModelId::parse(model).unwrap(),
        now: time(3_000),
    }
}

fn update_command(name: &str, model: &str) -> UpdatePresetAndBindCommand {
    let input = update_input(name, model);
    UpdatePresetAndBindCommand {
        identity_id: input.identity_id,
        expected_identity_version: input.expected_identity_version,
        preset_id: input.preset_id,
        expected_preset_version: input.expected_preset_version,
        name: input.name,
        model_id: input.model_id,
        now: input.now,
    }
}

struct FailOnceAt {
    point: PresetBindingFaultPoint,
    fired: bool,
}

impl FailOnceAt {
    const fn new(point: PresetBindingFaultPoint) -> Self {
        Self {
            point,
            fired: false,
        }
    }
}

impl PresetBindingFaults for FailOnceAt {
    fn should_fail(&mut self, point: PresetBindingFaultPoint) -> bool {
        if !self.fired && point == self.point {
            self.fired = true;
            true
        } else {
            false
        }
    }
}

#[test]
fn create_and_bind_commits_one_consistent_aggregate_and_is_idempotent() {
    let database = TempDatabase::new();
    let mut repository = seeded_repository(&database);

    let first = PresetBindingService::new(&mut repository)
        .create_and_bind(create_input())
        .unwrap();
    let PresetBindingOutcome::Applied(summary) = first else {
        panic!("first request must apply")
    };
    assert_eq!(summary.identity_version, version(2));
    assert_eq!(summary.preset_version, version(1));

    let repeated = PresetBindingService::new(&mut repository)
        .create_and_bind(create_input())
        .unwrap();
    assert!(matches!(repeated, PresetBindingOutcome::AlreadyApplied(_)));

    drop(repository);
    let repository = SqliteMetadataRepository::open(database.path()).unwrap();
    let identity = repository
        .get_runtime_identity(&identity_id())
        .unwrap()
        .unwrap();
    assert_eq!(identity.default_model_preset_id(), Some(&preset_id()));
    assert_eq!(identity.version(), version(2));
}

#[test]
fn update_and_bind_changes_preset_and_identity_together() {
    let database = TempDatabase::new();
    let mut repository = seeded_repository(&database);
    PresetBindingService::new(&mut repository)
        .create_and_bind(create_input())
        .unwrap();

    let outcome = PresetBindingService::new(&mut repository)
        .update_and_bind(update_input("日常更新", "sample/gpt-v2"))
        .unwrap();
    let PresetBindingOutcome::Applied(summary) = outcome else {
        panic!("update must apply")
    };
    assert_eq!(summary.identity_version, version(3));
    assert_eq!(summary.preset_version, version(2));
}

#[test]
fn update_and_bind_can_bind_an_existing_unbound_owned_preset() {
    let database = TempDatabase::new();
    let mut repository = seeded_repository(&database);
    let preset = ModelPreset::new_managed(
        preset_id(),
        identity_id(),
        EntityName::parse("尚未绑定").unwrap(),
        ModelId::parse("sample/unbound").unwrap(),
        time(1_500),
    )
    .unwrap();
    repository.create_model_preset(&preset).unwrap();

    let outcome = PresetBindingService::new(&mut repository)
        .update_and_bind(UpdatePresetAndBindInput {
            service_version: M27_SERVICE_VERSION,
            identity_id: identity_id(),
            expected_identity_version: version(1),
            preset_id: preset_id(),
            expected_preset_version: version(1),
            name: EntityName::parse("已绑定").unwrap(),
            model_id: ModelId::parse("sample/bound").unwrap(),
            now: time(2_000),
        })
        .unwrap();
    assert!(matches!(outcome, PresetBindingOutcome::Applied(_)));
    let identity = repository
        .get_runtime_identity(&identity_id())
        .unwrap()
        .unwrap();
    assert_eq!(identity.default_model_preset_id(), Some(&preset_id()));
    assert_eq!(identity.version(), version(2));
}

#[test]
fn managed_preset_metadata_rejects_secret_and_path_shapes_without_echo() {
    let database = TempDatabase::new();
    let mut repository = seeded_repository(&database);
    let secret = ["sk", "-", &"x".repeat(24)].concat();
    let error = ModelId::parse(&secret).unwrap_err();
    assert_eq!(error, DomainError::SecretLikeInput);
    assert!(!format!("{error}").contains(&secret));
    assert!(!format!("{error:?}").contains(&secret));

    let mut path_input = create_input();
    path_input.model_id = ModelId::parse("../sample/model").unwrap();
    let error = PresetBindingService::new(&mut repository)
        .create_and_bind(path_input)
        .unwrap_err();
    assert!(!format!("{error}").contains("../sample/model"));

    let mut path_name = create_input();
    path_name.name = EntityName::parse("folder/preset").unwrap();
    assert_eq!(
        PresetBindingService::new(&mut repository)
            .create_and_bind(path_name)
            .unwrap_err(),
        PresetBindingError::Validation
    );
}

#[test]
fn unsupported_service_version_fails_without_writes() {
    let database = TempDatabase::new();
    let mut repository = seeded_repository(&database);
    let mut input = create_input();
    input.service_version = M27_SERVICE_VERSION + 1;
    PresetBindingService::new(&mut repository)
        .create_and_bind(input)
        .unwrap_err();
    drop(repository);

    let repository = SqliteMetadataRepository::open(database.path()).unwrap();
    let identity = repository
        .get_runtime_identity(&identity_id())
        .unwrap()
        .unwrap();
    assert_eq!(identity.default_model_preset_id(), None);
}

#[test]
fn create_fault_matrix_rolls_back_or_reports_unknown_committed_outcome_after_reopen() {
    let precommit = [
        PresetBindingFaultPoint::AfterPresetWrite,
        PresetBindingFaultPoint::BeforeIdentityWrite,
        PresetBindingFaultPoint::AfterIdentityWrite,
        PresetBindingFaultPoint::BeforeCommit,
    ];
    for point in precommit {
        let database = TempDatabase::new();
        let mut repository = seeded_repository(&database);
        let error = repository
            .create_preset_and_bind_with_faults(create_command(), &mut FailOnceAt::new(point))
            .unwrap_err();
        assert_eq!(error, PresetBindingRepositoryError::StorageUnavailable);
        drop(repository);

        let repository = SqliteMetadataRepository::open(database.path()).unwrap();
        let identity = repository
            .get_runtime_identity(&identity_id())
            .unwrap()
            .unwrap();
        assert_eq!(identity.version(), version(1), "fault_matrix {point:?}");
        assert_eq!(identity.default_model_preset_id(), None);
        assert_eq!(repository.get_model_preset(&preset_id()).unwrap(), None);
    }

    let database = TempDatabase::new();
    let mut repository = seeded_repository(&database);
    let error = repository
        .create_preset_and_bind_with_faults(
            create_command(),
            &mut FailOnceAt::new(PresetBindingFaultPoint::CommitOutcomeUnknown),
        )
        .unwrap_err();
    assert_eq!(error, PresetBindingRepositoryError::RecoveryRequired);
    drop(repository);

    let mut reopened = SqliteMetadataRepository::open(database.path()).unwrap();
    let identity = reopened
        .get_runtime_identity(&identity_id())
        .unwrap()
        .unwrap();
    assert_eq!(identity.version(), version(2));
    assert_eq!(identity.default_model_preset_id(), Some(&preset_id()));
    assert!(matches!(
        PresetBindingService::new(&mut reopened)
            .create_and_bind(create_input())
            .unwrap(),
        PresetBindingOutcome::AlreadyApplied(_)
    ));
}

#[test]
fn update_fault_matrix_preserves_old_aggregate_or_commits_both_after_reopen() {
    let precommit = [
        PresetBindingFaultPoint::AfterPresetWrite,
        PresetBindingFaultPoint::BeforeIdentityWrite,
        PresetBindingFaultPoint::AfterIdentityWrite,
        PresetBindingFaultPoint::BeforeCommit,
    ];
    for point in precommit {
        let database = TempDatabase::new();
        let mut repository = seeded_repository(&database);
        PresetBindingService::new(&mut repository)
            .create_and_bind(create_input())
            .unwrap();
        let error = repository
            .update_preset_and_bind_with_faults(
                update_command("更新", "sample/gpt-v2"),
                &mut FailOnceAt::new(point),
            )
            .unwrap_err();
        assert_eq!(error, PresetBindingRepositoryError::StorageUnavailable);
        drop(repository);

        let repository = SqliteMetadataRepository::open(database.path()).unwrap();
        let identity = repository
            .get_runtime_identity(&identity_id())
            .unwrap()
            .unwrap();
        let preset = repository.get_model_preset(&preset_id()).unwrap().unwrap();
        assert_eq!(identity.version(), version(2), "fault_matrix {point:?}");
        assert_eq!(preset.version(), version(1));
        assert_eq!(preset.model_id().as_str(), "sample/gpt-v1");
    }

    let database = TempDatabase::new();
    let mut repository = seeded_repository(&database);
    PresetBindingService::new(&mut repository)
        .create_and_bind(create_input())
        .unwrap();
    let error = repository
        .update_preset_and_bind_with_faults(
            update_command("更新", "sample/gpt-v2"),
            &mut FailOnceAt::new(PresetBindingFaultPoint::CommitOutcomeUnknown),
        )
        .unwrap_err();
    assert_eq!(error, PresetBindingRepositoryError::RecoveryRequired);
    drop(repository);

    let mut reopened = SqliteMetadataRepository::open(database.path()).unwrap();
    let identity = reopened
        .get_runtime_identity(&identity_id())
        .unwrap()
        .unwrap();
    let preset = reopened.get_model_preset(&preset_id()).unwrap().unwrap();
    assert_eq!(identity.version(), version(3));
    assert_eq!(preset.version(), version(2));
    assert_eq!(preset.model_id().as_str(), "sample/gpt-v2");
    assert!(matches!(
        PresetBindingService::new(&mut reopened)
            .update_and_bind(update_input("更新", "sample/gpt-v2"))
            .unwrap(),
        PresetBindingOutcome::AlreadyApplied(_)
    ));
}

#[test]
fn missing_stale_unique_and_foreign_requests_fail_without_partial_changes() {
    let empty = TempDatabase::new();
    let mut repository = SqliteMetadataRepository::open(empty.path()).unwrap();
    assert_eq!(
        PresetBindingService::new(&mut repository)
            .create_and_bind(create_input())
            .unwrap_err(),
        PresetBindingError::IdentityNotFound
    );

    let database = TempDatabase::new();
    let mut repository = seeded_repository(&database);
    assert_eq!(
        PresetBindingService::new(&mut repository)
            .update_and_bind(update_input("missing", "sample/gpt-v2"))
            .unwrap_err(),
        PresetBindingError::PresetNotFound
    );
    let mut stale = create_input();
    stale.expected_identity_version = version(2);
    assert_eq!(
        PresetBindingService::new(&mut repository)
            .create_and_bind(stale)
            .unwrap_err(),
        PresetBindingError::Conflict
    );

    let existing = ModelPreset::new_managed(
        ModelPresetId::parse("44444444-4444-4444-8444-444444444444").unwrap(),
        identity_id(),
        EntityName::parse("日常").unwrap(),
        ModelId::parse("sample/other").unwrap(),
        time(1_500),
    )
    .unwrap();
    repository.create_model_preset(&existing).unwrap();
    assert_eq!(
        PresetBindingService::new(&mut repository)
            .create_and_bind(create_input())
            .unwrap_err(),
        PresetBindingError::Conflict
    );
    let identity = repository
        .get_runtime_identity(&identity_id())
        .unwrap()
        .unwrap();
    assert_eq!(identity.default_model_preset_id(), None);

    let foreign_credential = CredentialReference::new(
        CredentialRefId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap(),
        CredentialKind::ApiKey,
        CredentialBackend::WindowsDpapiCurrentUser,
        SchemaFingerprint::parse(&"c".repeat(64)).unwrap(),
        CredentialFingerprint::parse(&"d".repeat(64)).unwrap(),
        time(1_000),
    );
    let foreign_id = IdentityId::parse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").unwrap();
    let foreign_identity = RuntimeIdentity::new_draft(
        foreign_id.clone(),
        EntityName::parse("其他身份").unwrap(),
        ProviderId::parse("sample-provider").unwrap(),
        EntityName::parse("Sample Provider").unwrap(),
        EndpointUrl::parse("https://HOST/v1").unwrap(),
        None,
        foreign_credential.link(),
        time(1_000),
    )
    .unwrap();
    repository
        .create_credential_reference(&foreign_credential)
        .unwrap();
    repository
        .create_runtime_identity(&foreign_identity)
        .unwrap();
    let foreign_preset_id = ModelPresetId::parse("cccccccc-cccc-4ccc-8ccc-cccccccccccc").unwrap();
    let foreign_preset = ModelPreset::new_managed(
        foreign_preset_id.clone(),
        foreign_id,
        EntityName::parse("foreign").unwrap(),
        ModelId::parse("sample/foreign").unwrap(),
        time(2_000),
    )
    .unwrap();
    repository.create_model_preset(&foreign_preset).unwrap();
    let error = PresetBindingService::new(&mut repository)
        .update_and_bind(UpdatePresetAndBindInput {
            service_version: M27_SERVICE_VERSION,
            identity_id: identity_id(),
            expected_identity_version: version(1),
            preset_id: foreign_preset_id,
            expected_preset_version: version(1),
            name: EntityName::parse("foreign-update").unwrap(),
            model_id: ModelId::parse("sample/foreign-v2").unwrap(),
            now: time(3_000),
        })
        .unwrap_err();
    assert_eq!(error, PresetBindingError::Conflict);
}

#[test]
fn stale_preset_update_rolls_back_identity_cas() {
    let database = TempDatabase::new();
    let mut repository = seeded_repository(&database);
    PresetBindingService::new(&mut repository)
        .create_and_bind(create_input())
        .unwrap();
    let current = repository.get_model_preset(&preset_id()).unwrap().unwrap();
    let externally_updated = current
        .rename(EntityName::parse("外部更新").unwrap(), time(2_500))
        .unwrap();
    repository
        .update_model_preset(&externally_updated, version(1))
        .unwrap();

    assert_eq!(
        PresetBindingService::new(&mut repository)
            .update_and_bind(update_input("M27 更新", "sample/gpt-v2"))
            .unwrap_err(),
        PresetBindingError::Conflict
    );
    let identity = repository
        .get_runtime_identity(&identity_id())
        .unwrap()
        .unwrap();
    assert_eq!(identity.version(), version(2));
    assert_eq!(identity.default_model_preset_id(), Some(&preset_id()));
}

#[test]
fn metadata_canary_matrix_is_rejected_without_display_or_debug_echo() {
    let canaries = [
        ["sk", "-", &"q".repeat(24)].concat(),
        ["gh", "p_", &"r".repeat(24)].concat(),
        ["AK", "IA", &"S".repeat(16)].concat(),
        ["eyJ", "abcdefgh", ".", "ijklmnop", ".", "qrstuvwx"].concat(),
        ["-----BEGIN ", "PRIVATE", " KEY-----"].concat(),
    ];
    for canary in canaries {
        let error = EntityName::parse(&canary).unwrap_err();
        assert_eq!(error, DomainError::SecretLikeInput);
        assert!(!format!("{error}").contains(&canary));
        assert!(!format!("{error:?}").contains(&canary));
    }
    for path in [
        "../sample/model",
        "/sample/model",
        "C:/sample/model",
        "sample//model",
    ] {
        let database = TempDatabase::new();
        let mut repository = seeded_repository(&database);
        let mut input = create_input();
        input.model_id = ModelId::parse(path).unwrap();
        assert_eq!(
            PresetBindingService::new(&mut repository)
                .create_and_bind(input)
                .unwrap_err(),
            PresetBindingError::Validation
        );
    }

    let database = TempDatabase::new();
    let mut repository = seeded_repository(&database);
    PresetBindingService::new(&mut repository)
        .create_and_bind(create_input())
        .unwrap();
    let mut invalid_update = update_input("更新", "../sample/model");
    invalid_update.model_id = ModelId::parse("../sample/model").unwrap();
    assert_eq!(
        PresetBindingService::new(&mut repository)
            .update_and_bind(invalid_update)
            .unwrap_err(),
        PresetBindingError::Validation
    );
}

#[test]
fn timestamp_validation_rolls_back_both_create_and_update() {
    let database = TempDatabase::new();
    let mut repository = seeded_repository(&database);
    let mut create = create_input();
    create.now = time(500);
    assert_eq!(
        PresetBindingService::new(&mut repository)
            .create_and_bind(create)
            .unwrap_err(),
        PresetBindingError::Validation
    );
    assert_eq!(repository.get_model_preset(&preset_id()).unwrap(), None);

    PresetBindingService::new(&mut repository)
        .create_and_bind(create_input())
        .unwrap();
    let mut update = update_input("更新", "sample/gpt-v2");
    update.now = time(1_500);
    assert_eq!(
        PresetBindingService::new(&mut repository)
            .update_and_bind(update)
            .unwrap_err(),
        PresetBindingError::Validation
    );
    let identity = repository
        .get_runtime_identity(&identity_id())
        .unwrap()
        .unwrap();
    let preset = repository.get_model_preset(&preset_id()).unwrap().unwrap();
    assert_eq!(identity.version(), version(2));
    assert_eq!(preset.version(), version(1));
}

#[test]
fn concurrent_different_creates_have_exactly_one_winner_and_one_conflict() {
    let database = TempDatabase::new();
    drop(seeded_repository(&database));
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for (id, name) in [
        ("33333333-3333-4333-8333-333333333333", "并发一"),
        ("44444444-4444-4444-8444-444444444444", "并发二"),
    ] {
        let path = database.path().to_owned();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let mut repository = SqliteMetadataRepository::open(path).unwrap();
            barrier.wait();
            PresetBindingService::new(&mut repository).create_and_bind(CreatePresetAndBindInput {
                service_version: M27_SERVICE_VERSION,
                identity_id: identity_id(),
                expected_identity_version: version(1),
                preset_id: ModelPresetId::parse(id).unwrap(),
                name: EntityName::parse(name).unwrap(),
                model_id: ModelId::parse("sample/concurrent").unwrap(),
                now: time(2_000),
            })
        }));
    }
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Ok(PresetBindingOutcome::Applied(_))))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(PresetBindingError::Conflict)))
            .count(),
        1
    );
}

#[test]
fn concurrent_same_create_and_update_are_applied_once_then_already_applied() {
    let database = TempDatabase::new();
    drop(seeded_repository(&database));
    let run_pair = |update: bool| {
        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let path = database.path().to_owned();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let mut repository = SqliteMetadataRepository::open(path).unwrap();
                barrier.wait();
                if update {
                    PresetBindingService::new(&mut repository)
                        .update_and_bind(update_input("并发更新", "sample/concurrent-v2"))
                } else {
                    PresetBindingService::new(&mut repository).create_and_bind(create_input())
                }
            }));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap().unwrap())
            .collect::<Vec<_>>()
    };
    let create_results = run_pair(false);
    assert_eq!(
        create_results
            .iter()
            .filter(|result| matches!(result, PresetBindingOutcome::Applied(_)))
            .count(),
        1
    );
    assert_eq!(
        create_results
            .iter()
            .filter(|result| matches!(result, PresetBindingOutcome::AlreadyApplied(_)))
            .count(),
        1
    );
    let update_results = run_pair(true);
    assert_eq!(
        update_results
            .iter()
            .filter(|result| matches!(result, PresetBindingOutcome::Applied(_)))
            .count(),
        1
    );
    assert_eq!(
        update_results
            .iter()
            .filter(|result| matches!(result, PresetBindingOutcome::AlreadyApplied(_)))
            .count(),
        1
    );
}

#[test]
fn concurrent_different_updates_have_one_winner_and_one_conflict() {
    let database = TempDatabase::new();
    let mut repository = seeded_repository(&database);
    PresetBindingService::new(&mut repository)
        .create_and_bind(create_input())
        .unwrap();
    drop(repository);
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for (name, model) in [
        ("竞争更新一", "sample/race-v1"),
        ("竞争更新二", "sample/race-v2"),
    ] {
        let path = database.path().to_owned();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let mut repository = SqliteMetadataRepository::open(path).unwrap();
            barrier.wait();
            PresetBindingService::new(&mut repository).update_and_bind(update_input(name, model))
        }));
    }
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Ok(PresetBindingOutcome::Applied(_))))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(PresetBindingError::Conflict)))
            .count(),
        1
    );
}
