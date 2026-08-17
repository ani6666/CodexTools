#![allow(unused_crate_dependencies)]

use std::{
    fs,
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    sync::{Arc, Barrier},
    thread,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use codex_adapter::{CodexAdapter, hash_bytes};
use codex_application::{
    BackupRepository, Clock, CredentialEnvelopeBinding, CredentialReferenceRepository,
    CredentialStore, FileBaseline, ImportIdentityInput, ImportOutcome, MatchStatus,
    ModelPresetRepository, RuntimeIdentityRepository, ScanStatus, StabilityWindow,
    SwitchExecutionError, SwitchTransactionRepository, import_scanned_identity,
    match_actual_identity,
};
use codex_domain::{
    AuthMode, CredentialBackend, CredentialKind, CredentialRefId, CredentialReference, EntityName,
    IdentityId, ManagedConfigPatchId, ModelPreset, ModelPresetId, RuntimeIdentity,
    SwitchTransactionId, SwitchTransactionState, UnixMillis,
};
use local_infrastructure::{
    BackupService, CredentialServiceError, CrossProcessWriteLock, FaultDisposition, FaultInjector,
    FaultPoint, NoBackupFaults, SqliteMetadataRepository, SwitchExecutor, VerticalClosureError,
    VerticalSwitchPlanner,
};
use windows_platform::WindowsDpapiCredentialStore;
use zeroize::Zeroizing;

struct TempArea {
    root: PathBuf,
    live: PathBuf,
    database: PathBuf,
    credentials: PathBuf,
    backups: PathBuf,
}

impl TempArea {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "codextools-m25-{label}-{}-{nonce}",
            std::process::id()
        ));
        let live = root.join("codex-root");
        fs::create_dir_all(&live).unwrap();
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/g1-api-key");
        fs::copy(fixture.join("config.toml"), live.join("config.toml")).unwrap();
        fs::copy(fixture.join("auth.json"), live.join("auth.json")).unwrap();
        Self {
            database: root.join("metadata.sqlite3"),
            credentials: root.join("credentials"),
            backups: root.join("backups"),
            root,
            live,
        }
    }
}

impl Drop for TempArea {
    fn drop(&mut self) {
        make_tree_writable(&self.root);
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[allow(clippy::permissions_set_readonly_false)]
fn make_tree_writable(root: &Path) {
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                make_tree_writable(&path);
            } else if let Ok(metadata) = fs::metadata(&path) {
                let mut permissions = metadata.permissions();
                permissions.set_readonly(false);
                let _ = fs::set_permissions(path, permissions);
            }
        }
    }
}

struct FixedClock(i64);
impl Clock for FixedClock {
    fn now(&self) -> UnixMillis {
        UnixMillis::new(self.0).unwrap()
    }
}

struct NoWait;
impl StabilityWindow for NoWait {
    fn between_observations(&mut self, _: &Path) -> Result<(), SwitchExecutionError> {
        Ok(())
    }
}

struct MutatingWait {
    path: PathBuf,
    bytes: Option<Vec<u8>>,
}
impl StabilityWindow for MutatingWait {
    fn between_observations(&mut self, _: &Path) -> Result<(), SwitchExecutionError> {
        if let Some(bytes) = self.bytes.take() {
            fs::write(&self.path, bytes).unwrap();
        }
        Ok(())
    }
}

#[derive(Default)]
struct NoFault;
impl FaultInjector for NoFault {
    fn check(&mut self, _: FaultPoint) -> Option<FaultDisposition> {
        None
    }
}

struct ScriptedFault(Vec<(FaultPoint, FaultDisposition)>);
impl FaultInjector for ScriptedFault {
    fn check(&mut self, point: FaultPoint) -> Option<FaultDisposition> {
        self.0
            .iter()
            .position(|entry| entry.0 == point)
            .map(|index| self.0.remove(index).1)
    }
}

struct PanickingFault;
impl FaultInjector for PanickingFault {
    fn check(&mut self, point: FaultPoint) -> Option<FaultDisposition> {
        if point == FaultPoint::BeforeLock {
            panic!("SAMPLE vertical consumer panic");
        }
        None
    }
}

struct BlockingFault {
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
}
impl FaultInjector for BlockingFault {
    fn check(&mut self, point: FaultPoint) -> Option<FaultDisposition> {
        if point == FaultPoint::BeforeLock {
            self.entered.wait();
            self.release.wait();
        }
        None
    }
}

#[derive(Clone)]
struct ManagedIdentity {
    credential: CredentialReference,
    identity: RuntimeIdentity,
    preset: ModelPreset,
}

struct Provisioned {
    a: ManagedIdentity,
    b: ManagedIdentity,
    initial_config: Vec<u8>,
    initial_auth_hash: codex_domain::ContentHash,
    initial_config_readonly: bool,
    initial_auth_readonly: bool,
}

fn runtime_auth(suffix: u8) -> Zeroizing<Vec<u8>> {
    let mut secret = Vec::from(&b"sk-"[..]);
    secret.extend((0..40).map(|index| b'A' + (index % 26)));
    secret.push(suffix);
    let mut auth = Vec::from(&b"{\"OPENAI_API_KEY\":\""[..]);
    auth.extend_from_slice(&secret);
    auth.extend_from_slice(b"\"}\n");
    Zeroizing::new(auth)
}

fn tx_id(value: u64) -> SwitchTransactionId {
    SwitchTransactionId::parse(&format!("00000000-0000-4000-8000-{value:012x}")).unwrap()
}

fn baseline(path: &Path) -> FileBaseline {
    let bytes = fs::read(path).unwrap();
    FileBaseline::present(bytes.len() as u64, hash_bytes(&bytes))
}

fn pair(root: &Path) -> (Vec<u8>, Vec<u8>) {
    (
        fs::read(root.join("config.toml")).unwrap(),
        fs::read(root.join("auth.json")).unwrap(),
    )
}

fn pair_readonly(root: &Path) -> (bool, bool) {
    (
        fs::metadata(root.join("config.toml"))
            .unwrap()
            .permissions()
            .readonly(),
        fs::metadata(root.join("auth.json"))
            .unwrap()
            .permissions()
            .readonly(),
    )
}

fn credential_from_state(
    id: &str,
    actual: &codex_application::ActualCodexState,
    now: i64,
) -> CredentialReference {
    CredentialReference::new(
        CredentialRefId::parse(id).unwrap(),
        match actual.authentication.auth_mode {
            AuthMode::ApiKey => CredentialKind::ApiKey,
            AuthMode::OAuth => CredentialKind::OAuthBundle,
        },
        CredentialBackend::WindowsDpapiCurrentUser,
        local_infrastructure::credential_material_schema_fingerprint(
            match actual.authentication.auth_mode {
                AuthMode::ApiKey => CredentialKind::ApiKey,
                AuthMode::OAuth => CredentialKind::OAuthBundle,
            },
        ),
        actual.authentication.credential_fingerprint.clone(),
        UnixMillis::new(now).unwrap(),
    )
}

fn persist_material(
    repository: &mut SqliteMetadataRepository,
    store: &mut WindowsDpapiCredentialStore,
    reference: &CredentialReference,
    auth: &[u8],
) {
    let owner = store.begin_mutation(reference.id()).unwrap();
    let mut controlled = auth.to_vec();
    store
        .create(
            &CredentialEnvelopeBinding::new(
                reference.id().clone(),
                reference.kind(),
                reference.schema_fingerprint().clone(),
                reference.version(),
            ),
            &mut controlled,
        )
        .unwrap();
    store.end_mutation(owner).unwrap();
    repository.create_credential_reference(reference).unwrap();
}

#[allow(clippy::too_many_arguments)]
fn import_identity(
    repository: &mut SqliteMetadataRepository,
    actual: &codex_application::ActualCodexState,
    credential: &CredentialReference,
    identity_id: &str,
    identity_name: &str,
    preset_id: &str,
    patch_id: &str,
    now: i64,
) -> (RuntimeIdentity, ModelPreset) {
    let identity_id = IdentityId::parse(identity_id).unwrap();
    let preset_id = ModelPresetId::parse(preset_id).unwrap();
    let now = UnixMillis::new(now).unwrap();
    assert_eq!(
        import_scanned_identity(
            repository,
            actual,
            ImportIdentityInput {
                identity_id: identity_id.clone(),
                identity_name: EntityName::parse(identity_name).unwrap(),
                preset_id: preset_id.clone(),
                preset_name: EntityName::parse("Active model").unwrap(),
                patch_id: ManagedConfigPatchId::parse(patch_id).unwrap(),
                credential: Some(credential.clone()),
                credential_already_persisted: true,
                now,
            },
        )
        .unwrap(),
        ImportOutcome::Imported
    );
    (
        repository
            .get_runtime_identity(&identity_id)
            .unwrap()
            .unwrap(),
        repository.get_model_preset(&preset_id).unwrap().unwrap(),
    )
}

fn provision(
    area: &TempArea,
    repository: &mut SqliteMetadataRepository,
    store: &mut WindowsDpapiCredentialStore,
) -> Provisioned {
    let initial_config = fs::read(area.live.join("config.toml")).unwrap();
    let initial_auth = Zeroizing::new(fs::read(area.live.join("auth.json")).unwrap());
    let (initial_config_readonly, initial_auth_readonly) = pair_readonly(&area.live);
    let ScanStatus::Ready(actual_a) =
        CodexAdapter::new().scan_memory(&initial_config, &initial_auth)
    else {
        panic!("fixed A state must scan")
    };
    let mut config_b = initial_config.clone();
    let model = b"gpt-SAMPLE-1";
    let offset = config_b
        .windows(model.len())
        .position(|window| window == model)
        .unwrap();
    config_b[offset..offset + model.len()].copy_from_slice(b"gpt-SAMPLE-2");
    let auth_b = runtime_auth(b'Z');
    let ScanStatus::Ready(actual_b) = CodexAdapter::new().scan_memory(&config_b, &auth_b) else {
        panic!("synthetic B state must scan")
    };

    let credential_a = credential_from_state("31313131-3131-4131-8131-313131313131", &actual_a, 10);
    let credential_b = credential_from_state("32323232-3232-4232-8232-323232323232", &actual_b, 11);
    persist_material(repository, store, &credential_a, &initial_auth);
    persist_material(repository, store, &credential_b, &auth_b);
    let (identity_a, preset_a) = import_identity(
        repository,
        &actual_a,
        &credential_a,
        "41414141-4141-4141-8141-414141414141",
        "Imported identity A",
        "51515151-5151-4151-8151-515151515151",
        "61616161-6161-4161-8161-616161616161",
        20,
    );
    let (identity_b, preset_b) = import_identity(
        repository,
        &actual_b,
        &credential_b,
        "42424242-4242-4242-8242-424242424242",
        "Synthetic identity B",
        "52525252-5252-4252-8252-525252525252",
        "62626262-6262-4262-8262-626262626262",
        21,
    );
    Provisioned {
        a: ManagedIdentity {
            credential: credential_a,
            identity: identity_a,
            preset: preset_a,
        },
        b: ManagedIdentity {
            credential: credential_b,
            identity: identity_b,
            preset: preset_b,
        },
        initial_config,
        initial_auth_hash: hash_bytes(&initial_auth),
        initial_config_readonly,
        initial_auth_readonly,
    }
}

fn assert_matches(root: &Path, managed: &ManagedIdentity) {
    let verified = VerticalSwitchPlanner::new()
        .verify_expected(
            root,
            &managed.identity,
            &managed.preset,
            &managed.credential,
        )
        .unwrap();
    assert_eq!(verified.identity_id, *managed.identity.id());
    assert_eq!(verified.model_id, *managed.preset.model_id());
}

fn execute_prepared(
    area: &TempArea,
    credential_repository: &mut SqliteMetadataRepository,
    store: &mut WindowsDpapiCredentialStore,
    prepared: &local_infrastructure::PreparedVerticalSwitch,
    managed: &ManagedIdentity,
    now: i64,
    faults: &mut impl FaultInjector,
) -> Result<local_infrastructure::VerticalExecutionResult, VerticalClosureError> {
    let mut switch_repository = SqliteMetadataRepository::open(&area.database).unwrap();
    VerticalSwitchPlanner::new().execute_restore_from_store(
        credential_repository,
        store,
        &mut switch_repository,
        &FixedClock(now),
        &mut NoWait,
        faults,
        prepared,
        &managed.identity,
        &managed.preset,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_from_store(
    area: &TempArea,
    credential_repository: &mut SqliteMetadataRepository,
    store: &mut WindowsDpapiCredentialStore,
    managed: &ManagedIdentity,
    transaction_id: SwitchTransactionId,
    created_at: i64,
    expires_at: i64,
    now: i64,
    faults: &mut impl FaultInjector,
) -> Result<local_infrastructure::VerticalExecutionResult, VerticalClosureError> {
    execute_from_store_with_stability(
        area,
        credential_repository,
        store,
        managed,
        transaction_id,
        created_at,
        expires_at,
        now,
        &mut NoWait,
        faults,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_from_store_with_stability(
    area: &TempArea,
    credential_repository: &mut SqliteMetadataRepository,
    store: &mut WindowsDpapiCredentialStore,
    managed: &ManagedIdentity,
    transaction_id: SwitchTransactionId,
    created_at: i64,
    expires_at: i64,
    now: i64,
    stability: &mut impl StabilityWindow,
    faults: &mut impl FaultInjector,
) -> Result<local_infrastructure::VerticalExecutionResult, VerticalClosureError> {
    let before_pair = pair(&area.live);
    let before_residue = stage_or_quarantine_paths(&area.root);
    let before_rows = rusqlite::Connection::open(&area.database)
        .unwrap()
        .query_row("SELECT count(*) FROM switch_transactions", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap();
    let planner = VerticalSwitchPlanner::new();
    let intent = planner.preview_from_store(
        credential_repository,
        store,
        &area.live,
        transaction_id,
        &managed.identity,
        &managed.preset,
        managed.credential.id(),
        UnixMillis::new(created_at).unwrap(),
        UnixMillis::new(expires_at).unwrap(),
    )?;
    assert_eq!(pair(&area.live), before_pair);
    assert_eq!(
        rusqlite::Connection::open(&area.database)
            .unwrap()
            .query_row("SELECT count(*) FROM switch_transactions", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
        before_rows
    );
    assert_eq!(stage_or_quarantine_paths(&area.root), before_residue);
    let mut switch_repository = SqliteMetadataRepository::open(&area.database).unwrap();
    planner.execute_approved(
        credential_repository,
        store,
        &mut switch_repository,
        &FixedClock(now),
        stability,
        faults,
        &intent,
        &managed.identity,
        &managed.preset,
    )
}

fn contains_bytes(path: &Path, marker: &[u8]) -> bool {
    if path.is_dir() {
        return fs::read_dir(path)
            .unwrap()
            .flatten()
            .any(|entry| contains_bytes(&entry.path(), marker));
    }
    fs::read(path)
        .map(|bytes| bytes.windows(marker.len()).any(|window| window == marker))
        .unwrap_or(false)
}

fn fragment_hits_except(root: &Path, excluded: &Path, marker: &[u8]) -> usize {
    let secret_start = marker
        .windows(3)
        .position(|window| window == b"sk-")
        .expect("synthetic auth contains secret marker");
    let secret_end = marker[secret_start..]
        .iter()
        .position(|byte| *byte == b'"')
        .map(|offset| secret_start + offset)
        .expect("synthetic auth secret is quoted");
    let secret = &marker[secret_start..secret_end];
    let third = secret.len() / 3;
    let fragments = [
        &secret[..third],
        &secret[third..third * 2],
        &secret[third * 2..],
    ];
    fn visit(path: &Path, excluded: &Path, fragments: &[&[u8]]) -> usize {
        if path == excluded {
            return 0;
        }
        if path.is_dir() {
            return fs::read_dir(path)
                .into_iter()
                .flatten()
                .flatten()
                .map(|entry| visit(&entry.path(), excluded, fragments))
                .sum();
        }
        fs::read(path).ok().is_some_and(|bytes| {
            fragments.iter().any(|fragment| {
                bytes
                    .windows(fragment.len())
                    .any(|window| window == *fragment)
            })
        }) as usize
    }
    visit(root, excluded, &fragments)
}

fn has_stage_or_quarantine(root: &Path) -> bool {
    fs::read_dir(root).unwrap().flatten().any(|entry| {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        name.ends_with(".stage")
            || name.starts_with(".stage-")
            || name.starts_with(".delete-")
            || name.starts_with(".rollback-")
            || (path.is_dir() && has_stage_or_quarantine(&path))
    })
}

fn stage_or_quarantine_paths(root: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".stage")
                || name.starts_with(".stage-")
                || name.starts_with(".delete-")
                || name.starts_with(".rollback-")
            {
                paths.push(path.clone());
            }
            if path.is_dir() {
                paths.extend(stage_or_quarantine_paths(&path));
            }
        }
    }
    paths.sort();
    paths
}

#[test]
fn vertical_scan_import_create_preview_switch_verify_and_restore() {
    let area = TempArea::new("vertical-closure");
    let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(&area.credentials).unwrap();
    let provisioned = provision(&area, &mut repository, &mut store);
    let planner = VerticalSwitchPlanner::new();
    assert_eq!(
        match_actual_identity(
            &repository,
            &CodexAdapter::new().scan_explicit_root(&area.live)
        )
        .unwrap(),
        MatchStatus::UniqueMatch(provisioned.a.identity.id().clone())
    );
    let permanent = BackupService::new(&mut repository, &mut NoBackupFaults)
        .create_permanent(
            &area.live,
            &area.backups,
            "permanent-initial",
            UnixMillis::new(30).unwrap(),
        )
        .unwrap();
    let history = BackupService::new(&mut repository, &mut NoBackupFaults)
        .create_history(
            &area.live,
            &area.backups,
            "history-before-b",
            None,
            false,
            UnixMillis::new(31).unwrap(),
        )
        .unwrap();
    let switched = execute_from_store(
        &area,
        &mut repository,
        &mut store,
        &provisioned.b,
        tx_id(1),
        100,
        200,
        150,
        &mut NoFault,
    )
    .unwrap();
    let preview = format!("{:?}", switched.preview);
    assert!(!preview.contains("sk-"));
    assert_eq!(switched.preview.credential_fingerprint_prefix().len(), 8);
    assert!(switched.preview.diff().iter().all(|line| !line.is_empty()));
    assert_eq!(
        switched.transaction.transaction.state(),
        SwitchTransactionState::Committed
    );
    assert_matches(&area.live, &provisioned.b);
    assert_eq!(
        match_actual_identity(
            &repository,
            &CodexAdapter::new().scan_explicit_root(&area.live)
        )
        .unwrap(),
        MatchStatus::UniqueMatch(provisioned.b.identity.id().clone())
    );

    let restore_target = BackupService::new(&mut repository, &mut NoBackupFaults)
        .plan_restore(
            &area.live,
            &area.backups,
            &history,
            &baseline(&area.live.join("config.toml")),
            &baseline(&area.live.join("auth.json")),
            UnixMillis::new(160).unwrap(),
            UnixMillis::new(260).unwrap(),
            UnixMillis::new(170).unwrap(),
        )
        .unwrap();
    let restore = planner
        .prepare_restore(
            &area.live,
            tx_id(2),
            restore_target,
            &provisioned.a.identity,
            &provisioned.a.preset,
            &provisioned.a.credential,
            UnixMillis::new(160).unwrap(),
            UnixMillis::new(260).unwrap(),
        )
        .unwrap();
    execute_prepared(
        &area,
        &mut repository,
        &mut store,
        &restore,
        &provisioned.a,
        170,
        &mut NoFault,
    )
    .unwrap();
    assert_eq!(
        hash_bytes(&pair(&area.live).0),
        hash_bytes(&provisioned.initial_config)
    );
    assert_eq!(
        hash_bytes(&pair(&area.live).1),
        provisioned.initial_auth_hash
    );
    assert_eq!(
        pair_readonly(&area.live),
        (
            provisioned.initial_config_readonly,
            provisioned.initial_auth_readonly
        )
    );
    assert_eq!(permanent.kind, codex_application::BackupKind::Permanent);
    let marker = runtime_auth(b'Z');
    assert!(!contains_bytes(&area.root, &marker));
    assert_eq!(
        fragment_hits_except(&area.root, &area.live.join("auth.json"), &marker),
        0
    );
    assert!(!has_stage_or_quarantine(&area.root));
    println!(
        "M25_VERTICAL_CLOSURE scan=ready import_a=unique create_b=ready preview=redacted switch=committed reread=verified restore_previous=committed hashes=initial readonly=initial"
    );
    println!(
        "M25_SECRET_SCAN preview_secret=false sqlite_secret=false envelope_secret=false backup_manifest_secret=false error_debug_secret=false residue=0"
    );
    println!(
        "M25_ROLE_HASH source_config={} source_auth={} target_config={} target_auth={} restore_config={} restore_auth={} source_readonly={}/{} restore_readonly={}/{}",
        hash_bytes(&fs::read(area.live.join("config.toml")).unwrap()).as_str(),
        &hash_bytes(&fs::read(area.live.join("auth.json")).unwrap()).as_str()[..8],
        switched.preview.config_target().as_str(),
        switched.preview.auth_target_prefix(),
        hash_bytes(&fs::read(area.live.join("config.toml")).unwrap()).as_str(),
        &hash_bytes(&fs::read(area.live.join("auth.json")).unwrap()).as_str()[..8],
        provisioned.initial_config_readonly,
        provisioned.initial_auth_readonly,
        pair_readonly(&area.live).0,
        pair_readonly(&area.live).1,
    );
}

#[test]
fn one_hundred_real_switches_reopen_and_restore_initial_pair() {
    let started = Instant::now();
    let area = TempArea::new("hundred-switches");
    let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(&area.credentials).unwrap();
    let provisioned = provision(&area, &mut repository, &mut store);
    let permanent = BackupService::new(&mut repository, &mut NoBackupFaults)
        .create_permanent(
            &area.live,
            &area.backups,
            "permanent-initial-100",
            UnixMillis::new(1000).unwrap(),
        )
        .unwrap();
    let planner = VerticalSwitchPlanner::new();
    for iteration in 1..=100_u64 {
        let target = if iteration % 2 == 1 {
            &provisioned.b
        } else {
            &provisioned.a
        };
        let transaction_id = tx_id(1000 + iteration);
        BackupService::new(&mut repository, &mut NoBackupFaults)
            .create_history(
                &area.live,
                &area.backups,
                &format!("history-{iteration:03}"),
                None,
                false,
                UnixMillis::new(1100 + iteration as i64).unwrap(),
            )
            .unwrap();
        let now = 2000 + iteration as i64;
        let before = pair(&area.live);
        let intent = planner
            .preview_from_store(
                &mut repository,
                &mut store,
                &area.live,
                transaction_id,
                &target.identity,
                &target.preset,
                target.credential.id(),
                UnixMillis::new(now - 1).unwrap(),
                UnixMillis::new(now + 10).unwrap(),
            )
            .unwrap();
        assert_eq!(pair(&area.live), before);
        assert_eq!(
            rusqlite::Connection::open(&area.database)
                .unwrap()
                .query_row("SELECT count(*) FROM switch_transactions", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            i64::try_from(iteration - 1).unwrap()
        );
        println!(
            "M25_PREVIEW iteration={iteration:03} transaction={} prewrite=true config={} auth={} credential={} rows_unchanged=true live_unchanged=true",
            intent.preview().transaction_id().as_str(),
            intent.preview().config_target().as_str(),
            intent.preview().auth_target_prefix(),
            intent.preview().credential_fingerprint_prefix(),
        );
        let mut switch_repository = SqliteMetadataRepository::open(&area.database).unwrap();
        let result = planner
            .execute_approved(
                &mut repository,
                &mut store,
                &mut switch_repository,
                &FixedClock(now),
                &mut NoWait,
                &mut NoFault,
                &intent,
                &target.identity,
                &target.preset,
            )
            .unwrap();
        assert_eq!(
            result.transaction.transaction.state(),
            SwitchTransactionState::Committed
        );
        assert_eq!(result.transaction.transaction.completed_roles(), 3);
        assert_matches(&area.live, target);
        assert!(
            !area.live.join(".codextools-transactions").exists(),
            "iteration {iteration} retained terminal transaction material"
        );
        let marker = runtime_auth(b'Z');
        assert_eq!(
            fragment_hits_except(&area.root, &area.live.join("auth.json"), &marker),
            0,
            "iteration {iteration} retained a credential fragment outside canonical live auth"
        );
        println!(
            "M25_SWITCH iteration={iteration:03} transaction={} state=committed config={} auth={} credential={} exit=0 reread=true",
            result.preview.transaction_id().as_str(),
            result.preview.config_target().as_str(),
            result.preview.auth_target_prefix(),
            result.preview.credential_fingerprint_prefix(),
        );
    }
    assert_matches(&area.live, &provisioned.a);
    assert_eq!(
        rusqlite::Connection::open(&area.database)
            .unwrap()
            .query_row(
                "SELECT count(*) FROM switch_transactions WHERE state='committed'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        100
    );
    assert_eq!(
        BackupRepository::list_backups(&repository, &permanent.root_ref,)
            .unwrap()
            .into_iter()
            .filter(|record| record.kind == codex_application::BackupKind::History)
            .count(),
        10
    );
    assert_eq!(store.successful_read_count(), 200);

    let restore_target = BackupService::new(&mut repository, &mut NoBackupFaults)
        .plan_restore(
            &area.live,
            &area.backups,
            &permanent,
            &baseline(&area.live.join("config.toml")),
            &baseline(&area.live.join("auth.json")),
            UnixMillis::new(5000).unwrap(),
            UnixMillis::new(5100).unwrap(),
            UnixMillis::new(5050).unwrap(),
        )
        .unwrap();
    let restore = planner
        .prepare_restore(
            &area.live,
            tx_id(2000),
            restore_target,
            &provisioned.a.identity,
            &provisioned.a.preset,
            &provisioned.a.credential,
            UnixMillis::new(5000).unwrap(),
            UnixMillis::new(5100).unwrap(),
        )
        .unwrap();
    execute_prepared(
        &area,
        &mut repository,
        &mut store,
        &restore,
        &provisioned.a,
        5050,
        &mut NoFault,
    )
    .unwrap();
    assert_eq!(
        hash_bytes(&pair(&area.live).0),
        hash_bytes(&provisioned.initial_config)
    );
    assert_eq!(
        hash_bytes(&pair(&area.live).1),
        provisioned.initial_auth_hash
    );
    assert_eq!(
        pair_readonly(&area.live),
        (
            provisioned.initial_config_readonly,
            provisioned.initial_auth_readonly
        )
    );
    assert_eq!(store.successful_read_count(), 201);
    assert!(!area.live.join(".codextools-transactions").exists());
    drop(store);
    drop(repository);
    let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
    assert!(
        SwitchExecutor::new(
            &mut repository,
            &FixedClock(5060),
            &mut NoWait,
            &mut NoFault,
        )
        .recover_root(&area.live)
        .unwrap()
        .is_empty()
    );
    drop(repository);
    assert!(!has_stage_or_quarantine(&area.root));
    for suffix in ["-wal", "-shm", "-journal"] {
        assert!(!PathBuf::from(format!("{}{}", area.database.display(), suffix)).exists());
    }
    println!(
        "M25_SWITCH_100_SUMMARY preview_prewrite=100 committed=100 reread=100 dpapi_preview_reads=100 dpapi_execute_reads=100 dpapi_restore_reads=1 mixed_success=0 history=10 restore_initial=committed reopen_unfinished=0 elapsed_ms={} environment=windows-msvc-temp-root-not-benchmark",
        started.elapsed().as_millis()
    );
}

#[test]
fn vertical_switch_fails_closed_when_dpapi_material_is_missing() {
    let area = TempArea::new("store-bypass-red");
    let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(&area.credentials).unwrap();
    let provisioned = provision(&area, &mut repository, &mut store);
    let binding = CredentialEnvelopeBinding::new(
        provisioned.b.credential.id().clone(),
        provisioned.b.credential.kind(),
        provisioned.b.credential.schema_fingerprint().clone(),
        provisioned.b.credential.version(),
    );
    fs::remove_file(store.material_path(&binding)).unwrap();
    let result = execute_from_store(
        &area,
        &mut repository,
        &mut store,
        &provisioned.b,
        tx_id(2999),
        100,
        200,
        150,
        &mut NoFault,
    );
    assert!(
        result.is_err(),
        "missing DPAPI material must block the switch"
    );
    assert_eq!(
        rusqlite::Connection::open(&area.database)
            .unwrap()
            .query_row("SELECT count(*) FROM switch_transactions", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn approved_preview_is_prewrite_and_exactly_matches_execution() {
    let area = TempArea::new("approved-preview");
    let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(&area.credentials).unwrap();
    let provisioned = provision(&area, &mut repository, &mut store);
    let before = pair(&area.live);
    let intent = VerticalSwitchPlanner::new()
        .preview_from_store(
            &mut repository,
            &mut store,
            &area.live,
            tx_id(3000),
            &provisioned.b.identity,
            &provisioned.b.preset,
            provisioned.b.credential.id(),
            UnixMillis::new(100).unwrap(),
            UnixMillis::new(200).unwrap(),
        )
        .unwrap();
    let intent_debug = format!("{intent:?}");
    assert!(!intent_debug.contains(provisioned.b.credential.credential_fingerprint().as_str()));
    assert!(!intent_debug.contains("sk-"));
    assert_eq!(pair(&area.live), before);
    assert_eq!(
        rusqlite::Connection::open(&area.database)
            .unwrap()
            .query_row("SELECT count(*) FROM switch_transactions", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert!(!area.live.join(".codextools-transactions").exists());
    assert!(!area.backups.exists());
    assert!(!has_stage_or_quarantine(&area.root));
    let mut switch_repository = SqliteMetadataRepository::open(&area.database).unwrap();
    let result = VerticalSwitchPlanner::new()
        .execute_approved(
            &mut repository,
            &mut store,
            &mut switch_repository,
            &FixedClock(150),
            &mut NoWait,
            &mut NoFault,
            &intent,
            &provisioned.b.identity,
            &provisioned.b.preset,
        )
        .unwrap();
    assert_eq!(result.preview, *intent.preview());
    assert_eq!(
        result.transaction.transaction.state(),
        SwitchTransactionState::Committed
    );
    assert_matches(&area.live, &provisioned.b);
}

#[test]
fn approved_intent_rejects_live_credential_material_identity_and_preset_changes() {
    for role in ["config", "auth"] {
        let area = TempArea::new(&format!("approved-live-{role}"));
        let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
        let mut store = WindowsDpapiCredentialStore::new(&area.credentials).unwrap();
        let provisioned = provision(&area, &mut repository, &mut store);
        let intent = VerticalSwitchPlanner::new()
            .preview_from_store(
                &mut repository,
                &mut store,
                &area.live,
                tx_id(3300),
                &provisioned.b.identity,
                &provisioned.b.preset,
                provisioned.b.credential.id(),
                UnixMillis::new(100).unwrap(),
                UnixMillis::new(200).unwrap(),
            )
            .unwrap();
        let path = area.live.join(if role == "config" {
            "config.toml"
        } else {
            "auth.json"
        });
        let mut external = fs::read(&path).unwrap();
        external.extend_from_slice(b" EXTERNAL_SAMPLE");
        fs::write(&path, &external).unwrap();
        let mut switch_repository = SqliteMetadataRepository::open(&area.database).unwrap();
        assert_eq!(
            VerticalSwitchPlanner::new().execute_approved(
                &mut repository,
                &mut store,
                &mut switch_repository,
                &FixedClock(150),
                &mut NoWait,
                &mut NoFault,
                &intent,
                &provisioned.b.identity,
                &provisioned.b.preset,
            ),
            Err(VerticalClosureError::Switch(
                SwitchExecutionError::PlanStale
            ))
        );
        assert_eq!(fs::read(path).unwrap(), external);
        assert_eq!(
            rusqlite::Connection::open(&area.database)
                .unwrap()
                .query_row("SELECT count(*) FROM switch_transactions", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    let rotated = TempArea::new("approved-rotated");
    let mut repository = SqliteMetadataRepository::open(&rotated.database).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(&rotated.credentials).unwrap();
    let provisioned = provision(&rotated, &mut repository, &mut store);
    let intent = VerticalSwitchPlanner::new()
        .preview_from_store(
            &mut repository,
            &mut store,
            &rotated.live,
            tx_id(3301),
            &provisioned.b.identity,
            &provisioned.b.preset,
            provisioned.b.credential.id(),
            UnixMillis::new(100).unwrap(),
            UnixMillis::new(200).unwrap(),
        )
        .unwrap();
    let before = pair(&rotated.live);
    let mut replacement = runtime_auth(b'Y');
    let ScanStatus::Ready(replacement_state) = CodexAdapter::new().scan_memory(
        &fs::read(rotated.live.join("config.toml")).unwrap(),
        &replacement,
    ) else {
        panic!("replacement must scan")
    };
    let next = provisioned
        .b
        .credential
        .rotate(
            provisioned.b.credential.schema_fingerprint().clone(),
            replacement_state.authentication.credential_fingerprint,
            UnixMillis::new(151).unwrap(),
        )
        .unwrap();
    let previous_binding = CredentialEnvelopeBinding::new(
        provisioned.b.credential.id().clone(),
        provisioned.b.credential.kind(),
        provisioned.b.credential.schema_fingerprint().clone(),
        provisioned.b.credential.version(),
    );
    let next_binding = CredentialEnvelopeBinding::new(
        next.id().clone(),
        next.kind(),
        next.schema_fingerprint().clone(),
        next.version(),
    );
    let owner = store.begin_mutation(next.id()).unwrap();
    store
        .rotate(&previous_binding, &next_binding, &mut replacement)
        .unwrap();
    store.end_mutation(owner).unwrap();
    repository
        .update_credential_reference(&next, provisioned.b.credential.version())
        .unwrap();
    let mut switch_repository = SqliteMetadataRepository::open(&rotated.database).unwrap();
    assert_eq!(
        VerticalSwitchPlanner::new().execute_approved(
            &mut repository,
            &mut store,
            &mut switch_repository,
            &FixedClock(152),
            &mut NoWait,
            &mut NoFault,
            &intent,
            &provisioned.b.identity,
            &provisioned.b.preset,
        ),
        Err(VerticalClosureError::Switch(
            SwitchExecutionError::PlanStale
        ))
    );
    assert_eq!(pair(&rotated.live), before);

    for aggregate in ["identity", "preset", "material"] {
        let area = TempArea::new(&format!("approved-{aggregate}"));
        let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
        let mut store = WindowsDpapiCredentialStore::new(&area.credentials).unwrap();
        let provisioned = provision(&area, &mut repository, &mut store);
        let intent = VerticalSwitchPlanner::new()
            .preview_from_store(
                &mut repository,
                &mut store,
                &area.live,
                tx_id(3302),
                &provisioned.b.identity,
                &provisioned.b.preset,
                provisioned.b.credential.id(),
                UnixMillis::new(100).unwrap(),
                UnixMillis::new(200).unwrap(),
            )
            .unwrap();
        let (identity, preset) = match aggregate {
            "identity" => {
                let changed = provisioned
                    .b
                    .identity
                    .rename(
                        EntityName::parse("Changed identity").unwrap(),
                        UnixMillis::new(151).unwrap(),
                    )
                    .unwrap();
                repository
                    .update_runtime_identity(&changed, provisioned.b.identity.version())
                    .unwrap();
                (changed, provisioned.b.preset.clone())
            }
            "preset" => {
                let changed = provisioned
                    .b
                    .preset
                    .rename(
                        EntityName::parse("Changed preset").unwrap(),
                        UnixMillis::new(151).unwrap(),
                    )
                    .unwrap();
                repository
                    .update_model_preset(&changed, provisioned.b.preset.version())
                    .unwrap();
                (provisioned.b.identity.clone(), changed)
            }
            "material" => {
                let binding_a = CredentialEnvelopeBinding::new(
                    provisioned.a.credential.id().clone(),
                    provisioned.a.credential.kind(),
                    provisioned.a.credential.schema_fingerprint().clone(),
                    provisioned.a.credential.version(),
                );
                let binding_b = CredentialEnvelopeBinding::new(
                    provisioned.b.credential.id().clone(),
                    provisioned.b.credential.kind(),
                    provisioned.b.credential.schema_fingerprint().clone(),
                    provisioned.b.credential.version(),
                );
                fs::copy(
                    store.material_path(&binding_a),
                    store.material_path(&binding_b),
                )
                .unwrap();
                (provisioned.b.identity.clone(), provisioned.b.preset.clone())
            }
            _ => unreachable!(),
        };
        let before = pair(&area.live);
        let mut switch_repository = SqliteMetadataRepository::open(&area.database).unwrap();
        assert!(
            VerticalSwitchPlanner::new()
                .execute_approved(
                    &mut repository,
                    &mut store,
                    &mut switch_repository,
                    &FixedClock(152),
                    &mut NoWait,
                    &mut NoFault,
                    &intent,
                    &identity,
                    &preset,
                )
                .is_err()
        );
        assert_eq!(pair(&area.live), before);
        assert_eq!(
            rusqlite::Connection::open(&area.database)
                .unwrap()
                .query_row("SELECT count(*) FROM switch_transactions", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    println!(
        "M25_APPROVED_STALE live_config=prewrite live_auth=prewrite rotate=prewrite identity=prewrite preset=prewrite material=prewrite"
    );
}

#[test]
fn restore_revalidates_credential_generation_before_any_write() {
    let area = TempArea::new("restore-credential-stale");
    let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(&area.credentials).unwrap();
    let provisioned = provision(&area, &mut repository, &mut store);
    let permanent = BackupService::new(&mut repository, &mut NoBackupFaults)
        .create_permanent(
            &area.live,
            &area.backups,
            "restore-stale-permanent",
            UnixMillis::new(30).unwrap(),
        )
        .unwrap();
    execute_from_store(
        &area,
        &mut repository,
        &mut store,
        &provisioned.b,
        tx_id(3400),
        100,
        200,
        150,
        &mut NoFault,
    )
    .unwrap();
    let restore_target = BackupService::new(&mut repository, &mut NoBackupFaults)
        .plan_restore(
            &area.live,
            &area.backups,
            &permanent,
            &baseline(&area.live.join("config.toml")),
            &baseline(&area.live.join("auth.json")),
            UnixMillis::new(160).unwrap(),
            UnixMillis::new(260).unwrap(),
            UnixMillis::new(170).unwrap(),
        )
        .unwrap();
    let restore = VerticalSwitchPlanner::new()
        .prepare_restore(
            &area.live,
            tx_id(3401),
            restore_target,
            &provisioned.a.identity,
            &provisioned.a.preset,
            &provisioned.a.credential,
            UnixMillis::new(160).unwrap(),
            UnixMillis::new(260).unwrap(),
        )
        .unwrap();
    let rotated = provisioned
        .a
        .credential
        .rotate(
            provisioned.a.credential.schema_fingerprint().clone(),
            provisioned.a.credential.credential_fingerprint().clone(),
            UnixMillis::new(171).unwrap(),
        )
        .unwrap();
    repository
        .update_credential_reference(&rotated, provisioned.a.credential.version())
        .unwrap();
    let before = pair(&area.live);
    assert_eq!(
        execute_prepared(
            &area,
            &mut repository,
            &mut store,
            &restore,
            &provisioned.a,
            172,
            &mut NoFault,
        ),
        Err(VerticalClosureError::Switch(
            SwitchExecutionError::PlanStale
        ))
    );
    assert_eq!(pair(&area.live), before);
    assert_eq!(
        rusqlite::Connection::open(&area.database)
            .unwrap()
            .query_row("SELECT count(*) FROM switch_transactions", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    println!("M25_RESTORE_CREDENTIAL_STALE generation_changed=true prewrite=true rows_unchanged=1");
}

#[test]
fn vertical_store_corrupt_wrong_binding_and_stale_metadata_are_prewrite() {
    for case in ["corrupt", "wrong-binding", "stale-metadata"] {
        let area = TempArea::new(case);
        let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
        let mut store = WindowsDpapiCredentialStore::new(&area.credentials).unwrap();
        let provisioned = provision(&area, &mut repository, &mut store);
        let before = (
            hash_bytes(&fs::read(area.live.join("config.toml")).unwrap()),
            hash_bytes(&fs::read(area.live.join("auth.json")).unwrap()),
        );
        let binding_b = CredentialEnvelopeBinding::new(
            provisioned.b.credential.id().clone(),
            provisioned.b.credential.kind(),
            provisioned.b.credential.schema_fingerprint().clone(),
            provisioned.b.credential.version(),
        );
        match case {
            "corrupt" => fs::write(store.material_path(&binding_b), b"CORRUPT_SAMPLE").unwrap(),
            "wrong-binding" => {
                let binding_a = CredentialEnvelopeBinding::new(
                    provisioned.a.credential.id().clone(),
                    provisioned.a.credential.kind(),
                    provisioned.a.credential.schema_fingerprint().clone(),
                    provisioned.a.credential.version(),
                );
                fs::copy(
                    store.material_path(&binding_a),
                    store.material_path(&binding_b),
                )
                .unwrap();
            }
            "stale-metadata" => {
                rusqlite::Connection::open(&area.database)
                    .unwrap()
                    .execute(
                        "UPDATE credential_references SET credential_fingerprint=?1 WHERE id=?2",
                        rusqlite::params![
                            provisioned.a.credential.credential_fingerprint().as_str(),
                            provisioned.b.credential.id().as_str()
                        ],
                    )
                    .unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            execute_from_store(
                &area,
                &mut repository,
                &mut store,
                &provisioned.b,
                tx_id(3100),
                100,
                200,
                150,
                &mut NoFault,
            )
            .is_err()
        );
        assert_eq!(
            (
                hash_bytes(&fs::read(area.live.join("config.toml")).unwrap()),
                hash_bytes(&fs::read(area.live.join("auth.json")).unwrap()),
            ),
            before
        );
        assert_eq!(
            rusqlite::Connection::open(&area.database)
                .unwrap()
                .query_row("SELECT count(*) FROM switch_transactions", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    println!(
        "M25_STORE_NEGATIVE missing=prewrite corrupt=prewrite wrong_binding=prewrite stale_metadata=prewrite transaction_rows=0"
    );
}

#[test]
fn vertical_owner_blocks_rotate_and_panic_releases_owner() {
    let area = TempArea::new("owner-race-panic");
    let mut repository = SqliteMetadataRepository::open(&area.database).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(&area.credentials).unwrap();
    let provisioned = provision(&area, &mut repository, &mut store);

    let panic = catch_unwind(AssertUnwindSafe(|| {
        let _ = execute_from_store(
            &area,
            &mut repository,
            &mut store,
            &provisioned.b,
            tx_id(3200),
            100,
            200,
            150,
            &mut PanickingFault,
        );
    }));
    assert!(panic.is_err());
    let owner = store.begin_mutation(provisioned.b.credential.id()).unwrap();
    store.end_mutation(owner).unwrap();

    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let approved = VerticalSwitchPlanner::new()
        .preview_from_store(
            &mut repository,
            &mut store,
            &area.live,
            tx_id(3201),
            &provisioned.b.identity,
            &provisioned.b.preset,
            provisioned.b.credential.id(),
            UnixMillis::new(100).unwrap(),
            UnixMillis::new(200).unwrap(),
        )
        .unwrap();
    let database = area.database.clone();
    let credential_root = area.credentials.clone();
    let target = provisioned.b.clone();
    let approved_for_thread = approved.clone();
    let thread_entered = Arc::clone(&entered);
    let thread_release = Arc::clone(&release);
    let switcher = thread::spawn(move || {
        let mut credential_repository = SqliteMetadataRepository::open(&database).unwrap();
        let mut switch_repository = SqliteMetadataRepository::open(&database).unwrap();
        let mut thread_store = WindowsDpapiCredentialStore::new(&credential_root).unwrap();
        VerticalSwitchPlanner::new().execute_approved(
            &mut credential_repository,
            &mut thread_store,
            &mut switch_repository,
            &FixedClock(150),
            &mut NoWait,
            &mut BlockingFault {
                entered: thread_entered,
                release: thread_release,
            },
            &approved_for_thread,
            &target.identity,
            &target.preset,
        )
    });
    entered.wait();
    let mut replacement = Vec::from(&b"sk-"[..]);
    replacement.extend((0..48).map(|index| b'A' + (index % 26)));
    let rotate = local_infrastructure::CredentialService::new(&mut repository, &mut store)
        .rotate_credential(
            provisioned.b.credential.id(),
            provisioned.b.credential.version(),
            &mut replacement,
            UnixMillis::new(151).unwrap(),
        );
    assert_eq!(rotate, Err(CredentialServiceError::VersionConflict));
    assert!(replacement.iter().all(|byte| *byte == 0));
    release.wait();
    let switched = switcher.join().unwrap().unwrap();
    assert_eq!(
        switched.transaction.transaction.state(),
        SwitchTransactionState::Committed
    );
    assert_eq!(
        repository
            .get_credential_reference(provisioned.b.credential.id())
            .unwrap()
            .unwrap(),
        provisioned.b.credential
    );
    println!(
        "M25_OWNER_RACE preview_execute_owner=held rotate_contended=true stale_secret_written=false panic_owner_released=true"
    );
}

#[test]
fn vertical_fault_and_recovery_matrix_never_marks_mixed_state_successful() {
    let compatibility = TempArea::new("fault-compatibility");
    let mut repository = SqliteMetadataRepository::open(&compatibility.database).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(&compatibility.credentials).unwrap();
    let provisioned = provision(&compatibility, &mut repository, &mut store);
    fs::write(compatibility.live.join("config.toml"), b"invalid = [").unwrap();
    assert!(matches!(
        execute_from_store(
            &compatibility,
            &mut repository,
            &mut store,
            &provisioned.b,
            tx_id(3000),
            100,
            200,
            150,
            &mut NoFault,
        ),
        Err(VerticalClosureError::CompatibilityProtected(_))
    ));
    assert!(!compatibility.live.join(".codextools-transactions").exists());

    let stale = TempArea::new("fault-stale");
    let mut repository = SqliteMetadataRepository::open(&stale.database).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(&stale.credentials).unwrap();
    let provisioned = provision(&stale, &mut repository, &mut store);
    let external = [
        provisioned.initial_config.as_slice(),
        b"external_m25 = \"KEEP_EXTERNAL\"\n",
    ]
    .concat();
    let mut mutation = MutatingWait {
        path: stale.live.join("config.toml"),
        bytes: Some(external),
    };
    assert_eq!(
        execute_from_store_with_stability(
            &stale,
            &mut repository,
            &mut store,
            &provisioned.b,
            tx_id(3001),
            100,
            200,
            150,
            &mut mutation,
            &mut NoFault,
        ),
        Err(VerticalClosureError::Switch(
            SwitchExecutionError::PlanStale
        ))
    );
    assert!(
        fs::read_to_string(stale.live.join("config.toml"))
            .unwrap()
            .contains("KEEP_EXTERNAL")
    );

    let busy = TempArea::new("fault-busy");
    let mut repository = SqliteMetadataRepository::open(&busy.database).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(&busy.credentials).unwrap();
    let provisioned = provision(&busy, &mut repository, &mut store);
    let lock =
        CrossProcessWriteLock::try_acquire(&busy.live, UnixMillis::new(149).unwrap()).unwrap();
    assert_eq!(
        execute_from_store(
            &busy,
            &mut repository,
            &mut store,
            &provisioned.b,
            tx_id(3002),
            100,
            200,
            150,
            &mut NoFault,
        ),
        Err(VerticalClosureError::Switch(SwitchExecutionError::Busy))
    );
    drop(lock);
    assert!(
        SwitchTransactionRepository::list_blocking_switch_transactions(
            &repository,
            &hash_bytes(
                fs::canonicalize(&busy.live)
                    .unwrap()
                    .to_string_lossy()
                    .to_lowercase()
                    .as_bytes()
            )
        )
        .unwrap()
        .is_empty()
    );

    let rolled_back = TempArea::new("fault-rollback");
    let mut repository = SqliteMetadataRepository::open(&rolled_back.database).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(&rolled_back.credentials).unwrap();
    let provisioned = provision(&rolled_back, &mut repository, &mut store);
    assert_eq!(
        execute_from_store(
            &rolled_back,
            &mut repository,
            &mut store,
            &provisioned.b,
            tx_id(3003),
            100,
            200,
            150,
            &mut ScriptedFault(vec![(
                FaultPoint::AfterConfigReplace,
                FaultDisposition::Fail,
            )]),
        ),
        Err(VerticalClosureError::Switch(
            SwitchExecutionError::InjectedFailure
        ))
    );
    assert_matches(&rolled_back.live, &provisioned.a);

    let interrupted_mixed = TempArea::new("fault-interrupt-mixed");
    let mut repository = SqliteMetadataRepository::open(&interrupted_mixed.database).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(&interrupted_mixed.credentials).unwrap();
    let provisioned = provision(&interrupted_mixed, &mut repository, &mut store);
    assert_eq!(
        execute_from_store(
            &interrupted_mixed,
            &mut repository,
            &mut store,
            &provisioned.b,
            tx_id(3004),
            100,
            200,
            150,
            &mut ScriptedFault(vec![(
                FaultPoint::AfterConfigReplace,
                FaultDisposition::Interrupt,
            )]),
        ),
        Err(VerticalClosureError::Switch(
            SwitchExecutionError::Interrupted
        ))
    );
    drop(repository);
    let mut repository = SqliteMetadataRepository::open(&interrupted_mixed.database).unwrap();
    let recovered =
        SwitchExecutor::new(&mut repository, &FixedClock(151), &mut NoWait, &mut NoFault)
            .recover_root(&interrupted_mixed.live)
            .unwrap();
    assert_eq!(recovered.len(), 1);
    assert!(
        VerticalSwitchPlanner::new()
            .verify_expected(
                &interrupted_mixed.live,
                &provisioned.a.identity,
                &provisioned.a.preset,
                &provisioned.a.credential,
            )
            .is_ok()
            || VerticalSwitchPlanner::new()
                .verify_expected(
                    &interrupted_mixed.live,
                    &provisioned.b.identity,
                    &provisioned.b.preset,
                    &provisioned.b.credential,
                )
                .is_ok()
    );

    let interrupted_target = TempArea::new("fault-interrupt-target");
    let mut repository = SqliteMetadataRepository::open(&interrupted_target.database).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(&interrupted_target.credentials).unwrap();
    let provisioned = provision(&interrupted_target, &mut repository, &mut store);
    assert_eq!(
        execute_from_store(
            &interrupted_target,
            &mut repository,
            &mut store,
            &provisioned.b,
            tx_id(3005),
            100,
            200,
            150,
            &mut ScriptedFault(vec![(
                FaultPoint::AfterAuthenticationReplace,
                FaultDisposition::Interrupt,
            )]),
        ),
        Err(VerticalClosureError::Switch(
            SwitchExecutionError::Interrupted
        ))
    );
    drop(repository);
    let mut repository = SqliteMetadataRepository::open(&interrupted_target.database).unwrap();
    SwitchExecutor::new(&mut repository, &FixedClock(151), &mut NoWait, &mut NoFault)
        .recover_root(&interrupted_target.live)
        .unwrap();
    if hash_bytes(&pair(&interrupted_target.live).0) == hash_bytes(&provisioned.initial_config) {
        assert_matches(&interrupted_target.live, &provisioned.a);
    } else {
        assert_matches(&interrupted_target.live, &provisioned.b);
    }

    let protected = TempArea::new("fault-recovery-required");
    let mut repository = SqliteMetadataRepository::open(&protected.database).unwrap();
    let mut store = WindowsDpapiCredentialStore::new(&protected.credentials).unwrap();
    let provisioned = provision(&protected, &mut repository, &mut store);
    assert_eq!(
        execute_from_store(
            &protected,
            &mut repository,
            &mut store,
            &provisioned.b,
            tx_id(3006),
            100,
            200,
            150,
            &mut ScriptedFault(vec![
                (FaultPoint::AfterConfigReplace, FaultDisposition::Fail),
                (FaultPoint::RollbackConfig, FaultDisposition::Fail),
            ]),
        ),
        Err(VerticalClosureError::Switch(
            SwitchExecutionError::RecoveryRequired
        ))
    );
    assert_eq!(
        execute_from_store(
            &protected,
            &mut repository,
            &mut store,
            &provisioned.b,
            tx_id(3007),
            100,
            200,
            150,
            &mut NoFault,
        ),
        Err(VerticalClosureError::Switch(
            SwitchExecutionError::RecoveryRequired
        ))
    );
    let root_ref = hash_bytes(
        fs::canonicalize(&protected.live)
            .unwrap()
            .to_string_lossy()
            .to_lowercase()
            .as_bytes(),
    );
    assert_eq!(
        repository
            .list_recovery_required_diagnostics(&root_ref)
            .unwrap()
            .len(),
        1
    );
    println!(
        "M25_FAULT_MATRIX compatibility=prewrite plan_stale=external_preserved busy=no_transaction rollback=source interrupt_mixed=reopen_converged interrupt_target=reopen_converged recovery_required=root_blocked diagnostics=1 mixed_success=0"
    );
}
