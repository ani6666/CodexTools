#![allow(unused_crate_dependencies)]

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use codex_adapter::CodexAdapter;
use codex_application::{
    ApplicationError, EntityKind, ImportIdentityInput, ImportOutcome, ManagedConfigPatchRepository,
    MatchStatus, RepositoryError, ScanStatus, import_scanned_identity, match_actual_identity,
};
use codex_domain::{
    CredentialBackend, CredentialKind, CredentialRefId, CredentialReference, EntityName,
    IdentityId, ManagedConfigPatchId, ModelPresetId, UnixMillis,
};
use local_infrastructure::SqliteMetadataRepository;
use rusqlite::Connection;

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

struct TempDb(PathBuf);
impl TempDb {
    fn new(label: &str) -> Self {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "codextools-m22-{label}-{}-{n}-{id}.sqlite3",
            std::process::id()
        )))
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempDb {
    fn drop(&mut self) {
        for s in ["", "-wal", "-shm", "-journal"] {
            let _ = fs::remove_file(format!("{}{}", self.0.display(), s));
        }
    }
}
struct TempHome(PathBuf);
impl TempHome {
    fn new_fixture(name: &str) -> Self {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!(
            "codextools-m22-home-{}-{n}-{id}",
            std::process::id()
        ));
        fs::create_dir_all(&p).unwrap();
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name);
        fs::copy(root.join("config.toml"), p.join("config.toml")).unwrap();
        fs::copy(root.join("auth.json"), p.join("auth.json")).unwrap();
        Self(p)
    }
}
impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn actual() -> (TempHome, codex_application::ActualCodexState) {
    actual_fixture("g1-api-key")
}

fn actual_fixture(name: &str) -> (TempHome, codex_application::ActualCodexState) {
    let h = TempHome::new_fixture(name);
    let ScanStatus::Ready(s) = CodexAdapter::new().scan_explicit_root(&h.0) else {
        panic!()
    };
    (h, *s)
}
fn reference(state: &codex_application::ActualCodexState, id: &str) -> CredentialReference {
    CredentialReference::new(
        CredentialRefId::parse(id).unwrap(),
        CredentialKind::ApiKey,
        CredentialBackend::WindowsDpapiCurrentUser,
        state.authentication.schema_fingerprint.clone(),
        state.authentication.credential_fingerprint.clone(),
        UnixMillis::new(1).unwrap(),
    )
}
fn input(
    reference: CredentialReference,
    identity: &str,
    preset: &str,
    patch: &str,
) -> ImportIdentityInput {
    ImportIdentityInput {
        identity_id: IdentityId::parse(identity).unwrap(),
        identity_name: EntityName::parse("同名身份").unwrap(),
        preset_id: ModelPresetId::parse(preset).unwrap(),
        preset_name: EntityName::parse("日常").unwrap(),
        patch_id: ManagedConfigPatchId::parse(patch).unwrap(),
        credential: Some(reference),
        credential_already_persisted: false,
        now: UnixMillis::new(2).unwrap(),
    }
}

fn assert_empty(db: &TempDb) {
    let c = Connection::open(db.path()).unwrap();
    for target in [
        "credential_references",
        "runtime_identities",
        "model_presets",
        "managed_config_patches",
    ] {
        let count: i64 = c
            .query_row(&format!("SELECT COUNT(*) FROM {target}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0, "partial row in {target}");
    }
}

fn repository_error(result: Result<ImportOutcome, ApplicationError>) -> RepositoryError {
    match result {
        Err(ApplicationError::Repository(error)) => error,
        other => panic!("expected repository error, got {other:?}"),
    }
}

#[test]
fn import_is_atomic_at_identity_preset_and_patch_failure_points() {
    for (table, expected) in [
        (
            "runtime_identities",
            RepositoryError::ReferenceConflict(EntityKind::CredentialReference),
        ),
        (
            "model_presets",
            RepositoryError::ReferenceConflict(EntityKind::RuntimeIdentity),
        ),
        (
            "managed_config_patches",
            RepositoryError::ReferenceConflict(EntityKind::RuntimeIdentity),
        ),
    ] {
        let db = TempDb::new(table);
        {
            SqliteMetadataRepository::open(db.path()).unwrap();
        }
        let c = Connection::open(db.path()).unwrap();
        c.execute_batch(&format!("CREATE TRIGGER fail_{table} BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT,'fixture failure'); END;")).unwrap();
        drop(c);
        let (_home, state) = actual();
        let mut repo = SqliteMetadataRepository::open(db.path()).unwrap();
        let result = repository_error(import_scanned_identity(
            &mut repo,
            &state,
            input(
                reference(&state, "11111111-1111-4111-8111-111111111111"),
                "22222222-2222-4222-8222-222222222222",
                "33333333-3333-4333-8333-333333333333",
                "44444444-4444-4444-8444-444444444444",
            ),
        ));
        assert_eq!(result, expected, "trigger mapping for {table}");
        drop(repo);
        assert_empty(&db);
    }
}

#[test]
fn import_maps_missing_reference_and_check_failure_without_partial_rows() {
    let db = TempDb::new("missing-reference");
    let (_home, state) = actual();
    let mut request = input(
        reference(&state, "11111111-1111-4111-8111-111111111111"),
        "22222222-2222-4222-8222-222222222222",
        "33333333-3333-4333-8333-333333333333",
        "44444444-4444-4444-8444-444444444444",
    );
    request.credential_already_persisted = true;
    let mut repo = SqliteMetadataRepository::open(db.path()).unwrap();
    assert_eq!(
        repository_error(import_scanned_identity(&mut repo, &state, request)),
        RepositoryError::ReferenceConflict(EntityKind::CredentialReference)
    );
    drop(repo);
    assert_empty(&db);

    let db = TempDb::new("check-failure");
    SqliteMetadataRepository::open(db.path()).unwrap();
    let c = Connection::open(db.path()).unwrap();
    c.execute_batch(
        "CREATE TABLE import_check_fixture (value INTEGER CHECK(value = 1));
         CREATE TRIGGER fail_patch_check BEFORE INSERT ON managed_config_patches
         BEGIN INSERT INTO import_check_fixture(value) VALUES (0); END;",
    )
    .unwrap();
    drop(c);
    let mut repo = SqliteMetadataRepository::open(db.path()).unwrap();
    let error = repository_error(import_scanned_identity(
        &mut repo,
        &state,
        input(
            reference(&state, "11111111-1111-4111-8111-111111111111"),
            "22222222-2222-4222-8222-222222222222",
            "33333333-3333-4333-8333-333333333333",
            "44444444-4444-4444-8444-444444444444",
        ),
    ));
    assert_eq!(error, RepositoryError::CorruptData);
    drop(repo);
    assert_empty(&db);
}

#[test]
fn import_maps_duplicate_entity_at_each_bundle_step_and_rolls_back() {
    let db = TempDb::new("duplicates");
    let (_home, state) = actual();
    let mut repo = SqliteMetadataRepository::open(db.path()).unwrap();
    let seed = input(
        reference(&state, "11111111-1111-4111-8111-111111111111"),
        "22222222-2222-4222-8222-222222222222",
        "33333333-3333-4333-8333-333333333333",
        "44444444-4444-4444-8444-444444444444",
    );
    import_scanned_identity(&mut repo, &state, seed).unwrap();

    let credential_duplicate = input(
        reference(&state, "11111111-1111-4111-8111-111111111111"),
        "55555555-5555-4555-8555-555555555555",
        "66666666-6666-4666-8666-666666666666",
        "77777777-7777-4777-8777-777777777777",
    );
    assert_eq!(
        repository_error(import_scanned_identity(
            &mut repo,
            &state,
            credential_duplicate
        )),
        RepositoryError::AlreadyExists(EntityKind::CredentialReference)
    );

    let mut identity_unique_duplicate = input(
        reference(&state, "11111111-1111-4111-8111-111111111111"),
        "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
        "ffffffff-ffff-4fff-8fff-ffffffffffff",
        "12121212-1212-4212-8212-121212121212",
    );
    identity_unique_duplicate.credential_already_persisted = true;
    assert_eq!(
        repository_error(import_scanned_identity(
            &mut repo,
            &state,
            identity_unique_duplicate
        )),
        RepositoryError::AlreadyExists(EntityKind::RuntimeIdentity)
    );

    let mut identity_duplicate = input(
        reference(&state, "11111111-1111-4111-8111-111111111111"),
        "22222222-2222-4222-8222-222222222222",
        "88888888-8888-4888-8888-888888888888",
        "99999999-9999-4999-8999-999999999999",
    );
    identity_duplicate.credential_already_persisted = true;
    assert_eq!(
        repository_error(import_scanned_identity(
            &mut repo,
            &state,
            identity_duplicate
        )),
        RepositoryError::AlreadyExists(EntityKind::RuntimeIdentity)
    );

    let mut variant = state.clone();
    variant.config.api_base_url = codex_domain::EndpointUrl::parse("https://HOST/variant").unwrap();
    let mut preset_duplicate = input(
        reference(&state, "11111111-1111-4111-8111-111111111111"),
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "33333333-3333-4333-8333-333333333333",
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    );
    preset_duplicate.credential_already_persisted = true;
    assert_eq!(
        repository_error(import_scanned_identity(
            &mut repo,
            &variant,
            preset_duplicate
        )),
        RepositoryError::AlreadyExists(EntityKind::ModelPreset)
    );

    variant.config.api_base_url = codex_domain::EndpointUrl::parse("https://HOST/patch").unwrap();
    let mut patch_duplicate = input(
        reference(&state, "11111111-1111-4111-8111-111111111111"),
        "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        "44444444-4444-4444-8444-444444444444",
    );
    patch_duplicate.credential_already_persisted = true;
    assert_eq!(
        repository_error(import_scanned_identity(
            &mut repo,
            &variant,
            patch_duplicate
        )),
        RepositoryError::AlreadyExists(EntityKind::ManagedConfigPatch)
    );

    drop(repo);
    let c = Connection::open(db.path()).unwrap();
    for table in [
        "credential_references",
        "runtime_identities",
        "model_presets",
        "managed_config_patches",
    ] {
        let count: i64 = c
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1, "failed duplicate import left rows in {table}");
    }
}

#[test]
fn import_persists_bundle_and_matching_returns_zero_one_or_multiple() {
    let db = TempDb::new("match");
    let (home, state) = actual();
    let mut repo = SqliteMetadataRepository::open(db.path()).unwrap();
    assert_eq!(
        import_scanned_identity(
            &mut repo,
            &state,
            input(
                reference(&state, "11111111-1111-4111-8111-111111111111"),
                "22222222-2222-4222-8222-222222222222",
                "33333333-3333-4333-8333-333333333333",
                "44444444-4444-4444-8444-444444444444"
            )
        )
        .unwrap(),
        ImportOutcome::Imported
    );
    assert!(
        repo.get_managed_config_patch(
            &IdentityId::parse("22222222-2222-4222-8222-222222222222").unwrap()
        )
        .unwrap()
        .is_some()
    );
    let status = ScanStatus::Ready(Box::new(state.clone()));
    assert_eq!(
        match_actual_identity(&repo, &status).unwrap(),
        MatchStatus::UniqueMatch(
            IdentityId::parse("22222222-2222-4222-8222-222222222222").unwrap()
        )
    );
    let original_hash = state.config.baseline_sha256.clone();
    let config_path = home.0.join("config.toml");
    let changed_unknown = String::from_utf8(fs::read(&config_path).unwrap())
        .unwrap()
        .replace("KEEP_ME", "KEEP_CHANGED");
    fs::write(&config_path, changed_unknown).unwrap();
    let ScanStatus::Ready(unmanaged_changed) = CodexAdapter::new().scan_explicit_root(&home.0)
    else {
        panic!()
    };
    assert_ne!(unmanaged_changed.config.baseline_sha256, original_hash);
    assert_eq!(
        match_actual_identity(&repo, &ScanStatus::Ready(unmanaged_changed)).unwrap(),
        MatchStatus::UniqueMatch(
            IdentityId::parse("22222222-2222-4222-8222-222222222222").unwrap()
        )
    );
    let mut same_reference_variant = state.clone();
    same_reference_variant.config.api_base_url =
        codex_domain::EndpointUrl::parse("https://HOST/v2").unwrap();
    let mut variant_input = input(
        reference(&state, "11111111-1111-4111-8111-111111111111"),
        "55555555-5555-4555-8555-555555555555",
        "66666666-6666-4666-8666-666666666666",
        "77777777-7777-4777-8777-777777777777",
    );
    variant_input.credential_already_persisted = true;
    import_scanned_identity(&mut repo, &same_reference_variant, variant_input).unwrap();
    assert_eq!(
        match_actual_identity(&repo, &ScanStatus::Ready(Box::new(same_reference_variant))).unwrap(),
        MatchStatus::UniqueMatch(
            IdentityId::parse("55555555-5555-4555-8555-555555555555").unwrap()
        )
    );
    import_scanned_identity(
        &mut repo,
        &state,
        input(
            reference(&state, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        ),
    )
    .unwrap();
    assert_eq!(
        match_actual_identity(&repo, &status).unwrap(),
        MatchStatus::MultipleMatches
    );
    let mut changed = state.clone();
    changed.config.model_id = codex_domain::ModelId::parse("gpt-OTHER").unwrap();
    assert_eq!(
        match_actual_identity(&repo, &ScanStatus::Ready(Box::new(changed))).unwrap(),
        MatchStatus::Unmanaged
    );
}

#[test]
fn oauth_import_matches_and_credential_rotation_invalidates_old_fingerprint() {
    use codex_application::CredentialReferenceRepository;
    let db = TempDb::new("oauth");
    let (_home, state) = actual_fixture("g2-oauth");
    let mut repo = SqliteMetadataRepository::open(db.path()).unwrap();
    let oauth = CredentialReference::new(
        CredentialRefId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
        CredentialKind::OAuthBundle,
        CredentialBackend::WindowsDpapiCurrentUser,
        state.authentication.schema_fingerprint.clone(),
        state.authentication.credential_fingerprint.clone(),
        UnixMillis::new(1).unwrap(),
    );
    import_scanned_identity(
        &mut repo,
        &state,
        input(
            oauth.clone(),
            "22222222-2222-4222-8222-222222222222",
            "33333333-3333-4333-8333-333333333333",
            "44444444-4444-4444-8444-444444444444",
        ),
    )
    .unwrap();
    let status = ScanStatus::Ready(Box::new(state.clone()));
    assert!(matches!(
        match_actual_identity(&repo, &status).unwrap(),
        MatchStatus::UniqueMatch(_)
    ));
    let rotated = oauth
        .rotate(
            state.authentication.schema_fingerprint.clone(),
            codex_domain::CredentialFingerprint::parse(&"f".repeat(64)).unwrap(),
            UnixMillis::new(3).unwrap(),
        )
        .unwrap();
    repo.update_credential_reference(&rotated, oauth.version())
        .unwrap();
    assert_eq!(
        match_actual_identity(&repo, &status).unwrap(),
        MatchStatus::Unmanaged
    );
}

#[test]
fn missing_credential_requires_capture_without_sqlite_rows() {
    let db = TempDb::new("capture");
    let (_home, state) = actual();
    let mut repo = SqliteMetadataRepository::open(db.path()).unwrap();
    let mut request = input(
        reference(&state, "11111111-1111-4111-8111-111111111111"),
        "22222222-2222-4222-8222-222222222222",
        "33333333-3333-4333-8333-333333333333",
        "44444444-4444-4444-8444-444444444444",
    );
    request.credential = None;
    assert_eq!(
        import_scanned_identity(&mut repo, &state, request).unwrap(),
        ImportOutcome::CredentialCaptureRequired
    );
    drop(repo);
    let c = Connection::open(db.path()).unwrap();
    let count:i64=c.query_row("SELECT (SELECT COUNT(*) FROM runtime_identities)+(SELECT COUNT(*) FROM model_presets)+(SELECT COUNT(*) FROM managed_config_patches)",[],|r|r.get(0)).unwrap();
    assert_eq!(count, 0);
}

#[test]
fn runtime_auth_secret_is_hashed_and_never_persisted_or_echoed() {
    let db = TempDb::new("secret");
    let home = TempHome::new_fixture("g1-api-key");
    let marker = format!("{}{}", "sk-", "Z".repeat(24));
    let auth = format!("{{\"OPENAI_API_KEY\":\"{marker}\"}}");
    fs::write(home.0.join("auth.json"), auth).unwrap();
    let result = CodexAdapter::new().scan_explicit_root(&home.0);
    assert!(!format!("{result:?}").contains(&marker));
    let ScanStatus::Ready(state) = result else {
        panic!()
    };
    let mut repo = SqliteMetadataRepository::open(db.path()).unwrap();
    import_scanned_identity(
        &mut repo,
        &state,
        input(
            reference(&state, "11111111-1111-4111-8111-111111111111"),
            "22222222-2222-4222-8222-222222222222",
            "33333333-3333-4333-8333-333333333333",
            "44444444-4444-4444-8444-444444444444",
        ),
    )
    .unwrap();
    drop(repo);
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let path = PathBuf::from(format!("{}{}", db.path().display(), suffix));
        if path.exists() {
            let bytes = fs::read(path).unwrap();
            assert!(
                !bytes
                    .windows(marker.len())
                    .any(|window| window == marker.as_bytes())
            );
        }
    }
}
