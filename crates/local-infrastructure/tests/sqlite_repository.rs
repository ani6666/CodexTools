#![allow(unused_crate_dependencies)]

use codex_adapter as _;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use codex_application::{
    CredentialReferenceRepository, EntityKind, IdentityCandidateQuery, ModelPresetRepository,
    RepositoryError, RuntimeIdentityRepository,
};
use codex_domain::{
    CredentialBackend, CredentialFingerprint, CredentialKind, CredentialRefId, CredentialReference,
    DomainError, EndpointUrl, EntityName, IdentityId, ModelId, ModelPreset, ModelPresetId,
    ProviderId, RuntimeIdentity, SchemaFingerprint, UnixMillis,
};
use local_infrastructure::{
    LATEST_SCHEMA_VERSION, MigrationError, OpenRepositoryError, SqliteMetadataRepository,
};
use rusqlite::{Connection, params};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

struct TempDatabase {
    path: PathBuf,
}

impl TempDatabase {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "codextools-m21-{}-{nonce}-{sequence}.sqlite3",
            std::process::id()
        ));
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDatabase {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let candidate = PathBuf::from(format!("{}{}", self.path.display(), suffix));
            let _ = fs::remove_file(candidate);
        }
    }
}

fn time(value: i64) -> UnixMillis {
    UnixMillis::new(value).unwrap()
}

fn assert_secret_domain_error<T>(result: Result<T, DomainError>, marker: &str) {
    let error = match result {
        Ok(_) => panic!("embedded high-confidence marker reached repository input"),
        Err(error) => error,
    };
    assert_eq!(error, DomainError::SecretLikeInput);
    assert!(!format!("{error}").contains(marker));
    assert!(!format!("{error:?}").contains(marker));
}

fn credential() -> CredentialReference {
    credential_with(
        CredentialRefId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
        CredentialKind::ApiKey,
        'a',
        'b',
    )
}

fn oauth_credential() -> CredentialReference {
    credential_with(
        CredentialRefId::parse("99999999-9999-4999-8999-999999999999").unwrap(),
        CredentialKind::OAuthBundle,
        'c',
        'd',
    )
}

fn credential_with(
    id: CredentialRefId,
    kind: CredentialKind,
    schema_character: char,
    credential_character: char,
) -> CredentialReference {
    CredentialReference::new(
        id,
        kind,
        CredentialBackend::WindowsDpapiCurrentUser,
        SchemaFingerprint::parse(&schema_character.to_string().repeat(64)).unwrap(),
        CredentialFingerprint::parse(&credential_character.to_string().repeat(64)).unwrap(),
        time(1_000),
    )
}

fn identity(reference: &CredentialReference) -> RuntimeIdentity {
    RuntimeIdentity::new_draft(
        IdentityId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
        EntityName::parse("日常身份").unwrap(),
        ProviderId::parse("sample-provider").unwrap(),
        EntityName::parse("Sample Provider").unwrap(),
        EndpointUrl::parse("https://HOST/v1").unwrap(),
        None,
        reference.link(),
        time(1_000),
    )
    .unwrap()
}

fn preset(identity: &RuntimeIdentity) -> ModelPreset {
    ModelPreset::new(
        ModelPresetId::parse("33333333-3333-4333-8333-333333333333").unwrap(),
        identity.id().clone(),
        EntityName::parse("日常").unwrap(),
        ModelId::parse("gpt-SAMPLE").unwrap(),
        time(2_000),
    )
}

#[test]
fn migration_is_versioned_repeatable_and_enables_foreign_keys() {
    let database = TempDatabase::new();
    {
        let repository = SqliteMetadataRepository::open(database.path()).unwrap();
        assert_eq!(repository.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
        assert!(repository.foreign_keys_enabled().unwrap());
    }
    {
        let repository = SqliteMetadataRepository::open(database.path()).unwrap();
        assert_eq!(repository.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
        assert!(repository.foreign_keys_enabled().unwrap());
    }
    let connection = Connection::open(database.path()).unwrap();
    let migration_records: Vec<(i64, String)> = connection
        .prepare("SELECT version, name FROM schema_migrations ORDER BY version")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(
        migration_records,
        vec![
            (1, "identity_core".to_owned()),
            (2, "managed_config_patch".to_owned()),
            (3, "switch_transaction".to_owned()),
            (4, "switch_root_guard".to_owned()),
            (5, "credential_backup".to_owned()),
            (6, "backup_recovery".to_owned()),
            (7, "m24_r3_recovery_guards".to_owned()),
            (8, "credential_recovery_timestamps".to_owned()),
            (9, "credential_recovery_planned_fingerprint".to_owned()),
            (10, "switch_sensitive_temp_owner".to_owned())
        ]
    );
    let migration_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(migration_count, 10);
}

#[test]
fn oauth_identity_persists_and_matches_after_reopen() {
    let database = TempDatabase::new();
    let reference = oauth_credential();
    let identity = RuntimeIdentity::new_draft(
        IdentityId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap(),
        EntityName::parse("OAuth 身份").unwrap(),
        ProviderId::parse("oauth-provider").unwrap(),
        EntityName::parse("OAuth Provider").unwrap(),
        EndpointUrl::parse("https://HOST/oauth/v1").unwrap(),
        None,
        reference.link(),
        time(1_000),
    )
    .unwrap();

    {
        let mut repository = SqliteMetadataRepository::open(database.path()).unwrap();
        repository.create_credential_reference(&reference).unwrap();
        repository.create_runtime_identity(&identity).unwrap();
    }

    let repository = SqliteMetadataRepository::open(database.path()).unwrap();
    assert_eq!(
        repository.get_runtime_identity(identity.id()).unwrap(),
        Some(identity.clone())
    );
    let query = IdentityCandidateQuery::new(
        identity.provider_id().clone(),
        identity.api_base_url().clone(),
        identity.auth_mode(),
        reference.credential_fingerprint().clone(),
    );
    assert_eq!(
        repository.find_identity_candidates(&query).unwrap(),
        vec![identity]
    );
}

#[test]
fn schema_rejects_crossed_api_key_and_oauth_reference_types() {
    let database = TempDatabase::new();
    let api_key = credential();
    let oauth = oauth_credential();
    {
        let mut repository = SqliteMetadataRepository::open(database.path()).unwrap();
        repository.create_credential_reference(&api_key).unwrap();
        repository.create_credential_reference(&oauth).unwrap();
    }

    let connection = Connection::open(database.path()).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .unwrap();
    let mut statement = connection
        .prepare("SELECT kind, auth_mode FROM credential_references ORDER BY kind")
        .unwrap();
    let mappings = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(
        mappings,
        vec![
            ("api_key".to_owned(), "api_key".to_owned()),
            ("oauth_bundle".to_owned(), "oauth".to_owned())
        ]
    );
    drop(statement);
    for (id, provider, auth_mode, credential_ref_id) in [
        (
            "abababab-abab-4bab-8bab-abababababab",
            "oauth-with-api-key",
            "oauth",
            api_key.id().as_str(),
        ),
        (
            "cdcdcdcd-cdcd-4dcd-8dcd-cdcdcdcdcdcd",
            "api-key-with-oauth",
            "api_key",
            oauth.id().as_str(),
        ),
    ] {
        let result = connection.execute(
            "INSERT INTO runtime_identities(
                 id, name, provider_id, provider_display_name, api_base_url, management_url,
                 auth_mode, credential_ref_id, default_model_preset_id, status,
                 created_at_unix_ms, updated_at_unix_ms, version
             ) VALUES (?1, 'Invalid Cross', ?2, 'Invalid Cross', ?3, NULL,
                       ?4, ?5, NULL, 'draft', 1000, 1000, 1)",
            params![
                id,
                provider,
                format!("https://HOST/{provider}"),
                auth_mode,
                credential_ref_id,
            ],
        );
        assert!(result.is_err());
    }
}

#[test]
fn credential_rotation_is_versioned_and_persists_after_reopen() {
    let database = TempDatabase::new();
    let reference = oauth_credential();
    let mut first = SqliteMetadataRepository::open(database.path()).unwrap();
    first.create_credential_reference(&reference).unwrap();
    let mut second = SqliteMetadataRepository::open(database.path()).unwrap();

    let rotated = reference
        .rotate(
            SchemaFingerprint::parse(&"e".repeat(64)).unwrap(),
            CredentialFingerprint::parse(&"f".repeat(64)).unwrap(),
            time(2_000),
        )
        .unwrap();
    first
        .update_credential_reference(&rotated, reference.version())
        .unwrap();

    let stale = reference
        .rotate(
            SchemaFingerprint::parse(&"1".repeat(64)).unwrap(),
            CredentialFingerprint::parse(&"2".repeat(64)).unwrap(),
            time(2_100),
        )
        .unwrap();
    assert_eq!(
        second.update_credential_reference(&stale, reference.version()),
        Err(RepositoryError::version_conflict(
            EntityKind::CredentialReference
        ))
    );
    drop(first);
    drop(second);

    let repository = SqliteMetadataRepository::open(database.path()).unwrap();
    assert_eq!(
        repository.get_credential_reference(reference.id()).unwrap(),
        Some(rotated)
    );
}

#[test]
fn future_schema_version_fails_closed_without_modification() {
    let database = TempDatabase::new();
    let connection = Connection::open(database.path()).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, applied_at_unix_ms INTEGER NOT NULL);\
             INSERT INTO schema_migrations(version, name, applied_at_unix_ms) VALUES (99, 'future', 0);",
        )
        .unwrap();
    drop(connection);

    let error = SqliteMetadataRepository::open(database.path()).unwrap_err();
    assert!(matches!(
        error,
        OpenRepositoryError::Migration(MigrationError::FutureVersion {
            found: 99,
            supported: LATEST_SCHEMA_VERSION
        })
    ));

    let connection = Connection::open(database.path()).unwrap();
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 1);
    let application_table_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'table' AND name IN ('credential_references', 'runtime_identities', 'model_presets')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(application_table_count, 0);
}

#[test]
fn repository_crud_constraints_and_reopen_persistence() {
    let database = TempDatabase::new();
    let reference = credential();
    let draft = identity(&reference);
    let model = preset(&draft);

    {
        let mut repository = SqliteMetadataRepository::open(database.path()).unwrap();
        repository.create_credential_reference(&reference).unwrap();
        repository.create_runtime_identity(&draft).unwrap();
        repository.create_model_preset(&model).unwrap();
        assert_eq!(
            repository.list_credential_references().unwrap(),
            vec![reference.clone()]
        );

        let ready = draft.set_default_preset(&model, time(3_000)).unwrap();
        repository
            .update_runtime_identity(&ready, draft.version())
            .unwrap();

        assert_eq!(
            repository.get_runtime_identity(draft.id()).unwrap(),
            Some(ready.clone())
        );
        assert_eq!(
            repository.list_runtime_identities().unwrap(),
            vec![ready.clone()]
        );
        assert_eq!(
            repository.list_model_presets(draft.id()).unwrap(),
            vec![model.clone()]
        );

        let query = IdentityCandidateQuery::new(
            draft.provider_id().clone(),
            draft.api_base_url().clone(),
            draft.auth_mode(),
            reference.credential_fingerprint().clone(),
        );
        assert_eq!(
            repository.find_identity_candidates(&query).unwrap(),
            vec![ready]
        );

        assert_eq!(
            repository.delete_model_preset(model.id(), model.version()),
            Err(RepositoryError::reference_conflict(EntityKind::ModelPreset))
        );
    }

    {
        let repository = SqliteMetadataRepository::open(database.path()).unwrap();
        assert!(
            repository
                .get_credential_reference(reference.id())
                .unwrap()
                .is_some()
        );
        assert!(
            repository
                .get_runtime_identity(draft.id())
                .unwrap()
                .is_some()
        );
        assert!(repository.get_model_preset(model.id()).unwrap().is_some());
    }
}

#[test]
fn repository_reports_unique_missing_foreign_key_and_version_conflicts() {
    let database = TempDatabase::new();
    let reference = credential();
    let draft = identity(&reference);

    let mut first = SqliteMetadataRepository::open(database.path()).unwrap();
    first.create_credential_reference(&reference).unwrap();
    first.create_runtime_identity(&draft).unwrap();
    assert_eq!(
        first.create_runtime_identity(&draft),
        Err(RepositoryError::already_exists(EntityKind::RuntimeIdentity))
    );
    let duplicate_identity_key = RuntimeIdentity::new_draft(
        IdentityId::parse("88888888-8888-4888-8888-888888888888").unwrap(),
        EntityName::parse("同一认证组合").unwrap(),
        draft.provider_id().clone(),
        draft.provider_display_name().clone(),
        draft.api_base_url().clone(),
        None,
        reference.link(),
        time(1_000),
    )
    .unwrap();
    assert_eq!(
        first.create_runtime_identity(&duplicate_identity_key),
        Err(RepositoryError::already_exists(EntityKind::RuntimeIdentity))
    );

    let missing_reference = CredentialReference::new(
        CredentialRefId::parse("55555555-5555-4555-8555-555555555555").unwrap(),
        CredentialKind::ApiKey,
        CredentialBackend::WindowsDpapiCurrentUser,
        SchemaFingerprint::parse(&"c".repeat(64)).unwrap(),
        CredentialFingerprint::parse(&"d".repeat(64)).unwrap(),
        time(1_000),
    );
    let invalid_identity = RuntimeIdentity::new_draft(
        IdentityId::parse("77777777-7777-4777-8777-777777777777").unwrap(),
        EntityName::parse("缺失引用身份").unwrap(),
        ProviderId::parse("missing-reference-provider").unwrap(),
        EntityName::parse("Missing Reference Provider").unwrap(),
        EndpointUrl::parse("https://TARGET/v1").unwrap(),
        None,
        missing_reference.link(),
        time(1_000),
    )
    .unwrap();
    assert_eq!(
        first.create_runtime_identity(&invalid_identity),
        Err(RepositoryError::reference_conflict(
            EntityKind::CredentialReference
        ))
    );

    let mut second = SqliteMetadataRepository::open(database.path()).unwrap();
    let first_update = draft
        .rename(EntityName::parse("第一次更新").unwrap(), time(2_000))
        .unwrap();
    first
        .update_runtime_identity(&first_update, draft.version())
        .unwrap();
    let stale_update = draft
        .rename(EntityName::parse("过期更新").unwrap(), time(2_100))
        .unwrap();
    assert_eq!(
        second.update_runtime_identity(&stale_update, draft.version()),
        Err(RepositoryError::version_conflict(
            EntityKind::RuntimeIdentity
        ))
    );

    let missing = IdentityId::parse("66666666-6666-4666-8666-666666666666").unwrap();
    assert_eq!(first.get_runtime_identity(&missing).unwrap(), None);
}

#[test]
fn repository_updates_presets_and_deletes_allowed_aggregate_state() {
    let database = TempDatabase::new();
    let reference = credential();
    let draft = identity(&reference);
    let original_preset = preset(&draft);
    let renamed_preset = original_preset
        .rename(EntityName::parse("高推理").unwrap(), time(2_500))
        .unwrap();

    let mut repository = SqliteMetadataRepository::open(database.path()).unwrap();
    repository.create_credential_reference(&reference).unwrap();
    repository.create_runtime_identity(&draft).unwrap();
    repository.create_model_preset(&original_preset).unwrap();
    repository
        .update_model_preset(&renamed_preset, original_preset.version())
        .unwrap();
    assert_eq!(
        repository.get_model_preset(original_preset.id()).unwrap(),
        Some(renamed_preset.clone())
    );

    let ready = draft
        .set_default_preset(&renamed_preset, time(3_000))
        .unwrap();
    repository
        .update_runtime_identity(&ready, draft.version())
        .unwrap();
    repository
        .delete_runtime_identity(ready.id(), ready.version())
        .unwrap();
    assert_eq!(repository.get_runtime_identity(ready.id()).unwrap(), None);
    assert_eq!(
        repository.get_model_preset(renamed_preset.id()).unwrap(),
        None
    );

    repository
        .delete_credential_reference(reference.id(), reference.version())
        .unwrap();
    assert_eq!(
        repository.get_credential_reference(reference.id()).unwrap(),
        None
    );
}

#[test]
fn public_domain_and_repository_path_reject_embedded_secret_storage() {
    let database = TempDatabase::new();
    let markers = vec![
        format!("{}{}", "sk-", "Z".repeat(24)),
        format!("{}{}{}", "gh", "p_", "A".repeat(24)),
        format!("{}{}{}", "AK", "IA", "0".repeat(16)),
        format!(
            "{}{}{}.{}.{}",
            "ey",
            "J",
            "A".repeat(12),
            "B".repeat(12),
            "C".repeat(12)
        ),
    ];
    let reference = credential();
    let mut repository = SqliteMetadataRepository::open(database.path()).unwrap();
    repository.create_credential_reference(&reference).unwrap();

    for marker in &markers {
        assert_secret_domain_error(EntityName::parse(&format!("prefix-{marker}")), marker);
        let repository_error = RepositoryError::storage_unavailable();
        assert!(!format!("{repository_error}").contains(marker));
        assert!(!format!("{repository_error:?}").contains(marker));
    }

    let openai = &markers[0];
    assert_secret_domain_error(
        EndpointUrl::parse(&format!("https://HOST/path/{openai}")),
        openai,
    );
    let valid_identity = identity(&reference);
    repository.create_runtime_identity(&valid_identity).unwrap();
    assert_secret_domain_error(ModelId::parse(&format!("model/{openai}")), openai);
    assert_eq!(
        repository.list_runtime_identities().unwrap(),
        vec![valid_identity]
    );
    assert!(
        repository
            .list_model_presets(&IdentityId::parse("11111111-1111-4111-8111-111111111111").unwrap())
            .unwrap()
            .is_empty()
    );
    drop(repository);

    for suffix in ["", "-wal", "-shm", "-journal"] {
        let path = PathBuf::from(format!("{}{}", database.path().display(), suffix));
        if !path.exists() {
            continue;
        }
        let bytes = fs::read(path).unwrap();
        for marker in &markers {
            assert!(
                !bytes
                    .windows(marker.len())
                    .any(|window| window == marker.as_bytes()),
                "SQLite role contained a rejected marker"
            );
        }
    }
}

#[test]
fn temporary_sqlite_files_are_removed_after_test_scope() {
    let path;
    {
        let database = TempDatabase::new();
        path = database.path().to_owned();
        let _repository = SqliteMetadataRepository::open(database.path()).unwrap();
        assert!(path.exists());
    }
    assert!(!path.exists());
}
