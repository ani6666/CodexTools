use codex_domain::{
    AuthMode, CredentialBackend, CredentialFingerprint, CredentialKind, CredentialLink,
    CredentialRefId, CredentialReference, DomainError, EndpointUrl, EntityName, EntityVersion,
    IdentityId, IdentityStatus, ModelId, ModelPreset, ModelPresetId, ProviderId, RuntimeIdentity,
    SchemaFingerprint, SwitchTransaction, SwitchTransactionId, SwitchTransactionState, UnixMillis,
};

fn time(value: i64) -> UnixMillis {
    UnixMillis::new(value).expect("valid time")
}

#[test]
fn switch_transaction_state_machine_is_monotonic_and_fail_closed() {
    let hash =
        |value: char| codex_domain::ContentHash::parse(&value.to_string().repeat(64)).unwrap();
    let mut transaction = SwitchTransaction::new(
        SwitchTransactionId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
        hash('a'),
        Some(hash('b')),
        Some(hash('c')),
        hash('d'),
        hash('e'),
        ProviderId::parse("sample").unwrap(),
        ModelId::parse("gpt-TARGET").unwrap(),
        CredentialFingerprint::parse(&"f".repeat(64)).unwrap(),
        time(1),
    );
    for state in [
        SwitchTransactionState::LockAcquired,
        SwitchTransactionState::SnapshotCreated,
        SwitchTransactionState::TargetsStaged,
        SwitchTransactionState::Replacing,
    ] {
        transaction = transaction.transition(state, time(1)).unwrap();
    }
    transaction = transaction
        .mark_replaced(codex_domain::FileRole::Config, time(1))
        .unwrap();
    transaction = transaction
        .mark_replaced(codex_domain::FileRole::Authentication, time(1))
        .unwrap();
    for state in [
        SwitchTransactionState::TargetsReplaced,
        SwitchTransactionState::Verified,
        SwitchTransactionState::Committed,
    ] {
        transaction = transaction.transition(state, time(1)).unwrap();
    }
    assert_eq!(transaction.completed_roles(), 3);
    assert_eq!(transaction.state(), SwitchTransactionState::Committed);
    assert_eq!(
        transaction.transition(SwitchTransactionState::RollingBack, time(2)),
        Err(DomainError::TransactionStateMismatch)
    );
    let planned = SwitchTransaction::new(
        SwitchTransactionId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
        hash('a'),
        None,
        None,
        hash('d'),
        hash('e'),
        ProviderId::parse("sample").unwrap(),
        ModelId::parse("gpt-TARGET").unwrap(),
        CredentialFingerprint::parse(&"f".repeat(64)).unwrap(),
        time(2),
    );
    assert_eq!(
        planned.transition(SwitchTransactionState::TargetsStaged, time(2)),
        Err(DomainError::TransactionStateMismatch)
    );
    assert_eq!(
        planned.transition(SwitchTransactionState::RollingBack, time(2)),
        Err(DomainError::TransactionStateMismatch)
    );
    assert_eq!(
        planned
            .transition(SwitchTransactionState::RolledBack, time(2))
            .unwrap()
            .state(),
        SwitchTransactionState::RolledBack
    );

    let replacing = planned
        .transition(SwitchTransactionState::LockAcquired, time(2))
        .unwrap()
        .transition(SwitchTransactionState::SnapshotCreated, time(2))
        .unwrap()
        .transition(SwitchTransactionState::TargetsStaged, time(2))
        .unwrap()
        .transition(SwitchTransactionState::Replacing, time(2))
        .unwrap();
    assert_eq!(
        replacing.transition(SwitchTransactionState::TargetsReplaced, time(2)),
        Err(DomainError::TransactionStateMismatch)
    );
    assert_eq!(
        SwitchTransaction::restore(
            SwitchTransactionId::parse("33333333-3333-4333-8333-333333333333").unwrap(),
            hash('a'),
            None,
            None,
            hash('d'),
            hash('e'),
            ProviderId::parse("sample").unwrap(),
            ModelId::parse("gpt-TARGET").unwrap(),
            CredentialFingerprint::parse(&"f".repeat(64)).unwrap(),
            SwitchTransactionState::Committed,
            0,
            time(2),
            time(2),
            EntityVersion::initial(),
        ),
        Err(DomainError::TransactionStateMismatch)
    );
}

#[test]
fn managed_patch_keeps_only_non_secret_hash_metadata() {
    let patch = codex_domain::ManagedConfigPatch::new(
        codex_domain::ManagedConfigPatchId::parse("44444444-4444-4444-8444-444444444444").unwrap(),
        IdentityId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
        codex_domain::ContentHash::parse(&"a".repeat(64)).unwrap(),
        codex_domain::ContentHash::parse(&"b".repeat(64)).unwrap(),
        time(1_000),
    );
    let debug = format!("{patch:?}");
    assert!(!debug.contains(&"a".repeat(64)));
    assert!(!debug.contains(&"b".repeat(64)));
    assert_eq!(codex_domain::MANAGED_CONFIG_PATHS.len(), 4);
}

fn credential(kind: CredentialKind) -> CredentialReference {
    CredentialReference::new(
        CredentialRefId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
        kind,
        CredentialBackend::WindowsDpapiCurrentUser,
        SchemaFingerprint::parse(&"a".repeat(64)).unwrap(),
        CredentialFingerprint::parse(&"b".repeat(64)).unwrap(),
        time(1_000),
    )
}

fn assert_secret_error<T>(result: Result<T, DomainError>, marker: &str) {
    let error = match result {
        Ok(_) => panic!("embedded high-confidence marker was accepted"),
        Err(error) => error,
    };
    assert_eq!(error, DomainError::SecretLikeInput);
    assert!(!format!("{error}").contains(marker));
    assert!(!format!("{error:?}").contains(marker));
}

fn draft_identity(reference: &CredentialReference) -> RuntimeIdentity {
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
fn constructs_draft_identity_and_transitions_to_ready() {
    let reference = credential(CredentialKind::ApiKey);
    let draft = draft_identity(&reference);
    assert_eq!(draft.status(), IdentityStatus::Draft);
    assert_eq!(draft.auth_mode(), AuthMode::ApiKey);
    assert_eq!(draft.version(), EntityVersion::initial());

    let preset = preset(&draft);
    let ready = draft.set_default_preset(&preset, time(3_000)).unwrap();
    assert_eq!(ready.status(), IdentityStatus::Ready);
    assert_eq!(ready.default_model_preset_id(), Some(preset.id()));
    assert_eq!(ready.version(), EntityVersion::new(2).unwrap());
}

#[test]
fn rejects_empty_oversized_and_secret_like_text() {
    assert_eq!(EntityName::parse(" "), Err(DomainError::EmptyValue));
    assert_eq!(
        EntityName::parse(&"x".repeat(81)),
        Err(DomainError::ValueTooLong)
    );
    let marker = "sk-".to_owned() + &"Z".repeat(24);
    let error = EntityName::parse(&marker).unwrap_err();
    assert_eq!(error, DomainError::SecretLikeInput);
    assert!(!format!("{error}").contains(&marker));
    assert!(!format!("{error:?}").contains(&marker));
}

#[test]
fn rejects_embedded_high_confidence_secrets_across_metadata_values() {
    let openai = format!("{}{}", "sk-", "Z".repeat(24));
    assert_secret_error(EntityName::parse(&format!("prefix-{openai}")), &openai);
    assert_secret_error(
        EndpointUrl::parse(&format!("https://HOST/path/{openai}")),
        &openai,
    );
    assert_secret_error(ModelId::parse(&format!("model/{openai}")), &openai);

    let github = format!("{}{}{}", "gh", "p_", "A".repeat(24));
    assert_secret_error(EntityName::parse(&format!("prefix-{github}")), &github);

    let aws = format!("{}{}{}", "AK", "IA", "0".repeat(16));
    assert_secret_error(EntityName::parse(&format!("prefix-{aws}")), &aws);

    let jwt = format!(
        "{}{}{}.{}.{}",
        "ey",
        "J",
        "A".repeat(12),
        "B".repeat(12),
        "C".repeat(12)
    );
    assert_secret_error(EntityName::parse(&format!("prefix-{jwt}")), &jwt);
}

#[test]
fn credential_reference_is_opaque_and_debug_redacts_fingerprints() {
    let reference = credential(CredentialKind::OAuthBundle);
    let debug = format!("{reference:?}");
    assert!(debug.contains("OAuthBundle"));
    assert!(!debug.contains(&"a".repeat(64)));
    assert!(!debug.contains(&"b".repeat(64)));
    assert!(format!("{reference}").contains("credential reference"));
}

#[test]
fn credential_rotation_updates_only_non_secret_fingerprints_and_version() {
    let reference = credential(CredentialKind::OAuthBundle);
    let rotated = reference
        .rotate(
            SchemaFingerprint::parse(&"c".repeat(64)).unwrap(),
            CredentialFingerprint::parse(&"d".repeat(64)).unwrap(),
            time(2_000),
        )
        .unwrap();

    assert_eq!(rotated.id(), reference.id());
    assert_eq!(rotated.kind(), reference.kind());
    assert_eq!(rotated.backend(), reference.backend());
    assert_eq!(rotated.created_at(), reference.created_at());
    assert_eq!(rotated.updated_at(), time(2_000));
    assert_eq!(rotated.version(), EntityVersion::new(2).unwrap());
    assert!(!format!("{rotated:?}").contains(&"c".repeat(64)));
    assert!(!format!("{rotated:?}").contains(&"d".repeat(64)));

    assert_eq!(
        reference.rotate(
            SchemaFingerprint::parse(&"e".repeat(64)).unwrap(),
            CredentialFingerprint::parse(&"f".repeat(64)).unwrap(),
            time(999),
        ),
        Err(DomainError::TimestampOrder)
    );
}

#[test]
fn rejects_invalid_reference_and_authentication_combinations() {
    assert!(CredentialRefId::parse("not-an-id").is_err());
    assert!(SchemaFingerprint::parse("short").is_err());
    assert!(CredentialFingerprint::parse(&"G".repeat(64)).is_err());

    let link = CredentialLink::new(
        CredentialRefId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
        CredentialKind::ApiKey,
    );
    let result = RuntimeIdentity::restore(
        IdentityId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
        EntityName::parse("身份").unwrap(),
        ProviderId::parse("sample").unwrap(),
        EntityName::parse("Sample").unwrap(),
        EndpointUrl::parse("https://HOST/v1").unwrap(),
        None,
        AuthMode::OAuth,
        link,
        None,
        IdentityStatus::Draft,
        time(1),
        time(1),
        EntityVersion::initial(),
    );
    assert_eq!(result.unwrap_err(), DomainError::CredentialKindMismatch);

    let oauth_link = CredentialLink::new(
        CredentialRefId::parse("55555555-5555-4555-8555-555555555555").unwrap(),
        CredentialKind::OAuthBundle,
    );
    let reverse_result = RuntimeIdentity::restore(
        IdentityId::parse("66666666-6666-4666-8666-666666666666").unwrap(),
        EntityName::parse("反向错误身份").unwrap(),
        ProviderId::parse("reverse-sample").unwrap(),
        EntityName::parse("Reverse Sample").unwrap(),
        EndpointUrl::parse("https://HOST/reverse/v1").unwrap(),
        None,
        AuthMode::ApiKey,
        oauth_link,
        None,
        IdentityStatus::Draft,
        time(1),
        time(1),
        EntityVersion::initial(),
    );
    assert_eq!(
        reverse_result.unwrap_err(),
        DomainError::CredentialKindMismatch
    );
}

#[test]
fn validates_urls_versions_and_timestamps() {
    assert!(EndpointUrl::parse("ftp://HOST/path").is_err());
    assert!(EndpointUrl::parse("https://TOKEN@HOST/path").is_err());
    assert!(EndpointUrl::parse("https://HOST/path?token=TOKEN").is_err());
    assert!(EntityVersion::new(0).is_err());
    assert!(UnixMillis::new(-1).is_err());

    let reference = credential(CredentialKind::ApiKey);
    let identity = draft_identity(&reference);
    assert_eq!(
        identity.rename(EntityName::parse("新名称").unwrap(), time(999)),
        Err(DomainError::TimestampOrder)
    );
}

#[test]
fn default_preset_must_belong_to_identity() {
    let reference = credential(CredentialKind::ApiKey);
    let identity = draft_identity(&reference);
    let other = RuntimeIdentity::new_draft(
        IdentityId::parse("44444444-4444-4444-8444-444444444444").unwrap(),
        EntityName::parse("其他身份").unwrap(),
        ProviderId::parse("other").unwrap(),
        EntityName::parse("Other").unwrap(),
        EndpointUrl::parse("https://HOST/v2").unwrap(),
        None,
        reference.link(),
        time(1_000),
    )
    .unwrap();
    let foreign_preset = preset(&other);
    assert_eq!(
        identity.set_default_preset(&foreign_preset, time(3_000)),
        Err(DomainError::PresetIdentityMismatch)
    );
}
