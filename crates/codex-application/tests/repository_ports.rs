use codex_application::{EntityKind, RepositoryError};
use codex_domain as _;
use zeroize as _;

#[test]
fn repository_errors_are_structured_and_do_not_echo_input() {
    let marker = "sk-".to_owned() + &"Z".repeat(24);
    let errors = [
        RepositoryError::not_found(EntityKind::RuntimeIdentity),
        RepositoryError::already_exists(EntityKind::CredentialReference),
        RepositoryError::version_conflict(EntityKind::ModelPreset),
        RepositoryError::reference_conflict(EntityKind::RuntimeIdentity),
        RepositoryError::corrupt_data(),
        RepositoryError::storage_unavailable(),
    ];

    for error in errors {
        assert!(!format!("{error}").contains(&marker));
        assert!(!format!("{error:?}").contains(&marker));
    }
}
