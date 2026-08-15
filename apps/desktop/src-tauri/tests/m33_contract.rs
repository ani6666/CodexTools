use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use codextools_desktop_lib::application_facade::{
    ApplicationFacade, BackendImportResult, BackendPresetResult, BackendScanResult,
    ControlledRootDto, CreatePresetAndBindRequest, EventSink, EventSinkError, IdentitySummaryDto,
    ImportCandidateRequest, ImportStatusDto, M33_CONTRACT_VERSION, M33Backend, M33BackendError,
    ModelPresetSummaryDto, OperationStatusEvent, SafeIdentifier, ScanDefaultCodexRequest,
};

use codex_adapter as _;
use codex_application as _;
use codex_domain as _;
use local_infrastructure as _;
use serde as _;
use tauri as _;
use windows_platform as _;

fn secret_canaries() -> Vec<String> {
    vec![
        ["sk", "-", "0123456789abcdefghij"].concat(),
        ["gh", "p_", "0123456789abcdefghij"].concat(),
        ["AKIA", "0123456789ABCDEF"].concat(),
        ["eyJabcde12345", ".", "abcdefgh1234", ".", "ijklmnop5678"].concat(),
        ["-----BEGIN ", "PRIVATE KEY", "-----"].concat(),
    ]
}

#[test]
fn requests_are_versioned_closed_and_pathless() {
    let request = ScanDefaultCodexRequest {
        schema_version: M33_CONTRACT_VERSION,
        correlation_id: SafeIdentifier::parse("corr-m33").unwrap(),
        root: ControlledRootDto::DefaultCodex,
    };
    let json = serde_json::to_string(&request).unwrap();
    assert_eq!(
        json,
        r#"{"schema_version":1,"correlation_id":"corr-m33","root":"default_codex"}"#
    );
    assert!(
        serde_json::from_str::<ScanDefaultCodexRequest>(&format!(
            "{}{}",
            json.trim_end_matches('}'),
            r#",\"unknown\":true}"#
        ))
        .is_err()
    );
    assert!(!json.contains('\\'));
    assert!(!json.contains('/'));
}

#[test]
fn allowed_character_secret_canaries_fail_closed_without_echo() {
    for canary in secret_canaries() {
        let error = SafeIdentifier::parse(canary.clone()).unwrap_err();
        assert!(!format!("{error:?} {error}").contains(&canary));
    }
}

#[test]
fn managed_metadata_rejects_secret_and_path_shapes_without_echo() {
    let canary = ["sk", "-", "0123456789abcdefghij"].concat();
    let json = format!(
        r#"{{"schema_version":1,"operation_id":"op","correlation_id":"corr","identity_id":"00000000-0000-0000-0000-000000000001","expected_identity_version":1,"preset_id":"00000000-0000-0000-0000-000000000002","name":"safe","model_id":"{canary}"}}"#
    );
    let error = serde_json::from_str::<CreatePresetAndBindRequest>(&json).unwrap_err();
    assert!(!error.to_string().contains(&canary));

    let path = "C:/Users/example/model";
    let json = json.replace(&canary, path);
    let error = serde_json::from_str::<CreatePresetAndBindRequest>(&json).unwrap_err();
    assert!(!error.to_string().contains(path));
}

struct CountingBackend(AtomicUsize);

impl M33Backend for CountingBackend {
    fn scan_default_codex(&self) -> Result<BackendScanResult, M33BackendError> {
        Err(M33BackendError::Unavailable)
    }
    fn import_candidate(&self, _: &str) -> Result<BackendImportResult, M33BackendError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(BackendImportResult {
            status: ImportStatusDto::Imported,
            identity_id: "00000000-0000-0000-0000-000000000001".to_owned(),
        })
    }
    fn list_identities(&self) -> Result<Vec<IdentitySummaryDto>, M33BackendError> {
        Ok(Vec::new())
    }
    fn rename_identity(
        &self,
        _: &str,
        _: u64,
        _: &str,
    ) -> Result<IdentitySummaryDto, M33BackendError> {
        Err(M33BackendError::NotFound)
    }
    fn list_presets(&self, _: &str) -> Result<Vec<ModelPresetSummaryDto>, M33BackendError> {
        Ok(Vec::new())
    }
    fn create_preset_and_bind(
        &self,
        _: &CreatePresetAndBindRequest,
    ) -> Result<BackendPresetResult, M33BackendError> {
        Err(M33BackendError::Unavailable)
    }
    fn update_preset_and_bind(
        &self,
        _: &codextools_desktop_lib::application_facade::UpdatePresetAndBindRequest,
    ) -> Result<BackendPresetResult, M33BackendError> {
        Err(M33BackendError::Unavailable)
    }
}

struct RejectingSink;
impl EventSink for RejectingSink {
    fn publish(&self, _: &OperationStatusEvent) -> Result<(), EventSinkError> {
        Err(EventSinkError)
    }
}

fn import_request() -> ImportCandidateRequest {
    ImportCandidateRequest {
        schema_version: M33_CONTRACT_VERSION,
        operation_id: SafeIdentifier::parse("import-op").unwrap(),
        correlation_id: SafeIdentifier::parse("corr-op").unwrap(),
        root: ControlledRootDto::DefaultCodex,
        scan_id: SafeIdentifier::parse("a".repeat(64)).unwrap(),
    }
}

#[test]
fn sink_failure_rolls_back_before_backend_and_duplicate_request_is_stable() {
    let rejected_backend = Arc::new(CountingBackend(AtomicUsize::new(0)));
    let facade = ApplicationFacade::with_backend(Arc::new(RejectingSink), rejected_backend.clone());
    assert_eq!(
        facade.import_candidate(import_request()).unwrap_err().code,
        codextools_desktop_lib::application_facade::ErrorCode::Unavailable
    );
    assert_eq!(rejected_backend.0.load(Ordering::SeqCst), 0);
    assert_eq!(facade.operation_count().unwrap(), 0);

    let backend = Arc::new(CountingBackend(AtomicUsize::new(0)));
    let facade = ApplicationFacade::with_backend(
        Arc::new(codextools_desktop_lib::application_facade::NoopEventSink),
        backend.clone(),
    );
    assert_eq!(
        facade.import_candidate(import_request()).unwrap().status,
        ImportStatusDto::Imported
    );
    assert_eq!(
        facade.import_candidate(import_request()).unwrap_err().code,
        codextools_desktop_lib::application_facade::ErrorCode::Conflict
    );
    assert_eq!(backend.0.load(Ordering::SeqCst), 1);
}
