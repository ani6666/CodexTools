use std::{
    sync::{
        Arc, Barrier,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
};

use codextools_desktop_lib::application_facade::{
    ApplicationFacade, BackendRecoveryResult, BackendRecoverySummary, BackendSwitchExecution,
    BackendSwitchOperation, BackendSwitchPreview, CancelOperationRequest, CancellationOutcome,
    EventSink, EventSinkError, ExecuteSwitchRequest, IdentitySummaryDto, M34_CONTRACT_VERSION,
    M34Backend, M34BackendError, ModelPresetSummaryDto, OperationStatusEvent, PreviewSwitchRequest,
    SafeIdentifier, SwitchCompatibilityDto, SwitchExecutionStatusDto, SwitchOperationStateDto,
    UnavailableM33Backend,
};

use codex_adapter as _;
use codex_application as _;
use codex_domain as _;
use local_infrastructure as _;
use serde as _;
use tauri as _;
use tauri_plugin_single_instance as _;
use windows_platform as _;

fn identifier(value: &str) -> SafeIdentifier {
    SafeIdentifier::parse(value).unwrap()
}

fn preview_request() -> PreviewSwitchRequest {
    PreviewSwitchRequest {
        schema_version: M34_CONTRACT_VERSION,
        correlation_id: identifier("corr-m34"),
        identity_id: identifier("41414141-4141-4141-8141-414141414141"),
        expected_identity_version: 1,
        preset_id: identifier("51515151-5151-4151-8151-515151515151"),
        expected_preset_version: 1,
    }
}

fn backend_preview() -> BackendSwitchPreview {
    BackendSwitchPreview {
        plan_id: "71717171-7171-4171-8171-717171717171".to_owned(),
        plan_version: 1,
        operation_id: "71717171-7171-4171-8171-717171717171".to_owned(),
        identity: IdentitySummaryDto {
            identity_id: "41414141-4141-4141-8141-414141414141".to_owned(),
            credential_ref_id: "61616161-6161-4161-8161-616161616161".to_owned(),
            name: "Synthetic".to_owned(),
            provider_name: "Sample".to_owned(),
            auth_mode: codextools_desktop_lib::application_facade::AuthModeDto::ApiKey,
            status: "ready".to_owned(),
            default_preset_id: Some("51515151-5151-4151-8151-515151515151".to_owned()),
            version: 1,
        },
        preset: ModelPresetSummaryDto {
            preset_id: "51515151-5151-4151-8151-515151515151".to_owned(),
            name: "Default".to_owned(),
            model_id: "sample-model".to_owned(),
            version: 1,
            is_default: true,
        },
        affected_items: 2,
        compatibility: SwitchCompatibilityDto::Ready,
    }
}

fn execute_request() -> ExecuteSwitchRequest {
    ExecuteSwitchRequest {
        schema_version: M34_CONTRACT_VERSION,
        correlation_id: identifier("execute-corr"),
        plan_id: identifier("71717171-7171-4171-8171-717171717171"),
        expected_plan_version: 1,
        operation_id: identifier("71717171-7171-4171-8171-717171717171"),
    }
}

#[derive(Default)]
struct CountingM34Backend {
    validates: AtomicUsize,
    executes: AtomicUsize,
}
impl M34Backend for CountingM34Backend {
    fn preview_switch(
        &self,
        _: &PreviewSwitchRequest,
    ) -> Result<BackendSwitchPreview, M34BackendError> {
        Ok(backend_preview())
    }
    fn validate_switch(&self, _: &str, _: u64, _: &str) -> Result<(), M34BackendError> {
        self.validates.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn execute_switch(
        &self,
        _: &str,
        _: u64,
        _: &str,
    ) -> Result<BackendSwitchExecution, M34BackendError> {
        self.executes.fetch_add(1, Ordering::SeqCst);
        Ok(BackendSwitchExecution {
            status: SwitchExecutionStatusDto::Applied,
            operation: BackendSwitchOperation {
                operation_id: backend_preview().operation_id,
                state: SwitchOperationStateDto::Completed,
                completed_items: 2,
                total_items: 2,
            },
        })
    }
    fn query_switch(&self, _: &str) -> Result<BackendSwitchOperation, M34BackendError> {
        Err(M34BackendError::NotFound)
    }
    fn list_recoveries(&self) -> Result<Vec<BackendRecoverySummary>, M34BackendError> {
        Ok(Vec::new())
    }
    fn recover_switch(&self, _: &str) -> Result<BackendRecoveryResult, M34BackendError> {
        Err(M34BackendError::NotFound)
    }
}

struct RejectingSink;
impl EventSink for RejectingSink {
    fn publish(&self, _: &OperationStatusEvent) -> Result<(), EventSinkError> {
        Err(EventSinkError)
    }
}

struct FailAfterSink {
    calls: AtomicUsize,
    fail_at: usize,
}
impl EventSink for FailAfterSink {
    fn publish(&self, _: &OperationStatusEvent) -> Result<(), EventSinkError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call >= self.fail_at {
            Err(EventSinkError)
        } else {
            Ok(())
        }
    }
}

#[test]
fn requests_are_versioned_closed_and_pathless() {
    let json = serde_json::to_string(&preview_request()).unwrap();
    assert!(!json.contains('\\'));
    assert!(!json.contains("config"));
    assert!(
        serde_json::from_str::<PreviewSwitchRequest>(&format!(
            "{}{}",
            json.trim_end_matches('}'),
            r#",\"unknown\":true}"#
        ))
        .is_err()
    );
}

#[test]
fn unknown_version_and_secret_or_path_identifiers_fail_closed_without_echo() {
    let backend = Arc::new(CountingM34Backend::default());
    let facade = ApplicationFacade::with_backends(
        Arc::new(codextools_desktop_lib::application_facade::NoopEventSink),
        Arc::new(UnavailableM33Backend),
        backend,
    );
    let mut request = preview_request();
    request.schema_version = 99;
    assert_eq!(
        facade.preview_switch(request).unwrap_err().code,
        codextools_desktop_lib::application_facade::ErrorCode::Validation
    );
    let canary = ["gh", "p_", "0123456789abcdefghij"].concat();
    let error = SafeIdentifier::parse(canary.clone()).unwrap_err();
    assert!(!format!("{error:?} {error}").contains(&canary));
    let path = "C:/synthetic/private";
    let error = SafeIdentifier::parse(path.to_owned()).unwrap_err();
    assert!(!format!("{error:?} {error}").contains(path));
}

#[test]
fn preview_is_read_only_and_execute_is_a_single_backend_call() {
    let backend = Arc::new(CountingM34Backend::default());
    let facade = ApplicationFacade::with_backends(
        Arc::new(codextools_desktop_lib::application_facade::NoopEventSink),
        Arc::new(UnavailableM33Backend),
        backend.clone(),
    );
    let preview = facade.preview_switch(preview_request()).unwrap();
    assert_eq!(preview.preview.plan_version, 1);
    assert_eq!(backend.executes.load(Ordering::SeqCst), 0);
    let response = facade.execute_switch(execute_request()).unwrap();
    assert_eq!(response.status, SwitchExecutionStatusDto::Applied);
    assert_eq!(backend.validates.load(Ordering::SeqCst), 1);
    assert_eq!(backend.executes.load(Ordering::SeqCst), 1);
    assert_eq!(facade.operation_count().unwrap(), 0);
}

#[test]
fn initial_sink_failure_prevents_validation_and_execution() {
    let backend = Arc::new(CountingM34Backend::default());
    let facade = ApplicationFacade::with_backends(
        Arc::new(RejectingSink),
        Arc::new(UnavailableM33Backend),
        backend.clone(),
    );
    let request = execute_request();
    assert!(facade.execute_switch(request).is_err());
    assert_eq!(backend.validates.load(Ordering::SeqCst), 0);
    assert_eq!(backend.executes.load(Ordering::SeqCst), 0);
    assert_eq!(facade.operation_count().unwrap(), 0);
}

#[test]
fn sink_failure_after_atomic_entry_does_not_change_backend_outcome() {
    let backend = Arc::new(CountingM34Backend::default());
    let sink = Arc::new(FailAfterSink {
        calls: AtomicUsize::new(0),
        fail_at: 5,
    });
    let facade =
        ApplicationFacade::with_backends(sink, Arc::new(UnavailableM33Backend), backend.clone());
    assert_eq!(
        facade.execute_switch(execute_request()).unwrap().status,
        SwitchExecutionStatusDto::Applied
    );
    assert_eq!(backend.executes.load(Ordering::SeqCst), 1);
    assert_eq!(facade.operation_count().unwrap(), 0);
}

struct BlockingM34Backend {
    validate_entered: Arc<Barrier>,
    validate_release: Arc<Barrier>,
    execute_entered: Arc<Barrier>,
    execute_release: Arc<Barrier>,
    block_validate: bool,
}

impl M34Backend for BlockingM34Backend {
    fn validate_switch(&self, _: &str, _: u64, _: &str) -> Result<(), M34BackendError> {
        if self.block_validate {
            self.validate_entered.wait();
            self.validate_release.wait();
        }
        Ok(())
    }

    fn execute_switch(
        &self,
        _: &str,
        _: u64,
        _: &str,
    ) -> Result<BackendSwitchExecution, M34BackendError> {
        self.execute_entered.wait();
        self.execute_release.wait();
        Ok(BackendSwitchExecution {
            status: SwitchExecutionStatusDto::Applied,
            operation: BackendSwitchOperation {
                operation_id: "71717171-7171-4171-8171-717171717171".to_owned(),
                state: SwitchOperationStateDto::Completed,
                completed_items: 2,
                total_items: 2,
            },
        })
    }
}

fn cancel_request() -> CancelOperationRequest {
    CancelOperationRequest {
        schema_version: 1,
        operation_id: identifier("71717171-7171-4171-8171-717171717171"),
        correlation_id: identifier("cancel-corr"),
    }
}

#[test]
fn cancellation_before_critical_stops_backend_and_releases_registration() {
    let validate_entered = Arc::new(Barrier::new(2));
    let validate_release = Arc::new(Barrier::new(2));
    let execute_entered = Arc::new(Barrier::new(2));
    let execute_release = Arc::new(Barrier::new(2));
    let facade = ApplicationFacade::with_backends(
        Arc::new(codextools_desktop_lib::application_facade::NoopEventSink),
        Arc::new(UnavailableM33Backend),
        Arc::new(BlockingM34Backend {
            validate_entered: validate_entered.clone(),
            validate_release: validate_release.clone(),
            execute_entered,
            execute_release,
            block_validate: true,
        }),
    );
    let worker = {
        let facade = facade.clone();
        thread::spawn(move || facade.execute_switch(execute_request()))
    };
    validate_entered.wait();
    assert_eq!(
        facade.cancel_operation(cancel_request()).unwrap().outcome,
        CancellationOutcome::Requested
    );
    assert_eq!(
        facade.cancel_operation(cancel_request()).unwrap().outcome,
        CancellationOutcome::AlreadyRequested
    );
    validate_release.wait();
    assert_eq!(
        worker.join().unwrap().unwrap_err().code,
        codextools_desktop_lib::application_facade::ErrorCode::Cancelled
    );
    assert_eq!(facade.operation_count().unwrap(), 0);
}

#[test]
fn cancellation_after_critical_is_too_late_and_execution_completes() {
    let validate_entered = Arc::new(Barrier::new(1));
    let validate_release = Arc::new(Barrier::new(1));
    let execute_entered = Arc::new(Barrier::new(2));
    let execute_release = Arc::new(Barrier::new(2));
    let facade = ApplicationFacade::with_backends(
        Arc::new(codextools_desktop_lib::application_facade::NoopEventSink),
        Arc::new(UnavailableM33Backend),
        Arc::new(BlockingM34Backend {
            validate_entered,
            validate_release,
            execute_entered: execute_entered.clone(),
            execute_release: execute_release.clone(),
            block_validate: false,
        }),
    );
    let worker = {
        let facade = facade.clone();
        thread::spawn(move || facade.execute_switch(execute_request()))
    };
    execute_entered.wait();
    assert_eq!(
        facade.execute_switch(execute_request()).unwrap_err().code,
        codextools_desktop_lib::application_facade::ErrorCode::Conflict
    );
    assert_eq!(
        facade.cancel_operation(cancel_request()).unwrap().outcome,
        CancellationOutcome::TooLate
    );
    execute_release.wait();
    assert_eq!(
        worker.join().unwrap().unwrap().status,
        SwitchExecutionStatusDto::Applied
    );
    assert_eq!(facade.operation_count().unwrap(), 0);
}
