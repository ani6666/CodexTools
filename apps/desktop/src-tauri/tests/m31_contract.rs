use std::sync::{Arc, Mutex};

use codex_adapter as _;
use codex_domain as _;
use tauri as _;
use windows_platform as _;

use codex_application::{
    ApplicationError, BackupStoreError, CompatibilityReason, CredentialStoreError, EntityKind,
    OAuthCaptureError, RepositoryError, SwitchExecutionError,
};
use codextools_desktop_lib::application_facade::{
    ApplicationFacade, CancelOperationRequest, CancellationCheckpoint, CancellationOutcome,
    DescribeContractRequest, ErrorCode, ErrorEnvelope, EventSink, EventSinkError,
    M31_CONTRACT_VERSION, OperationRegistry, OperationStatusEvent, SafeIdentifier,
};
use local_infrastructure::{CredentialServiceError, VerticalClosureError};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;

const CANARY: &str = "M31_CANARY_SECRET_DO_NOT_LEAK_7f9!";
const DANGEROUS_PATH: &str = r"C:\Users\example\.private\auth-material.json";
const OPENAI_CANARY: &str = concat!("s", "k-", "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456");
const GITHUB_CANARY: &str = concat!("g", "hp_", "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456");
const AWS_CANARY: &str = concat!("AK", "IA", "ABCDEFGHIJKLMNOP");
const JWT_CANARY: &str = concat!("e", "yJabcdefgh", ".abcdefgh", ".abcdefgh");
const PRIVATE_KEY_HEADER: &str = concat!("-----BEGIN ", "PRIVATE KEY-----");

fn identifier(value: &str) -> SafeIdentifier {
    SafeIdentifier::parse(value).expect("test identifier must be safe")
}

fn assert_roundtrip<T>(value: &T)
where
    T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let json = serde_json::to_string(value).expect("contract value must serialize");
    let decoded = serde_json::from_str::<T>(&json).expect("contract value must deserialize");
    assert_eq!(&decoded, value);
}

fn assert_code<E>(error: E, expected: ErrorCode)
where
    ErrorEnvelope: From<E>,
{
    let envelope = ErrorEnvelope::from(error);
    assert_eq!(envelope.code, expected);
    let outputs = [
        format!("{envelope:?}"),
        envelope.to_string(),
        serde_json::to_string(&envelope).expect("error must serialize"),
    ];
    for output in outputs {
        assert!(!output.contains(CANARY));
        assert!(!output.contains(DANGEROUS_PATH));
    }
}

#[derive(Debug, Default)]
struct CapturingEventSink {
    events: Mutex<Vec<OperationStatusEvent>>,
}

impl EventSink for CapturingEventSink {
    fn publish(&self, event: &OperationStatusEvent) -> Result<(), EventSinkError> {
        self.events
            .lock()
            .expect("test event sink lock must be available")
            .push(event.clone());
        Ok(())
    }
}

#[derive(Debug)]
struct FailingEventSink {
    fail: Mutex<bool>,
}

impl EventSink for FailingEventSink {
    fn publish(&self, _event: &OperationStatusEvent) -> Result<(), EventSinkError> {
        if *self.fail.lock().expect("failure flag lock") {
            Err(EventSinkError)
        } else {
            Ok(())
        }
    }
}

#[test]
fn request_response_event_error_debug_display_and_json_are_secret_free() {
    assert!(SafeIdentifier::parse(CANARY).is_err());
    assert!(SafeIdentifier::parse(DANGEROUS_PATH).is_err());
    for secret_like in [
        OPENAI_CANARY,
        GITHUB_CANARY,
        AWS_CANARY,
        JWT_CANARY,
        PRIVATE_KEY_HEADER,
        DANGEROUS_PATH,
    ] {
        let error = SafeIdentifier::parse(secret_like)
            .expect_err("secret-like identifier must be rejected");
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(secret_like));
    }
    for allowed_shape_canary in [OPENAI_CANARY, GITHUB_CANARY, AWS_CANARY, JWT_CANARY] {
        assert!((1..=64).contains(&allowed_shape_canary.len()));
        assert!(allowed_shape_canary.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
        }));
    }
    for ordinary in [
        "550e8400-e29b-41d4-a716-446655440000",
        "operation-01",
        "correlation:01",
    ] {
        assert!(SafeIdentifier::parse(ordinary).is_ok());
    }

    for unsafe_value in [
        CANARY,
        OPENAI_CANARY,
        GITHUB_CANARY,
        AWS_CANARY,
        JWT_CANARY,
        PRIVATE_KEY_HEADER,
        DANGEROUS_PATH,
    ] {
        let unsafe_json = json!({
            "schema_version": M31_CONTRACT_VERSION,
            "correlation_id": unsafe_value,
        });
        let error = serde_json::from_value::<DescribeContractRequest>(unsafe_json)
            .expect_err("unsafe identifier must not cross IPC");
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(unsafe_value));
    }

    let request = DescribeContractRequest {
        schema_version: M31_CONTRACT_VERSION,
        correlation_id: identifier("correlation-01"),
    };
    assert_roundtrip(&request);

    let sink = Arc::new(CapturingEventSink::default());
    let facade = ApplicationFacade::new(sink.clone());
    let response = facade
        .describe_contract(request.clone())
        .expect("contract description must be available without Tauri runtime");
    assert_eq!(
        serde_json::to_value(&response).expect("response must serialize"),
        json!({
            "schema_version": 1,
            "correlation_id": "correlation-01",
            "commands": {
                "describe_contract": "describe_contract_v1",
                "cancel_operation": "cancel_operation_v1"
            },
            "events": {
                "operation_status": "codextools://operation-status/v1"
            },
            "capabilities": {
                "accepts_secret_material": false,
                "accesses_live_codex_state": false,
                "performs_network_requests": false,
                "supports_cancellation_contract": true
            }
        })
    );
    assert_roundtrip(&response);

    facade
        .register_operation(identifier("operation-01"), identifier("correlation-01"))
        .expect("operation registration must not access external state");
    let event = sink
        .events
        .lock()
        .expect("test event sink lock must be available")[0]
        .clone();
    assert_roundtrip(&event);

    let error = ErrorEnvelope::from_code(ErrorCode::CompatibilityProtected);
    assert_roundtrip(&error);

    let outputs = [
        format!("{request:?}"),
        serde_json::to_string(&request).expect("request must serialize"),
        format!("{response:?}"),
        serde_json::to_string(&response).expect("response must serialize"),
        format!("{event:?}"),
        serde_json::to_string(&event).expect("event must serialize"),
        format!("{error:?}"),
        error.to_string(),
        serde_json::to_string(&error).expect("error must serialize"),
        format!("{facade:?}"),
    ];
    for output in outputs {
        assert!(!output.contains(CANARY));
        assert!(!output.contains(DANGEROUS_PATH));
    }
}

#[test]
fn cancellation_semantics_are_stable() {
    let unknown = identifier("unknown-operation");
    let first = identifier("operation-cancellable");
    let atomic = identifier("operation-atomic");
    let completed = identifier("operation-completed");
    let mut registry = OperationRegistry::default();

    assert_eq!(
        registry.cancel(&unknown),
        CancellationOutcome::UnknownOperation
    );
    registry
        .register(first.clone())
        .expect("first registration");
    assert_eq!(registry.cancel(&first), CancellationOutcome::Requested);
    assert_eq!(
        registry.cancel(&first),
        CancellationOutcome::AlreadyRequested
    );
    assert_eq!(
        registry.checkpoint(&first),
        CancellationCheckpoint::Cancelled
    );
    assert_eq!(
        registry.enter_non_cancellable(&first),
        Err(CancellationCheckpoint::Cancelled)
    );

    registry
        .register(atomic.clone())
        .expect("atomic registration");
    registry
        .enter_non_cancellable(&atomic)
        .expect("operation may enter atomic M2 boundary before cancellation");
    assert_eq!(registry.cancel(&atomic), CancellationOutcome::TooLate);

    registry
        .register(completed.clone())
        .expect("completed registration");
    assert!(registry.complete(&completed));
    assert_eq!(
        registry.cancel(&completed),
        CancellationOutcome::AlreadyCompleted
    );

    let facade = ApplicationFacade::default();
    facade
        .register_operation(
            identifier("facade-operation"),
            identifier("facade-correlation"),
        )
        .expect("facade registration");
    let response = facade
        .cancel_operation(CancelOperationRequest {
            schema_version: M31_CONTRACT_VERSION,
            operation_id: identifier("facade-operation"),
            correlation_id: identifier("cancel-correlation"),
        })
        .expect("facade cancellation");
    assert_eq!(response.outcome, CancellationOutcome::Requested);
    assert_eq!(
        facade
            .cancellation_checkpoint(&identifier("facade-operation"))
            .expect_err("cancelled operation must stop at a cancellable point")
            .code,
        ErrorCode::Cancelled
    );
}

#[test]
fn event_sink_failure_rolls_back_registration_and_lifecycle_is_bounded() {
    let sink = Arc::new(FailingEventSink {
        fail: Mutex::new(true),
    });
    let facade = ApplicationFacade::new(sink.clone());
    let operation = identifier("retryable-operation");
    let correlation = identifier("retryable-correlation");

    let first = facade
        .register_operation(operation.clone(), correlation.clone())
        .expect_err("failing sink must surface unavailable");
    assert_eq!(first.code, ErrorCode::Unavailable);
    assert_eq!(facade.operation_count().expect("count"), 0);

    *sink.fail.lock().expect("failure flag lock") = false;
    facade
        .register_operation(operation.clone(), correlation)
        .expect("retry after rollback must be accepted");
    assert_eq!(facade.operation_count().expect("count"), 1);
    facade
        .complete_operation(&operation)
        .expect("registered operation may complete");
    facade
        .release_completed_operation(&operation)
        .expect("completed operation has explicit bounded cleanup");
    assert_eq!(facade.operation_count().expect("count"), 0);

    let mut registry = OperationRegistry::default();
    let atomic = identifier("atomic-survivor");
    registry
        .register(atomic.clone())
        .expect("atomic registration");
    registry
        .enter_non_cancellable(&atomic)
        .expect("atomic boundary");
    assert!(!registry.rollback_registration(&atomic));
    assert!(!registry.remove_completed(&atomic));
    assert_eq!(registry.len(), 1);
}

#[test]
fn m2_error_mapping_is_exhaustive_and_stable() {
    use ErrorCode::{
        CompatibilityProtected, Conflict, Internal, NotFound, PlanStale, RecoveryRequired,
        Unavailable, Validation,
    };

    for (error, code) in [
        (
            RepositoryError::NotFound(EntityKind::RuntimeIdentity),
            NotFound,
        ),
        (
            RepositoryError::AlreadyExists(EntityKind::RuntimeIdentity),
            Conflict,
        ),
        (
            RepositoryError::VersionConflict(EntityKind::RuntimeIdentity),
            Conflict,
        ),
        (
            RepositoryError::ReferenceConflict(EntityKind::RuntimeIdentity),
            Conflict,
        ),
        (RepositoryError::CorruptData, Internal),
        (RepositoryError::StorageUnavailable, Unavailable),
    ] {
        assert_code(error, code);
    }

    for (error, code) in [
        (SwitchExecutionError::Busy, Conflict),
        (SwitchExecutionError::PlanStale, PlanStale),
        (
            SwitchExecutionError::CompatibilityProtected(CompatibilityReason::InvalidUtf8),
            CompatibilityProtected,
        ),
        (SwitchExecutionError::InvalidPlan, Validation),
        (SwitchExecutionError::SnapshotInvalid, RecoveryRequired),
        (SwitchExecutionError::IoFailure, Unavailable),
        (SwitchExecutionError::RepositoryFailure, Unavailable),
        (SwitchExecutionError::InjectedFailure, Internal),
        (SwitchExecutionError::Interrupted, Internal),
        (SwitchExecutionError::RecoveryRequired, RecoveryRequired),
    ] {
        assert_code(error, code);
    }

    for (error, code) in [
        (CredentialServiceError::AlreadyExists, Conflict),
        (CredentialServiceError::NotFound, NotFound),
        (CredentialServiceError::VersionConflict, Conflict),
        (CredentialServiceError::ReferenceConflict, Conflict),
        (CredentialServiceError::InvalidSecret, Validation),
        (CredentialServiceError::StoreFailure, Unavailable),
        (CredentialServiceError::RepositoryFailure, Unavailable),
        (CredentialServiceError::RecoveryRequired, RecoveryRequired),
    ] {
        assert_code(error, code);
    }

    for (error, code) in [
        (CredentialStoreError::AlreadyExists, Conflict),
        (CredentialStoreError::NotFound, NotFound),
        (CredentialStoreError::VersionConflict, Conflict),
        (CredentialStoreError::BindingMismatch, Internal),
        (CredentialStoreError::CorruptEnvelope, Internal),
        (CredentialStoreError::ProtectionFailed, Unavailable),
        (CredentialStoreError::IoFailure, Unavailable),
        (CredentialStoreError::RecoveryRequired, RecoveryRequired),
    ] {
        assert_code(error, code);
    }

    for (error, code) in [
        (BackupStoreError::AlreadyExists, Conflict),
        (BackupStoreError::NotFound, NotFound),
        (BackupStoreError::PlanStale, PlanStale),
        (
            BackupStoreError::CompatibilityProtected,
            CompatibilityProtected,
        ),
        (BackupStoreError::RecoveryRequired, RecoveryRequired),
        (BackupStoreError::CorruptMaterial, RecoveryRequired),
        (BackupStoreError::IoFailure, Unavailable),
        (BackupStoreError::RepositoryFailure, Unavailable),
    ] {
        assert_code(error, code);
    }

    for (error, code) in [
        (OAuthCaptureError::Cancelled, ErrorCode::Cancelled),
        (OAuthCaptureError::TimedOut, Unavailable),
        (OAuthCaptureError::ProcessFailed, Unavailable),
        (OAuthCaptureError::ProcessTreeUnconfirmed, RecoveryRequired),
        (OAuthCaptureError::MissingAuthentication, NotFound),
        (
            OAuthCaptureError::CompatibilityProtected,
            CompatibilityProtected,
        ),
        (
            OAuthCaptureError::OutsideWriteDetected,
            CompatibilityProtected,
        ),
        (OAuthCaptureError::CredentialFailure, Unavailable),
        (OAuthCaptureError::IoFailure, Unavailable),
    ] {
        assert_code(error, code);
    }

    for (error, code) in [
        (ApplicationError::Domain, Validation),
        (
            ApplicationError::Repository(RepositoryError::StorageUnavailable),
            Unavailable,
        ),
        (ApplicationError::CredentialMismatch, Conflict),
    ] {
        assert_code(error, code);
    }

    for (error, code) in [
        (
            VerticalClosureError::CompatibilityProtected(CompatibilityReason::InvalidUtf8),
            CompatibilityProtected,
        ),
        (VerticalClosureError::InvalidTarget, Validation),
        (VerticalClosureError::IoFailure, Unavailable),
        (
            VerticalClosureError::Credential(CredentialServiceError::RecoveryRequired),
            RecoveryRequired,
        ),
        (
            VerticalClosureError::Switch(SwitchExecutionError::PlanStale),
            PlanStale,
        ),
    ] {
        assert_code(error, code);
    }
}

#[test]
fn schema_version_and_unknown_fields_fail_closed() {
    let facade = ApplicationFacade::default();
    let error = facade
        .describe_contract(DescribeContractRequest {
            schema_version: M31_CONTRACT_VERSION + 1,
            correlation_id: identifier("correlation-version"),
        })
        .expect_err("unsupported contract version must fail closed");
    assert_eq!(error.code, ErrorCode::Validation);

    let unknown_field = json!({
        "schema_version": M31_CONTRACT_VERSION,
        "correlation_id": "correlation-unknown",
        "unexpected": true
    });
    assert!(serde_json::from_value::<DescribeContractRequest>(unknown_field).is_err());
}
