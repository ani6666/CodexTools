use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[cfg(target_os = "windows")]
use std::{
    io::{BufRead, BufReader, Read, Write},
    process::{Command, Stdio},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use codextools_desktop_lib::application_facade::{
    ApplicationFacade, DiscoverModelsRequest, EndpointPolicyDto, ErrorCode, ExitSink,
    M35_CONTRACT_VERSION, M35Backend, M35BackendError, ModelCandidateDto, NoopEventSink,
    ProbeConnectionRequest, ProcessLifecyclePhase, RequestAppExitRequest, SafeIdentifier,
    UnavailableM33Backend, UnavailableM34Backend,
};
use std::time::Duration;

fn id(value: &str) -> SafeIdentifier {
    SafeIdentifier::parse(value).unwrap()
}
fn probe_request() -> ProbeConnectionRequest {
    ProbeConnectionRequest {
        schema_version: M35_CONTRACT_VERSION,
        correlation_id: id("corr-m35"),
        identity_id: id("identity-1"),
        credential_ref_id: id("credential-1"),
        expected_identity_version: 1,
        endpoint_policy: EndpointPolicyDto::PublicHttps,
        operation_id: id("network-op-1"),
    }
}

#[derive(Default)]
struct FakeM35 {
    probes: AtomicUsize,
    discoveries: AtomicUsize,
}
impl M35Backend for FakeM35 {
    fn probe_connection(&self, _: &ProbeConnectionRequest) -> Result<bool, M35BackendError> {
        self.probes.fetch_add(1, Ordering::SeqCst);
        Ok(true)
    }
    fn discover_models(
        &self,
        _: &DiscoverModelsRequest,
    ) -> Result<Vec<ModelCandidateDto>, M35BackendError> {
        self.discoveries.fetch_add(1, Ordering::SeqCst);
        Ok(vec![ModelCandidateDto {
            model_id: "model-a".into(),
            display_name: Some("Model A".into()),
        }])
    }
}

#[test]
fn dto_is_closed_and_secret_free() {
    let request = probe_request();
    let json = serde_json::to_string(&request).unwrap();
    assert!(!json.contains("authorization"));
    assert!(!json.contains("token"));
    assert!(
        serde_json::from_str::<ProbeConnectionRequest>(&format!(
            "{}{}",
            json.trim_end_matches('}'),
            r#",\"unknown\":true}"#
        ))
        .is_err()
    );
}

#[test]
fn facade_delegates_exactly_once() {
    let backend = Arc::new(FakeM35::default());
    let facade = ApplicationFacade::with_all_backends(
        Arc::new(NoopEventSink),
        Arc::new(UnavailableM33Backend),
        Arc::new(UnavailableM34Backend),
        backend.clone(),
    );
    let result = facade.probe_connection(probe_request()).unwrap();
    assert!(result.reachable);
    assert_eq!(backend.probes.load(Ordering::SeqCst), 1);
}

struct ActiveM35;
impl M35Backend for ActiveM35 {
    fn probe_connection(&self, _: &ProbeConnectionRequest) -> Result<bool, M35BackendError> {
        Ok(true)
    }
    fn discover_models(
        &self,
        _: &DiscoverModelsRequest,
    ) -> Result<Vec<ModelCandidateDto>, M35BackendError> {
        Ok(Vec::new())
    }
    fn active_operation_count(&self) -> usize {
        1
    }
}

#[test]
fn explicit_exit_fails_closed_while_an_operation_is_active() {
    let facade = ApplicationFacade::with_all_backends(
        Arc::new(NoopEventSink),
        Arc::new(UnavailableM33Backend),
        Arc::new(UnavailableM34Backend),
        Arc::new(ActiveM35),
    );
    let sink = RecordingExit {
        gate: facade.lifecycle_gate(),
        calls: AtomicUsize::new(0),
        sealed_and_idle: AtomicUsize::new(0),
    };
    let error = facade
        .request_app_exit_with_sink(
            RequestAppExitRequest {
                schema_version: M35_CONTRACT_VERSION,
                correlation_id: id("exit-corr"),
            },
            Duration::ZERO,
            &sink,
        )
        .unwrap_err();
    assert_eq!(
        error.code,
        codextools_desktop_lib::application_facade::ErrorCode::Conflict
    );
    assert_eq!(sink.calls.load(Ordering::SeqCst), 0);
}

struct RecordingExit {
    gate: codextools_desktop_lib::application_facade::ProcessLifecycleGate,
    calls: AtomicUsize,
    sealed_and_idle: AtomicUsize,
}

impl ExitSink for RecordingExit {
    fn exit(&self, code: i32) {
        assert_eq!(code, 0);
        let snapshot = self.gate.snapshot().unwrap();
        if snapshot.phase == ProcessLifecyclePhase::Draining && snapshot.active == 0 {
            self.sealed_and_idle.fetch_add(1, Ordering::SeqCst);
        }
        assert_eq!(
            self.gate.try_admit().unwrap_err().code,
            ErrorCode::ExitInProgress
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn exit_gate_seals_before_drain_wait_and_sink_runs_once_while_sealed() {
    let facade = ApplicationFacade::default();
    let gate = facade.lifecycle_gate();
    let lease = facade.admit_business_command().unwrap();
    let sink = Arc::new(RecordingExit {
        gate: gate.clone(),
        calls: AtomicUsize::new(0),
        sealed_and_idle: AtomicUsize::new(0),
    });
    let worker_facade = facade.clone();
    let worker_sink = sink.clone();
    let worker = std::thread::spawn(move || {
        worker_facade.request_app_exit_with_sink(
            RequestAppExitRequest {
                schema_version: M35_CONTRACT_VERSION,
                correlation_id: id("exit-barrier"),
            },
            Duration::from_secs(2),
            worker_sink.as_ref(),
        )
    });
    assert!(gate.wait_for_phase(ProcessLifecyclePhase::Draining, Duration::from_secs(1)));
    assert_eq!(
        gate.try_admit().unwrap_err().code,
        ErrorCode::ExitInProgress
    );
    assert_eq!(sink.calls.load(Ordering::SeqCst), 0);
    drop(lease);
    assert!(worker.join().unwrap().unwrap().ready);
    assert_eq!(sink.calls.load(Ordering::SeqCst), 1);
    assert_eq!(sink.sealed_and_idle.load(Ordering::SeqCst), 1);
}

#[test]
fn exit_timeout_stays_draining_retry_succeeds_and_concurrent_exit_is_rejected() {
    let facade = ApplicationFacade::default();
    let gate = facade.lifecycle_gate();
    let lease = facade.admit_business_command().unwrap();
    let sink = RecordingExit {
        gate: gate.clone(),
        calls: AtomicUsize::new(0),
        sealed_and_idle: AtomicUsize::new(0),
    };
    let timeout = facade
        .request_app_exit_with_sink(
            RequestAppExitRequest {
                schema_version: 1,
                correlation_id: id("exit-timeout"),
            },
            Duration::ZERO,
            &sink,
        )
        .unwrap_err();
    assert_eq!(timeout.code, ErrorCode::Conflict);
    assert_eq!(
        gate.snapshot().unwrap().phase,
        ProcessLifecyclePhase::Draining
    );
    assert_eq!(sink.calls.load(Ordering::SeqCst), 0);

    let first_facade = facade.clone();
    let first = std::thread::spawn(move || {
        first_facade.request_app_exit_with_sink(
            RequestAppExitRequest {
                schema_version: 1,
                correlation_id: id("exit-first"),
            },
            Duration::from_secs(2),
            &RecordingExit {
                gate: first_facade.lifecycle_gate(),
                calls: AtomicUsize::new(0),
                sealed_and_idle: AtomicUsize::new(0),
            },
        )
    });
    assert!(gate.wait_for_exit_attempt(Duration::from_secs(1)));
    let concurrent = facade
        .request_app_exit_with_sink(
            RequestAppExitRequest {
                schema_version: 1,
                correlation_id: id("exit-second"),
            },
            Duration::ZERO,
            &sink,
        )
        .unwrap_err();
    assert_eq!(concurrent.code, ErrorCode::Conflict);
    drop(lease);
    assert!(first.join().unwrap().unwrap().ready);
}

#[test]
fn admission_lease_returns_on_panic_without_reopening_draining_gate() {
    let facade = ApplicationFacade::default();
    let gate = facade.lifecycle_gate();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _lease = facade.admit_business_command().unwrap();
        panic!("synthetic admission panic");
    }));
    assert_eq!(gate.snapshot().unwrap().active, 0);
    let permit = gate.begin_exit().unwrap();
    assert!(permit.wait_for_zero(Duration::ZERO).unwrap());
    assert_eq!(
        gate.try_admit().unwrap_err().code,
        ErrorCode::ExitInProgress
    );
}

#[cfg(target_os = "windows")]
#[test]
fn instance_gate_child_entry() {
    let Some(role) = std::env::var_os("CODEXTOOLS_M35_GATE_CHILD") else {
        return;
    };
    let identifier = std::env::var("CODEXTOOLS_M35_GATE_ID").unwrap();
    match windows_platform::WindowsInstanceStartupGate::acquire(&identifier).unwrap() {
        windows_platform::InstanceStartupDisposition::Primary(gate) => {
            gate.mark_ready().unwrap();
            println!("PRIMARY_READY");
            std::io::stdout().flush().unwrap();
            if role == "crash" {
                std::process::abort();
            }
            let mut release = String::new();
            std::io::stdin().read_line(&mut release).unwrap();
        }
        windows_platform::InstanceStartupDisposition::Secondary(status) => {
            println!("SECONDARY:{status:?}");
            std::io::stdout().flush().unwrap();
        }
    }
}

#[cfg(target_os = "windows")]
#[test]
fn real_process_gate_is_unique_barriered_and_recovers_after_crash() {
    fn identifier(suffix: &str) -> String {
        format!(
            "dev.codextools.m35.test.{}.{}.{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            suffix
        )
    }
    fn spawn_child(identifier: &str, role: &str) -> std::process::Child {
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "instance_gate_child_entry",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("CODEXTOOLS_M35_GATE_CHILD", role)
            .env("CODEXTOOLS_M35_GATE_ID", identifier)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }
    fn read_marker(child: &mut std::process::Child) -> String {
        let mut reader = BufReader::new(child.stdout.take().unwrap());
        let mut marker = String::new();
        for _ in 0..32 {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap() == 0 {
                break;
            }
            if let Some(start) = line.find("PRIMARY_READY") {
                marker = line[start..].trim().to_owned();
                break;
            }
            if let Some(start) = line.find("SECONDARY:") {
                marker = line[start..]
                    .trim()
                    .trim_end_matches("ok")
                    .trim()
                    .to_owned();
                break;
            }
        }
        std::thread::spawn(move || {
            let mut discarded = Vec::new();
            let _ = reader.read_to_end(&mut discarded);
        });
        marker
    }

    let live_id = identifier("live");
    let mut primary = spawn_child(&live_id, "hold");
    assert_eq!(read_marker(&mut primary), "PRIMARY_READY");
    let started = Instant::now();
    let mut secondary = spawn_child(&live_id, "secondary");
    assert_eq!(read_marker(&mut secondary), "SECONDARY:TargetUnavailable");
    assert!(secondary.wait().unwrap().success());
    assert!(started.elapsed().as_secs() < 5);
    primary
        .stdin
        .take()
        .unwrap()
        .write_all(b"release\n")
        .unwrap();
    assert!(primary.wait().unwrap().success());

    let crash_id = identifier("crash");
    let mut crashing = spawn_child(&crash_id, "crash");
    assert_eq!(read_marker(&mut crashing), "PRIMARY_READY");
    assert!(!crashing.wait().unwrap().success());
    let mut recovered = spawn_child(&crash_id, "hold");
    assert_eq!(read_marker(&mut recovered), "PRIMARY_READY");
    recovered
        .stdin
        .take()
        .unwrap()
        .write_all(b"release\n")
        .unwrap();
    assert!(recovered.wait().unwrap().success());
}

use codex_adapter as _;
use codex_application as _;
use codex_domain as _;
use local_infrastructure as _;
use serde as _;
use tauri as _;
use tauri_plugin_single_instance as _;
use windows_platform as _;
