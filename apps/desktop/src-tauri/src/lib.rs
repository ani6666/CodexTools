#![forbid(unsafe_code)]
//! M3.1 提供不含秘密正文的 typed IPC 合同与纯 Rust application facade。

use std::sync::Arc;

use tauri::{Emitter, Manager};

pub mod application_facade;
mod commands;
mod m33_backend;

#[derive(Clone)]
struct TauriEventSink(tauri::AppHandle);

impl application_facade::EventSink for TauriEventSink {
    fn publish(
        &self,
        event: &application_facade::OperationStatusEvent,
    ) -> Result<(), application_facade::EventSinkError> {
        self.0
            .emit(application_facade::EVENT_OPERATION_STATUS_V1, event)
            .map_err(|_| application_facade::EventSinkError)
    }
}

#[cfg(test)]
use serde_json as _;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CoreBoundarySnapshot {
    stage: &'static str,
    schema_version: u32,
    adapter_size: usize,
    application_error_size: usize,
    platform_adapter_size: usize,
}

fn core_boundary_snapshot() -> CoreBoundarySnapshot {
    CoreBoundarySnapshot {
        stage: codex_domain::m2_stage(),
        schema_version: local_infrastructure::LATEST_SCHEMA_VERSION,
        adapter_size: std::mem::size_of::<codex_adapter::CodexAdapter>(),
        application_error_size: std::mem::size_of::<codex_application::ApplicationError>(),
        platform_adapter_size: std::mem::size_of::<windows_platform::DpapiCurrentUser>(),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let _core_boundary = core_boundary_snapshot();
    tauri::Builder::default()
        .setup(|app| {
            let app_data_dir = app.path().app_data_dir()?;
            let backend = m33_backend::ProductionM33Backend::new(app_data_dir)
                .map_err(|_| std::io::Error::other("M3.3 本地服务初始化失败"))?;
            let events = Arc::new(TauriEventSink(app.handle().clone()));
            app.manage(application_facade::ApplicationFacade::with_backend(
                events,
                Arc::new(backend),
            ));
            Ok(())
        })
        .invoke_handler(commands::registered_handlers())
        .run(tauri::generate_context!())
        .expect("Tauri 应用启动失败");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_links_existing_m2_crates_without_copying_core_logic() {
        let snapshot = core_boundary_snapshot();
        assert!(snapshot.stage.starts_with("M2."));
        assert!(snapshot.schema_version >= 10);
    }
}
