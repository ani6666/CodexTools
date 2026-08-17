#![forbid(unsafe_code)]
//! M3.1 提供不含秘密正文的 typed IPC 合同与纯 Rust application facade。

use std::sync::Arc;

use tauri::{Emitter, Manager};

pub mod application_facade;
mod commands;
mod m33_backend;
mod m34_backend;
mod m35_backend;
mod window_activation;

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
    let context = tauri::generate_context!();
    #[cfg(target_os = "windows")]
    let startup_gate =
        match windows_platform::WindowsInstanceStartupGate::acquire(&context.config().identifier) {
            Ok(windows_platform::InstanceStartupDisposition::Primary(gate)) => gate,
            Ok(windows_platform::InstanceStartupDisposition::Secondary(_)) | Err(_) => return,
        };
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let activation = window_activation::TauriMainWindowActivation(window);
                let _ = window_activation::activate_main_window(&activation);
            }
        }))
        .setup(|app| {
            let app_data_dir = app.path().app_data_dir()?;
            let m33_backend = m33_backend::ProductionM33Backend::new(&app_data_dir)
                .map_err(|_| std::io::Error::other("M3.3 本地服务初始化失败"))?;
            let m34_backend = m34_backend::ProductionM34Backend::new(&app_data_dir)
                .map_err(|_| std::io::Error::other("M3.4 本地服务初始化失败"))?;
            let events = Arc::new(TauriEventSink(app.handle().clone()));
            let m35_backend = m35_backend::ProductionM35Backend::new(&app_data_dir)
                .map_err(|_| std::io::Error::other("M3.5 连接服务初始化失败"))?;
            app.manage(application_facade::ApplicationFacade::with_all_backends(
                events,
                Arc::new(m33_backend),
                Arc::new(m34_backend),
                Arc::new(m35_backend),
            ));
            #[cfg(target_os = "windows")]
            {
                startup_gate.mark_ready()?;
                app.manage(startup_gate);
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                window
                    .state::<application_facade::ApplicationFacade>()
                    .cancel_network_operations();
                let _ = window.hide();
            }
        })
        .invoke_handler(commands::registered_handlers())
        .run(context)
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
