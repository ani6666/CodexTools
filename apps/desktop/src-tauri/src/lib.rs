#![forbid(unsafe_code)]
//! M3.1 提供不含秘密正文的 typed IPC 合同与纯 Rust application facade。

pub mod application_facade;
mod commands;

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
        .manage(application_facade::ApplicationFacade::default())
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
