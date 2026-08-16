use crate::application_facade::{
    ApplicationFacade, CancelOperationRequest, CancelOperationResponse, CreatePresetAndBindRequest,
    DescribeContractRequest, DescribeContractResponse, DiscoverModelsRequest,
    DiscoverModelsResponse, ErrorCode, ErrorEnvelope, ExecuteSwitchRequest, ExecuteSwitchResponse,
    ExitSink, ImportCandidateRequest, ImportCandidateResponse, ListIdentitiesRequest,
    ListIdentitiesResponse, ListPresetsRequest, ListPresetsResponse, ListSwitchRecoveriesRequest,
    ListSwitchRecoveriesResponse, PresetBindingResponse, PreviewSwitchRequest,
    PreviewSwitchResponse, ProbeConnectionRequest, ProbeConnectionResponse,
    QuerySwitchOperationRequest, QuerySwitchOperationResponse, RecoverSwitchRequest,
    RecoverSwitchResponse, RenameIdentityRequest, RenameIdentityResponse, RequestAppExitRequest,
    RequestAppExitResponse, ScanDefaultCodexRequest, ScanDefaultCodexResponse,
    UpdatePresetAndBindRequest,
};
use std::time::Duration;

pub const ADMISSION_EXEMPT_COMMANDS: [&str; 3] = [
    "describe_contract_v1",
    "cancel_operation_v1",
    "request_app_exit_v1",
];
const EXIT_DRAIN_TIMEOUT: Duration = Duration::from_millis(750);

#[tauri::command]
pub fn describe_contract_v1(
    facade: tauri::State<'_, ApplicationFacade>,
    request: DescribeContractRequest,
) -> Result<DescribeContractResponse, ErrorEnvelope> {
    facade.describe_contract(request)
}

#[tauri::command]
pub fn cancel_operation_v1(
    facade: tauri::State<'_, ApplicationFacade>,
    request: CancelOperationRequest,
) -> Result<CancelOperationResponse, ErrorEnvelope> {
    facade.cancel_operation(request)
}

async fn run_blocking<T: Send + 'static>(
    task: impl FnOnce() -> Result<T, ErrorEnvelope> + Send + 'static,
) -> Result<T, ErrorEnvelope> {
    tauri::async_runtime::spawn_blocking(task)
        .await
        .map_err(|_| ErrorEnvelope::from_code(ErrorCode::Internal))?
}

async fn run_admitted_blocking<T: Send + 'static>(
    facade: ApplicationFacade,
    task: impl FnOnce(&ApplicationFacade) -> Result<T, ErrorEnvelope> + Send + 'static,
) -> Result<T, ErrorEnvelope> {
    let admission = facade.admit_business_command()?;
    run_blocking(move || {
        let _admission = admission;
        task(&facade)
    })
    .await
}

#[tauri::command]
pub async fn scan_default_codex_v1(
    facade: tauri::State<'_, ApplicationFacade>,
    request: ScanDefaultCodexRequest,
) -> Result<ScanDefaultCodexResponse, ErrorEnvelope> {
    let facade = facade.inner().clone();
    run_admitted_blocking(facade, move |facade| facade.scan_default_codex(request)).await
}

#[tauri::command]
pub async fn import_candidate_v1(
    facade: tauri::State<'_, ApplicationFacade>,
    request: ImportCandidateRequest,
) -> Result<ImportCandidateResponse, ErrorEnvelope> {
    let facade = facade.inner().clone();
    run_admitted_blocking(facade, move |facade| facade.import_candidate(request)).await
}

#[tauri::command]
pub async fn list_identities_v1(
    facade: tauri::State<'_, ApplicationFacade>,
    request: ListIdentitiesRequest,
) -> Result<ListIdentitiesResponse, ErrorEnvelope> {
    let facade = facade.inner().clone();
    run_admitted_blocking(facade, move |facade| facade.list_identities(request)).await
}

#[tauri::command]
pub async fn rename_identity_v1(
    facade: tauri::State<'_, ApplicationFacade>,
    request: RenameIdentityRequest,
) -> Result<RenameIdentityResponse, ErrorEnvelope> {
    let facade = facade.inner().clone();
    run_admitted_blocking(facade, move |facade| facade.rename_identity(request)).await
}

#[tauri::command]
pub async fn list_presets_v1(
    facade: tauri::State<'_, ApplicationFacade>,
    request: ListPresetsRequest,
) -> Result<ListPresetsResponse, ErrorEnvelope> {
    let facade = facade.inner().clone();
    run_admitted_blocking(facade, move |facade| facade.list_presets(request)).await
}

#[tauri::command]
pub async fn create_preset_and_bind_v1(
    facade: tauri::State<'_, ApplicationFacade>,
    request: CreatePresetAndBindRequest,
) -> Result<PresetBindingResponse, ErrorEnvelope> {
    let facade = facade.inner().clone();
    run_admitted_blocking(facade, move |facade| facade.create_preset_and_bind(request)).await
}

#[tauri::command]
pub async fn update_preset_and_bind_v1(
    facade: tauri::State<'_, ApplicationFacade>,
    request: UpdatePresetAndBindRequest,
) -> Result<PresetBindingResponse, ErrorEnvelope> {
    let facade = facade.inner().clone();
    run_admitted_blocking(facade, move |facade| facade.update_preset_and_bind(request)).await
}

#[tauri::command]
pub async fn preview_switch_v1(
    facade: tauri::State<'_, ApplicationFacade>,
    request: PreviewSwitchRequest,
) -> Result<PreviewSwitchResponse, ErrorEnvelope> {
    let facade = facade.inner().clone();
    run_admitted_blocking(facade, move |facade| facade.preview_switch(request)).await
}

#[tauri::command]
pub async fn execute_switch_v1(
    facade: tauri::State<'_, ApplicationFacade>,
    request: ExecuteSwitchRequest,
) -> Result<ExecuteSwitchResponse, ErrorEnvelope> {
    let facade = facade.inner().clone();
    run_admitted_blocking(facade, move |facade| facade.execute_switch(request)).await
}

#[tauri::command]
pub async fn query_switch_operation_v1(
    facade: tauri::State<'_, ApplicationFacade>,
    request: QuerySwitchOperationRequest,
) -> Result<QuerySwitchOperationResponse, ErrorEnvelope> {
    let facade = facade.inner().clone();
    run_admitted_blocking(facade, move |facade| facade.query_switch_operation(request)).await
}

#[tauri::command]
pub async fn list_switch_recoveries_v1(
    facade: tauri::State<'_, ApplicationFacade>,
    request: ListSwitchRecoveriesRequest,
) -> Result<ListSwitchRecoveriesResponse, ErrorEnvelope> {
    let facade = facade.inner().clone();
    run_admitted_blocking(facade, move |facade| facade.list_switch_recoveries(request)).await
}

#[tauri::command]
pub async fn recover_switch_v1(
    facade: tauri::State<'_, ApplicationFacade>,
    request: RecoverSwitchRequest,
) -> Result<RecoverSwitchResponse, ErrorEnvelope> {
    let facade = facade.inner().clone();
    run_admitted_blocking(facade, move |facade| facade.recover_switch(request)).await
}

#[tauri::command]
pub async fn probe_connection_v1(
    facade: tauri::State<'_, ApplicationFacade>,
    request: ProbeConnectionRequest,
) -> Result<ProbeConnectionResponse, ErrorEnvelope> {
    let facade = facade.inner().clone();
    run_admitted_blocking(facade, move |facade| facade.probe_connection(request)).await
}

#[tauri::command]
pub async fn discover_models_v1(
    facade: tauri::State<'_, ApplicationFacade>,
    request: DiscoverModelsRequest,
) -> Result<DiscoverModelsResponse, ErrorEnvelope> {
    let facade = facade.inner().clone();
    run_admitted_blocking(facade, move |facade| facade.discover_models(request)).await
}

struct TauriExitSink(tauri::AppHandle);

impl ExitSink for TauriExitSink {
    fn exit(&self, code: i32) {
        self.0.exit(code);
    }
}

#[tauri::command]
pub async fn request_app_exit_v1(
    app: tauri::AppHandle,
    facade: tauri::State<'_, ApplicationFacade>,
    request: RequestAppExitRequest,
) -> Result<RequestAppExitResponse, ErrorEnvelope> {
    let facade = facade.inner().clone();
    let exit_sink = TauriExitSink(app);
    run_blocking(move || facade.request_app_exit_with_sink(request, EXIT_DRAIN_TIMEOUT, &exit_sink))
        .await
}

pub fn registered_handlers() -> impl Fn(tauri::ipc::Invoke<tauri::Wry>) -> bool {
    debug_assert_eq!(ADMISSION_EXEMPT_COMMANDS.len(), 3);
    tauri::generate_handler![
        describe_contract_v1,
        cancel_operation_v1,
        scan_default_codex_v1,
        import_candidate_v1,
        list_identities_v1,
        rename_identity_v1,
        list_presets_v1,
        create_preset_and_bind_v1,
        update_preset_and_bind_v1,
        preview_switch_v1,
        execute_switch_v1,
        query_switch_operation_v1,
        list_switch_recoveries_v1,
        recover_switch_v1,
        probe_connection_v1,
        discover_models_v1,
        request_app_exit_v1
    ]
}
