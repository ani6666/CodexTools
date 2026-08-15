use crate::application_facade::{
    ApplicationFacade, CancelOperationRequest, CancelOperationResponse, CreatePresetAndBindRequest,
    DescribeContractRequest, DescribeContractResponse, ErrorCode, ErrorEnvelope,
    ImportCandidateRequest, ImportCandidateResponse, ListIdentitiesRequest, ListIdentitiesResponse,
    ListPresetsRequest, ListPresetsResponse, PresetBindingResponse, RenameIdentityRequest,
    RenameIdentityResponse, ScanDefaultCodexRequest, ScanDefaultCodexResponse,
    UpdatePresetAndBindRequest,
};

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

#[tauri::command]
pub async fn scan_default_codex_v1(
    facade: tauri::State<'_, ApplicationFacade>,
    request: ScanDefaultCodexRequest,
) -> Result<ScanDefaultCodexResponse, ErrorEnvelope> {
    let facade = facade.inner().clone();
    run_blocking(move || facade.scan_default_codex(request)).await
}

#[tauri::command]
pub async fn import_candidate_v1(
    facade: tauri::State<'_, ApplicationFacade>,
    request: ImportCandidateRequest,
) -> Result<ImportCandidateResponse, ErrorEnvelope> {
    let facade = facade.inner().clone();
    run_blocking(move || facade.import_candidate(request)).await
}

#[tauri::command]
pub async fn list_identities_v1(
    facade: tauri::State<'_, ApplicationFacade>,
    request: ListIdentitiesRequest,
) -> Result<ListIdentitiesResponse, ErrorEnvelope> {
    let facade = facade.inner().clone();
    run_blocking(move || facade.list_identities(request)).await
}

#[tauri::command]
pub async fn rename_identity_v1(
    facade: tauri::State<'_, ApplicationFacade>,
    request: RenameIdentityRequest,
) -> Result<RenameIdentityResponse, ErrorEnvelope> {
    let facade = facade.inner().clone();
    run_blocking(move || facade.rename_identity(request)).await
}

#[tauri::command]
pub async fn list_presets_v1(
    facade: tauri::State<'_, ApplicationFacade>,
    request: ListPresetsRequest,
) -> Result<ListPresetsResponse, ErrorEnvelope> {
    let facade = facade.inner().clone();
    run_blocking(move || facade.list_presets(request)).await
}

#[tauri::command]
pub async fn create_preset_and_bind_v1(
    facade: tauri::State<'_, ApplicationFacade>,
    request: CreatePresetAndBindRequest,
) -> Result<PresetBindingResponse, ErrorEnvelope> {
    let facade = facade.inner().clone();
    run_blocking(move || facade.create_preset_and_bind(request)).await
}

#[tauri::command]
pub async fn update_preset_and_bind_v1(
    facade: tauri::State<'_, ApplicationFacade>,
    request: UpdatePresetAndBindRequest,
) -> Result<PresetBindingResponse, ErrorEnvelope> {
    let facade = facade.inner().clone();
    run_blocking(move || facade.update_preset_and_bind(request)).await
}

pub fn registered_handlers<R: tauri::Runtime>() -> impl Fn(tauri::ipc::Invoke<R>) -> bool {
    tauri::generate_handler![
        describe_contract_v1,
        cancel_operation_v1,
        scan_default_codex_v1,
        import_candidate_v1,
        list_identities_v1,
        rename_identity_v1,
        list_presets_v1,
        create_preset_and_bind_v1,
        update_preset_and_bind_v1
    ]
}
