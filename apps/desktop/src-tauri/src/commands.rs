use crate::application_facade::{
    ApplicationFacade, CancelOperationRequest, CancelOperationResponse, DescribeContractRequest,
    DescribeContractResponse, ErrorEnvelope,
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

pub fn registered_handlers<R: tauri::Runtime>() -> impl Fn(tauri::ipc::Invoke<R>) -> bool {
    tauri::generate_handler![describe_contract_v1, cancel_operation_v1]
}
