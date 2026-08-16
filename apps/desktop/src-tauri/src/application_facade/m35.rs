use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::{ErrorEnvelope, SafeIdentifier, ensure_version};

pub const M35_CONTRACT_VERSION: u16 = 1;
pub const COMMAND_PROBE_CONNECTION_V1: &str = "probe_connection_v1";
pub const COMMAND_DISCOVER_MODELS_V1: &str = "discover_models_v1";
pub const COMMAND_REQUEST_APP_EXIT_V1: &str = "request_app_exit_v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointPolicyDto {
    PublicHttps,
    LoopbackDevelopment,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeConnectionRequest {
    pub schema_version: u16,
    pub correlation_id: SafeIdentifier,
    pub identity_id: SafeIdentifier,
    pub credential_ref_id: SafeIdentifier,
    pub expected_identity_version: u64,
    pub endpoint_policy: EndpointPolicyDto,
    pub operation_id: SafeIdentifier,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProbeConnectionResponse {
    pub schema_version: u16,
    pub correlation_id: SafeIdentifier,
    pub operation_id: SafeIdentifier,
    pub reachable: bool,
    pub cancelled: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoverModelsRequest {
    pub schema_version: u16,
    pub correlation_id: SafeIdentifier,
    pub identity_id: SafeIdentifier,
    pub credential_ref_id: SafeIdentifier,
    pub expected_identity_version: u64,
    pub endpoint_policy: EndpointPolicyDto,
    pub operation_id: SafeIdentifier,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ModelCandidateDto {
    pub model_id: String,
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiscoverModelsResponse {
    pub schema_version: u16,
    pub correlation_id: SafeIdentifier,
    pub operation_id: SafeIdentifier,
    pub models: Vec<ModelCandidateDto>,
    pub cancelled: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestAppExitRequest {
    pub schema_version: u16,
    pub correlation_id: SafeIdentifier,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RequestAppExitResponse {
    pub schema_version: u16,
    pub correlation_id: SafeIdentifier,
    pub ready: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum M35BackendError {
    Validation,
    NotFound,
    Conflict,
    AuthRequired,
    Forbidden,
    RateLimited,
    Timeout,
    TlsFailure,
    NetworkUnavailable,
    InvalidResponse,
    ResponseTooLarge,
    CompatibilityProtected,
    Cancelled,
    Unavailable,
    Internal,
}

pub trait M35Backend: Send + Sync {
    fn probe_connection(&self, request: &ProbeConnectionRequest) -> Result<bool, M35BackendError>;
    fn discover_models(
        &self,
        request: &DiscoverModelsRequest,
    ) -> Result<Vec<ModelCandidateDto>, M35BackendError>;
    fn cancel_operation(&self, _operation_id: &str) -> Option<super::CancellationOutcome> {
        None
    }
    fn cancel_all(&self) {}
    fn active_operation_count(&self) -> usize {
        0
    }
}

pub trait ExitSink: Send + Sync {
    fn exit(&self, code: i32);
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableM35Backend;
impl M35Backend for UnavailableM35Backend {
    fn probe_connection(&self, _: &ProbeConnectionRequest) -> Result<bool, M35BackendError> {
        Err(M35BackendError::Unavailable)
    }
    fn discover_models(
        &self,
        _: &DiscoverModelsRequest,
    ) -> Result<Vec<ModelCandidateDto>, M35BackendError> {
        Err(M35BackendError::Unavailable)
    }
}

impl super::ApplicationFacade {
    pub fn cancel_network_operations(&self) {
        self.m35.cancel_all();
    }

    pub fn request_app_exit_with_sink(
        &self,
        request: RequestAppExitRequest,
        timeout: Duration,
        exit_sink: &dyn ExitSink,
    ) -> Result<RequestAppExitResponse, ErrorEnvelope> {
        ensure_version(request.schema_version)?;
        let permit = self.lifecycle_gate().begin_exit()?;
        self.m35.cancel_all();
        if !permit.wait_for_zero(timeout)?
            || self.operation_count()? != 0
            || self.m35.active_operation_count() != 0
        {
            return Err(ErrorEnvelope::from_code(super::ErrorCode::Conflict));
        }
        exit_sink.exit(0);
        Ok(RequestAppExitResponse {
            schema_version: M35_CONTRACT_VERSION,
            correlation_id: request.correlation_id,
            ready: true,
        })
    }
    pub fn probe_connection(
        &self,
        request: ProbeConnectionRequest,
    ) -> Result<ProbeConnectionResponse, ErrorEnvelope> {
        ensure_version(request.schema_version)?;
        let reachable = self.m35.probe_connection(&request)?;
        Ok(ProbeConnectionResponse {
            schema_version: M35_CONTRACT_VERSION,
            correlation_id: request.correlation_id,
            operation_id: request.operation_id,
            reachable,
            cancelled: false,
        })
    }

    pub fn discover_models(
        &self,
        request: DiscoverModelsRequest,
    ) -> Result<DiscoverModelsResponse, ErrorEnvelope> {
        ensure_version(request.schema_version)?;
        let models = self.m35.discover_models(&request)?;
        Ok(DiscoverModelsResponse {
            schema_version: M35_CONTRACT_VERSION,
            correlation_id: request.correlation_id,
            operation_id: request.operation_id,
            models,
            cancelled: false,
        })
    }
}
