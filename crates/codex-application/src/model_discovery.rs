use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::{Duration, Instant},
};

use codex_domain::{
    CredentialKind, CredentialRefId, DiscoveredModel, EndpointPolicy, EntityVersion, IdentityId,
    NetworkPolicyError, NormalizedEndpoint, RuntimeIdentity, SchemaFingerprint,
    contains_high_confidence_secret,
};
use zeroize::Zeroizing;

use crate::{
    CredentialEnvelopeBinding, CredentialReferenceRepository, CredentialStore,
    CredentialStoreError, RepositoryError, RuntimeIdentityRepository, SecretConsumer,
};

pub const M28_SERVICE_VERSION: u16 = 1;

#[derive(Clone, Eq, PartialEq)]
pub struct ProbeConnectionInput {
    pub service_version: u16,
    pub identity_id: IdentityId,
    pub credential_ref_id: CredentialRefId,
    pub expected_identity_version: EntityVersion,
    pub endpoint_policy: EndpointPolicy,
    pub operation_id: String,
}

#[derive(Clone, Eq, PartialEq)]
pub struct DiscoverModelsInput {
    pub service_version: u16,
    pub identity_id: IdentityId,
    pub credential_ref_id: CredentialRefId,
    pub expected_identity_version: EntityVersion,
    pub endpoint_policy: EndpointPolicy,
    pub operation_id: String,
}

impl fmt::Debug for ProbeConnectionInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProbeConnectionInput")
            .field("service_version", &self.service_version)
            .field("identity_id", &self.identity_id)
            .field("credential_ref_id", &self.credential_ref_id)
            .field("expected_identity_version", &self.expected_identity_version)
            .field("endpoint_policy", &self.endpoint_policy)
            .field("operation_id", &"[REDACTED_OPAQUE_ID]")
            .finish()
    }
}

impl fmt::Debug for DiscoverModelsInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiscoverModelsInput")
            .field("service_version", &self.service_version)
            .field("identity_id", &self.identity_id)
            .field("credential_ref_id", &self.credential_ref_id)
            .field("expected_identity_version", &self.expected_identity_version)
            .field("endpoint_policy", &self.endpoint_policy)
            .field("operation_id", &"[REDACTED_OPAQUE_ID]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryErrorCode {
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
    Internal,
}

impl DiscoveryErrorCode {
    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(
            self,
            Self::Conflict | Self::RateLimited | Self::Timeout | Self::NetworkUnavailable
        )
    }
}

impl fmt::Display for DiscoveryErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Validation => "validation",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::AuthRequired => "auth_required",
            Self::Forbidden => "forbidden",
            Self::RateLimited => "rate_limited",
            Self::Timeout => "timeout",
            Self::TlsFailure => "tls_failure",
            Self::NetworkUnavailable => "network_unavailable",
            Self::InvalidResponse => "invalid_response",
            Self::ResponseTooLarge => "response_too_large",
            Self::CompatibilityProtected => "compatibility_protected",
            Self::Cancelled => "cancelled",
            Self::Internal => "internal",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportErrorCode {
    Timeout,
    TlsFailure,
    NetworkUnavailable,
    InvalidResponse,
    ResponseTooLarge,
    Cancelled,
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolverErrorCode {
    Timeout,
    NetworkUnavailable,
    Cancelled,
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationParseError {
    AuthRequired,
    Unsupported,
    Invalid,
}

pub trait CancellationProbe: Send + Sync {
    fn is_cancelled(&self) -> bool;
}

mod operation_control_sealed {
    pub trait Sealed {}
}

pub trait OperationControl: CancellationProbe + operation_control_sealed::Sealed {
    fn begin(&self) -> Result<OperationLease, BeginDisposition>;
    fn cancel(&self) -> CancelDisposition;
    fn finish(&self, lease: &mut OperationLease) -> PublishDisposition;
}

#[derive(Clone, Debug)]
pub struct CancellationController {
    state: Arc<AtomicU8>,
}

const OPERATION_READY: u8 = 0;
const OPERATION_CLAIMED: u8 = 1;
const OPERATION_CANCELLED: u8 = 2;
const OPERATION_COMPLETED: u8 = 3;
const OPERATION_ABANDONED: u8 = 4;

pub struct OperationLease {
    owner: Arc<AtomicU8>,
    active: bool,
}

impl fmt::Debug for OperationLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperationLease")
            .field("owner", &"[OPAQUE_CONTROLLER]")
            .field("active", &self.active)
            .finish()
    }
}

impl Drop for OperationLease {
    fn drop(&mut self) {
        if self.active {
            let _ = self.owner.compare_exchange(
                OPERATION_CLAIMED,
                OPERATION_ABANDONED,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BeginDisposition {
    Cancelled,
    AlreadyClaimed,
    AlreadyTerminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancelDisposition {
    Cancelled,
    AlreadyCancelled,
    TooLate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublishDisposition {
    Published,
    Cancelled,
    AlreadyPublished,
    InvalidLease,
}

impl Default for CancellationController {
    fn default() -> Self {
        Self::new()
    }
}

impl CancellationController {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(AtomicU8::new(OPERATION_READY)),
        }
    }

    pub fn begin(&self) -> Result<OperationLease, BeginDisposition> {
        match self.state.compare_exchange(
            OPERATION_READY,
            OPERATION_CLAIMED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => Ok(OperationLease {
                owner: self.state.clone(),
                active: true,
            }),
            Err(OPERATION_CANCELLED) => Err(BeginDisposition::Cancelled),
            Err(OPERATION_CLAIMED) => Err(BeginDisposition::AlreadyClaimed),
            Err(_) => Err(BeginDisposition::AlreadyTerminal),
        }
    }

    pub fn cancel(&self) -> CancelDisposition {
        let mut current = self.state.load(Ordering::Acquire);
        loop {
            match current {
                OPERATION_READY | OPERATION_CLAIMED => {
                    match self.state.compare_exchange(
                        current,
                        OPERATION_CANCELLED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => return CancelDisposition::Cancelled,
                        Err(actual) => current = actual,
                    }
                }
                OPERATION_CANCELLED => return CancelDisposition::AlreadyCancelled,
                _ => return CancelDisposition::TooLate,
            }
        }
    }

    #[must_use]
    pub fn finish(&self, lease: &mut OperationLease) -> PublishDisposition {
        if !lease.active {
            return PublishDisposition::AlreadyPublished;
        }
        if !Arc::ptr_eq(&self.state, &lease.owner) {
            return PublishDisposition::InvalidLease;
        }
        let disposition = match self.state.compare_exchange(
            OPERATION_CLAIMED,
            OPERATION_COMPLETED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => PublishDisposition::Published,
            Err(OPERATION_CANCELLED) => PublishDisposition::Cancelled,
            Err(_) => PublishDisposition::AlreadyPublished,
        };
        lease.active = false;
        disposition
    }
}

impl CancellationProbe for CancellationController {
    fn is_cancelled(&self) -> bool {
        self.state.load(Ordering::Acquire) == OPERATION_CANCELLED
    }
}

impl operation_control_sealed::Sealed for CancellationController {}

impl OperationControl for CancellationController {
    fn begin(&self) -> Result<OperationLease, BeginDisposition> {
        CancellationController::begin(self)
    }

    fn cancel(&self) -> CancelDisposition {
        CancellationController::cancel(self)
    }

    fn finish(&self, lease: &mut OperationLease) -> PublishDisposition {
        CancellationController::finish(self, lease)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct NeverCancelled;
impl CancellationProbe for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

pub trait DnsResolver {
    fn resolve(
        &self,
        host: &str,
        port: u16,
        deadline: Instant,
        cancellation: &dyn CancellationProbe,
    ) -> Result<Vec<IpAddr>, ResolverErrorCode>;
}

pub trait AuthorizationConsumer {
    fn consume(&mut self, authorization: &[u8]) -> Result<(), AuthorizationParseError>;
}

pub trait CredentialAuthorizationParser {
    fn parse(
        &self,
        kind: CredentialKind,
        expected_schema: &SchemaFingerprint,
        document: &[u8],
        consumer: &mut dyn AuthorizationConsumer,
    ) -> Result<(), AuthorizationParseError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyMode {
    Disabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedirectMode {
    Disabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkLimits {
    pub connect_timeout: Duration,
    pub io_poll_timeout: Duration,
    pub total_timeout: Duration,
    pub maximum_header_bytes: usize,
    pub maximum_response_bytes: usize,
    pub maximum_model_count: usize,
    pub maximum_json_depth: usize,
}

impl Default for NetworkLimits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(3),
            io_poll_timeout: Duration::from_millis(100),
            total_timeout: Duration::from_secs(10),
            maximum_header_bytes: 16 * 1_024,
            maximum_response_bytes: 512 * 1_024,
            maximum_model_count: 256,
            maximum_json_depth: 16,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ApprovedHttpTarget {
    endpoint: NormalizedEndpoint,
    connect_addresses: Vec<SocketAddr>,
    limits: NetworkLimits,
    proxy_mode: ProxyMode,
    redirect_mode: RedirectMode,
}

impl fmt::Debug for ApprovedHttpTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovedHttpTarget")
            .field("endpoint", &"[REDACTED_ENDPOINT]")
            .field("address_count", &self.connect_addresses.len())
            .field("proxy_mode", &self.proxy_mode)
            .field("redirect_mode", &self.redirect_mode)
            .finish()
    }
}

impl ApprovedHttpTarget {
    pub fn new(
        endpoint: NormalizedEndpoint,
        mut addresses: Vec<IpAddr>,
        limits: NetworkLimits,
    ) -> Result<Self, NetworkPolicyError> {
        addresses.sort_unstable();
        addresses.dedup();
        endpoint.approve_addresses(&addresses)?;
        let connect_addresses = addresses
            .into_iter()
            .map(|address| SocketAddr::new(address, endpoint.port()))
            .collect();
        Ok(Self {
            endpoint,
            connect_addresses,
            limits,
            proxy_mode: ProxyMode::Disabled,
            redirect_mode: RedirectMode::Disabled,
        })
    }

    #[must_use]
    pub const fn endpoint(&self) -> &NormalizedEndpoint {
        &self.endpoint
    }
    #[must_use]
    pub fn connect_addresses(&self) -> &[SocketAddr] {
        &self.connect_addresses
    }
    #[must_use]
    pub const fn limits(&self) -> NetworkLimits {
        self.limits
    }
    #[must_use]
    pub const fn proxy_mode(&self) -> ProxyMode {
        self.proxy_mode
    }
    #[must_use]
    pub const fn redirect_mode(&self) -> RedirectMode {
        self.redirect_mode
    }
}

pub struct TransportResponse {
    status: u16,
    body: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for TransportResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportResponse")
            .field("status", &self.status)
            .field("body", &"[REDACTED_BODY]")
            .finish()
    }
}

impl TransportResponse {
    #[must_use]
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            body: Zeroizing::new(body),
        }
    }

    #[must_use]
    pub fn from_zeroizing_body(status: u16, body: Zeroizing<Vec<u8>>) -> Self {
        Self { status, body }
    }
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

pub trait ApprovedHttpTransport {
    fn get_models(
        &mut self,
        target: &ApprovedHttpTarget,
        authorization: &mut [u8],
        cancellation: &dyn CancellationProbe,
    ) -> Result<TransportResponse, TransportErrorCode>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReachableSummary {
    pub api_compatible: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProbeConnectionOutcome {
    Reachable(ReachableSummary),
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiscoverModelsOutcome {
    Models(Vec<DiscoveredModel>),
    Cancelled,
}

pub struct SafeModelDiscoveryService<'a, R, C, D, P, T> {
    repository: &'a R,
    credential_store: &'a C,
    resolver: &'a D,
    parser: &'a P,
    transport: &'a mut T,
    limits: NetworkLimits,
}

impl<'a, R, C, D, P, T> SafeModelDiscoveryService<'a, R, C, D, P, T>
where
    R: RuntimeIdentityRepository + CredentialReferenceRepository,
    C: CredentialStore,
    D: DnsResolver,
    P: CredentialAuthorizationParser,
    T: ApprovedHttpTransport,
{
    #[must_use]
    pub fn new(
        repository: &'a R,
        credential_store: &'a C,
        resolver: &'a D,
        parser: &'a P,
        transport: &'a mut T,
    ) -> Self {
        Self {
            repository,
            credential_store,
            resolver,
            parser,
            transport,
            limits: NetworkLimits::default(),
        }
    }

    #[must_use]
    pub fn with_limits(mut self, limits: NetworkLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn probe_connection(
        &mut self,
        input: &ProbeConnectionInput,
        cancellation: &dyn OperationControl,
    ) -> Result<ProbeConnectionOutcome, DiscoveryErrorCode> {
        let Some(mut lease) = begin_operation(cancellation)? else {
            return Ok(ProbeConnectionOutcome::Cancelled);
        };
        let pending = (|| {
            let response = self.execute(
                input.service_version,
                &input.identity_id,
                &input.credential_ref_id,
                input.expected_identity_version,
                input.endpoint_policy,
                &input.operation_id,
                cancellation,
            )?;
            check_cancelled(cancellation)?;
            validate_status(response.status())?;
            check_cancelled(cancellation)?;
            let _ = parse_models(
                response.body(),
                self.limits.maximum_model_count,
                self.limits.maximum_json_depth,
            )?;
            check_cancelled(cancellation)?;
            Ok(ReachableSummary {
                api_compatible: true,
            })
        })();
        match publish_terminal(cancellation, &mut lease, pending)? {
            Some(summary) => Ok(ProbeConnectionOutcome::Reachable(summary)),
            None => Ok(ProbeConnectionOutcome::Cancelled),
        }
    }

    pub fn discover_models(
        &mut self,
        input: &DiscoverModelsInput,
        cancellation: &dyn OperationControl,
    ) -> Result<DiscoverModelsOutcome, DiscoveryErrorCode> {
        let Some(mut lease) = begin_operation(cancellation)? else {
            return Ok(DiscoverModelsOutcome::Cancelled);
        };
        let pending = (|| {
            let response = self.execute(
                input.service_version,
                &input.identity_id,
                &input.credential_ref_id,
                input.expected_identity_version,
                input.endpoint_policy,
                &input.operation_id,
                cancellation,
            )?;
            check_cancelled(cancellation)?;
            validate_status(response.status())?;
            check_cancelled(cancellation)?;
            let models = parse_models(
                response.body(),
                self.limits.maximum_model_count,
                self.limits.maximum_json_depth,
            )?;
            check_cancelled(cancellation)?;
            Ok(models)
        })();
        match publish_terminal(cancellation, &mut lease, pending)? {
            Some(models) => Ok(DiscoverModelsOutcome::Models(models)),
            None => Ok(DiscoverModelsOutcome::Cancelled),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn execute(
        &mut self,
        service_version: u16,
        identity_id: &IdentityId,
        credential_ref_id: &CredentialRefId,
        expected_identity_version: EntityVersion,
        endpoint_policy: EndpointPolicy,
        operation_id: &str,
        cancellation: &dyn CancellationProbe,
    ) -> Result<TransportResponse, DiscoveryErrorCode> {
        if service_version != M28_SERVICE_VERSION || !valid_operation_id(operation_id) {
            return Err(DiscoveryErrorCode::Validation);
        }
        check_cancelled(cancellation)?;
        let identity = self
            .repository
            .get_runtime_identity(identity_id)
            .map_err(map_repository_error)?
            .ok_or(DiscoveryErrorCode::NotFound)?;
        validate_identity(&identity, credential_ref_id, expected_identity_version)?;
        let reference = self
            .repository
            .get_credential_reference(credential_ref_id)
            .map_err(map_repository_error)?
            .ok_or(DiscoveryErrorCode::NotFound)?;
        if identity.credential().kind() != reference.kind() {
            return Err(DiscoveryErrorCode::Conflict);
        }
        let endpoint = NormalizedEndpoint::parse(
            M28_SERVICE_VERSION,
            identity.api_base_url().as_str(),
            endpoint_policy,
        )
        .map_err(|_| DiscoveryErrorCode::Validation)?;
        let deadline = Instant::now()
            .checked_add(self.limits.total_timeout)
            .ok_or(DiscoveryErrorCode::Internal)?;
        let addresses = if let Some(address) = endpoint.literal_ip() {
            vec![address]
        } else {
            self.resolver
                .resolve(endpoint.host(), endpoint.port(), deadline, cancellation)
                .map_err(map_resolver_error)?
        };
        check_cancelled(cancellation)?;
        let target = ApprovedHttpTarget::new(endpoint, addresses, self.limits)
            .map_err(|_| DiscoveryErrorCode::Forbidden)?;

        let binding = CredentialEnvelopeBinding::new(
            reference.id().clone(),
            reference.kind(),
            reference.schema_fingerprint().clone(),
            reference.version(),
        );
        let mut capture = TokenCapture::default();
        let mut document_consumer = DocumentConsumer {
            parser: self.parser,
            reference: &reference,
            capture: &mut capture,
            parse_error: None,
        };
        self.credential_store
            .read(&binding, &mut document_consumer)
            .map_err(map_store_error)?;
        if let Some(error) = document_consumer.parse_error {
            return Err(map_auth_error(error));
        }
        let mut authorization = capture.bytes.ok_or(DiscoveryErrorCode::AuthRequired)?;
        check_cancelled(cancellation)?;
        let response = self
            .transport
            .get_models(&target, &mut authorization, cancellation)
            .map_err(map_transport_error)?;
        check_cancelled(cancellation)?;
        let current_identity = self
            .repository
            .get_runtime_identity(identity_id)
            .map_err(map_repository_error)?
            .ok_or(DiscoveryErrorCode::NotFound)?;
        let current_reference = self
            .repository
            .get_credential_reference(credential_ref_id)
            .map_err(map_repository_error)?
            .ok_or(DiscoveryErrorCode::NotFound)?;
        if current_identity != identity || current_reference != reference {
            return Err(DiscoveryErrorCode::Conflict);
        }
        Ok(response)
    }
}

fn check_cancelled(cancellation: &dyn CancellationProbe) -> Result<(), DiscoveryErrorCode> {
    if cancellation.is_cancelled() {
        Err(DiscoveryErrorCode::Cancelled)
    } else {
        Ok(())
    }
}

fn begin_operation(
    cancellation: &dyn OperationControl,
) -> Result<Option<OperationLease>, DiscoveryErrorCode> {
    match cancellation.begin() {
        Ok(lease) => Ok(Some(lease)),
        Err(BeginDisposition::Cancelled) => Ok(None),
        Err(BeginDisposition::AlreadyClaimed | BeginDisposition::AlreadyTerminal) => {
            Err(DiscoveryErrorCode::Internal)
        }
    }
}

fn publish_terminal<T>(
    cancellation: &dyn OperationControl,
    lease: &mut OperationLease,
    pending: Result<T, DiscoveryErrorCode>,
) -> Result<Option<T>, DiscoveryErrorCode> {
    // 不捕获不可恢复 panic；unwind 仍由各 Zeroizing owner 清理秘密，调用方须丢弃该 controller。
    let pending_cancelled = pending.as_ref().err() == Some(&DiscoveryErrorCode::Cancelled);
    if pending_cancelled && !cancellation.is_cancelled() {
        match cancellation.cancel() {
            CancelDisposition::Cancelled | CancelDisposition::AlreadyCancelled => {}
            CancelDisposition::TooLate => return Err(DiscoveryErrorCode::Internal),
        }
    }

    match cancellation.finish(lease) {
        PublishDisposition::Published if pending_cancelled => Ok(None),
        PublishDisposition::Published => pending.map(Some),
        PublishDisposition::Cancelled => Ok(None),
        PublishDisposition::AlreadyPublished | PublishDisposition::InvalidLease => {
            Err(DiscoveryErrorCode::Internal)
        }
    }
}

fn validate_identity(
    identity: &RuntimeIdentity,
    credential_ref_id: &CredentialRefId,
    expected_version: EntityVersion,
) -> Result<(), DiscoveryErrorCode> {
    if identity.version() != expected_version || identity.credential().id() != credential_ref_id {
        return Err(DiscoveryErrorCode::Conflict);
    }
    Ok(())
}

fn valid_operation_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && !contains_high_confidence_secret(value)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[derive(Default)]
struct TokenCapture {
    bytes: Option<Zeroizing<Vec<u8>>>,
}
impl AuthorizationConsumer for TokenCapture {
    fn consume(&mut self, authorization: &[u8]) -> Result<(), AuthorizationParseError> {
        if authorization.is_empty()
            || authorization.len() > 16_384
            || !authorization.iter().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
            })
        {
            return Err(AuthorizationParseError::Invalid);
        }
        self.bytes = Some(Zeroizing::new(authorization.to_vec()));
        Ok(())
    }
}

struct DocumentConsumer<'a, P> {
    parser: &'a P,
    reference: &'a codex_domain::CredentialReference,
    capture: &'a mut TokenCapture,
    parse_error: Option<AuthorizationParseError>,
}

impl<P: CredentialAuthorizationParser> SecretConsumer for DocumentConsumer<'_, P> {
    fn consume(&mut self, secret: &[u8]) -> Result<(), CredentialStoreError> {
        if let Err(error) = self.parser.parse(
            self.reference.kind(),
            self.reference.schema_fingerprint(),
            secret,
            self.capture,
        ) {
            self.parse_error = Some(error);
        }
        Ok(())
    }
}

fn map_repository_error(error: RepositoryError) -> DiscoveryErrorCode {
    match error {
        RepositoryError::NotFound(_) => DiscoveryErrorCode::NotFound,
        RepositoryError::VersionConflict(_) | RepositoryError::ReferenceConflict(_) => {
            DiscoveryErrorCode::Conflict
        }
        RepositoryError::CorruptData => DiscoveryErrorCode::CompatibilityProtected,
        _ => DiscoveryErrorCode::Internal,
    }
}
fn map_store_error(error: CredentialStoreError) -> DiscoveryErrorCode {
    match error {
        CredentialStoreError::NotFound => DiscoveryErrorCode::NotFound,
        CredentialStoreError::VersionConflict | CredentialStoreError::BindingMismatch => {
            DiscoveryErrorCode::Conflict
        }
        CredentialStoreError::CorruptEnvelope | CredentialStoreError::RecoveryRequired => {
            DiscoveryErrorCode::CompatibilityProtected
        }
        _ => DiscoveryErrorCode::Internal,
    }
}
fn map_resolver_error(error: ResolverErrorCode) -> DiscoveryErrorCode {
    match error {
        ResolverErrorCode::Timeout => DiscoveryErrorCode::Timeout,
        ResolverErrorCode::NetworkUnavailable => DiscoveryErrorCode::NetworkUnavailable,
        ResolverErrorCode::Cancelled => DiscoveryErrorCode::Cancelled,
        ResolverErrorCode::Internal => DiscoveryErrorCode::Internal,
    }
}
fn map_transport_error(error: TransportErrorCode) -> DiscoveryErrorCode {
    match error {
        TransportErrorCode::Timeout => DiscoveryErrorCode::Timeout,
        TransportErrorCode::TlsFailure => DiscoveryErrorCode::TlsFailure,
        TransportErrorCode::NetworkUnavailable => DiscoveryErrorCode::NetworkUnavailable,
        TransportErrorCode::InvalidResponse => DiscoveryErrorCode::InvalidResponse,
        TransportErrorCode::ResponseTooLarge => DiscoveryErrorCode::ResponseTooLarge,
        TransportErrorCode::Cancelled => DiscoveryErrorCode::Cancelled,
        TransportErrorCode::Internal => DiscoveryErrorCode::Internal,
    }
}
fn map_auth_error(error: AuthorizationParseError) -> DiscoveryErrorCode {
    match error {
        AuthorizationParseError::AuthRequired => DiscoveryErrorCode::AuthRequired,
        AuthorizationParseError::Unsupported | AuthorizationParseError::Invalid => {
            DiscoveryErrorCode::CompatibilityProtected
        }
    }
}

fn validate_status(status: u16) -> Result<(), DiscoveryErrorCode> {
    match status {
        200..=299 => Ok(()),
        401 => Err(DiscoveryErrorCode::AuthRequired),
        403 => Err(DiscoveryErrorCode::Forbidden),
        429 => Err(DiscoveryErrorCode::RateLimited),
        500..=599 => Err(DiscoveryErrorCode::NetworkUnavailable),
        _ => Err(DiscoveryErrorCode::InvalidResponse),
    }
}

fn parse_models(
    body: &[u8],
    maximum_count: usize,
    maximum_depth: usize,
) -> Result<Vec<DiscoveredModel>, DiscoveryErrorCode> {
    if std::str::from_utf8(body).is_err() {
        return Err(DiscoveryErrorCode::InvalidResponse);
    }
    let mut parser = ModelJsonParser {
        bytes: body,
        position: 0,
        maximum_count,
        maximum_depth,
    };
    let mut models = parser.root()?;
    parser.ws();
    if parser.position != body.len() {
        return Err(DiscoveryErrorCode::InvalidResponse);
    }
    models.sort();
    models.dedup_by(|left, right| left.id() == right.id());
    Ok(models)
}

struct ModelJsonParser<'a> {
    bytes: &'a [u8],
    position: usize,
    maximum_count: usize,
    maximum_depth: usize,
}

impl ModelJsonParser<'_> {
    fn ws(&mut self) {
        while self
            .bytes
            .get(self.position)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        {
            self.position += 1;
        }
    }
    fn expect(&mut self, byte: u8) -> Result<(), DiscoveryErrorCode> {
        self.ws();
        if self.bytes.get(self.position) == Some(&byte) {
            self.position += 1;
            Ok(())
        } else {
            Err(DiscoveryErrorCode::InvalidResponse)
        }
    }

    fn root(&mut self) -> Result<Vec<DiscoveredModel>, DiscoveryErrorCode> {
        self.expect(b'{')?;
        let mut models = None;
        self.ws();
        if self.bytes.get(self.position) == Some(&b'}') {
            return Err(DiscoveryErrorCode::InvalidResponse);
        }
        loop {
            let key = self.string(64)?;
            self.expect(b':')?;
            if key.as_slice() == b"data" {
                if models.is_some() {
                    return Err(DiscoveryErrorCode::InvalidResponse);
                }
                models = Some(self.model_array(1)?);
            } else {
                self.skip_value(1)?;
            }
            self.ws();
            match self.bytes.get(self.position) {
                Some(b',') => self.position += 1,
                Some(b'}') => {
                    self.position += 1;
                    break;
                }
                _ => return Err(DiscoveryErrorCode::InvalidResponse),
            }
        }
        models.ok_or(DiscoveryErrorCode::InvalidResponse)
    }

    fn model_array(&mut self, depth: usize) -> Result<Vec<DiscoveredModel>, DiscoveryErrorCode> {
        if depth > self.maximum_depth {
            return Err(DiscoveryErrorCode::InvalidResponse);
        }
        self.expect(b'[')?;
        let mut models = Vec::new();
        self.ws();
        if self.bytes.get(self.position) == Some(&b']') {
            self.position += 1;
            return Ok(models);
        }
        loop {
            if models.len() >= self.maximum_count {
                return Err(DiscoveryErrorCode::ResponseTooLarge);
            }
            models.push(self.model(depth + 1)?);
            self.ws();
            match self.bytes.get(self.position) {
                Some(b',') => self.position += 1,
                Some(b']') => {
                    self.position += 1;
                    return Ok(models);
                }
                _ => return Err(DiscoveryErrorCode::InvalidResponse),
            }
        }
    }

    fn model(&mut self, depth: usize) -> Result<DiscoveredModel, DiscoveryErrorCode> {
        if depth > self.maximum_depth {
            return Err(DiscoveryErrorCode::InvalidResponse);
        }
        self.expect(b'{')?;
        let mut id = None;
        let mut display = None;
        loop {
            self.ws();
            if self.bytes.get(self.position) == Some(&b'}') {
                self.position += 1;
                break;
            }
            let key = self.string(64)?;
            self.expect(b':')?;
            match key.as_slice() {
                b"id" if id.is_none() => id = Some(self.string(128)?),
                b"name" | b"display_name" if display.is_none() => display = Some(self.string(128)?),
                b"id" | b"name" | b"display_name" => {
                    return Err(DiscoveryErrorCode::InvalidResponse);
                }
                _ => self.skip_value(depth + 1)?,
            }
            self.ws();
            match self.bytes.get(self.position) {
                Some(b',') => self.position += 1,
                Some(b'}') => {
                    self.position += 1;
                    break;
                }
                _ => return Err(DiscoveryErrorCode::InvalidResponse),
            }
        }
        let id = id.ok_or(DiscoveryErrorCode::InvalidResponse)?;
        let id = std::str::from_utf8(&id).map_err(|_| DiscoveryErrorCode::InvalidResponse)?;
        let display = display
            .as_deref()
            .map(|value| std::str::from_utf8(value.as_slice()))
            .transpose()
            .map_err(|_| DiscoveryErrorCode::InvalidResponse)?;
        DiscoveredModel::parse(id, display).map_err(|_| DiscoveryErrorCode::InvalidResponse)
    }

    fn skip_value(&mut self, depth: usize) -> Result<(), DiscoveryErrorCode> {
        if depth > self.maximum_depth {
            return Err(DiscoveryErrorCode::InvalidResponse);
        }
        self.ws();
        match self.bytes.get(self.position) {
            Some(b'"') => {
                self.skip_string()?;
                Ok(())
            }
            Some(b'{') => {
                self.position += 1;
                self.skip_collection(b'}', depth)
            }
            Some(b'[') => {
                self.position += 1;
                self.skip_array(depth)
            }
            Some(b't') => self.literal(b"true"),
            Some(b'f') => self.literal(b"false"),
            Some(b'n') => self.literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(DiscoveryErrorCode::InvalidResponse),
        }
    }
    fn skip_collection(&mut self, end: u8, depth: usize) -> Result<(), DiscoveryErrorCode> {
        self.ws();
        if self.bytes.get(self.position) == Some(&end) {
            self.position += 1;
            return Ok(());
        }
        loop {
            self.skip_string()?;
            self.expect(b':')?;
            self.skip_value(depth + 1)?;
            self.ws();
            match self.bytes.get(self.position) {
                Some(b',') => self.position += 1,
                Some(byte) if *byte == end => {
                    self.position += 1;
                    return Ok(());
                }
                _ => return Err(DiscoveryErrorCode::InvalidResponse),
            }
        }
    }
    fn skip_array(&mut self, depth: usize) -> Result<(), DiscoveryErrorCode> {
        self.ws();
        if self.bytes.get(self.position) == Some(&b']') {
            self.position += 1;
            return Ok(());
        }
        loop {
            self.skip_value(depth + 1)?;
            self.ws();
            match self.bytes.get(self.position) {
                Some(b',') => self.position += 1,
                Some(b']') => {
                    self.position += 1;
                    return Ok(());
                }
                _ => return Err(DiscoveryErrorCode::InvalidResponse),
            }
        }
    }
    fn string(&mut self, maximum: usize) -> Result<Zeroizing<Vec<u8>>, DiscoveryErrorCode> {
        self.expect(b'"')?;
        let mut output = Zeroizing::new(Vec::new());
        loop {
            let byte = *self
                .bytes
                .get(self.position)
                .ok_or(DiscoveryErrorCode::InvalidResponse)?;
            self.position += 1;
            match byte {
                b'"' => return Ok(output),
                b'\\' => self.escape(&mut output)?,
                0..=31 => return Err(DiscoveryErrorCode::InvalidResponse),
                32..=127 => output.push(byte),
                _ => {
                    let start = self.position - 1;
                    let scalar = std::str::from_utf8(&self.bytes[start..])
                        .ok()
                        .and_then(|value| value.chars().next())
                        .ok_or(DiscoveryErrorCode::InvalidResponse)?;
                    self.position = start + scalar.len_utf8();
                    let mut buffer = [0_u8; 4];
                    output.extend_from_slice(scalar.encode_utf8(&mut buffer).as_bytes());
                }
            }
            if output.len() > maximum {
                return Err(DiscoveryErrorCode::InvalidResponse);
            }
        }
    }
    fn skip_string(&mut self) -> Result<(), DiscoveryErrorCode> {
        let _ = self.string(4_096)?;
        Ok(())
    }
    fn escape(&mut self, output: &mut Vec<u8>) -> Result<(), DiscoveryErrorCode> {
        let escaped = *self
            .bytes
            .get(self.position)
            .ok_or(DiscoveryErrorCode::InvalidResponse)?;
        self.position += 1;
        match escaped {
            b'"' | b'\\' | b'/' => output.push(escaped),
            b'b' => output.push(8),
            b'f' => output.push(12),
            b'n' => output.push(b'\n'),
            b'r' => output.push(b'\r'),
            b't' => output.push(b'\t'),
            b'u' => {
                let scalar = self.unicode_escape()?;
                let mut buffer = [0_u8; 4];
                output.extend_from_slice(scalar.encode_utf8(&mut buffer).as_bytes());
            }
            _ => return Err(DiscoveryErrorCode::InvalidResponse),
        }
        Ok(())
    }
    fn unicode_escape(&mut self) -> Result<char, DiscoveryErrorCode> {
        let first = self.hex_quad()?;
        let scalar = if (0xd800..=0xdbff).contains(&first) {
            if self.bytes.get(self.position..self.position + 2) != Some(b"\\u") {
                return Err(DiscoveryErrorCode::InvalidResponse);
            }
            self.position += 2;
            let second = self.hex_quad()?;
            if !(0xdc00..=0xdfff).contains(&second) {
                return Err(DiscoveryErrorCode::InvalidResponse);
            }
            0x1_0000 + ((u32::from(first) - 0xd800) << 10) + (u32::from(second) - 0xdc00)
        } else if (0xdc00..=0xdfff).contains(&first) {
            return Err(DiscoveryErrorCode::InvalidResponse);
        } else {
            u32::from(first)
        };
        char::from_u32(scalar).ok_or(DiscoveryErrorCode::InvalidResponse)
    }
    fn hex_quad(&mut self) -> Result<u16, DiscoveryErrorCode> {
        let digits = self
            .bytes
            .get(self.position..self.position + 4)
            .ok_or(DiscoveryErrorCode::InvalidResponse)?;
        let mut value = 0_u16;
        for digit in digits {
            value = value
                .checked_mul(16)
                .and_then(|v| {
                    digit
                        .to_ascii_lowercase()
                        .checked_sub(b'0')
                        .and_then(|o| match o {
                            0..=9 => Some(v + u16::from(o)),
                            49..=54 => Some(v + u16::from(o - 39)),
                            _ => None,
                        })
                })
                .ok_or(DiscoveryErrorCode::InvalidResponse)?;
        }
        self.position += 4;
        Ok(value)
    }
    fn literal(&mut self, value: &[u8]) -> Result<(), DiscoveryErrorCode> {
        if self.bytes.get(self.position..self.position + value.len()) == Some(value) {
            self.position += value.len();
            Ok(())
        } else {
            Err(DiscoveryErrorCode::InvalidResponse)
        }
    }
    fn number(&mut self) -> Result<(), DiscoveryErrorCode> {
        let start = self.position;
        if self.bytes.get(self.position) == Some(&b'-') {
            self.position += 1;
        }
        if self.bytes.get(self.position) == Some(&b'0') {
            self.position += 1;
        } else {
            let digits = self.position;
            while self
                .bytes
                .get(self.position)
                .is_some_and(u8::is_ascii_digit)
            {
                self.position += 1;
            }
            if self.position == digits {
                return Err(DiscoveryErrorCode::InvalidResponse);
            }
        }
        if self.bytes.get(self.position) == Some(&b'.') {
            self.position += 1;
            let digits = self.position;
            while self
                .bytes
                .get(self.position)
                .is_some_and(u8::is_ascii_digit)
            {
                self.position += 1;
            }
            if self.position == digits {
                return Err(DiscoveryErrorCode::InvalidResponse);
            }
        }
        if self
            .bytes
            .get(self.position)
            .is_some_and(|b| matches!(b, b'e' | b'E'))
        {
            self.position += 1;
            if self
                .bytes
                .get(self.position)
                .is_some_and(|b| matches!(b, b'+' | b'-'))
            {
                self.position += 1;
            }
            let digits = self.position;
            while self
                .bytes
                .get(self.position)
                .is_some_and(u8::is_ascii_digit)
            {
                self.position += 1;
            }
            if self.position == digits {
                return Err(DiscoveryErrorCode::InvalidResponse);
            }
        }
        if self.position == start {
            Err(DiscoveryErrorCode::InvalidResponse)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ApprovedHttpTarget, AuthorizationParseError, CancelDisposition, CancellationController,
        DiscoveryErrorCode, NetworkLimits, map_auth_error, parse_models, validate_status,
    };
    use codex_domain::{EndpointPolicy, NormalizedEndpoint};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn model_candidates_are_bounded_deduplicated_sorted_and_secret_free() {
        let models = parse_models(br#"{"data":[{"id":"z-model","name":"Zulu"},{"id":"a-model"},{"id":"a-model","name":"Duplicate"}]}"#, 8, 8).unwrap();
        assert_eq!(models.len(), 2);
        assert_eq!(models[0].id().as_str(), "a-model");
        assert_eq!(models[1].id().as_str(), "z-model");
        let canaries = [
            ["sk-", "123456789012345678901234"].concat(),
            ["gh", "p_", "ABCDEFGHIJKLMNOPQRSTUVWX"].concat(),
            ["AK", "IA", "ABCDEFGHIJKLMNOP"].concat(),
            ["eyJ", "abcdefgh.abcdefgh.abcdefgh"].concat(),
            ["-----BEGIN ", "PRIVATE KEY", "-----"].concat(),
            "C:/Users/SAMPLE/secret".to_owned(),
        ];
        for canary in canaries {
            let body = format!(r#"{{"data":[{{"id":"{canary}"}}]}}"#);
            assert_eq!(
                parse_models(body.as_bytes(), 8, 8),
                Err(DiscoveryErrorCode::InvalidResponse)
            );
        }
    }

    #[test]
    fn model_json_rejects_count_depth_duplicate_fields_and_malformed_input() {
        assert_eq!(
            parse_models(br#"{"data":[{"id":"a"},{"id":"b"}]}"#, 1, 8),
            Err(DiscoveryErrorCode::ResponseTooLarge)
        );
        assert_eq!(
            parse_models(br#"{"meta":{"a":{"b":{"c":1}}},"data":[]}"#, 8, 2),
            Err(DiscoveryErrorCode::InvalidResponse)
        );
        for body in [
            br#"{"data":[{"id":"a","id":"b"}]}"#.as_slice(),
            br#"{"data":[{"id":null}]}"#.as_slice(),
            br#"{"data":[{"id":"a"}],}"#.as_slice(),
        ] {
            assert_eq!(
                parse_models(body, 8, 8),
                Err(DiscoveryErrorCode::InvalidResponse)
            );
        }
    }

    #[test]
    fn status_and_cancellation_contracts_are_stable() {
        assert_eq!(validate_status(401), Err(DiscoveryErrorCode::AuthRequired));
        assert_eq!(validate_status(403), Err(DiscoveryErrorCode::Forbidden));
        assert_eq!(validate_status(429), Err(DiscoveryErrorCode::RateLimited));
        assert_eq!(
            validate_status(503),
            Err(DiscoveryErrorCode::NetworkUnavailable)
        );
        let cancellation = CancellationController::new();
        assert_eq!(cancellation.cancel(), CancelDisposition::Cancelled);
        assert_eq!(cancellation.cancel(), CancelDisposition::AlreadyCancelled);
        let completed = CancellationController::new();
        let mut lease = completed.begin().unwrap();
        assert_eq!(
            completed.finish(&mut lease),
            super::PublishDisposition::Published
        );
        assert_eq!(
            completed.finish(&mut lease),
            super::PublishDisposition::AlreadyPublished
        );
        assert_eq!(completed.cancel(), CancelDisposition::TooLate);
        assert_eq!(
            map_auth_error(AuthorizationParseError::Invalid),
            DiscoveryErrorCode::CompatibilityProtected
        );
    }

    #[test]
    fn approved_target_rejects_mixed_dns_answers() {
        let endpoint =
            NormalizedEndpoint::parse(1, "https://api.example.com/v1", EndpointPolicy::PublicHttps)
                .unwrap();
        assert!(
            ApprovedHttpTarget::new(
                endpoint,
                vec![
                    IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                    IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))
                ],
                NetworkLimits::default()
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod service_tests {
    use super::{
        ApprovedHttpTarget, ApprovedHttpTransport, AuthorizationConsumer, AuthorizationParseError,
        CancellationController, CancellationProbe, CredentialAuthorizationParser,
        DiscoverModelsInput, DiscoverModelsOutcome, DiscoveryErrorCode, DnsResolver,
        PublishDisposition, ResolverErrorCode, SafeModelDiscoveryService, TransportErrorCode,
        TransportResponse,
    };
    use crate::{
        CredentialEnvelopeBinding, CredentialReferenceRepository, CredentialStore,
        CredentialStoreError, IdentityCandidateQuery, RepositoryError, RuntimeIdentityRepository,
        SecretConsumer,
    };
    use codex_domain::{
        CredentialBackend, CredentialFingerprint, CredentialKind, CredentialRefId,
        CredentialReference, EndpointPolicy, EndpointUrl, EntityName, EntityVersion, IdentityId,
        ProviderId, RuntimeIdentity, SchemaFingerprint, UnixMillis,
    };
    use std::{
        cell::{Cell, RefCell},
        net::{IpAddr, Ipv4Addr},
        panic::{AssertUnwindSafe, catch_unwind},
        sync::{
            Arc, Barrier,
            atomic::{AtomicUsize, Ordering as AtomicOrdering},
            mpsc,
        },
        thread,
        time::Instant,
    };

    #[derive(Default)]
    struct LayerCounters {
        repository: AtomicUsize,
        credential: AtomicUsize,
        resolver: AtomicUsize,
        parser: AtomicUsize,
        transport: AtomicUsize,
    }

    impl LayerCounters {
        fn snapshot(&self) -> [usize; 5] {
            [
                self.repository.load(AtomicOrdering::SeqCst),
                self.credential.load(AtomicOrdering::SeqCst),
                self.resolver.load(AtomicOrdering::SeqCst),
                self.parser.load(AtomicOrdering::SeqCst),
                self.transport.load(AtomicOrdering::SeqCst),
            ]
        }
    }

    struct FakeRepository {
        identity: RuntimeIdentity,
        credential: RefCell<CredentialReference>,
        counters: Option<Arc<LayerCounters>>,
        counted: Cell<bool>,
    }
    impl FakeRepository {
        fn count_entry(&self) {
            if !self.counted.replace(true)
                && let Some(counters) = &self.counters
            {
                counters.repository.fetch_add(1, AtomicOrdering::SeqCst);
            }
        }
    }
    impl RuntimeIdentityRepository for FakeRepository {
        fn create_runtime_identity(&mut self, _: &RuntimeIdentity) -> Result<(), RepositoryError> {
            Err(RepositoryError::storage_unavailable())
        }
        fn get_runtime_identity(
            &self,
            id: &IdentityId,
        ) -> Result<Option<RuntimeIdentity>, RepositoryError> {
            self.count_entry();
            Ok((self.identity.id() == id).then(|| self.identity.clone()))
        }
        fn list_runtime_identities(&self) -> Result<Vec<RuntimeIdentity>, RepositoryError> {
            Ok(vec![self.identity.clone()])
        }
        fn update_runtime_identity(
            &mut self,
            _: &RuntimeIdentity,
            _: EntityVersion,
        ) -> Result<(), RepositoryError> {
            Err(RepositoryError::storage_unavailable())
        }
        fn delete_runtime_identity(
            &mut self,
            _: &IdentityId,
            _: EntityVersion,
        ) -> Result<(), RepositoryError> {
            Err(RepositoryError::storage_unavailable())
        }
        fn find_identity_candidates(
            &self,
            _: &IdentityCandidateQuery,
        ) -> Result<Vec<RuntimeIdentity>, RepositoryError> {
            Ok(Vec::new())
        }
    }
    impl CredentialReferenceRepository for FakeRepository {
        fn create_credential_reference(
            &mut self,
            _: &CredentialReference,
        ) -> Result<(), RepositoryError> {
            Err(RepositoryError::storage_unavailable())
        }
        fn get_credential_reference(
            &self,
            id: &CredentialRefId,
        ) -> Result<Option<CredentialReference>, RepositoryError> {
            self.count_entry();
            let value = self.credential.borrow();
            Ok((value.id() == id).then(|| value.clone()))
        }
        fn list_credential_references(&self) -> Result<Vec<CredentialReference>, RepositoryError> {
            Ok(vec![self.credential.borrow().clone()])
        }
        fn update_credential_reference(
            &mut self,
            _: &CredentialReference,
            _: EntityVersion,
        ) -> Result<(), RepositoryError> {
            Err(RepositoryError::storage_unavailable())
        }
        fn delete_credential_reference(
            &mut self,
            _: &CredentialRefId,
            _: EntityVersion,
        ) -> Result<(), RepositoryError> {
            Err(RepositoryError::storage_unavailable())
        }
    }
    struct FakeStore {
        document: Vec<u8>,
        counters: Option<Arc<LayerCounters>>,
    }
    impl CredentialStore for FakeStore {
        fn create(
            &mut self,
            _: &CredentialEnvelopeBinding,
            _: &mut [u8],
        ) -> Result<(), CredentialStoreError> {
            Err(CredentialStoreError::RecoveryRequired)
        }
        fn read(
            &self,
            _: &CredentialEnvelopeBinding,
            consumer: &mut dyn SecretConsumer,
        ) -> Result<(), CredentialStoreError> {
            if let Some(counters) = &self.counters {
                counters.credential.fetch_add(1, AtomicOrdering::SeqCst);
            }
            consumer.consume(&self.document)
        }
        fn rotate(
            &mut self,
            _: &CredentialEnvelopeBinding,
            _: &CredentialEnvelopeBinding,
            _: &mut [u8],
        ) -> Result<(), CredentialStoreError> {
            Err(CredentialStoreError::RecoveryRequired)
        }
        fn delete(&mut self, _: &CredentialEnvelopeBinding) -> Result<(), CredentialStoreError> {
            Err(CredentialStoreError::RecoveryRequired)
        }
    }
    struct FakeParser;
    impl CredentialAuthorizationParser for FakeParser {
        fn parse(
            &self,
            _: CredentialKind,
            _: &SchemaFingerprint,
            document: &[u8],
            consumer: &mut dyn AuthorizationConsumer,
        ) -> Result<(), AuthorizationParseError> {
            consumer.consume(document)
        }
    }
    struct CountingParser(Arc<LayerCounters>);
    impl CredentialAuthorizationParser for CountingParser {
        fn parse(
            &self,
            _: CredentialKind,
            _: &SchemaFingerprint,
            document: &[u8],
            consumer: &mut dyn AuthorizationConsumer,
        ) -> Result<(), AuthorizationParseError> {
            self.0.parser.fetch_add(1, AtomicOrdering::SeqCst);
            consumer.consume(document)
        }
    }
    struct FakeResolver;
    impl DnsResolver for FakeResolver {
        fn resolve(
            &self,
            _: &str,
            _: u16,
            _: Instant,
            cancellation: &dyn CancellationProbe,
        ) -> Result<Vec<IpAddr>, ResolverErrorCode> {
            if cancellation.is_cancelled() {
                Err(ResolverErrorCode::Cancelled)
            } else {
                Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
            }
        }
    }
    struct CountingResolver(Arc<LayerCounters>);
    impl DnsResolver for CountingResolver {
        fn resolve(
            &self,
            _: &str,
            _: u16,
            _: Instant,
            cancellation: &dyn CancellationProbe,
        ) -> Result<Vec<IpAddr>, ResolverErrorCode> {
            self.0.resolver.fetch_add(1, AtomicOrdering::SeqCst);
            if cancellation.is_cancelled() {
                Err(ResolverErrorCode::Cancelled)
            } else {
                Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
            }
        }
    }
    struct FakeTransport<'a> {
        calls: Cell<usize>,
        rotate: Option<&'a FakeRepository>,
        cancel_on_return: Option<CancellationController>,
        return_barrier: Option<Arc<Barrier>>,
        failure: Option<TransportErrorCode>,
        status: u16,
        body: &'static [u8],
    }
    impl FakeTransport<'_> {
        fn successful() -> Self {
            Self {
                calls: Cell::new(0),
                rotate: None,
                cancel_on_return: None,
                return_barrier: None,
                failure: None,
                status: 200,
                body: br#"{"data":[{"id":"model-b"},{"id":"model-a"}]}"#,
            }
        }
    }
    impl ApprovedHttpTransport for FakeTransport<'_> {
        fn get_models(
            &mut self,
            _: &ApprovedHttpTarget,
            authorization: &mut [u8],
            _: &dyn CancellationProbe,
        ) -> Result<TransportResponse, TransportErrorCode> {
            assert_eq!(authorization, secret_canary());
            self.calls.set(self.calls.get() + 1);
            if let Some(repository) = self.rotate {
                let current = repository.credential.borrow().clone();
                let rotated = current
                    .rotate(
                        SchemaFingerprint::parse(&"b".repeat(64)).unwrap(),
                        CredentialFingerprint::parse(&"c".repeat(64)).unwrap(),
                        UnixMillis::new(2).unwrap(),
                    )
                    .unwrap();
                repository.credential.replace(rotated);
            }
            if let Some(cancellation) = &self.cancel_on_return {
                let _ = cancellation.cancel();
            }
            if let Some(barrier) = &self.return_barrier {
                barrier.wait();
                barrier.wait();
            }
            if let Some(error) = self.failure {
                Err(error)
            } else {
                Ok(TransportResponse::new(self.status, self.body.to_vec()))
            }
        }
    }

    struct CountingTransport(Arc<LayerCounters>);
    impl ApprovedHttpTransport for CountingTransport {
        fn get_models(
            &mut self,
            _: &ApprovedHttpTarget,
            authorization: &mut [u8],
            _: &dyn CancellationProbe,
        ) -> Result<TransportResponse, TransportErrorCode> {
            assert_eq!(authorization, secret_canary());
            self.0.transport.fetch_add(1, AtomicOrdering::SeqCst);
            Ok(TransportResponse::new(
                200,
                br#"{"data":[{"id":"model-b"},{"id":"model-a"}]}"#.to_vec(),
            ))
        }
    }
    fn fixture() -> (FakeRepository, FakeStore, DiscoverModelsInput) {
        fixture_with_counters(None)
    }

    fn fixture_with_counters(
        counters: Option<Arc<LayerCounters>>,
    ) -> (FakeRepository, FakeStore, DiscoverModelsInput) {
        let credential = CredentialReference::new(
            CredentialRefId::parse("11111111-1111-1111-1111-111111111111").unwrap(),
            CredentialKind::ApiKey,
            CredentialBackend::WindowsDpapiCurrentUser,
            SchemaFingerprint::parse(&"a".repeat(64)).unwrap(),
            CredentialFingerprint::parse(&"b".repeat(64)).unwrap(),
            UnixMillis::new(1).unwrap(),
        );
        let identity = RuntimeIdentity::new_draft(
            IdentityId::parse("22222222-2222-2222-2222-222222222222").unwrap(),
            EntityName::parse("Synthetic").unwrap(),
            ProviderId::parse("openai-compatible").unwrap(),
            EntityName::parse("Synthetic Provider").unwrap(),
            EndpointUrl::parse("https://API.EXAMPLE.COM/v1").unwrap(),
            None,
            credential.link(),
            UnixMillis::new(1).unwrap(),
        )
        .unwrap();
        let input = DiscoverModelsInput {
            service_version: 1,
            identity_id: identity.id().clone(),
            credential_ref_id: credential.id().clone(),
            expected_identity_version: identity.version(),
            endpoint_policy: EndpointPolicy::PublicHttps,
            operation_id: "operation_1".to_owned(),
        };
        (
            FakeRepository {
                identity,
                credential: RefCell::new(credential),
                counters: counters.clone(),
                counted: Cell::new(false),
            },
            FakeStore {
                document: secret_canary(),
                counters,
            },
            input,
        )
    }

    fn secret_canary() -> Vec<u8> {
        [b"sk-".as_slice(), b"SYNTHETIC_12345678901234567890"].concat()
    }
    #[test]
    fn service_short_borrows_secret_and_returns_only_validated_models() {
        let (repository, store, input) = fixture();
        let mut transport = FakeTransport {
            calls: Cell::new(0),
            rotate: None,
            cancel_on_return: None,
            return_barrier: None,
            ..FakeTransport::successful()
        };
        let mut service = SafeModelDiscoveryService::new(
            &repository,
            &store,
            &FakeResolver,
            &FakeParser,
            &mut transport,
        );
        let cancellation = CancellationController::new();
        let outcome = service.discover_models(&input, &cancellation).unwrap();
        let DiscoverModelsOutcome::Models(models) = outcome else {
            panic!("models")
        };
        assert_eq!(
            models
                .iter()
                .map(|model| model.id().as_str())
                .collect::<Vec<_>>(),
            vec!["model-a", "model-b"]
        );
        assert_eq!(transport.calls.get(), 1);
        assert!(!format!("{models:?}").contains("sk-SYNTHETIC"));
    }
    #[test]
    fn stale_identity_and_midflight_credential_rotation_return_conflict() {
        let (repository, store, mut input) = fixture();
        input.expected_identity_version = EntityVersion::new(2).unwrap();
        let mut transport = FakeTransport {
            calls: Cell::new(0),
            rotate: None,
            cancel_on_return: None,
            return_barrier: None,
            ..FakeTransport::successful()
        };
        let mut service = SafeModelDiscoveryService::new(
            &repository,
            &store,
            &FakeResolver,
            &FakeParser,
            &mut transport,
        );
        assert_eq!(
            service.discover_models(&input, &CancellationController::new()),
            Err(DiscoveryErrorCode::Conflict)
        );
        assert_eq!(transport.calls.get(), 0);
        input.expected_identity_version = EntityVersion::initial();
        let mut rotating = FakeTransport {
            calls: Cell::new(0),
            rotate: Some(&repository),
            cancel_on_return: None,
            return_barrier: None,
            ..FakeTransport::successful()
        };
        let mut service = SafeModelDiscoveryService::new(
            &repository,
            &store,
            &FakeResolver,
            &FakeParser,
            &mut rotating,
        );
        assert_eq!(
            service.discover_models(&input, &CancellationController::new()),
            Err(DiscoveryErrorCode::Conflict)
        );
        assert_eq!(rotating.calls.get(), 1);
    }

    #[test]
    fn probe_cancellation_before_publish_wins_and_late_cancel_is_too_late() {
        let (repository, store, input) = fixture();
        let probe = super::ProbeConnectionInput {
            service_version: input.service_version,
            identity_id: input.identity_id.clone(),
            credential_ref_id: input.credential_ref_id.clone(),
            expected_identity_version: input.expected_identity_version,
            endpoint_policy: input.endpoint_policy,
            operation_id: "probe_operation".to_owned(),
        };
        let cancellation = CancellationController::new();
        let mut transport = FakeTransport {
            calls: Cell::new(0),
            rotate: None,
            cancel_on_return: Some(cancellation.clone()),
            return_barrier: None,
            ..FakeTransport::successful()
        };
        let mut service = SafeModelDiscoveryService::new(
            &repository,
            &store,
            &FakeResolver,
            &FakeParser,
            &mut transport,
        );
        assert_eq!(
            service.probe_connection(&probe, &cancellation),
            Ok(super::ProbeConnectionOutcome::Cancelled)
        );

        let late = CancellationController::new();
        let mut transport = FakeTransport {
            calls: Cell::new(0),
            rotate: None,
            cancel_on_return: None,
            return_barrier: None,
            ..FakeTransport::successful()
        };
        let mut service = SafeModelDiscoveryService::new(
            &repository,
            &store,
            &FakeResolver,
            &FakeParser,
            &mut transport,
        );
        assert!(matches!(
            service.probe_connection(&probe, &late),
            Ok(super::ProbeConnectionOutcome::Reachable(_))
        ));
        assert_eq!(late.cancel(), super::CancelDisposition::TooLate);
    }

    #[test]
    fn business_error_claims_terminal_before_late_cancel() {
        let (repository, store, mut input) = fixture();
        input.operation_id.clear();
        let cancellation = CancellationController::new();
        let mut transport = FakeTransport {
            calls: Cell::new(0),
            rotate: None,
            cancel_on_return: None,
            return_barrier: None,
            ..FakeTransport::successful()
        };
        let mut service = SafeModelDiscoveryService::new(
            &repository,
            &store,
            &FakeResolver,
            &FakeParser,
            &mut transport,
        );

        assert_eq!(
            service.discover_models(&input, &cancellation),
            Err(DiscoveryErrorCode::Validation)
        );
        assert_eq!(cancellation.cancel(), super::CancelDisposition::TooLate);

        let (repository, store, input) = fixture();
        let mut probe = probe_from(&input);
        probe.operation_id.clear();
        let probe_cancellation = CancellationController::new();
        let mut transport = FakeTransport::successful();
        let mut service = SafeModelDiscoveryService::new(
            &repository,
            &store,
            &FakeResolver,
            &FakeParser,
            &mut transport,
        );
        assert_eq!(
            service.probe_connection(&probe, &probe_cancellation),
            Err(DiscoveryErrorCode::Validation)
        );
        assert_eq!(
            probe_cancellation.cancel(),
            super::CancelDisposition::TooLate
        );
    }

    #[test]
    fn cancel_before_validation_wins_the_only_terminal_result() {
        let (repository, store, mut input) = fixture();
        input.operation_id.clear();
        let cancellation = CancellationController::new();
        assert_eq!(cancellation.cancel(), super::CancelDisposition::Cancelled);
        let mut transport = FakeTransport {
            calls: Cell::new(0),
            rotate: None,
            cancel_on_return: None,
            return_barrier: None,
            ..FakeTransport::successful()
        };
        let mut service = SafeModelDiscoveryService::new(
            &repository,
            &store,
            &FakeResolver,
            &FakeParser,
            &mut transport,
        );

        assert_eq!(
            service.discover_models(&input, &cancellation),
            Ok(DiscoverModelsOutcome::Cancelled)
        );
        assert_eq!(
            cancellation.cancel(),
            super::CancelDisposition::AlreadyCancelled
        );
    }

    #[test]
    fn sequential_controller_reuse_fails_closed_without_second_payload() {
        let (repository, store, input) = fixture();
        let cancellation = CancellationController::new();
        let mut transport = FakeTransport {
            calls: Cell::new(0),
            rotate: None,
            cancel_on_return: None,
            return_barrier: None,
            ..FakeTransport::successful()
        };
        let mut service = SafeModelDiscoveryService::new(
            &repository,
            &store,
            &FakeResolver,
            &FakeParser,
            &mut transport,
        );

        assert!(matches!(
            service.discover_models(&input, &cancellation),
            Ok(DiscoverModelsOutcome::Models(_))
        ));
        assert_eq!(
            service.discover_models(&input, &cancellation),
            Err(DiscoveryErrorCode::Internal)
        );
        assert_eq!(transport.calls.get(), 1);
        assert_eq!(cancellation.cancel(), super::CancelDisposition::TooLate);
    }

    #[test]
    fn probe_and_discover_share_success_and_cancel_terminal_rules() {
        let (repository, store, input) = fixture();
        let probe = probe_from(&input);

        let cancelled_probe = CancellationController::new();
        assert_eq!(
            cancelled_probe.cancel(),
            super::CancelDisposition::Cancelled
        );
        let mut transport = FakeTransport::successful();
        let mut service = SafeModelDiscoveryService::new(
            &repository,
            &store,
            &FakeResolver,
            &FakeParser,
            &mut transport,
        );
        assert_eq!(
            service.probe_connection(&probe, &cancelled_probe),
            Ok(super::ProbeConnectionOutcome::Cancelled)
        );
        assert_eq!(
            cancelled_probe.cancel(),
            super::CancelDisposition::AlreadyCancelled
        );

        let cancelled_discovery = CancellationController::new();
        assert_eq!(
            cancelled_discovery.cancel(),
            super::CancelDisposition::Cancelled
        );
        let mut transport = FakeTransport::successful();
        let mut service = SafeModelDiscoveryService::new(
            &repository,
            &store,
            &FakeResolver,
            &FakeParser,
            &mut transport,
        );
        assert_eq!(
            service.discover_models(&input, &cancelled_discovery),
            Ok(DiscoverModelsOutcome::Cancelled)
        );

        let completed_discovery = CancellationController::new();
        let mut transport = FakeTransport::successful();
        let mut service = SafeModelDiscoveryService::new(
            &repository,
            &store,
            &FakeResolver,
            &FakeParser,
            &mut transport,
        );
        assert!(matches!(
            service.discover_models(&input, &completed_discovery),
            Ok(DiscoverModelsOutcome::Models(_))
        ));
        assert_eq!(
            completed_discovery.cancel(),
            super::CancelDisposition::TooLate
        );
    }

    #[test]
    fn every_business_error_category_claims_a_terminal_result() {
        fn run(
            mutate_input: impl FnOnce(&mut DiscoverModelsInput),
            mutate_transport: impl FnOnce(&mut FakeTransport<'_>),
            expected: DiscoveryErrorCode,
        ) {
            let (repository, store, mut input) = fixture();
            mutate_input(&mut input);
            let cancellation = CancellationController::new();
            let mut transport = FakeTransport::successful();
            mutate_transport(&mut transport);
            let mut service = SafeModelDiscoveryService::new(
                &repository,
                &store,
                &FakeResolver,
                &FakeParser,
                &mut transport,
            );
            assert_eq!(
                service.discover_models(&input, &cancellation),
                Err(expected)
            );
            assert_eq!(cancellation.cancel(), super::CancelDisposition::TooLate);
        }

        run(
            |input| input.operation_id.clear(),
            |_| {},
            DiscoveryErrorCode::Validation,
        );
        run(
            |input| input.expected_identity_version = EntityVersion::new(2).unwrap(),
            |_| {},
            DiscoveryErrorCode::Conflict,
        );
        run(
            |input| {
                input.identity_id =
                    IdentityId::parse("33333333-3333-3333-3333-333333333333").unwrap();
            },
            |_| {},
            DiscoveryErrorCode::NotFound,
        );
        run(
            |_| {},
            |transport| transport.failure = Some(TransportErrorCode::Timeout),
            DiscoveryErrorCode::Timeout,
        );
        run(
            |_| {},
            |transport| transport.status = 401,
            DiscoveryErrorCode::AuthRequired,
        );
        run(
            |_| {},
            |transport| transport.body = br#"{"data":["#,
            DiscoveryErrorCode::InvalidResponse,
        );
        run(
            |_| {},
            |transport| transport.body = br#"{"data":[{"id":"../credential/token"}]}"#,
            DiscoveryErrorCode::InvalidResponse,
        );
    }

    #[test]
    fn lower_layer_cancel_claims_cancelled_terminal_and_blocks_second_side_effect() {
        let (repository, store, input) = fixture();
        let cancellation = CancellationController::new();
        let mut transport = FakeTransport {
            failure: Some(TransportErrorCode::Cancelled),
            ..FakeTransport::successful()
        };
        let mut service = SafeModelDiscoveryService::new(
            &repository,
            &store,
            &FakeResolver,
            &FakeParser,
            &mut transport,
        );
        assert_eq!(
            service.discover_models(&input, &cancellation),
            Ok(DiscoverModelsOutcome::Cancelled)
        );
        assert_eq!(transport.calls.get(), 1);
        assert_eq!(
            cancellation.cancel(),
            super::CancelDisposition::AlreadyCancelled
        );

        let mut transport = FakeTransport::successful();
        let mut service = SafeModelDiscoveryService::new(
            &repository,
            &store,
            &FakeResolver,
            &FakeParser,
            &mut transport,
        );
        assert_eq!(
            service.discover_models(&input, &cancellation),
            Ok(DiscoverModelsOutcome::Cancelled)
        );
        assert_eq!(transport.calls.get(), 0);
    }

    #[test]
    fn error_publish_and_cancel_races_have_one_terminal_winner() {
        let (result_tx, result_rx) = mpsc::sync_channel(1);
        let completed = CancellationController::new();
        let worker_controller = completed.clone();
        let error_worker = thread::spawn(move || {
            let (repository, store, mut input) = fixture();
            input.operation_id.clear();
            let mut transport = FakeTransport::successful();
            let mut service = SafeModelDiscoveryService::new(
                &repository,
                &store,
                &FakeResolver,
                &FakeParser,
                &mut transport,
            );
            let result = service.discover_models(&input, &worker_controller);
            result_tx.send(result).unwrap();
        });
        assert_eq!(
            result_rx.recv().unwrap(),
            Err(DiscoveryErrorCode::Validation)
        );
        assert_eq!(completed.cancel(), super::CancelDisposition::TooLate);
        error_worker.join().unwrap();

        let publish_barrier = Arc::new(Barrier::new(2));
        let publish_gate = Arc::new(PublishBarrierGate {
            controller: CancellationController::new(),
            barrier: publish_barrier.clone(),
        });
        let worker_gate = publish_gate.clone();
        let cancelled_worker = thread::spawn(move || {
            let (repository, store, input) = fixture();
            let mut transport = FakeTransport {
                status: 401,
                ..FakeTransport::successful()
            };
            let mut service = SafeModelDiscoveryService::new(
                &repository,
                &store,
                &FakeResolver,
                &FakeParser,
                &mut transport,
            );
            service.discover_models(&input, worker_gate.as_ref())
        });
        publish_barrier.wait();
        assert_eq!(
            publish_gate.controller.cancel(),
            super::CancelDisposition::Cancelled
        );
        publish_barrier.wait();
        assert_eq!(
            cancelled_worker.join().unwrap(),
            Ok(DiscoverModelsOutcome::Cancelled)
        );
        assert_eq!(
            publish_gate.controller.cancel(),
            super::CancelDisposition::AlreadyCancelled
        );
    }

    fn run_counted_call(
        probe: bool,
        controller: &dyn super::OperationControl,
        counters: Arc<LayerCounters>,
    ) -> Result<&'static str, DiscoveryErrorCode> {
        let (repository, store, input) = fixture_with_counters(Some(counters.clone()));
        let resolver = CountingResolver(counters.clone());
        let parser = CountingParser(counters.clone());
        let mut transport = CountingTransport(counters);
        let mut service =
            SafeModelDiscoveryService::new(&repository, &store, &resolver, &parser, &mut transport);
        if probe {
            service
                .probe_connection(&probe_from(&input), controller)
                .map(|outcome| match outcome {
                    super::ProbeConnectionOutcome::Reachable(_) => "payload",
                    super::ProbeConnectionOutcome::Cancelled => "cancelled",
                })
        } else {
            service
                .discover_models(&input, controller)
                .map(|outcome| match outcome {
                    DiscoverModelsOutcome::Models(_) => "payload",
                    DiscoverModelsOutcome::Cancelled => "cancelled",
                })
        }
    }

    #[test]
    fn sequential_reuse_never_reenters_sensitive_layers() {
        for probe in [false, true] {
            let counters = Arc::new(LayerCounters::default());
            let controller = CancellationController::new();
            assert_eq!(
                run_counted_call(probe, &controller, counters.clone()),
                Ok("payload")
            );
            assert_eq!(counters.snapshot(), [1, 1, 1, 1, 1]);
            assert_eq!(
                run_counted_call(probe, &controller, counters.clone()),
                Err(DiscoveryErrorCode::Internal)
            );
            assert_eq!(counters.snapshot(), [1, 1, 1, 1, 1]);
        }
    }

    #[test]
    fn concurrent_probe_and_discover_claim_before_sensitive_layers() {
        for probe in [false, true] {
            let counters = Arc::new(LayerCounters::default());
            let controller = CancellationController::new();
            let (claimed_tx, claimed_rx) = mpsc::sync_channel(1);
            let release = Arc::new(Barrier::new(2));
            let gate = Arc::new(ClaimGate {
                controller: controller.clone(),
                claimed_tx,
                release: release.clone(),
            });
            let start = Arc::new(Barrier::new(3));
            let (result_tx, result_rx) = mpsc::sync_channel(2);
            let workers = (0..2)
                .map(|_| {
                    let worker_gate = gate.clone();
                    let worker_start = start.clone();
                    let worker_counters = counters.clone();
                    let worker_tx = result_tx.clone();
                    thread::spawn(move || {
                        worker_start.wait();
                        worker_tx
                            .send(run_counted_call(
                                probe,
                                worker_gate.as_ref(),
                                worker_counters,
                            ))
                            .unwrap();
                    })
                })
                .collect::<Vec<_>>();
            start.wait();
            claimed_rx.recv().unwrap();
            assert_eq!(result_rx.recv().unwrap(), Err(DiscoveryErrorCode::Internal));
            assert_eq!(counters.snapshot(), [0, 0, 0, 0, 0]);
            release.wait();
            assert_eq!(result_rx.recv().unwrap(), Ok("payload"));
            for worker in workers {
                worker.join().unwrap();
            }
            assert_eq!(counters.snapshot(), [1, 1, 1, 1, 1]);
            assert_eq!(controller.cancel(), super::CancelDisposition::TooLate);
        }
    }

    #[test]
    fn cancel_before_and_during_claim_prevents_sensitive_layers() {
        let before = CancellationController::new();
        assert_eq!(before.cancel(), super::CancelDisposition::Cancelled);
        let counters = Arc::new(LayerCounters::default());
        assert_eq!(
            run_counted_call(false, &before, counters.clone()),
            Ok("cancelled")
        );
        assert_eq!(
            run_counted_call(false, &before, counters.clone()),
            Ok("cancelled")
        );
        assert_eq!(counters.snapshot(), [0, 0, 0, 0, 0]);

        let controller = CancellationController::new();
        let (claimed_tx, claimed_rx) = mpsc::sync_channel(1);
        let release = Arc::new(Barrier::new(2));
        let gate = Arc::new(ClaimGate {
            controller: controller.clone(),
            claimed_tx,
            release: release.clone(),
        });
        let worker_gate = gate.clone();
        let counters = Arc::new(LayerCounters::default());
        let worker_counters = counters.clone();
        let worker =
            thread::spawn(move || run_counted_call(false, worker_gate.as_ref(), worker_counters));
        claimed_rx.recv().unwrap();
        assert_eq!(controller.cancel(), super::CancelDisposition::Cancelled);
        release.wait();
        assert_eq!(worker.join().unwrap(), Ok("cancelled"));
        assert_eq!(counters.snapshot(), [0, 0, 0, 0, 0]);
    }

    #[test]
    fn cancel_and_begin_race_is_atomic_without_sleep() {
        let controller = CancellationController::new();
        let start = Arc::new(Barrier::new(3));
        let begin_controller = controller.clone();
        let begin_start = start.clone();
        let begin_worker = thread::spawn(move || {
            begin_start.wait();
            begin_controller.begin()
        });
        let cancel_controller = controller.clone();
        let cancel_start = start.clone();
        let cancel_worker = thread::spawn(move || {
            cancel_start.wait();
            cancel_controller.cancel()
        });
        start.wait();
        let begin = begin_worker.join().unwrap();
        assert_eq!(
            cancel_worker.join().unwrap(),
            super::CancelDisposition::Cancelled
        );
        match begin {
            Ok(mut lease) => {
                assert_eq!(controller.finish(&mut lease), PublishDisposition::Cancelled)
            }
            Err(super::BeginDisposition::Cancelled) => {}
            Err(other) => panic!("unexpected begin result: {other:?}"),
        }
        assert!(matches!(
            controller.begin(),
            Err(super::BeginDisposition::Cancelled)
        ));
    }

    #[test]
    fn lease_is_controller_bound_single_use_and_abandons_on_panic() {
        let owner = CancellationController::new();
        let intruder = CancellationController::new();
        let mut lease = owner.begin().unwrap();
        assert_eq!(
            intruder.finish(&mut lease),
            PublishDisposition::InvalidLease
        );
        assert_eq!(owner.finish(&mut lease), PublishDisposition::Published);
        assert_eq!(
            owner.finish(&mut lease),
            PublishDisposition::AlreadyPublished
        );

        struct PanicTransport(Arc<LayerCounters>);
        impl ApprovedHttpTransport for PanicTransport {
            fn get_models(
                &mut self,
                _: &ApprovedHttpTarget,
                authorization: &mut [u8],
                _: &dyn CancellationProbe,
            ) -> Result<TransportResponse, TransportErrorCode> {
                assert_eq!(authorization, secret_canary());
                self.0.transport.fetch_add(1, AtomicOrdering::SeqCst);
                panic!("synthetic transport panic")
            }
        }

        let counters = Arc::new(LayerCounters::default());
        let controller = CancellationController::new();
        let (repository, store, input) = fixture_with_counters(Some(counters.clone()));
        let resolver = CountingResolver(counters.clone());
        let parser = CountingParser(counters.clone());
        let mut transport = PanicTransport(counters.clone());
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut service = SafeModelDiscoveryService::new(
                &repository,
                &store,
                &resolver,
                &parser,
                &mut transport,
            );
            let _ = service.discover_models(&input, &controller);
        }));
        assert!(result.is_err());
        assert_eq!(counters.snapshot(), [1, 1, 1, 1, 1]);
        assert_eq!(
            run_counted_call(false, &controller, counters.clone()),
            Err(DiscoveryErrorCode::Internal)
        );
        assert_eq!(counters.snapshot(), [1, 1, 1, 1, 1]);
        assert_eq!(controller.cancel(), super::CancelDisposition::TooLate);
    }

    struct PublishBarrierGate {
        controller: CancellationController,
        barrier: Arc<Barrier>,
    }

    struct ClaimGate {
        controller: CancellationController,
        claimed_tx: mpsc::SyncSender<()>,
        release: Arc<Barrier>,
    }

    impl CancellationProbe for ClaimGate {
        fn is_cancelled(&self) -> bool {
            self.controller.is_cancelled()
        }
    }

    impl super::operation_control_sealed::Sealed for ClaimGate {}

    impl super::OperationControl for ClaimGate {
        fn begin(&self) -> Result<super::OperationLease, super::BeginDisposition> {
            let result = self.controller.begin();
            if result.is_ok() {
                self.claimed_tx.send(()).unwrap();
                self.release.wait();
            }
            result
        }

        fn cancel(&self) -> super::CancelDisposition {
            self.controller.cancel()
        }

        fn finish(&self, lease: &mut super::OperationLease) -> PublishDisposition {
            self.controller.finish(lease)
        }
    }

    impl CancellationProbe for PublishBarrierGate {
        fn is_cancelled(&self) -> bool {
            self.controller.is_cancelled()
        }
    }

    impl super::operation_control_sealed::Sealed for PublishBarrierGate {}

    impl super::OperationControl for PublishBarrierGate {
        fn begin(&self) -> Result<super::OperationLease, super::BeginDisposition> {
            self.controller.begin()
        }

        fn cancel(&self) -> super::CancelDisposition {
            self.controller.cancel()
        }

        fn finish(&self, lease: &mut super::OperationLease) -> PublishDisposition {
            self.barrier.wait();
            self.barrier.wait();
            self.controller.finish(lease)
        }
    }

    fn probe_from(input: &DiscoverModelsInput) -> super::ProbeConnectionInput {
        super::ProbeConnectionInput {
            service_version: input.service_version,
            identity_id: input.identity_id.clone(),
            credential_ref_id: input.credential_ref_id.clone(),
            expected_identity_version: input.expected_identity_version,
            endpoint_policy: input.endpoint_policy,
            operation_id: "barrier_probe".to_owned(),
        }
    }

    #[test]
    fn probe_barriers_linearize_transport_return_parse_and_publish() {
        let transport_barrier = Arc::new(Barrier::new(2));
        let worker_barrier = transport_barrier.clone();
        let transport_cancel = CancellationController::new();
        let worker_cancel = transport_cancel.clone();
        let transport_worker = thread::spawn(move || {
            let (repository, store, input) = fixture();
            let probe = probe_from(&input);
            let mut transport = FakeTransport {
                calls: Cell::new(0),
                rotate: None,
                cancel_on_return: None,
                return_barrier: Some(worker_barrier),
                ..FakeTransport::successful()
            };
            let mut service = SafeModelDiscoveryService::new(
                &repository,
                &store,
                &FakeResolver,
                &FakeParser,
                &mut transport,
            );
            service.probe_connection(&probe, &worker_cancel)
        });
        transport_barrier.wait();
        assert_eq!(
            transport_cancel.cancel(),
            super::CancelDisposition::Cancelled
        );
        transport_barrier.wait();
        assert_eq!(
            transport_worker.join().unwrap(),
            Ok(super::ProbeConnectionOutcome::Cancelled)
        );

        let publish_barrier = Arc::new(Barrier::new(2));
        let publish_gate = Arc::new(PublishBarrierGate {
            controller: CancellationController::new(),
            barrier: publish_barrier.clone(),
        });
        let worker_gate = publish_gate.clone();
        let publish_worker = thread::spawn(move || {
            let (repository, store, input) = fixture();
            let probe = probe_from(&input);
            let mut transport = FakeTransport {
                calls: Cell::new(0),
                rotate: None,
                cancel_on_return: None,
                return_barrier: None,
                ..FakeTransport::successful()
            };
            let mut service = SafeModelDiscoveryService::new(
                &repository,
                &store,
                &FakeResolver,
                &FakeParser,
                &mut transport,
            );
            service.probe_connection(&probe, worker_gate.as_ref())
        });
        publish_barrier.wait();
        assert_eq!(
            publish_gate.controller.cancel(),
            super::CancelDisposition::Cancelled
        );
        publish_barrier.wait();
        assert_eq!(
            publish_worker.join().unwrap(),
            Ok(super::ProbeConnectionOutcome::Cancelled)
        );
    }
}
