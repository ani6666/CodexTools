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

#[derive(Clone, Debug)]
pub struct CancellationController {
    state: Arc<AtomicU8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancelDisposition {
    Cancelled,
    AlreadyCancelled,
    TooLate,
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
            state: Arc::new(AtomicU8::new(0)),
        }
    }

    pub fn cancel(&self) -> CancelDisposition {
        match self
            .state
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => CancelDisposition::Cancelled,
            Err(1) => CancelDisposition::AlreadyCancelled,
            Err(_) => CancelDisposition::TooLate,
        }
    }

    pub fn complete(&self) {
        let _ = self
            .state
            .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire);
    }
}

impl CancellationProbe for CancellationController {
    fn is_cancelled(&self) -> bool {
        self.state.load(Ordering::Acquire) == 1
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
        cancellation: &dyn CancellationProbe,
    ) -> Result<ProbeConnectionOutcome, DiscoveryErrorCode> {
        let response = match self.execute(
            input.service_version,
            &input.identity_id,
            &input.credential_ref_id,
            input.expected_identity_version,
            input.endpoint_policy,
            &input.operation_id,
            cancellation,
        )? {
            Some(response) => response,
            None => return Ok(ProbeConnectionOutcome::Cancelled),
        };
        validate_status(response.status())?;
        let _ = parse_models(
            response.body(),
            self.limits.maximum_model_count,
            self.limits.maximum_json_depth,
        )?;
        Ok(ProbeConnectionOutcome::Reachable(ReachableSummary {
            api_compatible: true,
        }))
    }

    pub fn discover_models(
        &mut self,
        input: &DiscoverModelsInput,
        cancellation: &dyn CancellationProbe,
    ) -> Result<DiscoverModelsOutcome, DiscoveryErrorCode> {
        let response = match self.execute(
            input.service_version,
            &input.identity_id,
            &input.credential_ref_id,
            input.expected_identity_version,
            input.endpoint_policy,
            &input.operation_id,
            cancellation,
        )? {
            Some(response) => response,
            None => return Ok(DiscoverModelsOutcome::Cancelled),
        };
        validate_status(response.status())?;
        if cancellation.is_cancelled() {
            return Ok(DiscoverModelsOutcome::Cancelled);
        }
        let models = parse_models(
            response.body(),
            self.limits.maximum_model_count,
            self.limits.maximum_json_depth,
        )?;
        if cancellation.is_cancelled() {
            return Ok(DiscoverModelsOutcome::Cancelled);
        }
        Ok(DiscoverModelsOutcome::Models(models))
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
    ) -> Result<Option<TransportResponse>, DiscoveryErrorCode> {
        if service_version != M28_SERVICE_VERSION || !valid_operation_id(operation_id) {
            return Err(DiscoveryErrorCode::Validation);
        }
        if cancellation.is_cancelled() {
            return Ok(None);
        }
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
            match self
                .resolver
                .resolve(endpoint.host(), endpoint.port(), deadline, cancellation)
            {
                Ok(addresses) => addresses,
                Err(ResolverErrorCode::Cancelled) => return Ok(None),
                Err(error) => return Err(map_resolver_error(error)),
            }
        };
        if cancellation.is_cancelled() {
            return Ok(None);
        }
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
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let response = match self
            .transport
            .get_models(&target, &mut authorization, cancellation)
        {
            Ok(response) => response,
            Err(TransportErrorCode::Cancelled) => return Ok(None),
            Err(error) => return Err(map_transport_error(error)),
        };
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
        Ok(Some(response))
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
        ApprovedHttpTarget, CancelDisposition, CancellationController, DiscoveryErrorCode,
        NetworkLimits, parse_models, validate_status,
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
        completed.complete();
        assert_eq!(completed.cancel(), CancelDisposition::TooLate);
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
        CancellationProbe, CredentialAuthorizationParser, DiscoverModelsInput,
        DiscoverModelsOutcome, DiscoveryErrorCode, DnsResolver, NeverCancelled, ResolverErrorCode,
        SafeModelDiscoveryService, TransportErrorCode, TransportResponse,
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
        time::Instant,
    };

    struct FakeRepository {
        identity: RuntimeIdentity,
        credential: RefCell<CredentialReference>,
    }
    impl RuntimeIdentityRepository for FakeRepository {
        fn create_runtime_identity(&mut self, _: &RuntimeIdentity) -> Result<(), RepositoryError> {
            Err(RepositoryError::storage_unavailable())
        }
        fn get_runtime_identity(
            &self,
            id: &IdentityId,
        ) -> Result<Option<RuntimeIdentity>, RepositoryError> {
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
    struct FakeStore(Vec<u8>);
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
            consumer.consume(&self.0)
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
    struct FakeTransport<'a> {
        calls: Cell<usize>,
        rotate: Option<&'a FakeRepository>,
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
            Ok(TransportResponse::new(
                200,
                br#"{"data":[{"id":"model-b"},{"id":"model-a"}]}"#.to_vec(),
            ))
        }
    }
    fn fixture() -> (FakeRepository, FakeStore, DiscoverModelsInput) {
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
            },
            FakeStore(secret_canary()),
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
        };
        let mut service = SafeModelDiscoveryService::new(
            &repository,
            &store,
            &FakeResolver,
            &FakeParser,
            &mut transport,
        );
        let outcome = service.discover_models(&input, &NeverCancelled).unwrap();
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
        };
        let mut service = SafeModelDiscoveryService::new(
            &repository,
            &store,
            &FakeResolver,
            &FakeParser,
            &mut transport,
        );
        assert_eq!(
            service.discover_models(&input, &NeverCancelled),
            Err(DiscoveryErrorCode::Conflict)
        );
        assert_eq!(transport.calls.get(), 0);
        input.expected_identity_version = EntityVersion::initial();
        let mut rotating = FakeTransport {
            calls: Cell::new(0),
            rotate: Some(&repository),
        };
        let mut service = SafeModelDiscoveryService::new(
            &repository,
            &store,
            &FakeResolver,
            &FakeParser,
            &mut rotating,
        );
        assert_eq!(
            service.discover_models(&input, &NeverCancelled),
            Err(DiscoveryErrorCode::Conflict)
        );
        assert_eq!(rotating.calls.get(), 1);
    }
}
