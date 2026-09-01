use std::{collections::BTreeMap, sync::Arc, time::Duration};

use aep_core::{
    AgentStatus, AssertionOperation, AuthenticationMethod, ClaimName, ClaimValues,
    ClientAssertionClaims, EnrollRequest, EnrollmentDecisionStatus, ErrorCode, GrantRequest,
    GrantType, GrantTypeConfig, IdentityMethod, InspectDocument, ProblemDetails, RevokeRequest,
    SigningAlgorithm,
};
use async_trait::async_trait;
use http::HeaderMap;
use serde_json::Value;
use time::OffsetDateTime;
use url::Url;

use crate::ServiceError;

#[derive(Clone, Debug, PartialEq)]
pub enum ResponseBody {
    Enroll(aep_core::EnrollResponse),
    Grant(Value),
    Problem(ProblemDetails),
    Revoke(aep_core::RevokeResponse),
    Status(aep_core::StatusResponse),
}

impl ResponseBody {
    pub const fn content_type(&self) -> &'static str {
        match self {
            Self::Problem(_) => aep_core::PROBLEM_MEDIA_TYPE,
            Self::Enroll(_) | Self::Grant(_) | Self::Revoke(_) | Self::Status(_) => {
                aep_core::MEDIA_TYPE
            }
        }
    }

    pub fn to_json(&self) -> Result<Value, serde_json::Error> {
        match self {
            Self::Enroll(value) => serde_json::to_value(value),
            Self::Grant(value) => Ok(value.clone()),
            Self::Problem(value) => serde_json::to_value(value),
            Self::Revoke(value) => serde_json::to_value(value),
            Self::Status(value) => serde_json::to_value(value),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ServiceResponse {
    pub body: ResponseBody,
    pub headers: HeaderMap,
    pub status: u16,
}

impl ServiceResponse {
    pub fn to_json(&self) -> Result<Value, serde_json::Error> {
        self.body.to_json()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum IdempotentCommand {
    Enroll,
    Grant,
    Revoke,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandIdempotencyInput {
    pub agent_did: String,
    pub command: IdempotentCommand,
    pub idempotency_key: String,
    pub request_hash: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CommandIdempotencyRecord {
    pub input: CommandIdempotencyInput,
    pub response: ServiceResponse,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CommandIdempotencyResult {
    Created(ServiceResponse),
    Replayed(ServiceResponse),
    Conflict,
}

pub type CommandOperation = Box<
    dyn FnOnce() -> futures::future::BoxFuture<'static, Result<ServiceResponse, ServiceError>>
        + Send,
>;

#[async_trait]
pub trait CommandIdempotencyStore: Send + Sync {
    async fn execute(
        &self,
        input: CommandIdempotencyInput,
        operation: CommandOperation,
    ) -> Result<CommandIdempotencyResult, ServiceError>;
}

#[derive(Clone, Debug, PartialEq)]
pub struct EnrollmentRecord {
    pub agent_did: String,
    pub claims: ClaimValues,
    pub created_at: OffsetDateTime,
    pub owner_action_required: bool,
    pub requirements_pending: Vec<String>,
    pub since: OffsetDateTime,
    pub status: AgentStatus,
    pub updated_at: OffsetDateTime,
    pub verification_pending: Vec<String>,
}

#[async_trait]
pub trait EnrollmentStore: Send + Sync {
    async fn find(&self, agent_did: &str) -> Result<Option<EnrollmentRecord>, ServiceError>;
    async fn save(&self, record: EnrollmentRecord) -> Result<EnrollmentRecord, ServiceError>;
}

#[derive(Clone, Debug, PartialEq)]
pub struct EnrollmentDecision {
    pub owner_action_required: bool,
    pub requirements_pending: Vec<String>,
    pub status: EnrollmentDecisionStatus,
    pub verification_pending: Vec<String>,
}

impl Default for EnrollmentDecision {
    fn default() -> Self {
        Self {
            owner_action_required: false,
            requirements_pending: Vec::new(),
            status: EnrollmentDecisionStatus::Active,
            verification_pending: Vec::new(),
        }
    }
}

#[async_trait]
pub trait EnrollmentPolicy: Send + Sync {
    async fn decide(
        &self,
        request: &EnrollRequest,
        now: OffsetDateTime,
    ) -> Result<EnrollmentDecision, ServiceError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientAssertionReplayRecord {
    pub expires_at: OffsetDateTime,
    pub jti: String,
    pub sub: String,
}

#[async_trait]
pub trait ClientAssertionReplayStore: Send + Sync {
    async fn consume(
        &self,
        record: ClientAssertionReplayRecord,
        now: OffsetDateTime,
    ) -> Result<bool, ServiceError>;
}

#[derive(Clone, Debug, PartialEq)]
pub struct ClientAssertionVerificationContext {
    pub assertion: String,
    pub current_time: OffsetDateTime,
    pub idempotency_key: Option<String>,
    pub operation: AssertionOperation,
    pub resource: Option<Url>,
    pub service_did: String,
    pub signing_algorithms: Vec<SigningAlgorithm>,
}

#[async_trait]
pub trait ClientAssertionVerifier: Send + Sync {
    async fn verify(
        &self,
        context: ClientAssertionVerificationContext,
    ) -> Result<ClientAssertionClaims, ServiceError>;
}

pub struct DidWebClientAssertionVerifier {
    pub(crate) allow_insecure_loopback: bool,
    pub(crate) transport: Arc<dyn aep_core::HttpTransport>,
}

impl DidWebClientAssertionVerifier {
    pub fn new(transport: Arc<dyn aep_core::HttpTransport>, allow_insecure_loopback: bool) -> Self {
        Self {
            allow_insecure_loopback,
            transport,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct GrantContext {
    pub agent_did: String,
    pub enrollment: EnrollmentRecord,
    pub grant_type: GrantType,
}

#[derive(Clone, Debug)]
pub struct CredentialAuthenticationInput {
    pub headers: HeaderMap,
    pub now: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthenticationKind {
    ClientAssertion,
    SessionCredential,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AuthenticatedPrincipal {
    pub agent_did: String,
    pub authentication_kind: AuthenticationKind,
    pub authentication_method: AuthenticationMethod,
    pub credential_id: Option<String>,
    pub grant_type: Option<GrantType>,
    pub scopes: Vec<String>,
}

#[async_trait]
pub trait GrantTypeHandler: Send + Sync {
    async fn grant(
        &self,
        request: &GrantRequest,
        context: &GrantContext,
    ) -> Result<Value, ServiceError>;
    async fn revoke(
        &self,
        request: &RevokeRequest,
        context: &GrantContext,
    ) -> Result<(), ServiceError>;
    async fn authenticate(
        &self,
        _input: &CredentialAuthenticationInput,
    ) -> Result<Option<AuthenticatedPrincipal>, ServiceError> {
        Ok(None)
    }
    async fn has_presentation(
        &self,
        _input: &CredentialAuthenticationInput,
    ) -> Result<bool, ServiceError> {
        Ok(false)
    }
}

#[derive(Clone)]
pub struct GrantTypeDefinition {
    pub config: Option<GrantTypeConfig>,
    pub grant_type: GrantType,
    pub handler: Option<Arc<dyn GrantTypeHandler>>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ClaimsConfiguration {
    pub optional: Vec<ClaimName>,
    pub preferred: Vec<ClaimName>,
    pub required: Vec<ClaimName>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenApiConfiguration {
    pub trailing_slash: aep_core::OpenApiTrailingSlash,
    pub url: String,
}

pub trait Clock: Send + Sync {
    fn now(&self) -> OffsetDateTime;
}

#[derive(Clone)]
pub struct ServiceOptions {
    pub allow_insecure_loopback: bool,
    pub authentication_methods: Vec<AuthenticationMethod>,
    pub clock: Option<Arc<dyn Clock>>,
    pub claims: ClaimsConfiguration,
    pub endpoint_base: Option<String>,
    pub enrollment_policy: Option<Arc<dyn EnrollmentPolicy>>,
    pub enrollment_store: Option<Arc<dyn EnrollmentStore>>,
    pub extensions: Vec<String>,
    pub grant_types: Vec<GrantTypeDefinition>,
    pub identity_methods: Vec<IdentityMethod>,
    pub idempotency_store: Option<Arc<dyn CommandIdempotencyStore>>,
    pub inspect_url: Option<Url>,
    pub maximum_clock_skew: Duration,
    pub openapi: Option<OpenApiConfiguration>,
    pub replay_store: Option<Arc<dyn ClientAssertionReplayStore>>,
    pub service_did: String,
    pub signing_algorithms: Vec<SigningAlgorithm>,
    pub verifier: Arc<dyn ClientAssertionVerifier>,
}

impl ServiceOptions {
    pub fn new(service_did: impl Into<String>, verifier: Arc<dyn ClientAssertionVerifier>) -> Self {
        Self {
            allow_insecure_loopback: false,
            authentication_methods: Vec::new(),
            clock: None,
            claims: ClaimsConfiguration::default(),
            endpoint_base: None,
            enrollment_policy: None,
            enrollment_store: None,
            extensions: Vec::new(),
            grant_types: Vec::new(),
            identity_methods: vec![IdentityMethod::DidWeb],
            idempotency_store: None,
            inspect_url: None,
            maximum_clock_skew: aep_core::RECOMMENDED_CLOCK_SKEW,
            openapi: None,
            replay_store: None,
            service_did: service_did.into(),
            signing_algorithms: vec![SigningAlgorithm::EdDsa, SigningAlgorithm::Es256],
            verifier,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AuthenticatedCommandOptions {
    pub client_assertion: String,
}

#[derive(Clone, Debug)]
pub struct IdempotentCommandOptions {
    pub client_assertion: String,
    pub idempotency_key: String,
}

#[derive(Clone, Debug)]
pub struct ProtectedResourceRequest {
    pub headers: HeaderMap,
    pub method: http::Method,
    pub url: Url,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ProtectedResourceAuthentication {
    Authenticated(AuthenticatedPrincipal),
    Rejected(ServiceResponse),
}

#[derive(Clone)]
pub(crate) struct ServiceConfiguration {
    pub authentication_methods: Vec<AuthenticationMethod>,
    pub claims: ClaimsConfiguration,
    pub grant_handlers: BTreeMap<String, Arc<dyn GrantTypeHandler>>,
    pub inspect_document: InspectDocument,
    pub inspect_url: Option<Url>,
    pub maximum_clock_skew: Duration,
    pub service_did: String,
    pub signing_algorithms: Vec<SigningAlgorithm>,
}

pub(crate) fn problem(code: ErrorCode, status: u16) -> ServiceResponse {
    let title = code
        .as_str()
        .split('_')
        .map(|part| {
            let mut characters = part.chars();
            characters.next().map_or_else(String::new, |first| {
                first.to_uppercase().collect::<String>() + characters.as_str()
            })
        })
        .collect::<Vec<_>>()
        .join(" ");
    let body = ResponseBody::Problem(aep_core::new_problem_details(
        code,
        title,
        i64::from(status),
    ));
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static(body.content_type()),
    );
    ServiceResponse {
        body,
        headers,
        status,
    }
}
