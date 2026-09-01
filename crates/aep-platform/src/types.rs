use std::{collections::BTreeMap, sync::Arc, time::Duration};

use aep_core::{
    AssertionOperation, ClientAssertionClaims, ClientAssertionVerifyingKey, ErrorCode,
    ProblemDetails, SigningAlgorithm,
};
use async_trait::async_trait;
use futures::future::BoxFuture;
use http::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use crate::PlatformError;

pub const DID_MEDIA_TYPE: &str = "application/did+json";
pub const HOSTED_IDENTITY_DRAFT: &str = "draft-kavian-aep-platform-hosted-identity-01";
pub const WELL_KNOWN_PATH: &str = "/.well-known/aep-platform";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ManagedAgentStatus {
    Active,
    Revoked,
    Suspended,
    Terminated,
}

impl ManagedAgentStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Suspended => "suspended",
            Self::Terminated => "terminated",
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DiscoveryDocument {
    pub aep_version: String,
    pub endpoints: DiscoveryEndpoints,
    pub http: DiscoveryHttp,
    pub identity: DiscoveryIdentity,
    pub platform: DiscoveryPlatform,
    pub signing: DiscoverySigning,
    #[serde(flatten)]
    pub additional: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DiscoveryEndpoints {
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub hosted_verification: Option<String>,
    pub lifecycle: String,
    pub list: String,
    pub provision: String,
    pub sign: String,
    #[serde(flatten)]
    pub additional: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DiscoveryHttp {
    pub endpoint_base: String,
    #[serde(flatten)]
    pub additional: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DiscoveryIdentity {
    pub did_methods: Vec<String>,
    pub did_url_template: String,
    #[serde(flatten)]
    pub additional: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DiscoveryPlatform {
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub did: Option<String>,
    pub hosted_verification: bool,
    pub name: String,
    #[serde(flatten)]
    pub additional: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DiscoverySigning {
    pub algorithms: Vec<SigningAlgorithm>,
    pub default_lifetime_seconds: String,
    #[serde(flatten)]
    pub additional: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AgentIdentity {
    pub agent_did: String,
    pub agent_identity_id: String,
    pub created_at: String,
    pub did_document_url: String,
    pub key_id: String,
    pub service_did: String,
    pub signing_algorithms: Vec<SigningAlgorithm>,
    pub status: ManagedAgentStatus,
    pub updated_at: String,
    #[serde(flatten)]
    pub additional: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AgentIdentityListResponse {
    pub count: String,
    pub data: Vec<AgentIdentity>,
    pub total: String,
    #[serde(flatten)]
    pub additional: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisionRequest {
    pub service_did: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleRequest {
    pub status: ManagedAgentStatus,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SignStatus {
    Completed,
    Pending,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignRequest {
    pub jti: String,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub lifetime_seconds: Option<String>,
    pub op: AssertionOperation,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub platform_context: BTreeMap<String, Value>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub resource: Option<String>,
    pub service_did: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SignResponse {
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub agent_did: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub client_assertion: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub expires_at: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub issued_at: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub platform_context: BTreeMap<String, Value>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub retry_after_seconds: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub service_did: Option<String>,
    pub status: SignStatus,
    #[serde(flatten)]
    pub additional: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationRequest {
    pub client_assertion: String,
    pub op: AssertionOperation,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub resource: Option<String>,
    pub service_did: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct VerificationResponse {
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub agent_did: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub agent_identity_id: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub op: Option<AssertionOperation>,
    pub reason: String,
    pub service_did: String,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    pub status: Option<ManagedAgentStatus>,
    pub verified: bool,
    #[serde(flatten)]
    pub additional: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DidVerificationMethod {
    pub controller: String,
    pub id: String,
    #[serde(rename = "publicKeyJwk")]
    pub public_key_jwk: Value,
    #[serde(rename = "type")]
    pub method_type: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "assertionMethod")]
    pub assertion_method: Vec<String>,
    pub authentication: Vec<String>,
    #[serde(rename = "capabilityInvocation")]
    pub capability_invocation: Vec<String>,
    pub id: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<DidVerificationMethod>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ResponseBody<T> {
    Success(T),
    Problem(Box<ProblemDetails>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct PlatformResponse<T> {
    pub body: ResponseBody<T>,
    pub headers: HeaderMap,
    pub status: u16,
}

impl<T: Serialize> PlatformResponse<T> {
    pub fn to_json(&self) -> Result<Value, serde_json::Error> {
        match &self.body {
            ResponseBody::Success(value) => serde_json::to_value(value),
            ResponseBody::Problem(value) => serde_json::to_value(value),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RequestContext {
    pub authorization: Option<String>,
    pub idempotency_key: Option<String>,
    pub now: Option<OffsetDateTime>,
    pub principal: String,
    pub request_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct IdentityRecord {
    pub agent_did: String,
    pub agent_did_id: String,
    pub agent_identity_id: String,
    pub created_at: OffsetDateTime,
    pub did_document_url: String,
    pub key_id: String,
    pub principal: String,
    pub service_did: String,
    pub signing_algorithms: Vec<SigningAlgorithm>,
    pub status: ManagedAgentStatus,
    pub updated_at: OffsetDateTime,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IdentityListQuery {
    pub descending: bool,
    pub limit: usize,
    pub offset: usize,
    pub service_did: Option<String>,
    pub status: Option<ManagedAgentStatus>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct IdentityListResult {
    pub identities: Vec<IdentityRecord>,
    pub total: usize,
}

pub type IdentityCreation =
    Box<dyn FnOnce() -> BoxFuture<'static, Result<IdentityRecord, PlatformError>> + Send>;

#[async_trait]
pub trait IdentityStore: Send + Sync {
    async fn find_or_create(
        &self,
        principal: &str,
        service_did: &str,
        create: IdentityCreation,
    ) -> Result<IdentityRecord, PlatformError>;
    async fn find_by_agent_did(
        &self,
        agent_did: &str,
    ) -> Result<Option<IdentityRecord>, PlatformError>;
    async fn find_by_agent_did_id(
        &self,
        agent_did_id: &str,
    ) -> Result<Option<IdentityRecord>, PlatformError>;
    async fn get(&self, agent_identity_id: &str) -> Result<Option<IdentityRecord>, PlatformError>;
    async fn list(
        &self,
        principal: &str,
        query: &IdentityListQuery,
    ) -> Result<IdentityListResult, PlatformError>;
    async fn update_status(
        &self,
        agent_identity_id: &str,
        status: ManagedAgentStatus,
        updated_at: OffsetDateTime,
    ) -> Result<Option<IdentityRecord>, PlatformError>;
}

#[async_trait]
pub trait KeyStore: Send + Sync {
    async fn create_key(&self, identity: &IdentityRecord) -> Result<(), PlatformError>;
    async fn did_verification_method(
        &self,
        identity: &IdentityRecord,
    ) -> Result<DidVerificationMethod, PlatformError>;
    async fn sign(
        &self,
        identity: &IdentityRecord,
        claims: &ClientAssertionClaims,
    ) -> Result<String, PlatformError>;
    async fn verification_key(
        &self,
        identity: &IdentityRecord,
    ) -> Result<ClientAssertionVerifyingKey, PlatformError>;
}

#[async_trait]
pub trait ServiceDidResolver: Send + Sync {
    async fn resolve(&self, service_did: &str) -> Result<bool, PlatformError>;
}

#[derive(Clone, Debug, PartialEq)]
pub enum AuthorizationRequest {
    GetIdentity {
        identity: IdentityRecord,
    },
    ListIdentities {
        query: IdentityListQuery,
    },
    Provision {
        request: ProvisionRequest,
    },
    Sign {
        identity: IdentityRecord,
        request: SignRequest,
    },
    UpdateIdentity {
        identity: IdentityRecord,
        request: LifecycleRequest,
    },
    Verify {
        identity: IdentityRecord,
        request: VerificationRequest,
    },
}

#[async_trait]
pub trait Authorizer: Send + Sync {
    async fn authorize(
        &self,
        request: &AuthorizationRequest,
        context: &RequestContext,
    ) -> Result<bool, PlatformError>;
}

#[async_trait]
pub trait LifecyclePolicy: Send + Sync {
    async fn can_sign(
        &self,
        identity: &IdentityRecord,
        context: &RequestContext,
    ) -> Result<bool, PlatformError>;
    async fn can_transition(
        &self,
        identity: &IdentityRecord,
        status: ManagedAgentStatus,
        context: &RequestContext,
    ) -> Result<bool, PlatformError>;
    async fn can_verify(
        &self,
        identity: &IdentityRecord,
        context: &RequestContext,
    ) -> Result<bool, PlatformError>;
}

#[async_trait]
pub trait ReplayStore: Send + Sync {
    async fn consume(
        &self,
        key: &str,
        expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<bool, PlatformError>;
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum IdempotentOperation {
    HostedVerification,
    Provision,
    Sign,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdempotencyInput {
    pub idempotency_key: String,
    pub operation: IdempotentOperation,
    pub principal: String,
    pub request_hash: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct StoredResponse {
    pub body: Vec<u8>,
    pub content_type: String,
    pub created_at: OffsetDateTime,
    pub headers: HeaderMap,
    pub status: u16,
}

#[derive(Clone, Debug, PartialEq)]
pub enum IdempotencyResult {
    Created(StoredResponse),
    Replayed(StoredResponse),
    Conflict,
}

pub type IdempotencyOperation =
    Box<dyn FnOnce() -> BoxFuture<'static, Result<StoredResponse, PlatformError>> + Send>;

#[async_trait]
pub trait IdempotencyStore: Send + Sync {
    async fn execute(
        &self,
        input: IdempotencyInput,
        operation: IdempotencyOperation,
    ) -> Result<IdempotencyResult, PlatformError>;
}

#[async_trait]
pub trait SignHandler: Send + Sync {
    async fn sign(
        &self,
        identity: &IdentityRecord,
        request: &SignRequest,
        context: &RequestContext,
    ) -> Result<Option<PlatformResponse<SignResponse>>, PlatformError>;
}

pub trait Clock: Send + Sync {
    fn now(&self) -> OffsetDateTime;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DiscoveryOptions {
    pub endpoint_base: String,
    pub hosted_verification_endpoint: Option<String>,
    pub lifecycle_endpoint: String,
    pub list_endpoint: String,
    pub platform_did: Option<String>,
    pub platform_name: String,
    pub provision_endpoint: String,
    pub sign_endpoint: String,
}

#[derive(Clone)]
pub struct PlatformOptions {
    pub agent_did_id_generator:
        Option<Arc<dyn Fn() -> Result<String, PlatformError> + Send + Sync>>,
    pub authorizer: Arc<dyn Authorizer>,
    pub clock: Option<Arc<dyn Clock>>,
    pub default_lifetime: Duration,
    pub did_host: String,
    pub did_path_prefix: String,
    pub did_url_template: String,
    pub discovery: DiscoveryOptions,
    pub hosted_verification: bool,
    pub identifier: Option<Arc<dyn Fn() -> Result<String, PlatformError> + Send + Sync>>,
    pub idempotency_store: Option<Arc<dyn IdempotencyStore>>,
    pub identity_store: Option<Arc<dyn IdentityStore>>,
    pub key_store: Arc<dyn KeyStore>,
    pub lifecycle_policy: Option<Arc<dyn LifecyclePolicy>>,
    pub maximum_lifetime: Duration,
    pub replay_store: Option<Arc<dyn ReplayStore>>,
    pub service_did_resolver: Arc<dyn ServiceDidResolver>,
    pub sign_handler: Option<Arc<dyn SignHandler>>,
    pub signing_algorithms: Vec<SigningAlgorithm>,
}

impl PlatformOptions {
    pub fn new(
        authorizer: Arc<dyn Authorizer>,
        key_store: Arc<dyn KeyStore>,
        service_did_resolver: Arc<dyn ServiceDidResolver>,
        did_host: impl Into<String>,
        did_url_template: impl Into<String>,
    ) -> Self {
        Self {
            agent_did_id_generator: None,
            authorizer,
            clock: None,
            default_lifetime: aep_core::MAX_ASSERTION_LIFETIME,
            did_host: did_host.into(),
            did_path_prefix: "agents".to_owned(),
            did_url_template: did_url_template.into(),
            discovery: DiscoveryOptions::default(),
            hosted_verification: false,
            identifier: None,
            idempotency_store: None,
            identity_store: None,
            key_store,
            lifecycle_policy: None,
            maximum_lifetime: aep_core::MAX_ASSERTION_LIFETIME,
            replay_store: None,
            service_did_resolver,
            sign_handler: None,
            signing_algorithms: vec![SigningAlgorithm::EdDsa, SigningAlgorithm::Es256],
        }
    }
}

pub(crate) fn lifecycle_error_code(status: ManagedAgentStatus) -> ErrorCode {
    match status {
        ManagedAgentStatus::Terminated => ErrorCode::IdentityTerminated,
        ManagedAgentStatus::Revoked | ManagedAgentStatus::Suspended => ErrorCode::IdentitySuspended,
        ManagedAgentStatus::Active => ErrorCode::IdentityUnavailable,
    }
}

fn deserialize_optional_non_null<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}
