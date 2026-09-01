use std::{collections::BTreeMap, fmt, sync::Arc, time::Duration};

use aep_core::{
    AssertionOperation, AuthenticationMethod, BuiltInGrantResponse, ClaimValues,
    ClientAssertionClaims, Command, GrantType, HttpTransport, IdentityMethod, InspectDocument,
    ProtectedResourceAuthorization, SigningAlgorithm,
};
use async_trait::async_trait;
use http::HeaderMap;
use serde_json::Value;
use time::OffsetDateTime;
use url::Url;

use crate::AgentError;

#[derive(Clone, Debug, PartialEq)]
pub struct AgentIdentity {
    pub agent_did: String,
    pub identity_method: IdentityMethod,
    pub service_did: String,
    pub signing_algorithms: Vec<SigningAlgorithm>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct IdentityRequest {
    pub inspection: Inspection,
}

#[async_trait]
pub trait AssertionSigner: Send + Sync {
    async fn sign(
        &self,
        claims: &ClientAssertionClaims,
        algorithms: &[SigningAlgorithm],
    ) -> Result<String, AgentError>;
}

#[async_trait]
pub trait IdentityProvider: Send + Sync {
    async fn get_or_create_identity(
        &self,
        request: IdentityRequest,
    ) -> Result<AgentIdentity, AgentError>;
    async fn signer_for(
        &self,
        identity: &AgentIdentity,
    ) -> Result<Arc<dyn AssertionSigner>, AgentError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationKey {
    pub command: Command,
    pub credential_id: Option<String>,
    pub grant_type: Option<GrantType>,
    pub service_did: String,
    pub service_url: Url,
}

#[async_trait]
pub trait IdempotencyKeyProvider: Send + Sync {
    async fn create_key(&self, operation: &OperationKey) -> Result<String, AgentError>;
}

pub trait Clock: Send + Sync {
    fn now(&self) -> OffsetDateTime;
}

#[async_trait]
pub trait Delay: Send + Sync {
    async fn sleep(&self, duration: Duration);
}

#[derive(Clone, PartialEq)]
pub struct CredentialRecord {
    pub credential_id: String,
    pub expires_at: OffsetDateTime,
    pub grant_type: GrantType,
    pub issued_at: OffsetDateTime,
    pub payload: Value,
    pub service_did: String,
    pub service_url: Url,
}

impl fmt::Debug for CredentialRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialRecord")
            .field("credential_id", &self.credential_id)
            .field("expires_at", &self.expires_at)
            .field("grant_type", &self.grant_type)
            .field("issued_at", &self.issued_at)
            .field("payload", &"[REDACTED]")
            .field("service_did", &self.service_did)
            .field("service_url", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Inspection {
    pub cache_control: Option<String>,
    pub document: InspectDocument,
    pub etag: Option<String>,
    pub final_url: Url,
    pub inspect_url: Url,
    pub last_modified: Option<String>,
    pub service_url: Url,
}

impl Inspection {
    pub fn command_url(&self, command: &Command) -> Result<Url, AgentError> {
        let path = aep_core::command_path_from_inspect(&self.document, command)?;
        Ok(self.service_url.join(&path)?)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct InspectCacheEntry {
    pub cache_control: Option<String>,
    pub cached_at: OffsetDateTime,
    pub document: InspectDocument,
    pub etag: Option<String>,
    pub final_url: Url,
    pub last_modified: Option<String>,
}

#[async_trait]
pub trait IdentityStore: Send + Sync {
    async fn find(&self, service_did: &str) -> Result<Option<AgentIdentity>, AgentError>;
    async fn save(&self, identity: AgentIdentity) -> Result<(), AgentError>;
}

#[async_trait]
pub trait CredentialStore: Send + Sync {
    async fn delete(&self, service_did: &str, credential_id: &str) -> Result<(), AgentError>;
    async fn find(
        &self,
        service_did: &str,
        credential_id: &str,
    ) -> Result<Option<CredentialRecord>, AgentError>;
    async fn list(&self, service_did: &str) -> Result<Vec<CredentialRecord>, AgentError>;
    async fn save(&self, credential: CredentialRecord) -> Result<(), AgentError>;
}

#[async_trait]
pub trait InspectCache: Send + Sync {
    async fn delete(&self, inspect_url: &Url) -> Result<(), AgentError>;
    async fn find(&self, inspect_url: &Url) -> Result<Option<InspectCacheEntry>, AgentError>;
    async fn save(&self, inspect_url: &Url, entry: InspectCacheEntry) -> Result<(), AgentError>;
}

#[derive(Clone)]
pub struct ClientOptions {
    pub allow_insecure_loopback: bool,
    pub assertion_lifetime: Duration,
    pub clock: Option<Arc<dyn Clock>>,
    pub command_transport: Option<Arc<dyn HttpTransport>>,
    pub credential_store: Option<Arc<dyn CredentialStore>>,
    pub delay: Option<Arc<dyn Delay>>,
    pub identity_provider: Arc<dyn IdentityProvider>,
    pub identity_store: Option<Arc<dyn IdentityStore>>,
    pub idempotency_keys: Option<Arc<dyn IdempotencyKeyProvider>>,
    pub inspect_cache: Option<Arc<dyn InspectCache>>,
    pub inspect_transport: Option<Arc<dyn HttpTransport>>,
    pub maximum_response_bytes: usize,
    pub request_timeout: Duration,
}

impl ClientOptions {
    pub fn new(identity_provider: Arc<dyn IdentityProvider>) -> Self {
        Self {
            allow_insecure_loopback: false,
            assertion_lifetime: aep_core::MAX_ASSERTION_LIFETIME,
            clock: None,
            command_transport: None,
            credential_store: None,
            delay: None,
            identity_provider,
            identity_store: None,
            idempotency_keys: None,
            inspect_cache: None,
            inspect_transport: None,
            maximum_response_bytes: 1 << 20,
            request_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CommandResult<T> {
    pub body: T,
    pub status: u16,
    pub url: Url,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct EnrollOptions {
    pub claims: Option<ClaimValues>,
    pub idempotency_key: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GrantOptions {
    pub grant_type: Option<GrantType>,
    pub idempotency_key: Option<String>,
    pub preferred_grant_types: Vec<GrantType>,
    pub requested_scopes: Vec<String>,
}

#[derive(Clone, PartialEq)]
pub struct GrantResult {
    pub credential: Option<BuiltInGrantResponse>,
    pub grant_type: GrantType,
    pub raw: Value,
}

impl fmt::Debug for GrantResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GrantResult")
            .field("credential", &self.credential)
            .field("grant_type", &self.grant_type)
            .field("raw", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RevokeOptions {
    pub all_grant_types: bool,
    pub credential_id: Option<String>,
    pub grant_type: Option<GrantType>,
    pub idempotency_key: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitOptions {
    pub interval: Duration,
    pub timeout: Duration,
}

impl Default for WaitOptions {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(1),
            timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Clone, PartialEq)]
pub struct AuthenticationOptions {
    pub carrier: aep_core::AuthorizationCarrier,
    pub client_assertion_only: bool,
    pub credential_id: Option<String>,
    pub grant_type: Option<GrantType>,
    pub resource: Url,
}

impl fmt::Debug for AuthenticationOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticationOptions")
            .field("carrier", &self.carrier)
            .field("client_assertion_only", &self.client_assertion_only)
            .field("credential_id", &self.credential_id)
            .field("grant_type", &self.grant_type)
            .field("resource", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub struct AuthenticationResult {
    pub headers: HeaderMap,
    pub method: AuthenticationMethod,
}

impl fmt::Debug for AuthenticationResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticationResult")
            .field("headers", &"[REDACTED]")
            .field("method", &self.method)
            .finish()
    }
}

pub(crate) fn assertion_operation(command: &Command) -> Option<AssertionOperation> {
    match command {
        Command::Enroll => Some(AssertionOperation::Enroll),
        Command::Grant => Some(AssertionOperation::Grant),
        Command::Revoke => Some(AssertionOperation::Revoke),
        Command::Status => Some(AssertionOperation::Status),
        Command::Inspect | Command::Other(_) => None,
    }
}

pub(crate) fn authorization(
    carrier: aep_core::AuthorizationCarrier,
    scheme: aep_core::CredentialScheme,
    credentials: String,
) -> ProtectedResourceAuthorization {
    ProtectedResourceAuthorization {
        carrier,
        scheme,
        credentials,
    }
}
