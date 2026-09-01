use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
};

use aep_agent::{
    AgentError, AgentIdentity, AssertionSigner, AuthenticationOptions, Client, ClientOptions,
    CredentialRecord, CredentialStore, GrantOptions, IdentityProvider, IdentityRequest,
    IdentityStore, MemoryCredentialStore, MemoryIdentityStore, SystemClock,
};
use aep_core::{
    AgentStatus, AuthenticationMethod, AuthorizationCarrier, ClaimName, ClientAssertionClaims,
    GrantType, GrantTypeConfig, HttpRequest, HttpResponse, HttpTransport, IdentityMethod,
    SignClientAssertionOptions, SigningAlgorithm, StringBoolean, TransportError,
    sign_client_assertion,
};
use aep_service::{
    AuthenticatedCommandOptions, ClientAssertionVerificationContext, ClientAssertionVerifier,
    CredentialAuthenticationInput, EnrollmentRecord, EnrollmentStore, GrantContext,
    GrantTypeDefinition, GrantTypeHandler, IdempotentCommandOptions, MemoryEnrollmentStore,
    ProtectedResourceAuthentication, ProtectedResourceRequest, Service, ServiceError,
    ServiceOptions,
};
use async_trait::async_trait;
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;

const AGENT_DID: &str = "did:web:agent.example";
const SERVICE_DID: &str = "did:web:service.example";

pub struct ServiceFixture {
    pub service: Arc<Service>,
}

struct AssertionVerifier(String);

#[async_trait]
impl ClientAssertionVerifier for AssertionVerifier {
    async fn verify(
        &self,
        context: ClientAssertionVerificationContext,
    ) -> Result<ClientAssertionClaims, ServiceError> {
        let timestamp = context.current_time.unix_timestamp();
        Ok(ClientAssertionClaims {
            additional: BTreeMap::new(),
            aud: context.service_did,
            exp: timestamp + 60,
            iat: timestamp,
            iss: self.0.clone(),
            jti: context.assertion,
            op: context.operation,
            resource: context.resource.map(|resource| resource.to_string()),
            sub: self.0.clone(),
        })
    }
}

struct ApiKeyHandler(String);

#[async_trait]
impl GrantTypeHandler for ApiKeyHandler {
    async fn grant(
        &self,
        request: &aep_core::GrantRequest,
        _context: &GrantContext,
    ) -> Result<Value, ServiceError> {
        Ok(json!({
            "api_key": "secret",
            "credential_id": "credential-1",
            "expires_at": "2026-09-01T12:00:00Z",
            "header": "x-api-key",
            "scopes": request.requested_scopes,
        }))
    }

    async fn revoke(
        &self,
        _request: &aep_core::RevokeRequest,
        _context: &GrantContext,
    ) -> Result<(), ServiceError> {
        Ok(())
    }

    async fn authenticate(
        &self,
        input: &CredentialAuthenticationInput,
    ) -> Result<Option<aep_service::AuthenticatedPrincipal>, ServiceError> {
        if input
            .headers
            .get("x-api-key")
            .is_some_and(|value| value == "secret")
        {
            return Ok(Some(aep_service::AuthenticatedPrincipal {
                agent_did: self.0.clone(),
                authentication_kind: aep_service::AuthenticationKind::SessionCredential,
                authentication_method: AuthenticationMethod::ApiKey,
                credential_id: Some("credential-1".to_owned()),
                grant_type: Some(GrantType::ApiKey),
                scopes: vec!["resource:read".to_owned()],
            }));
        }
        Ok(None)
    }

    async fn has_presentation(
        &self,
        input: &CredentialAuthenticationInput,
    ) -> Result<bool, ServiceError> {
        Ok(
            input.headers.contains_key("x-api-key")
                || input.headers.contains_key("service-api-key"),
        )
    }
}

struct FixedServiceClock(OffsetDateTime);

impl aep_service::Clock for FixedServiceClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

pub fn service_fixture() -> Result<ServiceFixture, String> {
    let enrollment_store = Arc::new(MemoryEnrollmentStore::default());
    service_fixture_with(AGENT_DID, enrollment_store)
}

fn service_fixture_with(
    agent_did: &str,
    enrollment_store: Arc<MemoryEnrollmentStore>,
) -> Result<ServiceFixture, String> {
    let mut options = ServiceOptions::new(
        SERVICE_DID,
        Arc::new(AssertionVerifier(agent_did.to_owned())),
    );
    options.authentication_methods =
        vec![AuthenticationMethod::AepJwt, AuthenticationMethod::ApiKey];
    options.claims.required = vec![ClaimName::ContactEmail];
    options.clock = Some(Arc::new(FixedServiceClock(fixed_time()?)));
    options.enrollment_store = Some(enrollment_store.clone());
    options.grant_types = vec![GrantTypeDefinition {
        config: Some(GrantTypeConfig {
            additional: BTreeMap::new(),
            supports_per_credential_revoke: Some(StringBoolean::True),
        }),
        grant_type: GrantType::ApiKey,
        handler: Some(Arc::new(ApiKeyHandler(agent_did.to_owned()))),
    }];
    options.inspect_url = Some(
        Url::parse("https://service.example/.well-known/aep").map_err(|error| error.to_string())?,
    );
    Ok(ServiceFixture {
        service: Service::new(options).map_err(|error| error.to_string())?,
    })
}

impl ServiceFixture {
    pub async fn enroll(&self, key: &str) -> Result<aep_service::ServiceResponse, String> {
        self.service
            .enroll(
                br#"{"agent_did":"did:web:agent.example","claims":{"contact.email":"buyer@example.com"}}"#,
                idempotent("enroll", key),
            )
            .await
            .map_err(|error| error.to_string())
    }

    pub async fn grant_before_enroll(&self) -> Result<aep_service::ServiceResponse, String> {
        self.service
            .grant(
                br#"{"grant_type":"api-key"}"#,
                idempotent("grant", "grant-before-enroll"),
            )
            .await
            .map_err(|error| error.to_string())
    }

    pub async fn idempotency_conflict(&self) -> Result<aep_service::ServiceResponse, String> {
        self.enroll("same-key").await?;
        self.service
            .enroll(
                br#"{"agent_did":"did:web:agent.example","claims":{"contact.email":"different@example.com"}}"#,
                idempotent("different", "same-key"),
            )
            .await
            .map_err(|error| error.to_string())
    }

    pub async fn authenticate_api_key(
        &self,
        header_name: &str,
    ) -> Result<ProtectedResourceAuthentication, String> {
        self.enroll("authentication-enroll").await?;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::HeaderName::from_bytes(header_name.as_bytes())
                .map_err(|error| error.to_string())?,
            HeaderValue::from_static("secret"),
        );
        self.service
            .authenticate_protected_resource(ProtectedResourceRequest {
                headers,
                method: Method::GET,
                url: Url::parse("https://service.example/resource")
                    .map_err(|error| error.to_string())?,
            })
            .await
            .map_err(|error| error.to_string())
    }

    pub async fn authenticate_assertion(&self) -> Result<ProtectedResourceAuthentication, String> {
        self.enroll("assertion-enroll").await?;
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("AEP resource-assertion"),
        );
        self.service
            .authenticate_protected_resource(ProtectedResourceRequest {
                headers,
                method: Method::GET,
                url: Url::parse("https://service.example/resource")
                    .map_err(|error| error.to_string())?,
            })
            .await
            .map_err(|error| error.to_string())
    }

    pub async fn replay_status(&self) -> Result<aep_service::ServiceResponse, String> {
        self.enroll("replay-enroll").await?;
        let options = authenticated("status-replay");
        let first = self
            .service
            .status(options.clone())
            .await
            .map_err(|error| error.to_string())?;
        if first.status != 200 {
            return Err("first Status did not succeed".to_owned());
        }
        self.service
            .status(options)
            .await
            .map_err(|error| error.to_string())
    }
}

pub async fn repeated_existing(
    agent_did: &str,
    since: OffsetDateTime,
    idempotency_key: &str,
) -> Result<(aep_service::ServiceResponse, bool), String> {
    let record = EnrollmentRecord {
        agent_did: agent_did.to_owned(),
        claims: Default::default(),
        created_at: since,
        owner_action_required: false,
        requirements_pending: Vec::new(),
        since,
        status: AgentStatus::Suspended,
        updated_at: since,
        verification_pending: Vec::new(),
    };
    let store =
        Arc::new(MemoryEnrollmentStore::new([record.clone()]).map_err(|error| error.to_string())?);
    let fixture = service_fixture_with(agent_did, store.clone())?;
    let request = serde_json::to_vec(&json!({
        "agent_did": agent_did,
        "idempotency_key": idempotency_key,
    }))
    .map_err(|error| error.to_string())?;
    let response = fixture
        .service
        .enroll(&request, idempotent("repeated-enroll", idempotency_key))
        .await
        .map_err(|error| error.to_string())?;
    let unchanged = store
        .find(agent_did)
        .await
        .map_err(|error| error.to_string())?
        == Some(record);
    Ok((response, unchanged))
}

fn idempotent(assertion: &str, key: &str) -> IdempotentCommandOptions {
    IdempotentCommandOptions {
        client_assertion: assertion.to_owned(),
        idempotency_key: key.to_owned(),
    }
}

fn authenticated(assertion: &str) -> AuthenticatedCommandOptions {
    AuthenticatedCommandOptions {
        client_assertion: assertion.to_owned(),
    }
}

#[derive(Default)]
struct ScriptedTransport {
    requests: Mutex<Vec<HttpRequest>>,
    responses: Mutex<VecDeque<HttpResponse>>,
}

impl ScriptedTransport {
    fn push_response(&self, response: HttpResponse) -> Result<(), String> {
        self.responses
            .lock()
            .map_err(|_| "response lock is poisoned".to_owned())?
            .push_back(response);
        Ok(())
    }

    fn push_json(&self, status: StatusCode, body: Value) -> Result<(), String> {
        self.push_json_at(status, body, inspect_url()?)
    }

    fn push_json_at(&self, status: StatusCode, body: Value, final_url: Url) -> Result<(), String> {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(aep_core::MEDIA_TYPE),
        );
        self.push_response(HttpResponse {
            body: serde_json::to_vec(&body).map_err(|error| error.to_string())?,
            final_url,
            headers,
            status,
        })
    }

    fn request_count(&self) -> Result<usize, String> {
        self.requests
            .lock()
            .map(|requests| requests.len())
            .map_err(|_| "request lock is poisoned".to_owned())
    }

    fn requests(&self) -> Result<Vec<HttpRequest>, String> {
        self.requests
            .lock()
            .map(|requests| requests.clone())
            .map_err(|_| "request lock is poisoned".to_owned())
    }
}

#[async_trait]
impl HttpTransport for ScriptedTransport {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        self.requests
            .lock()
            .map_err(|_| TransportError::new("request lock is poisoned"))?
            .push(request);
        self.responses
            .lock()
            .map_err(|_| TransportError::new("response lock is poisoned"))?
            .pop_front()
            .ok_or_else(|| TransportError::new("no scripted response"))
    }
}

struct Identity;

#[async_trait]
impl IdentityProvider for Identity {
    async fn get_or_create_identity(
        &self,
        request: IdentityRequest,
    ) -> Result<AgentIdentity, AgentError> {
        Ok(AgentIdentity {
            agent_did: AGENT_DID.to_owned(),
            identity_method: IdentityMethod::DidWeb,
            metadata: BTreeMap::new(),
            service_did: request.inspection.document.service.did,
            signing_algorithms: vec![SigningAlgorithm::EdDsa],
        })
    }

    async fn signer_for(
        &self,
        _identity: &AgentIdentity,
    ) -> Result<Arc<dyn AssertionSigner>, AgentError> {
        Ok(Arc::new(Signer))
    }
}

struct Signer;

#[async_trait]
impl AssertionSigner for Signer {
    async fn sign(
        &self,
        claims: &ClientAssertionClaims,
        _algorithms: &[SigningAlgorithm],
    ) -> Result<String, AgentError> {
        let key = aep_core::ClientAssertionSigningKey::ed25519_from_seed([5; 32]);
        Ok(sign_client_assertion(
            claims,
            SignClientAssertionOptions {
                allow_insecure_loopback: false,
                key: &key,
                key_id: "did:web:agent.example#key-1",
            },
        )?)
    }
}

pub async fn agent_authentication(
    methods: Option<Vec<&str>>,
    grant_type: Option<GrantType>,
    resource: Url,
) -> Result<Result<aep_agent::AuthenticationResult, AgentError>, String> {
    let transport = Arc::new(ScriptedTransport::default());
    let host = resource
        .host_str()
        .ok_or_else(|| "protected resource host is missing".to_owned())?;
    let service_url = Url::parse(&format!("{}://{host}", resource.scheme()))
        .map_err(|error| error.to_string())?;
    let service_did = format!("did:web:{host}");
    let mut document = inspect_document_for(&service_did);
    if let Some(methods) = methods {
        let grant_types = methods
            .iter()
            .copied()
            .filter(|method| matches!(*method, "api-key" | "basic" | "oauth-bearer"))
            .collect::<Vec<_>>();
        document["authentication"] = json!({"methods": methods});
        document["commands"]["grant_types"] = json!(grant_types);
    }
    transport.push_json_at(
        StatusCode::OK,
        document,
        service_url
            .join(aep_core::WELL_KNOWN_PATH)
            .map_err(|error| error.to_string())?,
    )?;
    let mut options = ClientOptions::new(Arc::new(Identity));
    options.command_transport = Some(transport.clone());
    options.inspect_transport = Some(transport);
    let session = Client::new(options)
        .map_err(|error| error.to_string())?
        .service(service_url.as_str())
        .map_err(|error| error.to_string())?;
    Ok(session
        .authentication(AuthenticationOptions {
            carrier: AuthorizationCarrier::Standard,
            client_assertion_only: false,
            credential_id: None,
            grant_type,
            resource,
        })
        .await)
}

pub async fn agent_grant_before_enroll() -> Result<AgentError, String> {
    let transport = Arc::new(ScriptedTransport::default());
    let mut document = inspect_document();
    document["authentication"] = json!({"methods": ["api-key"]});
    document["commands"] = json!({
        "grant_types": ["api-key"],
        "supported": ["inspect", "grant", "status"],
    });
    transport.push_json(StatusCode::OK, document)?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(aep_core::PROBLEM_MEDIA_TYPE),
    );
    transport.push_response(HttpResponse {
        body: serde_json::to_vec(&json!({
            "code": "not_recognized",
            "status": 401,
            "title": "Not recognized",
            "type": "urn:aep:error:not_recognized",
        }))
        .map_err(|error| error.to_string())?,
        final_url: Url::parse("https://service.example/aep/status")
            .map_err(|error| error.to_string())?,
        headers,
        status: StatusCode::UNAUTHORIZED,
    })?;
    let identity_store = Arc::new(MemoryIdentityStore::default());
    identity_store
        .save(AgentIdentity {
            agent_did: AGENT_DID.to_owned(),
            identity_method: IdentityMethod::DidWeb,
            metadata: BTreeMap::new(),
            service_did: SERVICE_DID.to_owned(),
            signing_algorithms: vec![SigningAlgorithm::EdDsa],
        })
        .await
        .map_err(|error| error.to_string())?;
    let mut options = ClientOptions::new(Arc::new(Identity));
    options.command_transport = Some(transport.clone());
    options.identity_store = Some(identity_store);
    options.inspect_transport = Some(transport);
    let session = Client::new(options)
        .map_err(|error| error.to_string())?
        .service("https://service.example")
        .map_err(|error| error.to_string())?;
    match session
        .grant(GrantOptions {
            grant_type: Some(GrantType::ApiKey),
            ..Default::default()
        })
        .await
    {
        Ok(_) => Err("Grant before Enroll unexpectedly succeeded".to_owned()),
        Err(error) => Ok(error),
    }
}

pub async fn agent_api_key_header(issued_header: &str) -> Result<HeaderMap, String> {
    let transport = Arc::new(ScriptedTransport::default());
    let mut document = inspect_document();
    document["authentication"] = json!({"methods": ["api-key"]});
    document["commands"]["grant_types"] = json!(["api-key"]);
    transport.push_json(StatusCode::OK, document)?;
    let clock: Arc<dyn aep_agent::Clock> = Arc::new(SystemClock);
    let credential_store = Arc::new(MemoryCredentialStore::new(clock));
    credential_store
        .save(CredentialRecord {
            credential_id: "credential-1".to_owned(),
            expires_at: OffsetDateTime::parse("2030-01-01T00:00:00Z", &Rfc3339)
                .map_err(|error| error.to_string())?,
            grant_type: GrantType::ApiKey,
            issued_at: fixed_time()?,
            payload: json!({
                "api_key": "opaque-api-key",
                "credential_id": "credential-1",
                "expires_at": "2030-01-01T00:00:00Z",
                "header": issued_header,
            }),
            service_did: SERVICE_DID.to_owned(),
            service_url: Url::parse("https://service.example")
                .map_err(|error| error.to_string())?,
        })
        .await
        .map_err(|error| error.to_string())?;
    let mut options = ClientOptions::new(Arc::new(Identity));
    options.command_transport = Some(transport.clone());
    options.credential_store = Some(credential_store);
    options.inspect_transport = Some(transport);
    let session = Client::new(options)
        .map_err(|error| error.to_string())?
        .service("https://service.example")
        .map_err(|error| error.to_string())?;
    session
        .authentication(AuthenticationOptions {
            carrier: AuthorizationCarrier::Standard,
            client_assertion_only: false,
            credential_id: None,
            grant_type: Some(GrantType::ApiKey),
            resource: Url::parse("https://service.example/resource")
                .map_err(|error| error.to_string())?,
        })
        .await
        .map(|result| result.headers)
        .map_err(|error| error.to_string())
}

pub async fn agent_public_discovery_cache() -> Result<bool, String> {
    let document = inspect_document();

    let freshness_transport = Arc::new(ScriptedTransport::default());
    freshness_transport.push_json(StatusCode::OK, document.clone())?;
    let freshness_session = agent_session(freshness_transport.clone())?;
    freshness_session
        .inspect()
        .await
        .map_err(|error| error.to_string())?;
    freshness_session
        .inspect()
        .await
        .map_err(|error| error.to_string())?;
    if freshness_transport.request_count()? != 1 {
        return Ok(false);
    }

    let no_store_transport = Arc::new(ScriptedTransport::default());
    for _ in 0..2 {
        let mut headers = inspect_headers();
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        no_store_transport.push_response(HttpResponse {
            body: serde_json::to_vec(&document).map_err(|error| error.to_string())?,
            final_url: inspect_url()?,
            headers,
            status: StatusCode::OK,
        })?;
    }
    let no_store_session = agent_session(no_store_transport.clone())?;
    no_store_session
        .inspect()
        .await
        .map_err(|error| error.to_string())?;
    no_store_session
        .inspect()
        .await
        .map_err(|error| error.to_string())?;
    if no_store_transport.request_count()? != 2 {
        return Ok(false);
    }

    let validation_transport = Arc::new(ScriptedTransport::default());
    let mut initial_headers = inspect_headers();
    initial_headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    initial_headers.insert(header::ETAG, HeaderValue::from_static("\"aep-1\""));
    validation_transport.push_response(HttpResponse {
        body: serde_json::to_vec(&document).map_err(|error| error.to_string())?,
        final_url: inspect_url()?,
        headers: initial_headers,
        status: StatusCode::OK,
    })?;
    validation_transport.push_response(HttpResponse {
        body: Vec::new(),
        final_url: inspect_url()?,
        headers: HeaderMap::new(),
        status: StatusCode::NOT_MODIFIED,
    })?;
    let validation_session = agent_session(validation_transport.clone())?;
    validation_session
        .inspect()
        .await
        .map_err(|error| error.to_string())?;
    validation_session
        .inspect()
        .await
        .map_err(|error| error.to_string())?;
    let requests = validation_transport.requests()?;
    Ok(requests.len() == 2
        && requests[1].headers.get(header::IF_NONE_MATCH)
            == Some(&HeaderValue::from_static("\"aep-1\"")))
}

fn agent_session(transport: Arc<ScriptedTransport>) -> Result<aep_agent::Session, String> {
    let mut options = ClientOptions::new(Arc::new(Identity));
    options.command_transport = Some(transport.clone());
    options.inspect_transport = Some(transport);
    Client::new(options)
        .map_err(|error| error.to_string())?
        .service("https://service.example")
        .map_err(|error| error.to_string())
}

fn inspect_document() -> Value {
    inspect_document_for(SERVICE_DID)
}

fn inspect_document_for(service_did: &str) -> Value {
    json!({
        "aep_version": "1.0",
        "bindings": {"supported": ["http"]},
        "commands": {"supported": ["inspect", "enroll", "status"]},
        "core": {"signing_algorithms": ["EdDSA", "ES256"]},
        "http": {"endpoint_base": "/aep"},
        "identity": {"methods": ["did:web"]},
        "service": {"did": service_did}
    })
}

fn inspect_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(aep_core::MEDIA_TYPE),
    );
    headers
}

fn inspect_url() -> Result<Url, String> {
    Url::parse("https://service.example/.well-known/aep").map_err(|error| error.to_string())
}

fn fixed_time() -> Result<OffsetDateTime, String> {
    OffsetDateTime::parse("2026-08-31T12:00:00Z", &Rfc3339).map_err(|error| error.to_string())
}
