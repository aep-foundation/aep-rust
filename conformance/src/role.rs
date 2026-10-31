use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
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
    CredentialAuthenticationInput, EnrollmentDecision, EnrollmentPolicy, EnrollmentRecord,
    EnrollmentStore, GrantContext, GrantTypeDefinition, GrantTypeHandler, IdempotentCommandOptions,
    MemoryEnrollmentStore, ProtectedResourceAuthentication, ProtectedResourceRequest, Service,
    ServiceError, ServiceOptions,
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

struct SignedAssertionVerifier(aep_core::ClientAssertionVerifyingKey);

#[async_trait]
impl ClientAssertionVerifier for SignedAssertionVerifier {
    async fn verify(
        &self,
        context: ClientAssertionVerificationContext,
    ) -> Result<ClientAssertionClaims, ServiceError> {
        let key = if aep_core::decode_jwt_unverified(&context.assertion)?
            .header
            .algorithm
            == SigningAlgorithm::EdDsa
        {
            aep_core::ClientAssertionSigningKey::ed25519_from_seed([5; 32]).verifying_key()
        } else {
            self.0.clone()
        };
        Ok(aep_core::verify_client_assertion(
            &context.assertion,
            &key,
            &aep_core::VerifyClientAssertionOptions {
                algorithms: context.signing_algorithms,
                audience: Some(context.service_did),
                current_time: Some(context.current_time.unix_timestamp()),
                issuer: Some(AGENT_DID.to_owned()),
                subject: Some(AGENT_DID.to_owned()),
                operation: Some(context.operation),
                resource: context.resource.map(|url| url.to_string()),
                ..Default::default()
            },
        )?)
    }
}

pub fn signed_assertion(
    operation: aep_core::AssertionOperation,
    resource: Option<&str>,
    jti: &str,
) -> Result<String, String> {
    let now = fixed_time()?.unix_timestamp();
    sign_client_assertion(
        &ClientAssertionClaims {
            additional: BTreeMap::new(),
            aud: SERVICE_DID.to_owned(),
            exp: now + 60,
            iat: now,
            iss: AGENT_DID.to_owned(),
            jti: jti.to_owned(),
            op: operation,
            resource: resource.map(str::to_owned),
            sub: AGENT_DID.to_owned(),
        },
        SignClientAssertionOptions {
            allow_insecure_loopback: false,
            key: &aep_core::ClientAssertionSigningKey::es256_from_bytes(&[13; 32])
                .map_err(|error| error.to_string())?,
            key_id: "did:web:agent.example#key-1",
        },
    )
    .map_err(|error| error.to_string())
}

pub fn signed_service_fixture() -> Result<ServiceFixture, String> {
    Ok(ServiceFixture {
        service: authentication_service()?.0,
    })
}

pub fn document_service_options() -> Result<ServiceOptions, String> {
    let key = aep_core::ClientAssertionSigningKey::es256_from_bytes(&[13; 32])
        .map_err(|error| error.to_string())?;
    let mut options = ServiceOptions::new(
        SERVICE_DID,
        Arc::new(SignedAssertionVerifier(key.verifying_key())),
    );
    options.clock = Some(Arc::new(FixedServiceClock(fixed_time()?)));
    Ok(options)
}

pub fn authentication_service()
-> Result<(Arc<Service>, Arc<aep_service::MemoryServiceCredentialStore>), String> {
    let key = aep_core::ClientAssertionSigningKey::es256_from_bytes(&[13; 32])
        .map_err(|error| error.to_string())?;
    wire_service_with_store(
        AGENT_DID,
        Arc::new(SignedAssertionVerifier(key.verifying_key())),
        None,
    )
}

pub async fn command_with_assertion(
    fixture: &ServiceFixture,
    command: &str,
    assertion: &str,
    key: &str,
) -> Result<aep_service::ServiceResponse, String> {
    let response = match command {
        "enroll" => fixture.service.enroll(
            br#"{"agent_did":"did:web:agent.example","claims":{"contact.email":"buyer@example.com"}}"#,
            idempotent(assertion, key),
        ).await,
        "grant" => fixture.service.grant(br#"{"grant_type":"api-key"}"#, idempotent(assertion, key)).await,
        "revoke" => fixture.service.revoke(br#"{"grant_type":"api-key"}"#, idempotent(assertion, key)).await,
        "status" => fixture.service.status(authenticated(assertion)).await,
        _ => return Err(format!("unknown command {command}")),
    };
    response.map_err(|error| error.to_string())
}

pub async fn resource_with_assertion(
    fixture: &ServiceFixture,
    assertion: &str,
    url: &str,
) -> Result<ProtectedResourceAuthentication, String> {
    let headers = HeaderMap::from_iter([(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("AEP {assertion}")).map_err(|error| error.to_string())?,
    )]);
    fixture
        .service
        .authenticate_protected_resource(ProtectedResourceRequest {
            headers,
            method: Method::GET,
            url: Url::parse(url).map_err(|error| error.to_string())?,
        })
        .await
        .map_err(|error| error.to_string())
}

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
        Ok(input.headers.contains_key("x-api-key"))
    }
}

struct FixedServiceClock(OffsetDateTime);

impl aep_service::Clock for FixedServiceClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

impl aep_agent::Clock for FixedServiceClock {
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
    service_fixture_with_verifier(
        agent_did,
        enrollment_store,
        Arc::new(AssertionVerifier(agent_did.to_owned())),
    )
}

fn service_fixture_with_verifier(
    agent_did: &str,
    enrollment_store: Arc<MemoryEnrollmentStore>,
    verifier: Arc<dyn ClientAssertionVerifier>,
) -> Result<ServiceFixture, String> {
    let mut options = ServiceOptions::new(SERVICE_DID, verifier);
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

    /// The same protected resource reached with no credential at all.
    pub async fn unauthenticated_resource(
        &self,
    ) -> Result<ProtectedResourceAuthentication, String> {
        self.service
            .authenticate_protected_resource(ProtectedResourceRequest {
                headers: HeaderMap::new(),
                method: Method::GET,
                url: Url::parse("https://service.example/resource")
                    .map_err(|error| error.to_string())?,
            })
            .await
            .map_err(|error| error.to_string())
    }

    /// One Enroll and an exact retry of it: the same body under the same idempotency key, carried
    /// by a fresh assertion, because a retry may not replay the `jti` of the first attempt.
    pub async fn idempotent_replay(
        &self,
    ) -> Result<(aep_service::ServiceResponse, aep_service::ServiceResponse), String> {
        let retry = |assertion: &'static str| {
            self.service.enroll(
                br#"{"agent_did":"did:web:agent.example","claims":{"contact.email":"buyer@example.com"}}"#,
                idempotent(assertion, "replay-key"),
            )
        };
        let first = retry("replay-first")
            .await
            .map_err(|error| error.to_string())?;
        let replay = retry("replay-second")
            .await
            .map_err(|error| error.to_string())?;
        Ok((first, replay))
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
}

struct UnchangedEnrollmentPolicy(Arc<AtomicUsize>);

#[async_trait]
impl EnrollmentPolicy for UnchangedEnrollmentPolicy {
    async fn decide(
        &self,
        _request: &aep_core::EnrollRequest,
        _now: OffsetDateTime,
    ) -> Result<EnrollmentDecision, ServiceError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(EnrollmentDecision {
            update_existing: false,
            ..Default::default()
        })
    }
}

pub async fn repeated_existing(
    agent_did: &str,
    since: OffsetDateTime,
    idempotency_key: &str,
) -> Result<(aep_service::ServiceResponse, bool, bool), String> {
    let record = EnrollmentRecord {
        acknowledged_document_ids: Vec::new(),
        required_document_ids: Vec::new(),
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
    let calls = Arc::new(AtomicUsize::new(0));
    let mut options = ServiceOptions::new(
        SERVICE_DID,
        Arc::new(AssertionVerifier(agent_did.to_owned())),
    );
    options.clock = Some(Arc::new(FixedServiceClock(fixed_time()?)));
    options.enrollment_store = Some(store.clone());
    options.enrollment_policy = Some(Arc::new(UnchangedEnrollmentPolicy(calls.clone())));
    let service = Service::new(options).map_err(|error| error.to_string())?;
    let request = serde_json::to_vec(&json!({
        "agent_did": agent_did,
        "idempotency_key": idempotency_key,
    }))
    .map_err(|error| error.to_string())?;
    let response = service
        .enroll(&request, idempotent("repeated-enroll", idempotency_key))
        .await
        .map_err(|error| error.to_string())?;
    let unchanged = store
        .find(agent_did)
        .await
        .map_err(|error| error.to_string())?
        == Some(record);
    Ok((response, unchanged, calls.load(Ordering::SeqCst) == 1))
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
pub(crate) struct ScriptedTransport {
    requests: Mutex<Vec<HttpRequest>>,
    responses: Mutex<VecDeque<HttpResponse>>,
}

impl ScriptedTransport {
    pub(crate) fn push_response(&self, response: HttpResponse) -> Result<(), String> {
        self.responses
            .lock()
            .map_err(|_| "response lock is poisoned".to_owned())?
            .push_back(response);
        Ok(())
    }

    fn push_json(&self, status: StatusCode, body: Value) -> Result<(), String> {
        self.push_json_at(status, body, inspect_url()?)
    }

    pub(crate) fn push_json_at(
        &self,
        status: StatusCode,
        body: Value,
        final_url: Url,
    ) -> Result<(), String> {
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

    pub(crate) fn requests(&self) -> Result<Vec<HttpRequest>, String> {
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
    agent_authentication_with_carrier(
        methods,
        grant_type,
        resource,
        AuthorizationCarrier::Standard,
    )
    .await
}

pub async fn agent_authentication_with_carrier(
    methods: Option<Vec<&str>>,
    grant_type: Option<GrantType>,
    resource: Url,
    carrier: AuthorizationCarrier,
) -> Result<Result<aep_agent::AuthenticationResult, AgentError>, String> {
    agent_authentication_selected(methods, grant_type, resource, carrier, None).await
}

pub async fn agent_authentication_selected(
    methods: Option<Vec<&str>>,
    grant_type: Option<GrantType>,
    resource: Url,
    carrier: AuthorizationCarrier,
    credential_id: Option<String>,
) -> Result<Result<aep_agent::AuthenticationResult, AgentError>, String> {
    let transport = Arc::new(ScriptedTransport::default());
    let host = resource
        .host_str()
        .ok_or_else(|| "protected resource host is missing".to_owned())?;
    let service_url =
        Url::parse(&resource.origin().ascii_serialization()).map_err(|error| error.to_string())?;
    let service_did = match resource.port() {
        Some(port) => format!("did:web:{host}%3A{port}"),
        None => format!("did:web:{host}"),
    };
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
    let clock = Arc::new(FixedServiceClock(fixed_time()?));
    let store = Arc::new(MemoryCredentialStore::new(clock.clone()));
    let stored_type = grant_type
        .clone()
        .or_else(|| credential_id.as_ref().map(|_| GrantType::OAuthBearer));
    if let Some(grant_type) = &stored_type {
        store
            .save(CredentialRecord {
                credential_id: "credential-1".to_owned(),
                expires_at: OffsetDateTime::parse("2030-01-01T00:00:00Z", &Rfc3339)
                    .map_err(|error| error.to_string())?,
                grant_type: grant_type.clone(),
                issued_at: fixed_time()?,
                payload: grant_payload(grant_type),
                service_did: service_did.clone(),
                service_url: service_url.clone(),
            })
            .await
            .map_err(|error| error.to_string())?;
    }
    let mut options = ClientOptions::new(Arc::new(Identity));
    options.clock = Some(clock);
    options.credential_store = Some(store);
    options.command_transport = Some(transport.clone());
    options.inspect_transport = Some(transport);
    let session = Client::new(options)
        .map_err(|error| error.to_string())?
        .service(service_url.as_str())
        .map_err(|error| error.to_string())?;
    Ok(session
        .authentication(AuthenticationOptions {
            carrier,
            client_assertion_only: false,
            credential_id,
            grant_type,
            resource,
        })
        .await)
}

pub async fn agent_redirect_authentication(
    source: &Url,
    same_origin: &Url,
    cross_origin: &Url,
) -> Result<bool, String> {
    let service_url =
        Url::parse(&source.origin().ascii_serialization()).map_err(|error| error.to_string())?;
    let host = source
        .host_str()
        .ok_or_else(|| "resource host is missing".to_owned())?;
    let service_did = match source.port() {
        Some(port) => format!("did:web:{host}%3A{port}"),
        None => format!("did:web:{host}"),
    };
    let transport = Arc::new(ScriptedTransport::default());
    let mut document = inspect_document_for(&service_did);
    document["authentication"] = json!({"methods":["aep-jwt","api-key","basic","oauth-bearer"]});
    document["commands"]["grant_types"] = json!(["api-key", "basic", "oauth-bearer"]);
    let discovery = service_url
        .join(aep_core::WELL_KNOWN_PATH)
        .map_err(|error| error.to_string())?;
    transport.push_json_at(StatusCode::OK, document, discovery.clone())?;
    let clock = Arc::new(FixedServiceClock(fixed_time()?));
    let store = Arc::new(MemoryCredentialStore::new(clock.clone()));
    for (grant_type, payload) in [
        (
            GrantType::ApiKey,
            json!({"api_key":"secret", "header":"x-api-key"}),
        ),
        (
            GrantType::Basic,
            json!({"username":"buyer", "password":"secret"}),
        ),
        (
            GrantType::OAuthBearer,
            json!({"access_token":"secret", "token_type":"Bearer"}),
        ),
    ] {
        let id = format!("redirect-{}", grant_type.as_str());
        let mut payload = payload;
        payload["credential_id"] = json!(id);
        payload["expires_at"] = json!("2030-01-01T00:00:00Z");
        store
            .save(CredentialRecord {
                credential_id: id,
                expires_at: OffsetDateTime::parse("2030-01-01T00:00:00Z", &Rfc3339)
                    .map_err(|error| error.to_string())?,
                grant_type,
                issued_at: fixed_time()?,
                payload,
                service_did: service_did.clone(),
                service_url: service_url.clone(),
            })
            .await
            .map_err(|error| error.to_string())?;
    }
    let mut options = ClientOptions::new(Arc::new(Identity));
    options.inspect_transport = Some(transport.clone());
    options.command_transport = Some(transport.clone());
    options.credential_store = Some(store);
    options.clock = Some(clock);
    let session = Client::new(options)
        .map_err(|error| error.to_string())?
        .service(service_url.as_str())
        .map_err(|error| error.to_string())?;
    let key = aep_core::ClientAssertionSigningKey::ed25519_from_seed([5; 32]).verifying_key();
    for carrier in [
        AuthorizationCarrier::Standard,
        AuthorizationCarrier::Dedicated,
    ] {
        let field = match carrier {
            AuthorizationCarrier::Standard => "authorization",
            AuthorizationCarrier::Dedicated => "aep-authorization",
        };
        let mut previous_jti = None;
        for resource in [source, same_origin] {
            let authentication = session
                .authentication(AuthenticationOptions {
                    carrier,
                    client_assertion_only: true,
                    credential_id: None,
                    grant_type: None,
                    resource: resource.clone(),
                })
                .await
                .map_err(|error| error.to_string())?;
            let Some(token) = authentication
                .headers
                .get(field)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("AEP "))
            else {
                return Ok(false);
            };
            let claims = aep_core::verify_client_assertion(
                token,
                &key,
                &aep_core::VerifyClientAssertionOptions {
                    audience: Some(service_did.clone()),
                    issuer: Some(AGENT_DID.to_owned()),
                    subject: Some(AGENT_DID.to_owned()),
                    current_time: Some(fixed_time()?.unix_timestamp()),
                    operation: Some(aep_core::AssertionOperation::Authenticate),
                    resource: Some(resource.to_string()),
                    ..Default::default()
                },
            )
            .map_err(|error| error.to_string())?;
            if authentication.headers.len() != 1 || previous_jti.as_ref() == Some(&claims.jti) {
                return Ok(false);
            }
            previous_jti = Some(claims.jti);
        }
        for grant_type in [
            None,
            Some(GrantType::ApiKey),
            Some(GrantType::Basic),
            Some(GrantType::OAuthBearer),
        ] {
            if let Some(grant_type) = &grant_type {
                let authentication = session
                    .authentication(AuthenticationOptions {
                        carrier,
                        client_assertion_only: false,
                        credential_id: None,
                        grant_type: Some(grant_type.clone()),
                        resource: source.clone(),
                    })
                    .await
                    .map_err(|error| error.to_string())?;
                let (method, name, value) = match grant_type {
                    GrantType::ApiKey => (
                        aep_core::AuthenticationMethod::ApiKey,
                        "x-api-key",
                        "secret",
                    ),
                    GrantType::Basic => (
                        aep_core::AuthenticationMethod::Basic,
                        field,
                        "Basic YnV5ZXI6c2VjcmV0",
                    ),
                    GrantType::OAuthBearer => (
                        aep_core::AuthenticationMethod::OAuthBearer,
                        field,
                        "Bearer secret",
                    ),
                    _ => {
                        return Err("unsupported redirect fixture Grant Type".to_owned());
                    }
                };
                if authentication.method != method
                    || authentication.headers.len() != 1
                    || authentication
                        .headers
                        .get(name)
                        .and_then(|value| value.to_str().ok())
                        != Some(value)
                {
                    return Ok(false);
                }
            }
            let result = session
                .authentication(AuthenticationOptions {
                    carrier,
                    client_assertion_only: grant_type.is_none(),
                    credential_id: None,
                    grant_type,
                    resource: cross_origin.clone(),
                })
                .await;
            if !matches!(result, Err(AgentError::InvalidServiceReference(_))) {
                return Ok(false);
            }
        }
    }
    let requests = transport.requests()?;
    Ok(requests.len() == 1
        && requests[0].url == discovery
        && requests[0].method == Method::GET
        && requests[0].headers.len() == 1
        && requests[0].headers.get(header::ACCEPT)
            == Some(&HeaderValue::from_static(aep_core::MEDIA_TYPE))
        && requests[0].body.is_empty())
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

/// Drives the caching contract the vector publishes: the recommended freshness value, what
/// `no-cache` and `no-store` mean for reuse, that a `304` reuses the stored representation, and
/// that an accepted redirect makes the final URL a cache key of its own.
pub async fn agent_public_discovery_cache(
    expected: &serde_json::Map<String, Value>,
) -> Result<bool, String> {
    let member = |name: &str| -> Result<String, String> {
        expected
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| format!("caching expectation is missing {name:?}"))
    };
    if member("default_freshness_seconds")?
        != aep_core::DEFAULT_INSPECT_FRESHNESS.as_secs().to_string()
        || member("no_cache")? != "revalidate"
        || member("no_store")? != "do-not-persist"
        || member("status_304")? != "reuse-validated-representation"
        || member("cache_key")? != "final-safe-redirect-url"
    {
        return Ok(false);
    }
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
    if requests.len() != 2
        || requests[1].headers.get(header::IF_NONE_MATCH)
            != Some(&HeaderValue::from_static("\"aep-1\""))
    {
        return Ok(false);
    }

    // An accepted same-origin redirect makes the URL it resolved to a key of its own, so the
    // document is reachable under the advertised spelling and under the final one.
    let redirect_target =
        Url::parse("https://service.example/discovery/aep").map_err(|error| error.to_string())?;
    let redirect_transport = Arc::new(ScriptedTransport::default());
    let mut redirect_headers = HeaderMap::new();
    redirect_headers.insert(header::LOCATION, HeaderValue::from_static("/discovery/aep"));
    redirect_transport.push_response(HttpResponse {
        body: Vec::new(),
        final_url: inspect_url()?,
        headers: redirect_headers,
        status: StatusCode::FOUND,
    })?;
    redirect_transport.push_json_at(StatusCode::OK, document, redirect_target.clone())?;
    let cache = Arc::new(RecordingInspectCache::default());
    let mut options = ClientOptions::new(Arc::new(Identity));
    options.command_transport = Some(redirect_transport.clone());
    options.inspect_transport = Some(redirect_transport);
    options.inspect_cache = Some(cache.clone());
    let redirect_session = Client::new(options)
        .map_err(|error| error.to_string())?
        .service("https://service.example")
        .map_err(|error| error.to_string())?;
    let inspection = redirect_session
        .inspect()
        .await
        .map_err(|error| error.to_string())?;
    Ok(inspection.final_url == redirect_target
        && cache.keys()?.contains(&redirect_target.to_string()))
}

/// An Inspect cache that records the keys it was written under.
#[derive(Default)]
struct RecordingInspectCache {
    entries: Mutex<BTreeMap<String, aep_agent::InspectCacheEntry>>,
}

impl RecordingInspectCache {
    fn keys(&self) -> Result<Vec<String>, String> {
        self.entries
            .lock()
            .map(|entries| entries.keys().cloned().collect())
            .map_err(|_| "Inspect cache lock is poisoned".to_owned())
    }
}

#[async_trait]
impl aep_agent::InspectCache for RecordingInspectCache {
    async fn delete(&self, inspect_url: &Url) -> Result<(), AgentError> {
        self.entries
            .lock()
            .map_err(|_| AgentError::Store("Inspect cache lock is poisoned".to_owned()))?
            .remove(inspect_url.as_str());
        Ok(())
    }
    async fn find(
        &self,
        inspect_url: &Url,
    ) -> Result<Option<aep_agent::InspectCacheEntry>, AgentError> {
        Ok(self
            .entries
            .lock()
            .map_err(|_| AgentError::Store("Inspect cache lock is poisoned".to_owned()))?
            .get(inspect_url.as_str())
            .cloned())
    }
    async fn save(
        &self,
        inspect_url: &Url,
        entry: aep_agent::InspectCacheEntry,
    ) -> Result<(), AgentError> {
        self.entries
            .lock()
            .map_err(|_| AgentError::Store("Inspect cache lock is poisoned".to_owned()))?
            .insert(inspect_url.to_string(), entry);
        Ok(())
    }
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

pub fn inspect_document_for(service_did: &str) -> Value {
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

struct NoInspectIdentity(std::sync::atomic::AtomicUsize);

#[async_trait]
impl IdentityProvider for NoInspectIdentity {
    async fn get_or_create_identity(
        &self,
        _request: IdentityRequest,
    ) -> Result<AgentIdentity, AgentError> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(AgentError::Identity(
            "Inspect must not provision an identity".to_owned(),
        ))
    }
    async fn signer_for(
        &self,
        _identity: &AgentIdentity,
    ) -> Result<Arc<dyn AssertionSigner>, AgentError> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(AgentError::Identity(
            "Inspect must not request a signer".to_owned(),
        ))
    }
}

pub async fn inspect_responses(
    url: &Url,
    responses: Vec<HttpResponse>,
    maximum_bytes: Option<usize>,
) -> Result<(Vec<HttpRequest>, Result<aep_agent::Inspection, AgentError>), String> {
    let transport = Arc::new(ScriptedTransport::default());
    for response in responses {
        transport.push_response(response)?;
    }
    let identity = Arc::new(NoInspectIdentity(std::sync::atomic::AtomicUsize::new(0)));
    let mut options = ClientOptions::new(identity.clone());
    options.inspect_transport = Some(transport.clone());
    options.command_transport = Some(transport.clone());
    if let Some(maximum) = maximum_bytes {
        options.maximum_response_bytes = maximum;
    }
    let session = Client::new(options)
        .map_err(|error| error.to_string())?
        .service(url.as_str())
        .map_err(|error| error.to_string())?;
    let result = session.inspect().await;
    if identity.0.load(std::sync::atomic::Ordering::SeqCst) != 0 {
        return Err("Inspect attempted identity or signing work".to_owned());
    }
    Ok((transport.requests()?, result))
}

struct CommandIdentity(String);

#[async_trait]
impl IdentityProvider for CommandIdentity {
    async fn get_or_create_identity(
        &self,
        request: IdentityRequest,
    ) -> Result<AgentIdentity, AgentError> {
        Ok(AgentIdentity {
            agent_did: self.0.clone(),
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
        Ok(Arc::new(CommandSigner(self.0.clone())))
    }
}

struct CommandSigner(String);

#[async_trait]
impl AssertionSigner for CommandSigner {
    async fn sign(
        &self,
        claims: &ClientAssertionClaims,
        _algorithms: &[SigningAlgorithm],
    ) -> Result<String, AgentError> {
        Ok(sign_client_assertion(
            claims,
            SignClientAssertionOptions {
                allow_insecure_loopback: false,
                key: &aep_core::ClientAssertionSigningKey::ed25519_from_seed([5; 32]),
                key_id: &self.0,
            },
        )?)
    }
}

pub fn grant_payload(grant_type: &GrantType) -> Value {
    let mut value = match grant_type {
        GrantType::ApiKey => json!({"api_key":"opaque-api-key", "header":"x-api-key"}),
        GrantType::Basic => json!({"username":"buyer", "password":"secret"}),
        _ => json!({"access_token":"secret", "token_type":"Bearer"}),
    };
    value["credential_id"] = json!("credential-1");
    value["expires_at"] = json!("2030-01-01T00:00:00Z");
    value
}

pub fn wire_service(agent_did: &str) -> Result<Arc<Service>, String> {
    Ok(wire_service_with_store(
        agent_did,
        Arc::new(AssertionVerifier(agent_did.to_owned())),
        None,
    )?
    .0)
}

pub fn authentication_document(
    methods: Vec<AuthenticationMethod>,
) -> Result<aep_core::InspectDocument, String> {
    Ok(wire_service_with_store(
        AGENT_DID,
        Arc::new(AssertionVerifier(AGENT_DID.to_owned())),
        Some(methods),
    )?
    .0
    .inspect_document())
}

fn wire_service_with_store(
    agent_did: &str,
    verifier: Arc<dyn ClientAssertionVerifier>,
    methods: Option<Vec<AuthenticationMethod>>,
) -> Result<(Arc<Service>, Arc<aep_service::MemoryServiceCredentialStore>), String> {
    let now = fixed_time()?;
    let mut options = ServiceOptions::new(SERVICE_DID, verifier);
    options.clock = Some(Arc::new(FixedServiceClock(now)));
    options.enrollment_store = Some(Arc::new(
        MemoryEnrollmentStore::new([EnrollmentRecord {
            acknowledged_document_ids: Vec::new(),
            required_document_ids: Vec::new(),
            agent_did: agent_did.to_owned(),
            claims: Default::default(),
            created_at: now,
            owner_action_required: false,
            requirements_pending: vec![],
            since: now,
            status: AgentStatus::Active,
            updated_at: now,
            verification_pending: vec![],
        }])
        .map_err(|error| error.to_string())?,
    ));
    let store = Arc::new(aep_service::MemoryServiceCredentialStore::default());
    options.authentication_methods = methods.unwrap_or_else(|| {
        vec![
            AuthenticationMethod::AepJwt,
            AuthenticationMethod::ApiKey,
            AuthenticationMethod::Basic,
            AuthenticationMethod::OAuthBearer,
        ]
    });
    options.grant_types = vec![
        aep_service::stored_api_key_grant_type(aep_service::StoredApiKeyGrantTypeOptions {
            config: Default::default(),
            store: store.clone(),
            issue: Arc::new(|_, _| {
                Box::pin(async { Ok(serde_json::from_value(grant_payload(&GrantType::ApiKey))?) })
            }),
        })
        .map_err(|error| error.to_string())?,
        aep_service::stored_basic_grant_type(aep_service::StoredBasicGrantTypeOptions {
            config: Default::default(),
            store: store.clone(),
            issue: Arc::new(|_, _| {
                Box::pin(async { Ok(serde_json::from_value(grant_payload(&GrantType::Basic))?) })
            }),
        })
        .map_err(|error| error.to_string())?,
        aep_service::stored_oauth_bearer_grant_type(
            aep_service::StoredOAuthBearerGrantTypeOptions {
                config: Default::default(),
                store: store.clone(),
                issue: Arc::new(|_, _| {
                    Box::pin(async {
                        Ok(serde_json::from_value(grant_payload(
                            &GrantType::OAuthBearer,
                        ))?)
                    })
                }),
            },
        )
        .map_err(|error| error.to_string())?,
    ];
    Ok((
        Service::new(options).map_err(|error| error.to_string())?,
        store,
    ))
}

pub async fn service_command(
    command: &str,
    body: Value,
    key: &str,
) -> Result<aep_service::ServiceResponse, String> {
    let agent_did = body
        .get("agent_did")
        .and_then(Value::as_str)
        .unwrap_or(AGENT_DID);
    let service = wire_service(agent_did)?;
    let bytes = serde_json::to_vec(&body).map_err(|error| error.to_string())?;
    let options = idempotent(command, key);
    let response = match command {
        "enroll" => service.enroll(&bytes, options).await,
        "grant" => service.grant(&bytes, options).await,
        "revoke" => service.revoke(&bytes, options).await,
        _ => return Err(format!("unknown Service command {command}")),
    };
    response.map_err(|error| error.to_string())
}

pub async fn agent_command(
    command: &str,
    body: Value,
    key: Option<String>,
    answer: Value,
    status: StatusCode,
) -> Result<(Vec<HttpRequest>, Result<Value, AgentError>), String> {
    let agent_did = body
        .get("agent_did")
        .and_then(Value::as_str)
        .unwrap_or(AGENT_DID)
        .to_owned();
    let identity = Arc::new(CommandIdentity(agent_did.clone()));
    let transport = Arc::new(ScriptedTransport::default());
    let mut document = inspect_document();
    document["commands"] = json!({
        "supported":["inspect","enroll","status","grant","revoke"],
        "grant_types":["api-key","basic","oauth-bearer"]
    });
    document["commands"]["grant_types_config"] = json!({
        "oauth-bearer":{"supports_per_credential_revoke":"true"}
    });
    transport.push_json(StatusCode::OK, document)?;
    if command == "grant" {
        transport.push_json_at(
            StatusCode::OK,
            json!({
                "agent_did":agent_did, "status":"active", "since":"2026-08-31T12:00:00Z"
            }),
            Url::parse("https://service.example/aep/status").map_err(|error| error.to_string())?,
        )?;
    }
    let mut headers = inspect_headers();
    if !status.is_success() {
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(aep_core::PROBLEM_MEDIA_TYPE),
        );
    }
    transport.push_response(HttpResponse {
        body: serde_json::to_vec(&answer).map_err(|error| error.to_string())?,
        final_url: Url::parse(&format!("https://service.example/aep/{command}"))
            .map_err(|error| error.to_string())?,
        headers,
        status,
    })?;
    let identities = Arc::new(MemoryIdentityStore::default());
    identities
        .save(AgentIdentity {
            agent_did,
            identity_method: IdentityMethod::DidWeb,
            metadata: BTreeMap::new(),
            service_did: SERVICE_DID.to_owned(),
            signing_algorithms: vec![SigningAlgorithm::EdDsa],
        })
        .await
        .map_err(|error| error.to_string())?;
    let mut options = ClientOptions::new(identity);
    options.inspect_transport = Some(transport.clone());
    options.command_transport = Some(transport.clone());
    options.identity_store = Some(identities);
    options.clock = Some(Arc::new(FixedServiceClock(fixed_time()?)));
    let session = Client::new(options)
        .map_err(|error| error.to_string())?
        .service("https://service.example")
        .map_err(|error| error.to_string())?;
    let result = match command {
        "enroll" => session
            .enroll(aep_agent::EnrollOptions {
                acknowledged_document_ids: None,
                claims: body
                    .get("claims")
                    .map(|claims| serde_json::from_value(claims.clone()))
                    .transpose()
                    .map_err(|error| error.to_string())?,
                idempotency_key: key,
            })
            .await
            .map(|response| serde_json::to_value(response.body)),
        "grant" => session
            .grant(GrantOptions {
                grant_type: body
                    .get("grant_type")
                    .map(|grant| serde_json::from_value(grant.clone()))
                    .transpose()
                    .map_err(|error| error.to_string())?,
                idempotency_key: key,
                requested_scopes: body
                    .get("requested_scopes")
                    .map(|scopes| serde_json::from_value(scopes.clone()))
                    .transpose()
                    .map_err(|error| error.to_string())?
                    .unwrap_or_default(),
                ..Default::default()
            })
            .await
            .map(|response| Ok(response.body.raw)),
        "revoke" => session
            .revoke(aep_agent::RevokeOptions {
                all_grant_types: body.get("all_grant_types").and_then(Value::as_str)
                    == Some("true"),
                credential_id: body
                    .get("credential_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                grant_type: body
                    .get("grant_type")
                    .map(|grant| serde_json::from_value(grant.clone()))
                    .transpose()
                    .map_err(|error| error.to_string())?,
                idempotency_key: key,
            })
            .await
            .map(|response| serde_json::to_value(response.body)),
        "status" => session
            .status()
            .await
            .map(|response| serde_json::to_value(response.body)),
        _ => return Err(format!("unknown Agent command {command}")),
    };
    let result = match result {
        Ok(value) => Ok(value.map_err(|error| error.to_string())?),
        Err(error) => Err(error),
    };
    Ok((transport.requests()?, result))
}
