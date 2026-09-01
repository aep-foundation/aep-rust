use std::{collections::BTreeMap, sync::Arc, time::Duration};

use aep_agent::{
    AuthenticationOptions as AgentAuthenticationOptions, Client, ClientOptions, EnrollOptions,
    GrantOptions, PlatformIdentityProvider, PlatformIdentityProviderOptions,
    ReqwestTransport as AgentReqwestTransport, RevokeOptions,
};
use aep_axum::{AepPrincipal, AuthenticationOptions, authentication_layer, router};
use aep_core::{
    ApiKeyGrantResponse, AuthenticationMethod, AuthorizationCarrier, BuiltInGrantResponse,
    ClientAssertionClaims, ClientAssertionSigningKey, ClientAssertionVerifyingKey, GrantType,
    GrantTypeConfig, HttpRequest, HttpResponse, HttpTransport, SignClientAssertionOptions,
    SigningAlgorithm, StringBoolean, TransportError, sign_client_assertion,
};
use aep_platform::{
    AgentIdentityListResponse, AuthorizationRequest, Authorizer, DidVerificationMethod,
    DiscoveryOptions, IdentityListQuery, IdentityRecord, KeyStore, ManagedAgentStatus, Platform,
    PlatformError, PlatformOptions, PlatformResponse, ProvisionRequest, RequestContext,
    ResponseBody, ServiceDidResolver, SignRequest,
};
use aep_service::{
    DidWebClientAssertionVerifier, MemoryServiceCredentialStore, ReqwestTransport, Service,
    ServiceError, ServiceOptions, StoredApiKeyGrantTypeOptions, stored_api_key_grant_type,
};
use async_trait::async_trait;
use axum::{
    Json, Router,
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use futures::FutureExt as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::{Duration as TimeDuration, format_description::well_known::Rfc3339};
use tokio::net::TcpListener;
use url::Url;

const PLATFORM_AUTHORIZATION: &str = "Bearer demo-agent";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match arguments.first().map(String::as_str) {
        Some("agent") => run_agent(required(&arguments, "--platform-url")?, required(&arguments, "--service-url")?).await,
        Some("server") => run_server(required(&arguments, "--listen")?).await,
        _ => Err("usage: aep-interop agent --platform-url URL --service-url URL | server --listen HOST:PORT".into()),
    }
}

#[derive(Serialize)]
struct AgentResult {
    agent: &'static str,
    credential_mode: &'static str,
    enrollment: String,
    platform: &'static str,
    protected_resource_status: u16,
    revoked: bool,
    service: &'static str,
}

async fn run_agent(
    platform_url: &str,
    service_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut secure_platform_url = Url::parse(platform_url)?;
    if secure_platform_url.scheme() != "http" {
        return Err("interoperability Platform URL must use loopback HTTP".into());
    }
    secure_platform_url
        .set_scheme("https")
        .map_err(|_| "interoperability Platform URL scheme is invalid")?;
    let mut provider_options =
        PlatformIdentityProviderOptions::new(secure_platform_url.to_string());
    provider_options.authorization = Some(PLATFORM_AUTHORIZATION.to_owned());
    provider_options.transport = Some(Arc::new(LoopbackPlatformTransport {
        inner: AgentReqwestTransport::new(1 << 20, Duration::from_secs(30))?,
    }));
    let provider = PlatformIdentityProvider::new(provider_options)?;
    let mut client_options = ClientOptions::new(provider);
    client_options.allow_insecure_loopback = true;
    let session = Client::new(client_options)?.service(service_url)?;

    let inspection = session.inspect().await?;
    if !inspection.document.service.did.starts_with("did:web:") {
        return Err("Node Service did not advertise a did:web Service DID".into());
    }
    let enrollment = session.enroll(EnrollOptions::default()).await?;
    let grant = session
        .grant(GrantOptions {
            grant_type: Some(GrantType::ApiKey),
            requested_scopes: vec!["read:resource".to_owned(), "write:profile".to_owned()],
            ..GrantOptions::default()
        })
        .await?;
    let credential = match grant.body.credential {
        Some(BuiltInGrantResponse::ApiKey(credential)) => credential,
        _ => return Err("Node Service did not return an API-key credential".into()),
    };
    let resource = Url::parse(&format!(
        "{}/api/resource",
        service_url.trim_end_matches('/')
    ))?;
    let authentication = session
        .authentication(AgentAuthenticationOptions {
            carrier: AuthorizationCarrier::Standard,
            client_assertion_only: false,
            credential_id: Some(credential.credential_id.clone()),
            grant_type: Some(GrantType::ApiKey),
            resource: resource.clone(),
        })
        .await?;
    let client = reqwest::Client::new();
    let response = client
        .get(resource)
        .headers(authentication.headers)
        .send()
        .await?;
    let protected_resource_status = response.status().as_u16();
    if !response.status().is_success() {
        return Err(
            format!("Node protected resource returned HTTP {protected_resource_status}").into(),
        );
    }
    session
        .revoke(RevokeOptions {
            credential_id: Some(credential.credential_id.clone()),
            grant_type: Some(GrantType::ApiKey),
            ..RevokeOptions::default()
        })
        .await?;
    let revoked = session
        .authentication(AgentAuthenticationOptions {
            carrier: AuthorizationCarrier::Standard,
            client_assertion_only: false,
            credential_id: Some(credential.credential_id),
            grant_type: Some(GrantType::ApiKey),
            resource: Url::parse(&format!(
                "{}/api/resource",
                service_url.trim_end_matches('/')
            ))?,
        })
        .await
        .is_err();
    if !revoked {
        return Err("revoked Node credential remained available".into());
    }
    serde_json::to_writer_pretty(
        std::io::stdout(),
        &AgentResult {
            agent: "rust",
            credential_mode: "api-key",
            enrollment: enrollment.body.status.as_str().to_owned(),
            platform: "node",
            protected_resource_status,
            revoked,
            service: "node",
        },
    )?;
    println!();
    Ok(())
}

struct LoopbackPlatformTransport {
    inner: AgentReqwestTransport,
}

#[async_trait]
impl HttpTransport for LoopbackPlatformTransport {
    async fn send(&self, mut request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let requested_url = request.url.clone();
        request
            .url
            .set_scheme("http")
            .map_err(|_| TransportError::new("loopback Platform URL scheme is invalid"))?;
        let mut response = self.inner.send(request).await?;
        response.final_url = requested_url;
        Ok(response)
    }
}

#[derive(Clone)]
struct InteropState {
    platform: Arc<Platform>,
}

async fn run_server(listen: &str) -> Result<(), Box<dyn std::error::Error>> {
    let origin = Url::parse(&format!("http://{listen}"))?;
    let service_did = format!("did:web:{}:services:store", listen.replace(':', "%3A"));
    let service = create_service(service_did.clone(), &origin)?;
    let platform = create_platform(listen, service_did)?;
    let state = InteropState { platform };

    let mut authentication = AuthenticationOptions::new(origin);
    authentication.allow_insecure_loopback = true;
    let protected = Router::new()
        .route("/api/resource", get(resource))
        .route("/api/profile", post(profile))
        .route_layer(authentication_layer(service.clone(), authentication)?);
    let platform_routes = Router::<InteropState>::new()
        .route("/health", get(|| async { Json(json!({"ok": true})) }))
        .route("/.well-known/aep-platform", get(platform_discovery))
        .route(
            "/platform/agent-identities",
            get(platform_list).post(platform_provision),
        )
        .route(
            "/platform/agent-identities/{identity}",
            get(platform_identity),
        )
        .route(
            "/platform/agent-identities/{identity}/sign",
            post(platform_sign),
        )
        .route("/agents/{agent}/did.json", get(platform_did_document))
        .with_state(state);
    let application = router(service, 1 << 20)?
        .merge(protected)
        .merge(platform_routes);
    let listener = TcpListener::bind(listen).await?;
    axum::serve(listener, application).await?;
    Ok(())
}

async fn resource(_principal: AepPrincipal) -> Json<Value> {
    Json(json!({"available": true}))
}

async fn profile(_principal: AepPrincipal) -> Json<Value> {
    Json(json!({"updated": true}))
}

async fn platform_discovery(State(state): State<InteropState>) -> Response {
    platform_response(state.platform.discovery())
}

#[derive(Default, Deserialize)]
struct ListQuery {
    descending: Option<bool>,
    limit: Option<usize>,
    offset: Option<usize>,
    service_did: Option<String>,
    status: Option<String>,
}

async fn platform_list(
    State(state): State<InteropState>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Response {
    let status = match query.status.as_deref() {
        None | Some("") => None,
        Some("active") => Some(ManagedAgentStatus::Active),
        Some("revoked") => Some(ManagedAgentStatus::Revoked),
        Some("suspended") => Some(ManagedAgentStatus::Suspended),
        Some("terminated") => Some(ManagedAgentStatus::Terminated),
        Some(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    match state
        .platform
        .list(
            IdentityListQuery {
                descending: query.descending.unwrap_or(false),
                limit: query.limit.unwrap_or(0),
                offset: query.offset.unwrap_or(0),
                service_did: query.service_did,
                status,
            },
            &request_context(&headers),
        )
        .await
    {
        Ok(response) => platform_response::<AgentIdentityListResponse>(response),
        Err(error) => internal_error(error),
    }
}

async fn platform_provision(
    State(state): State<InteropState>,
    headers: HeaderMap,
    Json(request): Json<ProvisionRequest>,
) -> Response {
    match state
        .platform
        .provision(request, request_context(&headers))
        .await
    {
        Ok(response) => platform_response(response),
        Err(error) => internal_error(error),
    }
}

async fn platform_identity(
    State(state): State<InteropState>,
    headers: HeaderMap,
    Path(identity): Path<String>,
) -> Response {
    match state
        .platform
        .get_identity(&identity, &request_context(&headers))
        .await
    {
        Ok(response) => platform_response(response),
        Err(error) => internal_error(error),
    }
}

async fn platform_sign(
    State(state): State<InteropState>,
    headers: HeaderMap,
    Path(identity): Path<String>,
    Json(request): Json<SignRequest>,
) -> Response {
    match state
        .platform
        .sign(&identity, request, request_context(&headers))
        .await
    {
        Ok(response) => platform_response(response),
        Err(error) => internal_error(error),
    }
}

async fn platform_did_document(
    State(state): State<InteropState>,
    Path(agent): Path<String>,
) -> Response {
    match state.platform.did_document(&agent).await {
        Ok(response) => platform_response(response),
        Err(error) => internal_error(error),
    }
}

fn platform_response<T: Serialize>(response: PlatformResponse<T>) -> Response {
    let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = match response.body {
        ResponseBody::Success(body) => serde_json::to_vec(&body),
        ResponseBody::Problem(problem) => serde_json::to_vec(&problem),
    };
    let Ok(body) = body else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let mut rendered = Response::new(Body::from(body));
    *rendered.status_mut() = status;
    *rendered.headers_mut() = response.headers;
    rendered
}

fn internal_error(_error: PlatformError) -> Response {
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

fn request_context(headers: &HeaderMap) -> RequestContext {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let principal = if authorization.as_deref() == Some(PLATFORM_AUTHORIZATION) {
        "interop-agent".to_owned()
    } else {
        String::new()
    };
    RequestContext {
        authorization,
        idempotency_key: headers
            .get("idempotency-key")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        principal,
        ..RequestContext::default()
    }
}

fn create_service(
    service_did: String,
    origin: &Url,
) -> Result<Arc<Service>, Box<dyn std::error::Error>> {
    let transport = Arc::new(ReqwestTransport::new(1 << 20, Duration::from_secs(10))?);
    let verifier = Arc::new(DidWebClientAssertionVerifier::new(transport, true));
    let grant_type = stored_api_key_grant_type(StoredApiKeyGrantTypeOptions {
        config: GrantTypeConfig {
            additional: BTreeMap::from([("header_names".to_owned(), json!(["x-api-key"]))]),
            supports_per_credential_revoke: Some(StringBoolean::True),
        },
        issue: Arc::new(|request, context| {
            async move {
                Ok::<_, ServiceError>(ApiKeyGrantResponse {
                    additional: BTreeMap::new(),
                    api_key: "interop-secret".to_owned(),
                    credential_id: "interop-credential".to_owned(),
                    expires_at: (context.now + TimeDuration::hours(1))
                        .format(&Rfc3339)
                        .map_err(|error| ServiceError::Handler(error.to_string()))?,
                    header: "x-api-key".to_owned(),
                    scopes: request.requested_scopes,
                })
            }
            .boxed()
        }),
        store: Arc::new(MemoryServiceCredentialStore::default()),
    })?;
    let mut options = ServiceOptions::new(service_did, verifier);
    options.allow_insecure_loopback = true;
    options.authentication_methods = vec![AuthenticationMethod::ApiKey];
    options.endpoint_base = Some("/aep".to_owned());
    options.grant_types = vec![grant_type];
    options.inspect_url = Some(origin.join(".well-known/aep")?);
    options.signing_algorithms = vec![SigningAlgorithm::EdDsa, SigningAlgorithm::Es256];
    Ok(Service::new(options)?)
}

struct InteropAuthorizer;

#[async_trait]
impl Authorizer for InteropAuthorizer {
    async fn authorize(
        &self,
        _request: &AuthorizationRequest,
        context: &RequestContext,
    ) -> Result<bool, PlatformError> {
        Ok(
            context.authorization.as_deref() == Some(PLATFORM_AUTHORIZATION)
                && context.principal == "interop-agent",
        )
    }
}

struct InteropServiceResolver {
    service_did: String,
}

#[async_trait]
impl ServiceDidResolver for InteropServiceResolver {
    async fn resolve(&self, service_did: &str) -> Result<bool, PlatformError> {
        Ok(service_did == self.service_did)
    }
}

struct InteropKeyStore {
    key: ClientAssertionSigningKey,
    public_key: [u8; 32],
}

impl InteropKeyStore {
    fn new() -> Self {
        let seed = [9; 32];
        Self {
            key: ClientAssertionSigningKey::ed25519_from_seed(seed),
            public_key: *SigningKey::from_bytes(&seed).verifying_key().as_bytes(),
        }
    }
}

#[async_trait]
impl KeyStore for InteropKeyStore {
    async fn create_key(&self, _identity: &IdentityRecord) -> Result<(), PlatformError> {
        Ok(())
    }

    async fn did_verification_method(
        &self,
        identity: &IdentityRecord,
    ) -> Result<DidVerificationMethod, PlatformError> {
        Ok(DidVerificationMethod {
            controller: identity.agent_did.clone(),
            id: identity.key_id.clone(),
            method_type: "JsonWebKey2020".to_owned(),
            public_key_jwk: json!({
                "alg": "EdDSA",
                "crv": "Ed25519",
                "kid": identity.key_id,
                "kty": "OKP",
                "use": "sig",
                "x": URL_SAFE_NO_PAD.encode(self.public_key)
            }),
        })
    }

    async fn sign(
        &self,
        identity: &IdentityRecord,
        claims: &ClientAssertionClaims,
    ) -> Result<String, PlatformError> {
        Ok(sign_client_assertion(
            claims,
            SignClientAssertionOptions {
                allow_insecure_loopback: true,
                key: &self.key,
                key_id: &identity.key_id,
            },
        )?)
    }

    async fn verification_key(
        &self,
        _identity: &IdentityRecord,
    ) -> Result<ClientAssertionVerifyingKey, PlatformError> {
        Ok(self.key.verifying_key())
    }
}

fn create_platform(listen: &str, service_did: String) -> Result<Arc<Platform>, PlatformError> {
    let mut options = PlatformOptions::new(
        Arc::new(InteropAuthorizer),
        Arc::new(InteropKeyStore::new()),
        Arc::new(InteropServiceResolver { service_did }),
        listen,
        format!("https://{listen}/agents/{{agent_did_id}}/did.json"),
    );
    options.discovery = DiscoveryOptions {
        endpoint_base: "/platform/".to_owned(),
        lifecycle_endpoint: "/platform/agent-identities/{agent_identity_id}".to_owned(),
        list_endpoint: "/platform/agent-identities".to_owned(),
        platform_did: Some(format!("did:web:{}", listen.replace(':', "%3A"))),
        platform_name: "Rust Interoperability Platform".to_owned(),
        provision_endpoint: "/platform/agent-identities".to_owned(),
        sign_endpoint: "/platform/agent-identities/{agent_identity_id}/sign".to_owned(),
        ..DiscoveryOptions::default()
    };
    options.signing_algorithms = vec![SigningAlgorithm::EdDsa];
    Platform::new(options)
}

fn required<'a>(
    arguments: &'a [String],
    name: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    arguments
        .windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].as_str())
        .ok_or_else(|| format!("missing required argument {name}").into())
}
