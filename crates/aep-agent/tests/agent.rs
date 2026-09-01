use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
};

use aep_agent::*;
use aep_core::*;
use async_trait::async_trait;
use futures::executor::block_on;
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;

#[derive(Clone)]
struct FixedClock(OffsetDateTime);

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

struct AdvancingClock(Mutex<OffsetDateTime>);

impl Clock for AdvancingClock {
    fn now(&self) -> OffsetDateTime {
        *self.0.lock().expect("clock lock")
    }
}

struct AdvancingDelay {
    clock: Arc<AdvancingClock>,
}

#[async_trait]
impl Delay for AdvancingDelay {
    async fn sleep(&self, duration: std::time::Duration) {
        *self.clock.0.lock().expect("clock lock") +=
            time::Duration::try_from(duration).expect("duration");
    }
}

#[derive(Default)]
struct RecordingSigner {
    claims: Mutex<Vec<ClientAssertionClaims>>,
}

#[async_trait]
impl AssertionSigner for RecordingSigner {
    async fn sign(
        &self,
        claims: &ClientAssertionClaims,
        algorithms: &[SigningAlgorithm],
    ) -> Result<String, AgentError> {
        assert_eq!(
            algorithms,
            &[SigningAlgorithm::EdDsa, SigningAlgorithm::Es256]
        );
        self.claims
            .lock()
            .expect("claims lock")
            .push(claims.clone());
        Ok("signed.assertion.value".to_owned())
    }
}

struct TestIdentityProvider {
    signer: Arc<RecordingSigner>,
}

struct SequencePlatformKeys(Mutex<VecDeque<String>>);

impl PlatformIdempotencyKeyProvider for SequencePlatformKeys {
    fn create_key(&self) -> Result<String, AgentError> {
        self.0
            .lock()
            .expect("key lock")
            .pop_front()
            .ok_or_else(|| AgentError::InvalidConfiguration("no test key".to_owned()))
    }
}

struct CompletingPendingSign;

#[async_trait]
impl PlatformPendingSignResolver for CompletingPendingSign {
    async fn resolve(
        &self,
        pending: PlatformPendingSign,
    ) -> Result<BTreeMap<String, serde_json::Value>, AgentError> {
        assert_eq!(pending.retry_after, std::time::Duration::from_secs(2));
        assert_eq!(pending.platform_context["approval_id"], "approval-one");
        Ok(BTreeMap::from([(
            "approval_id".to_owned(),
            serde_json::Value::String("approval-one".to_owned()),
        )]))
    }
}

struct TestPlatformHeaders;

#[async_trait]
impl PlatformAuthenticationHeaders for TestPlatformHeaders {
    async fn headers(&self) -> Result<HeaderMap, AgentError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer dynamic"),
        );
        headers.insert(header::ACCEPT, HeaderValue::from_static("text/plain"));
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        headers.insert("idempotency-key", HeaderValue::from_static("not-allowed"));
        headers.insert("x-platform-context", HeaderValue::from_static("context"));
        Ok(headers)
    }
}

#[async_trait]
impl IdentityProvider for TestIdentityProvider {
    async fn get_or_create_identity(
        &self,
        request: IdentityRequest,
    ) -> Result<AgentIdentity, AgentError> {
        Ok(AgentIdentity {
            agent_did: "did:web:agent.example:agents:one".to_owned(),
            identity_method: IdentityMethod::DidWeb,
            service_did: request.inspection.document.service.did,
            signing_algorithms: vec![SigningAlgorithm::EdDsa, SigningAlgorithm::Es256],
            metadata: BTreeMap::new(),
        })
    }

    async fn signer_for(
        &self,
        _identity: &AgentIdentity,
    ) -> Result<Arc<dyn AssertionSigner>, AgentError> {
        Ok(self.signer.clone())
    }
}

struct Response {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
    final_url: Option<Url>,
}

#[derive(Default)]
struct ScriptedTransport {
    requests: Mutex<Vec<HttpRequest>>,
    responses: Mutex<VecDeque<Response>>,
}

impl ScriptedTransport {
    fn push_json(&self, status: StatusCode, body: serde_json::Value) {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(MEDIA_TYPE));
        self.responses
            .lock()
            .expect("responses lock")
            .push_back(Response {
                status,
                headers,
                body: serde_json::to_vec(&body).expect("JSON"),
                final_url: None,
            });
    }

    fn push(&self, response: Response) {
        self.responses
            .lock()
            .expect("responses lock")
            .push_back(response);
    }
}

#[async_trait]
impl HttpTransport for ScriptedTransport {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let response = self
            .responses
            .lock()
            .expect("responses lock")
            .pop_front()
            .ok_or_else(|| TransportError::new("no scripted response"))?;
        let final_url = response
            .final_url
            .clone()
            .unwrap_or_else(|| request.url.clone());
        self.requests.lock().expect("requests lock").push(request);
        Ok(HttpResponse {
            status: response.status,
            final_url,
            headers: response.headers,
            body: response.body,
        })
    }
}

fn inspect_document(authentication: serde_json::Value) -> serde_json::Value {
    let mut document = serde_json::json!({
        "aep_version": "1.0",
        "authentication": authentication,
        "bindings": {"supported": ["http"]},
        "claims": {"required": ["contact.email"]},
        "commands": {
            "supported": ["inspect", "enroll", "grant", "revoke", "status"],
            "grant_types": ["api-key"],
            "grant_types_config": {"api-key": {"supports_per_credential_revoke": "true"}}
        },
        "core": {"signing_algorithms": ["EdDSA", "ES256"]},
        "http": {"endpoint_base": "/aep/"},
        "identity": {"methods": ["did:web"]},
        "service": {"did": "did:web:service.example"}
    });
    if authentication.is_null() {
        document
            .as_object_mut()
            .expect("Inspect object")
            .remove("authentication");
    }
    document
}

fn client(transport: Arc<ScriptedTransport>, signer: Arc<RecordingSigner>) -> Arc<Client> {
    let provider = Arc::new(TestIdentityProvider { signer });
    let mut options = ClientOptions::new(provider);
    options.clock = Some(Arc::new(FixedClock(
        OffsetDateTime::parse("2026-08-31T12:00:00Z", &Rfc3339).expect("fixed time"),
    )));
    options.command_transport = Some(transport.clone());
    options.inspect_transport = Some(transport);
    Client::new(options).expect("client")
}

fn platform_discovery() -> serde_json::Value {
    serde_json::json!({
        "aep_version": "1.0",
        "endpoints": {
            "lifecycle": "/v1/aep/agent-identities/{agent_identity_id}",
            "list": "/v1/aep/agent-identities",
            "provision": "/v1/aep/agent-identities",
            "sign": "/v1/aep/agent-identities/{agent_identity_id}/sign"
        },
        "http": {"endpoint_base": "/v1/aep"},
        "identity": {
            "did_methods": ["did:web"],
            "did_url_template": "https://platform.example/agents/{agent_did_id}/did.json"
        },
        "platform": {
            "hosted_verification": false,
            "name": "Example Platform"
        },
        "signing": {
            "algorithms": ["ES256"],
            "default_lifetime_seconds": "300"
        }
    })
}

fn platform_identity() -> serde_json::Value {
    serde_json::json!({
        "agent_did": "did:web:platform.example:agents:one",
        "agent_identity_id": "identity/one",
        "created_at": "2026-08-31T12:00:00Z",
        "did_document_url": "https://platform.example/agents/one/did.json",
        "key_id": "did:web:platform.example:agents:one",
        "service_did": "did:web:service.example",
        "signing_algorithms": ["ES256"],
        "status": "active",
        "updated_at": "2026-08-31T12:00:00Z"
    })
}

fn inspection() -> Inspection {
    Inspection {
        cache_control: None,
        document: parse_inspect_document(
            &serde_json::to_vec(&inspect_document(serde_json::json!({
                "methods": ["aep-jwt"]
            })))
            .expect("Inspect JSON"),
        )
        .expect("Inspect document"),
        etag: None,
        final_url: Url::parse("https://service.example/.well-known/aep").expect("final URL"),
        inspect_url: Url::parse("https://service.example/.well-known/aep").expect("Inspect URL"),
        last_modified: None,
        service_url: Url::parse("https://service.example/").expect("Service URL"),
    }
}

fn platform_provider(transport: Arc<ScriptedTransport>) -> Arc<PlatformIdentityProvider> {
    let mut options = PlatformIdentityProviderOptions::new("https://platform.example");
    options.authorization = Some("Bearer platform-token".to_owned());
    options.clock = Some(Arc::new(FixedClock(
        OffsetDateTime::parse("2026-08-31T12:00:00Z", &Rfc3339).expect("fixed time"),
    )));
    options.transport = Some(transport);
    PlatformIdentityProvider::new(options).expect("Platform provider")
}

#[test]
fn provisions_and_signs_with_a_hosted_platform_identity() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        transport.push_json(StatusCode::OK, platform_discovery());
        transport.push_json(
            StatusCode::OK,
            serde_json::json!({"count": "0", "data": [], "total": "0"}),
        );
        transport.push_json(StatusCode::CREATED, platform_identity());
        transport.push_json(
            StatusCode::OK,
            serde_json::json!({
                "agent_did": "did:web:platform.example:agents:one",
                "client_assertion": "platform.assertion.value",
                "expires_at": "2026-08-31T12:05:00Z",
                "issued_at": "2026-08-31T12:00:00Z",
                "jti": "assertion-one",
                "service_did": "did:web:service.example",
                "status": "completed"
            }),
        );
        let provider = platform_provider(transport.clone());
        let identity = provider
            .get_or_create_identity(IdentityRequest {
                inspection: inspection(),
            })
            .await
            .expect("provision identity");
        let signer = provider
            .signer_for(&identity)
            .await
            .expect("Platform signer");
        let assertion = signer
            .sign(
                &ClientAssertionClaims {
                    aud: "did:web:service.example".to_owned(),
                    exp: 1_788_177_900,
                    iat: 1_788_177_600,
                    iss: "did:web:platform.example:agents:one".to_owned(),
                    jti: "assertion-one".to_owned(),
                    op: AssertionOperation::Enroll,
                    resource: None,
                    sub: "did:web:platform.example:agents:one".to_owned(),
                    additional: BTreeMap::new(),
                },
                &[SigningAlgorithm::Es256],
            )
            .await
            .expect("delegated assertion");
        assert_eq!(assertion, "platform.assertion.value");

        let requests = transport.requests.lock().expect("requests lock");
        assert_eq!(requests.len(), 4);
        assert_eq!(requests[0].url.path(), "/.well-known/aep-platform");
        assert_eq!(
            requests[1].url.query(),
            Some("descending=true&limit=100&service_did=did%3Aweb%3Aservice.example")
        );
        assert_eq!(requests[2].method, Method::POST);
        assert_eq!(
            requests[2].headers.get(header::AUTHORIZATION),
            Some(&HeaderValue::from_static("Bearer platform-token"))
        );
        assert!(requests[2].headers.contains_key("idempotency-key"));
        assert_eq!(
            requests[3].url.path(),
            "/v1/aep/agent-identities/identity%2Fone/sign"
        );
        let sign_body: serde_json::Value =
            serde_json::from_slice(&requests[3].body).expect("Sign request");
        assert!(sign_body.get("resource").is_none());
    });
}

#[test]
fn recovers_an_existing_identity_and_reuses_discovery_cache() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        transport.push_json(StatusCode::OK, platform_discovery());
        for _ in 0..2 {
            transport.push_json(
                StatusCode::OK,
                serde_json::json!({
                    "count": "1",
                    "data": [platform_identity()],
                    "total": "1"
                }),
            );
        }
        let provider = platform_provider(transport.clone());
        for _ in 0..2 {
            let identity = provider
                .find_identity_by_service_did("did:web:service.example")
                .await
                .expect("identity lookup")
                .expect("active identity");
            assert_eq!(identity.agent_did, "did:web:platform.example:agents:one");
        }
        let requests = transport.requests.lock().expect("requests lock");
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].url.path(), "/.well-known/aep-platform");
    });
}

#[test]
fn exposes_or_resolves_pending_platform_signing() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        transport.push_json(StatusCode::OK, platform_discovery());
        transport.push_json(
            StatusCode::OK,
            serde_json::json!({
                "count": "1",
                "data": [platform_identity()],
                "total": "1"
            }),
        );
        transport.push_json(
            StatusCode::ACCEPTED,
            serde_json::json!({
                "platform_context": {"approval_id": "approval-one"},
                "retry_after_seconds": "2",
                "status": "pending"
            }),
        );
        transport.push_json(
            StatusCode::OK,
            serde_json::json!({
                "agent_did": "did:web:platform.example:agents:one",
                "client_assertion": "platform.assertion.value",
                "expires_at": "2026-08-31T12:05:00Z",
                "issued_at": "2026-08-31T12:00:00Z",
                "jti": "assertion-one",
                "service_did": "did:web:service.example",
                "status": "completed"
            }),
        );
        let mut options = PlatformIdentityProviderOptions::new("https://platform.example");
        options.clock = Some(Arc::new(FixedClock(
            OffsetDateTime::parse("2026-08-31T12:00:00Z", &Rfc3339).expect("fixed time"),
        )));
        options.idempotency_keys = Some(Arc::new(SequencePlatformKeys(Mutex::new(
            VecDeque::from(["sign-one".to_owned(), "sign-two".to_owned()]),
        ))));
        options.pending_sign_resolver = Some(Arc::new(CompletingPendingSign));
        options.transport = Some(transport.clone());
        let provider = PlatformIdentityProvider::new(options).expect("Platform provider");
        let identity = provider
            .find_identity_by_service_did("did:web:service.example")
            .await
            .expect("identity lookup")
            .expect("active identity");
        let signer = provider.signer_for(&identity).await.expect("signer");
        let assertion = signer
            .sign(&platform_claims(), &[SigningAlgorithm::Es256])
            .await
            .expect("resolved assertion");
        assert_eq!(assertion, "platform.assertion.value");
        let requests = transport.requests.lock().expect("requests lock");
        assert_eq!(requests[2].headers["idempotency-key"], "sign-one");
        assert_eq!(requests[3].headers["idempotency-key"], "sign-two");
        let completion_body: serde_json::Value =
            serde_json::from_slice(&requests[3].body).expect("completion request");
        assert_eq!(
            completion_body["platform_context"]["approval_id"],
            "approval-one"
        );
    });
}

#[test]
fn returns_typed_pending_signing_without_a_resolver() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        transport.push_json(StatusCode::OK, platform_discovery());
        transport.push_json(
            StatusCode::OK,
            serde_json::json!({
                "count": "1",
                "data": [platform_identity()],
                "total": "1"
            }),
        );
        transport.push_json(
            StatusCode::ACCEPTED,
            serde_json::json!({"retry_after_seconds": "5", "status": "pending"}),
        );
        let provider = platform_provider(transport);
        let identity = provider
            .find_identity_by_service_did("did:web:service.example")
            .await
            .expect("identity lookup")
            .expect("active identity");
        let error = provider
            .signer_for(&identity)
            .await
            .expect("signer")
            .sign(&platform_claims(), &[SigningAlgorithm::Es256])
            .await
            .expect_err("pending result");
        let AgentError::PlatformSignPending { pending } = error else {
            panic!("expected typed pending error");
        };
        assert_eq!(pending.retry_after, std::time::Duration::from_secs(5));
    });
}

#[test]
fn conditionally_revalidates_platform_discovery() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        let mut discovery_headers = HeaderMap::new();
        discovery_headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(MEDIA_TYPE));
        discovery_headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        discovery_headers.insert(header::ETAG, HeaderValue::from_static("\"platform-one\""));
        transport.push(Response {
            status: StatusCode::OK,
            headers: discovery_headers,
            body: serde_json::to_vec(&platform_discovery()).expect("Discovery JSON"),
            final_url: None,
        });
        transport.push_json(
            StatusCode::OK,
            serde_json::json!({"count": "0", "data": [], "total": "0"}),
        );
        transport.push(Response {
            status: StatusCode::NOT_MODIFIED,
            headers: HeaderMap::new(),
            body: Vec::new(),
            final_url: None,
        });
        transport.push_json(
            StatusCode::OK,
            serde_json::json!({"count": "0", "data": [], "total": "0"}),
        );
        let provider = platform_provider(transport.clone());
        for _ in 0..2 {
            assert!(
                provider
                    .find_identity_by_service_did("did:web:service.example")
                    .await
                    .expect("identity lookup")
                    .is_none()
            );
        }
        let requests = transport.requests.lock().expect("requests lock");
        assert_eq!(requests.len(), 4);
        assert_eq!(
            requests[2].headers.get(header::IF_NONE_MATCH),
            Some(&HeaderValue::from_static("\"platform-one\""))
        );
    });
}

#[test]
fn rejects_unsafe_platform_discovery_and_command_failures() {
    block_on(async {
        let redirect_transport = Arc::new(ScriptedTransport::default());
        let mut redirect_headers = HeaderMap::new();
        redirect_headers.insert(
            header::LOCATION,
            HeaderValue::from_static("https://other.example/.well-known/aep-platform"),
        );
        redirect_transport.push(Response {
            status: StatusCode::FOUND,
            headers: redirect_headers,
            body: Vec::new(),
            final_url: None,
        });
        let error = platform_provider(redirect_transport)
            .find_identity_by_service_did("did:web:service.example")
            .await
            .expect_err("cross-origin redirect");
        assert!(error.to_string().contains("changed origin"));

        let command_transport = Arc::new(ScriptedTransport::default());
        command_transport.push_json(StatusCode::OK, platform_discovery());
        let mut problem_headers = HeaderMap::new();
        problem_headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(PROBLEM_MEDIA_TYPE),
        );
        command_transport.push(Response {
            status: StatusCode::FORBIDDEN,
            headers: problem_headers,
            body: serde_json::to_vec(&serde_json::json!({
                "code": "authentication_required",
                "detail": "Authenticate to the Platform.",
                "status": 403,
                "title": "Authentication required",
                "type": "urn:aep:error:authentication_required"
            }))
            .expect("Problem JSON"),
            final_url: None,
        });
        let error = platform_provider(command_transport)
            .find_identity_by_service_did("did:web:service.example")
            .await
            .expect_err("command failure");
        let AgentError::PlatformCommand { status, problem } = error else {
            panic!("expected Platform command error");
        };
        assert_eq!(status, 403);
        assert_eq!(
            problem.expect("Problem Details").code,
            ErrorCode::AuthenticationRequired
        );
    });
}

#[test]
fn validates_platform_provider_configuration() {
    let mut options = PlatformIdentityProviderOptions::new("http://platform.example");
    assert!(PlatformIdentityProvider::new(options.clone()).is_err());
    options.platform_url = "https://platform.example".to_owned();
    options.maximum_response_bytes = 0;
    assert!(PlatformIdentityProvider::new(options.clone()).is_err());
    options.maximum_response_bytes = 1024;
    options.request_timeout = std::time::Duration::ZERO;
    assert!(PlatformIdentityProvider::new(options.clone()).is_err());
    options.request_timeout = std::time::Duration::from_secs(1);
    options.authorization = Some("bad\nvalue".to_owned());
    assert!(PlatformIdentityProvider::new(options).is_err());
}

#[test]
fn applies_dynamic_platform_headers_and_rejects_invalid_signer_inputs() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        transport.push_json(StatusCode::OK, platform_discovery());
        transport.push_json(
            StatusCode::OK,
            serde_json::json!({
                "count": "1",
                "data": [platform_identity()],
                "total": "1"
            }),
        );
        let mut options = PlatformIdentityProviderOptions::new("https://platform.example");
        options.authentication_headers = Some(Arc::new(TestPlatformHeaders));
        options.authorization = Some("Bearer static".to_owned());
        options.transport = Some(transport.clone());
        let provider = PlatformIdentityProvider::new(options).expect("Platform provider");
        let identity = provider
            .find_identity_by_service_did("did:web:service.example")
            .await
            .expect("identity lookup")
            .expect("identity");
        let signer = provider.signer_for(&identity).await.expect("signer");
        let mut claims = platform_claims();
        claims.aud = "did:web:other.example".to_owned();
        assert!(
            signer
                .sign(&claims, &[SigningAlgorithm::Es256])
                .await
                .is_err()
        );
        assert!(
            signer
                .sign(&platform_claims(), &[SigningAlgorithm::EdDsa])
                .await
                .is_err()
        );

        let requests = transport.requests.lock().expect("requests lock");
        let headers = &requests[1].headers;
        assert_eq!(headers[header::AUTHORIZATION], "Bearer dynamic");
        assert_eq!(headers[header::ACCEPT], MEDIA_TYPE);
        assert_eq!(headers["x-platform-context"], "context");
        assert!(!headers.contains_key("idempotency-key"));
    });
}

#[test]
fn rejects_oversized_platform_responses_and_empty_idempotency_keys() {
    block_on(async {
        let oversized = Arc::new(ScriptedTransport::default());
        oversized.push_json(StatusCode::OK, platform_discovery());
        let mut options = PlatformIdentityProviderOptions::new("https://platform.example");
        options.maximum_response_bytes = 16;
        options.transport = Some(oversized);
        let error = PlatformIdentityProvider::new(options)
            .expect("Platform provider")
            .find_identity_by_service_did("did:web:service.example")
            .await
            .expect_err("oversized discovery");
        assert!(error.to_string().contains("configured limit"));

        let transport = Arc::new(ScriptedTransport::default());
        transport.push_json(StatusCode::OK, platform_discovery());
        transport.push_json(
            StatusCode::OK,
            serde_json::json!({"count": "0", "data": [], "total": "0"}),
        );
        let mut options = PlatformIdentityProviderOptions::new("https://platform.example");
        options.idempotency_keys = Some(Arc::new(SequencePlatformKeys(Mutex::new(
            VecDeque::from([" ".to_owned()]),
        ))));
        options.transport = Some(transport);
        let error = PlatformIdentityProvider::new(options)
            .expect("Platform provider")
            .get_or_create_identity(IdentityRequest {
                inspection: inspection(),
            })
            .await
            .expect_err("empty idempotency key");
        assert!(error.to_string().contains("empty key"));
    });
}

#[test]
fn rejects_malformed_platform_http_results() {
    block_on(async {
        let invalid_media = Arc::new(ScriptedTransport::default());
        invalid_media.push_json(StatusCode::OK, platform_discovery());
        invalid_media.push(Response {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: b"{}".to_vec(),
            final_url: None,
        });
        assert!(
            platform_provider(invalid_media)
                .find_identity_by_service_did("did:web:service.example")
                .await
                .expect_err("invalid media type")
                .to_string()
                .contains("media type")
        );

        let followed_redirect = Arc::new(ScriptedTransport::default());
        followed_redirect.push_json(StatusCode::OK, platform_discovery());
        followed_redirect.push(Response {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: b"{}".to_vec(),
            final_url: Some(Url::parse("https://platform.example/other").expect("URL")),
        });
        assert!(
            platform_provider(followed_redirect)
                .find_identity_by_service_did("did:web:service.example")
                .await
                .expect_err("followed redirect")
                .to_string()
                .contains("redirects are not allowed")
        );

        let invalid_key = Arc::new(ScriptedTransport::default());
        invalid_key.push_json(StatusCode::OK, platform_discovery());
        invalid_key.push_json(
            StatusCode::OK,
            serde_json::json!({"count": "0", "data": [], "total": "0"}),
        );
        let mut options = PlatformIdentityProviderOptions::new("https://platform.example");
        options.idempotency_keys = Some(Arc::new(SequencePlatformKeys(Mutex::new(
            VecDeque::from(["invalid\nkey".to_owned()]),
        ))));
        options.transport = Some(invalid_key);
        assert!(
            PlatformIdentityProvider::new(options)
                .expect("Platform provider")
                .get_or_create_identity(IdentityRequest {
                    inspection: inspection(),
                })
                .await
                .expect_err("invalid HTTP field")
                .to_string()
                .contains("HTTP field value")
        );
    });
}

fn platform_claims() -> ClientAssertionClaims {
    ClientAssertionClaims {
        aud: "did:web:service.example".to_owned(),
        exp: 1_788_177_900,
        iat: 1_788_177_600,
        iss: "did:web:platform.example:agents:one".to_owned(),
        jti: "assertion-one".to_owned(),
        op: AssertionOperation::Enroll,
        resource: None,
        sub: "did:web:platform.example:agents:one".to_owned(),
        additional: BTreeMap::new(),
    }
}

#[test]
fn executes_agent_lifecycle_and_uses_then_revokes_credential() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        transport.push_json(
            StatusCode::OK,
            inspect_document(serde_json::json!({"methods": ["api-key", "aep-jwt"]})),
        );
        transport.push_json(StatusCode::OK, serde_json::json!({"status": "active"}));
        transport.push_json(StatusCode::OK, serde_json::json!({"status": "active"}));
        transport.push_json(StatusCode::OK, serde_json::json!({
            "api_key": "secret", "credential_id": "credential-1", "expires_at": "2026-09-01T12:00:00Z",
            "header": "X-Agent-Key", "scopes": ["purchase"]
        }));
        transport.push_json(StatusCode::OK, serde_json::json!({}));
        let signer = Arc::new(RecordingSigner::default());
        let session = client(transport.clone(), signer.clone())
            .service("service.example/catalog")
            .expect("session");

        let missing = session
            .enroll(EnrollOptions::default())
            .await
            .expect_err("required Claim must fail");
        assert!(matches!(missing, AgentError::ClaimRequirements { .. }));
        let claims = ClaimValues {
            contact_email: Some("buyer@example.com".to_owned()),
            ..ClaimValues::default()
        };
        assert_eq!(
            session
                .enroll(EnrollOptions {
                    claims: Some(claims),
                    idempotency_key: Some("enroll-1".to_owned())
                })
                .await
                .expect("enroll")
                .body
                .status,
            AgentStatus::Active
        );

        let grant = session
            .grant(GrantOptions {
                grant_type: Some(GrantType::ApiKey),
                idempotency_key: Some("grant-1".to_owned()),
                preferred_grant_types: Vec::new(),
                requested_scopes: vec!["purchase".to_owned()],
            })
            .await
            .expect("grant");
        assert!(matches!(
            grant.body.credential,
            Some(BuiltInGrantResponse::ApiKey(_))
        ));
        let resource = Url::parse("https://service.example/orders").expect("resource URL");
        let authentication = session
            .authentication(AuthenticationOptions {
                carrier: AuthorizationCarrier::Standard,
                client_assertion_only: false,
                credential_id: None,
                grant_type: None,
                resource: resource.clone(),
            })
            .await
            .expect("credential authentication");
        assert_eq!(authentication.method, AuthenticationMethod::ApiKey);
        assert_eq!(authentication.headers["X-Agent-Key"], "secret");

        session
            .revoke(RevokeOptions {
                all_grant_types: false,
                credential_id: Some("credential-1".to_owned()),
                grant_type: Some(GrantType::ApiKey),
                idempotency_key: Some("revoke-1".to_owned()),
            })
            .await
            .expect("revoke");
        let authentication = session
            .authentication(AuthenticationOptions {
                carrier: AuthorizationCarrier::Dedicated,
                client_assertion_only: false,
                credential_id: None,
                grant_type: None,
                resource,
            })
            .await
            .expect("JWT fallback");
        assert_eq!(authentication.method, AuthenticationMethod::AepJwt);
        assert_eq!(
            authentication.headers[AUTHORIZATION_HEADER],
            "AEP signed.assertion.value"
        );

        let requests = transport.requests.lock().expect("requests lock");
        assert_eq!(
            requests
                .iter()
                .map(|request| (request.method.clone(), request.url.path().to_owned()))
                .collect::<Vec<_>>(),
            vec![
                (Method::GET, WELL_KNOWN_PATH.to_owned()),
                (Method::POST, "/aep/enroll".to_owned()),
                (Method::GET, "/aep/status".to_owned()),
                (Method::POST, "/aep/grant".to_owned()),
                (Method::POST, "/aep/revoke".to_owned()),
            ]
        );
        assert_eq!(requests[1].headers["idempotency-key"], "enroll-1");
        assert_eq!(requests[3].headers["idempotency-key"], "grant-1");
        assert!(requests[1..].iter().all(|request| {
            request.headers[header::AUTHORIZATION]
                .to_str()
                .expect("authorization")
                .starts_with("AEP ")
        }));
        let signed = signer.claims.lock().expect("claims lock");
        assert!(
            signed
                .iter()
                .any(|claims| claims.op == AssertionOperation::Authenticate
                    && claims.resource.as_deref() == Some("https://service.example/orders"))
        );
    });
}

#[test]
fn caches_inspection_and_does_not_infer_jwt_authentication() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        transport.push_json(StatusCode::OK, inspect_document(serde_json::Value::Null));
        let session = client(transport.clone(), Arc::new(RecordingSigner::default()))
            .service("https://service.example")
            .expect("session");
        session.inspect().await.expect("first Inspect");
        session.inspect().await.expect("cached Inspect");
        let error = session
            .authentication(AuthenticationOptions {
                carrier: AuthorizationCarrier::Standard,
                client_assertion_only: false,
                credential_id: None,
                grant_type: None,
                resource: Url::parse("https://service.example/resource").expect("resource"),
            })
            .await
            .expect_err("omitted authentication must not imply JWT");
        assert!(matches!(error, AgentError::NoAuthenticationMethod));
        assert_eq!(transport.requests.lock().expect("requests lock").len(), 1);
    });
}

#[test]
fn rejects_cross_origin_inspect_redirect() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        let mut headers = HeaderMap::new();
        headers.insert(
            header::LOCATION,
            HeaderValue::from_static("https://other.example/.well-known/aep"),
        );
        transport
            .responses
            .lock()
            .expect("responses lock")
            .push_back(Response {
                status: StatusCode::FOUND,
                headers,
                body: Vec::new(),
                final_url: None,
            });
        let session = client(transport, Arc::new(RecordingSigner::default()))
            .service("service.example")
            .expect("session");
        let error = session.inspect().await.expect_err("cross-origin redirect");
        assert!(matches!(
            error,
            AgentError::Inspect {
                code: InspectErrorCode::InvalidRedirect,
                ..
            }
        ));
    });
}

#[test]
fn conditionally_revalidates_stale_inspection() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        let mut first_headers = HeaderMap::new();
        first_headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(MEDIA_TYPE));
        first_headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("max-age=0"));
        first_headers.insert(header::ETAG, HeaderValue::from_static("\"one\""));
        transport.push(Response {
            status: StatusCode::OK,
            headers: first_headers,
            body: serde_json::to_vec(&inspect_document(serde_json::Value::Null)).expect("JSON"),
            final_url: None,
        });
        let mut second_headers = HeaderMap::new();
        second_headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("max-age=60"),
        );
        transport.push(Response {
            status: StatusCode::NOT_MODIFIED,
            headers: second_headers,
            body: Vec::new(),
            final_url: None,
        });
        let session = client(transport.clone(), Arc::new(RecordingSigner::default()))
            .service("service.example")
            .expect("session");
        session.inspect().await.expect("initial Inspect");
        let second = session.inspect().await.expect("conditional Inspect");
        assert_eq!(second.cache_control.as_deref(), Some("max-age=60"));
        let requests = transport.requests.lock().expect("requests lock");
        assert_eq!(requests[1].headers[header::IF_NONE_MATCH], "\"one\"");
    });
}

#[test]
fn classifies_inspect_failures() {
    block_on(async {
        let cases = vec![
            (
                Response {
                    status: StatusCode::NOT_FOUND,
                    headers: HeaderMap::new(),
                    body: Vec::new(),
                    final_url: None,
                },
                InspectErrorCode::HttpError,
            ),
            (
                Response {
                    status: StatusCode::OK,
                    headers: HeaderMap::new(),
                    body: b"{}".to_vec(),
                    final_url: None,
                },
                InspectErrorCode::InvalidMediaType,
            ),
            (aep_response(b"{".to_vec()), InspectErrorCode::InvalidJson),
            (
                aep_response(b"{}".to_vec()),
                InspectErrorCode::ValidationFailed,
            ),
            (
                aep_response(vec![b' '; (1 << 20) + 1]),
                InspectErrorCode::ResponseTooLarge,
            ),
            (
                Response {
                    status: StatusCode::OK,
                    headers: aep_headers(),
                    body: serde_json::to_vec(&inspect_document(serde_json::Value::Null))
                        .expect("JSON"),
                    final_url: Some(Url::parse("https://service.example/elsewhere").expect("URL")),
                },
                InspectErrorCode::InvalidRedirect,
            ),
        ];
        for (response, expected) in cases {
            let transport = Arc::new(ScriptedTransport::default());
            transport.push(response);
            let session = client(transport, Arc::new(RecordingSigner::default()))
                .service("service.example")
                .expect("session");
            let error = session.inspect().await.expect_err("Inspect must fail");
            assert!(matches!(error, AgentError::Inspect { code, .. } if code == expected));
        }
    });
}

#[test]
fn validates_client_configuration_service_references_and_resources() {
    block_on(async {
        let provider: Arc<dyn IdentityProvider> = Arc::new(TestIdentityProvider {
            signer: Arc::new(RecordingSigner::default()),
        });
        let mut invalid = ClientOptions::new(provider.clone());
        invalid.assertion_lifetime = std::time::Duration::ZERO;
        assert!(Client::new(invalid).is_err());
        let mut invalid = ClientOptions::new(provider.clone());
        invalid.maximum_response_bytes = 0;
        assert!(Client::new(invalid).is_err());
        let mut invalid = ClientOptions::new(provider);
        invalid.request_timeout = std::time::Duration::ZERO;
        assert!(Client::new(invalid).is_err());

        let transport = Arc::new(ScriptedTransport::default());
        transport.push_json(
            StatusCode::OK,
            inspect_document(serde_json::json!({"methods": ["aep-jwt"]})),
        );
        let client = client(transport, Arc::new(RecordingSigner::default()));
        assert!(client.service("").is_err());
        assert!(client.service("http://service.example").is_err());
        assert!(client.service("https://user:pass@service.example").is_err());
        let session = client
            .service("did:web:service.example")
            .expect("DID Service reference");
        assert_eq!(session.service_url().as_str(), "https://service.example/");
        let error = session
            .authentication(AuthenticationOptions {
                carrier: AuthorizationCarrier::Standard,
                client_assertion_only: false,
                credential_id: None,
                grant_type: None,
                resource: Url::parse("https://other.example/resource").expect("URL"),
            })
            .await
            .expect_err("cross-origin resource");
        assert!(matches!(error, AgentError::InvalidServiceReference(_)));
    });
}

#[test]
fn reports_command_failures_and_rejects_unadvertised_operations() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        let mut document = inspect_document(serde_json::json!({"methods": ["aep-jwt"]}));
        document["commands"]["supported"] = serde_json::json!(["inspect", "enroll"]);
        document["commands"]
            .as_object_mut()
            .expect("commands")
            .remove("grant_types");
        document["commands"]
            .as_object_mut()
            .expect("commands")
            .remove("grant_types_config");
        transport.push_json(StatusCode::OK, document);
        let session = client(transport, Arc::new(RecordingSigner::default()))
            .service("service.example")
            .expect("session");
        assert!(matches!(
            session.status().await,
            Err(AgentError::CommandNotAdvertised(_))
        ));

        let transport = Arc::new(ScriptedTransport::default());
        transport.push_json(
            StatusCode::OK,
            inspect_document(serde_json::json!({"methods": ["aep-jwt"]})),
        );
        let problem = serde_json::json!({
            "type": "urn:aep:error:verification_pending", "title": "Pending", "status": 409,
            "code": "verification_pending", "verification_pending": ["owner_approval"]
        });
        transport.push_json(StatusCode::CONFLICT, problem);
        let session = client(transport, Arc::new(RecordingSigner::default()))
            .service("service.example")
            .expect("session");
        let error = session.status().await.expect_err("Problem Details");
        assert!(matches!(
            error,
            AgentError::Command {
                status: 409,
                problem: Some(_)
            }
        ));
    });
}

#[test]
fn memory_stores_copy_select_expire_and_delete_records() {
    block_on(async {
        let clock: Arc<dyn Clock> = Arc::new(FixedClock(
            OffsetDateTime::parse("2026-08-31T12:00:00Z", &Rfc3339).expect("time"),
        ));
        let identities = MemoryIdentityStore::default();
        assert!(
            identities
                .find("did:web:service.example")
                .await
                .expect("find")
                .is_none()
        );
        let identity = AgentIdentity {
            agent_did: "did:web:agent.example".to_owned(),
            identity_method: IdentityMethod::DidWeb,
            service_did: "did:web:service.example".to_owned(),
            signing_algorithms: vec![SigningAlgorithm::EdDsa],
            metadata: BTreeMap::new(),
        };
        identities.save(identity.clone()).await.expect("save");
        assert_eq!(
            identities.find(&identity.service_did).await.expect("find"),
            Some(identity)
        );

        let credentials = MemoryCredentialStore::new(clock);
        let payload = serde_json::json!({
            "api_key": "secret", "credential_id": "one", "expires_at": "2026-09-01T12:00:00Z", "header": "X-Key"
        });
        let record = CredentialRecord {
            credential_id: "one".to_owned(),
            expires_at: OffsetDateTime::parse("2026-09-01T12:00:00Z", &Rfc3339).expect("expiry"),
            grant_type: GrantType::ApiKey,
            issued_at: OffsetDateTime::parse("2026-08-31T12:00:00Z", &Rfc3339).expect("issued"),
            payload,
            service_did: "did:web:service.example".to_owned(),
            service_url: Url::parse("https://service.example").expect("URL"),
        };
        credentials.save(record.clone()).await.expect("save");
        assert_eq!(
            credentials
                .find(&record.service_did, "one")
                .await
                .expect("find"),
            Some(record.clone())
        );
        assert_eq!(
            credentials.list(&record.service_did).await.expect("list"),
            vec![record]
        );
        credentials
            .delete("did:web:service.example", "one")
            .await
            .expect("delete");
        assert!(
            credentials
                .list("did:web:service.example")
                .await
                .expect("list")
                .is_empty()
        );
    });
}

#[test]
fn presents_oauth_and_basic_credentials_and_validates_selection() {
    block_on(async {
        let now = OffsetDateTime::parse("2026-08-31T12:00:00Z", &Rfc3339).expect("time");
        let clock: Arc<dyn Clock> = Arc::new(FixedClock(now));
        let credentials: Arc<dyn CredentialStore> =
            Arc::new(MemoryCredentialStore::new(clock.clone()));
        for (credential_id, grant_type, payload) in [
            (
                "oauth",
                GrantType::OAuthBearer,
                serde_json::json!({
                    "access_token": "token", "credential_id": "oauth", "expires_at": "2026-09-01T12:00:00Z", "scopes": null, "token_type": "Bearer"
                }),
            ),
            (
                "basic",
                GrantType::Basic,
                serde_json::json!({
                    "credential_id": "basic", "expires_at": "2026-09-01T12:00:00Z", "password": "pass", "scopes": [], "username": "user"
                }),
            ),
        ] {
            credentials
                .save(CredentialRecord {
                    credential_id: credential_id.to_owned(),
                    expires_at: OffsetDateTime::parse("2026-09-01T12:00:00Z", &Rfc3339)
                        .expect("expiry"),
                    grant_type,
                    issued_at: now,
                    payload,
                    service_did: "did:web:service.example".to_owned(),
                    service_url: Url::parse("https://service.example").expect("URL"),
                })
                .await
                .expect("save credential");
        }
        let transport = Arc::new(ScriptedTransport::default());
        transport.push_json(
            StatusCode::OK,
            inspect_document(serde_json::json!({"methods": ["oauth-bearer", "basic", "aep-jwt"]})),
        );
        let provider = Arc::new(TestIdentityProvider {
            signer: Arc::new(RecordingSigner::default()),
        });
        let mut options = ClientOptions::new(provider);
        options.clock = Some(clock);
        options.credential_store = Some(credentials);
        options.command_transport = Some(transport.clone());
        options.inspect_transport = Some(transport);
        let session = Client::new(options)
            .expect("client")
            .service("service.example")
            .expect("session");
        let resource = Url::parse("https://service.example/orders").expect("resource");
        let oauth = session
            .authentication(AuthenticationOptions {
                carrier: AuthorizationCarrier::Standard,
                client_assertion_only: false,
                credential_id: None,
                grant_type: None,
                resource: resource.clone(),
            })
            .await
            .expect("OAuth");
        assert_eq!(oauth.method, AuthenticationMethod::OAuthBearer);
        assert_eq!(oauth.headers[header::AUTHORIZATION], "Bearer token");
        let basic = session
            .authentication(AuthenticationOptions {
                carrier: AuthorizationCarrier::Dedicated,
                client_assertion_only: false,
                credential_id: Some("basic".to_owned()),
                grant_type: Some(GrantType::Basic),
                resource: resource.clone(),
            })
            .await
            .expect("Basic");
        assert_eq!(basic.method, AuthenticationMethod::Basic);
        assert_eq!(basic.headers[AUTHORIZATION_HEADER], "Basic dXNlcjpwYXNz");
        assert!(
            session
                .authentication(AuthenticationOptions {
                    carrier: AuthorizationCarrier::Standard,
                    client_assertion_only: true,
                    credential_id: Some("oauth".to_owned()),
                    grant_type: None,
                    resource: resource.clone(),
                })
                .await
                .is_err()
        );
        assert!(
            session
                .authentication(AuthenticationOptions {
                    carrier: AuthorizationCarrier::Standard,
                    client_assertion_only: false,
                    credential_id: Some("missing".to_owned()),
                    grant_type: None,
                    resource,
                })
                .await
                .is_err()
        );
        session.forget_credential("oauth").await.expect("forget");
        assert!(session.forget_credential("").await.is_err());
    });
}

#[test]
fn polls_until_active_and_reports_terminal_states() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        transport.push_json(
            StatusCode::OK,
            inspect_document(serde_json::json!({"methods": ["aep-jwt"]})),
        );
        transport.push_json(StatusCode::OK, serde_json::json!({"status": "pending"}));
        transport.push_json(StatusCode::OK, serde_json::json!({"status": "active"}));
        let clock = Arc::new(AdvancingClock(Mutex::new(
            OffsetDateTime::parse("2026-08-31T12:00:00Z", &Rfc3339).expect("time"),
        )));
        let provider = Arc::new(TestIdentityProvider {
            signer: Arc::new(RecordingSigner::default()),
        });
        let mut options = ClientOptions::new(provider);
        options.clock = Some(clock.clone());
        options.delay = Some(Arc::new(AdvancingDelay { clock }));
        options.command_transport = Some(transport.clone());
        options.inspect_transport = Some(transport);
        let session = Client::new(options)
            .expect("client")
            .service("service.example")
            .expect("session");
        assert_eq!(
            session
                .wait_for_active(WaitOptions {
                    interval: std::time::Duration::from_secs(1),
                    timeout: std::time::Duration::from_secs(5)
                })
                .await
                .expect("active")
                .body
                .status,
            AgentStatus::Active
        );
        assert!(
            session
                .wait_for_active(WaitOptions {
                    interval: std::time::Duration::ZERO,
                    timeout: std::time::Duration::from_secs(1)
                })
                .await
                .is_err()
        );

        let transport = Arc::new(ScriptedTransport::default());
        transport.push_json(
            StatusCode::OK,
            inspect_document(serde_json::json!({"methods": ["aep-jwt"]})),
        );
        transport.push_json(StatusCode::OK, serde_json::json!({"status": "rejected"}));
        let session = client(transport, Arc::new(RecordingSigner::default()))
            .service("service.example")
            .expect("session");
        assert!(matches!(
            session.wait_for_active(WaitOptions::default()).await,
            Err(AgentError::EnrollmentState {
                status: AgentStatus::Rejected
            })
        ));
    });
}

#[test]
fn follows_safe_inspect_redirect_and_honors_no_store() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        let mut redirect_headers = HeaderMap::new();
        redirect_headers.insert(header::LOCATION, HeaderValue::from_static("/aep-document"));
        transport.push(Response {
            status: StatusCode::TEMPORARY_REDIRECT,
            headers: redirect_headers,
            body: Vec::new(),
            final_url: None,
        });
        let mut headers = aep_headers();
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        let body = serde_json::to_vec(&inspect_document(serde_json::Value::Null)).expect("JSON");
        transport.push(Response {
            status: StatusCode::OK,
            headers: headers.clone(),
            body: body.clone(),
            final_url: None,
        });
        transport.push(Response {
            status: StatusCode::OK,
            headers,
            body,
            final_url: None,
        });
        let session = client(transport.clone(), Arc::new(RecordingSigner::default()))
            .service("service.example")
            .expect("session");
        assert_eq!(
            session
                .inspect()
                .await
                .expect("redirected Inspect")
                .final_url
                .path(),
            "/aep-document"
        );
        session.inspect().await.expect("uncached Inspect");
        assert_eq!(transport.requests.lock().expect("requests lock").len(), 3);
    });
}

#[test]
fn coalesces_concurrent_inspection_for_a_session() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        transport.push_json(StatusCode::OK, inspect_document(serde_json::Value::Null));
        let session = client(transport.clone(), Arc::new(RecordingSigner::default()))
            .service("service.example")
            .expect("session");
        let (first, second) = futures::join!(session.inspect(), session.inspect());
        assert!(first.is_ok() && second.is_ok());
        assert_eq!(transport.requests.lock().expect("requests lock").len(), 1);
    });
}

#[test]
fn requires_enrollment_before_grant_and_accepts_extension_grants() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        transport.push_json(
            StatusCode::OK,
            inspect_document(serde_json::json!({"methods": ["aep-jwt"]})),
        );
        let session = client(transport, Arc::new(RecordingSigner::default()))
            .service("service.example")
            .expect("session");
        assert!(matches!(
            session.grant(GrantOptions::default()).await,
            Err(AgentError::Identity(_))
        ));

        let mut document =
            inspect_document(serde_json::json!({"methods": ["custom-session", "aep-jwt"]}));
        document["commands"]["grant_types"] = serde_json::json!(["custom-session"]);
        document["commands"]["grant_types_config"] = serde_json::json!({});
        let transport = Arc::new(ScriptedTransport::default());
        transport.push_json(StatusCode::OK, document);
        transport.push_json(StatusCode::OK, serde_json::json!({"status": "active"}));
        transport.push_json(
            StatusCode::OK,
            serde_json::json!({"credential_id": "custom-1", "value": "opaque"}),
        );
        let identity_store = Arc::new(MemoryIdentityStore::default());
        identity_store
            .save(AgentIdentity {
                agent_did: "did:web:agent.example:agents:one".to_owned(),
                identity_method: IdentityMethod::DidWeb,
                service_did: "did:web:service.example".to_owned(),
                signing_algorithms: vec![SigningAlgorithm::EdDsa, SigningAlgorithm::Es256],
                metadata: BTreeMap::new(),
            })
            .await
            .expect("identity");
        let provider = Arc::new(TestIdentityProvider {
            signer: Arc::new(RecordingSigner::default()),
        });
        let mut options = ClientOptions::new(provider);
        options.identity_store = Some(identity_store);
        options.command_transport = Some(transport.clone());
        options.inspect_transport = Some(transport);
        let session = Client::new(options)
            .expect("client")
            .service("service.example")
            .expect("session");
        let result = session
            .grant(GrantOptions {
                grant_type: Some(GrantType::Other("custom-session".to_owned())),
                idempotency_key: None,
                preferred_grant_types: Vec::new(),
                requested_scopes: Vec::new(),
            })
            .await
            .expect("extension grant");
        assert!(result.body.credential.is_none());
        assert_eq!(result.body.raw["credential_id"], "custom-1");
        assert!(
            session
                .revoke(RevokeOptions {
                    all_grant_types: true,
                    credential_id: Some("invalid".to_owned()),
                    ..RevokeOptions::default()
                })
                .await
                .is_err()
        );
    });
}

fn aep_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(MEDIA_TYPE));
    headers
}

fn aep_response(body: Vec<u8>) -> Response {
    Response {
        status: StatusCode::OK,
        headers: aep_headers(),
        body,
        final_url: None,
    }
}

#[test]
fn redacts_agent_credentials_from_debug_output() {
    let issued_at = OffsetDateTime::parse("2026-08-31T12:00:00Z", &Rfc3339).expect("time");
    let record = CredentialRecord {
        credential_id: "credential-1".to_owned(),
        expires_at: issued_at + time::Duration::hours(1),
        grant_type: GrantType::ApiKey,
        issued_at,
        payload: serde_json::json!({"api_key": "record-secret"}),
        service_did: "did:web:service.example".to_owned(),
        service_url: Url::parse("https://service.example").expect("URL"),
    };
    let grant = GrantResult {
        credential: None,
        grant_type: GrantType::Other("custom".to_owned()),
        raw: serde_json::json!({"credential": "grant-secret"}),
    };
    let authentication = AuthenticationResult {
        headers: HeaderMap::from_iter([(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer authentication-secret"),
        )]),
        method: AuthenticationMethod::OAuthBearer,
    };
    let authentication_options = AuthenticationOptions {
        carrier: AuthorizationCarrier::Standard,
        client_assertion_only: false,
        credential_id: Some("credential-1".to_owned()),
        grant_type: Some(GrantType::ApiKey),
        resource: Url::parse("https://service.example/path?token=options-secret").expect("URL"),
    };
    let pending = PlatformPendingSign {
        identity: AgentIdentity {
            agent_did: "did:web:agent.example".to_owned(),
            identity_method: IdentityMethod::DidWeb,
            metadata: BTreeMap::new(),
            service_did: "did:web:service.example".to_owned(),
            signing_algorithms: vec![SigningAlgorithm::EdDsa],
        },
        platform_context: BTreeMap::from([(
            "credential".to_owned(),
            serde_json::json!("context-secret"),
        )]),
        retry_after: std::time::Duration::from_secs(1),
    };
    for output in [
        format!("{record:?}"),
        format!("{grant:?}"),
        format!("{authentication:?}"),
        format!("{authentication_options:?}"),
        format!("{pending:?}"),
    ] {
        assert!(!output.contains("secret"));
        assert!(output.contains("[REDACTED]"));
    }
}

#[tokio::test]
async fn reqwest_transport_sends_requests_and_bounds_responses() {
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
    let address = listener.local_addr().expect("address");
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("connection");
        let mut request = [0_u8; 2048];
        let read = stream.read(&mut request).expect("request");
        assert!(String::from_utf8_lossy(&request[..read]).starts_with("GET /inspect HTTP/1.1"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .expect("response");
    });
    let transport = ReqwestTransport::new(2, std::time::Duration::from_secs(2)).expect("transport");
    let response = transport
        .send(HttpRequest {
            method: Method::GET,
            url: Url::parse(&format!("http://{address}/inspect")).expect("URL"),
            headers: HeaderMap::new(),
            body: Vec::new(),
        })
        .await
        .expect("response");
    assert_eq!(response.body, b"ok");
    server.join().expect("server thread");

    let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
    let address = listener.local_addr().expect("address");
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("connection");
        let mut request = [0_u8; 2048];
        let _ = stream.read(&mut request).expect("request");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\ntoo")
            .expect("response");
    });
    let error = transport
        .send(HttpRequest {
            method: Method::GET,
            url: Url::parse(&format!("http://{address}/large")).expect("URL"),
            headers: HeaderMap::new(),
            body: Vec::new(),
        })
        .await
        .expect_err("bounded response");
    assert!(error.to_string().contains("configured limit"));
    server.join().expect("server thread");
}
