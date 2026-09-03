use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use aep_core::*;
use aep_service::*;
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use futures::executor::block_on;
use http::{HeaderMap, HeaderValue, header};
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;

struct DidDocumentTransport;

#[async_trait]
impl HttpTransport for DidDocumentTransport {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        assert_eq!(
            request.url.as_str(),
            "https://agent.example/.well-known/did.json"
        );
        let public_key = SigningKey::from_bytes(&[7; 32]).verifying_key();
        Ok(HttpResponse {
            body: serde_json::to_vec(&json!({
                "verificationMethod": [{
                    "id": "did:web:agent.example#key-1",
                    "publicKeyJwk": {
                        "alg": "EdDSA",
                        "crv": "Ed25519",
                        "kid": "did:web:agent.example#key-1",
                        "kty": "OKP",
                        "use": "sig",
                        "x": URL_SAFE_NO_PAD.encode(public_key.as_bytes())
                    }
                }]
            }))
            .expect("DID document"),
            final_url: request.url,
            headers: HeaderMap::new(),
            status: http::StatusCode::OK,
        })
    }
}

#[derive(Clone)]
struct FixedClock(OffsetDateTime);

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

#[derive(Default)]
struct RecordingVerifier {
    contexts: Mutex<Vec<ClientAssertionVerificationContext>>,
}

#[async_trait]
impl ClientAssertionVerifier for RecordingVerifier {
    async fn verify(
        &self,
        context: ClientAssertionVerificationContext,
    ) -> Result<ClientAssertionClaims, ServiceError> {
        self.contexts
            .lock()
            .expect("contexts lock")
            .push(context.clone());
        let timestamp = context.current_time.unix_timestamp();
        Ok(ClientAssertionClaims {
            additional: BTreeMap::new(),
            aud: context.service_did,
            exp: timestamp + 60,
            iat: timestamp,
            iss: agent_did().to_owned(),
            jti: context.assertion,
            op: context.operation,
            resource: context.resource.map(|resource| resource.to_string()),
            sub: agent_did().to_owned(),
        })
    }
}

struct ExpirationBoundaryVerifier;

#[async_trait]
impl ClientAssertionVerifier for ExpirationBoundaryVerifier {
    async fn verify(
        &self,
        context: ClientAssertionVerificationContext,
    ) -> Result<ClientAssertionClaims, ServiceError> {
        let expiration = context.current_time.unix_timestamp() - 30;
        Ok(ClientAssertionClaims {
            additional: BTreeMap::new(),
            aud: context.service_did,
            exp: expiration,
            iat: expiration - 60,
            iss: agent_did().to_owned(),
            jti: "expiration-boundary".to_owned(),
            op: context.operation,
            resource: context.resource.map(|resource| resource.to_string()),
            sub: agent_did().to_owned(),
        })
    }
}

#[derive(Default)]
struct RecordingGrantHandler {
    grants: Mutex<Vec<GrantRequest>>,
    revocations: Mutex<Vec<RevokeRequest>>,
}

#[async_trait]
impl GrantTypeHandler for RecordingGrantHandler {
    async fn grant(
        &self,
        request: &GrantRequest,
        context: &GrantContext,
    ) -> Result<Value, ServiceError> {
        assert_eq!(context.agent_did, agent_did());
        assert_eq!(context.enrollment.status, AgentStatus::Active);
        self.grants
            .lock()
            .expect("grants lock")
            .push(request.clone());
        Ok(json!({
            "api_key": "secret",
            "credential_id": "credential-1",
            "expires_at": "2026-09-01T12:00:00Z",
            "header": "X-Agent-Key"
        }))
    }

    async fn revoke(
        &self,
        request: &RevokeRequest,
        _context: &GrantContext,
    ) -> Result<(), ServiceError> {
        self.revocations
            .lock()
            .expect("revocations lock")
            .push(request.clone());
        Ok(())
    }

    async fn authenticate(
        &self,
        input: &CredentialAuthenticationInput,
    ) -> Result<Option<AuthenticatedPrincipal>, ServiceError> {
        if input
            .headers
            .get("x-agent-key")
            .is_some_and(|value| value == "secret")
        {
            Ok(Some(AuthenticatedPrincipal {
                agent_did: agent_did().to_owned(),
                authentication_kind: AuthenticationKind::SessionCredential,
                authentication_method: AuthenticationMethod::ApiKey,
                credential_id: Some("credential-1".to_owned()),
                grant_type: Some(GrantType::ApiKey),
                scopes: vec!["purchase".to_owned()],
            }))
        } else {
            Ok(None)
        }
    }

    async fn has_presentation(
        &self,
        input: &CredentialAuthenticationInput,
    ) -> Result<bool, ServiceError> {
        Ok(input.headers.contains_key("x-agent-key"))
    }
}

struct TestService {
    grant_handler: Arc<RecordingGrantHandler>,
    service: Arc<Service>,
    store: Arc<MemoryEnrollmentStore>,
    verifier: Arc<RecordingVerifier>,
}

fn test_service() -> TestService {
    let verifier = Arc::new(RecordingVerifier::default());
    let store = Arc::new(MemoryEnrollmentStore::default());
    let grant_handler = Arc::new(RecordingGrantHandler::default());
    let mut options = ServiceOptions::new(service_did(), verifier.clone());
    options.authentication_methods =
        vec![AuthenticationMethod::AepJwt, AuthenticationMethod::ApiKey];
    options.claims.required = vec![ClaimName::ContactEmail];
    options.clock = Some(Arc::new(FixedClock(fixed_time())));
    options.enrollment_store = Some(store.clone());
    options.grant_types = vec![GrantTypeDefinition {
        config: Some(GrantTypeConfig {
            additional: BTreeMap::new(),
            supports_per_credential_revoke: Some(StringBoolean::True),
        }),
        grant_type: GrantType::ApiKey,
        handler: Some(grant_handler.clone()),
    }];
    options.inspect_url =
        Some(Url::parse("https://service.example/.well-known/aep").expect("inspect URL"));
    TestService {
        grant_handler,
        service: Service::new(options).expect("Service"),
        store,
        verifier,
    }
}

#[test]
fn builds_inspect_from_the_enabled_service_contract() {
    let test = test_service();
    let inspect = test.service.inspect_document();
    assert_eq!(inspect.aep_version, VERSION);
    assert_eq!(
        inspect.commands.supported,
        vec![
            Command::Enroll,
            Command::Grant,
            Command::Inspect,
            Command::Revoke,
            Command::Status
        ]
    );
    assert_eq!(inspect.commands.grant_types, vec![GrantType::ApiKey]);
    assert_eq!(
        inspect
            .authentication
            .as_ref()
            .expect("authentication")
            .methods,
        vec![AuthenticationMethod::AepJwt, AuthenticationMethod::ApiKey]
    );
    validate_inspect_document(&inspect).expect("valid Inspect document");
}

#[test]
fn enrolls_reports_status_and_replays_an_existing_lifecycle() {
    block_on(async {
        let test = test_service();
        let missing = test
            .service
            .enroll(
                br#"{"agent_did":"did:web:agent.example"}"#,
                idempotent("enroll-missing", "key-missing"),
            )
            .await
            .expect("missing Claim response");
        assert_problem(&missing, ErrorCode::RequirementsUnmet, 403);
        let ResponseBody::Problem(problem) = missing.body else {
            panic!("Problem Details expected");
        };
        assert_eq!(
            problem.requirements_pending,
            Some(vec!["contact.email".to_owned()])
        );

        let response = test
            .service
            .enroll(enroll_request(), idempotent("enroll-1", "key-1"))
            .await
            .expect("Enroll response");
        assert_enrollment_status(&response, AgentStatus::Active);

        let status = test
            .service
            .status(authenticated("status-1"))
            .await
            .expect("Status response");
        let ResponseBody::Status(status) = status.body else {
            panic!("Status response expected");
        };
        assert_eq!(status.status, AgentStatus::Active);
        assert_eq!(status.since.as_deref(), Some("2026-08-31T12:00:00Z"));

        let mut record = test
            .store
            .find(agent_did())
            .await
            .expect("store")
            .expect("enrollment");
        record.status = AgentStatus::Suspended;
        test.store.save(record).await.expect("store");
        let repeated = test
            .service
            .enroll(enroll_request(), idempotent("enroll-2", "key-2"))
            .await
            .expect("repeated Enroll response");
        assert_enrollment_status(&repeated, AgentStatus::Suspended);
        let operations = test
            .verifier
            .contexts
            .lock()
            .expect("contexts lock")
            .iter()
            .map(|context| context.operation)
            .collect::<Vec<_>>();
        assert_eq!(
            operations,
            vec![
                AssertionOperation::Enroll,
                AssertionOperation::Enroll,
                AssertionOperation::Status,
                AssertionOperation::Enroll
            ]
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer secret"),
        );
        let result = test
            .service
            .authenticate_protected_resource(ProtectedResourceRequest {
                headers,
                method: http::Method::GET,
                url: Url::parse("https://service.example/catalog").expect("resource URL"),
            })
            .await
            .expect("unsupported method");
        let ProtectedResourceAuthentication::Rejected(response) = result else {
            panic!("rejection expected");
        };
        assert_problem(&response, ErrorCode::UnsupportedAuthenticationMethod, 401);
    });
}

#[test]
fn applies_command_idempotency_and_dispatches_grant_and_revoke() {
    block_on(async {
        let test = test_service();
        enroll(&test, "enroll-1", "enroll-key").await;
        let grant = br#"{"grant_type":"api-key","requested_scopes":["purchase"]}"#;
        let first = test
            .service
            .grant(grant, idempotent("grant-1", "grant-key"))
            .await
            .expect("Grant response");
        assert_eq!(first.status, 200);
        assert!(matches!(first.body, ResponseBody::Grant(_)));
        let replay = test
            .service
            .grant(grant, idempotent("grant-2", "grant-key"))
            .await
            .expect("Grant replay");
        assert_eq!(first, replay);
        assert_eq!(
            test.grant_handler.grants.lock().expect("grants lock").len(),
            1
        );

        let conflict = test
            .service
            .grant(
                br#"{"grant_type":"api-key","requested_scopes":["other"]}"#,
                idempotent("grant-3", "grant-key"),
            )
            .await
            .expect("Grant conflict");
        assert_problem(&conflict, ErrorCode::IdempotencyConflict, 409);

        let revoke = test
            .service
            .revoke(
                br#"{"grant_type":"api-key","credential_id":"credential-1"}"#,
                idempotent("revoke-1", "revoke-key"),
            )
            .await
            .expect("Revoke response");
        assert!(matches!(revoke.body, ResponseBody::Revoke(_)));
        assert_eq!(
            test.grant_handler
                .revocations
                .lock()
                .expect("revocations lock")
                .len(),
            1
        );
    });
}

#[test]
fn enforces_lifecycle_before_grant() {
    block_on(async {
        let test = test_service();
        enroll(&test, "enroll-1", "enroll-key").await;
        let mut record = test
            .store
            .find(agent_did())
            .await
            .expect("store")
            .expect("enrollment");
        record.status = AgentStatus::Suspended;
        test.store.save(record).await.expect("store");
        let response = test
            .service
            .grant(
                br#"{"grant_type":"api-key"}"#,
                idempotent("grant-1", "grant-key"),
            )
            .await
            .expect("Grant response");
        assert_problem(&response, ErrorCode::IdentitySuspended, 403);
    });
}

#[test]
fn authenticates_assertions_and_session_credentials_at_protected_resources() {
    block_on(async {
        let test = test_service();
        enroll(&test, "enroll-1", "enroll-key").await;
        let resource = Url::parse("https://service.example/catalog/one").expect("resource URL");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("AEP resource-1"),
        );
        let result = test
            .service
            .authenticate_protected_resource(ProtectedResourceRequest {
                headers,
                method: http::Method::GET,
                url: resource.clone(),
            })
            .await
            .expect("resource authentication");
        let ProtectedResourceAuthentication::Authenticated(principal) = result else {
            panic!("authenticated principal expected");
        };
        assert_eq!(principal.agent_did, agent_did());
        assert_eq!(
            principal.authentication_method,
            AuthenticationMethod::AepJwt
        );

        let mut headers = HeaderMap::new();
        headers.insert("x-agent-key", HeaderValue::from_static("secret"));
        let result = test
            .service
            .authenticate_protected_resource(ProtectedResourceRequest {
                headers,
                method: http::Method::GET,
                url: resource.clone(),
            })
            .await
            .expect("session authentication");
        assert!(matches!(
            result,
            ProtectedResourceAuthentication::Authenticated(AuthenticatedPrincipal {
                authentication_kind: AuthenticationKind::SessionCredential,
                ..
            })
        ));

        let result = test
            .service
            .authenticate_protected_resource(ProtectedResourceRequest {
                headers: HeaderMap::new(),
                method: http::Method::GET,
                url: resource,
            })
            .await
            .expect("challenge");
        let ProtectedResourceAuthentication::Rejected(response) = result else {
            panic!("challenge expected");
        };
        assert_problem(&response, ErrorCode::AuthenticationRequired, 401);
        assert_eq!(
            response
                .headers
                .get(header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some(
                "AEP service_did=\"did:web:service.example\", inspect=\"https://service.example/.well-known/aep\", reason=\"authentication_required\""
            )
        );
    });
}

#[test]
fn rejects_replayed_assertions_and_ambiguous_authorization_carriers() {
    block_on(async {
        let test = test_service();
        enroll(&test, "enroll-1", "enroll-key").await;
        let first = test
            .service
            .status(authenticated("status-replay"))
            .await
            .expect("first Status");
        assert_eq!(first.status, 200);
        let replay = test
            .service
            .status(authenticated("status-replay"))
            .await
            .expect("replayed Status");
        assert_problem(&replay, ErrorCode::NotRecognized, 401);

        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("AEP first"));
        headers.insert(AUTHORIZATION_HEADER, HeaderValue::from_static("AEP second"));
        let result = test
            .service
            .authenticate_protected_resource(ProtectedResourceRequest {
                headers,
                method: http::Method::GET,
                url: Url::parse("https://service.example/catalog").expect("resource URL"),
            })
            .await
            .expect("ambiguous authorization");
        let ProtectedResourceAuthentication::Rejected(response) = result else {
            panic!("rejection expected");
        };
        assert_problem(&response, ErrorCode::NotRecognized, 401);
    });
}

#[test]
fn rejects_expiration_boundary_from_custom_verifier() {
    block_on(async {
        let mut options = ServiceOptions::new(service_did(), Arc::new(ExpirationBoundaryVerifier));
        options.clock = Some(Arc::new(FixedClock(fixed_time())));
        let service = Service::new(options).expect("Service");

        let response = service
            .status(authenticated("assertion"))
            .await
            .expect("Status response");

        assert_problem(&response, ErrorCode::NotRecognized, 401);
    });
}

#[test]
fn validates_service_configuration() {
    let verifier = Arc::new(RecordingVerifier::default());
    let mut options = ServiceOptions::new("not-a-did", verifier.clone());
    assert!(Service::new(options.clone()).is_err());
    options.service_did = service_did().to_owned();
    options.identity_methods = Vec::new();
    assert!(Service::new(options.clone()).is_err());
    options.identity_methods = vec![IdentityMethod::DidWeb];
    options.authentication_methods = vec![AuthenticationMethod::ApiKey];
    assert!(Service::new(options).is_err());
}

#[test]
fn verifies_a_real_did_web_client_assertion() {
    block_on(async {
        let timestamp = fixed_time().unix_timestamp();
        let claims = ClientAssertionClaims {
            additional: BTreeMap::new(),
            aud: service_did().to_owned(),
            exp: timestamp + 60,
            iat: timestamp,
            iss: agent_did().to_owned(),
            jti: "jti-real".to_owned(),
            op: AssertionOperation::Enroll,
            resource: None,
            sub: agent_did().to_owned(),
        };
        let signing_key = ClientAssertionSigningKey::ed25519_from_seed([7; 32]);
        let assertion = sign_client_assertion(
            &claims,
            SignClientAssertionOptions {
                allow_insecure_loopback: false,
                key: &signing_key,
                key_id: "did:web:agent.example#key-1",
            },
        )
        .expect("signed assertion");
        let verifier = DidWebClientAssertionVerifier::new(Arc::new(DidDocumentTransport), false);
        let verified = verifier
            .verify(ClientAssertionVerificationContext {
                assertion,
                current_time: fixed_time(),
                idempotency_key: Some("key-1".to_owned()),
                operation: AssertionOperation::Enroll,
                resource: None,
                service_did: service_did().to_owned(),
                signing_algorithms: vec![SigningAlgorithm::EdDsa, SigningAlgorithm::Es256],
            })
            .await
            .expect("verified assertion");
        assert_eq!(verified, claims);
    });
}

#[test]
fn coalesces_concurrent_idempotent_operations() {
    block_on(async {
        let store = MemoryCommandIdempotencyStore::default();
        let executions = Arc::new(AtomicUsize::new(0));
        let input = CommandIdempotencyInput {
            agent_did: agent_did().to_owned(),
            command: IdempotentCommand::Enroll,
            idempotency_key: "key-1".to_owned(),
            request_hash: "sha256:one".to_owned(),
        };
        let operation = |executions: Arc<AtomicUsize>| -> CommandOperation {
            Box::new(move || {
                Box::pin(async move {
                    executions.fetch_add(1, Ordering::SeqCst);
                    Ok(ServiceResponse {
                        body: ResponseBody::Enroll(EnrollResponse {
                            additional: BTreeMap::new(),
                            owner_action_required: None,
                            requirements_pending: None,
                            status: AgentStatus::Active,
                            verification_pending: None,
                        }),
                        headers: HeaderMap::new(),
                        status: 200,
                    })
                })
            })
        };
        let (first, second) = futures::join!(
            store.execute(input.clone(), operation(executions.clone())),
            store.execute(input, operation(executions.clone()))
        );
        assert!(matches!(
            first.expect("first"),
            CommandIdempotencyResult::Created(_)
        ));
        assert!(matches!(
            second.expect("second"),
            CommandIdempotencyResult::Replayed(_)
        ));
        assert_eq!(executions.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn redacts_service_credentials_from_debug_output() {
    let response = ServiceResponse {
        body: ResponseBody::Grant(json!({"api_key": "grant-secret"})),
        headers: HeaderMap::from_iter([(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer header-secret"),
        )]),
        status: 200,
    };
    let options = IdempotentCommandOptions {
        client_assertion: "assertion-secret".to_owned(),
        idempotency_key: "request-1".to_owned(),
    };
    let request = ProtectedResourceRequest {
        headers: response.headers.clone(),
        method: http::Method::GET,
        url: Url::parse("https://service.example/resource?token=url-secret").expect("URL"),
    };
    let assertion = ClientAssertionVerificationContext {
        assertion: "assertion-context-secret".to_owned(),
        current_time: fixed_time(),
        idempotency_key: Some("request-1".to_owned()),
        operation: AssertionOperation::Authenticate,
        resource: Some(request.url.clone()),
        service_did: service_did().to_owned(),
        signing_algorithms: vec![SigningAlgorithm::EdDsa],
    };
    let authentication = CredentialAuthenticationInput {
        headers: response.headers.clone(),
        now: fixed_time(),
    };
    let authenticated_options = AuthenticatedCommandOptions {
        client_assertion: "authenticated-secret".to_owned(),
    };
    for output in [
        format!("{response:?}"),
        format!("{options:?}"),
        format!("{request:?}"),
        format!("{assertion:?}"),
        format!("{authentication:?}"),
        format!("{authenticated_options:?}"),
    ] {
        assert!(!output.contains("secret"));
        assert!(output.contains("[REDACTED]"));
    }
}

async fn enroll(test: &TestService, assertion: &str, key: &str) {
    let response = test
        .service
        .enroll(enroll_request(), idempotent(assertion, key))
        .await
        .expect("Enroll response");
    assert_enrollment_status(&response, AgentStatus::Active);
}

fn enroll_request() -> &'static [u8] {
    br#"{"agent_did":"did:web:agent.example","claims":{"contact.email":"buyer@example.com"}}"#
}

fn authenticated(assertion: &str) -> AuthenticatedCommandOptions {
    AuthenticatedCommandOptions {
        client_assertion: assertion.to_owned(),
    }
}

fn idempotent(assertion: &str, key: &str) -> IdempotentCommandOptions {
    IdempotentCommandOptions {
        client_assertion: assertion.to_owned(),
        idempotency_key: key.to_owned(),
    }
}

fn assert_enrollment_status(response: &ServiceResponse, expected: AgentStatus) {
    assert_eq!(response.status, 200);
    let ResponseBody::Enroll(enrollment) = &response.body else {
        panic!("Enroll response expected");
    };
    assert_eq!(enrollment.status, expected);
}

fn assert_problem(response: &ServiceResponse, code: ErrorCode, status: u16) {
    assert_eq!(response.status, status);
    let ResponseBody::Problem(problem) = &response.body else {
        panic!("Problem Details expected");
    };
    assert_eq!(problem.code, code);
    validate_problem_details(problem).expect("valid Problem Details");
}

fn fixed_time() -> OffsetDateTime {
    OffsetDateTime::parse("2026-08-31T12:00:00Z", &Rfc3339).expect("fixed time")
}

fn agent_did() -> &'static str {
    "did:web:agent.example"
}

fn service_did() -> &'static str {
    "did:web:service.example"
}
