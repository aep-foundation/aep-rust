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
                "id": "did:web:agent.example",
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
        // CORE-ERR-009 pairs `requirements_unmet` with 422.
        assert_problem(&missing, ErrorCode::RequirementsUnmet, 422);
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
fn policy_metadata_distinguishes_omitted_false_and_empty() {
    block_on(async {
        for initial in [true, false] {
            for value in [None, Some(false), Some(true)] {
                let store = Arc::new(MemoryEnrollmentStore::default());
                let original = EnrollmentRecord {
                    acknowledged_document_ids: Vec::new(),
                    required_document_ids: Vec::new(),
                    agent_did: agent_did().to_owned(),
                    claims: ClaimValues::default(),
                    created_at: fixed_time() - time::Duration::hours(1),
                    owner_action_required: true,
                    requirements_pending: vec!["review".to_owned()],
                    since: fixed_time() - time::Duration::hours(1),
                    status: AgentStatus::Suspended,
                    updated_at: fixed_time() - time::Duration::hours(1),
                    verification_pending: vec!["contact.email".to_owned()],
                };
                if !initial {
                    store.save(original.clone()).await.expect("seed");
                }
                let mut options =
                    ServiceOptions::new(service_did(), Arc::new(RecordingVerifier::default()));
                options.clock = Some(Arc::new(FixedClock(fixed_time())));
                options.enrollment_store = Some(store.clone());
                options.enrollment_policy =
                    Some(Arc::new(StaticEnrollmentPolicy::new(EnrollmentDecision {
                        owner_action_required: value,
                        requirements_pending: value.map(|_| Vec::new()),
                        verification_pending: value.map(|_| Vec::new()),
                        ..EnrollmentDecision::default()
                    })));
                let service = Service::new(options).expect("service");
                let result = service
                    .enroll(enroll_request(), idempotent("metadata", "metadata"))
                    .await
                    .expect("enroll");
                assert_enrollment_status(
                    &result,
                    if initial {
                        AgentStatus::Active
                    } else {
                        AgentStatus::Suspended
                    },
                );
                let saved = store
                    .find(agent_did())
                    .await
                    .expect("find")
                    .expect("record");
                assert_eq!(saved.owner_action_required, value.unwrap_or(!initial));
                if value.is_none() && !initial {
                    assert_eq!(saved.requirements_pending, original.requirements_pending);
                    assert_eq!(saved.verification_pending, original.verification_pending);
                } else {
                    assert!(saved.requirements_pending.is_empty());
                    assert!(saved.verification_pending.is_empty());
                }
                if !initial {
                    assert_eq!(saved.created_at, original.created_at);
                    assert_eq!(saved.since, original.since);
                    assert_eq!(saved.status, original.status);
                }
            }
        }
    });
}

#[test]
fn repeated_policy_can_merge_reject_or_leave_unchanged() {
    block_on(async {
        for decision in [
            EnrollmentDecision {
                owner_action_required: Some(true),
                requirements_pending: Some(vec!["review".to_owned()]),
                verification_pending: Some(vec!["email".to_owned()]),
                ..EnrollmentDecision::default()
            },
            EnrollmentDecision {
                status: EnrollmentDecisionStatus::Rejected,
                ..EnrollmentDecision::default()
            },
            EnrollmentDecision {
                update_existing: false,
                ..EnrollmentDecision::default()
            },
        ] {
            let store = Arc::new(MemoryEnrollmentStore::default());
            let original = EnrollmentRecord {
                acknowledged_document_ids: Vec::new(),
                required_document_ids: Vec::new(),
                agent_did: agent_did().to_owned(),
                claims: ClaimValues {
                    contact_email: Some("owner@example.com".to_owned()),
                    ..ClaimValues::default()
                },
                created_at: fixed_time() - time::Duration::hours(1),
                owner_action_required: false,
                requirements_pending: Vec::new(),
                since: fixed_time() - time::Duration::hours(1),
                status: AgentStatus::Pending,
                updated_at: fixed_time() - time::Duration::hours(1),
                verification_pending: Vec::new(),
            };
            store.save(original.clone()).await.expect("seed");
            let mut options =
                ServiceOptions::new(service_did(), Arc::new(RecordingVerifier::default()));
            options.clock = Some(Arc::new(FixedClock(fixed_time())));
            options.claims.required = vec![ClaimName::ContactEmail];
            options.enrollment_store = Some(store.clone());
            options.enrollment_policy =
                Some(Arc::new(StaticEnrollmentPolicy::new(decision.clone())));
            let service = Service::new(options).expect("service");
            let response = service.enroll(br#"{"agent_did":"did:web:agent.example","claims":{"person.first_name":"Owner"}}"#, idempotent("update", "update")).await.expect("update");
            let saved = store
                .find(agent_did())
                .await
                .expect("find")
                .expect("record");
            if decision.status == EnrollmentDecisionStatus::Rejected {
                assert_problem(&response, ErrorCode::EnrollmentFailed, 403);
                assert_eq!(saved, original);
            } else if !decision.update_existing {
                assert_enrollment_status(&response, AgentStatus::Pending);
                assert_eq!(saved, original);
            } else {
                assert_enrollment_status(&response, AgentStatus::Pending);
                assert_eq!(saved.claims.contact_email, original.claims.contact_email);
                assert_eq!(saved.claims.person_first_name.as_deref(), Some("Owner"));
                assert!(saved.owner_action_required);
                assert_eq!(saved.requirements_pending, vec!["review"]);
                assert_eq!(saved.verification_pending, vec!["email"]);
            }
        }
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

        // CORE-CA-016: an `authenticate` assertion carries the resource it was minted for, and
        // the verifier checks it against the target the caller names.
        let resource = Url::parse("https://service.example/v1/orders").expect("resource");
        let authenticate = ClientAssertionClaims {
            jti: "jti-authenticate".to_owned(),
            op: AssertionOperation::Authenticate,
            resource: Some(resource.to_string()),
            ..claims.clone()
        };
        let assertion = sign_client_assertion(
            &authenticate,
            SignClientAssertionOptions {
                allow_insecure_loopback: false,
                key: &signing_key,
                key_id: "did:web:agent.example#key-1",
            },
        )
        .expect("signed assertion");
        let context = |resource: Url| ClientAssertionVerificationContext {
            assertion: assertion.clone(),
            current_time: fixed_time(),
            idempotency_key: None,
            operation: AssertionOperation::Authenticate,
            resource: Some(resource),
            service_did: service_did().to_owned(),
            signing_algorithms: vec![SigningAlgorithm::EdDsa],
        };
        assert_eq!(
            verifier.verify(context(resource)).await.expect("verified"),
            authenticate
        );
        assert!(
            verifier
                .verify(context(
                    Url::parse("https://service.example/v1/other").expect("resource")
                ))
                .await
                .is_err()
        );
    });
}

/// The bundled transport refuses a configuration it cannot enforce.
#[test]
fn the_bundled_transport_requires_usable_bounds() {
    assert!(ReqwestTransport::new(1 << 20, std::time::Duration::from_secs(30)).is_ok());
    assert!(ReqwestTransport::new(0, std::time::Duration::from_secs(30)).is_err());
    assert!(ReqwestTransport::new(1 << 20, std::time::Duration::ZERO).is_err());
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
        let (started, entered) = futures::channel::oneshot::channel();
        let (release, waiting) = futures::channel::oneshot::channel();
        let operation = |executions: Arc<AtomicUsize>,
                         barrier: Option<(
            futures::channel::oneshot::Sender<()>,
            futures::channel::oneshot::Receiver<()>,
        )>|
         -> CommandOperation {
            Box::new(move || {
                Box::pin(async move {
                    executions.fetch_add(1, Ordering::SeqCst);
                    if let Some((started, waiting)) = barrier {
                        started.send(()).expect("started");
                        waiting.await.expect("released");
                    }
                    Ok(ServiceResponse {
                        body: ResponseBody::Enroll(EnrollResponse {
                            acknowledged_document_ids: None,
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
        let first = store.execute(
            input.clone(),
            operation(executions.clone(), Some((started, waiting))),
        );
        let second = async {
            entered.await.expect("first operation is running");
            let mut second = Box::pin(store.execute(input, operation(executions.clone(), None)));
            assert!(futures::poll!(second.as_mut()).is_pending());
            assert_eq!(executions.load(Ordering::SeqCst), 1);
            release.send(()).expect("release first");
            second.await
        };
        let (first, second) = futures::join!(first, second);
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

fn document_service(
    required: &[&str],
    store: Arc<MemoryEnrollmentStore>,
    handler: Arc<RecordingGrantHandler>,
    policy: EnrollmentDecision,
) -> Arc<Service> {
    let mut options = ServiceOptions::new(service_did(), Arc::new(RecordingVerifier::default()));
    options.clock = Some(Arc::new(FixedClock(fixed_time())));
    options.enrollment_store = Some(store);
    options.enrollment_policy = Some(Arc::new(StaticEnrollmentPolicy::new(policy)));
    options.claims.required = vec![ClaimName::ContactEmail];
    options.extensions = vec![SERVICE_DOCUMENTS_EXTENSION.into()];
    options.service_documents = Some(
        required
            .iter()
            .map(|id| ServiceDocument {
                id: (*id).into(),
                document_type: "terms_of_service".into(),
                title: (*id).into(),
                enrollment: DocumentEnrollment::Required,
                representations: vec![DocumentRepresentation {
                    media_type: "text/html".into(),
                    url: format!("https://service.example/{id}"),
                }],
            })
            .collect(),
    );
    options.grant_types = vec![GrantTypeDefinition {
        config: None,
        grant_type: GrantType::ApiKey,
        handler: Some(handler),
    }];
    Service::new(options).unwrap()
}

#[test]
fn grant_idempotency_precedes_changed_enrollment_requirements() {
    block_on(async {
        for (missing_claim, missing_document) in [(true, false), (false, true), (true, true)] {
            let store = Arc::new(MemoryEnrollmentStore::default());
            let handler = Arc::new(RecordingGrantHandler::default());
            let service = document_service(
                &["terms"],
                store.clone(),
                handler.clone(),
                EnrollmentDecision::default(),
            );
            let enrollment = service
                .enroll(
                    br#"{"agent_did":"did:web:agent.example","claims":{"contact.email":"owner@example.com"},"acknowledged_document_ids":["terms"]}"#,
                    idempotent("enroll", "enroll-key"),
                )
                .await
                .unwrap();
            assert_eq!(enrollment.status, 200);
            let original = store.find(agent_did()).await.unwrap().unwrap();
            let request = br#"{"grant_type":"api-key"}"#;
            let first = service
                .grant(request, idempotent("first", "grant-key"))
                .await
                .unwrap();
            assert_eq!(first.status, 200);

            let mut changed = original.clone();
            if missing_claim {
                changed.claims.contact_email = None;
            }
            if missing_document {
                changed.required_document_ids = vec!["terms".into()];
            }
            store.save(changed).await.unwrap();
            let replay = service
                .grant(request, idempotent("replay", "grant-key"))
                .await
                .unwrap();
            assert_eq!(replay, first);
            let conflict = service
                .grant(
                    br#"{"grant_type":"api-key","requested_scopes":["other"]}"#,
                    idempotent("conflict", "grant-key"),
                )
                .await
                .unwrap();
            assert_problem(&conflict, ErrorCode::IdempotencyConflict, 409);
            let blocked = service
                .grant(request, idempotent("new-request", "new-key"))
                .await
                .unwrap();
            assert_problem(&blocked, ErrorCode::RequirementsUnmet, 422);
            assert_eq!(handler.grants.lock().unwrap().len(), 1);

            store.save(original).await.unwrap();
            let blocked_replay = service
                .grant(request, idempotent("blocked-replay", "new-key"))
                .await
                .unwrap();
            assert_eq!(blocked_replay, blocked);
            let recovered = service
                .grant(request, idempotent("recovered", "recovered-key"))
                .await
                .unwrap();
            assert_eq!(recovered.status, 200);
            assert_eq!(handler.grants.lock().unwrap().len(), 2);
        }
    });
}

#[test]
fn document_declarations_preserve_history_and_defer_new_requirements_to_grant() {
    block_on(async {
        let store = Arc::new(MemoryEnrollmentStore::default());
        let handler = Arc::new(RecordingGrantHandler::default());
        let service = document_service(
            &["terms", "new-notice"],
            store.clone(),
            handler.clone(),
            EnrollmentDecision::default(),
        );
        let missing = service
            .enroll(
                br#"{"agent_did":"did:web:agent.example"}"#,
                idempotent("missing", "missing"),
            )
            .await
            .unwrap();
        assert_problem(&missing, ErrorCode::RequirementsUnmet, 422);
        let ResponseBody::Problem(details) = missing.body else {
            panic!("problem");
        };
        assert_eq!(
            details.required_document_ids,
            Some(vec!["terms".into(), "new-notice".into()])
        );
        assert_eq!(
            details.requirements_pending,
            Some(vec!["contact.email".into(), "service_documents".into()])
        );
        assert!(store.find(agent_did()).await.unwrap().is_none());
        let partial = br#"{"agent_did":"did:web:agent.example","claims":{"contact.email":"owner@example.com","person.first_name":"Owner"},"acknowledged_document_ids":["terms","retired"]}"#;
        let first = service
            .enroll(partial, idempotent("first", "first"))
            .await
            .unwrap();
        assert_eq!(
            first.body.to_json().unwrap()["acknowledged_document_ids"],
            json!(["terms", "retired"])
        );
        let original = store.find(agent_did()).await.unwrap().unwrap();
        assert_eq!(original.acknowledged_document_ids, vec!["terms"]);
        let replay = service
            .enroll(partial, idempotent("retry", "first"))
            .await
            .unwrap();
        assert_eq!(
            first.body.to_json().unwrap(),
            replay.body.to_json().unwrap()
        );
        assert_eq!(store.find(agent_did()).await.unwrap().unwrap(), original);
        let conflict = service
            .enroll(enroll_request(), idempotent("conflict", "first"))
            .await
            .unwrap();
        assert_problem(&conflict, ErrorCode::IdempotencyConflict, 409);
        assert_eq!(store.find(agent_did()).await.unwrap().unwrap(), original);
        let grant = service
            .grant(br#"{"grant_type":"api-key"}"#, idempotent("grant", "grant"))
            .await
            .unwrap();
        assert_problem(&grant, ErrorCode::RequirementsUnmet, 422);
        assert_eq!(
            grant.body.to_json().unwrap()["required_document_ids"],
            json!(["new-notice"])
        );
        assert!(handler.grants.lock().unwrap().is_empty());
        let empty = service
            .enroll(
                br#"{"agent_did":"did:web:agent.example","acknowledged_document_ids":[]}"#,
                idempotent("empty", "empty"),
            )
            .await
            .unwrap();
        assert_eq!(
            empty.body.to_json().unwrap()["acknowledged_document_ids"],
            json!([])
        );
        assert_eq!(
            store
                .find(agent_did())
                .await
                .unwrap()
                .unwrap()
                .acknowledged_document_ids,
            vec!["terms"]
        );
        let omitted = service
            .enroll(
                br#"{"agent_did":"did:web:agent.example"}"#,
                idempotent("omitted", "omitted"),
            )
            .await
            .unwrap();
        assert_problem(&omitted, ErrorCode::RequirementsUnmet, 422);
        let update = service.enroll(br#"{"agent_did":"did:web:agent.example","claims":{"contact.email":"updated@example.com"},"acknowledged_document_ids":["new-notice"]}"#,idempotent("update","update")).await.unwrap();
        assert_eq!(
            update.body.to_json().unwrap()["acknowledged_document_ids"],
            json!(["new-notice"])
        );
        let mut stored = store.find(agent_did()).await.unwrap().unwrap();
        assert_eq!(stored.created_at, original.created_at);
        assert_eq!(stored.since, original.since);
        assert_eq!(
            stored.claims.person_first_name,
            original.claims.person_first_name
        );
        assert_eq!(
            stored.claims.contact_email.as_deref(),
            Some("updated@example.com")
        );
        stored.required_document_ids = vec!["terms".into()];
        store.save(stored).await.unwrap();
        assert_problem(
            &service
                .grant(
                    br#"{"grant_type":"api-key"}"#,
                    idempotent("renew-grant", "renew-grant"),
                )
                .await
                .unwrap(),
            ErrorCode::RequirementsUnmet,
            422,
        );
        service
            .enroll(
                br#"{"agent_did":"did:web:agent.example","acknowledged_document_ids":["terms"]}"#,
                idempotent("renew", "renew"),
            )
            .await
            .unwrap();
        assert!(
            store
                .find(agent_did())
                .await
                .unwrap()
                .unwrap()
                .required_document_ids
                .is_empty()
        );
        let grant = service
            .grant(br#"{"grant_type":"api-key"}"#, idempotent("ready", "ready"))
            .await
            .unwrap();
        assert_eq!(grant.status, 200);
        assert_eq!(handler.grants.lock().unwrap().len(), 1);
        let omitted = service
            .enroll(
                br#"{"agent_did":"did:web:agent.example"}"#,
                idempotent("satisfied", "satisfied"),
            )
            .await
            .unwrap();
        assert_eq!(omitted.status, 200);
        assert!(
            omitted
                .body
                .to_json()
                .unwrap()
                .get("acknowledged_document_ids")
                .is_none()
        );
    });
}

#[test]
fn document_updates_obey_service_policy_and_preserve_unrelated_lifecycle() {
    block_on(async {
        for status in [
            AgentStatus::Pending,
            AgentStatus::Suspended,
            AgentStatus::Terminated,
            AgentStatus::Unavailable,
        ] {
            for decision in [
                EnrollmentDecision::default(),
                EnrollmentDecision {
                    update_existing: false,
                    ..Default::default()
                },
                EnrollmentDecision {
                    status: EnrollmentDecisionStatus::Rejected,
                    ..Default::default()
                },
            ] {
                let store = Arc::new(MemoryEnrollmentStore::default());
                let original = EnrollmentRecord {
                    acknowledged_document_ids: vec!["terms".into()],
                    required_document_ids: vec!["terms".into()],
                    agent_did: agent_did().into(),
                    claims: ClaimValues {
                        contact_email: Some("owner@example.com".into()),
                        ..Default::default()
                    },
                    created_at: fixed_time() - time::Duration::hours(1),
                    updated_at: fixed_time() - time::Duration::hours(1),
                    since: fixed_time() - time::Duration::hours(1),
                    status,
                    owner_action_required: true,
                    requirements_pending: vec!["review".into()],
                    verification_pending: vec!["email".into()],
                };
                store.save(original.clone()).await.unwrap();
                let service = document_service(
                    &["terms"],
                    store.clone(),
                    Arc::new(RecordingGrantHandler::default()),
                    decision.clone(),
                );
                let response = service.enroll(br#"{"agent_did":"did:web:agent.example","acknowledged_document_ids":["terms"]}"#,idempotent("update","update")).await.unwrap();
                let stored = store.find(agent_did()).await.unwrap().unwrap();
                if decision.status == EnrollmentDecisionStatus::Rejected
                    || !decision.update_existing
                {
                    assert_eq!(stored, original);
                    assert_eq!(
                        response.status,
                        if decision.status == EnrollmentDecisionStatus::Rejected {
                            403
                        } else {
                            200
                        }
                    );
                } else {
                    assert_eq!(stored.status, original.status);
                    assert_eq!(stored.created_at, original.created_at);
                    assert_eq!(stored.since, original.since);
                    assert_eq!(stored.requirements_pending, original.requirements_pending);
                    assert_eq!(stored.verification_pending, original.verification_pending);
                    assert_eq!(stored.owner_action_required, original.owner_action_required);
                    assert!(stored.required_document_ids.is_empty());
                }
            }
        }
    });
}
