use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use aep_core::{
    AssertionOperation, ClientAssertionClaims, ClientAssertionSigningKey,
    ClientAssertionVerifyingKey, ErrorCode, SignClientAssertionOptions, SigningAlgorithm,
    VerifyClientAssertionOptions, sign_client_assertion, verify_client_assertion,
};
use aep_platform::*;
use async_trait::async_trait;
use futures::{FutureExt as _, executor::block_on};
use http::{HeaderMap, HeaderValue, header};
use serde_json::json;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Default)]
struct TestAuthorizer {
    allowed: AtomicBool,
    operations: Mutex<Vec<&'static str>>,
}

impl TestAuthorizer {
    fn allow() -> Self {
        Self {
            allowed: AtomicBool::new(true),
            operations: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl Authorizer for TestAuthorizer {
    async fn authorize(
        &self,
        request: &AuthorizationRequest,
        _context: &RequestContext,
    ) -> Result<bool, PlatformError> {
        let operation = match request {
            AuthorizationRequest::GetIdentity { .. } => "get",
            AuthorizationRequest::ListIdentities { .. } => "list",
            AuthorizationRequest::Provision { .. } => "provision",
            AuthorizationRequest::Sign { .. } => "sign",
            AuthorizationRequest::UpdateIdentity { .. } => "update",
            AuthorizationRequest::Verify { .. } => "verify",
        };
        self.operations
            .lock()
            .expect("operations lock")
            .push(operation);
        Ok(self.allowed.load(Ordering::SeqCst))
    }
}

struct TestKeyStore {
    created: Mutex<BTreeSet<String>>,
    key: ClientAssertionSigningKey,
}

impl Default for TestKeyStore {
    fn default() -> Self {
        Self {
            created: Mutex::new(BTreeSet::new()),
            key: ClientAssertionSigningKey::ed25519_from_seed([7; 32]),
        }
    }
}

#[async_trait]
impl KeyStore for TestKeyStore {
    async fn create_key(&self, identity: &IdentityRecord) -> Result<(), PlatformError> {
        self.created
            .lock()
            .expect("created lock")
            .insert(identity.agent_identity_id.clone());
        Ok(())
    }

    async fn did_verification_method(
        &self,
        identity: &IdentityRecord,
    ) -> Result<DidVerificationMethod, PlatformError> {
        Ok(DidVerificationMethod {
            controller: identity.agent_did.clone(),
            id: identity.key_id.clone(),
            public_key_jwk: json!({
                "crv": "Ed25519",
                "kty": "OKP",
                "x": "11qYAYKxCrfVS_7TyWGDWZ4VnZ5wJzI7A2kB6FzM7o0"
            }),
            method_type: "JsonWebKey2020".to_owned(),
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
                allow_insecure_loopback: false,
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

struct TestResolver;

#[async_trait]
impl ServiceDidResolver for TestResolver {
    async fn resolve(&self, service_did: &str) -> Result<bool, PlatformError> {
        Ok(service_did.starts_with("did:web:"))
    }
}

struct PendingSignHandler;

#[async_trait]
impl SignHandler for PendingSignHandler {
    async fn sign(
        &self,
        _identity: &IdentityRecord,
        request: &SignRequest,
        _context: &RequestContext,
    ) -> Result<Option<PlatformResponse<SignResponse>>, PlatformError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(aep_core::MEDIA_TYPE),
        );
        Ok(Some(PlatformResponse {
            body: ResponseBody::Success(SignResponse {
                additional: BTreeMap::new(),
                agent_did: None,
                client_assertion: None,
                expires_at: None,
                issued_at: None,
                jti: None,
                platform_context: request.platform_context.clone(),
                retry_after_seconds: Some("5".to_owned()),
                service_did: None,
                status: SignStatus::Pending,
            }),
            headers,
            status: 202,
        }))
    }
}

struct FixedClock(OffsetDateTime);

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

struct MutableClock(Mutex<OffsetDateTime>);

impl Clock for MutableClock {
    fn now(&self) -> OffsetDateTime {
        *self.0.lock().expect("clock lock")
    }
}

struct TestPlatform {
    authorizer: Arc<TestAuthorizer>,
    key_store: Arc<TestKeyStore>,
    platform: Arc<Platform>,
}

fn test_platform(hosted_verification: bool) -> TestPlatform {
    let authorizer = Arc::new(TestAuthorizer::allow());
    let key_store = Arc::new(TestKeyStore::default());
    let identity_counter = Arc::new(AtomicUsize::new(0));
    let did_counter = Arc::new(AtomicUsize::new(0));
    let mut options = PlatformOptions::new(
        authorizer.clone(),
        key_store.clone(),
        Arc::new(TestResolver),
        "platform.example",
        "https://platform.example/agents/{agent_did_id}/did.json",
    );
    options.agent_did_id_generator = Some(Arc::new(move || {
        Ok(format!(
            "did-{}",
            did_counter.fetch_add(1, Ordering::SeqCst)
        ))
    }));
    options.clock = Some(Arc::new(FixedClock(fixed_time())));
    options.discovery = DiscoveryOptions {
        endpoint_base: "/v1/aep".to_owned(),
        hosted_verification_endpoint: hosted_verification
            .then(|| "/v1/aep/verifications".to_owned()),
        lifecycle_endpoint: "/v1/aep/agent-identities/{agent_identity_id}".to_owned(),
        list_endpoint: "/v1/aep/agent-identities".to_owned(),
        platform_did: Some("did:web:platform.example".to_owned()),
        platform_name: "Example Platform".to_owned(),
        provision_endpoint: "/v1/aep/agent-identities".to_owned(),
        sign_endpoint: "/v1/aep/agent-identities/{agent_identity_id}/sign".to_owned(),
    };
    options.hosted_verification = hosted_verification;
    options.identifier = Some(Arc::new(move || {
        Ok(format!(
            "identity-{}",
            identity_counter.fetch_add(1, Ordering::SeqCst)
        ))
    }));
    options.replay_store =
        hosted_verification.then(|| Arc::new(MemoryReplayStore::default()) as Arc<dyn ReplayStore>);
    TestPlatform {
        authorizer,
        key_store,
        platform: Platform::new(options).expect("Platform"),
    }
}

fn test_platform_with_sign_handler(handler: Arc<dyn SignHandler>) -> TestPlatform {
    let authorizer = Arc::new(TestAuthorizer::allow());
    let key_store = Arc::new(TestKeyStore::default());
    let mut options = PlatformOptions::new(
        authorizer.clone(),
        key_store.clone(),
        Arc::new(TestResolver),
        "platform.example",
        "https://platform.example/agents/{agent_did_id}/did.json",
    );
    options.agent_did_id_generator = Some(Arc::new(|| Ok("did-0".to_owned())));
    options.clock = Some(Arc::new(FixedClock(fixed_time())));
    options.discovery = DiscoveryOptions {
        endpoint_base: "/v1/aep".to_owned(),
        lifecycle_endpoint: "/v1/aep/agent-identities/{agent_identity_id}".to_owned(),
        list_endpoint: "/v1/aep/agent-identities".to_owned(),
        platform_name: "Example Platform".to_owned(),
        provision_endpoint: "/v1/aep/agent-identities".to_owned(),
        sign_endpoint: "/v1/aep/agent-identities/{agent_identity_id}/sign".to_owned(),
        ..DiscoveryOptions::default()
    };
    options.identifier = Some(Arc::new(|| Ok("identity-0".to_owned())));
    options.sign_handler = Some(handler);
    TestPlatform {
        authorizer,
        key_store,
        platform: Platform::new(options).expect("Platform"),
    }
}

#[test]
fn publishes_discovery_and_service_scoped_did_documents() {
    block_on(async {
        let test = test_platform(false);
        let discovery = success_body(test.platform.discovery());
        assert_eq!(discovery.aep_version, aep_core::VERSION);
        assert_eq!(discovery.identity.did_methods, vec!["did:web"]);
        assert!(!discovery.platform.hosted_verification);
        assert_eq!(
            create_service_scoped_agent_did("platform.example", "agents", "opaque")
                .expect("Agent DID"),
            "did:web:platform.example:agents:opaque"
        );
        let identity = provision(&test.platform, "did:web:service.example", "provision-1").await;
        let document = success_body(
            test.platform
                .did_document("did-0")
                .await
                .expect("DID document"),
        );
        assert_eq!(document.id, identity.agent_did);
        assert_eq!(document.verification_method[0].id, identity.key_id);
    });
}

#[test]
fn provisions_once_per_principal_and_service_with_idempotent_replay() {
    block_on(async {
        let test = test_platform(false);
        let first = provision(&test.platform, "did:web:first.example", "provision-1").await;
        let replay = provision(&test.platform, "did:web:first.example", "provision-1").await;
        assert_eq!(first, replay);
        let repeated = provision(&test.platform, "did:web:first.example", "provision-2").await;
        assert_eq!(first, repeated);
        let second = provision(&test.platform, "did:web:second.example", "provision-3").await;
        assert_ne!(first.agent_did, second.agent_did);
        assert_eq!(
            test.key_store.created.lock().expect("created lock").len(),
            2
        );

        let conflict = test
            .platform
            .provision(
                ProvisionRequest {
                    service_did: "did:web:third.example".to_owned(),
                },
                context("provision-1"),
            )
            .await
            .expect("conflict");
        assert_problem(conflict, ErrorCode::IdempotencyConflict, 409);
    });
}

#[test]
fn coalesces_concurrent_provisioning() {
    block_on(async {
        let test = test_platform(false);
        let request = ProvisionRequest {
            service_did: "did:web:service.example".to_owned(),
        };
        let (first, second) = futures::join!(
            test.platform.provision(request.clone(), context("first")),
            test.platform.provision(request, context("second"))
        );
        let first = success_body(first.expect("first"));
        let second = success_body(second.expect("second"));
        assert_eq!(first, second);
        assert_eq!(
            test.key_store.created.lock().expect("created lock").len(),
            1
        );
    });
}

#[test]
fn fails_closed_and_isolates_principals() {
    block_on(async {
        let test = test_platform(false);
        let identity = provision(&test.platform, "did:web:service.example", "provision-1").await;
        test.authorizer.allowed.store(false, Ordering::SeqCst);
        assert_problem(
            test.platform
                .get_identity(&identity.agent_identity_id, &context("unused"))
                .await
                .expect("denied"),
            ErrorCode::NotRecognized,
            404,
        );
        test.authorizer.allowed.store(true, Ordering::SeqCst);
        let mut other = context("unused");
        other.principal = "other".to_owned();
        assert_problem(
            test.platform
                .get_identity(&identity.agent_identity_id, &other)
                .await
                .expect("isolated"),
            ErrorCode::NotRecognized,
            404,
        );
    });
}

#[test]
fn lists_deterministically_and_applies_lifecycle() {
    block_on(async {
        let test = test_platform(false);
        let first = provision(&test.platform, "did:web:first.example", "provision-1").await;
        let second = provision(&test.platform, "did:web:second.example", "provision-2").await;
        let list = success_body(
            test.platform
                .list(
                    IdentityListQuery {
                        limit: 1,
                        ..IdentityListQuery::default()
                    },
                    &context("unused"),
                )
                .await
                .expect("list"),
        );
        assert_eq!(list.count, "1");
        assert_eq!(list.total, "2");
        assert_eq!(list.data[0].agent_identity_id, first.agent_identity_id);

        let suspended = success_body(
            test.platform
                .update_identity(
                    &second.agent_identity_id,
                    LifecycleRequest {
                        status: ManagedAgentStatus::Suspended,
                    },
                    &context("unused"),
                )
                .await
                .expect("lifecycle"),
        );
        assert_eq!(suspended.status, ManagedAgentStatus::Suspended);
        let response = test
            .platform
            .sign(
                &second.agent_identity_id,
                sign_request("did:web:second.example", "sign-1"),
                context("sign-1"),
            )
            .await
            .expect("blocked sign");
        assert_problem(response, ErrorCode::IdentitySuspended, 403);
        assert_problem(
            test.platform
                .did_document("did-1")
                .await
                .expect("inactive DID"),
            ErrorCode::NotRecognized,
            404,
        );
    });
}

#[test]
fn signs_assertions_with_the_exact_requested_contract() {
    block_on(async {
        let test = test_platform(false);
        let identity = provision(&test.platform, "did:web:service.example", "provision-1").await;
        let response = success_body(
            test.platform
                .sign(
                    &identity.agent_identity_id,
                    sign_request("did:web:service.example", "jti-1"),
                    context("sign-1"),
                )
                .await
                .expect("sign"),
        );
        assert_eq!(response.status, SignStatus::Completed);
        let assertion = response.client_assertion.expect("assertion");
        let claims = verify_client_assertion(
            &assertion,
            &test.key_store.key.verifying_key(),
            &VerifyClientAssertionOptions {
                algorithms: vec![SigningAlgorithm::EdDsa],
                audience: Some("did:web:service.example".to_owned()),
                current_time: Some(fixed_time().unix_timestamp()),
                issuer: Some(identity.agent_did.clone()),
                operation: Some(AssertionOperation::Enroll),
                subject: Some(identity.agent_did),
                ..VerifyClientAssertionOptions::default()
            },
        )
        .expect("verified assertion");
        assert_eq!(claims.jti, "jti-1");

        let invalid = test
            .platform
            .sign(
                &identity.agent_identity_id,
                SignRequest {
                    resource: Some("https://service.example/catalog".to_owned()),
                    ..sign_request("did:web:service.example", "jti-2")
                },
                context("sign-2"),
            )
            .await
            .expect("invalid sign");
        assert_problem(invalid, ErrorCode::InvalidRequest, 400);
    });
}

#[test]
fn preserves_valid_pending_sign_responses_for_idempotent_polling() {
    block_on(async {
        let test = test_platform_with_sign_handler(Arc::new(PendingSignHandler));
        let identity = provision(&test.platform, "did:web:service.example", "provision-1").await;
        let mut request = sign_request("did:web:service.example", "jti-pending");
        request
            .platform_context
            .insert("authorization_handle".to_owned(), json!("opaque"));
        let first = test
            .platform
            .sign(
                &identity.agent_identity_id,
                request.clone(),
                context("sign-pending"),
            )
            .await
            .expect("pending sign");
        assert_eq!(first.status, 202);
        let pending = success_body(first);
        assert_eq!(pending.status, SignStatus::Pending);
        assert_eq!(pending.retry_after_seconds.as_deref(), Some("5"));
        assert_eq!(
            pending.platform_context.get("authorization_handle"),
            Some(&json!("opaque"))
        );
        let replay = test
            .platform
            .sign(
                &identity.agent_identity_id,
                request,
                context("sign-pending"),
            )
            .await
            .expect("pending replay");
        assert_eq!(replay.status, 202);
    });
}

#[test]
fn verifies_hosted_assertions_without_disclosing_recognition_details() {
    block_on(async {
        let test = test_platform(true);
        let identity = provision(&test.platform, "did:web:service.example", "provision-1").await;
        let signed = success_body(
            test.platform
                .sign(
                    &identity.agent_identity_id,
                    sign_request("did:web:service.example", "jti-verify"),
                    context("sign-1"),
                )
                .await
                .expect("sign"),
        );
        let request = VerificationRequest {
            client_assertion: signed.client_assertion.expect("assertion"),
            op: AssertionOperation::Enroll,
            resource: None,
            service_did: "did:web:service.example".to_owned(),
        };
        let verified = success_body(
            test.platform
                .verify(request.clone(), context("verify-1"))
                .await
                .expect("verification"),
        );
        assert!(verified.verified);
        assert_eq!(verified.agent_identity_id, Some(identity.agent_identity_id));

        let replayed = success_body(
            test.platform
                .verify(request, context("verify-2"))
                .await
                .expect("replayed verification"),
        );
        assert!(!replayed.verified);
        assert_eq!(replayed.reason, "not_recognized");

        let malformed = success_body(
            test.platform
                .verify(
                    VerificationRequest {
                        client_assertion: "not-a-jwt".to_owned(),
                        op: AssertionOperation::Enroll,
                        resource: None,
                        service_did: "did:web:service.example".to_owned(),
                    },
                    context("verify-3"),
                )
                .await
                .expect("malformed verification"),
        );
        assert!(!malformed.verified);
    });
}

#[test]
fn rejects_incomplete_or_inconsistent_configuration() {
    let authorizer = Arc::new(TestAuthorizer::allow());
    let key_store = Arc::new(TestKeyStore::default());
    let mut options = PlatformOptions::new(
        authorizer,
        key_store,
        Arc::new(TestResolver),
        "platform.example",
        "https://platform.example/agents/{agent_did_id}/did.json",
    );
    assert!(Platform::new(options.clone()).is_err());
    options.discovery = DiscoveryOptions {
        endpoint_base: "/v1/aep".to_owned(),
        lifecycle_endpoint: "/v1/aep/identities/{agent_identity_id}".to_owned(),
        list_endpoint: "/v1/aep/identities".to_owned(),
        platform_name: "Example Platform".to_owned(),
        provision_endpoint: "/v1/aep/identities".to_owned(),
        sign_endpoint: "/v1/aep/identities/{agent_identity_id}/sign".to_owned(),
        ..DiscoveryOptions::default()
    };
    options.signing_algorithms = vec![SigningAlgorithm::EdDsa, SigningAlgorithm::EdDsa];
    assert!(Platform::new(options.clone()).is_err());
    options.signing_algorithms = vec![SigningAlgorithm::EdDsa];
    options.hosted_verification = true;
    options.discovery.hosted_verification_endpoint = Some("/v1/aep/verifications".to_owned());
    assert!(Platform::new(options).is_err());
}

#[test]
fn preserves_response_extensions_and_rejects_null_request_members() {
    let discovery: DiscoveryDocument = serde_json::from_value(json!({
        "aep_version": "1.0",
        "endpoints": {
            "lifecycle": "/v1/aep/agent-identities/{agent_identity_id}",
            "list": "/v1/aep/agent-identities",
            "provision": "/v1/aep/agent-identities",
            "sign": "/v1/aep/agent-identities/{agent_identity_id}/sign",
            "vendor_endpoint": "/vendor"
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
            "algorithms": ["EdDSA"],
            "default_lifetime_seconds": "300"
        },
        "vendor": {"enabled": true}
    }))
    .expect("extended Discovery");
    assert_eq!(
        discovery.additional.get("vendor"),
        Some(&json!({"enabled": true}))
    );
    assert_eq!(
        discovery.endpoints.additional.get("vendor_endpoint"),
        Some(&json!("/vendor"))
    );

    assert!(
        serde_json::from_value::<SignRequest>(json!({
            "jti": "jti-1",
            "lifetime_seconds": null,
            "op": "enroll",
            "service_did": "did:web:service.example"
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<VerificationRequest>(json!({
            "client_assertion": "assertion",
            "op": "enroll",
            "resource": null,
            "service_did": "did:web:service.example"
        }))
        .is_err()
    );
}

#[test]
fn expires_idempotency_records_against_the_configured_clock() {
    block_on(async {
        let clock = Arc::new(MutableClock(Mutex::new(fixed_time())));
        let store = MemoryIdempotencyStore::new(clock.clone());
        let calls = Arc::new(AtomicUsize::new(0));
        let input = IdempotencyInput {
            idempotency_key: "key".to_owned(),
            operation: IdempotentOperation::Provision,
            principal: "owner".to_owned(),
            request_hash: "hash".to_owned(),
        };
        let execute = |calls: Arc<AtomicUsize>| {
            Box::new(move || {
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(StoredResponse {
                        body: b"{}".to_vec(),
                        content_type: aep_core::MEDIA_TYPE.to_owned(),
                        created_at: OffsetDateTime::UNIX_EPOCH,
                        headers: HeaderMap::new(),
                        status: 200,
                    })
                }
                .boxed()
            }) as IdempotencyOperation
        };

        let created = store
            .execute(input.clone(), execute(calls.clone()))
            .await
            .expect("created record");
        assert!(matches!(created, IdempotencyResult::Created(_)));
        *clock.0.lock().expect("clock lock") = fixed_time() + Duration::from_secs(3599);
        let replayed = store
            .execute(input.clone(), execute(calls.clone()))
            .await
            .expect("replayed record");
        assert!(matches!(replayed, IdempotencyResult::Replayed(_)));
        *clock.0.lock().expect("clock lock") = fixed_time() + Duration::from_secs(3600);
        let expired = store
            .execute(input, execute(calls.clone()))
            .await
            .expect("expired record");
        assert!(matches!(expired, IdempotencyResult::Created(_)));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    });
}

async fn provision(platform: &Arc<Platform>, service_did: &str, key: &str) -> AgentIdentity {
    success_body(
        platform
            .provision(
                ProvisionRequest {
                    service_did: service_did.to_owned(),
                },
                context(key),
            )
            .await
            .expect("provision"),
    )
}

fn sign_request(service_did: &str, jti: &str) -> SignRequest {
    SignRequest {
        jti: jti.to_owned(),
        lifetime_seconds: Some("300".to_owned()),
        op: AssertionOperation::Enroll,
        platform_context: BTreeMap::new(),
        resource: None,
        service_did: service_did.to_owned(),
    }
}

fn context(idempotency_key: &str) -> RequestContext {
    RequestContext {
        authorization: Some("Bearer platform-token".to_owned()),
        idempotency_key: Some(idempotency_key.to_owned()),
        now: Some(fixed_time()),
        principal: "agent-owner".to_owned(),
        request_id: None,
    }
}

fn success_body<T>(response: PlatformResponse<T>) -> T {
    assert!(matches!(response.status, 200 | 202));
    let ResponseBody::Success(body) = response.body else {
        panic!("successful body expected");
    };
    body
}

fn assert_problem<T>(response: PlatformResponse<T>, code: ErrorCode, status: u16) {
    assert_eq!(response.status, status);
    let ResponseBody::Problem(problem) = response.body else {
        panic!("Problem Details expected");
    };
    assert_eq!(problem.code, code);
    aep_core::validate_problem_details(&problem).expect("valid Problem Details");
}

fn fixed_time() -> OffsetDateTime {
    OffsetDateTime::parse("2026-08-31T12:00:00Z", &Rfc3339).expect("fixed time")
}
