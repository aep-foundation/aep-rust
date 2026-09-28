//! Hosted verification, delegated-signing handlers, and the policy hooks around them.

use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use aep_core::{
    AssertionOperation, ClientAssertionClaims, ClientAssertionSigningKey,
    ClientAssertionVerifyingKey, ErrorCode, SignClientAssertionOptions, new_problem_details,
    sign_client_assertion,
};
use aep_platform::*;
use async_trait::async_trait;
use futures::executor::block_on;
use http::{HeaderMap, HeaderValue, header};
use serde_json::json;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const DID_HOST: &str = "platform.example";
const DID_TEMPLATE: &str = "https://platform.example/agents/{agent_did_id}/did.json";
const SERVICE_DID: &str = "did:web:service.example";

fn fixed_time() -> OffsetDateTime {
    OffsetDateTime::parse("2026-08-31T12:00:00Z", &Rfc3339).expect("fixed time")
}

struct FixedClock(OffsetDateTime);

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

struct Switch(AtomicBool);

impl Switch {
    fn on() -> Arc<Self> {
        Arc::new(Self(AtomicBool::new(true)))
    }

    fn set(&self, value: bool) {
        self.0.store(value, Ordering::SeqCst);
    }

    fn get(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl Authorizer for Switch {
    async fn authorize(
        &self,
        _request: &AuthorizationRequest,
        context: &RequestContext,
    ) -> Result<bool, PlatformError> {
        Ok(self.get() && context.principal == "owner")
    }
}

#[async_trait]
impl ServiceDidResolver for Switch {
    async fn resolve(&self, _service_did: &str) -> Result<bool, PlatformError> {
        Ok(self.get())
    }
}

/// A policy that refuses whatever the switch is set to refuse.
struct SwitchedPolicy(Arc<Switch>);

#[async_trait]
impl LifecyclePolicy for SwitchedPolicy {
    async fn can_sign(
        &self,
        _identity: &IdentityRecord,
        _context: &RequestContext,
    ) -> Result<bool, PlatformError> {
        Ok(self.0.get())
    }
    async fn can_transition(
        &self,
        _identity: &IdentityRecord,
        _status: ManagedAgentStatus,
        _context: &RequestContext,
    ) -> Result<bool, PlatformError> {
        Ok(self.0.get())
    }
    async fn can_verify(
        &self,
        _identity: &IdentityRecord,
        _context: &RequestContext,
    ) -> Result<bool, PlatformError> {
        Ok(self.0.get())
    }
}

struct TestKeyStore {
    assertion: Mutex<Option<String>>,
    key: ClientAssertionSigningKey,
}

impl Default for TestKeyStore {
    fn default() -> Self {
        Self {
            assertion: Mutex::new(None),
            key: ClientAssertionSigningKey::ed25519_from_seed([7; 32]),
        }
    }
}

#[async_trait]
impl KeyStore for TestKeyStore {
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
            public_key_jwk: json!({"crv": "Ed25519", "kty": "OKP", "x": "public"}),
            method_type: "JsonWebKey2020".to_owned(),
        })
    }

    async fn sign(
        &self,
        identity: &IdentityRecord,
        claims: &ClientAssertionClaims,
    ) -> Result<String, PlatformError> {
        if let Some(assertion) = self.assertion.lock().expect("assertion lock").clone() {
            return Ok(assertion);
        }
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

struct Fixture {
    key_store: Arc<TestKeyStore>,
    platform: Arc<Platform>,
    policy: Arc<Switch>,
    switch: Arc<Switch>,
}

struct Settings {
    hosted_verification: bool,
    identifier: Option<Arc<dyn Fn() -> Result<String, PlatformError> + Send + Sync>>,
    sign_handler: Option<Arc<dyn SignHandler>>,
    switched_policy: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            hosted_verification: false,
            identifier: Some(Arc::new(|| Ok("identity-0".to_owned()))),
            sign_handler: None,
            switched_policy: false,
        }
    }
}

fn fixture(settings: Settings) -> Fixture {
    let switch = Switch::on();
    let policy = Switch::on();
    let key_store = Arc::new(TestKeyStore::default());
    let mut options = PlatformOptions::new(
        switch.clone(),
        key_store.clone(),
        switch.clone(),
        DID_HOST,
        DID_TEMPLATE,
    );
    options.agent_did_id_generator = Some(Arc::new(|| Ok("did-0".to_owned())));
    options.clock = Some(Arc::new(FixedClock(fixed_time())));
    options.discovery = DiscoveryOptions {
        endpoint_base: "/v1/aep".to_owned(),
        hosted_verification_endpoint: settings
            .hosted_verification
            .then(|| "/v1/aep/verifications".to_owned()),
        lifecycle_endpoint: "/v1/aep/agent-identities/{agent_identity_id}".to_owned(),
        list_endpoint: "/v1/aep/agent-identities".to_owned(),
        platform_did: None,
        platform_name: "Example Platform".to_owned(),
        provision_endpoint: "/v1/aep/agent-identities".to_owned(),
        sign_endpoint: "/v1/aep/agent-identities/{agent_identity_id}/sign".to_owned(),
    };
    options.hosted_verification = settings.hosted_verification;
    options.identifier = settings.identifier;
    if settings.switched_policy {
        options.lifecycle_policy = Some(Arc::new(SwitchedPolicy(policy.clone())));
    }
    options.replay_store = settings
        .hosted_verification
        .then(|| Arc::new(MemoryReplayStore::default()) as Arc<dyn ReplayStore>);
    options.sign_handler = settings.sign_handler;
    Fixture {
        key_store,
        platform: Platform::new(options).expect("Platform"),
        policy,
        switch,
    }
}

fn context(idempotency_key: &str) -> RequestContext {
    RequestContext {
        authorization: None,
        idempotency_key: Some(idempotency_key.to_owned()),
        now: Some(fixed_time()),
        principal: "owner".to_owned(),
        request_id: None,
    }
}

fn code_of<T>(response: &PlatformResponse<T>) -> Option<ErrorCode> {
    match &response.body {
        ResponseBody::Problem(problem) => Some(problem.code.clone()),
        ResponseBody::Success(_) => None,
    }
}

fn body_of<T>(response: PlatformResponse<T>) -> T {
    match response.body {
        ResponseBody::Success(body) => body,
        ResponseBody::Problem(problem) => panic!("expected a success, got {problem:?}"),
    }
}

async fn provisioned(fixture: &Fixture, key: &str) -> AgentIdentity {
    body_of(
        fixture
            .platform
            .provision(
                ProvisionRequest {
                    service_did: SERVICE_DID.to_owned(),
                },
                context(key),
            )
            .await
            .expect("provisioned"),
    )
}

fn sign_request(op: AssertionOperation) -> SignRequest {
    SignRequest {
        jti: "assertion-1".to_owned(),
        lifetime_seconds: Some("60".to_owned()),
        op,
        platform_context: BTreeMap::new(),
        resource: None,
        service_did: SERVICE_DID.to_owned(),
    }
}

// --- authorization and policy -------------------------------------------------------------------

#[test]
fn cached_results_require_current_authorization() {
    block_on(async {
        let fixture = fixture(Settings {
            hosted_verification: true,
            ..Settings::default()
        });
        let identity = provisioned(&fixture, "provision-1").await;
        let request = sign_request(AssertionOperation::Enroll);
        let signed = fixture
            .platform
            .sign(
                &identity.agent_identity_id,
                request.clone(),
                context("sign-1"),
            )
            .await
            .expect("signed");
        let verification = VerificationRequest {
            client_assertion: body_of(signed.clone()).client_assertion.expect("assertion"),
            op: AssertionOperation::Enroll,
            resource: None,
            service_did: SERVICE_DID.into(),
        };
        let verified = fixture
            .platform
            .verify(verification.clone(), context("verify-1"))
            .await
            .expect("verified");
        assert!(body_of(verified.clone()).verified);

        fixture.switch.set(false);
        let denied = fixture
            .platform
            .provision(
                ProvisionRequest {
                    service_did: SERVICE_DID.into(),
                },
                context("provision-1"),
            )
            .await
            .expect("denied");
        assert_eq!(code_of(&denied), Some(ErrorCode::NotRecognized));
        let denied = fixture
            .platform
            .sign(
                &identity.agent_identity_id,
                request.clone(),
                context("sign-1"),
            )
            .await
            .expect("denied");
        assert_eq!(code_of(&denied), Some(ErrorCode::NotRecognized));
        let denied = body_of(
            fixture
                .platform
                .verify(verification.clone(), context("verify-1"))
                .await
                .expect("denied"),
        );
        assert!(!denied.verified);
        assert!(denied.agent_did.is_none());

        fixture.switch.set(true);
        let mut replay_context = context("verify-1");
        replay_context.now = Some(fixed_time() + Duration::from_secs(600));
        assert_eq!(
            body_of(
                fixture
                    .platform
                    .provision(
                        ProvisionRequest {
                            service_did: SERVICE_DID.into()
                        },
                        context("provision-1")
                    )
                    .await
                    .expect("replay")
            ),
            identity
        );
        assert_eq!(
            fixture
                .platform
                .sign(&identity.agent_identity_id, request, context("sign-1"))
                .await
                .expect("sign replay"),
            signed
        );
        assert_eq!(
            fixture
                .platform
                .verify(verification, replay_context)
                .await
                .expect("verification replay"),
            verified
        );
    });
}

#[test]
fn custom_policy_cannot_enable_inactive_signing_or_verification() {
    block_on(async {
        for status in [
            ManagedAgentStatus::Suspended,
            ManagedAgentStatus::Terminated,
            ManagedAgentStatus::Revoked,
        ] {
            let fixture = fixture(Settings {
                hosted_verification: true,
                switched_policy: true,
                ..Settings::default()
            });
            let identity = provisioned(&fixture, "provision-1").await;
            let request = sign_request(AssertionOperation::Enroll);
            let signed = fixture
                .platform
                .sign(
                    &identity.agent_identity_id,
                    request.clone(),
                    context("sign-1"),
                )
                .await
                .expect("signed");
            let verification = VerificationRequest {
                client_assertion: body_of(signed.clone()).client_assertion.expect("assertion"),
                op: AssertionOperation::Enroll,
                resource: None,
                service_did: SERVICE_DID.into(),
            };
            let verified = fixture
                .platform
                .verify(verification.clone(), context("verify-1"))
                .await
                .expect("verified");
            assert!(body_of(verified.clone()).verified);
            let mut unused_request = request.clone();
            unused_request.jti = "unused-assertion".into();
            let unused_assertion = body_of(
                fixture
                    .platform
                    .sign(
                        &identity.agent_identity_id,
                        unused_request,
                        context("unused-sign"),
                    )
                    .await
                    .expect("unconsumed assertion"),
            )
            .client_assertion
            .expect("assertion");
            let updated = body_of(
                fixture
                    .platform
                    .update_identity(
                        &identity.agent_identity_id,
                        LifecycleRequest { status },
                        &context("update"),
                    )
                    .await
                    .expect("updated"),
            );
            assert_eq!(updated.status, status);
            let refused = fixture
                .platform
                .sign(
                    &identity.agent_identity_id,
                    request.clone(),
                    context("new-sign"),
                )
                .await
                .expect("refused");
            assert_eq!(refused.status, 403);
            let refused = body_of(
                fixture
                    .platform
                    .verify(
                        VerificationRequest {
                            client_assertion: unused_assertion,
                            ..verification.clone()
                        },
                        context("new-verify"),
                    )
                    .await
                    .expect("refused"),
            );
            assert!(!refused.verified);
            assert!(refused.agent_did.is_none());
            assert_eq!(
                fixture
                    .platform
                    .sign(&identity.agent_identity_id, request, context("sign-1"))
                    .await
                    .expect("sign replay"),
                signed
            );
            assert_eq!(
                fixture
                    .platform
                    .verify(verification, context("verify-1"))
                    .await
                    .expect("verification replay"),
                verified
            );
        }
    });
}

#[test]
fn pending_replay_checks_authorization_without_restarting_signing() {
    block_on(async {
        let handler = FixedHandler::new(pending(Some("5")));
        let fixture = fixture(Settings {
            sign_handler: Some(handler.clone()),
            switched_policy: true,
            ..Settings::default()
        });
        let identity = provisioned(&fixture, "provision-1").await;
        let request = sign_request(AssertionOperation::Enroll);
        let first = fixture
            .platform
            .sign(
                &identity.agent_identity_id,
                request.clone(),
                context("pending"),
            )
            .await
            .expect("pending");
        assert_eq!(first.status, 202);
        fixture.switch.set(false);
        let refused = fixture
            .platform
            .sign(
                &identity.agent_identity_id,
                request.clone(),
                context("pending"),
            )
            .await
            .expect("denied");
        assert_eq!(code_of(&refused), Some(ErrorCode::NotRecognized));
        fixture.switch.set(true);
        fixture.policy.set(false);
        *handler.0.lock().expect("handler lock") = None;
        *fixture.key_store.assertion.lock().expect("assertion lock") = Some("must-not-sign".into());
        assert_eq!(
            fixture
                .platform
                .sign(&identity.agent_identity_id, request, context("pending"))
                .await
                .expect("replay"),
            first
        );
    });
}

#[test]
fn authorization_refusals_do_not_reserve_idempotency_keys() {
    block_on(async {
        let fixture = fixture(Settings::default());
        fixture.switch.set(false);
        let refused = fixture
            .platform
            .provision(
                ProvisionRequest {
                    service_did: SERVICE_DID.to_owned(),
                },
                context("provision-1"),
            )
            .await
            .expect("answered");
        assert_eq!(code_of(&refused), Some(ErrorCode::NotRecognized));

        fixture.switch.set(true);
        let replayed = fixture
            .platform
            .provision(
                ProvisionRequest {
                    service_did: SERVICE_DID.to_owned(),
                },
                context("provision-1"),
            )
            .await
            .expect("answered");
        assert_eq!(replayed.status, 200);
        assert_eq!(body_of(replayed).service_did, SERVICE_DID);
    });
}

/// A Service DID the Platform cannot resolve is not provisioned against.
#[test]
fn unresolvable_service_dids_are_refused() {
    block_on(async {
        let switch = Switch::on();
        let key_store = Arc::new(TestKeyStore::default());
        let mut options = PlatformOptions::new(
            Arc::new(AlwaysAuthorized),
            key_store,
            switch.clone(),
            DID_HOST,
            DID_TEMPLATE,
        );
        options.clock = Some(Arc::new(FixedClock(fixed_time())));
        options.discovery = DiscoveryOptions {
            endpoint_base: "/v1/aep".to_owned(),
            hosted_verification_endpoint: None,
            lifecycle_endpoint: "/v1/aep/agent-identities/{agent_identity_id}".to_owned(),
            list_endpoint: "/v1/aep/agent-identities".to_owned(),
            platform_did: None,
            platform_name: "Example Platform".to_owned(),
            provision_endpoint: "/v1/aep/agent-identities".to_owned(),
            sign_endpoint: "/v1/aep/agent-identities/{agent_identity_id}/sign".to_owned(),
        };
        // No identifier or DID generator is supplied, so the Platform mints its own.
        let platform = Platform::new(options).expect("Platform");
        switch.set(false);
        let response = platform
            .provision(
                ProvisionRequest {
                    service_did: SERVICE_DID.to_owned(),
                },
                context("provision-1"),
            )
            .await
            .expect("answered");
        assert_eq!(code_of(&response), Some(ErrorCode::InvalidRequest));

        switch.set(true);
        let identity = body_of(
            platform
                .provision(
                    ProvisionRequest {
                        service_did: SERVICE_DID.to_owned(),
                    },
                    context("provision-2"),
                )
                .await
                .expect("answered"),
        );
        assert!(identity.agent_identity_id.starts_with("pai_"));
        assert!(
            identity
                .agent_did
                .starts_with("did:web:platform.example:agents:")
        );
    });
}

struct AlwaysAuthorized;

#[async_trait]
impl Authorizer for AlwaysAuthorized {
    async fn authorize(
        &self,
        _request: &AuthorizationRequest,
        _context: &RequestContext,
    ) -> Result<bool, PlatformError> {
        Ok(true)
    }
}

/// PLT-LIFE-009: a Platform decides its own permitted transitions, and a refusal names the state
/// the identity is in.
#[test]
fn lifecycle_transitions_follow_the_platform_policy() {
    block_on(async {
        let fixture = fixture(Settings {
            switched_policy: true,
            ..Settings::default()
        });
        let identity = provisioned(&fixture, "provision-1").await;
        fixture.policy.set(false);
        let response = fixture
            .platform
            .update_identity(
                &identity.agent_identity_id,
                LifecycleRequest {
                    status: ManagedAgentStatus::Revoked,
                },
                &context("lifecycle-1"),
            )
            .await
            .expect("answered");
        assert_eq!(response.status, 403);
        // The identity is still active, so the refusal says the operation is unavailable rather
        // than naming a withdrawal that has not happened.
        assert_eq!(code_of(&response), Some(ErrorCode::IdentityUnavailable));

        let response = fixture
            .platform
            .sign(
                &identity.agent_identity_id,
                sign_request(AssertionOperation::Enroll),
                context("sign-1"),
            )
            .await
            .expect("answered");
        assert_eq!(code_of(&response), Some(ErrorCode::IdentityUnavailable));
    });
}

/// A generator that answers with nothing usable stops provisioning rather than minting a record
/// without an identifier.
#[test]
fn identity_generators_must_answer() {
    block_on(async {
        let fixture = fixture(Settings {
            identifier: Some(Arc::new(|| Ok(String::new()))),
            ..Settings::default()
        });
        assert!(
            fixture
                .platform
                .provision(
                    ProvisionRequest {
                        service_did: SERVICE_DID.to_owned(),
                    },
                    context("provision-1"),
                )
                .await
                .is_err()
        );
    });
}

/// A key store that answers with nothing has not signed anything.
#[test]
fn empty_assertions_are_refused() {
    block_on(async {
        let fixture = fixture(Settings::default());
        let identity = provisioned(&fixture, "provision-1").await;
        *fixture.key_store.assertion.lock().expect("lock") = Some(String::new());
        assert!(
            fixture
                .platform
                .sign(
                    &identity.agent_identity_id,
                    sign_request(AssertionOperation::Enroll),
                    context("sign-1"),
                )
                .await
                .is_err()
        );
    });
}

// --- sign handlers --------------------------------------------------------------------------------

struct FixedHandler(Mutex<Option<PlatformResponse<SignResponse>>>);

impl FixedHandler {
    fn new(response: PlatformResponse<SignResponse>) -> Arc<Self> {
        Arc::new(Self(Mutex::new(Some(response))))
    }
}

#[async_trait]
impl SignHandler for FixedHandler {
    async fn sign(
        &self,
        _identity: &IdentityRecord,
        _request: &SignRequest,
        _context: &RequestContext,
    ) -> Result<Option<PlatformResponse<SignResponse>>, PlatformError> {
        Ok(self.0.lock().expect("handler lock").clone())
    }
}

fn pending(retry_after_seconds: Option<&str>) -> PlatformResponse<SignResponse> {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(aep_core::MEDIA_TYPE),
    );
    PlatformResponse {
        body: ResponseBody::Success(SignResponse {
            additional: BTreeMap::new(),
            agent_did: None,
            client_assertion: None,
            expires_at: None,
            issued_at: None,
            jti: None,
            platform_context: BTreeMap::new(),
            retry_after_seconds: retry_after_seconds.map(str::to_owned),
            service_did: None,
            status: SignStatus::Pending,
        }),
        headers,
        status: 202,
    }
}

fn completed(agent_did: &str, window: Duration) -> PlatformResponse<SignResponse> {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(aep_core::MEDIA_TYPE),
    );
    let issued = fixed_time();
    PlatformResponse {
        body: ResponseBody::Success(SignResponse {
            additional: BTreeMap::new(),
            agent_did: Some(agent_did.to_owned()),
            client_assertion: Some("platform.assertion.value".to_owned()),
            expires_at: Some((issued + window).format(&Rfc3339).expect("time")),
            issued_at: Some(issued.format(&Rfc3339).expect("time")),
            jti: Some("assertion-1".to_owned()),
            platform_context: BTreeMap::new(),
            retry_after_seconds: None,
            service_did: Some(SERVICE_DID.to_owned()),
            status: SignStatus::Completed,
        }),
        headers,
        status: 200,
    }
}

async fn handled(response: PlatformResponse<SignResponse>) -> Result<u16, ()> {
    let fixture = fixture(Settings {
        sign_handler: Some(FixedHandler::new(response)),
        ..Settings::default()
    });
    let identity = provisioned(&fixture, "provision-1").await;
    fixture
        .platform
        .sign(
            &identity.agent_identity_id,
            sign_request(AssertionOperation::Enroll),
            context("sign-1"),
        )
        .await
        .map(|response| response.status)
        .map_err(|_| ())
}

/// PLT-SIGN-015/016/017: a pending answer is `202` with a usable polling interval, carries none
/// of the completed members, and never uses the HTTP `Retry-After` field.
#[test]
fn pending_sign_answers_follow_the_published_contract() {
    block_on(async {
        assert_eq!(handled(pending(Some("2"))).await, Ok(202));
        for retry in [None, Some("0"), Some("301"), Some("+2"), Some("02")] {
            assert_eq!(handled(pending(retry)).await, Err(()), "{retry:?}");
        }

        let mut carries_completed_member = pending(Some("2"));
        if let ResponseBody::Success(body) = &mut carries_completed_member.body {
            body.jti = Some("assertion-1".to_owned());
        }
        assert_eq!(handled(carries_completed_member).await, Err(()));

        let mut wrong_status = pending(Some("2"));
        wrong_status.status = 200;
        assert_eq!(handled(wrong_status).await, Err(()));

        let mut with_retry_header = pending(Some("2"));
        with_retry_header
            .headers
            .insert(header::RETRY_AFTER, HeaderValue::from_static("2"));
        assert_eq!(handled(with_retry_header).await, Err(()));
    });
}

/// PLT-SIGN-014 and PLT-SIGN-010/011: a completed answer names the identity and request it
/// answers, and carries exactly the window the request resolved to.
#[test]
fn completed_sign_answers_carry_the_effective_window() {
    block_on(async {
        let agent_did = "did:web:platform.example:agents:did-0";
        assert_eq!(
            handled(completed(agent_did, Duration::from_secs(60))).await,
            Ok(200)
        );
        // The request asked for 60 seconds; a longer or shorter window is not that assertion.
        for window in [Duration::from_secs(59), Duration::from_secs(300)] {
            assert_eq!(
                handled(completed(agent_did, window)).await,
                Err(()),
                "{window:?}"
            );
        }
        assert_eq!(
            handled(completed("did:web:other.example", Duration::from_secs(60))).await,
            Err(())
        );

        let mut without_window = completed(agent_did, Duration::from_secs(60));
        if let ResponseBody::Success(body) = &mut without_window.body {
            body.issued_at = None;
        }
        assert_eq!(handled(without_window).await, Err(()));

        let mut empty_assertion = completed(agent_did, Duration::from_secs(60));
        if let ResponseBody::Success(body) = &mut empty_assertion.body {
            body.client_assertion = Some(String::new());
        }
        assert_eq!(handled(empty_assertion).await, Err(()));

        let mut wrong_jti = completed(agent_did, Duration::from_secs(60));
        if let ResponseBody::Success(body) = &mut wrong_jti.body {
            body.jti = Some("assertion-other".to_owned());
        }
        assert_eq!(handled(wrong_jti).await, Err(()));
    });
}

/// A handler may refuse, and its refusal has to be an answer the Platform can send.
#[test]
fn handler_refusals_must_be_consistent() {
    block_on(async {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(aep_core::PROBLEM_MEDIA_TYPE),
        );
        let refusal = |status: u16, declared: i64| PlatformResponse {
            body: ResponseBody::Problem(Box::new(new_problem_details(
                ErrorCode::RateLimited,
                "Rate Limited",
                declared,
            ))),
            headers: headers.clone(),
            status,
        };
        assert_eq!(handled(refusal(429, 429)).await, Ok(429));
        assert_eq!(handled(refusal(429, 503)).await, Err(()));
    });
}

// --- hosted verification --------------------------------------------------------------------------

/// PLT-VER-004/005: a hosted verification answers for a live assertion once, and every other
/// outcome is the same undisclosing refusal.
#[test]
fn hosted_verification_answers_once_and_discloses_nothing() {
    block_on(async {
        let fixture = fixture(Settings {
            hosted_verification: true,
            ..Settings::default()
        });
        let identity = provisioned(&fixture, "provision-1").await;
        let assertion = body_of(
            fixture
                .platform
                .sign(
                    &identity.agent_identity_id,
                    sign_request(AssertionOperation::Enroll),
                    context("sign-1"),
                )
                .await
                .expect("signed"),
        )
        .client_assertion
        .expect("assertion");

        let verify = |assertion: String, key: &'static str| {
            let platform = fixture.platform.clone();
            async move {
                body_of(
                    platform
                        .verify(
                            VerificationRequest {
                                client_assertion: assertion,
                                op: AssertionOperation::Enroll,
                                resource: None,
                                service_did: SERVICE_DID.to_owned(),
                            },
                            context(key),
                        )
                        .await
                        .expect("answered"),
                )
            }
        };

        let verified = verify(assertion.clone(), "verify-1").await;
        assert!(verified.verified);
        assert_eq!(verified.reason, "verified");
        assert_eq!(
            verified.agent_did.as_deref(),
            Some(identity.agent_did.as_str())
        );
        assert_eq!(verified.status, Some(ManagedAgentStatus::Active));

        // PLT-VER-005: the same assertion is not consumable twice.
        let replayed = verify(assertion.clone(), "verify-2").await;
        assert!(!replayed.verified);
        assert_eq!(replayed.reason, "not_recognized");
        assert!(replayed.agent_did.is_none());

        // Anything the Platform cannot tie to one of its own live identities answers the same way:
        // something that is not a JWT, one with no issuer, one whose subject or `kid` names
        // another identity, one for an identity this Platform never minted, and one whose
        // signature does not hold.
        // The signature is altered in place, so the token still decodes and fails where it is
        // checked rather than where it is read.
        let (prefix, signature) = assertion.rsplit_once('.').expect("compact JWS");
        let tampered = format!(
            "{prefix}.{}{}",
            if signature.starts_with('A') { 'B' } else { 'A' },
            &signature[1..]
        );
        for (body, key) in [
            ("not-a-jwt".to_owned(), "verify-3"),
            (assertion.clone(), "verify-4"),
            // `{"alg":"EdDSA","kid":"<agent did>","typ":"JWT"}` over an empty payload.
            ("eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWI6cGxhdGZvcm0uZXhhbXBsZTphZ2VudHM6ZGlkLTAiLCJ0eXAiOiJKV1QifQ.e30.AAAA".to_owned(), "verify-5"),
            // The same header over claims whose `sub` names another identity.
            ("eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWI6cGxhdGZvcm0uZXhhbXBsZTphZ2VudHM6ZGlkLTAiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJkaWQ6d2ViOnBsYXRmb3JtLmV4YW1wbGU6YWdlbnRzOmRpZC0wIiwic3ViIjoiZGlkOndlYjpvdGhlci5leGFtcGxlIn0.AAAA".to_owned(), "verify-6"),
            // Claims for an Agent DID this Platform never minted.
            ("eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWI6dW5rbm93bi5leGFtcGxlIiwidHlwIjoiSldUIn0.eyJpc3MiOiJkaWQ6d2ViOnVua25vd24uZXhhbXBsZSIsInN1YiI6ImRpZDp3ZWI6dW5rbm93bi5leGFtcGxlIn0.AAAA".to_owned(), "verify-7"),
            (tampered, "verify-8"),
        ] {
            let refused = verify(body, key).await;
            assert!(!refused.verified, "{key}");
            assert_eq!(refused.reason, "not_recognized", "{key}");
            assert!(refused.agent_did.is_none(), "{key}");
        }
    });
}

/// PLT-VER-003/006/007: the request shape is checked before anything is verified.
#[test]
fn hosted_verification_requests_are_checked_first() {
    block_on(async {
        let fixture = fixture(Settings {
            hosted_verification: true,
            ..Settings::default()
        });
        let request =
            |assertion: &str, op: AssertionOperation, resource: Option<&str>| VerificationRequest {
                client_assertion: assertion.to_owned(),
                op,
                resource: resource.map(str::to_owned),
                service_did: SERVICE_DID.to_owned(),
            };
        for (value, key) in [
            (request("", AssertionOperation::Enroll, None), "v1"),
            (
                request("assertion", AssertionOperation::Authenticate, None),
                "v2",
            ),
            (
                request(
                    "assertion",
                    AssertionOperation::Authenticate,
                    Some("http://service.example/x"),
                ),
                "v3",
            ),
            (
                request(
                    "assertion",
                    AssertionOperation::Enroll,
                    Some("https://service.example/x"),
                ),
                "v4",
            ),
        ] {
            let response = fixture
                .platform
                .verify(value, context(key))
                .await
                .expect("answered");
            assert_eq!(code_of(&response), Some(ErrorCode::InvalidRequest), "{key}");
        }

        let mut bad_service = request("assertion", AssertionOperation::Enroll, None);
        bad_service.service_did = "service.example".to_owned();
        let response = fixture
            .platform
            .verify(bad_service, context("v5"))
            .await
            .expect("answered");
        assert_eq!(code_of(&response), Some(ErrorCode::InvalidRequest));
    });
}

/// PLT-VER-009: a caller that is not the identity's own principal learns nothing about it.
#[test]
fn hosted_verification_stays_within_the_caller() {
    block_on(async {
        let fixture = fixture(Settings {
            hosted_verification: true,
            switched_policy: true,
            ..Settings::default()
        });
        let identity = provisioned(&fixture, "provision-1").await;
        let assertion = body_of(
            fixture
                .platform
                .sign(
                    &identity.agent_identity_id,
                    sign_request(AssertionOperation::Enroll),
                    context("sign-1"),
                )
                .await
                .expect("signed"),
        )
        .client_assertion
        .expect("assertion");
        let request = || VerificationRequest {
            client_assertion: assertion.clone(),
            op: AssertionOperation::Enroll,
            resource: None,
            service_did: SERVICE_DID.to_owned(),
        };

        let mut intruder = context("verify-1");
        intruder.principal = "intruder".to_owned();
        assert!(
            !body_of(
                fixture
                    .platform
                    .verify(request(), intruder)
                    .await
                    .expect("answered")
            )
            .verified
        );

        // A Service the identity was not scoped to learns nothing either.
        let mut other_service = request();
        other_service.service_did = "did:web:other.example".to_owned();
        assert!(
            !body_of(
                fixture
                    .platform
                    .verify(other_service, context("verify-2"))
                    .await
                    .expect("answered")
            )
            .verified
        );

        // Nor does a caller the policy will not verify for.
        fixture.policy.set(false);
        assert!(
            !body_of(
                fixture
                    .platform
                    .verify(request(), context("verify-3"))
                    .await
                    .expect("answered")
            )
            .verified
        );
    });
}

/// Every response renders to the JSON body it will be sent as.
#[test]
fn responses_render_to_their_wire_form() {
    block_on(async {
        let fixture = fixture(Settings::default());
        let identity = provisioned(&fixture, "provision-1").await;
        let listed = fixture
            .platform
            .list(
                IdentityListQuery {
                    descending: true,
                    limit: 10,
                    offset: 0,
                    service_did: None,
                    status: Some(ManagedAgentStatus::Active),
                },
                &context("list-1"),
            )
            .await
            .expect("answered");
        let rendered = listed.to_json().expect("JSON");
        assert_eq!(rendered["count"], json!("1"));
        assert_eq!(rendered["data"][0]["agent_did"], json!(identity.agent_did));

        let refused = fixture
            .platform
            .get_identity("identity-missing", &context("get-1"))
            .await
            .expect("answered");
        assert_eq!(
            refused.to_json().expect("JSON")["code"],
            json!("not_recognized")
        );
        assert_eq!(ManagedAgentStatus::Active.as_str(), "active");
        assert_eq!(ManagedAgentStatus::Revoked.as_str(), "revoked");
        assert_eq!(ManagedAgentStatus::Suspended.as_str(), "suspended");
        assert_eq!(ManagedAgentStatus::Terminated.as_str(), "terminated");
    });
}
