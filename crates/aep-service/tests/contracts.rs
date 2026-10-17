//! Command refusals, authorization-carrier selection, and the configuration that guards both.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use aep_core::{
    AgentStatus, AuthenticationMethod, ClaimName, ClientAssertionClaims, EnrollmentDecisionStatus,
    ErrorCode, GrantRequest, GrantType, GrantTypeConfig, IdentityMethod, RevokeRequest,
    SigningAlgorithm, StringBoolean, validate_problem_details,
};
use aep_service::*;
use async_trait::async_trait;
use futures::executor::block_on;
use http::{HeaderMap, HeaderValue, header};
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;

const AGENT_DID: &str = "did:web:agent.example";
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

/// A verifier that answers with claims built from the request, or refuses outright.
struct ScriptedVerifier {
    refuse: bool,
    subject: Mutex<String>,
}

impl ScriptedVerifier {
    fn accepting() -> Arc<Self> {
        Arc::new(Self {
            refuse: false,
            subject: Mutex::new(AGENT_DID.to_owned()),
        })
    }

    fn refusing() -> Arc<Self> {
        Arc::new(Self {
            refuse: true,
            subject: Mutex::new(AGENT_DID.to_owned()),
        })
    }
}

#[async_trait]
impl ClientAssertionVerifier for ScriptedVerifier {
    async fn verify(
        &self,
        context: ClientAssertionVerificationContext,
    ) -> Result<ClientAssertionClaims, ServiceError> {
        if self.refuse {
            return Err(ServiceError::Handler("refused".to_owned()));
        }
        let subject = self.subject.lock().expect("subject lock").clone();
        let timestamp = context.current_time.unix_timestamp();
        Ok(ClientAssertionClaims {
            additional: BTreeMap::new(),
            aud: context.service_did,
            exp: timestamp + 60,
            iat: timestamp,
            iss: subject.clone(),
            jti: context.assertion,
            op: context.operation,
            resource: context.resource.map(|resource| resource.to_string()),
            sub: subject,
        })
    }
}

#[derive(Default)]
struct StubHandler {
    grants: Mutex<Vec<GrantRequest>>,
    revocations: Mutex<Vec<RevokeRequest>>,
    principal: Option<AuthenticatedPrincipal>,
}

#[async_trait]
impl GrantTypeHandler for StubHandler {
    async fn grant(
        &self,
        request: &GrantRequest,
        _context: &GrantContext,
    ) -> Result<Value, ServiceError> {
        self.grants.lock().expect("lock").push(request.clone());
        Ok(json!({
            "api_key": "secret",
            "credential_id": "credential-1",
            "expires_at": "2026-09-01T12:00:00Z",
            "header": "x-api-key"
        }))
    }

    async fn revoke(
        &self,
        request: &RevokeRequest,
        _context: &GrantContext,
    ) -> Result<(), ServiceError> {
        self.revocations.lock().expect("lock").push(request.clone());
        Ok(())
    }

    async fn authenticate(
        &self,
        _input: &CredentialAuthenticationInput,
    ) -> Result<Option<AuthenticatedPrincipal>, ServiceError> {
        Ok(self.principal.clone())
    }
}

/// A handler whose Grant answer is missing the credential identifier the Service requires.
struct UnusableHandler;

#[async_trait]
impl GrantTypeHandler for UnusableHandler {
    async fn grant(
        &self,
        _request: &GrantRequest,
        _context: &GrantContext,
    ) -> Result<Value, ServiceError> {
        Ok(json!({"credential_id": ""}))
    }

    async fn revoke(
        &self,
        _request: &RevokeRequest,
        _context: &GrantContext,
    ) -> Result<(), ServiceError> {
        Ok(())
    }
}

struct Fixture {
    service: Arc<Service>,
    store: Arc<MemoryEnrollmentStore>,
    verifier: Arc<ScriptedVerifier>,
}

struct Settings {
    authentication_methods: Vec<AuthenticationMethod>,
    handler: Option<Arc<dyn GrantTypeHandler>>,
    identity_methods: Vec<IdentityMethod>,
    maximum_clock_skew: Duration,
    verifier: Arc<ScriptedVerifier>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            authentication_methods: vec![
                AuthenticationMethod::AepJwt,
                AuthenticationMethod::ApiKey,
            ],
            handler: Some(Arc::new(StubHandler::default())),
            identity_methods: vec![IdentityMethod::DidWeb],
            maximum_clock_skew: aep_core::RECOMMENDED_CLOCK_SKEW,
            verifier: ScriptedVerifier::accepting(),
        }
    }
}

fn options(settings: &Settings) -> ServiceOptions {
    let mut options = ServiceOptions::new(SERVICE_DID, settings.verifier.clone());
    options.authentication_methods = settings.authentication_methods.clone();
    options.claims.required = vec![ClaimName::ContactEmail];
    options.clock = Some(Arc::new(FixedClock(fixed_time())));
    options.identity_methods = settings.identity_methods.clone();
    options.maximum_clock_skew = settings.maximum_clock_skew;
    // Every advertised session-credential method needs a grant type behind it, so the fixture
    // offers one per method it advertises.
    options.grant_types = settings
        .handler
        .clone()
        .map(|handler| {
            settings
                .authentication_methods
                .iter()
                .filter(|method| *method != &AuthenticationMethod::AepJwt)
                .map(|method| GrantTypeDefinition {
                    config: Some(GrantTypeConfig {
                        additional: BTreeMap::new(),
                        supports_per_credential_revoke: Some(StringBoolean::True),
                    }),
                    grant_type: GrantType::from(method.as_str()),
                    handler: Some(handler.clone()),
                })
                .collect()
        })
        .unwrap_or_default();
    options
}

fn build_fixture(settings: Settings) -> Fixture {
    let store = Arc::new(MemoryEnrollmentStore::default());
    let mut settings_options = options(&settings);
    settings_options.enrollment_store = Some(store.clone());
    Fixture {
        service: Service::new(settings_options).expect("Service"),
        store,
        verifier: settings.verifier,
    }
}

fn enroll_body(claims: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"agent_did": AGENT_DID, "claims": claims})).expect("JSON")
}

/// An Enroll body that also carries the idempotency key, which CORE-ENR-006 requires to match the
/// header form.
fn enroll_body_with_key(claims: Value, key: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "agent_did": AGENT_DID,
        "claims": claims,
        "idempotency_key": key
    }))
    .expect("JSON")
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

fn code_of(response: &ServiceResponse) -> Option<ErrorCode> {
    match &response.body {
        ResponseBody::Problem(problem) => {
            validate_problem_details(problem).expect("valid Problem Details");
            Some(problem.code.clone())
        }
        _ => None,
    }
}

async fn enrolled(fixture: &Fixture) {
    let response = fixture
        .service
        .enroll(
            &enroll_body(json!({"contact.email": "owner@example.com"})),
            idempotent("enroll-assertion", "request-1"),
        )
        .await
        .expect("enrolled");
    assert_eq!(response.status, 200);
}

// --- command refusals ---------------------------------------------------------------------------

/// CORE-ERR-009: every refusal carries its registered code with the status the registry pairs it
/// with, and the published title is one sentence.
#[test]
fn refusals_carry_their_registered_status() {
    block_on(async {
        let fixture = build_fixture(Settings::default());
        // CLM-SEC-003 and CORE-ERR-009: unmet requirements answer 422, not 403.
        let response = fixture
            .service
            .enroll(&enroll_body(json!({})), idempotent("a1", "request-1"))
            .await
            .expect("answered");
        assert_eq!(response.status, 422);
        assert_eq!(code_of(&response), Some(ErrorCode::RequirementsUnmet));
        let ResponseBody::Problem(problem) = &response.body else {
            panic!("Problem Details expected");
        };
        assert_eq!(problem.title, "Requirements unmet");
        assert_eq!(
            problem.requirements_pending.as_deref(),
            Some(&["contact.email".to_owned()][..])
        );
    });
}

/// An assertion the verifier will not accept is not an authenticated request.
#[test]
fn unverifiable_assertions_are_refused() {
    block_on(async {
        let fixture = build_fixture(Settings {
            verifier: ScriptedVerifier::refusing(),
            ..Settings::default()
        });
        for response in [
            fixture
                .service
                .enroll(&enroll_body(json!({})), idempotent("a1", "request-1"))
                .await
                .expect("answered"),
            fixture
                .service
                .status(authenticated("a1"))
                .await
                .expect("answered"),
            fixture
                .service
                .grant(
                    b"{\"grant_type\":\"api-key\"}",
                    idempotent("a1", "request-1"),
                )
                .await
                .expect("answered"),
            fixture
                .service
                .revoke(
                    b"{\"grant_type\":\"api-key\"}",
                    idempotent("a1", "request-1"),
                )
                .await
                .expect("answered"),
        ] {
            assert_eq!(response.status, 401);
            assert_eq!(code_of(&response), Some(ErrorCode::NotRecognized));
        }
    });
}

/// CORE-IDP-002/003 and CORE-ENR-006: a state-mutating command carries a non-empty key, and the
/// body form has to agree with it.
#[test]
fn idempotency_keys_are_required_and_consistent() {
    block_on(async {
        let fixture = build_fixture(Settings::default());
        for response in [
            fixture
                .service
                .enroll(
                    &enroll_body(json!({"contact.email": "owner@example.com"})),
                    idempotent("a1", ""),
                )
                .await
                .expect("answered"),
            fixture
                .service
                .grant(b"{\"grant_type\":\"api-key\"}", idempotent("a2", ""))
                .await
                .expect("answered"),
            fixture
                .service
                .revoke(b"{\"grant_type\":\"api-key\"}", idempotent("a3", ""))
                .await
                .expect("answered"),
        ] {
            assert_eq!(response.status, 400);
            assert_eq!(code_of(&response), Some(ErrorCode::InvalidRequest));
        }

        let response = fixture
            .service
            .enroll(
                &enroll_body_with_key(json!({"contact.email": "owner@example.com"}), "request-1"),
                idempotent("a4", "another-key"),
            )
            .await
            .expect("answered");
        assert_eq!(code_of(&response), Some(ErrorCode::InvalidRequest));
    });
}

/// A body the Service cannot parse, or one that names another Agent, is refused before anything
/// is stored.
#[test]
fn unusable_command_bodies_are_refused() {
    block_on(async {
        let fixture = build_fixture(Settings::default());
        for (index, (body, code)) in [
            (&b"{"[..], ErrorCode::InvalidRequest),
            (b"{\"agent_did\":\"\"}", ErrorCode::InvalidRequest),
        ]
        .into_iter()
        .enumerate()
        {
            let response = fixture
                .service
                .enroll(body, idempotent(&format!("body-{index}"), "request-1"))
                .await
                .expect("answered");
            assert_eq!(code_of(&response), Some(code), "{body:?}");
        }

        // The body names an Agent other than the authenticated subject.
        let other =
            serde_json::to_vec(&json!({"agent_did": "did:web:other.example"})).expect("JSON");
        let response = fixture
            .service
            .enroll(&other, idempotent("a2", "request-2"))
            .await
            .expect("answered");
        assert_eq!(code_of(&response), Some(ErrorCode::NotRecognized));

        for (index, body) in [&b"{"[..], b"{\"grant_type\":\"\"}"]
            .into_iter()
            .enumerate()
        {
            assert_eq!(
                code_of(
                    &fixture
                        .service
                        .grant(body, idempotent(&format!("grant-{index}"), "request-3"))
                        .await
                        .expect("answered")
                ),
                Some(ErrorCode::InvalidRequest)
            );
            assert_eq!(
                code_of(
                    &fixture
                        .service
                        .revoke(body, idempotent(&format!("revoke-{index}"), "request-4"))
                        .await
                        .expect("answered")
                ),
                Some(ErrorCode::InvalidRequest)
            );
        }
    });
}

/// CLM-SEC-006: the claim document is bounded before it is stored or acted on.
#[test]
fn oversized_claim_documents_are_refused() {
    block_on(async {
        let fixture = build_fixture(Settings::default());
        let deep = |depth: usize| {
            let mut value = json!("leaf");
            for _ in 0..depth {
                value = json!({ "nested": value });
            }
            json!({"contact.email": "owner@example.com", "vendor.tree": value})
        };
        let wide = || {
            let mut object = serde_json::Map::new();
            object.insert("contact.email".to_owned(), json!("owner@example.com"));
            for index in 0..200 {
                object.insert(format!("vendor.member-{index}"), json!(index));
            }
            Value::Object(object)
        };
        for (index, (label, claims)) in [
            ("depth", deep(12)),
            ("members", wide()),
            (
                "string length",
                json!({"contact.email": "owner@example.com", "vendor.note": "x".repeat(5000)}),
            ),
            (
                "encoded size",
                json!({"contact.email": "owner@example.com", "vendor.blob": vec!["x".repeat(4000); 32]}),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let response = fixture
                .service
                .enroll(&enroll_body(claims), idempotent(&format!("limit-{index}"), "request-1"))
                .await
                .expect("answered");
            assert_eq!(
                code_of(&response),
                Some(ErrorCode::InvalidRequest),
                "{label}"
            );
        }

        // A document inside every bound is accepted.
        let response = fixture
            .service
            .enroll(
                &enroll_body(json!({"contact.email": "owner@example.com", "vendor.tree": deep(4)})),
                idempotent("a2", "request-2"),
            )
            .await
            .expect("answered");
        assert_eq!(response.status, 200);
    });
}

/// CORE-GRT-003 and the lifecycle table: Grant needs a recognized, active enrolment, and each
/// withdrawn state answers with its own registered code.
#[test]
fn grant_follows_the_enrolment_lifecycle() {
    block_on(async {
        let fixture = build_fixture(Settings::default());
        // No enrolment at all.
        assert_eq!(
            code_of(
                &fixture
                    .service
                    .grant(
                        b"{\"grant_type\":\"api-key\"}",
                        idempotent("a1", "request-1")
                    )
                    .await
                    .expect("answered")
            ),
            Some(ErrorCode::NotRecognized)
        );
        assert_eq!(
            code_of(
                &fixture
                    .service
                    .revoke(
                        b"{\"grant_type\":\"api-key\"}",
                        idempotent("a2", "request-2")
                    )
                    .await
                    .expect("answered")
            ),
            Some(ErrorCode::NotRecognized)
        );
        assert_eq!(
            code_of(
                &fixture
                    .service
                    .status(authenticated("a3"))
                    .await
                    .expect("answered")
            ),
            Some(ErrorCode::NotRecognized)
        );

        for (status, code, http) in [
            (AgentStatus::Pending, ErrorCode::VerificationPending, 403),
            (AgentStatus::Rejected, ErrorCode::NotRecognized, 401),
            (AgentStatus::Suspended, ErrorCode::IdentitySuspended, 403),
            (AgentStatus::Terminated, ErrorCode::IdentityTerminated, 403),
            (
                AgentStatus::Unavailable,
                ErrorCode::IdentityUnavailable,
                403,
            ),
        ] {
            fixture
                .store
                .save(EnrollmentRecord {
                    agent_did: AGENT_DID.to_owned(),
                    claims: Default::default(),
                    created_at: fixed_time(),
                    owner_action_required: status == AgentStatus::Pending,
                    requirements_pending: vec!["company.registration".to_owned()],
                    since: fixed_time(),
                    status,
                    updated_at: fixed_time(),
                    verification_pending: vec!["contact.email".to_owned()],
                })
                .await
                .expect("saved");
            let response = fixture
                .service
                .grant(
                    b"{\"grant_type\":\"api-key\"}",
                    idempotent(
                        &format!("a-{}", status.as_str()),
                        &format!("k-{}", status.as_str()),
                    ),
                )
                .await
                .expect("answered");
            assert_eq!(response.status, http, "{status:?}");
            assert_eq!(code_of(&response), Some(code), "{status:?}");
            if status == AgentStatus::Pending {
                let ResponseBody::Problem(problem) = &response.body else {
                    panic!("Problem Details expected");
                };
                assert_eq!(problem.owner_action_required, Some(StringBoolean::True));
                assert!(problem.verification_pending.is_some());
                assert!(problem.requirements_pending.is_some());
            }
        }
    });
}

/// CORE-GRT-005 / CORE-RVK-002: a grant type the Service does not offer has no handler.
#[test]
fn unoffered_grant_types_are_refused() {
    block_on(async {
        let fixture = build_fixture(Settings::default());
        enrolled(&fixture).await;
        for response in [
            fixture
                .service
                .grant(
                    b"{\"grant_type\":\"oauth-bearer\"}",
                    idempotent("a1", "request-2"),
                )
                .await
                .expect("answered"),
            fixture
                .service
                .revoke(
                    b"{\"grant_type\":\"oauth-bearer\"}",
                    idempotent("a2", "request-3"),
                )
                .await
                .expect("answered"),
        ] {
            assert_eq!(response.status, 400);
            assert_eq!(code_of(&response), Some(ErrorCode::UnsupportedGrantType));
        }
    });
}

/// CORE-IDP-007/009: the same key with different material is a conflict.
#[test]
fn reusing_a_key_for_other_material_conflicts() {
    block_on(async {
        let fixture = build_fixture(Settings::default());
        enrolled(&fixture).await;
        let response = fixture
            .service
            .grant(b"{\"grant_type\":\"api-key\"}", idempotent("a1", "shared"))
            .await
            .expect("answered");
        assert_eq!(response.status, 200);
        let conflict = fixture
            .service
            .grant(
                b"{\"grant_type\":\"api-key\",\"requested_scopes\":[\"purchase\"]}",
                idempotent("a2", "shared"),
            )
            .await
            .expect("answered");
        assert_eq!(conflict.status, 409);
        assert_eq!(code_of(&conflict), Some(ErrorCode::IdempotencyConflict));
    });
}

/// A Grant handler that does not return a usable credential identifier has not issued anything.
#[test]
fn grant_answers_require_a_credential_identifier() {
    block_on(async {
        let fixture = build_fixture(Settings {
            handler: Some(Arc::new(UnusableHandler)),
            ..Settings::default()
        });
        enrolled(&fixture).await;
        assert!(
            fixture
                .service
                .grant(
                    b"{\"grant_type\":\"api-key\"}",
                    idempotent("a1", "request-2")
                )
                .await
                .is_err()
        );
    });
}

/// Revoke without a grant type reaches every handler the Service offers.
#[test]
fn revoke_without_a_grant_type_reaches_every_handler() {
    block_on(async {
        let handler = Arc::new(StubHandler::default());
        let fixture = build_fixture(Settings {
            handler: Some(handler.clone()),
            ..Settings::default()
        });
        enrolled(&fixture).await;
        let response = fixture
            .service
            .revoke(
                b"{\"all_grant_types\":\"true\"}",
                idempotent("a1", "request-2"),
            )
            .await
            .expect("answered");
        assert_eq!(response.status, 200);
        assert_eq!(handler.revocations.lock().expect("lock").len(), 1);
    });
}

// --- authorization carriers ---------------------------------------------------------------------

fn protected(headers: HeaderMap) -> ProtectedResourceRequest {
    ProtectedResourceRequest {
        headers,
        method: http::Method::GET,
        url: Url::parse("https://service.example/v1/orders").expect("URL"),
    }
}

fn headers(values: &[(&str, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in values {
        headers.append(
            http::HeaderName::from_bytes(name.as_bytes()).expect("name"),
            HeaderValue::from_str(value).expect("value"),
        );
    }
    headers
}

fn rejected(authentication: ProtectedResourceAuthentication) -> (u16, Option<ErrorCode>) {
    match authentication {
        ProtectedResourceAuthentication::Rejected(response) => {
            (response.status, code_of(&response))
        }
        ProtectedResourceAuthentication::Authenticated(principal) => {
            panic!("expected a refusal, got {principal:?}")
        }
    }
}

/// CORE-PR-010/018: a request presents at most one AEP carrier, and anything ambiguous is refused
/// without a fallback.
#[test]
fn ambiguous_carriers_are_refused() {
    block_on(async {
        let fixture = build_fixture(Settings::default());
        for values in [
            // Two dedicated field lines.
            vec![
                ("aep-authorization", "AEP first"),
                ("aep-authorization", "AEP second"),
            ],
            // Two standard field lines.
            vec![
                ("authorization", "Bearer first"),
                ("authorization", "Bearer second"),
            ],
            // Both carriers, each recognized.
            vec![
                ("aep-authorization", "AEP assertion"),
                ("authorization", "Bearer token"),
            ],
            // A dedicated value the grammar does not recognize.
            vec![("aep-authorization", "AEP first,AEP second")],
            vec![("aep-authorization", "Digest value")],
            vec![("aep-authorization", "AEP")],
        ] {
            let outcome = rejected(
                fixture
                    .service
                    .authenticate_protected_resource(protected(headers(&values)))
                    .await
                    .expect("answered"),
            );
            assert_eq!(outcome, (401, Some(ErrorCode::NotRecognized)), "{values:?}");
        }
    });
}

/// CORE-PR-038: a request with no credential asks for one; a credential the Service cannot place
/// is not recognized; a method the Service does not advertise is named as unsupported.
#[test]
fn protected_resource_refusals_name_their_reason() {
    block_on(async {
        let fixture = build_fixture(Settings::default());
        // Nothing presented at all, and an unrelated authorization scheme.
        for values in [
            vec![],
            vec![("authorization", "Digest realm=\"x\"")],
            vec![("authorization", "Payment credential")],
        ] {
            assert_eq!(
                rejected(
                    fixture
                        .service
                        .authenticate_protected_resource(protected(headers(&values)))
                        .await
                        .expect("answered")
                ),
                (401, Some(ErrorCode::AuthenticationRequired)),
                "{values:?}"
            );
        }

        for value in [
            "AEP",
            "Bearer",
            "Basic",
            "AEP first second",
            "bEaReR first second",
            "Basic first, second",
        ] {
            assert_eq!(
                rejected(
                    fixture
                        .service
                        .authenticate_protected_resource(protected(headers(&[(
                            "authorization",
                            value
                        )])))
                        .await
                        .expect("malformed credential response")
                ),
                (401, Some(ErrorCode::NotRecognized)),
                "{value}"
            );
        }
        let mut malformed_bytes = HeaderMap::new();
        malformed_bytes.insert(
            header::AUTHORIZATION,
            HeaderValue::from_bytes(b"AEP \xff").expect("header"),
        );
        assert_eq!(
            rejected(
                fixture
                    .service
                    .authenticate_protected_resource(protected(malformed_bytes))
                    .await
                    .expect("malformed assertion response")
            ),
            (401, Some(ErrorCode::NotRecognized))
        );

        // An advertised method whose credential does not match anything issued.
        assert_eq!(
            rejected(
                fixture
                    .service
                    .authenticate_protected_resource(protected(headers(&[(
                        "authorization",
                        "Bearer unknown"
                    )])))
                    .await
                    .expect("answered")
            ),
            (401, Some(ErrorCode::UnsupportedAuthenticationMethod))
        );

        // A Service that advertises no AEP JWT method does not accept an assertion.
        let jwt_less = build_fixture(Settings {
            authentication_methods: vec![AuthenticationMethod::ApiKey],
            ..Settings::default()
        });
        assert_eq!(
            rejected(
                jwt_less
                    .service
                    .authenticate_protected_resource(protected(headers(&[(
                        "authorization",
                        "AEP assertion"
                    )])))
                    .await
                    .expect("answered")
            ),
            (401, Some(ErrorCode::UnsupportedAuthenticationMethod))
        );
    });
}

/// The challenge names the Service, where to inspect it, and why the request was refused.
#[test]
fn refusals_carry_an_aep_challenge() {
    block_on(async {
        let fixture = build_fixture(Settings::default());
        let ProtectedResourceAuthentication::Rejected(response) = fixture
            .service
            .authenticate_protected_resource(protected(HeaderMap::new()))
            .await
            .expect("answered")
        else {
            panic!("expected a refusal");
        };
        let challenge = response
            .headers
            .get(header::WWW_AUTHENTICATE)
            .expect("challenge")
            .to_str()
            .expect("value")
            .to_owned();
        assert!(challenge.starts_with("AEP "), "{challenge}");
        assert!(challenge.contains(&format!("service_did=\"{SERVICE_DID}\"")));
        // With no configured Inspect URL the challenge points at the well-known path of the
        // resource's own origin.
        assert!(
            challenge.contains("inspect=\"https://service.example/.well-known/aep\""),
            "{challenge}"
        );
        assert!(challenge.contains("reason=\"authentication_required\""));
    });
}

/// An assertion authenticates a protected resource only while its enrolment is active.
#[test]
fn assertions_authenticate_only_active_enrolments() {
    block_on(async {
        let fixture = build_fixture(Settings::default());
        let request = || protected(headers(&[("authorization", "AEP assertion-1")]));
        // No enrolment behind the assertion.
        assert_eq!(
            rejected(
                fixture
                    .service
                    .authenticate_protected_resource(request())
                    .await
                    .expect("answered")
            ),
            (401, Some(ErrorCode::NotRecognized))
        );

        enrolled(&fixture).await;
        let ProtectedResourceAuthentication::Authenticated(principal) = fixture
            .service
            .authenticate_protected_resource(protected(headers(&[(
                "aep-authorization",
                "AEP assertion-2",
            )])))
            .await
            .expect("answered")
        else {
            panic!("expected an authenticated principal");
        };
        assert_eq!(principal.agent_did, AGENT_DID);
        assert_eq!(
            principal.authentication_method,
            AuthenticationMethod::AepJwt
        );
        assert_eq!(
            principal.authentication_kind,
            AuthenticationKind::ClientAssertion
        );

        fixture
            .store
            .save(EnrollmentRecord {
                agent_did: AGENT_DID.to_owned(),
                claims: Default::default(),
                created_at: fixed_time(),
                owner_action_required: false,
                requirements_pending: Vec::new(),
                since: fixed_time(),
                status: AgentStatus::Suspended,
                updated_at: fixed_time(),
                verification_pending: Vec::new(),
            })
            .await
            .expect("saved");
        assert_eq!(
            rejected(
                fixture
                    .service
                    .authenticate_protected_resource(protected(headers(&[(
                        "authorization",
                        "AEP assertion-3"
                    )])))
                    .await
                    .expect("answered")
            ),
            (401, Some(ErrorCode::NotRecognized))
        );
    });
}

#[test]
fn custom_credential_handlers_cannot_substitute_the_authenticated_method() {
    block_on(async {
        let valid = AuthenticatedPrincipal {
            agent_did: AGENT_DID.into(),
            authentication_kind: AuthenticationKind::SessionCredential,
            authentication_method: AuthenticationMethod::ApiKey,
            credential_id: Some("credential-1".into()),
            grant_type: Some(GrantType::ApiKey),
            scopes: vec![],
        };
        for case in 0..5 {
            let mut principal = valid.clone();
            match case {
                0 => {}
                1 => principal.agent_did.clear(),
                2 => principal.authentication_kind = AuthenticationKind::ClientAssertion,
                3 => principal.authentication_method = AuthenticationMethod::Basic,
                _ => principal.grant_type = Some(GrantType::OAuthBearer),
            }
            let fixture = build_fixture(Settings {
                handler: Some(Arc::new(StubHandler {
                    principal: Some(principal),
                    ..Default::default()
                })),
                ..Default::default()
            });
            enrolled(&fixture).await;
            let result = fixture
                .service
                .authenticate_protected_resource(protected(headers(&[(
                    "x-api-key",
                    "credential-secret",
                )])))
                .await
                .expect("authentication result");
            if case == 0 {
                assert!(
                    matches!(result, ProtectedResourceAuthentication::Authenticated(principal) if principal == valid)
                );
            } else {
                assert_eq!(rejected(result), (401, Some(ErrorCode::NotRecognized)));
            }
        }
    });
}

#[test]
fn a_grant_handler_without_authentication_support_cannot_authenticate_a_resource() {
    block_on(async {
        let fixture = build_fixture(Settings {
            handler: Some(Arc::new(UnusableHandler)),
            ..Settings::default()
        });
        enrolled(&fixture).await;
        let result = fixture
            .service
            .authenticate_protected_resource(protected(headers(&[(
                "x-api-key",
                "not-authenticated-by-the-handler",
            )])))
            .await
            .expect("authentication result");
        assert_eq!(
            rejected(result),
            (401, Some(ErrorCode::AuthenticationRequired))
        );
    });
}

/// DWB-ID-003: the assertion subject has to use an identity method the Service accepts.
#[test]
fn subjects_must_use_an_advertised_identity_method() {
    block_on(async {
        let fixture = build_fixture(Settings {
            identity_methods: vec![IdentityMethod::from("platform")],
            ..Settings::default()
        });
        // The configured method is not `did:web`, so a `did:web` subject is not accepted.
        assert_eq!(
            code_of(
                &fixture
                    .service
                    .status(authenticated("a1"))
                    .await
                    .expect("answered")
            ),
            Some(ErrorCode::NotRecognized)
        );

        *fixture.verifier.subject.lock().expect("lock") = "platform:agent-1".to_owned();
        // The subject now uses the advertised method, so the assertion is accepted and the
        // refusal comes from the missing enrolment instead.
        assert_eq!(
            code_of(
                &fixture
                    .service
                    .status(authenticated("a2"))
                    .await
                    .expect("answered")
            ),
            Some(ErrorCode::NotRecognized)
        );
    });
}

/// A clock skew that cannot be expressed as an elapsed time leaves every assertion outside its
/// window rather than widening it without bound.
#[test]
fn an_unusable_clock_skew_accepts_nothing() {
    block_on(async {
        let fixture = build_fixture(Settings {
            maximum_clock_skew: Duration::from_secs(u64::MAX),
            ..Settings::default()
        });
        assert_eq!(
            code_of(
                &fixture
                    .service
                    .status(authenticated("a1"))
                    .await
                    .expect("answered")
            ),
            Some(ErrorCode::NotRecognized)
        );
    });
}

// --- configuration ------------------------------------------------------------------------------

/// A Service's advertisements are checked once, at construction.
#[test]
fn service_configuration_is_checked_at_construction() {
    let build = |change: &dyn Fn(&mut ServiceOptions)| {
        let mut settings = options(&Settings::default());
        change(&mut settings);
        Service::new(settings).is_ok()
    };
    assert!(build(&|_| {}));
    assert!(!build(
        &|options| options.service_did = "service.example".to_owned()
    ));
    assert!(!build(&|options| options.identity_methods = Vec::new()));
    assert!(!build(&|options| options.signing_algorithms = Vec::new()));
    assert!(!build(
        &|options| options.identity_methods = vec![IdentityMethod::DidWeb, IdentityMethod::DidWeb]
    ));
    assert!(!build(&|options| options.signing_algorithms =
        vec![SigningAlgorithm::EdDsa, SigningAlgorithm::EdDsa]));
    assert!(!build(&|options| options.authentication_methods = vec![
        AuthenticationMethod::AepJwt,
        AuthenticationMethod::AepJwt
    ]));
    // An authentication method with no matching grant type has nothing to authenticate against.
    assert!(!build(
        &|options| options.authentication_methods = vec![AuthenticationMethod::OAuthBearer]
    ));
    // A grant type with no handler cannot answer a Grant.
    assert!(!build(&|options| {
        options.grant_types = vec![GrantTypeDefinition {
            config: None,
            grant_type: GrantType::ApiKey,
            handler: None,
        }];
    }));
    assert!(!build(&|options| {
        options.grant_types = vec![
            GrantTypeDefinition {
                config: None,
                grant_type: GrantType::ApiKey,
                handler: Some(Arc::new(StubHandler::default())),
            },
            GrantTypeDefinition {
                config: None,
                grant_type: GrantType::ApiKey,
                handler: Some(Arc::new(StubHandler::default())),
            },
        ];
    }));
    // CLM-SEC-006: the bounds themselves have to be usable.
    for limits in [
        ClaimValueLimits {
            maximum_encoded_bytes: 0,
            ..ClaimValueLimits::default()
        },
        ClaimValueLimits {
            maximum_member_count: 0,
            ..ClaimValueLimits::default()
        },
        ClaimValueLimits {
            maximum_object_depth: 0,
            ..ClaimValueLimits::default()
        },
        ClaimValueLimits {
            maximum_string_length: 0,
            ..ClaimValueLimits::default()
        },
    ] {
        assert!(!build(&|options| options.claim_value_limits = limits));
    }
}

/// A Service with no grant types advertises only the commands it can answer.
#[test]
fn a_service_without_grant_types_advertises_fewer_commands() {
    let fixture = build_fixture(Settings {
        authentication_methods: vec![AuthenticationMethod::AepJwt],
        handler: None,
        ..Settings::default()
    });
    let document = fixture.service.inspect_document();
    assert_eq!(
        document.commands.supported,
        vec![
            aep_core::Command::Enroll,
            aep_core::Command::Inspect,
            aep_core::Command::Status
        ]
    );
    assert!(document.commands.grant_types.is_empty());
}

// --- stores -------------------------------------------------------------------------------------

/// The bundled stores refuse records that would break the invariants the Service relies on.
#[test]
fn memory_stores_guard_their_invariants() {
    block_on(async {
        let record = |agent_did: &str| EnrollmentRecord {
            agent_did: agent_did.to_owned(),
            claims: Default::default(),
            created_at: fixed_time(),
            owner_action_required: false,
            requirements_pending: Vec::new(),
            since: fixed_time(),
            status: AgentStatus::Active,
            updated_at: fixed_time(),
            verification_pending: Vec::new(),
        };
        assert!(MemoryEnrollmentStore::new([record(AGENT_DID)]).is_ok());
        assert!(MemoryEnrollmentStore::new([record("")]).is_err());
        let store = MemoryEnrollmentStore::default();
        assert!(store.save(record("")).await.is_err());
        assert!(
            store
                .find("did:web:missing")
                .await
                .expect("lookup")
                .is_none()
        );

        assert!(MemoryCommandIdempotencyStore::new([]).is_ok());
    });
}

/// CORE-IDP-004: a stored command result stays replayable for at least an hour and no longer.
#[test]
fn command_results_expire_after_their_retention() {
    block_on(async {
        let clock = Arc::new(MovableClock(Mutex::new(fixed_time())));
        let store = Arc::new(MemoryCommandIdempotencyStore::with_clock(clock.clone()));
        let mut settings = options(&Settings::default());
        settings.idempotency_store = Some(store.clone());
        let service = Service::new(settings).expect("Service");
        let body = enroll_body(json!({"contact.email": "owner@example.com"}));

        let first = service
            .enroll(&body, idempotent("a1", "request-1"))
            .await
            .expect("answered");
        assert_eq!(first.status, 200);

        // Still replayable at exactly one hour old.
        clock.set(fixed_time() + Duration::from_secs(3600));
        let replayed = service
            .enroll(&body, idempotent("a2", "request-1"))
            .await
            .expect("answered");
        assert_eq!(
            replayed.to_json().expect("JSON"),
            first.to_json().expect("JSON")
        );

        // Past the retention the record is gone, so a different body under the same key is no
        // longer a conflict.
        clock.set(fixed_time() + Duration::from_secs(3601));
        let reissued = service
            .enroll(
                &serde_json::to_vec(&json!({"agent_did": AGENT_DID})).expect("JSON"),
                idempotent("a3", "request-1"),
            )
            .await
            .expect("answered");
        assert_eq!(reissued.status, 200);
    });
}

#[test]
fn retains_command_responses_for_an_hour_after_execution_completes() {
    block_on(async {
        let clock = Arc::new(MovableClock(Mutex::new(fixed_time())));
        let store = MemoryCommandIdempotencyStore::with_clock(clock.clone());
        let input = CommandIdempotencyInput {
            agent_did: AGENT_DID.into(),
            command: IdempotentCommand::Revoke,
            idempotency_key: "slow-command".into(),
            request_hash: "same-body".into(),
        };
        let response = ServiceResponse {
            body: ResponseBody::Revoke(aep_core::RevokeResponse::default()),
            headers: HeaderMap::from_iter([(
                header::HeaderName::from_static("x-request-id"),
                HeaderValue::from_static("completed-request"),
            )]),
            status: 200,
        };
        let operation_clock = clock.clone();
        let completed = response.clone();
        assert_eq!(
            store
                .execute(
                    input.clone(),
                    Box::new(move || Box::pin(async move {
                        operation_clock.set(fixed_time() + Duration::from_secs(120));
                        Ok(completed)
                    }))
                )
                .await
                .expect("created"),
            CommandIdempotencyResult::Created(response.clone())
        );
        clock.set(fixed_time() + Duration::from_secs(3720));
        assert_eq!(
            store
                .execute(input.clone(), Box::new(|| panic!("result must be cached")))
                .await
                .expect("replayed"),
            CommandIdempotencyResult::Replayed(response.clone())
        );
        let mut conflict = input.clone();
        conflict.request_hash = "different-body".into();
        assert_eq!(
            store
                .execute(conflict, Box::new(|| panic!("conflict must not execute")))
                .await
                .expect("conflict"),
            CommandIdempotencyResult::Conflict
        );
        clock.set(fixed_time() + Duration::from_secs(3721));
        let completed = response.clone();
        assert_eq!(
            store
                .execute(
                    input,
                    Box::new(move || Box::pin(async move { Ok(completed) }))
                )
                .await
                .expect("created after expiration"),
            CommandIdempotencyResult::Created(response)
        );
    });
}

#[test]
fn failed_commands_release_their_key_for_a_retry() {
    block_on(async {
        let store = MemoryCommandIdempotencyStore::default();
        let input = CommandIdempotencyInput {
            agent_did: AGENT_DID.into(),
            command: IdempotentCommand::Revoke,
            idempotency_key: "retry-failed-command".into(),
            request_hash: "same-body".into(),
        };
        let error = store
            .execute(
                input.clone(),
                Box::new(|| {
                    Box::pin(async {
                        Err(ServiceError::Handler(
                            "credential provider unavailable".into(),
                        ))
                    })
                }),
            )
            .await
            .expect_err("operation fails");
        assert!(matches!(error, ServiceError::Handler(_)));
        let response = ServiceResponse {
            body: ResponseBody::Revoke(aep_core::RevokeResponse::default()),
            headers: HeaderMap::new(),
            status: 200,
        };
        let completed = response.clone();
        assert_eq!(
            store
                .execute(
                    input.clone(),
                    Box::new(move || Box::pin(async move { Ok(completed) }))
                )
                .await
                .expect("retry executes"),
            CommandIdempotencyResult::Created(response.clone())
        );
        assert_eq!(
            store
                .execute(input, Box::new(|| panic!("completed retry must be cached")))
                .await
                .expect("replay"),
            CommandIdempotencyResult::Replayed(response)
        );
    });
}

struct MovableClock(Mutex<OffsetDateTime>);

impl MovableClock {
    fn set(&self, value: OffsetDateTime) {
        *self.0.lock().expect("clock lock") = value;
    }
}

impl Clock for MovableClock {
    fn now(&self) -> OffsetDateTime {
        *self.0.lock().expect("clock lock")
    }
}

/// Every response renders to the JSON body it will be sent as.
#[test]
fn responses_render_to_their_wire_form() {
    block_on(async {
        let fixture = build_fixture(Settings::default());
        enrolled(&fixture).await;
        let status = fixture
            .service
            .status(authenticated("a1"))
            .await
            .expect("answered");
        assert_eq!(status.to_json().expect("JSON")["status"], json!("active"));
        assert_eq!(status.body.content_type(), aep_core::MEDIA_TYPE);

        let grant = fixture
            .service
            .grant(
                b"{\"grant_type\":\"api-key\"}",
                idempotent("a2", "request-2"),
            )
            .await
            .expect("answered");
        assert_eq!(
            grant.to_json().expect("JSON")["credential_id"],
            json!("credential-1")
        );

        let revoke = fixture
            .service
            .revoke(
                b"{\"grant_type\":\"api-key\"}",
                idempotent("a3", "request-3"),
            )
            .await
            .expect("answered");
        assert_eq!(revoke.to_json().expect("JSON"), json!({}));

        // CORE-ENR-008: a repeat Enroll returns the existing record rather than re-running policy.
        let repeated = fixture
            .service
            .enroll(&enroll_body(json!({})), idempotent("a4", "request-4"))
            .await
            .expect("answered");
        assert_eq!(repeated.to_json().expect("JSON")["status"], json!("active"));

        // A Service that has never seen this Agent states what it still needs.
        let fresh = build_fixture(Settings::default());
        let refused = fresh
            .service
            .enroll(&enroll_body(json!({})), idempotent("a5", "request-5"))
            .await
            .expect("answered");
        assert_eq!(
            refused.to_json().expect("JSON")["code"],
            json!("requirements_unmet")
        );
        assert_eq!(refused.body.content_type(), aep_core::PROBLEM_MEDIA_TYPE);
        assert!(format!("{:?}", grant.body).contains("REDACTED"));
        assert!(format!("{status:?}").contains("REDACTED"));
    });
}

// --- carrier selection variants -------------------------------------------------------------------

/// Registered schemes use either carrier; values without a recognizable scheme remain unrelated.
#[test]
fn every_scheme_is_recognized_through_either_carrier() {
    block_on(async {
        let fixture = build_fixture(Settings {
            authentication_methods: vec![
                AuthenticationMethod::AepJwt,
                AuthenticationMethod::ApiKey,
                AuthenticationMethod::OAuthBearer,
                AuthenticationMethod::Basic,
            ],
            handler: Some(Arc::new(StubHandler::default())),
            ..Settings::default()
        });
        // Bearer and Basic reach the Service through the dedicated field as well as the standard
        // one; none of them match an issued credential here, so each is `not_recognized`.
        for values in [
            vec![("aep-authorization", "Bearer token")],
            vec![("aep-authorization", "Basic YWdlbnQ6c2VjcmV0")],
            vec![("authorization", "Basic YWdlbnQ6c2VjcmV0")],
        ] {
            assert_eq!(
                rejected(
                    fixture
                        .service
                        .authenticate_protected_resource(protected(headers(&values)))
                        .await
                        .expect("answered")
                ),
                (401, Some(ErrorCode::NotRecognized)),
                "{values:?}"
            );
        }

        // A field value that is not valid text at all is not an AEP presentation.
        let mut binary = HeaderMap::new();
        binary.insert(
            header::AUTHORIZATION,
            HeaderValue::from_bytes(&[0xff, 0xfe]).expect("value"),
        );
        assert_eq!(
            rejected(
                fixture
                    .service
                    .authenticate_protected_resource(protected(binary))
                    .await
                    .expect("answered")
            ),
            (401, Some(ErrorCode::AuthenticationRequired))
        );
    });
}

/// An unsupported authentication method is only advertised when a Service offers it, and a
/// Service that offers none answers every presentation the same way.
#[test]
fn a_service_offering_only_assertions_refuses_session_credentials() {
    block_on(async {
        let fixture = build_fixture(Settings {
            authentication_methods: vec![AuthenticationMethod::AepJwt],
            handler: None,
            ..Settings::default()
        });
        assert_eq!(
            rejected(
                fixture
                    .service
                    .authenticate_protected_resource(protected(headers(&[(
                        "authorization",
                        "Basic YWdlbnQ6c2VjcmV0"
                    )])))
                    .await
                    .expect("answered")
            ),
            (401, Some(ErrorCode::UnsupportedAuthenticationMethod))
        );
    });
}

/// An assertion the verifier will not accept is no more authenticated at a protected resource
/// than it is at a command.
#[test]
fn unverifiable_assertions_do_not_reach_protected_resources() {
    block_on(async {
        let fixture = build_fixture(Settings {
            verifier: ScriptedVerifier::refusing(),
            ..Settings::default()
        });
        assert_eq!(
            rejected(
                fixture
                    .service
                    .authenticate_protected_resource(protected(headers(&[(
                        "authorization",
                        "AEP assertion"
                    )])))
                    .await
                    .expect("answered")
            ),
            (401, Some(ErrorCode::NotRecognized))
        );
    });
}

/// A session-credential handler answers for its own method and its own Agent, and a principal
/// that does not describe one is refused rather than admitted.
#[test]
fn session_principals_must_describe_their_own_credential() {
    block_on(async {
        struct FixedPrincipal(AuthenticatedPrincipal);

        #[async_trait]
        impl GrantTypeHandler for FixedPrincipal {
            async fn grant(
                &self,
                _request: &GrantRequest,
                _context: &GrantContext,
            ) -> Result<Value, ServiceError> {
                Ok(json!({"credential_id": "c1"}))
            }
            async fn revoke(
                &self,
                _request: &RevokeRequest,
                _context: &GrantContext,
            ) -> Result<(), ServiceError> {
                Ok(())
            }
            async fn authenticate(
                &self,
                _input: &CredentialAuthenticationInput,
            ) -> Result<Option<AuthenticatedPrincipal>, ServiceError> {
                Ok(Some(self.0.clone()))
            }
            async fn has_presentation(
                &self,
                _input: &CredentialAuthenticationInput,
            ) -> Result<bool, ServiceError> {
                Ok(true)
            }
        }

        let usable = AuthenticatedPrincipal {
            agent_did: AGENT_DID.to_owned(),
            authentication_kind: AuthenticationKind::SessionCredential,
            authentication_method: AuthenticationMethod::ApiKey,
            credential_id: Some("c1".to_owned()),
            grant_type: Some(GrantType::ApiKey),
            scopes: vec!["purchase".to_owned()],
        };
        let refusals = [
            AuthenticatedPrincipal {
                agent_did: String::new(),
                ..usable.clone()
            },
            AuthenticatedPrincipal {
                authentication_kind: AuthenticationKind::ClientAssertion,
                ..usable.clone()
            },
            AuthenticatedPrincipal {
                authentication_method: AuthenticationMethod::Basic,
                ..usable.clone()
            },
            AuthenticatedPrincipal {
                grant_type: Some(GrantType::Basic),
                ..usable.clone()
            },
        ];
        for principal in refusals {
            let fixture = build_fixture(Settings {
                handler: Some(Arc::new(FixedPrincipal(principal.clone()))),
                ..Settings::default()
            });
            assert_eq!(
                rejected(
                    fixture
                        .service
                        .authenticate_protected_resource(protected(headers(&[(
                            "x-api-key",
                            "secret"
                        )])))
                        .await
                        .expect("answered")
                ),
                (401, Some(ErrorCode::NotRecognized)),
                "{principal:?}"
            );
        }

        // A usable principal still needs an active enrolment behind it.
        let fixture = build_fixture(Settings {
            handler: Some(Arc::new(FixedPrincipal(usable))),
            ..Settings::default()
        });
        assert_eq!(
            rejected(
                fixture
                    .service
                    .authenticate_protected_resource(protected(headers(&[("x-api-key", "secret")])))
                    .await
                    .expect("answered")
            ),
            (401, Some(ErrorCode::NotRecognized))
        );
        enrolled(&fixture).await;
        let ProtectedResourceAuthentication::Authenticated(principal) = fixture
            .service
            .authenticate_protected_resource(protected(headers(&[("x-api-key", "secret")])))
            .await
            .expect("answered")
        else {
            panic!("expected an authenticated principal");
        };
        assert_eq!(principal.scopes, vec!["purchase".to_owned()]);

        fixture
            .store
            .save(EnrollmentRecord {
                agent_did: AGENT_DID.to_owned(),
                claims: Default::default(),
                created_at: fixed_time(),
                owner_action_required: false,
                requirements_pending: Vec::new(),
                since: fixed_time(),
                status: AgentStatus::Terminated,
                updated_at: fixed_time(),
                verification_pending: Vec::new(),
            })
            .await
            .expect("saved");
        assert_eq!(
            rejected(
                fixture
                    .service
                    .authenticate_protected_resource(protected(headers(&[("x-api-key", "secret")])))
                    .await
                    .expect("answered")
            ),
            (401, Some(ErrorCode::NotRecognized))
        );
    });
}

// --- enrolment policy -----------------------------------------------------------------------------

/// The Service's own policy decides the lifecycle state a new enrolment lands in.
#[test]
fn the_enrolment_policy_decides_the_lifecycle_state() {
    block_on(async {
        for (decision, expected) in [
            (EnrollmentDecisionStatus::Pending, AgentStatus::Pending),
            (EnrollmentDecisionStatus::Rejected, AgentStatus::Rejected),
            (EnrollmentDecisionStatus::Active, AgentStatus::Active),
        ] {
            let mut settings = options(&Settings::default());
            settings.enrollment_policy =
                Some(Arc::new(StaticEnrollmentPolicy::new(EnrollmentDecision {
                    owner_action_required: true,
                    requirements_pending: vec!["company.registration".to_owned()],
                    status: decision,
                    verification_pending: vec!["contact.email".to_owned()],
                })));
            let service = Service::new(settings).expect("Service");
            let response = service
                .enroll(
                    &enroll_body(json!({"contact.email": "owner@example.com"})),
                    idempotent("a1", "request-1"),
                )
                .await
                .expect("answered");
            let ResponseBody::Enroll(body) = &response.body else {
                panic!("Enroll response expected");
            };
            assert_eq!(body.status, expected, "{decision:?}");
            assert_eq!(body.owner_action_required, Some(StringBoolean::True));
            assert!(body.verification_pending.is_some());
        }
    });
}

/// A Service that advertises an OpenAPI document publishes it with its path-matching rule.
#[test]
fn an_openapi_advertisement_is_published() {
    let mut settings = options(&Settings::default());
    settings.endpoint_base = Some("/aep".to_owned());
    settings.openapi = Some(OpenApiConfiguration {
        trailing_slash: aep_core::OpenApiTrailingSlash::Equivalent,
        url: "https://service.example/openapi.json".to_owned(),
    });
    let document = Service::new(settings).expect("Service").inspect_document();
    let openapi = document.http.openapi.expect("OpenAPI reference");
    assert_eq!(openapi.url, "https://service.example/openapi.json");
    assert_eq!(
        openapi.path_matching.trailing_slash,
        aep_core::OpenApiTrailingSlash::Equivalent
    );
    assert_eq!(document.http.endpoint_base.as_deref(), Some("/aep"));
}

/// A claim document made of arrays is bounded by the same depth rule as one made of objects.
#[test]
fn nested_arrays_are_bounded_by_depth() {
    block_on(async {
        let fixture = build_fixture(Settings::default());
        let mut value = json!("leaf");
        for _ in 0..12 {
            value = json!([value]);
        }
        let response = fixture
            .service
            .enroll(
                &enroll_body(json!({"contact.email": "owner@example.com", "vendor.list": value})),
                idempotent("a1", "request-1"),
            )
            .await
            .expect("answered");
        assert_eq!(code_of(&response), Some(ErrorCode::InvalidRequest));
    });
}

/// A pre-populated idempotency store replays the results it was built with.
#[test]
fn a_prepopulated_idempotency_store_replays_its_records() {
    block_on(async {
        let stored = ServiceResponse {
            body: ResponseBody::Revoke(aep_core::RevokeResponse::default()),
            headers: HeaderMap::new(),
            status: 200,
        };
        let record = |agent_did: &str, key: &str| CommandIdempotencyRecord {
            created_at: fixed_time(),
            input: CommandIdempotencyInput {
                agent_did: agent_did.to_owned(),
                command: IdempotentCommand::Revoke,
                idempotency_key: key.to_owned(),
                request_hash: "sha256:none".to_owned(),
            },
            response: stored.clone(),
        };
        let mut active = record(AGENT_DID, "k1");
        active.created_at = OffsetDateTime::now_utc();
        let input = active.input.clone();
        let store = MemoryCommandIdempotencyStore::new([active]).expect("prepopulated store");
        assert_eq!(
            store
                .execute(
                    input,
                    Box::new(|| panic!("seeded response must be replayed"))
                )
                .await
                .expect("seeded replay"),
            CommandIdempotencyResult::Replayed(stored.clone())
        );
        assert!(MemoryCommandIdempotencyStore::new([record("", "k1")]).is_err());
        assert!(MemoryCommandIdempotencyStore::new([record(AGENT_DID, "")]).is_err());
    });
}

/// Grant credential material is redacted while lifecycle and problem metadata remain inspectable.
#[test]
fn response_debug_output_redacts_grant_credentials() {
    let bodies = [
        ResponseBody::Enroll(aep_core::EnrollResponse {
            additional: BTreeMap::new(),
            owner_action_required: None,
            requirements_pending: None,
            status: AgentStatus::Active,
            verification_pending: None,
        }),
        ResponseBody::Grant(json!({"api_key": "secret"})),
        ResponseBody::Problem(aep_core::new_problem_details(
            ErrorCode::NotRecognized,
            "Not recognized",
            401,
        )),
        ResponseBody::Revoke(aep_core::RevokeResponse::default()),
        ResponseBody::Status(aep_core::StatusResponse {
            additional: BTreeMap::new(),
            owner_action_required: None,
            requirements_pending: None,
            since: None,
            status: AgentStatus::Active,
            verification_pending: None,
        }),
    ];
    for body in bodies {
        let rendered = format!("{body:?}");
        assert!(!rendered.contains("secret"), "{rendered}");
        assert!(body.to_json().is_ok());
    }
}

// --- the did:web verifier -------------------------------------------------------------------------

/// A `did:web` assertion names its issuer in the claims and the key that signed it in the header;
/// without either there is nothing to resolve.
#[test]
fn did_web_assertions_must_name_an_issuer_and_a_key() {
    block_on(async {
        struct NoTransport;

        #[async_trait]
        impl aep_core::HttpTransport for NoTransport {
            async fn send(
                &self,
                _request: aep_core::HttpRequest,
            ) -> Result<aep_core::HttpResponse, aep_core::TransportError> {
                Err(aep_core::TransportError::new("not reachable"))
            }
        }

        let verifier = DidWebClientAssertionVerifier::new(Arc::new(NoTransport), false);
        let context = |assertion: &str| ClientAssertionVerificationContext {
            assertion: assertion.to_owned(),
            current_time: fixed_time(),
            idempotency_key: None,
            operation: aep_core::AssertionOperation::Authenticate,
            resource: Some(Url::parse("https://service.example/v1/orders").expect("URL")),
            service_did: SERVICE_DID.to_owned(),
            signing_algorithms: vec![SigningAlgorithm::EdDsa],
        };
        for assertion in [
            "not-a-jwt",
            // `{"alg":"EdDSA","kid":"did:web:agent.example","typ":"JWT"}` over claims with no
            // issuer.
            "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWI6YWdlbnQuZXhhbXBsZSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkaWQ6d2ViOmFnZW50LmV4YW1wbGUifQ.AAAA",
            // A header with no `kid` at all.
            "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJkaWQ6d2ViOmFnZW50LmV4YW1wbGUifQ.AAAA",
        ] {
            assert!(
                verifier.verify(context(assertion)).await.is_err(),
                "{assertion}"
            );
        }
    });
}
