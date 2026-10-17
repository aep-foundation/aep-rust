//! Contracts the Axum integration owes its host.
//!
//! The router's job is to place the Service's advertised endpoints on Axum's path tree without
//! changing what they match, and to hand every request through to the command service so the AEP
//! adapter — not Axum — decides the HTTP semantics.

use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use aep_axum::{AepPrincipal, AuthenticationOptions, TowerError, authentication_layer, router};
use aep_core::{AgentStatus, AuthenticationMethod, ClientAssertionClaims};
use aep_service::{
    AuthenticatedPrincipal, ClientAssertionVerificationContext, ClientAssertionVerifier, Clock,
    EnrollmentRecord, MemoryEnrollmentStore, Service, ServiceError, ServiceOptions,
};
use async_trait::async_trait;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
    routing::{get, post},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tower::ServiceExt as _;
use url::Url;

// --- Mounting --------------------------------------------------------------------------------

#[tokio::test]
async fn mounts_endpoint_bases_that_look_like_route_templates() {
    // Use the URL encoding a caller sends, not raw characters accepted only by a test request.
    for base in [
        "/aep/{tenant}",
        "/aep/{",
        "/aep/}x",
        "/aep/*rest",
        "/aep/:id",
        "/aep/with space",
        "/aep/é",
        "/aep/%7Btenant%7D",
    ] {
        let application = router(service_with_base(base, false), 1 << 20)
            .unwrap_or_else(|error| panic!("endpoint_base {base} was refused: {error}"));

        let command_url = Url::parse("https://service.example")
            .expect("origin")
            .join(&format!("{base}/status"))
            .expect("command URL");
        let advertised = application
            .clone()
            .oneshot(get_request(command_url.path()))
            .await
            .expect("Status response");
        assert_eq!(
            advertised.status(),
            StatusCode::UNAUTHORIZED,
            "the advertised path {base}/status did not reach the Service"
        );

        // ...and the route tree matches nothing else. A capture route would match here and be
        // rejected a layer later instead, which is the same answer by a longer path.
        let captured = application
            .oneshot(get_request("/aep/anything/status"))
            .await
            .expect("unadvertised response");
        assert_eq!(
            captured.status(),
            StatusCode::NOT_FOUND,
            "endpoint_base {base} mounted a capture route"
        );
    }
}

#[tokio::test]
async fn mounts_every_advertised_command() {
    let application = router(service_with_base("/custom/aep", true), 1 << 20).expect("router");

    for (method, path, unmatched) in [
        (Method::GET, "/.well-known/aep", StatusCode::OK),
        (Method::GET, "/custom/aep/status", StatusCode::UNAUTHORIZED),
        (Method::POST, "/custom/aep/enroll", StatusCode::BAD_REQUEST),
        (Method::POST, "/custom/aep/grant", StatusCode::BAD_REQUEST),
        (Method::POST, "/custom/aep/revoke", StatusCode::BAD_REQUEST),
    ] {
        let response = application
            .clone()
            .oneshot(
                Request::builder()
                    .method(method.clone())
                    .uri(path)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("command response");
        assert_eq!(
            response.status(),
            unmatched,
            "{method} {path} was not mounted"
        );
    }
}

#[tokio::test]
async fn refuses_a_zero_body_limit() {
    assert!(matches!(
        router(service_with_base("/custom/aep", false), 0),
        Err(TowerError::InvalidConfiguration(_))
    ));
}

// --- Method handling stays with the AEP adapter ----------------------------------------------

#[tokio::test]
async fn hands_every_method_to_the_command_service() {
    let application = router(service_with_base("/custom/aep", false), 1 << 20).expect("router");

    // Axum must not answer these itself: the AEP adapter owns the 405, its `Allow` set and its
    // Problem Details body.
    let refused = application
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/.well-known/aep")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("method response");
    assert_eq!(refused.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        refused
            .headers()
            .get(header::ALLOW)
            .and_then(|value| value.to_str().ok()),
        Some("GET, HEAD")
    );
    let body = to_bytes(refused.into_body(), usize::MAX)
        .await
        .expect("body");
    let problem: serde_json::Value = serde_json::from_slice(&body).expect("Problem Details");
    assert_eq!(problem["code"], "invalid_request");

    let head = application
        .oneshot(
            Request::builder()
                .method(Method::HEAD)
                .uri("/.well-known/aep")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("HEAD response");
    assert_eq!(head.status(), StatusCode::OK);
    assert!(
        to_bytes(head.into_body(), usize::MAX)
            .await
            .expect("body")
            .is_empty()
    );
}

// --- The principal extractor ------------------------------------------------------------------

#[tokio::test]
async fn refuses_to_invent_a_principal_without_the_layer() {
    // Forgetting the layer must fail closed. The extractor has no credential to inspect, so the
    // only safe answer is the Service's own failure, never an unauthenticated handler call.
    let unprotected = Router::new().route(
        "/private",
        get(|principal: AepPrincipal| async move { principal.agent_did.clone() }),
    );

    let response = unprotected
        .oneshot(get_request("/private"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn hands_the_whole_principal_to_the_handler() {
    let protected = Router::new()
        .route(
            "/private",
            get(|principal: AepPrincipal| async move {
                // `Deref` reaches the Service's own principal, and the wrapper keeps every field.
                let inner: &AuthenticatedPrincipal = &principal;
                format!(
                    "{}|{:?}|{}|{}",
                    inner.agent_did,
                    principal.authentication_kind,
                    principal.scopes.len(),
                    principal.clone().0.agent_did
                )
            }),
        )
        .route_layer(
            authentication_layer(
                service_with_base("/custom/aep", true),
                AuthenticationOptions::new(Url::parse("https://service.example").expect("origin")),
            )
            .expect("authentication layer"),
        );

    let response = protected
        .oneshot(
            Request::builder()
                .uri("/private")
                .header(header::AUTHORIZATION, "AEP resource-1")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("authenticated response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    assert_eq!(
        String::from_utf8(body.to_vec()).expect("UTF-8"),
        "did:web:agent.example|ClientAssertion|0|did:web:agent.example"
    );
}

#[tokio::test]
async fn refuses_an_origin_that_is_not_a_bare_https_origin() {
    let refused = authentication_layer(
        service_with_base("/custom/aep", false),
        AuthenticationOptions::new(Url::parse("http://service.example").expect("origin")),
    );
    assert!(matches!(refused, Err(TowerError::InvalidConfiguration(_))));

    let mut loopback = AuthenticationOptions::new(Url::parse("http://[::1]:3000").expect("origin"));
    loopback.allow_insecure_loopback = true;
    authentication_layer(service_with_base("/custom/aep", false), loopback)
        .expect("loopback layer");
}

#[tokio::test]
async fn verifies_real_assertions_and_preserves_the_payment_request() {
    let mut options = ServiceOptions::new(SERVICE_DID, Arc::new(SignedVerifier));
    options.authentication_methods = vec![AuthenticationMethod::AepJwt];
    options.clock = Some(Arc::new(FixedClock(fixed_time())));
    options.inspect_url = Some(Url::parse("https://service.example/.well-known/aep").expect("URL"));
    let service = Service::new(options).expect("Service");
    let enrolled = service
        .enroll(
            br#"{"agent_did":"did:web:agent.example"}"#,
            aep_service::IdempotentCommandOptions {
                client_assertion: signed_assertion(
                    aep_core::AssertionOperation::Enroll,
                    None,
                    "enroll",
                ),
                idempotency_key: "enroll".to_owned(),
            },
        )
        .await
        .expect("enrollment");
    assert_eq!(enrolled.status, 200);

    let calls = Arc::new(AtomicUsize::new(0));
    let reached = calls.clone();
    let application = Router::new()
        .route(
            "//other/orders",
            post(
                move |principal: AepPrincipal,
                      headers: axum::http::HeaderMap,
                      body: axum::body::Bytes| {
                    reached.fetch_add(1, Ordering::SeqCst);
                    async move {
                        assert_eq!(headers[header::AUTHORIZATION], "Payment payment-credential");
                        assert_eq!(headers["payment-signature"], "x402-credential");
                        assert_eq!(body, "order-body");
                        principal.agent_did.clone()
                    }
                },
            ),
        )
        .route_layer(
            authentication_layer(
                service,
                AuthenticationOptions::new(Url::parse("https://service.example").expect("origin")),
            )
            .expect("layer"),
        );

    let expected_resource = "https://service.example//other/orders?format=full";
    let correct = signed_assertion(
        aep_core::AssertionOperation::Authenticate,
        Some(expected_resource),
        "correct",
    );
    let wrong_target = signed_assertion(
        aep_core::AssertionOperation::Authenticate,
        Some("https://service.example/other/orders?format=full"),
        "wrong-target",
    );
    let wrong_operation = signed_assertion(
        aep_core::AssertionOperation::Enroll,
        None,
        "wrong-operation",
    );
    for (assertion, expected) in [
        (None, StatusCode::UNAUTHORIZED),
        (Some(wrong_target.as_str()), StatusCode::UNAUTHORIZED),
        (Some(wrong_operation.as_str()), StatusCode::UNAUTHORIZED),
        (Some(correct.as_str()), StatusCode::OK),
        (Some(correct.as_str()), StatusCode::UNAUTHORIZED),
    ] {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri("//other/orders?format=full")
            .header(header::AUTHORIZATION, "Payment payment-credential")
            .header("payment-signature", "x402-credential");
        if let Some(assertion) = assertion {
            request = request.header("aep-authorization", format!("AEP {assertion}"));
        }
        let response = application
            .clone()
            .oneshot(request.body(Body::from("order-body")).expect("request"))
            .await
            .expect("response");
        assert_eq!(response.status(), expected);
        if expected == StatusCode::UNAUTHORIZED {
            let challenge = response.headers()[header::WWW_AUTHENTICATE]
                .to_str()
                .expect("challenge");
            assert!(challenge.contains(SERVICE_DID));
            assert!(challenge.contains("https://service.example/.well-known/aep"));
        }
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

struct SignedVerifier;

#[async_trait]
impl ClientAssertionVerifier for SignedVerifier {
    async fn verify(
        &self,
        context: ClientAssertionVerificationContext,
    ) -> Result<ClientAssertionClaims, ServiceError> {
        let key = aep_core::ClientAssertionSigningKey::ed25519_from_seed([7; 32]).verifying_key();
        Ok(aep_core::verify_client_assertion(
            &context.assertion,
            &key,
            &aep_core::VerifyClientAssertionOptions {
                audience: Some(context.service_did),
                algorithms: context.signing_algorithms,
                current_time: Some(context.current_time.unix_timestamp()),
                operation: Some(context.operation),
                resource: context.resource.map(|url| url.to_string()),
                ..Default::default()
            },
        )?)
    }
}

fn signed_assertion(
    operation: aep_core::AssertionOperation,
    resource: Option<&str>,
    jti: &str,
) -> String {
    let now = fixed_time().unix_timestamp();
    aep_core::sign_client_assertion(
        &ClientAssertionClaims {
            aud: SERVICE_DID.to_owned(),
            exp: now + 60,
            iat: now,
            iss: AGENT_DID.to_owned(),
            jti: jti.to_owned(),
            op: operation,
            resource: resource.map(str::to_owned),
            sub: AGENT_DID.to_owned(),
            additional: BTreeMap::new(),
        },
        aep_core::SignClientAssertionOptions {
            allow_insecure_loopback: false,
            key: &aep_core::ClientAssertionSigningKey::ed25519_from_seed([7; 32]),
            key_id: AGENT_DID,
        },
    )
    .expect("signed assertion")
}

// --- Fixtures ----------------------------------------------------------------------------------

#[derive(Clone)]
struct FixedClock(OffsetDateTime);

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

struct AcceptingVerifier;

#[async_trait]
impl ClientAssertionVerifier for AcceptingVerifier {
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
            iss: AGENT_DID.to_owned(),
            jti: context.assertion,
            op: context.operation,
            resource: context.resource.map(|resource| resource.to_string()),
            sub: AGENT_DID.to_owned(),
        })
    }
}

const AGENT_DID: &str = "did:web:agent.example";
const SERVICE_DID: &str = "did:web:service.example";

fn service_with_base(endpoint_base: &str, enrolled: bool) -> Arc<Service> {
    let now = fixed_time();
    let records = enrolled.then(|| EnrollmentRecord {
        agent_did: AGENT_DID.to_owned(),
        claims: Default::default(),
        created_at: now,
        owner_action_required: false,
        requirements_pending: Vec::new(),
        since: now,
        status: AgentStatus::Active,
        updated_at: now,
        verification_pending: Vec::new(),
    });
    let mut options = ServiceOptions::new(SERVICE_DID, Arc::new(AcceptingVerifier));
    options.authentication_methods = vec![AuthenticationMethod::AepJwt];
    options.clock = Some(Arc::new(FixedClock(now)));
    options.endpoint_base = Some(endpoint_base.to_owned());
    options.enrollment_store = Some(Arc::new(
        MemoryEnrollmentStore::new(records).expect("enrollment store"),
    ));
    options.inspect_url =
        Some(Url::parse("https://service.example/.well-known/aep").expect("Inspect URL"));
    Service::new(options).expect("Service")
}

fn fixed_time() -> OffsetDateTime {
    OffsetDateTime::parse("2026-08-31T12:00:00Z", &Rfc3339).expect("fixed time")
}

fn get_request(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("request")
}
