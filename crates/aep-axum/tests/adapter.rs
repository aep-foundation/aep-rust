use std::{collections::BTreeMap, sync::Arc};

use aep_axum::{AepPrincipal, AuthenticationOptions, authentication_layer, router};
use aep_core::{AgentStatus, AuthenticationMethod, ClientAssertionClaims};
use aep_service::{
    ClientAssertionVerificationContext, ClientAssertionVerifier, Clock, EnrollmentRecord,
    MemoryEnrollmentStore, Service, ServiceError, ServiceOptions,
};
use async_trait::async_trait;
use axum::{Router, body::Body, body::to_bytes, http::Request, routing::get};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tower::ServiceExt as _;
use url::Url;

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
            iss: agent_did().to_owned(),
            jti: context.assertion,
            op: context.operation,
            resource: context.resource.map(|resource| resource.to_string()),
            sub: agent_did().to_owned(),
        })
    }
}

#[tokio::test]
async fn mounts_the_service_command_routes() {
    let application = router(test_service(false), 1 << 20).expect("router");
    let inspect = application
        .oneshot(
            Request::builder()
                .uri("/.well-known/aep")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("Inspect response");
    assert_eq!(inspect.status(), 200);

    let unknown = router(test_service(false), 1 << 20)
        .expect("router")
        .oneshot(
            Request::builder()
                .uri("/aep/enroll")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("unknown response");
    assert_eq!(unknown.status(), 404);
}

#[tokio::test]
async fn exposes_the_authenticated_principal_to_axum_handlers() {
    let service = test_service(true);
    let protected = Router::new()
        .route(
            "/private",
            get(|principal: AepPrincipal| async move { principal.agent_did.clone() }),
        )
        .route_layer(
            authentication_layer(
                service,
                AuthenticationOptions::new(Url::parse("https://service.example").expect("origin")),
            )
            .expect("authentication layer"),
        );

    let authenticated = protected
        .clone()
        .oneshot(
            Request::builder()
                .uri("/private")
                .header("authorization", "AEP resource-1")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("authenticated response");
    assert_eq!(authenticated.status(), 200);
    assert_eq!(
        to_bytes(authenticated.into_body(), usize::MAX)
            .await
            .expect("body"),
        agent_did()
    );

    let rejected = protected
        .oneshot(
            Request::builder()
                .uri("/private")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("rejected response");
    assert_eq!(rejected.status(), 401);
    assert!(rejected.headers().contains_key("www-authenticate"));
}

fn test_service(enrolled: bool) -> Arc<Service> {
    let now = fixed_time();
    let records = enrolled.then(|| EnrollmentRecord {
        agent_did: agent_did().to_owned(),
        claims: Default::default(),
        created_at: now,
        owner_action_required: false,
        requirements_pending: Vec::new(),
        since: now,
        status: AgentStatus::Active,
        updated_at: now,
        verification_pending: Vec::new(),
    });
    let store = MemoryEnrollmentStore::new(records).expect("enrollment store");
    let mut options = ServiceOptions::new(service_did(), Arc::new(AcceptingVerifier));
    options.authentication_methods = vec![AuthenticationMethod::AepJwt];
    options.clock = Some(Arc::new(FixedClock(now)));
    options.endpoint_base = Some("/custom/aep".to_owned());
    options.enrollment_store = Some(Arc::new(store));
    options.inspect_url =
        Some(Url::parse("https://service.example/.well-known/aep").expect("Inspect URL"));
    Service::new(options).expect("Service")
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
