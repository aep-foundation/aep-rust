use std::{collections::BTreeMap, sync::Arc};

use aep_core::{AgentStatus, AuthenticationMethod, ClientAssertionClaims, ErrorCode};
use aep_service::{
    AuthenticatedPrincipal, ClientAssertionVerificationContext, ClientAssertionVerifier, Clock,
    EnrollmentRecord, MemoryEnrollmentStore, Service, ServiceError, ServiceOptions,
};
use aep_tower::{AuthenticationLayer, AuthenticationOptions, CommandService, TowerError};
use async_trait::async_trait;
use bytes::Bytes;
use futures::executor::block_on;
use http::{Method, Request, StatusCode, header};
use http_body_util::{BodyExt as _, Full};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tower::{ServiceBuilder, ServiceExt as _, service_fn};
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

#[test]
fn dispatches_aep_commands_on_the_configured_paths() {
    block_on(async {
        let commands = CommandService::new(test_service(false), 1 << 20).expect("command service");
        assert_eq!(commands.paths().enroll, "/custom/aep/enroll");

        let inspect = commands
            .clone()
            .oneshot(request(
                Method::GET,
                "/.well-known/aep",
                Full::new(Bytes::new()),
            ))
            .await
            .expect("Inspect response");
        assert_eq!(inspect.status(), StatusCode::OK);
        assert_eq!(
            inspect.headers().get(header::CONTENT_TYPE),
            Some(&aep_core::MEDIA_TYPE.parse().expect("media type"))
        );

        let wrong_method = commands
            .clone()
            .oneshot(request(
                Method::GET,
                "/custom/aep/enroll",
                Full::new(Bytes::new()),
            ))
            .await
            .expect("method response");
        assert_eq!(wrong_method.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            wrong_method.headers().get(header::ALLOW),
            Some(&"POST".parse().expect("allow"))
        );

        let enroll = commands
            .clone()
            .oneshot(command_request(
                "/custom/aep/enroll",
                br#"{"agent_did":"did:web:agent.example"}"#,
                "enroll-1",
            ))
            .await
            .expect("Enroll response");
        assert_eq!(enroll.status(), StatusCode::OK);
        let body = enroll.into_body().collect().await.expect("body").to_bytes();
        let response: serde_json::Value = serde_json::from_slice(&body).expect("JSON response");
        assert_eq!(response["status"], "active");

        let invalid_media_type = commands
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/custom/aep/enroll")
                    .header(header::AUTHORIZATION, "AEP enroll-2")
                    .header("idempotency-key", "key-2")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from_static(
                        br#"{"agent_did":"did:web:agent.example"}"#,
                    )))
                    .expect("request"),
            )
            .await
            .expect("invalid media type response");
        assert_problem(
            invalid_media_type,
            StatusCode::BAD_REQUEST,
            ErrorCode::InvalidRequest,
        )
        .await;

        let too_large = CommandService::new(test_service(false), 4)
            .expect("limited command service")
            .oneshot(command_request(
                "/custom/aep/enroll",
                br#"{"agent_did":"did:web:agent.example"}"#,
                "enroll-3",
            ))
            .await
            .expect("body limit response");
        assert_problem(
            too_large,
            StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::InvalidRequest,
        )
        .await;
    });
}

#[test]
fn authenticates_before_running_the_inner_service() {
    block_on(async {
        let service = test_service(true);
        let layer = AuthenticationLayer::new(
            service,
            AuthenticationOptions::new(Url::parse("https://service.example").expect("origin")),
        )
        .expect("authentication layer");
        let protected = ServiceBuilder::new().layer(layer).service(service_fn(
            |request: Request<Full<Bytes>>| async move {
                let principal = request
                    .extensions()
                    .get::<AuthenticatedPrincipal>()
                    .expect("authenticated principal");
                Ok::<_, std::convert::Infallible>(http::Response::new(Full::from(
                    principal.agent_did.clone(),
                )))
            },
        ));

        let authenticated = protected
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/private?item=1")
                    .header(header::AUTHORIZATION, "AEP resource-1")
                    .body(Full::new(Bytes::new()))
                    .expect("request"),
            )
            .await
            .expect("authenticated response");
        assert_eq!(authenticated.status(), StatusCode::OK);
        assert_eq!(
            authenticated
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes(),
            agent_did()
        );

        let rejected = protected
            .oneshot(request(Method::GET, "/private", Full::new(Bytes::new())))
            .await
            .expect("rejected response");
        assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
        assert!(rejected.headers().contains_key(header::WWW_AUTHENTICATE));
    });
}

#[test]
fn accepts_only_secure_or_explicit_loopback_origins() {
    let service = test_service(false);
    let insecure = AuthenticationOptions::new(Url::parse("http://service.example").expect("URL"));
    assert!(matches!(
        AuthenticationLayer::new(service.clone(), insecure),
        Err(TowerError::InvalidConfiguration(_))
    ));

    let mut loopback =
        AuthenticationOptions::new(Url::parse("http://127.0.0.1:3000").expect("URL"));
    loopback.allow_insecure_loopback = true;
    AuthenticationLayer::new(service, loopback).expect("loopback layer");
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

fn request<B>(method: Method, uri: &str, body: B) -> Request<B> {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(body)
        .expect("request")
}

fn command_request(uri: &str, body: &'static [u8], assertion: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("AEP {assertion}"))
        .header("idempotency-key", format!("key-{assertion}"))
        .header(header::CONTENT_TYPE, aep_core::MEDIA_TYPE)
        .body(Full::new(Bytes::from_static(body)))
        .expect("request")
}

async fn assert_problem(response: aep_tower::HttpResponse, status: StatusCode, code: ErrorCode) {
    assert_eq!(response.status(), status);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Problem Details");
    assert_eq!(response["code"], code.as_str());
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
