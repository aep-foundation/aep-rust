//! Wire-level contracts of the Tower adapter.
//!
//! The adapter owns the HTTP behaviour the Service crate deliberately leaves to its host: method
//! handling, the request target that a protected-resource assertion is bound to, and the shape of
//! the Problem Details it emits on its own account.

use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use aep_core::{AgentStatus, AuthenticationMethod, ClientAssertionClaims, ErrorCode};
use aep_service::{
    ClientAssertionVerificationContext, ClientAssertionVerifier, Clock, EnrollmentRecord,
    EnrollmentStore, MemoryEnrollmentStore, Service, ServiceError, ServiceOptions,
};
use aep_tower::{
    AuthenticationLayer, AuthenticationOptions, CommandService, TowerError,
    protected_resource_request,
};
use async_trait::async_trait;
use bytes::Bytes;
use futures::executor::block_on;
use http::{HeaderValue, Method, Request, StatusCode, header};
use http_body_util::{BodyExt as _, Full};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tower::{ServiceBuilder, ServiceExt as _, service_fn};
use url::Url;

// --- The request target an assertion is bound to -------------------------------------------

#[test]
fn keeps_the_request_target_on_the_configured_origin() {
    let options = AuthenticationOptions::new(origin());

    // A target beginning with `//` is a network-path reference. Resolving it against the origin
    // would replace the authority, and the result is the `resource` CORE-CA-016 checks the
    // assertion against, so an assertion bound to another origin would satisfy the check.
    for target in ["//attacker.example/x", "/\\attacker.example/x"] {
        let built = protected_resource_request(&options, &target_request(target))
            .expect("protected-resource request");
        assert_eq!(
            built.url.host_str(),
            Some("service.example"),
            "target {target} moved the resource off the configured origin"
        );
    }

    let absolute =
        protected_resource_request(&options, &target_request("http://attacker.example/x"))
            .expect("protected-resource request");
    assert_eq!(absolute.url.as_str(), "https://service.example/x");
}

#[test]
fn carries_the_path_query_and_method_of_the_request() {
    let options = AuthenticationOptions::new(origin());
    let built = protected_resource_request(&options, &target_request("/reports/7?format=csv"))
        .expect("protected-resource request");

    assert_eq!(
        built.url.as_str(),
        "https://service.example/reports/7?format=csv"
    );
    assert_eq!(built.method, Method::GET);
    assert!(built.headers.is_empty());

    // The fragment is never sent on the wire, so the resource never carries one (CORE-CA-014).
    assert_eq!(built.url.fragment(), None);
}

#[test]
fn rejects_origins_that_are_not_a_bare_https_origin() {
    for candidate in [
        "http://service.example/",
        "https://user@service.example/",
        "https://service.example/base",
        "https://service.example/?q=1",
    ] {
        let options = AuthenticationOptions::new(Url::parse(candidate).expect("URL"));
        assert!(
            matches!(
                protected_resource_request(&options, &target_request("/private")),
                Err(TowerError::InvalidConfiguration(_))
            ),
            "{candidate} was accepted as a protected-resource origin"
        );
    }
}

#[test]
fn admits_only_the_three_syntactic_loopback_hosts_over_plaintext() {
    // CORE-OAS-003 names `localhost`, `127.0.0.1` and `[::1]`. Any other address in 127.0.0.0/8
    // is an ordinary plaintext origin, and the bracketed IPv6 literal must be recognised.
    for accepted in [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://[::1]:3000",
    ] {
        let mut options = AuthenticationOptions::new(Url::parse(accepted).expect("URL"));
        options.allow_insecure_loopback = true;
        protected_resource_request(&options, &target_request("/private"))
            .unwrap_or_else(|_| panic!("{accepted} was rejected as a loopback origin"));
    }

    for refused in ["http://127.9.9.9:3000", "http://loopback.example"] {
        let mut options = AuthenticationOptions::new(Url::parse(refused).expect("URL"));
        options.allow_insecure_loopback = true;
        assert!(
            matches!(
                protected_resource_request(&options, &target_request("/private")),
                Err(TowerError::InvalidConfiguration(_))
            ),
            "{refused} was accepted as a loopback origin"
        );
    }
}

// --- Method handling -------------------------------------------------------------------------

#[test]
fn answers_head_on_every_endpoint_that_answers_get() {
    block_on(async {
        let commands = CommandService::new(test_service(true), 1 << 20).expect("command service");

        let get = commands
            .clone()
            .oneshot(request(Method::GET, "/.well-known/aep"))
            .await
            .expect("Inspect response");
        let content_type = get.headers().get(header::CONTENT_TYPE).cloned();
        let length = get
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes()
            .len();
        assert!(length > 0);

        let head = commands
            .clone()
            .oneshot(request(Method::HEAD, "/.well-known/aep"))
            .await
            .expect("Inspect HEAD response");
        assert_eq!(head.status(), StatusCode::OK);
        assert_eq!(
            head.headers().get(header::CONTENT_TYPE),
            content_type.as_ref()
        );
        assert_eq!(
            head.headers().get(header::CONTENT_LENGTH),
            Some(&HeaderValue::from(u64::try_from(length).expect("length"))),
            "HEAD must keep the representation metadata of the GET response"
        );
        assert!(
            head.into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes()
                .is_empty()
        );

        let status = commands
            .oneshot(
                Request::builder()
                    .method(Method::HEAD)
                    .uri("/custom/aep/status")
                    .header(header::AUTHORIZATION, "AEP status-head")
                    .body(Full::new(Bytes::new()))
                    .expect("request"),
            )
            .await
            .expect("Status HEAD response");
        assert_eq!(status.status(), StatusCode::OK);
        assert!(
            status
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes()
                .is_empty()
        );
    });
}

#[test]
fn reports_every_supported_method_when_refusing_one() {
    block_on(async {
        let commands = CommandService::new(test_service(false), 1 << 20).expect("command service");

        // RFC 9110 Section 15.5.6: `Allow` names the whole set the target supports, and HEAD is
        // supported wherever GET is.
        let on_inspect = commands
            .clone()
            .oneshot(request(Method::POST, "/.well-known/aep"))
            .await
            .expect("Inspect method response");
        assert_eq!(on_inspect.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            on_inspect.headers().get(header::ALLOW),
            Some(&HeaderValue::from_static("GET, HEAD"))
        );
        assert_problem(
            on_inspect,
            StatusCode::METHOD_NOT_ALLOWED,
            &ErrorCode::InvalidRequest,
        )
        .await;

        for (method, path) in [
            (Method::HEAD, "/custom/aep/enroll"),
            (Method::DELETE, "/custom/aep/grant"),
            (Method::PUT, "/custom/aep/revoke"),
        ] {
            let response = commands
                .clone()
                .oneshot(request(method.clone(), path))
                .await
                .expect("method response");
            assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
            assert_eq!(
                response.headers().get(header::ALLOW),
                Some(&HeaderValue::from_static("POST")),
                "{method} {path} advertised the wrong method set"
            );
            if method == Method::HEAD {
                assert!(
                    response
                        .into_body()
                        .collect()
                        .await
                        .expect("body")
                        .to_bytes()
                        .is_empty()
                );
            }
        }

        let unknown = commands
            .oneshot(request(Method::GET, "/custom/aep/unknown"))
            .await
            .expect("unknown path response");
        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    });
}

// --- Problem Details -------------------------------------------------------------------------

#[test]
fn publishes_problem_titles_as_one_sentence() {
    block_on(async {
        let commands = CommandService::new(test_service(false), 1 << 20).expect("command service");
        let refused = commands
            .oneshot(request(Method::POST, "/.well-known/aep"))
            .await
            .expect("method response");

        assert_eq!(
            refused.headers().get(header::CONTENT_TYPE),
            Some(&HeaderValue::from_static(aep_core::PROBLEM_MEDIA_TYPE))
        );
        let body = body_json(refused).await;
        // The registry spells the code in lower snake case and the published titles capitalise
        // only the first word, exactly as the Service's own Problem Details do.
        assert_eq!(body["title"], "Invalid request");
        assert_eq!(body["type"], "urn:aep:error:invalid_request");
        assert_eq!(body["status"], 405);
    });
}

// --- Command dispatch ------------------------------------------------------------------------

#[test]
fn dispatches_grant_and_revoke_through_the_service() {
    block_on(async {
        let commands = CommandService::new(test_service(true), 1 << 20).expect("command service");
        assert_eq!(commands.paths().grant, "/custom/aep/grant");
        assert_eq!(commands.paths().revoke, "/custom/aep/revoke");
        assert_eq!(commands.paths().status, "/custom/aep/status");
        assert_eq!(commands.paths().inspect, "/.well-known/aep");

        for (path, body, assertion) in [
            (
                "/custom/aep/grant",
                &br#"{"grant_type":"unregistered"}"#[..],
                "grant-1",
            ),
            (
                "/custom/aep/revoke",
                &br#"{"grant_type":""}"#[..],
                "revoke-1",
            ),
        ] {
            let response = commands
                .clone()
                .oneshot(command_request(path, body, assertion))
                .await
                .expect("command response");
            // The route is reached and the Service answers on the wire; only a routing failure
            // would produce 404 or 405 here.
            assert!(
                response.status().is_client_error(),
                "{path} returned {}",
                response.status()
            );
            assert_ne!(response.status(), StatusCode::NOT_FOUND);
            assert_ne!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        }
    });
}

#[test]
fn accepts_the_aep_media_type_with_parameters_and_nothing_else() {
    block_on(async {
        let commands = CommandService::new(test_service(false), 1 << 20).expect("command service");

        let parameterised = commands
            .clone()
            .oneshot(
                enroll_builder("media-1")
                    .header(
                        header::CONTENT_TYPE,
                        format!("{}; charset=utf-8", aep_core::MEDIA_TYPE),
                    )
                    .body(enroll_body())
                    .expect("request"),
            )
            .await
            .expect("parameterised media type response");
        assert_eq!(parameterised.status(), StatusCode::OK);

        // Two Content-Type lines leave the media type ambiguous, so the request is refused rather
        // than resolved to one of them.
        let ambiguous = commands
            .clone()
            .oneshot(
                enroll_builder("media-2")
                    .header(header::CONTENT_TYPE, aep_core::MEDIA_TYPE)
                    .header(header::CONTENT_TYPE, aep_core::MEDIA_TYPE)
                    .body(enroll_body())
                    .expect("request"),
            )
            .await
            .expect("ambiguous media type response");
        assert_problem(
            ambiguous,
            StatusCode::BAD_REQUEST,
            &ErrorCode::InvalidRequest,
        )
        .await;

        let missing = commands
            .oneshot(
                enroll_builder("media-3")
                    .body(enroll_body())
                    .expect("request"),
            )
            .await
            .expect("missing media type response");
        assert_problem(missing, StatusCode::BAD_REQUEST, &ErrorCode::InvalidRequest).await;
    });
}

#[test]
fn reads_no_credential_from_an_ambiguous_or_foreign_authorization_field() {
    block_on(async {
        let commands = CommandService::new(test_service(true), 1 << 20).expect("command service");

        let cases: Vec<(&str, Vec<HeaderValue>)> = vec![
            (
                "two field lines",
                vec![
                    HeaderValue::from_static("AEP first"),
                    HeaderValue::from_static("AEP second"),
                ],
            ),
            (
                "a foreign scheme",
                vec![HeaderValue::from_static("Bearer opaque")],
            ),
            ("an unparsable value", vec![HeaderValue::from_static("AEP")]),
            (
                "a non-ASCII value",
                vec![HeaderValue::from_bytes(b"AEP \xff").expect("header value")],
            ),
        ];

        for (label, values) in cases {
            let mut builder = Request::builder()
                .method(Method::GET)
                .uri("/custom/aep/status");
            for value in values {
                builder = builder.header(header::AUTHORIZATION, value);
            }
            let response = commands
                .clone()
                .oneshot(builder.body(Full::new(Bytes::new())).expect("request"))
                .await
                .expect("status response");
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{label} was read as a usable credential"
            );
        }
    });
}

#[test]
fn reads_no_idempotency_key_from_repeated_or_non_ascii_field_lines() {
    block_on(async {
        let commands = CommandService::new(test_service(false), 1 << 20).expect("command service");

        // Each case needs its own assertion: the Service consumes `jti` once, so reusing one
        // would make the second case fail as a replay rather than on the header under test.
        let cases: Vec<(&str, Vec<HeaderValue>)> = vec![
            (
                "idem-repeated",
                vec![
                    HeaderValue::from_static("key-a"),
                    HeaderValue::from_static("key-b"),
                ],
            ),
            (
                "idem-binary",
                vec![HeaderValue::from_bytes(b"key-\xff").expect("header value")],
            ),
        ];

        for (assertion, values) in cases {
            let mut builder = Request::builder()
                .method(Method::POST)
                .uri("/custom/aep/enroll")
                .header(header::AUTHORIZATION, format!("AEP {assertion}"))
                .header(header::CONTENT_TYPE, aep_core::MEDIA_TYPE);
            for value in values {
                builder = builder.header("idempotency-key", value);
            }
            let response = commands
                .clone()
                .oneshot(builder.body(enroll_body()).expect("request"))
                .await
                .expect("enroll response");
            // An absent key is a plain non-idempotent Enroll, which the Service refuses because
            // the header is mandatory on state-changing commands.
            assert_problem(
                response,
                StatusCode::BAD_REQUEST,
                &ErrorCode::InvalidRequest,
            )
            .await;
        }
    });
}

#[test]
fn separates_an_oversized_body_from_a_broken_one() {
    block_on(async {
        // The length limit is the caller's fault and gets a 413 Problem Details; a transport that
        // stops mid-body is not, and must not be reported as an AEP protocol error.
        let too_large = CommandService::new(test_service(false), 4)
            .expect("command service")
            .oneshot(command_request(
                "/custom/aep/enroll",
                br#"{"agent_did":"did:web:agent.example"}"#,
                "size-1",
            ))
            .await
            .expect("body limit response");
        assert_problem(
            too_large,
            StatusCode::PAYLOAD_TOO_LARGE,
            &ErrorCode::InvalidRequest,
        )
        .await;

        let broken = CommandService::new(test_service(false), 1 << 20)
            .expect("command service")
            .oneshot(
                enroll_builder("size-2")
                    .header(header::CONTENT_TYPE, aep_core::MEDIA_TYPE)
                    .body(BrokenBody)
                    .expect("request"),
            )
            .await
            .expect("broken body response");
        assert_eq!(broken.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = br#"{"agent_did":"did:web:agent.example"}"#;
        let frames = [&body[..10], &body[10..]].map(|chunk| {
            Ok::<_, std::io::Error>(http_body::Frame::data(Bytes::copy_from_slice(chunk)))
        });
        let streamed = CommandService::new(test_service(false), body.len() - 1)
            .expect("command service")
            .oneshot(
                enroll_builder("size-streamed")
                    .header(header::CONTENT_TYPE, aep_core::MEDIA_TYPE)
                    .body(http_body_util::StreamBody::new(futures::stream::iter(
                        frames,
                    )))
                    .expect("request"),
            )
            .await
            .expect("streamed response");
        assert_problem(
            streamed,
            StatusCode::PAYLOAD_TOO_LARGE,
            &ErrorCode::InvalidRequest,
        )
        .await;
    });
}

#[test]
fn calls_the_inner_service_instance_that_reported_readiness() {
    block_on(async {
        let layer =
            AuthenticationLayer::new(test_service(true), AuthenticationOptions::new(origin()))
                .expect("authentication layer");
        let protected = ServiceBuilder::new()
            .layer(layer)
            .service(ReadyInner { ready: false });
        let response = protected
            .oneshot(
                Request::builder()
                    .uri("/private")
                    .header(header::AUTHORIZATION, "AEP ready")
                    .body(Full::new(Bytes::new()))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
    });
}

#[test]
fn preserves_the_authenticated_inner_service_error() {
    block_on(async {
        let layer =
            AuthenticationLayer::new(test_service(true), AuthenticationOptions::new(origin()))
                .expect("authentication layer");
        let protected = ServiceBuilder::new().layer(layer).service(service_fn(
            |_: Request<Full<Bytes>>| async {
                Err::<http::Response<Full<Bytes>>, _>(std::io::Error::other("application failed"))
            },
        ));
        let error = protected
            .oneshot(
                Request::builder()
                    .uri("/private")
                    .header(header::AUTHORIZATION, "AEP inner-error")
                    .body(Full::new(Bytes::new()))
                    .expect("request"),
            )
            .await
            .expect_err("application error");
        assert_eq!(error.to_string(), "application failed");
    });
}

struct ReadyInner {
    ready: bool,
}

impl Clone for ReadyInner {
    fn clone(&self) -> Self {
        Self { ready: false }
    }
}

impl tower::Service<Request<Full<Bytes>>> for ReadyInner {
    type Response = http::Response<Full<Bytes>>;
    type Error = std::convert::Infallible;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.ready = true;
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: Request<Full<Bytes>>) -> Self::Future {
        assert!(
            std::mem::take(&mut self.ready),
            "a clone did not acquire readiness"
        );
        std::future::ready(Ok(http::Response::new(Full::new(Bytes::new()))))
    }
}

#[test]
fn refuses_a_body_limit_of_zero() {
    assert!(matches!(
        CommandService::new(test_service(false), 0),
        Err(TowerError::InvalidConfiguration(_))
    ));
}

// --- Failures that are nobody's fault but the Service's --------------------------------------

#[test]
fn answers_a_store_failure_without_leaking_it() {
    block_on(async {
        let commands = CommandService::new(failing_service(), 1 << 20).expect("command service");
        let response = commands
            .oneshot(command_request(
                "/custom/aep/enroll",
                br#"{"agent_did":"did:web:agent.example"}"#,
                "store-1",
            ))
            .await
            .expect("enroll response");
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            response
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes()
                .is_empty()
        );

        let layer =
            AuthenticationLayer::new(failing_service(), AuthenticationOptions::new(origin()))
                .expect("authentication layer");
        let reached = Arc::new(AtomicBool::new(false));
        let calls = reached.clone();
        let protected = ServiceBuilder::new().layer(layer).service(service_fn(
            move |_: Request<Full<Bytes>>| {
                calls.store(true, Ordering::SeqCst);
                async {
                    Ok::<_, std::convert::Infallible>(http::Response::new(Full::new(Bytes::new())))
                }
            },
        ));
        let rejected = protected
            .oneshot(
                Request::builder()
                    .uri("/private")
                    .header(header::AUTHORIZATION, "AEP resource-1")
                    .body(Full::new(Bytes::new()))
                    .expect("request"),
            )
            .await
            .expect("protected response");
        assert_eq!(rejected.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!reached.load(Ordering::SeqCst));
    });
}

#[test]
fn refuses_an_invalid_response_from_a_custom_idempotency_store() {
    block_on(async {
        let mut options = service_options();
        options.idempotency_store = Some(Arc::new(InvalidResponseStore));
        let commands = CommandService::new(Service::new(options).expect("Service"), 1 << 20)
            .expect("command service");
        let body = br#"{"agent_did":"did:web:agent.example"}"#;
        assert!(matches!(
            commands
                .dispatch(command_request(
                    "/custom/aep/enroll",
                    body,
                    "invalid-direct"
                ))
                .await,
            Err(TowerError::InvalidConfiguration(_))
        ));
        let response = commands
            .oneshot(command_request("/custom/aep/enroll", body, "invalid-wire"))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            response
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes()
                .is_empty()
        );
    });
}

struct InvalidResponseStore;

#[async_trait]
impl aep_service::CommandIdempotencyStore for InvalidResponseStore {
    async fn execute(
        &self,
        _: aep_service::CommandIdempotencyInput,
        _: aep_service::CommandOperation,
    ) -> Result<aep_service::CommandIdempotencyResult, ServiceError> {
        Ok(aep_service::CommandIdempotencyResult::Replayed(
            aep_service::ServiceResponse {
                status: 0,
                headers: Default::default(),
                body: aep_service::ResponseBody::Revoke(Default::default()),
            },
        ))
    }
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

/// A request body whose transport fails before any data arrives.
struct BrokenBody;

impl http_body::Body for BrokenBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        _context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        std::task::Poll::Ready(Some(Err(std::io::Error::other("connection reset"))))
    }
}

struct FailingStore;

#[async_trait]
impl EnrollmentStore for FailingStore {
    async fn find(&self, _agent_did: &str) -> Result<Option<EnrollmentRecord>, ServiceError> {
        Err(ServiceError::Store(
            "enrollment store unavailable".to_owned(),
        ))
    }

    async fn save(&self, _record: EnrollmentRecord) -> Result<EnrollmentRecord, ServiceError> {
        Err(ServiceError::Store(
            "enrollment store unavailable".to_owned(),
        ))
    }
}

const AGENT_DID: &str = "did:web:agent.example";
const SERVICE_DID: &str = "did:web:service.example";

fn origin() -> Url {
    Url::parse("https://service.example").expect("origin")
}

fn service_options() -> ServiceOptions {
    let mut options = ServiceOptions::new(SERVICE_DID, Arc::new(AcceptingVerifier));
    options.authentication_methods = vec![AuthenticationMethod::AepJwt];
    options.clock = Some(Arc::new(FixedClock(fixed_time())));
    options.endpoint_base = Some("/custom/aep".to_owned());
    options.inspect_url =
        Some(Url::parse("https://service.example/.well-known/aep").expect("Inspect URL"));
    options
}

fn test_service(enrolled: bool) -> Arc<Service> {
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
    let mut options = service_options();
    options.enrollment_store = Some(Arc::new(
        MemoryEnrollmentStore::new(records).expect("enrollment store"),
    ));
    Service::new(options).expect("Service")
}

fn failing_service() -> Arc<Service> {
    let mut options = service_options();
    options.enrollment_store = Some(Arc::new(FailingStore));
    Service::new(options).expect("Service")
}

fn fixed_time() -> OffsetDateTime {
    OffsetDateTime::parse("2026-08-31T12:00:00Z", &Rfc3339).expect("fixed time")
}

fn target_request(uri: &str) -> Request<()> {
    Request::builder().uri(uri).body(()).expect("request")
}

fn request(method: Method, uri: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(Full::new(Bytes::new()))
        .expect("request")
}

fn enroll_builder(assertion: &str) -> http::request::Builder {
    Request::builder()
        .method(Method::POST)
        .uri("/custom/aep/enroll")
        .header(header::AUTHORIZATION, format!("AEP {assertion}"))
        .header("idempotency-key", format!("key-{assertion}"))
}

fn enroll_body() -> Full<Bytes> {
    Full::new(Bytes::from_static(
        br#"{"agent_did":"did:web:agent.example"}"#,
    ))
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

async fn body_json(response: aep_tower::HttpResponse) -> serde_json::Value {
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    serde_json::from_slice(&body).expect("JSON body")
}

async fn assert_problem(response: aep_tower::HttpResponse, status: StatusCode, code: &ErrorCode) {
    assert_eq!(response.status(), status);
    let body = body_json(response).await;
    assert_eq!(body["code"], code.as_str());
    assert_eq!(body["status"], status.as_u16());
}
