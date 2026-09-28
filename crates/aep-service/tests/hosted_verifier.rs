use aep_core::{
    AssertionOperation, ClientAssertionClaims, ClientAssertionSigningKey, HttpRequest,
    HttpResponse, HttpTransport, SignClientAssertionOptions, SigningAlgorithm, TransportError,
    sign_client_assertion,
};
use aep_service::{
    ClientAssertionVerificationContext, ClientAssertionVerifier,
    HostedPlatformClientAssertionVerifier, HostedPlatformClientAssertionVerifierOptions,
    ReqwestTransport,
};
use async_trait::async_trait;
use futures::executor::block_on;
use http::{HeaderMap, Method, StatusCode, header};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;

const ENDPOINT: &str = "https://platform.example/v1/aep/verifications";
const AGENT: &str = "did:web:platform.example:agents:one";
const SERVICE: &str = "did:web:service.example";

fn context(operation: AssertionOperation, jti: &str) -> ClientAssertionVerificationContext {
    let now = OffsetDateTime::parse("2026-08-31T12:00:00Z", &Rfc3339).expect("time");
    let resource = (operation == AssertionOperation::Authenticate)
        .then(|| Url::parse("https://service.example/resource?query=one").expect("URL"));
    let claims = ClientAssertionClaims {
        additional: BTreeMap::new(),
        aud: SERVICE.into(),
        exp: now.unix_timestamp() + 60,
        iat: now.unix_timestamp(),
        iss: AGENT.into(),
        jti: jti.into(),
        op: operation,
        resource: resource.as_ref().map(ToString::to_string),
        sub: AGENT.into(),
    };
    let assertion = sign_client_assertion(
        &claims,
        SignClientAssertionOptions {
            allow_insecure_loopback: false,
            key: &ClientAssertionSigningKey::ed25519_from_seed([42; 32]),
            key_id: AGENT,
        },
    )
    .expect("real assertion");
    ClientAssertionVerificationContext {
        assertion,
        current_time: now,
        idempotency_key: Some("command-key".into()),
        operation,
        resource,
        service_did: SERVICE.into(),
        signing_algorithms: vec![SigningAlgorithm::EdDsa],
    }
}

#[derive(Default)]
struct Transport {
    requests: Mutex<Vec<HttpRequest>>,
    answers: Mutex<VecDeque<Result<HttpResponse, TransportError>>>,
}
impl Transport {
    fn answer(&self, body: Value) {
        self.answers
            .lock()
            .expect("answers")
            .push_back(Ok(HttpResponse {
                body: serde_json::to_vec(&body).expect("JSON"),
                final_url: Url::parse(ENDPOINT).expect("URL"),
                headers: HeaderMap::new(),
                status: StatusCode::OK,
            }));
    }
}
#[async_trait]
impl HttpTransport for Transport {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        self.requests.lock().expect("requests").push(request);
        self.answers
            .lock()
            .expect("answers")
            .pop_front()
            .expect("scripted answer")
    }
}
fn verified(op: AssertionOperation) -> Value {
    json!({"agent_did":AGENT,"op":op,"reason":"verified","service_did":SERVICE,"verified":true})
}
fn verifier(transport: Arc<Transport>) -> HostedPlatformClientAssertionVerifier {
    let mut options = HostedPlatformClientAssertionVerifierOptions::new(ENDPOINT);
    options.authorization = Some("Bearer service-secret".into());
    options.transport = Some(transport);
    HostedPlatformClientAssertionVerifier::new(options).expect("verifier")
}

#[test]
fn sends_exact_verification_bodies_and_body_derived_keys_for_every_operation() {
    block_on(async {
        for op in [
            AssertionOperation::Enroll,
            AssertionOperation::Grant,
            AssertionOperation::Revoke,
            AssertionOperation::Status,
            AssertionOperation::Authenticate,
        ] {
            let transport = Arc::new(Transport::default());
            let verifier = verifier(transport.clone());
            let original = context(op, "first");
            for _ in 0..3 {
                transport.answer(verified(op));
            }
            let claims = verifier.verify(original.clone()).await.expect("verified");
            assert_eq!(claims.sub, AGENT);
            assert_eq!(claims.op, op);
            let mut retry = original.clone();
            retry.idempotency_key = Some("another-command-key".into());
            verifier.verify(retry).await.expect("exact retry");
            verifier
                .verify(context(op, "second"))
                .await
                .expect("fresh assertion");
            let requests = transport.requests.lock().expect("requests");
            assert_eq!(requests.len(), 3);
            for request in requests.iter() {
                assert_eq!(request.method, Method::POST);
                assert_eq!(request.url.as_str(), ENDPOINT);
                assert_eq!(request.headers[header::ACCEPT], aep_core::MEDIA_TYPE);
                assert_eq!(request.headers[header::CONTENT_TYPE], aep_core::MEDIA_TYPE);
                assert_eq!(
                    request.headers[header::AUTHORIZATION],
                    "Bearer service-secret"
                );
                assert!(request.headers[header::AUTHORIZATION].is_sensitive());
                let key: String = Sha256::digest(&request.body)
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                assert_eq!(request.headers["idempotency-key"], key);
            }
            let body: Value = serde_json::from_slice(&requests[0].body).expect("body");
            let mut expected =
                json!({"client_assertion":original.assertion,"op":op,"service_did":SERVICE});
            if let Some(resource) = original.resource {
                expected["resource"] = json!(resource.as_str());
            }
            assert_eq!(body, expected);
            assert_eq!(requests[0].body, requests[1].body);
            assert_ne!(
                requests[0].headers["idempotency-key"],
                requests[2].headers["idempotency-key"]
            );
        }
    });
}

#[test]
fn refuses_unconfirmed_or_malformed_platform_responses() {
    block_on(async {
        let valid = verified(AssertionOperation::Status);
        let mut invalids = vec![
            json!([]),
            json!({}),
            json!({"verified":true,"service_did":SERVICE}),
        ];
        for (field, value) in [
            ("verified", json!(false)),
            ("verified", json!("true")),
            ("agent_did", json!("did:web:other.example")),
            ("op", json!("enroll")),
            ("service_did", json!("did:web:other.example")),
            ("reason", Value::Null),
        ] {
            let mut body = valid.clone();
            body[field] = value;
            invalids.push(body);
        }
        for body in invalids {
            let t = Arc::new(Transport::default());
            t.answer(body);
            assert!(
                verifier(t)
                    .verify(context(AssertionOperation::Status, "jti"))
                    .await
                    .is_err()
            );
        }
        for (status, body, final_url) in [
            (
                StatusCode::SERVICE_UNAVAILABLE,
                b"private response".to_vec(),
                ENDPOINT,
            ),
            (StatusCode::FOUND, vec![], ENDPOINT),
            (StatusCode::OK, b"not JSON".to_vec(), ENDPOINT),
            (
                StatusCode::OK,
                serde_json::to_vec(&valid).expect("JSON"),
                "https://attacker.example/verify",
            ),
            (StatusCode::OK, vec![b' '; (1 << 20) + 1], ENDPOINT),
        ] {
            let t = Arc::new(Transport::default());
            t.answers
                .lock()
                .expect("answers")
                .push_back(Ok(HttpResponse {
                    status,
                    body,
                    final_url: Url::parse(final_url).expect("URL"),
                    headers: HeaderMap::new(),
                }));
            let error = verifier(t)
                .verify(context(AssertionOperation::Status, "jti"))
                .await
                .expect_err("refused");
            assert!(!error.to_string().contains("private response"));
        }
        let t = Arc::new(Transport::default());
        t.answers
            .lock()
            .expect("answers")
            .push_back(Err(TransportError::new("service-secret")));
        assert!(
            !verifier(t)
                .verify(context(AssertionOperation::Status, "jti"))
                .await
                .expect_err("failed")
                .to_string()
                .contains("service-secret")
        );
    });
}

#[test]
fn validates_configuration_and_rejects_bad_assertions_before_network_use() {
    for url in [
        "not a URL",
        "http://platform.example/v",
        "https://user:secret@platform.example/v",
        "https://platform.example/v#fragment",
    ] {
        assert!(
            HostedPlatformClientAssertionVerifier::new(
                HostedPlatformClientAssertionVerifierOptions::new(url)
            )
            .is_err()
        );
    }
    for limit in [true, false] {
        let mut options = HostedPlatformClientAssertionVerifierOptions::new(ENDPOINT);
        if limit {
            options.maximum_response_bytes = 0;
        } else {
            options.request_timeout = Duration::ZERO;
        }
        assert!(HostedPlatformClientAssertionVerifier::new(options).is_err());
    }
    let mut options = HostedPlatformClientAssertionVerifierOptions::new(ENDPOINT);
    options.authorization = Some("Bearer secret\nInjected: true".into());
    assert!(HostedPlatformClientAssertionVerifier::new(options).is_err());
    let defaults = HostedPlatformClientAssertionVerifierOptions::new(ENDPOINT);
    assert_eq!(defaults.request_timeout, Duration::from_secs(30));
    assert_eq!(defaults.maximum_response_bytes, 1 << 20);
    assert!(HostedPlatformClientAssertionVerifier::new(defaults).is_ok());
    block_on(async {
        let t = Arc::new(Transport::default());
        let verifier = verifier(t.clone());
        let mut bad = context(AssertionOperation::Status, "jti");
        bad.assertion = "not a JWT".into();
        assert!(verifier.verify(bad).await.is_err());
        assert!(t.requests.lock().expect("requests").is_empty());
        let mut unsupported = context(AssertionOperation::Status, "jti");
        unsupported.signing_algorithms = vec![SigningAlgorithm::Es256];
        assert!(verifier.verify(unsupported).await.is_err());
        assert!(t.requests.lock().expect("requests").is_empty());
        let mut invalid = context(AssertionOperation::Status, "jti");
        let parts = invalid.assertion.split('.').collect::<Vec<_>>();
        let mut claims = aep_core::decode_jwt_unverified(&invalid.assertion)
            .expect("claims")
            .payload;
        claims.insert("jti".into(), json!(""));
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        invalid.assertion = format!(
            "{}.{}.{}",
            parts[0],
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims")),
            parts[2]
        );
        assert!(verifier.verify(invalid).await.is_err());
        assert!(t.requests.lock().expect("requests").is_empty());
        let mut options = HostedPlatformClientAssertionVerifierOptions::new(ENDPOINT);
        options.transport = Some(t.clone());
        let verifier =
            HostedPlatformClientAssertionVerifier::new(options).expect("anonymous verifier");
        t.answer(verified(AssertionOperation::Status));
        verifier
            .verify(context(AssertionOperation::Status, "jti"))
            .await
            .expect("verified");
        assert!(
            !t.requests.lock().expect("requests")[0]
                .headers
                .contains_key(header::AUTHORIZATION)
        );
    });
}

struct Stalled(Arc<AtomicBool>);
struct Dropped(Arc<AtomicBool>);
impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
#[async_trait]
impl HttpTransport for Stalled {
    async fn send(&self, _: HttpRequest) -> Result<HttpResponse, TransportError> {
        let _guard = Dropped(self.0.clone());
        futures::future::pending().await
    }
}
#[test]
fn timeout_cancels_an_injected_transport_without_a_tokio_runtime() {
    block_on(async {
        let dropped = Arc::new(AtomicBool::new(false));
        let mut options = HostedPlatformClientAssertionVerifierOptions::new(ENDPOINT);
        options.transport = Some(Arc::new(Stalled(dropped.clone())));
        options.request_timeout = Duration::from_millis(20);
        let verifier = HostedPlatformClientAssertionVerifier::new(options).expect("verifier");
        assert!(
            verifier
                .verify(context(AssertionOperation::Status, "jti"))
                .await
                .expect_err("timeout")
                .to_string()
                .contains("timed out")
        );
        assert!(dropped.load(Ordering::SeqCst));
    });
}

fn server(response: Vec<u8>, stall: bool) -> (Url, std::thread::JoinHandle<()>) {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
    listener.set_nonblocking(true).expect("nonblocking");
    let address = listener.local_addr().expect("address");
    let task = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "client did not connect"
                    );
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error) => panic!("{error}"),
            }
        };
        stream.set_nonblocking(false).expect("blocking");
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("timeout");
        let mut received = Vec::new();
        let mut buffer = [0; 512];
        while !received.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
            let n = stream.read(&mut buffer).expect("read");
            if n == 0 {
                return;
            }
            received.extend_from_slice(&buffer[..n]);
        }
        let header_end = received
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .expect("headers")
            + 4;
        let content_length = std::str::from_utf8(&received[..header_end])
            .expect("HTTP headers")
            .lines()
            .find_map(|line| {
                line.split_once(':')
                    .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .map(|(_, value)| value.trim().parse::<usize>().expect("length"))
            })
            .unwrap_or(0);
        while received.len() < header_end + content_length {
            let n = stream.read(&mut buffer).expect("body");
            assert!(n > 0);
            received.extend_from_slice(&buffer[..n]);
        }
        if content_length > 0 {
            assert_eq!(&received[header_end..], b"probe");
        }
        if stall {
            std::thread::sleep(Duration::from_millis(400));
        } else {
            stream.write_all(&response).expect("response");
        }
    });
    (
        Url::parse(&format!("http://{address}/verify")).expect("URL"),
        task,
    )
}
#[tokio::test]
async fn native_transport_does_not_follow_redirects_and_bounds_response_size() {
    let cases = [
        (b"HTTP/1.1 302 Found\r\nLocation: https://attacker.example/v\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(), 64, Some(StatusCode::FOUND)),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n12345".as_slice(), 5, Some(StatusCode::OK)),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n12345".as_slice(), 4, None),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n12".as_slice(), 8, None),
    ];
    for (wire, limit, expected) in cases {
        let (url, task) = server(wire.to_vec(), false);
        let transport = ReqwestTransport::new(limit, Duration::from_secs(1)).expect("transport");
        let (method, body) = if expected.is_some() {
            (Method::GET, vec![])
        } else {
            (Method::POST, b"probe".to_vec())
        };
        let result = transport
            .send(HttpRequest {
                method,
                url: url.clone(),
                headers: HeaderMap::new(),
                body,
            })
            .await;
        if let Some(status) = expected {
            let response = result.expect("response");
            assert_eq!(response.status, status);
            assert_eq!(response.final_url, url);
            if status == StatusCode::OK {
                assert_eq!(response.body, b"12345");
            }
        } else {
            assert!(result.is_err());
        }
        task.join().expect("server");
    }
}
#[tokio::test]
async fn native_transport_times_out_a_stalled_response() {
    let (url, task) = server(vec![], true);
    let transport = ReqwestTransport::new(1024, Duration::from_millis(200)).expect("transport");
    assert!(
        transport
            .send(HttpRequest {
                method: Method::GET,
                url,
                headers: HeaderMap::new(),
                body: vec![]
            })
            .await
            .is_err()
    );
    task.join().expect("server");
}
