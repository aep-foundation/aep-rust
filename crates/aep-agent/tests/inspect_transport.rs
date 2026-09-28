//! Inspect transport, redirect safety, and cache behaviour.

use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
};

use aep_agent::*;
use aep_core::*;
use async_trait::async_trait;
use futures::executor::block_on;
use http::{HeaderMap, HeaderValue, StatusCode, header};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;

const SERVICE: &str = "https://service.example/";
const INSPECT: &str = "https://service.example/.well-known/aep";

fn now() -> OffsetDateTime {
    OffsetDateTime::parse("2026-08-31T12:00:00Z", &Rfc3339).expect("fixed time")
}

struct FixedClock(OffsetDateTime);

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

struct StubSigner;

#[async_trait]
impl AssertionSigner for StubSigner {
    async fn sign(
        &self,
        _claims: &ClientAssertionClaims,
        _algorithms: &[SigningAlgorithm],
    ) -> Result<String, AgentError> {
        Ok("signed.assertion.value".to_owned())
    }
}

struct StubIdentityProvider;

#[async_trait]
impl IdentityProvider for StubIdentityProvider {
    async fn get_or_create_identity(
        &self,
        request: IdentityRequest,
    ) -> Result<AgentIdentity, AgentError> {
        Ok(AgentIdentity {
            agent_did: "did:web:agent.example:agents:one".to_owned(),
            identity_method: IdentityMethod::DidWeb,
            service_did: request.inspection.document.service.did,
            signing_algorithms: vec![SigningAlgorithm::EdDsa, SigningAlgorithm::Es256],
            metadata: BTreeMap::new(),
        })
    }

    async fn signer_for(
        &self,
        _identity: &AgentIdentity,
    ) -> Result<Arc<dyn AssertionSigner>, AgentError> {
        Ok(Arc::new(StubSigner))
    }
}

struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
    final_url: Option<Url>,
}

enum Scripted {
    Answer(Box<Answer>),
    Failure,
}

fn answer(
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
    final_url: Option<Url>,
) -> Scripted {
    Scripted::Answer(Box::new(Answer {
        status,
        headers,
        body,
        final_url,
    }))
}

#[derive(Default)]
struct ScriptedTransport {
    responses: Mutex<VecDeque<Scripted>>,
    requests: Mutex<Vec<HttpRequest>>,
}

impl ScriptedTransport {
    fn push(&self, response: Scripted) {
        self.responses.lock().expect("lock").push_back(response);
    }

    fn document(&self, service_did: &str) {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(MEDIA_TYPE));
        self.push(answer(
            StatusCode::OK,
            headers,
            serde_json::to_vec(&document(service_did)).expect("JSON"),
            None,
        ));
    }

    fn redirect(&self, location: Option<&str>) {
        let mut headers = HeaderMap::new();
        if let Some(location) = location {
            headers.insert(
                header::LOCATION,
                HeaderValue::from_str(location).expect("location"),
            );
        }
        self.push(answer(StatusCode::FOUND, headers, Vec::new(), None));
    }
}

#[async_trait]
impl HttpTransport for ScriptedTransport {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let response = self
            .responses
            .lock()
            .expect("lock")
            .pop_front()
            .ok_or_else(|| TransportError::new("no scripted response"))?;
        self.requests.lock().expect("lock").push(request.clone());
        match response {
            Scripted::Failure => Err(TransportError::new("connection reset")),
            Scripted::Answer(answer) => Ok(HttpResponse {
                status: answer.status,
                final_url: answer.final_url.unwrap_or(request.url),
                headers: answer.headers,
                body: answer.body,
            }),
        }
    }
}

#[derive(Default)]
struct RecordingCache {
    entries: Mutex<BTreeMap<String, InspectCacheEntry>>,
}

impl RecordingCache {
    fn keys(&self) -> Vec<String> {
        self.entries.lock().expect("lock").keys().cloned().collect()
    }

    fn seed(&self, key: &str, entry: InspectCacheEntry) {
        self.entries
            .lock()
            .expect("lock")
            .insert(key.to_owned(), entry);
    }
}

#[async_trait]
impl InspectCache for RecordingCache {
    async fn delete(&self, inspect_url: &Url) -> Result<(), AgentError> {
        self.entries
            .lock()
            .expect("lock")
            .remove(inspect_url.as_str());
        Ok(())
    }
    async fn find(&self, inspect_url: &Url) -> Result<Option<InspectCacheEntry>, AgentError> {
        Ok(self
            .entries
            .lock()
            .expect("lock")
            .get(inspect_url.as_str())
            .cloned())
    }
    async fn save(&self, inspect_url: &Url, entry: InspectCacheEntry) -> Result<(), AgentError> {
        self.entries
            .lock()
            .expect("lock")
            .insert(inspect_url.to_string(), entry);
        Ok(())
    }
}

fn document(service_did: &str) -> serde_json::Value {
    serde_json::json!({
        "aep_version": "1.0",
        "bindings": {"supported": ["http"]},
        "commands": {"supported": ["inspect"]},
        "core": {"signing_algorithms": ["EdDSA", "ES256"]},
        "http": {},
        "identity": {"methods": ["did:web"]},
        "service": {"did": service_did}
    })
}

fn entry(cache_control: Option<&str>, final_url: &str) -> InspectCacheEntry {
    let mut headers = HeaderMap::new();
    if let Some(value) = cache_control {
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_str(value).expect("Cache-Control"),
        );
    }
    headers.insert(header::ETAG, HeaderValue::from_static("\"one\""));
    headers.insert(
        header::LAST_MODIFIED,
        HeaderValue::from_static("Mon, 31 Aug 2026 11:00:00 GMT"),
    );
    InspectCacheEntry {
        cached_at: now(),
        document: parse_inspect_document(
            &serde_json::to_vec(&document("did:web:service.example")).expect("JSON"),
        )
        .expect("document"),
        final_url: Url::parse(final_url).expect("URL"),
        headers,
    }
}

fn agent(transport: Arc<ScriptedTransport>, cache: Arc<RecordingCache>) -> Session {
    let mut options = ClientOptions::new(Arc::new(StubIdentityProvider));
    options.clock = Some(Arc::new(FixedClock(now())));
    options.command_transport = Some(transport.clone());
    options.inspect_transport = Some(transport);
    options.inspect_cache = Some(cache);
    Client::new(options)
        .expect("client")
        .service(SERVICE)
        .expect("session")
}

fn inspect_code(error: AgentError) -> InspectErrorCode {
    match error {
        AgentError::Inspect { code, .. } => code,
        other => panic!("expected an Inspect failure, got {other:?}"),
    }
}

/// A stored final URL that is no longer a safe target is discarded before it is reused, whether or
/// not the entry is still fresh.
#[test]
fn a_cached_entry_naming_another_origin_is_discarded() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        transport.document("did:web:service.example");
        let cache = Arc::new(RecordingCache::default());
        cache.seed(
            INSPECT,
            entry(None, "https://elsewhere.example/.well-known/aep"),
        );
        let session = agent(transport.clone(), cache.clone());
        let inspection = session.inspect().await.expect("inspection");
        assert_eq!(inspection.final_url.as_str(), INSPECT);
        assert_eq!(cache.keys(), vec![INSPECT.to_owned()]);
        // The poisoned entry was not reused, so the document came from the network.
        assert_eq!(transport.requests.lock().expect("lock").len(), 1);
    });
}

#[test]
fn a_custom_cache_cannot_revalidate_a_no_store_document() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        transport.document("did:web:service.example");
        let cache = Arc::new(RecordingCache::default());
        let final_url = "https://service.example/discovery/current";
        let stored = entry(Some("max-age=300,no-store"), final_url);
        cache.seed(INSPECT, stored.clone());
        cache.seed(final_url, stored);
        let session = agent(transport.clone(), cache.clone());
        session.inspect().await.expect("fresh fetch");
        assert_eq!(cache.keys(), vec![INSPECT.to_owned()]);
        let requests = transport.requests.lock().expect("requests");
        assert_eq!(requests[0].url.as_str(), INSPECT);
        assert!(!requests[0].headers.contains_key(header::IF_NONE_MATCH));
        assert!(!requests[0].headers.contains_key(header::IF_MODIFIED_SINCE));
    });
}

#[test]
fn revalidation_redirects_remove_the_obsolete_cache_alias() {
    block_on(async {
        let old_url = "https://service.example/discovery/old";
        let cache = Arc::new(RecordingCache::default());
        let stored = entry(Some("no-cache"), old_url);
        cache.seed(INSPECT, stored.clone());
        cache.seed(old_url, stored);
        let transport = Arc::new(ScriptedTransport::default());
        transport.redirect(Some("/discovery/current"));
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(MEDIA_TYPE));
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        transport.push(answer(
            StatusCode::OK,
            headers,
            serde_json::to_vec(&document("did:web:service.example")).expect("JSON"),
            None,
        ));
        let session = agent(transport, cache.clone());
        assert_eq!(
            session
                .inspect()
                .await
                .expect("redirected revalidation")
                .final_url
                .path(),
            "/discovery/current"
        );
        assert!(cache.keys().is_empty());
    });
}

/// CORE-CACHE-003: a stored validator is offered back on revalidation.
#[test]
fn revalidation_offers_both_stored_validators() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        let mut headers = HeaderMap::new();
        headers.insert(header::ETAG, HeaderValue::from_static("\"two\""));
        headers.insert(
            header::LAST_MODIFIED,
            HeaderValue::from_static("Mon, 31 Aug 2026 11:30:00 GMT"),
        );
        transport.push(answer(StatusCode::NOT_MODIFIED, headers, Vec::new(), None));
        let cache = Arc::new(RecordingCache::default());
        cache.seed(INSPECT, entry(Some("no-cache"), INSPECT));
        let session = agent(transport.clone(), cache.clone());
        let inspection = session.inspect().await.expect("inspection");
        assert_eq!(inspection.etag.as_deref(), Some("\"two\""));
        assert_eq!(
            inspection.last_modified.as_deref(),
            Some("Mon, 31 Aug 2026 11:30:00 GMT")
        );
        let requests = transport.requests.lock().expect("lock");
        let sent = requests.first().expect("request");
        assert_eq!(
            sent.headers
                .get(header::IF_NONE_MATCH)
                .map(|v| v.to_str().expect("value")),
            Some("\"one\"")
        );
        assert!(sent.headers.contains_key(header::IF_MODIFIED_SINCE));
    });
}

/// A `304` is only usable against a stored representation.
#[test]
fn a_conditional_response_without_a_stored_document_is_refused() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        transport.push(answer(
            StatusCode::NOT_MODIFIED,
            HeaderMap::new(),
            Vec::new(),
            None,
        ));
        let session = agent(transport, Arc::new(RecordingCache::default()));
        assert_eq!(
            inspect_code(session.inspect().await.expect_err("no stored document")),
            InspectErrorCode::HttpError
        );
    });
}

/// A transport failure is an Inspect failure rather than a panic or a silent retry.
#[test]
fn a_transport_failure_is_reported_as_an_http_error() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        transport.push(Scripted::Failure);
        let session = agent(transport, Arc::new(RecordingCache::default()));
        assert_eq!(
            inspect_code(session.inspect().await.expect_err("transport failure")),
            InspectErrorCode::HttpError
        );
    });
}

/// CORE-CACHE-010/011: the Agent follows Inspect redirects itself, so a transport that followed
/// one behind its back is refused, as is a chain that never terminates or that cannot be followed.
#[test]
fn unusable_redirects_are_refused() {
    block_on(async {
        // A transport that resolved the request somewhere else.
        let transport = Arc::new(ScriptedTransport::default());
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(MEDIA_TYPE));
        transport.push(answer(
            StatusCode::OK,
            headers,
            serde_json::to_vec(&document("did:web:service.example")).expect("JSON"),
            Some(Url::parse("https://service.example/moved").expect("URL")),
        ));
        let session = agent(transport, Arc::new(RecordingCache::default()));
        assert_eq!(
            inspect_code(session.inspect().await.expect_err("followed redirect")),
            InspectErrorCode::InvalidRedirect
        );

        // Six hops exceed the five the Agent will follow.
        let transport = Arc::new(ScriptedTransport::default());
        for index in 0..=5 {
            transport.redirect(Some(&format!("/hop-{index}")));
        }
        let session = agent(transport, Arc::new(RecordingCache::default()));
        assert_eq!(
            inspect_code(session.inspect().await.expect_err("redirect limit")),
            InspectErrorCode::InvalidRedirect
        );

        // A redirect that names no target, or one that is not a URL reference at all.
        for location in [None, Some("http://[")] {
            let transport = Arc::new(ScriptedTransport::default());
            transport.redirect(location);
            let session = agent(transport, Arc::new(RecordingCache::default()));
            assert_eq!(
                inspect_code(session.inspect().await.expect_err("unusable Location")),
                InspectErrorCode::InvalidRedirect,
                "{location:?}"
            );
        }
    });
}

/// CORE-CACHE-007: an accepted redirect makes the final URL a cache key of its own, so the
/// document is reachable under the advertised spelling and under the one it resolved to.
#[test]
fn an_accepted_redirect_is_cached_under_both_urls() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        transport.redirect(Some("/discovery/aep"));
        transport.document("did:web:service.example");
        let cache = Arc::new(RecordingCache::default());
        let session = agent(transport, cache.clone());
        let inspection = session.inspect().await.expect("inspection");
        assert_eq!(
            inspection.final_url.as_str(),
            "https://service.example/discovery/aep"
        );
        assert_eq!(
            cache.keys(),
            vec![
                INSPECT.to_owned(),
                "https://service.example/discovery/aep".to_owned(),
            ]
        );
    });
}

/// CORE-INS-025/026/030: the Service DID has to encode the origin the document was served from,
/// and a DID method without that binding is refused outright.
#[test]
fn the_service_did_must_bind_the_inspect_origin() {
    block_on(async {
        for service_did in [
            "did:example:service",
            "did:web:other.example",
            "did:web:service_example",
        ] {
            let transport = Arc::new(ScriptedTransport::default());
            transport.document(service_did);
            let session = agent(transport, Arc::new(RecordingCache::default()));
            assert_eq!(
                inspect_code(session.inspect().await.expect_err("identity mismatch")),
                InspectErrorCode::ServiceIdentityMismatch,
                "{service_did}"
            );
        }
    });
}

/// CORE-CACHE-005/006: `no-cache` revalidates, and a freshness value that is not a usable number
/// of seconds leaves the entry stale rather than being guessed at.
#[test]
fn unusable_freshness_metadata_leaves_the_entry_stale() {
    block_on(async {
        for cache_control in ["no-cache", "max-age=soon", "max-age=18446744073709551615"] {
            let transport = Arc::new(ScriptedTransport::default());
            transport.document("did:web:service.example");
            let cache = Arc::new(RecordingCache::default());
            cache.seed(INSPECT, entry(Some(cache_control), INSPECT));
            let session = agent(transport.clone(), cache);
            session.inspect().await.expect("inspection");
            assert_eq!(
                transport.requests.lock().expect("lock").len(),
                1,
                "{cache_control}"
            );
        }

        // A usable lifetime is honoured without a request.
        let transport = Arc::new(ScriptedTransport::default());
        let cache = Arc::new(RecordingCache::default());
        cache.seed(INSPECT, entry(Some("max-age=300"), INSPECT));
        let session = agent(transport.clone(), cache);
        session.inspect().await.expect("inspection");
        assert!(transport.requests.lock().expect("lock").is_empty());
    });
}

/// A revalidated entry is still checked against its Service DID, so a stored document whose
/// identity no longer binds the Inspect origin is refused rather than reused.
#[test]
fn a_revalidated_entry_is_still_identity_checked() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        transport.push(answer(
            StatusCode::NOT_MODIFIED,
            HeaderMap::new(),
            Vec::new(),
            None,
        ));
        let cache = Arc::new(RecordingCache::default());
        let mut stored = entry(Some("no-cache"), INSPECT);
        stored.document = parse_inspect_document(
            &serde_json::to_vec(&document("did:web:other.example")).expect("JSON"),
        )
        .expect("document");
        cache.seed(INSPECT, stored);
        let session = agent(transport, cache);
        assert_eq!(
            inspect_code(session.inspect().await.expect_err("identity mismatch")),
            InspectErrorCode::ServiceIdentityMismatch
        );
    });
}

#[tokio::test]
async fn real_http_inspection_honors_repeated_no_store_fields() {
    use std::{
        io::{BufRead as _, BufReader, Write as _},
        net::TcpListener,
        time::{Duration, Instant},
    };
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let address = listener.local_addr().expect("address");
    let service_did = format!("did:web:127.0.0.1%3A{}", address.port());
    let body = serde_json::to_string(&document(&service_did)).expect("JSON");
    let server = std::thread::spawn(move || {
        let started = Instant::now();
        let mut served = 0;
        while served < 2 && started.elapsed() < Duration::from_secs(2) {
            let (mut socket, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(error) => panic!("accept: {error}"),
            };
            socket
                .set_nonblocking(false)
                .expect("blocking request socket");
            socket
                .set_read_timeout(Some(Duration::from_secs(1)))
                .expect("read timeout");
            {
                let mut reader = BufReader::new(&mut socket);
                let mut first_line = String::new();
                reader.read_line(&mut first_line).expect("request");
                assert!(first_line.starts_with("GET /.well-known/aep HTTP/1.1"));
                loop {
                    let mut line = String::new();
                    assert!(reader.read_line(&mut line).expect("header") > 0);
                    if line == "\r\n" {
                        break;
                    }
                    assert!(!line.to_ascii_lowercase().starts_with("authorization:"));
                }
            }
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/aep+json\r\nCache-Control: max-age=300\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).expect("response");
            served += 1;
        }
        assert_eq!(served, 2, "no-store must cause a second network request");
    });
    let mut options = ClientOptions::new(Arc::new(StubIdentityProvider));
    options.allow_insecure_loopback = true;
    let session = Client::new(options)
        .expect("client")
        .service(&format!("http://{address}"))
        .expect("session");
    for _ in 0..2 {
        let inspection = session.inspect().await.expect("network Inspect");
        assert_eq!(
            inspection.cache_control.as_deref(),
            Some("max-age=300, no-store")
        );
    }
    server.join().expect("server thread");
}
