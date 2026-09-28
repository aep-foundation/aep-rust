//! Platform discovery transport and the refusals around delegated signing.

use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
};

use aep_agent::*;
use aep_core::*;
use async_trait::async_trait;
use futures::executor::block_on;
use http::{HeaderMap, HeaderValue, StatusCode, header};
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;

const PLATFORM: &str = "https://platform.example";
const AGENT_DID: &str = "did:web:platform.example:agents:one";
const SERVICE_DID: &str = "did:web:service.example";

fn now() -> OffsetDateTime {
    OffsetDateTime::parse("2026-08-31T12:00:00Z", &Rfc3339).expect("fixed time")
}

struct FixedClock(OffsetDateTime);

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
    final_url: Option<Url>,
}

#[derive(Default)]
struct ScriptedTransport {
    responses: Mutex<VecDeque<Answer>>,
}

impl ScriptedTransport {
    fn push(&self, answer: Answer) {
        self.responses.lock().expect("lock").push_back(answer);
    }

    fn json(&self, status: StatusCode, body: &Value) {
        self.typed(status, MEDIA_TYPE, serde_json::to_vec(body).expect("JSON"));
    }

    fn typed(&self, status: StatusCode, media_type: &'static str, body: Vec<u8>) {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(media_type));
        self.push(Answer {
            status,
            headers,
            body,
            final_url: None,
        });
    }

    fn redirect(&self, location: Option<&str>) {
        let mut headers = HeaderMap::new();
        if let Some(location) = location {
            headers.insert(
                header::LOCATION,
                HeaderValue::from_str(location).expect("location"),
            );
        }
        self.push(Answer {
            status: StatusCode::FOUND,
            headers,
            body: Vec::new(),
            final_url: None,
        });
    }

    fn discovery(&self, cache_control: Option<&'static str>) {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(MEDIA_TYPE));
        if let Some(value) = cache_control {
            headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(value));
        }
        self.push(Answer {
            status: StatusCode::OK,
            headers,
            body: serde_json::to_vec(&discovery_document()).expect("JSON"),
            final_url: None,
        });
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
        Ok(HttpResponse {
            status: response.status,
            final_url: response.final_url.unwrap_or(request.url),
            headers: response.headers,
            body: response.body,
        })
    }
}

fn discovery_document() -> Value {
    json!({
        "aep_version": "1.0",
        "endpoints": {
            "lifecycle": "/v1/aep/agent-identities/{agent_identity_id}",
            "list": "/v1/aep/agent-identities",
            "provision": "/v1/aep/agent-identities",
            "sign": "/v1/aep/agent-identities/{agent_identity_id}/sign"
        },
        "http": {"endpoint_base": "/v1/aep"},
        "identity": {
            "did_methods": ["did:web"],
            "did_url_template": "https://platform.example/agents/{agent_did_id}/did.json"
        },
        "platform": {"hosted_verification": false, "name": "Example Platform"},
        "signing": {"algorithms": ["ES256"], "default_lifetime_seconds": "300"}
    })
}

fn platform_identity() -> Value {
    json!({
        "agent_did": AGENT_DID,
        "agent_identity_id": "identity/one",
        "created_at": "2026-08-31T12:00:00Z",
        "did_document_url": "https://platform.example/agents/one/did.json",
        "key_id": AGENT_DID,
        "service_did": SERVICE_DID,
        "signing_algorithms": ["ES256"],
        "status": "active",
        "updated_at": "2026-08-31T12:00:00Z"
    })
}

fn identity() -> AgentIdentity {
    AgentIdentity {
        agent_did: AGENT_DID.to_owned(),
        identity_method: IdentityMethod::DidWeb,
        service_did: SERVICE_DID.to_owned(),
        signing_algorithms: vec![SigningAlgorithm::Es256],
        metadata: BTreeMap::from([
            ("agent_identity_id".to_owned(), "identity/one".to_owned()),
            ("platform_url".to_owned(), format!("{PLATFORM}/")),
            ("status".to_owned(), "active".to_owned()),
        ]),
    }
}

fn claims(operation: AssertionOperation, resource: Option<&str>) -> ClientAssertionClaims {
    ClientAssertionClaims {
        aud: SERVICE_DID.to_owned(),
        exp: 1_000_060,
        iat: 1_000_000,
        iss: AGENT_DID.to_owned(),
        jti: "assertion-one".to_owned(),
        op: operation,
        resource: resource.map(str::to_owned),
        sub: AGENT_DID.to_owned(),
        additional: Default::default(),
    }
}

fn provider(transport: Arc<ScriptedTransport>) -> Arc<PlatformIdentityProvider> {
    let mut options = PlatformIdentityProviderOptions::new(PLATFORM);
    options.clock = Some(Arc::new(FixedClock(now())));
    options.transport = Some(transport);
    PlatformIdentityProvider::new(options).expect("provider")
}

async fn discover(transport: Arc<ScriptedTransport>) -> Result<Option<AgentIdentity>, AgentError> {
    provider(transport)
        .find_identity_by_service_did(SERVICE_DID)
        .await
}

/// The Agent follows Platform discovery redirects itself and only within the bound it documents,
/// so a transport that followed one, an endless chain, or a target it cannot reach safely all
/// fail closed.
#[test]
fn unusable_discovery_redirects_are_refused() {
    block_on(async {
        // A transport that resolved the request somewhere else.
        let transport = Arc::new(ScriptedTransport::default());
        transport.push(Answer {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: Vec::new(),
            final_url: Some(Url::parse("https://platform.example/moved").expect("URL")),
        });
        assert!(matches!(
            discover(transport).await,
            Err(AgentError::Transport(_))
        ));

        // Six hops exceed the five the Agent will follow.
        let transport = Arc::new(ScriptedTransport::default());
        for index in 0..=5 {
            transport.redirect(Some(&format!("/hop-{index}")));
        }
        assert!(matches!(
            discover(transport).await,
            Err(AgentError::Transport(_))
        ));

        // A redirect naming no target, an unusable one, and one leaving the origin.
        for location in [
            None,
            Some("http://["),
            Some("https://elsewhere.example/aep"),
        ] {
            let transport = Arc::new(ScriptedTransport::default());
            transport.redirect(location);
            assert!(
                matches!(discover(transport).await, Err(AgentError::Transport(_))),
                "{location:?}"
            );
        }
    });
}

/// A same-origin redirect is followed, and the document it reaches is the one that is cached.
#[test]
fn a_safe_discovery_redirect_is_followed() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        transport.redirect(Some("/aep-platform"));
        transport.discovery(None);
        transport.json(
            StatusCode::OK,
            &json!({"count": "1", "data": [platform_identity()], "total": "1"}),
        );
        let identity = discover(transport)
            .await
            .expect("lookup")
            .expect("identity");
        assert_eq!(identity.agent_did, AGENT_DID);
    });
}

/// `no-store` discovery is used once and never reused, and an unusable freshness value leaves the
/// entry stale rather than being guessed at.
#[test]
fn discovery_caching_follows_the_response_metadata() {
    block_on(async {
        for cache_control in ["no-store", "max-age=18446744073709551615"] {
            let transport = Arc::new(ScriptedTransport::default());
            transport.discovery(Some(match cache_control {
                "no-store" => "no-store",
                _ => "max-age=18446744073709551615",
            }));
            transport.json(
                StatusCode::OK,
                &json!({"count": "0", "data": [], "total": "0"}),
            );
            transport.discovery(None);
            transport.json(
                StatusCode::OK,
                &json!({"count": "0", "data": [], "total": "0"}),
            );
            let provider = provider(transport);
            assert!(
                provider
                    .find_identity_by_service_did(SERVICE_DID)
                    .await
                    .expect("first lookup")
                    .is_none(),
                "{cache_control}"
            );
            // A second lookup has to fetch discovery again, which the script only allows because
            // the entry was not reusable.
            assert!(
                provider
                    .find_identity_by_service_did(SERVICE_DID)
                    .await
                    .expect("second lookup")
                    .is_none(),
                "{cache_control}"
            );
        }
    });
}

/// Discovery has to succeed, arrive under the AEP media type, and be a document the Agent can
/// use; a command answer has to be JSON.
#[test]
fn unusable_discovery_and_command_bodies_are_refused() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        transport.json(StatusCode::SERVICE_UNAVAILABLE, &json!({}));
        assert!(matches!(
            discover(transport).await,
            Err(AgentError::Transport(_))
        ));

        let transport = Arc::new(ScriptedTransport::default());
        transport.typed(StatusCode::OK, "text/plain", b"not a document".to_vec());
        assert!(matches!(
            discover(transport).await,
            Err(AgentError::Transport(_))
        ));

        let transport = Arc::new(ScriptedTransport::default());
        transport.typed(StatusCode::OK, MEDIA_TYPE, b"{".to_vec());
        assert!(matches!(
            discover(transport).await,
            Err(AgentError::Identity(_))
        ));

        let transport = Arc::new(ScriptedTransport::default());
        transport.discovery(None);
        transport.typed(StatusCode::OK, MEDIA_TYPE, b"{".to_vec());
        assert!(matches!(
            discover(transport).await,
            Err(AgentError::Identity(_))
        ));
    });
}

/// PLT-SIGN-022: a listed identity names a DID document URL that its own DID resolves to.
#[test]
fn listed_identities_must_resolve_to_their_did_document() {
    block_on(async {
        for (label, mutate) in [
            (
                "unresolvable DID",
                json!({"agent_did": "did:web:platform_example", "key_id": "did:web:platform_example"}),
            ),
            (
                "mismatched document URL",
                json!({"did_document_url": "https://platform.example/agents/two/did.json"}),
            ),
        ] {
            let mut identity = platform_identity();
            for (key, value) in mutate.as_object().expect("object") {
                identity[key] = value.clone();
            }
            let transport = Arc::new(ScriptedTransport::default());
            transport.discovery(None);
            transport.json(
                StatusCode::OK,
                &json!({"count": "1", "data": [identity], "total": "1"}),
            );
            assert!(discover(transport).await.is_err(), "{label}");
        }
    });
}

/// Only an active identity this Platform issued can be signed for.
#[test]
fn signing_requires_an_owned_active_identity() {
    block_on(async {
        let unusable = [
            AgentIdentity {
                metadata: BTreeMap::new(),
                ..identity()
            },
            AgentIdentity {
                metadata: BTreeMap::from([
                    ("agent_identity_id".to_owned(), "identity/one".to_owned()),
                    (
                        "platform_url".to_owned(),
                        "https://other.example/".to_owned(),
                    ),
                    ("status".to_owned(), "active".to_owned()),
                ]),
                ..identity()
            },
            AgentIdentity {
                metadata: BTreeMap::from([
                    ("agent_identity_id".to_owned(), "identity/one".to_owned()),
                    ("platform_url".to_owned(), format!("{PLATFORM}/")),
                    ("status".to_owned(), "revoked".to_owned()),
                ]),
                ..identity()
            },
        ];
        for identity in unusable {
            let provider = provider(Arc::new(ScriptedTransport::default()));
            assert!(
                matches!(
                    provider.signer_for(&identity).await,
                    Err(AgentError::Identity(_))
                ),
                "{identity:?}"
            );
        }
    });
}

/// The Sign request carries the assertion's own window and, for `authenticate`, its resource; a
/// window that cannot be expressed is refused before the request is made.
#[test]
fn sign_requests_carry_the_assertion_window_and_resource() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        transport.discovery(None);
        transport.json(
            StatusCode::OK,
            &json!({
                "agent_did": AGENT_DID,
                "client_assertion": "platform.assertion.value",
                "expires_at": "2026-08-31T12:01:00Z",
                "issued_at": "2026-08-31T12:00:00Z",
                "jti": "assertion-one",
                "service_did": SERVICE_DID,
                "status": "completed"
            }),
        );
        let signer = provider(transport)
            .signer_for(&identity())
            .await
            .expect("signer");
        let assertion = signer
            .sign(
                &claims(
                    AssertionOperation::Authenticate,
                    Some("https://service.example/orders"),
                ),
                &[SigningAlgorithm::Es256],
            )
            .await
            .expect("assertion");
        assert_eq!(assertion, "platform.assertion.value");

        let transport = Arc::new(ScriptedTransport::default());
        transport.discovery(None);
        let signer = provider(transport)
            .signer_for(&identity())
            .await
            .expect("signer");
        let mut unbounded = claims(AssertionOperation::Enroll, None);
        unbounded.iat = i64::MIN;
        unbounded.exp = i64::MAX;
        assert!(matches!(
            signer.sign(&unbounded, &[SigningAlgorithm::Es256]).await,
            Err(AgentError::Identity(_))
        ));
    });
}

/// A completed Sign response has to describe the same assertion that was requested.
#[test]
fn completed_sign_responses_must_match_the_request() {
    block_on(async {
        let complete = |body: Value| async move {
            let transport = Arc::new(ScriptedTransport::default());
            transport.discovery(None);
            transport.json(StatusCode::OK, &body);
            let signer = provider(transport)
                .signer_for(&identity())
                .await
                .expect("signer");
            signer
                .sign(
                    &claims(AssertionOperation::Enroll, None),
                    &[SigningAlgorithm::Es256],
                )
                .await
        };
        // No window at all, and a window of a different length than the one requested.
        for body in [
            json!({
                "agent_did": AGENT_DID,
                "client_assertion": "platform.assertion.value",
                "jti": "assertion-one",
                "service_did": SERVICE_DID,
                "status": "completed"
            }),
            json!({
                "agent_did": AGENT_DID,
                "client_assertion": "platform.assertion.value",
                "expires_at": "2026-08-31T12:05:00Z",
                "issued_at": "2026-08-31T12:00:00Z",
                "jti": "assertion-one",
                "service_did": SERVICE_DID,
                "status": "completed"
            }),
        ] {
            assert!(matches!(complete(body).await, Err(AgentError::Identity(_))));
        }
    });
}

/// Building a provider without a transport still yields a usable one, and the configuration is
/// checked before it is used.
#[test]
fn provider_construction_supplies_its_own_transport() {
    let options = PlatformIdentityProviderOptions::new(PLATFORM);
    assert!(PlatformIdentityProvider::new(options).is_ok());
    assert!(matches!(
        PlatformIdentityProvider::new(PlatformIdentityProviderOptions::new("http://[")),
        Err(AgentError::InvalidConfiguration(_))
    ));
}

#[test]
fn platform_transport_failures_reach_the_caller() {
    block_on(async {
        let error = discover(Arc::new(ScriptedTransport::default()))
            .await
            .expect_err("transport failure");
        assert!(
            matches!(error, AgentError::Transport(message) if message.contains("no scripted response"))
        );
    });
}

#[test]
fn platform_credentials_are_not_sent_to_origin_changing_or_unresolved_endpoints() {
    block_on(async {
        for endpoint in [
            "/\\elsewhere.example/identities",
            "/identities/{unexpected}",
        ] {
            let transport = Arc::new(ScriptedTransport::default());
            let mut document = discovery_document();
            document["endpoints"]["sign"] = json!(format!("{endpoint}/{{agent_identity_id}}/sign"));
            transport.json(StatusCode::OK, &document);
            let mut options = PlatformIdentityProviderOptions::new(PLATFORM);
            options.authorization = Some("Bearer platform-secret".to_owned());
            options.transport = Some(transport.clone());
            let provider = PlatformIdentityProvider::new(options).expect("provider");
            let signer = provider.signer_for(&identity()).await.expect("signer");
            let error = signer
                .sign(
                    &claims(AssertionOperation::Enroll, None),
                    &[SigningAlgorithm::Es256],
                )
                .await
                .expect_err("unsafe endpoint");
            assert!(matches!(error, AgentError::Identity(_)), "{error}");
            assert!(transport.responses.lock().expect("responses").is_empty());
        }
    });
}

/// A `304` is only usable against a stored discovery document, and a stored `Last-Modified` is
/// offered back when one is available.
#[test]
fn discovery_revalidation_needs_a_stored_document() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        transport.push(Answer {
            status: StatusCode::NOT_MODIFIED,
            headers: HeaderMap::new(),
            body: Vec::new(),
            final_url: None,
        });
        assert!(matches!(
            discover(transport).await,
            Err(AgentError::Transport(_))
        ));

        let transport = Arc::new(ScriptedTransport::default());
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(MEDIA_TYPE));
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        headers.insert(header::ETAG, HeaderValue::from_static("\"one\""));
        headers.insert(
            header::LAST_MODIFIED,
            HeaderValue::from_static("Mon, 31 Aug 2026 11:00:00 GMT"),
        );
        transport.push(Answer {
            status: StatusCode::OK,
            headers,
            body: serde_json::to_vec(&discovery_document()).expect("JSON"),
            final_url: None,
        });
        transport.json(
            StatusCode::OK,
            &json!({"count": "0", "data": [], "total": "0"}),
        );
        let mut revalidated = HeaderMap::new();
        revalidated.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        transport.push(Answer {
            status: StatusCode::NOT_MODIFIED,
            headers: revalidated,
            body: Vec::new(),
            final_url: None,
        });
        transport.json(
            StatusCode::OK,
            &json!({"count": "0", "data": [], "total": "0"}),
        );
        let provider = provider(transport);
        for _ in 0..2 {
            assert!(
                provider
                    .find_identity_by_service_did(SERVICE_DID)
                    .await
                    .expect("lookup")
                    .is_none()
            );
        }
    });
}
