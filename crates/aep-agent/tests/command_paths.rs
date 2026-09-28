//! Command dispatch, credential selection, and the refusals that guard both.

use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
    time::Duration,
};

use aep_agent::*;
use aep_core::*;
use async_trait::async_trait;
use futures::executor::block_on;
use http::{HeaderMap, HeaderValue, StatusCode, header};
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;

const SERVICE: &str = "https://service.example/";
const SERVICE_DID: &str = "did:web:service.example";
const AGENT_DID: &str = "did:web:agent.example:agents:one";

fn now() -> OffsetDateTime {
    OffsetDateTime::parse("2026-08-31T12:00:00Z", &Rfc3339).expect("fixed time")
}

struct FixedClock(OffsetDateTime);

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

struct ImmediateDelay;

#[async_trait]
impl Delay for ImmediateDelay {
    async fn sleep(&self, _duration: Duration) {}
}

struct FixedSigner(String);

#[async_trait]
impl AssertionSigner for FixedSigner {
    async fn sign(
        &self,
        _claims: &ClientAssertionClaims,
        _algorithms: &[SigningAlgorithm],
    ) -> Result<String, AgentError> {
        Ok(self.0.clone())
    }
}

struct FixedProvider {
    identity: AgentIdentity,
    assertion: String,
}

#[async_trait]
impl IdentityProvider for FixedProvider {
    async fn get_or_create_identity(
        &self,
        _request: IdentityRequest,
    ) -> Result<AgentIdentity, AgentError> {
        Ok(self.identity.clone())
    }

    async fn signer_for(
        &self,
        _identity: &AgentIdentity,
    ) -> Result<Arc<dyn AssertionSigner>, AgentError> {
        Ok(Arc::new(FixedSigner(self.assertion.clone())))
    }
}

fn identity() -> AgentIdentity {
    AgentIdentity {
        agent_did: AGENT_DID.to_owned(),
        identity_method: IdentityMethod::DidWeb,
        service_did: SERVICE_DID.to_owned(),
        signing_algorithms: vec![SigningAlgorithm::EdDsa, SigningAlgorithm::Es256],
        metadata: BTreeMap::new(),
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
    requests: Mutex<Vec<HttpRequest>>,
}

impl ScriptedTransport {
    fn push(&self, status: StatusCode, media_type: &'static str, body: Vec<u8>) {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(media_type));
        self.responses.lock().expect("lock").push_back(Answer {
            status,
            headers,
            body,
            final_url: None,
        });
    }

    fn json(&self, status: StatusCode, body: &Value) {
        self.push(status, MEDIA_TYPE, serde_json::to_vec(body).expect("JSON"));
    }

    fn inspect(&self, document: &Value) {
        self.json(StatusCode::OK, document);
    }

    fn elsewhere(&self, body: &Value) {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(MEDIA_TYPE));
        self.responses.lock().expect("lock").push_back(Answer {
            status: StatusCode::OK,
            headers,
            body: serde_json::to_vec(body).expect("JSON"),
            final_url: Some(Url::parse("https://service.example/moved").expect("URL")),
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
        self.requests.lock().expect("lock").push(request.clone());
        Ok(HttpResponse {
            status: response.status,
            final_url: response.final_url.unwrap_or(request.url),
            headers: response.headers,
            body: response.body,
        })
    }
}

struct Options {
    assertion: String,
    identity: AgentIdentity,
    maximum_response_bytes: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            assertion: "signed.assertion.value".to_owned(),
            identity: identity(),
            maximum_response_bytes: 1 << 20,
        }
    }
}

fn agent_with(transport: Arc<ScriptedTransport>, settings: Options) -> Session {
    let mut options = ClientOptions::new(Arc::new(FixedProvider {
        assertion: settings.assertion,
        identity: settings.identity,
    }));
    options.clock = Some(Arc::new(FixedClock(now())));
    options.delay = Some(Arc::new(ImmediateDelay));
    options.maximum_response_bytes = settings.maximum_response_bytes;
    options.command_transport = Some(transport.clone());
    options.inspect_transport = Some(transport);
    Client::new(options)
        .expect("client")
        .service(SERVICE)
        .expect("session")
}

fn agent(transport: Arc<ScriptedTransport>) -> Session {
    agent_with(transport, Options::default())
}

/// Grant never creates an identity, so a session that will call it resolves one first. The Inspect
/// document is cached, so this costs one scripted response.
async fn enrolled(transport: Arc<ScriptedTransport>) -> Session {
    let session = agent(transport);
    session.identity().await.expect("identity");
    session
}

fn document() -> Value {
    json!({
        "aep_version": "1.0",
        "authentication": {"methods": ["api-key", "oauth-bearer", "aep-jwt"]},
        "bindings": {"supported": ["http"]},
        "commands": {
            "supported": ["inspect", "enroll", "grant", "revoke", "status"],
            "grant_types": ["api-key", "oauth-bearer"],
            "grant_types_config": {"api-key": {"supports_per_credential_revoke": "true"}}
        },
        "core": {"signing_algorithms": ["EdDSA", "ES256"]},
        "http": {"endpoint_base": "/aep/"},
        "identity": {"methods": ["did:web"]},
        "service": {"did": SERVICE_DID}
    })
}

fn active() -> Value {
    json!({"status": "active", "since": "2026-08-31T11:00:00Z"})
}

fn api_key_credential() -> Value {
    json!({
        "api_key": "opaque-api-key",
        "credential_id": "credential-one",
        "expires_at": "2026-08-31T13:00:00Z",
        "header": "x-api-key"
    })
}

// --- identity validation -------------------------------------------------------------------

/// An identity provider answers for one Service with one usable method and algorithm; anything
/// else is refused before an assertion is signed.
#[test]
fn identities_are_checked_against_the_inspect_document() {
    let unusable = [
        AgentIdentity {
            agent_did: "agent.example".to_owned(),
            ..identity()
        },
        AgentIdentity {
            service_did: "did:web:other.example".to_owned(),
            ..identity()
        },
        AgentIdentity {
            signing_algorithms: Vec::new(),
            ..identity()
        },
        AgentIdentity {
            agent_did: "did:key:z6Mk".to_owned(),
            ..identity()
        },
        AgentIdentity {
            identity_method: IdentityMethod::from("platform"),
            ..identity()
        },
        AgentIdentity {
            signing_algorithms: vec![SigningAlgorithm::from("RS256")],
            ..identity()
        },
    ];
    for identity in unusable {
        block_on(async {
            let transport = Arc::new(ScriptedTransport::default());
            transport.inspect(&document());
            let session = agent_with(
                transport,
                Options {
                    identity: identity.clone(),
                    ..Options::default()
                },
            );
            assert!(
                matches!(session.identity().await, Err(AgentError::Identity(_))),
                "{identity:?}"
            );
        });
    }
}

/// A Service that does not advertise the Agent's identity method cannot enrol it.
#[test]
fn an_unadvertised_identity_method_is_refused() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        let mut restricted = document();
        restricted["identity"]["methods"] = json!(["platform"]);
        transport.inspect(&restricted);
        let session = agent(transport);
        assert!(matches!(
            session.identity().await,
            Err(AgentError::Identity(_))
        ));
    });
}

// --- command transport ---------------------------------------------------------------------

/// A command answer has to come from the URL the command was sent to, stay inside the configured
/// bound, and arrive under the AEP media type.
#[test]
fn command_answers_are_checked_before_they_are_parsed() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        transport.inspect(&document());
        transport.elsewhere(&active());
        assert!(matches!(
            agent(transport).status().await,
            Err(AgentError::Transport(_))
        ));

        let transport = Arc::new(ScriptedTransport::default());
        transport.inspect(&document());
        transport.json(
            StatusCode::OK,
            &json!({"status": "active", "pad": "x".repeat(4096)}),
        );
        let session = agent_with(
            transport,
            Options {
                maximum_response_bytes: 2048,
                ..Options::default()
            },
        );
        assert!(matches!(
            session.status().await,
            Err(AgentError::Transport(_))
        ));

        let transport = Arc::new(ScriptedTransport::default());
        transport.inspect(&document());
        transport.push(
            StatusCode::OK,
            "text/plain",
            serde_json::to_vec(&active()).expect("JSON"),
        );
        assert!(matches!(
            agent(transport).status().await,
            Err(AgentError::Transport(_))
        ));
    });
}

/// Values that cannot be rendered into a field are refused rather than truncated onto the wire.
#[test]
fn unusable_field_values_are_refused() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        transport.inspect(&document());
        let session = agent_with(
            transport,
            Options {
                assertion: "signed.\nassertion".to_owned(),
                ..Options::default()
            },
        );
        assert!(matches!(
            session.status().await,
            Err(AgentError::Identity(_))
        ));

        let transport = Arc::new(ScriptedTransport::default());
        transport.inspect(&document());
        let session = agent(transport);
        assert!(matches!(
            session
                .enroll(EnrollOptions {
                    claims: None,
                    idempotency_key: Some("key\nwith-break".to_owned()),
                })
                .await,
            Err(AgentError::InvalidConfiguration(_))
        ));
    });
}

/// CORE-IDP-003: an empty idempotency key is the same as no key, whether it is supplied or
/// generated, and whitespace renders as empty on the wire.
#[test]
fn empty_idempotency_keys_are_refused() {
    block_on(async {
        for key in ["", "   "] {
            let transport = Arc::new(ScriptedTransport::default());
            transport.inspect(&document());
            let session = agent(transport);
            assert!(
                matches!(
                    session
                        .enroll(EnrollOptions {
                            claims: None,
                            idempotency_key: Some(key.to_owned()),
                        })
                        .await,
                    Err(AgentError::InvalidConfiguration(_))
                ),
                "{key:?}"
            );
        }
    });
}

// --- grant ---------------------------------------------------------------------------------

/// CORE-GRT-004/005: Grant names an advertised grant type, needs Status to confirm enrolment, and
/// never enrols implicitly.
#[test]
fn grant_requires_an_advertised_type_and_an_active_enrolment() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        transport.inspect(&document());
        assert!(matches!(
            enrolled(transport)
                .await
                .grant(GrantOptions {
                    grant_type: Some(GrantType::from("vendor-token")),
                    ..GrantOptions::default()
                })
                .await,
            Err(AgentError::NoCompatibleGrantType)
        ));

        // A preference list still only selects from what the Service advertises.
        let transport = Arc::new(ScriptedTransport::default());
        transport.inspect(&document());
        assert!(matches!(
            enrolled(transport)
                .await
                .grant(GrantOptions {
                    preferred_grant_types: vec![GrantType::from("vendor-token")],
                    ..GrantOptions::default()
                })
                .await,
            Err(AgentError::NoCompatibleGrantType)
        ));

        let transport = Arc::new(ScriptedTransport::default());
        let mut reduced = document();
        reduced["commands"]["supported"] = json!(["inspect", "grant"]);
        transport.inspect(&reduced);
        assert!(matches!(
            enrolled(transport)
                .await
                .grant(GrantOptions::default())
                .await,
            Err(AgentError::CommandNotAdvertised(_))
        ));

        let transport = Arc::new(ScriptedTransport::default());
        transport.inspect(&document());
        transport.json(
            StatusCode::OK,
            &json!({"status": "pending", "since": "2026-08-31T11:00:00Z"}),
        );
        let error = enrolled(transport)
            .await
            .grant(GrantOptions::default())
            .await
            .expect_err("inactive enrolment");
        let AgentError::Command {
            status,
            problem: Some(problem),
        } = error
        else {
            panic!("expected a command failure carrying a problem document");
        };
        assert_eq!(status, 401);
        assert_eq!(problem.code, ErrorCode::NotRecognized);
        assert_eq!(problem.status, 401);
    });
}

/// A Grant answer that is not a credential document leaves nothing stored.
#[test]
fn unusable_grant_answers_are_refused() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        transport.inspect(&document());
        transport.json(StatusCode::OK, &active());
        transport.json(StatusCode::OK, &json!(["not", "an", "object"]));
        assert!(matches!(
            enrolled(transport)
                .await
                .grant(GrantOptions::default())
                .await,
            Err(AgentError::Credential(_))
        ));

        let transport = Arc::new(ScriptedTransport::default());
        transport.inspect(&document());
        transport.json(StatusCode::OK, &active());
        let mut credential = api_key_credential();
        credential["expires_at"] = json!("2026-08-31T13:00:00Z");
        transport.json(StatusCode::OK, &credential);
        let result = enrolled(transport)
            .await
            .grant(GrantOptions {
                grant_type: Some(GrantType::ApiKey),
                ..GrantOptions::default()
            })
            .await
            .expect("granted");
        assert_eq!(result.body.grant_type, GrantType::ApiKey);
    });
}

#[test]
fn extension_grants_require_an_opaque_nonempty_credential_identifier() {
    block_on(async {
        for credential_id in [
            None,
            Some(json!(null)),
            Some(json!(17)),
            Some(json!("")),
            Some(json!("opaque/id")),
        ] {
            let transport = Arc::new(ScriptedTransport::default());
            let mut advertised = document();
            advertised["commands"]["grant_types"] = json!(["vendor-token"]);
            advertised["commands"]["grant_types_config"] = json!({});
            transport.inspect(&advertised);
            transport.json(StatusCode::OK, &active());
            let mut body = json!({"secret": "extension-defined"});
            if let Some(value) = credential_id.clone() {
                body["credential_id"] = value;
            }
            transport.json(StatusCode::OK, &body);
            let session = enrolled(transport.clone()).await;
            let result = session.grant(GrantOptions::default()).await;
            if credential_id == Some(json!("opaque/id")) {
                let granted = result.expect("extension credential");
                assert_eq!(granted.body.raw, body);
                assert!(granted.body.credential.is_none());
            } else {
                assert!(
                    matches!(result, Err(AgentError::Credential(_))),
                    "{credential_id:?}"
                );
            }
            let requests = transport.requests.lock().expect("lock");
            assert_eq!(requests.len(), 3);
            assert_eq!(requests[1].url.path(), "/aep/status");
            assert_eq!(requests[2].url.path(), "/aep/grant");
        }
    });
}

#[test]
fn an_unusable_oauth_token_is_not_presented_or_silently_replaced() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        transport.inspect(&document());
        transport.json(StatusCode::OK, &active());
        transport.json(
            StatusCode::OK,
            &json!({
                "access_token": "bad token", "credential_id": "oauth-one",
                "expires_at": "2026-08-31T13:00:00Z", "token_type": "Bearer"
            }),
        );
        let session = enrolled(transport.clone()).await;
        session
            .grant(GrantOptions {
                grant_type: Some(GrantType::OAuthBearer),
                ..GrantOptions::default()
            })
            .await
            .expect("grant response");
        assert!(matches!(
            session
                .authentication(AuthenticationOptions {
                    carrier: AuthorizationCarrier::Standard,
                    client_assertion_only: false,
                    credential_id: Some("oauth-one".to_owned()),
                    grant_type: None,
                    resource: Url::parse("https://service.example/orders").expect("resource"),
                })
                .await,
            Err(AgentError::Credential(_))
        ));
        assert_eq!(transport.requests.lock().expect("requests").len(), 3);
    });
}

// --- revoke --------------------------------------------------------------------------------

/// CORE-RVK-002/004: Revoke names an advertised grant type, and the targeted form is sent only
/// where the Service advertises per-credential Revoke.
#[test]
fn revoke_selectors_follow_the_advertisement() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        transport.inspect(&document());
        assert!(matches!(
            agent(transport)
                .revoke(RevokeOptions {
                    grant_type: Some(GrantType::from("vendor-token")),
                    ..RevokeOptions::default()
                })
                .await,
            Err(AgentError::NoCompatibleGrantType)
        ));

        let transport = Arc::new(ScriptedTransport::default());
        transport.inspect(&document());
        assert!(matches!(
            agent(transport)
                .revoke(RevokeOptions {
                    credential_id: Some("credential-one".to_owned()),
                    grant_type: Some(GrantType::OAuthBearer),
                    ..RevokeOptions::default()
                })
                .await,
            Err(AgentError::Credential(_))
        ));

        assert!(matches!(
            agent(Arc::new(ScriptedTransport::default()))
                .revoke(RevokeOptions {
                    all_grant_types: true,
                    grant_type: Some(GrantType::ApiKey),
                    ..RevokeOptions::default()
                })
                .await,
            Err(AgentError::InvalidConfiguration(_))
        ));
    });
}

/// Revoking every grant type clears the stored credentials for that Service.
#[test]
fn revoking_all_grant_types_clears_the_store() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        transport.inspect(&document());
        transport.json(StatusCode::OK, &active());
        transport.json(StatusCode::OK, &api_key_credential());
        transport.json(StatusCode::OK, &json!({}));
        let session = enrolled(transport).await;
        session
            .grant(GrantOptions {
                grant_type: Some(GrantType::ApiKey),
                ..GrantOptions::default()
            })
            .await
            .expect("granted");
        session
            .revoke(RevokeOptions {
                all_grant_types: true,
                ..RevokeOptions::default()
            })
            .await
            .expect("revoked");
        assert!(matches!(
            session
                .authentication(AuthenticationOptions {
                    carrier: AuthorizationCarrier::Standard,
                    client_assertion_only: false,
                    credential_id: Some("credential-one".to_owned()),
                    grant_type: None,
                    resource: Url::parse("https://service.example/orders").expect("URL"),
                })
                .await,
            Err(AgentError::Credential(_))
        ));
    });
}

// --- status polling ------------------------------------------------------------------------

/// A polling window that cannot be expressed as an elapsed time is a configuration error.
#[test]
fn polling_windows_must_be_expressible() {
    block_on(async {
        for options in [
            WaitOptions {
                interval: Duration::ZERO,
                timeout: Duration::from_secs(1),
            },
            WaitOptions {
                interval: Duration::from_secs(1),
                timeout: Duration::ZERO,
            },
        ] {
            let transport = Arc::new(ScriptedTransport::default());
            assert!(matches!(
                agent(transport).wait_for_active(options).await,
                Err(AgentError::InvalidConfiguration(_))
            ));
        }

        let transport = Arc::new(ScriptedTransport::default());
        transport.inspect(&document());
        transport.json(
            StatusCode::OK,
            &json!({"status": "pending", "since": "2026-08-31T11:00:00Z"}),
        );
        assert!(matches!(
            agent(transport)
                .wait_for_active(WaitOptions {
                    interval: Duration::from_secs(1),
                    timeout: Duration::MAX,
                })
                .await,
            Err(AgentError::InvalidConfiguration(_))
        ));
    });
}

/// A clock that does not advance while the delay sleeps still stops at the polling bound instead
/// of asking forever.
#[test]
fn polling_stops_when_the_clock_does_not_advance() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        transport.inspect(&document());
        for _ in 0..4 {
            transport.json(
                StatusCode::OK,
                &json!({"status": "pending", "since": "2026-08-31T11:00:00Z"}),
            );
        }
        assert!(matches!(
            agent(transport)
                .wait_for_active(WaitOptions {
                    interval: Duration::from_secs(1),
                    timeout: Duration::from_secs(3),
                })
                .await,
            Err(AgentError::PollingTimeout)
        ));
    });
}

// --- credential selection --------------------------------------------------------------------

/// A stored credential is only presented for a method the Service advertises, under the grant
/// type it was issued for, and while its metadata still agrees with its payload.
#[test]
fn stored_credentials_are_checked_before_they_are_presented() {
    block_on(async {
        let resource = Url::parse("https://service.example/orders").expect("URL");
        let selection =
            |credential_id: Option<&str>, grant_type: Option<GrantType>| AuthenticationOptions {
                carrier: AuthorizationCarrier::Standard,
                client_assertion_only: false,
                credential_id: credential_id.map(str::to_owned),
                grant_type,
                resource: resource.clone(),
            };

        // An unadvertised grant type is refused before any credential is looked up.
        let transport = Arc::new(ScriptedTransport::default());
        transport.inspect(&document());
        assert!(matches!(
            agent(transport)
                .authentication(selection(None, Some(GrantType::from("vendor-token"))))
                .await,
            Err(AgentError::NoAuthenticationMethod)
        ));

        // A named credential that was never issued is not silently replaced by an assertion.
        let transport = Arc::new(ScriptedTransport::default());
        transport.inspect(&document());
        assert!(matches!(
            agent(transport)
                .authentication(selection(Some("credential-missing"), None))
                .await,
            Err(AgentError::Credential(_))
        ));

        // A stored credential answers only to its own grant type.
        let transport = Arc::new(ScriptedTransport::default());
        transport.inspect(&document());
        transport.json(StatusCode::OK, &active());
        transport.json(StatusCode::OK, &api_key_credential());
        let session = enrolled(transport).await;
        session
            .grant(GrantOptions {
                grant_type: Some(GrantType::ApiKey),
                ..GrantOptions::default()
            })
            .await
            .expect("granted");
        assert!(matches!(
            session
                .authentication(selection(
                    Some("credential-one"),
                    Some(GrantType::OAuthBearer)
                ))
                .await,
            Err(AgentError::Credential(_))
        ));

        // The issued credential is presented in exactly the header the Service selected.
        let result = session
            .authentication(selection(Some("credential-one"), None))
            .await
            .expect("api key");
        assert_eq!(result.method, AuthenticationMethod::ApiKey);
        assert_eq!(
            result
                .headers
                .get("x-api-key")
                .map(|value| value.to_str().expect("value")),
            Some("opaque-api-key")
        );
        let result = session
            .authentication(selection(None, Some(GrantType::ApiKey)))
            .await
            .expect("selected grant type");
        assert_eq!(result.method, AuthenticationMethod::ApiKey);

        // Forgetting it removes it.
        session
            .forget_credential("credential-one")
            .await
            .expect("forgotten");
        assert!(matches!(
            session
                .authentication(selection(Some("credential-one"), None))
                .await,
            Err(AgentError::Credential(_))
        ));
        assert!(matches!(
            session.forget_credential("").await,
            Err(AgentError::Credential(_))
        ));
    });
}

/// CORE-PR: the protected resource shares the Service origin and is reached over HTTPS.
#[test]
fn protected_resource_urls_are_checked_first() {
    block_on(async {
        for resource in [
            "https://user@service.example/orders",
            "https://service.example/orders#section",
            "http://service.example/orders",
            "https://other.example/orders",
        ] {
            let transport = Arc::new(ScriptedTransport::default());
            assert!(
                matches!(
                    agent(transport)
                        .authentication(AuthenticationOptions {
                            carrier: AuthorizationCarrier::Standard,
                            client_assertion_only: false,
                            credential_id: None,
                            grant_type: None,
                            resource: Url::parse(resource).expect("URL"),
                        })
                        .await,
                    Err(AgentError::InvalidServiceReference(_))
                ),
                "{resource}"
            );
        }
    });
}

/// Client-assertion-only authentication names no credential, and a Service advertising no method
/// is not assumed to accept one.
#[test]
fn client_assertion_only_authentication_is_exclusive() {
    block_on(async {
        let resource = Url::parse("https://service.example/orders").expect("URL");
        let transport = Arc::new(ScriptedTransport::default());
        assert!(matches!(
            agent(transport)
                .authentication(AuthenticationOptions {
                    carrier: AuthorizationCarrier::Dedicated,
                    client_assertion_only: true,
                    credential_id: Some("credential-one".to_owned()),
                    grant_type: None,
                    resource: resource.clone(),
                })
                .await,
            Err(AgentError::InvalidConfiguration(_))
        ));

        let transport = Arc::new(ScriptedTransport::default());
        let mut anonymous = document();
        anonymous
            .as_object_mut()
            .expect("object")
            .remove("authentication");
        transport.inspect(&anonymous);
        assert!(matches!(
            agent(transport)
                .authentication(AuthenticationOptions {
                    carrier: AuthorizationCarrier::Standard,
                    client_assertion_only: true,
                    credential_id: None,
                    grant_type: None,
                    resource: resource.clone(),
                })
                .await,
            Err(AgentError::NoAuthenticationMethod)
        ));

        let transport = Arc::new(ScriptedTransport::default());
        transport.inspect(&document());
        let result = agent(transport)
            .authentication(AuthenticationOptions {
                carrier: AuthorizationCarrier::Dedicated,
                client_assertion_only: true,
                credential_id: None,
                grant_type: None,
                resource,
            })
            .await
            .expect("assertion");
        assert_eq!(result.method, AuthenticationMethod::AepJwt);
        assert!(result.headers.contains_key("aep-authorization"));
    });
}

// --- client configuration --------------------------------------------------------------------

struct EmptyKeys;

#[async_trait]
impl IdempotencyKeyProvider for EmptyKeys {
    async fn create_key(&self, _operation: &OperationKey) -> Result<String, AgentError> {
        Ok("  ".to_owned())
    }
}

/// A client with no transport of its own builds one, and a `did:web` reference resolves to the
/// origin that DID encodes.
#[test]
fn clients_supply_a_transport_and_resolve_did_references() {
    let client = Client::new(ClientOptions::new(Arc::new(FixedProvider {
        assertion: "signed.assertion.value".to_owned(),
        identity: identity(),
    })))
    .expect("client");
    assert_eq!(
        client
            .service(SERVICE_DID)
            .expect("session")
            .service_url()
            .as_str(),
        SERVICE
    );
}

/// An assertion signer that returns nothing has not signed anything.
#[test]
fn an_empty_assertion_is_refused() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        transport.inspect(&document());
        let session = agent_with(
            transport,
            Options {
                assertion: String::new(),
                ..Options::default()
            },
        );
        assert!(matches!(
            session.status().await,
            Err(AgentError::Identity(_))
        ));
    });
}

#[test]
fn transport_and_assertion_presentation_errors_reach_the_caller() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        transport.inspect(&document());
        let error = agent(transport)
            .status()
            .await
            .expect_err("transport failure");
        assert!(
            matches!(error, AgentError::Transport(message) if message.contains("no scripted response"))
        );
        let transport = Arc::new(ScriptedTransport::default());
        transport.inspect(&document());
        let session = agent_with(
            transport,
            Options {
                assertion: "bad\nassertion".to_owned(),
                ..Options::default()
            },
        );
        assert!(matches!(
            session
                .authentication(AuthenticationOptions {
                    carrier: AuthorizationCarrier::Dedicated,
                    client_assertion_only: true,
                    credential_id: None,
                    grant_type: None,
                    resource: Url::parse("https://service.example/orders").expect("resource"),
                })
                .await,
            Err(AgentError::Credential(_))
        ));
    });
}

/// A key provider that answers with nothing usable stops the command.
#[test]
fn a_generated_key_has_to_be_usable() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        transport.inspect(&document());
        let mut options = ClientOptions::new(Arc::new(FixedProvider {
            assertion: "signed.assertion.value".to_owned(),
            identity: identity(),
        }));
        options.clock = Some(Arc::new(FixedClock(now())));
        options.idempotency_keys = Some(Arc::new(EmptyKeys));
        options.command_transport = Some(transport.clone());
        options.inspect_transport = Some(transport);
        let session = Client::new(options)
            .expect("client")
            .service(SERVICE)
            .expect("session");
        assert!(matches!(
            session.enroll(EnrollOptions::default()).await,
            Err(AgentError::InvalidConfiguration(_))
        ));
    });
}

// --- credential bookkeeping --------------------------------------------------------------------

/// Revoking one grant type leaves credentials of the other grant types in place.
#[test]
fn revoking_one_grant_type_spares_the_others() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        transport.inspect(&document());
        transport.json(StatusCode::OK, &active());
        transport.json(StatusCode::OK, &api_key_credential());
        transport.json(StatusCode::OK, &active());
        transport.json(
            StatusCode::OK,
            &json!({
                "access_token": "opaque-token",
                "credential_id": "credential-two",
                "expires_at": "2026-08-31T13:00:00Z",
                "token_type": "Bearer"
            }),
        );
        transport.json(StatusCode::OK, &json!({}));
        let session = enrolled(transport).await;
        for grant_type in [GrantType::ApiKey, GrantType::OAuthBearer] {
            session
                .grant(GrantOptions {
                    grant_type: Some(grant_type),
                    ..GrantOptions::default()
                })
                .await
                .expect("granted");
        }
        session
            .revoke(RevokeOptions {
                grant_type: Some(GrantType::ApiKey),
                ..RevokeOptions::default()
            })
            .await
            .expect("revoked");

        let selection = |credential_id: &str| AuthenticationOptions {
            carrier: AuthorizationCarrier::Standard,
            client_assertion_only: false,
            credential_id: Some(credential_id.to_owned()),
            grant_type: None,
            resource: Url::parse("https://service.example/orders").expect("URL"),
        };
        assert!(matches!(
            session.authentication(selection("credential-one")).await,
            Err(AgentError::Credential(_))
        ));
        let result = session
            .authentication(selection("credential-two"))
            .await
            .expect("bearer");
        assert_eq!(result.method, AuthenticationMethod::OAuthBearer);
    });
}

/// A credential is presented only for a grant type the Service also accepts at the protected
/// resource, which is a separate advertisement from the grant types it issues.
#[test]
fn an_issued_credential_still_needs_an_advertised_method() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        let mut narrowed = document();
        narrowed["authentication"]["methods"] = json!(["oauth-bearer", "aep-jwt"]);
        transport.inspect(&narrowed);
        transport.json(StatusCode::OK, &active());
        transport.json(StatusCode::OK, &api_key_credential());
        let session = enrolled(transport).await;
        session
            .grant(GrantOptions {
                grant_type: Some(GrantType::ApiKey),
                ..GrantOptions::default()
            })
            .await
            .expect("granted");
        assert!(matches!(
            session
                .authentication(AuthenticationOptions {
                    carrier: AuthorizationCarrier::Standard,
                    client_assertion_only: false,
                    credential_id: Some("credential-one".to_owned()),
                    grant_type: None,
                    resource: Url::parse("https://service.example/orders").expect("URL"),
                })
                .await,
            Err(AgentError::NoAuthenticationMethod)
        ));
    });
}

/// A stored record has to agree with the credential document it carries, so a store cannot hand
/// back metadata that was edited underneath the payload.
#[test]
fn stored_records_must_agree_with_their_payload() {
    block_on(async {
        let store = MemoryCredentialStore::new(Arc::new(FixedClock(now())));
        let record = |credential_id: &str, expires_at: OffsetDateTime| CredentialRecord {
            credential_id: credential_id.to_owned(),
            expires_at,
            grant_type: GrantType::ApiKey,
            issued_at: now(),
            payload: api_key_credential(),
            service_did: SERVICE_DID.to_owned(),
            service_url: Url::parse(SERVICE).expect("URL"),
        };
        let expires_at = OffsetDateTime::parse("2026-08-31T13:00:00Z", &Rfc3339).expect("time");
        assert!(
            store
                .save(record("credential-one", expires_at))
                .await
                .is_ok()
        );
        // An empty identifier, an expiry in the past, and metadata the payload does not carry.
        assert!(store.save(record("", expires_at)).await.is_err());
        assert!(
            store
                .save(record("credential-one", now() - time::Duration::seconds(1)))
                .await
                .is_err()
        );
        assert!(
            store
                .save(record("credential-other", expires_at))
                .await
                .is_err()
        );
    });
}

/// A `did:web` reference that names no resolvable origin is not a Service reference.
#[test]
fn unresolvable_did_references_are_refused() {
    let client = Client::new(ClientOptions::new(Arc::new(FixedProvider {
        assertion: "signed.assertion.value".to_owned(),
        identity: identity(),
    })))
    .expect("client");
    for reference in ["did:web:service_example", "did:web:", "   "] {
        assert!(client.service(reference).is_err(), "{reference}");
    }
}

/// Every built-in credential document yields a record the store will accept.
#[test]
fn basic_credentials_are_stored_like_the_others() {
    block_on(async {
        let transport = Arc::new(ScriptedTransport::default());
        let mut widened = document();
        widened["commands"]["grant_types"] = json!(["api-key", "oauth-bearer", "basic"]);
        widened["authentication"]["methods"] = json!(["basic", "aep-jwt"]);
        transport.inspect(&widened);
        transport.json(StatusCode::OK, &active());
        transport.json(
            StatusCode::OK,
            &json!({
                "credential_id": "credential-three",
                "expires_at": "2026-08-31T13:00:00Z",
                "password": "secret",
                "username": "agent"
            }),
        );
        let session = enrolled(transport).await;
        session
            .grant(GrantOptions {
                grant_type: Some(GrantType::Basic),
                ..GrantOptions::default()
            })
            .await
            .expect("granted");
        let result = session
            .authentication(AuthenticationOptions {
                carrier: AuthorizationCarrier::Standard,
                client_assertion_only: false,
                credential_id: Some("credential-three".to_owned()),
                grant_type: None,
                resource: Url::parse("https://service.example/orders").expect("URL"),
            })
            .await
            .expect("basic");
        assert_eq!(result.method, AuthenticationMethod::Basic);
        assert_eq!(
            result
                .headers
                .get(header::AUTHORIZATION)
                .map(|value| value.to_str().expect("value")),
            Some("Basic YWdlbnQ6c2VjcmV0")
        );
    });
}

/// The bundled delay waits rather than returning at once.
#[test]
fn the_bundled_delay_sleeps() {
    block_on(async {
        let before = std::time::Instant::now();
        TimerDelay.sleep(Duration::from_millis(5)).await;
        assert!(before.elapsed() >= Duration::from_millis(1));
    });
}
