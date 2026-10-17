//! Configuration, publication and request contracts, and the refusals that guard each one.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use aep_core::{
    AssertionOperation, ClientAssertionClaims, ClientAssertionSigningKey,
    ClientAssertionVerifyingKey, ErrorCode, SignClientAssertionOptions, SigningAlgorithm,
    sign_client_assertion,
};
use aep_platform::*;
use async_trait::async_trait;
use futures::executor::block_on;
use serde_json::{Value, json};
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

struct AllowAll;

#[async_trait]
impl Authorizer for AllowAll {
    async fn authorize(
        &self,
        _request: &AuthorizationRequest,
        _context: &RequestContext,
    ) -> Result<bool, PlatformError> {
        Ok(true)
    }
}

struct AnyDid;

#[async_trait]
impl ServiceDidResolver for AnyDid {
    async fn resolve(&self, _service_did: &str) -> Result<bool, PlatformError> {
        Ok(true)
    }
}

struct TestKeyStore {
    jwk: Mutex<Value>,
    key: ClientAssertionSigningKey,
}

impl Default for TestKeyStore {
    fn default() -> Self {
        Self {
            jwk: Mutex::new(json!({
                "crv": "Ed25519",
                "kty": "OKP",
                "x": "11qYAYKxCrfVS_7TyWGDWZ4VnZ5wJzI7A2kB6FzM7o0"
            })),
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
            public_key_jwk: self.jwk.lock().expect("jwk lock").clone(),
            method_type: "JsonWebKey2020".to_owned(),
        })
    }

    async fn sign(
        &self,
        identity: &IdentityRecord,
        claims: &ClientAssertionClaims,
    ) -> Result<String, PlatformError> {
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

fn discovery_options() -> DiscoveryOptions {
    DiscoveryOptions {
        endpoint_base: "/v1/aep".to_owned(),
        hosted_verification_endpoint: None,
        lifecycle_endpoint: "/v1/aep/agent-identities/{agent_identity_id}".to_owned(),
        list_endpoint: "/v1/aep/agent-identities".to_owned(),
        platform_did: Some("did:web:platform.example".to_owned()),
        platform_name: "Example Platform".to_owned(),
        provision_endpoint: "/v1/aep/agent-identities".to_owned(),
        sign_endpoint: "/v1/aep/agent-identities/{agent_identity_id}/sign".to_owned(),
    }
}

fn options(key_store: Arc<TestKeyStore>) -> PlatformOptions {
    let mut options = PlatformOptions::new(
        Arc::new(AllowAll),
        key_store,
        Arc::new(AnyDid),
        DID_HOST,
        DID_TEMPLATE,
    );
    options.agent_did_id_generator = Some(Arc::new(|| Ok("did-0".to_owned())));
    options.clock = Some(Arc::new(FixedClock(fixed_time())));
    options.discovery = discovery_options();
    options.identifier = Some(Arc::new(|| Ok("identity-0".to_owned())));
    options
}

fn platform(key_store: Arc<TestKeyStore>) -> Arc<Platform> {
    Platform::new(options(key_store)).expect("Platform")
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

fn status_of<T>(response: &PlatformResponse<T>) -> u16 {
    response.status
}

fn code_of<T>(response: &PlatformResponse<T>) -> Option<ErrorCode> {
    match &response.body {
        ResponseBody::Problem(problem) => Some(problem.code.clone()),
        ResponseBody::Success(_) => None,
    }
}

async fn provisioned(platform: &Arc<Platform>) -> AgentIdentity {
    let response = platform
        .provision(
            ProvisionRequest {
                service_did: SERVICE_DID.to_owned(),
            },
            context("provision-1"),
        )
        .await
        .expect("provisioned");
    match response.body {
        ResponseBody::Success(identity) => identity,
        ResponseBody::Problem(problem) => panic!("expected an identity, got {problem:?}"),
    }
}

// --- configuration ----------------------------------------------------------------------------

/// DWB-RES-001 resolves a minted DID to exactly one document URL, and PLT-DISC-006 advertises
/// where the Platform publishes it. A Platform whose two answers disagree is refused outright.
#[test]
fn the_did_url_template_must_resolve_the_minted_dids() {
    for (host, prefix, template) in [
        (
            DID_HOST,
            "agents",
            "https://platform.example/identities/{agent_did_id}/did.json",
        ),
        (
            DID_HOST,
            "agents",
            "https://other.example/agents/{agent_did_id}/did.json",
        ),
        (DID_HOST, "tenants/agents", DID_TEMPLATE),
    ] {
        let mut settings = options(Arc::new(TestKeyStore::default()));
        settings.did_path_prefix = prefix.to_owned();
        settings.did_url_template = template.to_owned();
        settings.did_host = host.to_owned();
        assert!(Platform::new(settings).is_err(), "{prefix} / {template}");
    }

    // A nested prefix is fine as long as the template publishes the same place.
    let mut settings = options(Arc::new(TestKeyStore::default()));
    settings.did_path_prefix = "tenants/agents".to_owned();
    settings.did_url_template =
        "https://platform.example/tenants/agents/{agent_did_id}/did.json".to_owned();
    assert!(Platform::new(settings).is_ok());
}

/// The DID host is an origin, and the template renders one absolute HTTPS URL per identity.
#[test]
fn unusable_did_configuration_is_refused() {
    for host in [
        "",
        "platform.example/agents",
        "Platform.Example",
        "platform.example?x=1",
    ] {
        let mut settings = options(Arc::new(TestKeyStore::default()));
        settings.did_host = host.to_owned();
        assert!(Platform::new(settings).is_err(), "{host}");
    }
    for template in [
        "https://platform.example/agents/did.json",
        "https://platform.example/{agent_did_id}/{agent_did_id}/did.json",
        "http://platform.example/agents/{agent_did_id}/did.json",
        "https://user@platform.example/agents/{agent_did_id}/did.json",
        "https://platform.example/agents/{agent_did_id}/did.json#key",
        "not-a-url/{agent_did_id}",
    ] {
        let mut settings = options(Arc::new(TestKeyStore::default()));
        settings.did_url_template = template.to_owned();
        assert!(Platform::new(settings).is_err(), "{template}");
    }
}

/// PLT-DISC-011: every advertised endpoint is an absolute path, and hosted verification is
/// advertised exactly when it is offered.
#[test]
fn discovery_advertisements_are_checked_at_construction() {
    for path in ["", "v1/aep", "//v1/aep", "/v1/aep?x=1", "/v1/aep#x"] {
        let mut settings = options(Arc::new(TestKeyStore::default()));
        settings.discovery.list_endpoint = path.to_owned();
        assert!(Platform::new(settings).is_err(), "{path:?}");
    }

    // Hosted verification and its endpoint are advertised together, or not at all.
    let mut settings = options(Arc::new(TestKeyStore::default()));
    settings.hosted_verification = true;
    settings.replay_store = Some(Arc::new(MemoryReplayStore::default()));
    assert!(Platform::new(settings).is_err());

    let mut settings = options(Arc::new(TestKeyStore::default()));
    settings.discovery.hosted_verification_endpoint = Some("/v1/aep/verifications".to_owned());
    assert!(Platform::new(settings).is_err());

    // Hosted verification also needs somewhere to record consumed assertions.
    let mut settings = options(Arc::new(TestKeyStore::default()));
    settings.hosted_verification = true;
    settings.discovery.hosted_verification_endpoint = Some("/v1/aep/verifications".to_owned());
    assert!(Platform::new(settings).is_err());

    let mut settings = options(Arc::new(TestKeyStore::default()));
    settings.discovery.platform_name = String::new();
    assert!(Platform::new(settings).is_err());

    for platform_did in [
        "platform.example",
        "did:web",
        "did::identifier",
        "did:WEB:x",
        "did:web: ",
    ] {
        let mut settings = options(Arc::new(TestKeyStore::default()));
        settings.discovery.platform_did = Some(platform_did.to_owned());
        assert!(Platform::new(settings).is_err(), "{platform_did}");
    }
}

/// PLT-DISC-007/008/009: the advertised algorithms are the registered ones, listed once, and the
/// advertised lifetimes stay inside the AEP assertion window.
#[test]
fn signing_advertisements_are_checked_at_construction() {
    for algorithms in [
        Vec::new(),
        vec![SigningAlgorithm::EdDsa, SigningAlgorithm::EdDsa],
        vec![SigningAlgorithm::from("RS256")],
    ] {
        let mut settings = options(Arc::new(TestKeyStore::default()));
        settings.signing_algorithms = algorithms.clone();
        assert!(Platform::new(settings).is_err(), "{algorithms:?}");
    }
    for (default, maximum) in [
        (Duration::ZERO, Duration::from_secs(300)),
        (Duration::from_secs(301), Duration::from_secs(301)),
        (Duration::from_millis(1500), Duration::from_secs(300)),
        (Duration::from_secs(120), Duration::from_secs(60)),
    ] {
        let mut settings = options(Arc::new(TestKeyStore::default()));
        settings.default_lifetime = default;
        settings.maximum_lifetime = maximum;
        assert!(
            Platform::new(settings).is_err(),
            "{default:?} / {maximum:?}"
        );
    }
}

/// PLT-DISC-012: the discovery response carries validators alongside its freshness policy.
#[test]
fn discovery_publishes_cache_metadata() {
    let platform = platform(Arc::new(TestKeyStore::default()));
    let response = platform.discovery();
    let header = |name: http::header::HeaderName| {
        response
            .headers
            .get(name)
            .map(|value| value.to_str().expect("value").to_owned())
    };
    assert_eq!(
        header(http::header::CACHE_CONTROL).as_deref(),
        Some("max-age=300")
    );
    let etag = header(http::header::ETAG).expect("entity tag");
    assert!(etag.starts_with('"') && etag.ends_with('"'), "{etag}");
    assert_eq!(
        header(http::header::LAST_MODIFIED).as_deref(),
        Some("Mon, 31 Aug 2026 12:00:00 GMT")
    );
    // The same document always carries the same entity tag.
    assert_eq!(header(http::header::ETAG), Some(etag));
}

// --- DID documents ----------------------------------------------------------------------------

/// PLT-DID-002: a published verification method carries public material for this identity and
/// nothing else.
#[test]
fn did_documents_publish_public_material_only() {
    block_on(async {
        for jwk in [
            // A full key pair, in each of the shapes a key store might hand over.
            json!({"crv": "Ed25519", "kty": "OKP", "x": "11qYAYKxCrfVS_7TyWGDWZ4VnZ5wJzI7A2kB6FzM7o0", "d": "private"}),
            json!({"kty": "RSA", "n": "modulus", "e": "AQAB", "p": "prime"}),
            json!({"kty": "oct", "k": "symmetric"}),
            // Metadata that does not describe this identity's key.
            json!({"crv": "Ed25519", "kty": "OKP", "x": "public", "kid": "did:web:other.example"}),
            json!({"crv": "Ed25519", "kty": "OKP", "x": "public", "alg": "RS256"}),
            json!({"crv": "Ed25519", "kty": "OKP", "x": "public", "use": "enc"}),
        ] {
            let key_store = Arc::new(TestKeyStore::default());
            let platform = platform(key_store.clone());
            let identity = provisioned(&platform).await;
            *key_store.jwk.lock().expect("jwk lock") = jwk.clone();
            assert!(platform.did_document("did-0").await.is_err(), "{jwk}");
            assert!(!identity.agent_did.is_empty());
        }
    });
}

/// A verification method has to name the identity it belongs to.
#[test]
fn verification_methods_must_match_their_identity() {
    block_on(async {
        let key_store = Arc::new(TestKeyStore::default());
        let platform = platform(key_store.clone());
        let identity = provisioned(&platform).await;
        let record = IdentityRecord {
            agent_did: identity.agent_did.clone(),
            agent_did_id: "did-0".to_owned(),
            agent_identity_id: identity.agent_identity_id.clone(),
            created_at: fixed_time(),
            did_document_url: identity.did_document_url.clone(),
            key_id: identity.key_id.clone(),
            principal: "owner".to_owned(),
            service_did: SERVICE_DID.to_owned(),
            signing_algorithms: vec![SigningAlgorithm::EdDsa],
            status: ManagedAgentStatus::Active,
            updated_at: fixed_time(),
        };
        let method = |change: fn(&mut DidVerificationMethod)| {
            let mut method = DidVerificationMethod {
                controller: record.agent_did.clone(),
                id: record.key_id.clone(),
                public_key_jwk: json!({"crv": "Ed25519", "kty": "OKP", "x": "public"}),
                method_type: "JsonWebKey2020".to_owned(),
            };
            change(&mut method);
            method
        };
        assert!(create_did_document(&record, method(|_| {})).is_ok());
        for change in [
            (|method: &mut DidVerificationMethod| method.id = "other".to_owned())
                as fn(&mut DidVerificationMethod),
            |method: &mut DidVerificationMethod| method.controller = "other".to_owned(),
            |method: &mut DidVerificationMethod| method.method_type = String::new(),
            |method: &mut DidVerificationMethod| method.public_key_jwk = json!("public"),
        ] {
            assert!(create_did_document(&record, method(change)).is_err());
        }

        // An incomplete record is refused before anything is published.
        let mut empty = record.clone();
        empty.principal = String::new();
        assert!(create_did_document(&empty, method(|_| {})).is_err());
    });
}

/// PLT-DID-001/006: only an active identity has a published document, and an unknown one is not
/// distinguishable from a withdrawn one.
#[test]
fn did_documents_are_published_for_active_identities_only() {
    block_on(async {
        let platform = platform(Arc::new(TestKeyStore::default()));
        let identity = provisioned(&platform).await;
        assert_eq!(
            status_of(&platform.did_document("did-0").await.expect("found")),
            200
        );
        assert_eq!(
            code_of(&platform.did_document("did-missing").await.expect("missing")),
            Some(ErrorCode::NotRecognized)
        );
        platform
            .update_identity(
                &identity.agent_identity_id,
                LifecycleRequest {
                    status: ManagedAgentStatus::Revoked,
                },
                &context("lifecycle-1"),
            )
            .await
            .expect("revoked");
        let response = platform.did_document("did-0").await.expect("revoked");
        assert_eq!(status_of(&response), 404);
        assert_eq!(code_of(&response), Some(ErrorCode::NotRecognized));
    });
}

// --- sign -------------------------------------------------------------------------------------

fn sign_request(op: AssertionOperation, resource: Option<&str>) -> SignRequest {
    SignRequest {
        jti: "assertion-1".to_owned(),
        lifetime_seconds: None,
        op,
        platform_context: BTreeMap::new(),
        resource: resource.map(str::to_owned),
        service_did: SERVICE_DID.to_owned(),
    }
}

/// PLT-SIGN-008: `lifetime_seconds` is the published decimal syntax, inside the AEP window.
#[test]
fn sign_lifetimes_follow_the_published_syntax() {
    block_on(async {
        let platform = platform(Arc::new(TestKeyStore::default()));
        let identity = provisioned(&platform).await;
        for value in ["+5", "007", "0", "301", "5.0", "5 ", "", "five"] {
            let mut request = sign_request(AssertionOperation::Enroll, None);
            request.lifetime_seconds = Some(value.to_owned());
            let response = platform
                .sign(&identity.agent_identity_id, request, context("sign-bad"))
                .await
                .expect("refused");
            assert_eq!(
                code_of(&response),
                Some(ErrorCode::InvalidRequest),
                "{value:?}"
            );
        }
        let mut request = sign_request(AssertionOperation::Enroll, None);
        request.lifetime_seconds = Some("60".to_owned());
        let response = platform
            .sign(&identity.agent_identity_id, request, context("sign-good"))
            .await
            .expect("signed");
        assert_eq!(status_of(&response), 200);
    });
}

/// PLT-SIGN-012/013: `resource` travels with `authenticate` and with nothing else.
#[test]
fn sign_resources_belong_to_authenticate_alone() {
    block_on(async {
        let platform = platform(Arc::new(TestKeyStore::default()));
        let identity = provisioned(&platform).await;
        let refused = |request: SignRequest, key: &'static str| {
            let platform = platform.clone();
            let agent_identity_id = identity.agent_identity_id.clone();
            async move {
                let response = platform
                    .sign(&agent_identity_id, request, context(key))
                    .await
                    .expect("answered");
                code_of(&response)
            }
        };
        assert_eq!(
            refused(sign_request(AssertionOperation::Authenticate, None), "s1").await,
            Some(ErrorCode::InvalidRequest)
        );
        assert_eq!(
            refused(
                sign_request(
                    AssertionOperation::Authenticate,
                    Some("http://service.example/x")
                ),
                "s2"
            )
            .await,
            Some(ErrorCode::InvalidRequest)
        );
        assert_eq!(
            refused(
                sign_request(
                    AssertionOperation::Authenticate,
                    Some("https://service.example/x#part")
                ),
                "s3"
            )
            .await,
            Some(ErrorCode::InvalidRequest)
        );
        assert_eq!(
            refused(
                sign_request(
                    AssertionOperation::Enroll,
                    Some("https://service.example/x")
                ),
                "s4"
            )
            .await,
            Some(ErrorCode::InvalidRequest)
        );
        let mut empty_jti = sign_request(AssertionOperation::Enroll, None);
        empty_jti.jti = String::new();
        assert_eq!(
            refused(empty_jti, "s5").await,
            Some(ErrorCode::InvalidRequest)
        );
        let mut bad_service = sign_request(AssertionOperation::Enroll, None);
        bad_service.service_did = "service.example".to_owned();
        assert_eq!(
            refused(bad_service, "s6").await,
            Some(ErrorCode::InvalidRequest)
        );

        let response = platform
            .sign(
                &identity.agent_identity_id,
                sign_request(
                    AssertionOperation::Authenticate,
                    Some("https://service.example/orders"),
                ),
                context("s7"),
            )
            .await
            .expect("signed");
        assert_eq!(status_of(&response), 200);
    });
}

/// PLT-SIGN-006/007 and PLT-LIFE-002: signing needs the caller's own active identity, scoped to
/// the Service the assertion names.
#[test]
fn signing_is_scoped_to_an_active_identity() {
    block_on(async {
        let platform = platform(Arc::new(TestKeyStore::default()));
        let identity = provisioned(&platform).await;

        let mut other_service = sign_request(AssertionOperation::Enroll, None);
        other_service.service_did = "did:web:other.example".to_owned();
        let response = platform
            .sign(
                &identity.agent_identity_id,
                other_service,
                context("scope-1"),
            )
            .await
            .expect("answered");
        assert_eq!(code_of(&response), Some(ErrorCode::NotRecognized));

        let response = platform
            .sign(
                "identity-missing",
                sign_request(AssertionOperation::Enroll, None),
                context("scope-2"),
            )
            .await
            .expect("answered");
        assert_eq!(code_of(&response), Some(ErrorCode::NotRecognized));

        for (status, code) in [
            (ManagedAgentStatus::Suspended, ErrorCode::IdentitySuspended),
            (
                ManagedAgentStatus::Terminated,
                ErrorCode::IdentityTerminated,
            ),
        ] {
            platform
                .update_identity(
                    &identity.agent_identity_id,
                    LifecycleRequest { status },
                    &context("lifecycle"),
                )
                .await
                .expect("updated");
            let response = platform
                .sign(
                    &identity.agent_identity_id,
                    sign_request(AssertionOperation::Enroll, None),
                    context(&format!("sign-{}", status.as_str())),
                )
                .await
                .expect("answered");
            assert_eq!(status_of(&response), 403);
            assert_eq!(code_of(&response), Some(code));
        }
    });
}

/// PLT-IDP-001: a state-mutating Platform request carries an idempotency key.
#[test]
fn state_mutating_requests_require_an_idempotency_key() {
    block_on(async {
        let platform = platform(Arc::new(TestKeyStore::default()));
        for key in [None, Some(String::new())] {
            let mut missing = context("unused");
            missing.idempotency_key = key.clone();
            let response = platform
                .provision(
                    ProvisionRequest {
                        service_did: SERVICE_DID.to_owned(),
                    },
                    missing,
                )
                .await
                .expect("answered");
            assert_eq!(
                code_of(&response),
                Some(ErrorCode::InvalidRequest),
                "{key:?}"
            );
        }
        let mut anonymous = context("provision-anon");
        anonymous.principal = String::new();
        let response = platform
            .provision(
                ProvisionRequest {
                    service_did: SERVICE_DID.to_owned(),
                },
                anonymous,
            )
            .await
            .expect("answered");
        assert_eq!(code_of(&response), Some(ErrorCode::InvalidRequest));

        // PLT-PROV-006: the requested Service DID has to be one.
        let response = platform
            .provision(
                ProvisionRequest {
                    service_did: "service.example".to_owned(),
                },
                context("provision-bad"),
            )
            .await
            .expect("answered");
        assert_eq!(code_of(&response), Some(ErrorCode::InvalidRequest));
    });
}

// --- listing and lifecycle ----------------------------------------------------------------------

/// PLT-LIST-002/004: the listing query is bounded and its filters are checked.
#[test]
fn list_queries_are_bounded_and_checked() {
    block_on(async {
        let platform = platform(Arc::new(TestKeyStore::default()));
        provisioned(&platform).await;
        let query = |limit: usize, service_did: Option<&str>| IdentityListQuery {
            descending: false,
            limit,
            offset: 0,
            service_did: service_did.map(str::to_owned),
            status: None,
        };
        let response = platform
            .list(query(101, None), &context("list"))
            .await
            .expect("answered");
        assert_eq!(code_of(&response), Some(ErrorCode::InvalidRequest));
        let response = platform
            .list(query(10, Some("service.example")), &context("list"))
            .await
            .expect("answered");
        assert_eq!(code_of(&response), Some(ErrorCode::InvalidRequest));

        // A zero limit takes the Platform's own bound rather than returning nothing.
        let response = platform
            .list(query(0, Some(SERVICE_DID)), &context("list"))
            .await
            .expect("answered");
        let ResponseBody::Success(body) = response.body else {
            panic!("expected a listing");
        };
        assert_eq!(body.count, "1");
        assert_eq!(body.total, "1");

        let mut anonymous = context("list");
        anonymous.principal = String::new();
        let response = platform
            .list(query(10, None), &anonymous)
            .await
            .expect("answered");
        assert_eq!(code_of(&response), Some(ErrorCode::NotRecognized));
    });
}

/// PLT-LIFE-005: an identity that is not the caller's is not readable or changeable.
#[test]
fn lifecycle_operations_stay_within_the_caller() {
    block_on(async {
        let platform = platform(Arc::new(TestKeyStore::default()));
        let identity = provisioned(&platform).await;
        let mut other = context("lifecycle");
        other.principal = "intruder".to_owned();
        assert_eq!(
            code_of(
                &platform
                    .get_identity(&identity.agent_identity_id, &other)
                    .await
                    .expect("answered")
            ),
            Some(ErrorCode::NotRecognized)
        );
        assert_eq!(
            code_of(
                &platform
                    .update_identity(
                        &identity.agent_identity_id,
                        LifecycleRequest {
                            status: ManagedAgentStatus::Revoked,
                        },
                        &other,
                    )
                    .await
                    .expect("answered")
            ),
            Some(ErrorCode::NotRecognized)
        );
        assert_eq!(
            code_of(
                &platform
                    .get_identity("identity-missing", &context("lifecycle"))
                    .await
                    .expect("answered")
            ),
            Some(ErrorCode::NotRecognized)
        );
        assert_eq!(
            status_of(
                &platform
                    .get_identity(&identity.agent_identity_id, &context("lifecycle"))
                    .await
                    .expect("answered")
            ),
            200
        );
    });
}

// --- hosted verification ------------------------------------------------------------------------

/// PLT-VER-001: a Platform that does not offer hosted verification does not answer for it.
#[test]
fn hosted_verification_is_absent_unless_it_is_offered() {
    block_on(async {
        let platform = platform(Arc::new(TestKeyStore::default()));
        let response = platform
            .verify(
                VerificationRequest {
                    client_assertion: "assertion".to_owned(),
                    op: AssertionOperation::Enroll,
                    resource: None,
                    service_did: SERVICE_DID.to_owned(),
                },
                context("verify-1"),
            )
            .await
            .expect("answered");
        assert_eq!(status_of(&response), 404);
        assert_eq!(code_of(&response), Some(ErrorCode::NotRecognized));
    });
}

// --- stores ---------------------------------------------------------------------------------------

/// The memory stores refuse records that would break the invariants the Platform relies on.
#[test]
fn memory_stores_guard_their_invariants() {
    block_on(async {
        let store = MemoryIdentityStore::default();
        let record =
            |agent_identity_id: &str, agent_did: &str, agent_did_id: &str| IdentityRecord {
                agent_did: agent_did.to_owned(),
                agent_did_id: agent_did_id.to_owned(),
                agent_identity_id: agent_identity_id.to_owned(),
                created_at: fixed_time(),
                did_document_url: "https://platform.example/agents/did-0/did.json".to_owned(),
                key_id: agent_did.to_owned(),
                principal: "owner".to_owned(),
                service_did: SERVICE_DID.to_owned(),
                signing_algorithms: vec![SigningAlgorithm::EdDsa],
                status: ManagedAgentStatus::Active,
                updated_at: fixed_time(),
            };
        let creation = |record: IdentityRecord| {
            Box::new(move || {
                let record = record.clone();
                Box::pin(async move { Ok(record) })
                    as futures::future::BoxFuture<'static, Result<IdentityRecord, PlatformError>>
            }) as IdentityCreation
        };

        // An unscoped lookup has nothing to key on.
        assert!(
            store
                .find_or_create("", SERVICE_DID, creation(record("a", "did:web:a", "a")))
                .await
                .is_err()
        );
        assert!(
            store
                .find_or_create("owner", "", creation(record("a", "did:web:a", "a")))
                .await
                .is_err()
        );

        // A record that does not belong to the scope it was created for is refused.
        let mut wrong_scope = record("a", "did:web:a", "a");
        wrong_scope.principal = "other".to_owned();
        assert!(
            store
                .find_or_create("owner", SERVICE_DID, creation(wrong_scope))
                .await
                .is_err()
        );

        // An incomplete record never reaches the index.
        let mut incomplete = record("a", "did:web:a", "a");
        incomplete.key_id = String::new();
        assert!(
            store
                .find_or_create("owner", SERVICE_DID, creation(incomplete))
                .await
                .is_err()
        );

        assert!(
            store
                .find_or_create(
                    "owner",
                    SERVICE_DID,
                    creation(record("a", "did:web:a", "a"))
                )
                .await
                .is_ok()
        );
        // Another scope may not reuse the same identity material, whichever index it collides on.
        for (identity_id, agent_did, agent_did_id) in [
            ("a", "did:web:b", "b"),
            ("b", "did:web:a", "b"),
            ("b", "did:web:b", "a"),
        ] {
            let mut other_scope = record(identity_id, agent_did, agent_did_id);
            other_scope.service_did = "did:web:other.example".to_owned();
            assert!(
                store
                    .find_or_create("owner", "did:web:other.example", creation(other_scope))
                    .await
                    .is_err(),
                "{identity_id}/{agent_did}/{agent_did_id}"
            );
        }
        assert!(store.get("missing").await.expect("lookup").is_none());
        assert!(
            store
                .find_by_agent_did("did:web:missing")
                .await
                .expect("lookup")
                .is_none()
        );
        assert!(
            store
                .update_status("missing", ManagedAgentStatus::Revoked, fixed_time())
                .await
                .expect("update")
                .is_none()
        );
        assert!(store.list("", &IdentityListQuery::default()).await.is_err());
    });
}

/// PLT-VER-005: an assertion is consumable once, and only inside its own validity window.
#[test]
fn the_replay_store_consumes_an_assertion_once() {
    block_on(async {
        let store = MemoryReplayStore::default();
        let now = fixed_time();
        let later = now + Duration::from_secs(60);
        assert!(!store.consume("", later, now).await.expect("consume"));
        assert!(!store.consume("key", now, now).await.expect("consume"));
        assert!(store.consume("key", later, now).await.expect("consume"));
        assert!(!store.consume("key", later, now).await.expect("consume"));
        // Once the window has passed the record is gone, so the key is free again.
        let after = now + Duration::from_secs(120);
        assert!(
            store
                .consume("key", after + Duration::from_secs(60), after)
                .await
                .expect("consume")
        );
    });
}

/// The bundled stores stand up without configuration.
#[test]
fn the_bundled_stores_have_working_defaults() {
    let store = MemoryIdempotencyStore::default();
    let _ = &store;
    assert!(SystemClock.now() > OffsetDateTime::UNIX_EPOCH);
}
