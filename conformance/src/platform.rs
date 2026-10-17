use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use aep_core::{
    AssertionOperation, ClientAssertionClaims, ClientAssertionSigningKey,
    ClientAssertionVerifyingKey, SignClientAssertionOptions, SigningAlgorithm,
    sign_client_assertion,
};
use aep_platform::{
    AuthorizationRequest, Authorizer, Clock, DidVerificationMethod, DiscoveryOptions,
    IdentityListQuery, IdentityRecord, KeyStore, LifecycleRequest, ManagedAgentStatus,
    MemoryReplayStore, Platform, PlatformError, PlatformOptions, ProvisionRequest, RequestContext,
    ResponseBody, ServiceDidResolver, SignRequest, SignResponse, SignStatus, VerificationRequest,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{AdapterRequest, input, object_value};

const PRINCIPAL: &str = "stable-principal-123";
const SERVICE_DID: &str = "did:web:api.service.example";

pub async fn evaluate(request: &AdapterRequest) -> Result<bool, String> {
    match request.vector.id.as_str() {
        "authorization-required" => authorization_required(request).await,
        "discovery" => discovery(request),
        "idempotency-replay-conflict" => idempotency(request).await,
        "lifecycle-request" | "lifecycle-response" => lifecycle(request).await,
        "list-response" => list(request).await,
        "provision-request" | "provision-response" => provision(request).await,
        "provision-response-distinct-services" => distinct_services(request).await,
        "sign-request" | "sign-response" => sign(request).await,
        "sign-response-pending" => pending_sign(request).await,
        "verification-authenticate-missing-resource" => missing_resource(request).await,
        "verification-request" => verification_request(request).await,
        "verification-response-recognized" => recognized_verification(request).await,
        "verification-response-unrecognized" => unrecognized_verification(request).await,
        other => Err(format!(
            "no Platform operation maps vector platform/{other}"
        )),
    }
}

struct FixedAuthorizer(AtomicBool);

#[async_trait]
impl Authorizer for FixedAuthorizer {
    async fn authorize(
        &self,
        _request: &AuthorizationRequest,
        _context: &RequestContext,
    ) -> Result<bool, PlatformError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

struct Resolver;

#[async_trait]
impl ServiceDidResolver for Resolver {
    async fn resolve(&self, _service_did: &str) -> Result<bool, PlatformError> {
        Ok(true)
    }
}

struct FixedClock(Mutex<OffsetDateTime>);

impl FixedClock {
    fn set(&self, value: OffsetDateTime) -> Result<(), String> {
        *self
            .0
            .lock()
            .map_err(|_| "clock lock is poisoned".to_owned())? = value;
        Ok(())
    }
}

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.0
            .lock()
            .map(|value| *value)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH)
    }
}

struct FixtureKeyStore {
    key: ClientAssertionSigningKey,
    public_key_x: Vec<u8>,
    public_key_y: Vec<u8>,
}

impl FixtureKeyStore {
    fn new() -> Result<Self, String> {
        let key = ClientAssertionSigningKey::es256_from_bytes(&[11; 32])
            .map_err(|error| error.to_string())?;
        let public_key = p256::ecdsa::SigningKey::from_slice(&[11; 32])
            .map_err(|error| error.to_string())?
            .verifying_key()
            .to_encoded_point(false);
        Ok(Self {
            key,
            public_key_x: public_key
                .x()
                .ok_or_else(|| "ES256 public key x-coordinate is missing".to_owned())?
                .to_vec(),
            public_key_y: public_key
                .y()
                .ok_or_else(|| "ES256 public key y-coordinate is missing".to_owned())?
                .to_vec(),
        })
    }
}

#[async_trait]
impl KeyStore for FixtureKeyStore {
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
            method_type: "JsonWebKey2020".to_owned(),
            public_key_jwk: json!({
                "alg": "ES256",
                "crv": "P-256",
                "kid": identity.key_id,
                "kty": "EC",
                "use": "sig",
                "x": URL_SAFE_NO_PAD.encode(&self.public_key_x),
                "y": URL_SAFE_NO_PAD.encode(&self.public_key_y),
            }),
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

struct Fixture {
    authorizer: Arc<FixedAuthorizer>,
    clock: Arc<FixedClock>,
    context: RequestContext,
    platform: Arc<Platform>,
}

fn fixture(authorized: bool) -> Result<Fixture, String> {
    fixture_with_sign_handler(authorized, None)
}

fn fixture_with_sign_handler(
    authorized: bool,
    handler: Option<Arc<dyn aep_platform::SignHandler>>,
) -> Result<Fixture, String> {
    let identity_ids = Arc::new(Mutex::new(vec![
        "01J0AEPPLATFORM000000000002".to_owned(),
        "01J0AEPPLATFORM000000000001".to_owned(),
    ]));
    let did_ids = Arc::new(Mutex::new(vec![
        "9Lm2r8VnQ4".to_owned(),
        "4Yf7p2xQd9".to_owned(),
    ]));
    let clock = Arc::new(FixedClock(Mutex::new(parse_time("2026-07-06T12:00:00Z")?)));
    let authorizer = Arc::new(FixedAuthorizer(AtomicBool::new(authorized)));
    let mut options = PlatformOptions::new(
        authorizer.clone(),
        Arc::new(FixtureKeyStore::new()?),
        Arc::new(Resolver),
        "p.example",
        "https://p.example/a/{agent_did_id}/did.json",
    );
    options.agent_did_id_generator = Some(Arc::new(move || {
        did_ids
            .lock()
            .map_err(|_| PlatformError::Handler("DID identifier lock is poisoned".to_owned()))?
            .pop()
            .ok_or_else(|| PlatformError::Handler("DID identifiers are exhausted".to_owned()))
    }));
    options.clock = Some(clock.clone());
    options.default_lifetime = Duration::from_secs(300);
    options.did_path_prefix = "a".to_owned();
    options.discovery = DiscoveryOptions {
        endpoint_base: "/v1/aep".to_owned(),
        hosted_verification_endpoint: Some("/v1/aep/verifications".to_owned()),
        lifecycle_endpoint: "/v1/aep/agent-identities/{agent_identity_id}".to_owned(),
        list_endpoint: "/v1/aep/agent-identities".to_owned(),
        platform_did: Some("did:web:p.example".to_owned()),
        platform_name: "Example Platform".to_owned(),
        provision_endpoint: "/v1/aep/agent-identities".to_owned(),
        sign_endpoint: "/v1/aep/agent-identities/{agent_identity_id}/sign".to_owned(),
    };
    options.hosted_verification = true;
    options.sign_handler = handler;
    options.identifier = Some(Arc::new(move || {
        identity_ids
            .lock()
            .map_err(|_| PlatformError::Handler("identity identifier lock is poisoned".to_owned()))?
            .pop()
            .ok_or_else(|| PlatformError::Handler("identity identifiers are exhausted".to_owned()))
    }));
    options.maximum_lifetime = Duration::from_secs(300);
    options.replay_store = Some(Arc::new(MemoryReplayStore::default()));
    options.signing_algorithms = vec![SigningAlgorithm::Es256];
    let platform = Platform::new(options).map_err(|error| error.to_string())?;
    Ok(Fixture {
        authorizer,
        clock,
        context: RequestContext {
            authorization: Some("Bearer platform".to_owned()),
            idempotency_key: Some("01J0AEPPLATFORM000000000001".to_owned()),
            now: Some(parse_time("2026-07-06T12:00:00Z")?),
            principal: PRINCIPAL.to_owned(),
            request_id: None,
        },
        platform,
    })
}

fn success<T>(body: ResponseBody<T>) -> Result<T, String> {
    match body {
        ResponseBody::Success(value) => Ok(value),
        ResponseBody::Problem(problem) => {
            Err(format!("Platform returned {}", problem.code.as_str()))
        }
    }
}

/// PLT-PROV-002, PLT-LIST-005, PLT-LIFE-005, PLT-SIGN-006 and PLT-VER-009: every management
/// operation is authorized, an unauthorized caller learns nothing and changes nothing, and the
/// DID document stays public throughout.
async fn authorization_required(request: &AdapterRequest) -> Result<bool, String> {
    let denied_status = expected_u16(request, "management_denied_status")?;
    let denied_code = expected_string(request, "management_denied_code")?;
    let verification = request
        .case
        .expected
        .get("verification_denied")
        .ok_or_else(|| "verification_denied expectation is missing".to_owned())?;
    if !matches!(
        request.case.expected.get("did_document_public"),
        Some(Value::Bool(true))
    ) || !matches!(
        request.case.expected.get("side_effects"),
        Some(Value::Bool(false))
    ) || expected_string(request, "missing_authorizer")? != "construction-error"
        || verification.get("verified") != Some(&Value::Bool(false))
        || verification.get("reason").and_then(Value::as_str) != Some(denied_code.as_str())
    {
        return Ok(false);
    }

    // The identity exists, minted by an authorized caller.
    let authorized = fixture(true)?;
    let identity = success(
        authorized
            .platform
            .provision(
                ProvisionRequest {
                    service_did: SERVICE_DID.to_owned(),
                },
                authorized.context.clone(),
            )
            .await
            .map_err(|error| error.to_string())?
            .body,
    )?;

    let signed = success(
        authorized
            .platform
            .sign(
                &identity.agent_identity_id,
                SignRequest {
                    jti: "authorization-required".to_owned(),
                    lifetime_seconds: None,
                    op: AssertionOperation::Enroll,
                    platform_context: BTreeMap::new(),
                    resource: None,
                    service_did: SERVICE_DID.to_owned(),
                },
                RequestContext {
                    idempotency_key: Some("authorization-required-sign".to_owned()),
                    ..authorized.context.clone()
                },
            )
            .await
            .map_err(|error| error.to_string())?
            .body,
    )?;
    authorized.authorizer.0.store(false, Ordering::SeqCst);
    let denied = &authorized;
    let denied_identity = &identity;
    // Each state-mutating attempt carries its own idempotency key, so a refusal is the answer to
    // that operation rather than a conflict with the previous one.
    let keyed = |suffix: &str| {
        let mut context = denied.context.clone();
        context.idempotency_key = Some(format!("01J0AEPDENIED{suffix}"));
        context
    };
    let refusals: Vec<(u16, Option<String>)> = vec![
        status_and_code(
            denied
                .platform
                .provision(
                    ProvisionRequest {
                        service_did: SERVICE_DID.to_owned(),
                    },
                    keyed("PROVISION"),
                )
                .await
                .map_err(|error| error.to_string())?,
        ),
        status_and_code(
            denied
                .platform
                .get_identity(&denied_identity.agent_identity_id, &denied.context)
                .await
                .map_err(|error| error.to_string())?,
        ),
        status_and_code(
            denied
                .platform
                .list(
                    IdentityListQuery {
                        descending: false,
                        limit: 10,
                        offset: 0,
                        service_did: None,
                        status: None,
                    },
                    &denied.context,
                )
                .await
                .map_err(|error| error.to_string())?,
        ),
        status_and_code(
            denied
                .platform
                .update_identity(
                    &denied_identity.agent_identity_id,
                    LifecycleRequest {
                        status: ManagedAgentStatus::Revoked,
                    },
                    &denied.context,
                )
                .await
                .map_err(|error| error.to_string())?,
        ),
        status_and_code(
            denied
                .platform
                .sign(
                    &denied_identity.agent_identity_id,
                    SignRequest {
                        jti: "01J0AEPASSERTION0000000001".to_owned(),
                        lifetime_seconds: None,
                        op: AssertionOperation::Enroll,
                        platform_context: BTreeMap::new(),
                        resource: None,
                        service_did: SERVICE_DID.to_owned(),
                    },
                    keyed("SIGN"),
                )
                .await
                .map_err(|error| error.to_string())?,
        ),
    ];
    if refusals
        .iter()
        .any(|refusal| refusal.0 != denied_status || refusal.1.as_deref() != Some(&denied_code))
    {
        return Ok(false);
    }

    // Hosted verification answers the published refusal rather than a Problem.
    let verified = success(
        denied
            .platform
            .verify(
                VerificationRequest {
                    client_assertion: signed
                        .client_assertion
                        .ok_or_else(|| "authorized Sign omitted assertion".to_owned())?,
                    op: AssertionOperation::Enroll,
                    resource: None,
                    service_did: SERVICE_DID.to_owned(),
                },
                keyed("VERIFY"),
            )
            .await
            .map_err(|error| error.to_string())?
            .body,
    )?;
    if verified.verified || verified.reason != denied_code {
        return Ok(false);
    }

    // PLT-DID-006: the managed DID document stays publicly resolvable.
    let agent_did_id = identity
        .agent_did
        .rsplit(':')
        .next()
        .ok_or_else(|| "Agent DID has no identifier component".to_owned())?;
    if denied
        .platform
        .did_document(agent_did_id)
        .await
        .map_err(|error| error.to_string())?
        .status
        != 200
    {
        return Ok(false);
    }
    authorized.authorizer.0.store(true, Ordering::SeqCst);
    let unchanged = success(
        authorized
            .platform
            .get_identity(&identity.agent_identity_id, &authorized.context)
            .await
            .map_err(|error| error.to_string())?
            .body,
    )?;
    let listed = success(
        authorized
            .platform
            .list(
                IdentityListQuery {
                    descending: false,
                    limit: 10,
                    offset: 0,
                    service_did: None,
                    status: None,
                },
                &authorized.context,
            )
            .await
            .map_err(|error| error.to_string())?
            .body,
    )?;
    Ok(unchanged == identity && listed.data == vec![identity] && listed.total == "1")
}

fn discovery(request: &AdapterRequest) -> Result<bool, String> {
    let fixture = fixture(true)?;
    let response = fixture.platform.discovery();
    Ok(response.status == 200
        && response.to_json().map_err(|error| error.to_string())?
            == object_value(&request.case.expected))
}

async fn provision(request: &AdapterRequest) -> Result<bool, String> {
    let fixture = fixture(true)?;
    let service_did = request
        .case
        .input
        .get("service_did")
        .and_then(Value::as_str)
        .unwrap_or(SERVICE_DID);
    let mut context = fixture.context;
    if request.vector.id == "provision-request" {
        // PLT-PROV-004: the request carries the published, non-empty idempotency key, and the
        // Platform refuses the same request without one.
        context.idempotency_key = Some(expected_string(request, "idempotency_key_header")?);
        if context.idempotency_key.as_deref().is_none_or(str::is_empty) {
            return Ok(false);
        }
        let mut anonymous = context.clone();
        anonymous.idempotency_key = None;
        let refused = fixture
            .platform
            .provision(
                ProvisionRequest {
                    service_did: service_did.to_owned(),
                },
                anonymous,
            )
            .await
            .map_err(|error| error.to_string())?;
        if refused.status != 400 {
            return Ok(false);
        }
    }
    let response = fixture
        .platform
        .provision(
            ProvisionRequest {
                service_did: service_did.to_owned(),
            },
            context,
        )
        .await
        .map_err(|error| error.to_string())?;
    if response.status != 200 {
        return Ok(false);
    }
    let body = success(response.body)?;
    if request.vector.id == "provision-response" {
        return Ok(
            serde_json::to_value(body).map_err(|error| error.to_string())?
                == object_value(&request.case.expected),
        );
    }
    Ok(body.service_did == service_did)
}

async fn distinct_services(request: &AdapterRequest) -> Result<bool, String> {
    let fixture = fixture(true)?;
    let first_value: Value = input(request, "first_request")?;
    let second_value: Value = input(request, "second_request")?;
    let first = ProvisionRequest {
        service_did: first_value
            .get("service_did")
            .and_then(Value::as_str)
            .ok_or_else(|| "first Service DID is missing".to_owned())?
            .to_owned(),
    };
    let second = ProvisionRequest {
        service_did: second_value
            .get("service_did")
            .and_then(Value::as_str)
            .ok_or_else(|| "second Service DID is missing".to_owned())?
            .to_owned(),
    };
    let first_response = success(
        fixture
            .platform
            .provision(first, fixture.context.clone())
            .await
            .map_err(|error| error.to_string())?
            .body,
    )?;
    fixture.clock.set(parse_time("2026-07-06T12:01:00Z")?)?;
    let mut context = fixture.context;
    context.idempotency_key = Some("01J0AEPPLATFORM000000000002".to_owned());
    context.now = Some(parse_time("2026-07-06T12:01:00Z")?);
    let second_response = success(
        fixture
            .platform
            .provision(second, context)
            .await
            .map_err(|error| error.to_string())?
            .body,
    )?;
    // PLT-PROV-008/011/012: the two DIDs differ and share nothing beyond the Platform-controlled
    // prefix, which is the invariant the vector publishes.
    let expected_first: Value = expected_member(request, "first_response")?;
    let expected_second: Value = expected_member(request, "second_response")?;
    let invariant = expected_string(request, "invariant")?;
    if !invariant.contains("differ")
        || expected_first.get("service_did") != Some(&json!(first_response.service_did))
        || expected_second.get("service_did") != Some(&json!(second_response.service_did))
        || expected_first.get("agent_did") == expected_second.get("agent_did")
    {
        return Ok(false);
    }
    let prefix = |did: &str| {
        did.rsplit_once(':')
            .map(|(prefix, _)| prefix.to_owned())
            .unwrap_or_default()
    };
    Ok(first_response.agent_did != second_response.agent_did
        && first_response.agent_identity_id != second_response.agent_identity_id
        && first_response.did_document_url != second_response.did_document_url
        && prefix(&first_response.agent_did) == prefix(&second_response.agent_did)
        && first_response.service_did != second_response.service_did)
}

async fn list(request: &AdapterRequest) -> Result<bool, String> {
    let fixture = fixture(true)?;
    success(
        fixture
            .platform
            .provision(
                ProvisionRequest {
                    service_did: SERVICE_DID.to_owned(),
                },
                fixture.context.clone(),
            )
            .await
            .map_err(|error| error.to_string())?
            .body,
    )?;
    let query_value = request
        .case
        .input
        .get("query")
        .ok_or_else(|| "list query is missing".to_owned())?;
    let query = IdentityListQuery {
        descending: query_value
            .get("descending")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        limit: query_value
            .get("limit")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize,
        offset: query_value
            .get("offset")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize,
        service_did: query_value
            .get("service_did")
            .and_then(Value::as_str)
            .map(str::to_owned),
        status: query_value
            .get("status")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| error.to_string())?,
    };
    let response = fixture
        .platform
        .list(query, &fixture.context)
        .await
        .map_err(|error| error.to_string())?;
    Ok(response.status == 200
        && response.to_json().map_err(|error| error.to_string())?
            == object_value(&request.case.expected))
}

async fn lifecycle(request: &AdapterRequest) -> Result<bool, String> {
    let fixture = fixture(true)?;
    let identity = success(
        fixture
            .platform
            .provision(
                ProvisionRequest {
                    service_did: SERVICE_DID.to_owned(),
                },
                fixture.context.clone(),
            )
            .await
            .map_err(|error| error.to_string())?
            .body,
    )?;
    let status = request
        .case
        .input
        .get("status")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| error.to_string())?
        .unwrap_or(ManagedAgentStatus::Suspended);
    fixture.clock.set(parse_time("2026-07-06T12:10:00Z")?)?;
    let response = fixture
        .platform
        .update_identity(
            &identity.agent_identity_id,
            LifecycleRequest { status },
            &fixture.context,
        )
        .await
        .map_err(|error| error.to_string())?;
    if response.status != 200 {
        return Ok(false);
    }
    if request.vector.id == "lifecycle-response" {
        return Ok(response.to_json().map_err(|error| error.to_string())?
            == object_value(&request.case.expected));
    }
    // PLT-LIFE-007: the request body is exactly the target state, so the vector publishes no
    // expectation beyond it and the Platform's answer is the identity in that state.
    Ok(request.case.expected.is_empty() && success(response.body)?.status == status)
}

async fn sign(request: &AdapterRequest) -> Result<bool, String> {
    let fixture = fixture(true)?;
    let identity = success(
        fixture
            .platform
            .provision(
                ProvisionRequest {
                    service_did: SERVICE_DID.to_owned(),
                },
                fixture.context.clone(),
            )
            .await
            .map_err(|error| error.to_string())?
            .body,
    )?;
    let sign_request = if request.vector.id == "sign-request" {
        serde_json::from_value(object_value(&request.case.input))
            .map_err(|error| error.to_string())?
    } else {
        SignRequest {
            jti: "01J0AEPASSERTION0000000001".to_owned(),
            lifetime_seconds: Some("300".to_owned()),
            op: AssertionOperation::Enroll,
            platform_context: BTreeMap::from([(
                "authorization_handle".to_owned(),
                json!("opaque-value"),
            )]),
            resource: None,
            service_did: SERVICE_DID.to_owned(),
        }
    };
    let mut context = fixture.context;
    if request.vector.id == "sign-request" {
        // PLT-SIGN-002: the request carries the published, non-empty idempotency key, and the
        // Platform refuses the same request without one.
        context.idempotency_key = Some(expected_string(request, "idempotency_key_header")?);
        if context.idempotency_key.as_deref().is_none_or(str::is_empty) {
            return Ok(false);
        }
        let mut anonymous = context.clone();
        anonymous.idempotency_key = None;
        let refused = fixture
            .platform
            .sign(&identity.agent_identity_id, sign_request.clone(), anonymous)
            .await
            .map_err(|error| error.to_string())?;
        if refused.status != 400 {
            return Ok(false);
        }
    } else {
        context.idempotency_key = Some("01J0AEPSIGNINITIAL0000000001".to_owned());
    }
    let response = fixture
        .platform
        .sign(&identity.agent_identity_id, sign_request.clone(), context)
        .await
        .map_err(|error| error.to_string())?;
    let body = success(response.body)?;
    if request.vector.id == "sign-response" {
        // The fixture signs with its own key, so the published document is compared member by
        // member: the window it states, the operation and identity it names, and the `kid` that
        // PLT-SIGN-022 binds to the Agent DID.
        let issued = parse_time(&expected_string(request, "issued_at")?)?;
        let expires = parse_time(&expected_string(request, "expires_at")?)?;
        let assertion = body
            .client_assertion
            .as_deref()
            .ok_or_else(|| "completed Sign response has no assertion".to_owned())?;
        let decoded =
            aep_core::decode_jwt_unverified(assertion).map_err(|error| error.to_string())?;
        return Ok(response.status == 200
            && expected_string(request, "status")? == "completed"
            && body.status == SignStatus::Completed
            && body.jti.as_deref() == Some(expected_string(request, "jti")?.as_str())
            && body.service_did.as_deref()
                == Some(expected_string(request, "service_did")?.as_str())
            && body.agent_did.as_deref() == Some(identity.agent_did.as_str())
            && body.platform_context
                == serde_json::from_value(
                    request
                        .case
                        .expected
                        .get("platform_context")
                        .cloned()
                        .unwrap_or_else(|| json!({})),
                )
                .map_err(|error| error.to_string())?
            && signed_window(&body)? == expires - issued
            && decoded.header.key_id.as_deref() == Some(identity.key_id.as_str()));
    }
    Ok(response.status == 200
        && body.status == SignStatus::Completed
        && body
            .client_assertion
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        && body.jti.as_deref() == Some(sign_request.jti.as_str()))
}

/// The validity window a completed Sign response states.
fn signed_window(body: &SignResponse) -> Result<time::Duration, String> {
    let issued = parse_time(
        body.issued_at
            .as_deref()
            .ok_or_else(|| "completed Sign response has no issued_at".to_owned())?,
    )?;
    let expires = parse_time(
        body.expires_at
            .as_deref()
            .ok_or_else(|| "completed Sign response has no expires_at".to_owned())?,
    )?;
    Ok(expires - issued)
}

async fn pending_sign(request: &AdapterRequest) -> Result<bool, String> {
    let fixture = fixture_with_sign_handler(true, Some(Arc::new(PendingSigner)))?;
    let identity = success(
        fixture
            .platform
            .provision(
                ProvisionRequest {
                    service_did: SERVICE_DID.to_owned(),
                },
                fixture.context.clone(),
            )
            .await
            .map_err(|error| error.to_string())?
            .body,
    )?;
    let response = fixture
        .platform
        .sign(
            &identity.agent_identity_id,
            SignRequest {
                jti: "pending-sign-vector".to_owned(),
                lifetime_seconds: None,
                op: AssertionOperation::Enroll,
                platform_context: BTreeMap::new(),
                resource: None,
                service_did: SERVICE_DID.to_owned(),
            },
            RequestContext {
                idempotency_key: Some(input(request, "idempotency_key_header")?),
                ..fixture.context
            },
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(response.status == 202
        && response.to_json().map_err(|error| error.to_string())?
            == object_value(&request.case.expected))
}

struct PendingSigner;

#[async_trait]
impl aep_platform::SignHandler for PendingSigner {
    async fn sign(
        &self,
        _identity: &IdentityRecord,
        _request: &SignRequest,
        _context: &RequestContext,
    ) -> Result<Option<aep_platform::PlatformResponse<SignResponse>>, PlatformError> {
        Ok(Some(aep_platform::PlatformResponse {
            body: ResponseBody::Success(SignResponse {
                additional: BTreeMap::new(),
                agent_did: None,
                client_assertion: None,
                expires_at: None,
                issued_at: None,
                jti: None,
                platform_context: BTreeMap::from([(
                    "authorization_handle".to_owned(),
                    json!("opaque-value"),
                )]),
                retry_after_seconds: Some("5".to_owned()),
                service_did: None,
                status: SignStatus::Pending,
            }),
            headers: http::HeaderMap::from_iter([(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static(aep_core::MEDIA_TYPE),
            )]),
            status: 202,
        }))
    }
}

/// PLT-IDP-004/005/009: an exact retry returns the stored result for at least the published
/// retention window, and the same key with different material is a conflict.
async fn idempotency(request: &AdapterRequest) -> Result<bool, String> {
    let retention = expected_string(request, "retention_seconds_minimum")?
        .parse::<u64>()
        .map_err(|error| error.to_string())?;
    if expected_string(request, "exact_replay")? != "stored_http_result" {
        return Ok(false);
    }
    let conflict_status = expected_u16(request, "changed_input_or_operation_status")?;
    let conflict_code = expected_string(request, "changed_input_or_operation_code")?;
    let fixture = fixture(true)?;
    let provision_request = ProvisionRequest {
        service_did: SERVICE_DID.to_owned(),
    };
    let first = fixture
        .platform
        .provision(provision_request.clone(), fixture.context.clone())
        .await
        .map_err(|error| error.to_string())?;
    // The retry happens at the far edge of the published retention window.
    let start = fixture.clock.now();
    fixture.clock.set(start + Duration::from_secs(retention))?;
    let mut later = fixture.context.clone();
    later.now = Some(start + Duration::from_secs(retention));
    let replay = fixture
        .platform
        .provision(provision_request, later)
        .await
        .map_err(|error| error.to_string())?;
    let conflict = status_and_code(
        fixture
            .platform
            .provision(
                ProvisionRequest {
                    service_did: "did:web:other.example".to_owned(),
                },
                fixture.context,
            )
            .await
            .map_err(|error| error.to_string())?,
    );
    Ok(first.to_json().map_err(|error| error.to_string())?
        == replay.to_json().map_err(|error| error.to_string())?
        && conflict.0 == conflict_status
        && conflict.1.as_deref() == Some(&conflict_code))
}

/// PLT-VER-006: an `authenticate` verification without a `resource` is not a request the Platform
/// can answer.
async fn missing_resource(request: &AdapterRequest) -> Result<bool, String> {
    if request.case.expected.get("valid") != Some(&Value::Bool(false)) {
        return Ok(false);
    }
    let fixture = fixture(true)?;
    let verification: VerificationRequest = input(request, "request")?;
    let response = fixture
        .platform
        .verify(verification, fixture.context)
        .await
        .map_err(|error| error.to_string())?;
    Ok(response.status == 400
        && matches!(response.body, ResponseBody::Problem(problem) if problem.code == aep_core::ErrorCode::InvalidRequest))
}

/// PLT-VER-002: hosted verification carries the published, non-empty idempotency key, and the
/// Platform refuses the same request without one.
async fn verification_request(request: &AdapterRequest) -> Result<bool, String> {
    let verification: VerificationRequest =
        serde_json::from_value(object_value(&request.case.input))
            .map_err(|error| error.to_string())?;
    let fixture = fixture(true)?;
    let key = expected_string(request, "idempotency_key_header")?;
    if key.is_empty() {
        return Ok(false);
    }
    let authorized = signed_verification_request(&fixture).await?;
    if authorized.op != verification.op || authorized.service_did != verification.service_did {
        return Ok(false);
    }
    let mut anonymous = fixture.context.clone();
    anonymous.idempotency_key = None;
    if fixture
        .platform
        .verify(authorized.clone(), anonymous)
        .await
        .map_err(|error| error.to_string())?
        .status
        != 400
    {
        return Ok(false);
    }
    let mut context = fixture.context.clone();
    context.idempotency_key = Some(key.clone());
    let recognized = fixture
        .platform
        .verify(authorized, context)
        .await
        .map_err(|error| error.to_string())?;
    if recognized.status != 200 || !success(recognized.body)?.verified {
        return Ok(false);
    }
    let mut context = fixture.context;
    context.idempotency_key = Some(format!("{key}-unrecognized"));
    let response = fixture
        .platform
        .verify(verification, context)
        .await
        .map_err(|error| error.to_string())?;
    let body = success(response.body)?;
    Ok(response.status == 200 && !body.verified && body.reason == "not_recognized")
}

async fn signed_verification_request(fixture: &Fixture) -> Result<VerificationRequest, String> {
    let identity = success(
        fixture
            .platform
            .provision(
                ProvisionRequest {
                    service_did: SERVICE_DID.to_owned(),
                },
                fixture.context.clone(),
            )
            .await
            .map_err(|error| error.to_string())?
            .body,
    )?;
    let mut sign_context = fixture.context.clone();
    sign_context.idempotency_key = Some("sign-for-verification".to_owned());
    let signed = success(
        fixture
            .platform
            .sign(
                &identity.agent_identity_id,
                SignRequest {
                    jti: "verification".to_owned(),
                    lifetime_seconds: Some("300".to_owned()),
                    op: AssertionOperation::Enroll,
                    platform_context: BTreeMap::new(),
                    resource: None,
                    service_did: SERVICE_DID.to_owned(),
                },
                sign_context,
            )
            .await
            .map_err(|error| error.to_string())?
            .body,
    )?;
    Ok(VerificationRequest {
        client_assertion: signed
            .client_assertion
            .ok_or_else(|| "signed assertion is missing".to_owned())?,
        op: AssertionOperation::Enroll,
        resource: None,
        service_did: SERVICE_DID.to_owned(),
    })
}

async fn recognized_verification(request: &AdapterRequest) -> Result<bool, String> {
    let fixture = fixture(true)?;
    let verification = signed_verification_request(&fixture).await?;
    let mut verify_context = fixture.context;
    verify_context.idempotency_key = Some("verify-recognized".to_owned());
    let verified = fixture
        .platform
        .verify(verification, verify_context)
        .await
        .map_err(|error| error.to_string())?;
    let actual = verified.to_json().map_err(|error| error.to_string())?;
    let expected = object_value(&request.case.expected);
    if verified.status != 200 || actual != expected {
        return Err(format!(
            "recognized verification mismatch: status={} actual={} expected={}",
            verified.status, actual, expected
        ));
    }
    Ok(true)
}

/// PLT-VER-008: an unrecognized answer carries the published reason and nothing about the
/// identity the caller asked about.
async fn unrecognized_verification(request: &AdapterRequest) -> Result<bool, String> {
    let service_did = expected_string(request, "service_did")?;
    let reason = expected_string(request, "reason")?;
    if request.case.expected.get("verified") != Some(&Value::Bool(false)) {
        return Ok(false);
    }
    let fixture = fixture(true)?;
    let response = fixture
        .platform
        .verify(
            VerificationRequest {
                client_assertion: "invalid".to_owned(),
                op: AssertionOperation::Enroll,
                resource: None,
                service_did: service_did.clone(),
            },
            fixture.context,
        )
        .await
        .map_err(|error| error.to_string())?;
    let body = success(response.body)?;
    Ok(response.status == 200
        && !body.verified
        && body.reason == reason
        && body.service_did == service_did
        && body.agent_did.is_none()
        && body.agent_identity_id.is_none()
        && body.status.is_none())
}

/// One string member of a vector's expectation, named so that a vector change is reported rather
/// than silently passing.
pub(crate) fn expected_string(request: &AdapterRequest, name: &str) -> Result<String, String> {
    request
        .case
        .expected
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("expectation is missing the {name:?} member"))
}

pub(crate) fn expected_u16(request: &AdapterRequest, name: &str) -> Result<u16, String> {
    request
        .case
        .expected
        .get(name)
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .ok_or_else(|| format!("expectation is missing the {name:?} member"))
}

pub(crate) fn expected_member(request: &AdapterRequest, name: &str) -> Result<Value, String> {
    request
        .case
        .expected
        .get(name)
        .cloned()
        .ok_or_else(|| format!("expectation is missing the {name:?} member"))
}

/// The HTTP status a Platform response carries, with the AEP error code when it is a refusal.
fn status_and_code<T>(response: aep_platform::PlatformResponse<T>) -> (u16, Option<String>) {
    let code = match &response.body {
        ResponseBody::Problem(problem) => Some(problem.code.as_str().to_owned()),
        ResponseBody::Success(_) => None,
    };
    (response.status, code)
}

fn parse_time(value: &str) -> Result<OffsetDateTime, String> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|error| error.to_string())
}

#[cfg(test)]
mod hosted_service_tests {
    use super::*;
    use aep_core::{HttpRequest, HttpResponse, HttpTransport, TransportError};
    use aep_service::{
        AuthenticatedCommandOptions, ClientAssertionVerificationContext, ClientAssertionVerifier,
        HostedPlatformClientAssertionVerifier, HostedPlatformClientAssertionVerifierOptions,
        IdempotentCommandOptions, ProtectedResourceAuthentication, ProtectedResourceRequest,
        Service, ServiceOptions,
    };
    use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
    use url::Url;

    struct ServiceClock(Arc<FixedClock>);
    impl aep_service::Clock for ServiceClock {
        fn now(&self) -> OffsetDateTime {
            self.0.now()
        }
    }

    struct PlatformTransport {
        platform: Arc<Platform>,
        clock: Arc<FixedClock>,
        requests: Mutex<Vec<HttpRequest>>,
    }
    #[async_trait]
    impl HttpTransport for PlatformTransport {
        async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
            assert_eq!(request.method, Method::POST);
            assert_eq!(
                request.url.as_str(),
                "https://p.example/v1/aep/verifications"
            );
            assert_eq!(
                request.headers[header::AUTHORIZATION],
                "Bearer service-token"
            );
            let key = request.headers["idempotency-key"]
                .to_str()
                .expect("key")
                .to_owned();
            let verification = serde_json::from_slice(&request.body).expect("verification request");
            let url = request.url.clone();
            self.requests.lock().expect("requests").push(request);
            let response = self
                .platform
                .verify(
                    verification,
                    RequestContext {
                        authorization: Some("Bearer service-token".into()),
                        idempotency_key: Some(key),
                        principal: "service-account".into(),
                        now: Some(self.clock.now()),
                        request_id: None,
                    },
                )
                .await
                .map_err(|e| TransportError::new(e.to_string()))?;
            Ok(HttpResponse {
                status: StatusCode::from_u16(response.status).expect("status"),
                headers: response.headers.clone(),
                body: serde_json::to_vec(&response.to_json().expect("response")).expect("JSON"),
                final_url: url,
            })
        }
    }

    async fn assertion(
        fixture: &Fixture,
        identity: &aep_platform::AgentIdentity,
        op: AssertionOperation,
        resource: Option<&str>,
        jti: &str,
    ) -> String {
        success(
            fixture
                .platform
                .sign(
                    &identity.agent_identity_id,
                    SignRequest {
                        jti: jti.into(),
                        lifetime_seconds: Some("300".into()),
                        op,
                        platform_context: BTreeMap::new(),
                        resource: resource.map(str::to_owned),
                        service_did: SERVICE_DID.into(),
                    },
                    RequestContext {
                        idempotency_key: Some(format!("sign-{jti}")),
                        ..fixture.context.clone()
                    },
                )
                .await
                .expect("sign")
                .body,
        )
        .expect("signed response")
        .client_assertion
        .expect("assertion")
    }

    #[tokio::test]
    async fn separate_service_account_verifies_real_assertions_without_bypassing_service_replay() {
        let fixture = fixture(true).expect("fixture");
        let enrollment = signed_verification_request(&fixture)
            .await
            .expect("real enrollment assertion");
        let identity = success(
            fixture
                .platform
                .provision(
                    ProvisionRequest {
                        service_did: SERVICE_DID.into(),
                    },
                    fixture.context.clone(),
                )
                .await
                .expect("identity")
                .body,
        )
        .expect("identity replay");
        let transport = Arc::new(PlatformTransport {
            platform: fixture.platform.clone(),
            clock: fixture.clock.clone(),
            requests: Mutex::new(vec![]),
        });
        let mut options = HostedPlatformClientAssertionVerifierOptions::new(
            "https://p.example/v1/aep/verifications",
        );
        options.authorization = Some("Bearer service-token".into());
        options.transport = Some(transport.clone());
        let verifier =
            Arc::new(HostedPlatformClientAssertionVerifier::new(options).expect("hosted verifier"));
        let mut options = ServiceOptions::new(SERVICE_DID, verifier.clone());
        options.authentication_methods = vec![aep_core::AuthenticationMethod::AepJwt];
        options.clock = Some(Arc::new(ServiceClock(fixture.clock.clone())));
        let service = Service::new(options).expect("Service");
        let body = serde_json::to_vec(&json!({"agent_did":identity.agent_did})).expect("body");
        let enrolled = service
            .enroll(
                &body,
                IdempotentCommandOptions {
                    client_assertion: enrollment.client_assertion,
                    idempotency_key: "enroll-command".into(),
                },
            )
            .await
            .expect("enroll");
        assert_eq!(enrolled.status, 200);

        let status = assertion(
            &fixture,
            &identity,
            AssertionOperation::Status,
            None,
            "status",
        )
        .await;
        let options = AuthenticatedCommandOptions {
            client_assertion: status.clone(),
        };
        assert_eq!(
            service
                .status(options.clone())
                .await
                .expect("status")
                .status,
            200
        );
        assert_eq!(
            service
                .status(options)
                .await
                .expect("replay rejected")
                .status,
            401
        );
        {
            let requests = transport.requests.lock().expect("requests");
            assert_eq!(requests.len(), 3);
            assert_eq!(requests[1].body, requests[2].body);
            assert_eq!(
                requests[1].headers["idempotency-key"],
                requests[2].headers["idempotency-key"]
            );
        }

        let resource = "https://api.service.example/items/one?color=black";
        let token = assertion(
            &fixture,
            &identity,
            AssertionOperation::Authenticate,
            Some(resource),
            "resource",
        )
        .await;
        let protected = |url: &str| ProtectedResourceRequest {
            headers: HeaderMap::from_iter([(
                header::AUTHORIZATION,
                HeaderValue::from_str(&format!("AEP {token}")).expect("header"),
            )]),
            method: Method::GET,
            url: Url::parse(url).expect("URL"),
        };
        assert!(matches!(
            service
                .authenticate_protected_resource(protected(resource))
                .await
                .expect("authenticate"),
            ProtectedResourceAuthentication::Authenticated(_)
        ));
        for url in [resource, "https://api.service.example/items/two"] {
            assert!(
                matches!(service.authenticate_protected_resource(protected(url)).await.expect("rejected"),ProtectedResourceAuthentication::Rejected(response) if response.status==401)
            );
        }

        let service_context = RequestContext {
            principal: "service-account".into(),
            idempotency_key: Some("forbidden".into()),
            ..fixture.context.clone()
        };
        let denied = fixture
            .platform
            .sign(
                &identity.agent_identity_id,
                SignRequest {
                    jti: "forbidden".into(),
                    lifetime_seconds: None,
                    op: AssertionOperation::Enroll,
                    platform_context: BTreeMap::new(),
                    resource: None,
                    service_did: SERVICE_DID.into(),
                },
                service_context.clone(),
            )
            .await
            .expect("denied");
        assert_eq!(denied.status, 404);
        assert_eq!(
            fixture
                .platform
                .update_identity(
                    &identity.agent_identity_id,
                    LifecycleRequest {
                        status: ManagedAgentStatus::Suspended
                    },
                    &service_context
                )
                .await
                .expect("denied")
                .status,
            404
        );
        assert_eq!(
            fixture
                .platform
                .get_identity(&identity.agent_identity_id, &service_context)
                .await
                .expect("denied")
                .status,
            404
        );

        for (principal, authorized) in [("", true), ("service-account", false)] {
            fixture.authorizer.0.store(authorized, Ordering::SeqCst);
            let denied = fixture
                .platform
                .verify(
                    VerificationRequest {
                        client_assertion: status.clone(),
                        op: AssertionOperation::Status,
                        resource: None,
                        service_did: SERVICE_DID.into(),
                    },
                    RequestContext {
                        principal: principal.into(),
                        idempotency_key: Some("denied".into()),
                        ..fixture.context.clone()
                    },
                )
                .await
                .expect("denied");
            assert!(!success(denied.body).expect("unrecognized").verified);
        }
        assert!(
            verifier
                .verify(ClientAssertionVerificationContext {
                    assertion: status,
                    current_time: fixture.clock.now(),
                    idempotency_key: None,
                    operation: AssertionOperation::Status,
                    resource: None,
                    service_did: SERVICE_DID.into(),
                    signing_algorithms: vec![SigningAlgorithm::Es256]
                })
                .await
                .is_err()
        );
    }
}
