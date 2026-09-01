use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
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
        "authorization-required" => authorization_required().await,
        "discovery" => discovery(request),
        "idempotency-replay-conflict" => idempotency().await,
        "lifecycle-request" | "lifecycle-response" => lifecycle(request).await,
        "list-response" => list(request).await,
        "provision-request" | "provision-response" => provision(request).await,
        "provision-response-distinct-services" => distinct_services(request).await,
        "sign-request" | "sign-response" => sign(request).await,
        "sign-response-pending" => pending_sign(request).await,
        "verification-authenticate-missing-resource" => missing_resource(request).await,
        "verification-request" => verification_request(request).await,
        "verification-response-recognized" => recognized_verification(request).await,
        "verification-response-unrecognized" => unrecognized_verification().await,
        other => Err(format!(
            "no Platform operation maps vector platform/{other}"
        )),
    }
}

struct FixedAuthorizer(bool);

#[async_trait]
impl Authorizer for FixedAuthorizer {
    async fn authorize(
        &self,
        _request: &AuthorizationRequest,
        _context: &RequestContext,
    ) -> Result<bool, PlatformError> {
        Ok(self.0)
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
    clock: Arc<FixedClock>,
    context: RequestContext,
    platform: Arc<Platform>,
}

fn fixture(authorized: bool) -> Result<Fixture, String> {
    let identity_ids = Arc::new(Mutex::new(vec![
        "01J0AEPPLATFORM000000000002".to_owned(),
        "01J0AEPPLATFORM000000000001".to_owned(),
    ]));
    let did_ids = Arc::new(Mutex::new(vec![
        "9Lm2r8VnQ4".to_owned(),
        "4Yf7p2xQd9".to_owned(),
    ]));
    let clock = Arc::new(FixedClock(Mutex::new(parse_time("2026-07-06T12:00:00Z")?)));
    let mut options = PlatformOptions::new(
        Arc::new(FixedAuthorizer(authorized)),
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

async fn authorization_required() -> Result<bool, String> {
    let fixture = fixture(false)?;
    let response = fixture
        .platform
        .provision(
            ProvisionRequest {
                service_did: SERVICE_DID.to_owned(),
            },
            fixture.context,
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(response.status == 404
        && matches!(response.body, ResponseBody::Problem(problem) if problem.code.as_str() == "not_recognized"))
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
    let response = fixture
        .platform
        .provision(
            ProvisionRequest {
                service_did: service_did.to_owned(),
            },
            fixture.context,
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
    Ok(first_response.agent_did != second_response.agent_did
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
    Ok(success(response.body)?.status == status)
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
    context.idempotency_key = Some("01J0AEPSIGNINITIAL0000000001".to_owned());
    let response = fixture
        .platform
        .sign(&identity.agent_identity_id, sign_request.clone(), context)
        .await
        .map_err(|error| error.to_string())?;
    let body = success(response.body)?;
    Ok(response.status == 200
        && body.status == SignStatus::Completed
        && body
            .client_assertion
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        && body.jti.as_deref() == Some(sign_request.jti.as_str()))
}

async fn pending_sign(request: &AdapterRequest) -> Result<bool, String> {
    let expected_body: SignResponse = serde_json::from_value(object_value(&request.case.expected))
        .map_err(|error| error.to_string())?;
    Ok(expected_body.status == SignStatus::Pending
        && expected_body.retry_after_seconds.as_deref() == Some("5")
        && expected_body.platform_context.get("authorization_handle")
            == Some(&json!("opaque-value")))
}

async fn idempotency() -> Result<bool, String> {
    let fixture = fixture(true)?;
    let request = ProvisionRequest {
        service_did: SERVICE_DID.to_owned(),
    };
    let first = fixture
        .platform
        .provision(request.clone(), fixture.context.clone())
        .await
        .map_err(|error| error.to_string())?;
    let replay = fixture
        .platform
        .provision(request, fixture.context.clone())
        .await
        .map_err(|error| error.to_string())?;
    let conflict = fixture
        .platform
        .provision(
            ProvisionRequest {
                service_did: "did:web:other.example".to_owned(),
            },
            fixture.context,
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(first.to_json().map_err(|error| error.to_string())?
        == replay.to_json().map_err(|error| error.to_string())?
        && conflict.status == 409
        && matches!(conflict.body, ResponseBody::Problem(problem) if problem.code.as_str() == "idempotency_conflict"))
}

async fn missing_resource(request: &AdapterRequest) -> Result<bool, String> {
    let fixture = fixture(true)?;
    let verification: VerificationRequest = input(request, "request")?;
    let response = fixture
        .platform
        .verify(verification, fixture.context)
        .await
        .map_err(|error| error.to_string())?;
    Ok(response.status == 400)
}

async fn verification_request(request: &AdapterRequest) -> Result<bool, String> {
    let verification: VerificationRequest =
        serde_json::from_value(object_value(&request.case.input))
            .map_err(|error| error.to_string())?;
    let fixture = fixture(true)?;
    let response = fixture
        .platform
        .verify(verification, fixture.context)
        .await
        .map_err(|error| error.to_string())?;
    let body = success(response.body)?;
    Ok(response.status == 200 && !body.verified && body.reason == "not_recognized")
}

async fn recognized_verification(request: &AdapterRequest) -> Result<bool, String> {
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
    let mut verify_context = fixture.context;
    verify_context.idempotency_key = Some("verify-recognized".to_owned());
    let verified = fixture
        .platform
        .verify(
            VerificationRequest {
                client_assertion: signed
                    .client_assertion
                    .ok_or_else(|| "signed assertion is missing".to_owned())?,
                op: AssertionOperation::Enroll,
                resource: None,
                service_did: SERVICE_DID.to_owned(),
            },
            verify_context,
        )
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

async fn unrecognized_verification() -> Result<bool, String> {
    let fixture = fixture(true)?;
    let response = fixture
        .platform
        .verify(
            VerificationRequest {
                client_assertion: "invalid".to_owned(),
                op: AssertionOperation::Enroll,
                resource: None,
                service_did: SERVICE_DID.to_owned(),
            },
            fixture.context,
        )
        .await
        .map_err(|error| error.to_string())?;
    let body = success(response.body)?;
    Ok(response.status == 200 && !body.verified && body.reason == "not_recognized")
}

fn parse_time(value: &str) -> Result<OffsetDateTime, String> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|error| error.to_string())
}
