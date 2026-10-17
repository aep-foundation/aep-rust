use std::sync::Arc;

use aep_core::{AssertionOperation, ClientAssertionClaims, SigningAlgorithm};
use aep_service::{
    ClientAssertionVerificationContext, ClientAssertionVerifier,
    HostedPlatformClientAssertionVerifier, HostedPlatformClientAssertionVerifierOptions,
    ProtectedResourceAuthentication, ProtectedResourceRequest, Service, ServiceOptions,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use serde_json::{Value, json};
use time::OffsetDateTime;
use url::Url;

use crate::{AdapterRequest, expected, input, object_value, role::ScriptedTransport};

const ENDPOINT: &str = "https://p.example/v1/aep/verifications";
const AGENT: &str = "did:web:p.example:a:4Yf7p2xQd9";
const ISSUED_AT: i64 = 1783425600;

pub async fn evaluate(request: &AdapterRequest) -> Result<bool, String> {
    match request.vector.id.as_str() {
        "verification-request" => verification_request(request).await,
        "verification-response-recognized" | "verification-response-unrecognized" => {
            verification_response(request).await
        }
        "verification-authenticate-missing-resource" => missing_resource(request).await,
        other => Err(format!("no Service hosted operation maps vector {other}")),
    }
}

fn verifier(
    transport: Arc<ScriptedTransport>,
) -> Result<HostedPlatformClientAssertionVerifier, String> {
    let mut options = HostedPlatformClientAssertionVerifierOptions::new(ENDPOINT);
    options.transport = Some(transport);
    HostedPlatformClientAssertionVerifier::new(options).map_err(|error| error.to_string())
}

fn context(
    assertion: String,
    operation: AssertionOperation,
    service_did: String,
) -> ClientAssertionVerificationContext {
    ClientAssertionVerificationContext {
        assertion,
        current_time: OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(ISSUED_AT),
        idempotency_key: None,
        operation,
        resource: None,
        service_did,
        signing_algorithms: vec![SigningAlgorithm::Es256],
    }
}

async fn verification_request(request: &AdapterRequest) -> Result<bool, String> {
    let transport = Arc::new(ScriptedTransport::default());
    let verifier = verifier(transport.clone())?;
    let operation = input(request, "op")?;
    let service_did: String = input(request, "service_did")?;
    let illustrated: String = input(request, "client_assertion")?;
    // The published token ends in a literal placeholder signature; sign its unchanged claims.
    let mut parts = illustrated.split('.');
    let token_header: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(parts.next().ok_or("missing JWT header")?)
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if token_header.get("alg").and_then(Value::as_str) != Some("ES256")
        || token_header
            .get("typ")
            .is_some_and(|value| value.as_str() != Some("JWT"))
    {
        return Err("hosted request fixture signer requires an ES256 JWT header".into());
    }
    let payload: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(parts.next().ok_or("missing JWT payload")?)
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let signed = crate::assertions::sign_raw(
        payload.clone(),
        token_header.get("kid").and_then(Value::as_str),
        "JWT",
    )?;
    let mut outgoing_body = object_value(&request.case.input);
    outgoing_body["client_assertion"] = json!(signed);
    let mut context = context(signed, operation, service_did.clone());
    context.idempotency_key = Some(expected(request, "idempotency_key_header")?);
    if context
        .idempotency_key
        .as_ref()
        .is_none_or(|key| key.is_empty())
    {
        return Ok(false);
    }
    let recognized = json!({
        "agent_did":payload.get("sub"), "op":operation, "reason":"verified",
        "service_did":service_did, "verified":true
    });
    for _ in 0..2 {
        transport.push_json_at(
            StatusCode::OK,
            recognized.clone(),
            Url::parse(ENDPOINT).map_err(|error| error.to_string())?,
        )?;
        verifier
            .verify(context.clone())
            .await
            .map_err(|error| error.to_string())?;
    }
    let requests = transport.requests()?;
    let [first, second] = requests.as_slice() else {
        return Ok(false);
    };
    let first_key = first
        .headers
        .get("idempotency-key")
        .and_then(|key| key.to_str().ok());
    // The vector's key illustrates a nonempty header; verification keys bind the actual body.
    Ok(first_key.is_some_and(|key| !key.is_empty())
        && first.headers.get("idempotency-key") == second.headers.get("idempotency-key")
        && requests.iter().all(|outgoing| {
            outgoing.method == Method::POST
                && outgoing.url.as_str() == ENDPOINT
                && outgoing
                    .headers
                    .get(header::ACCEPT)
                    .is_some_and(|value| value == aep_core::MEDIA_TYPE)
                && outgoing
                    .headers
                    .get(header::CONTENT_TYPE)
                    .is_some_and(|value| value == aep_core::MEDIA_TYPE)
                && serde_json::from_slice::<Value>(&outgoing.body).ok()
                    == Some(outgoing_body.clone())
        }))
}

fn assertion(
    service_did: &str,
    agent_did: &str,
    operation: AssertionOperation,
) -> Result<String, String> {
    // Raw signing also permits the intentionally missing authenticate resource in its vector.
    crate::assertions::sign_raw(
        json!({
            "aud":service_did, "exp":ISSUED_AT+300, "iat":ISSUED_AT,
            "iss":agent_did, "jti":"hosted-service-vector", "op":operation, "sub":agent_did
        }),
        Some(agent_did),
        "JWT",
    )
}

async fn verification_response(request: &AdapterRequest) -> Result<bool, String> {
    let service_did: String = expected(request, "service_did")?;
    let recognized: bool = expected(request, "verified")?;
    let agent_did = request
        .case
        .expected
        .get("agent_did")
        .and_then(Value::as_str)
        .unwrap_or(AGENT);
    let operation = request
        .case
        .expected
        .get("op")
        .map(|op| serde_json::from_value(op.clone()).map_err(|error| error.to_string()))
        .transpose()?
        .unwrap_or(AssertionOperation::Enroll);
    let context = context(
        assertion(&service_did, agent_did, operation)?,
        operation,
        service_did,
    );
    let transport = Arc::new(ScriptedTransport::default());
    transport.push_json_at(
        StatusCode::OK,
        object_value(&request.case.expected),
        Url::parse(ENDPOINT).map_err(|error| error.to_string())?,
    )?;
    let result = verifier(transport.clone())?.verify(context).await;
    if transport.requests()?.len() != 1 {
        return Ok(false);
    }
    match result {
        Ok(ClientAssertionClaims { sub, op, .. }) => {
            Ok(recognized && sub == agent_did && op == operation)
        }
        Err(_) => Ok(!recognized),
    }
}

async fn missing_resource(request: &AdapterRequest) -> Result<bool, String> {
    let body: Value = input(request, "request")?;
    let service_did = body
        .get("service_did")
        .and_then(Value::as_str)
        .ok_or("missing Service DID")?;
    let operation: AssertionOperation =
        serde_json::from_value(body.get("op").cloned().ok_or("missing operation")?)
            .map_err(|error| error.to_string())?;
    let transport = Arc::new(ScriptedTransport::default());
    let mut options = ServiceOptions::new(service_did, Arc::new(verifier(transport.clone())?));
    options.authentication_methods = vec![aep_core::AuthenticationMethod::AepJwt];
    options.clock = Some(Arc::new(FixedClock));
    let service = Service::new(options).map_err(|error| error.to_string())?;
    let assertion = assertion(service_did, AGENT, operation)?;
    let result = service
        .authenticate_protected_resource(ProtectedResourceRequest {
            headers: HeaderMap::from_iter([(
                header::AUTHORIZATION,
                HeaderValue::from_str(&format!("AEP {assertion}"))
                    .map_err(|error| error.to_string())?,
            )]),
            method: Method::GET,
            url: Url::parse("https://api.service.example/orders")
                .map_err(|error| error.to_string())?,
        })
        .await
        .map_err(|error| error.to_string())?;
    Ok(!expected::<bool>(request, "valid")?
        && body.get("resource").is_none()
        && matches!(result, ProtectedResourceAuthentication::Rejected(response) if response.status == 401)
        && transport.requests()?.is_empty())
}

struct FixedClock;
impl aep_service::Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(ISSUED_AT)
    }
}
