use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use aep_agent::{
    AgentError, AgentIdentity, Clock, IdentityProvider, IdentityRequest, Inspection,
    PlatformContextProvider, PlatformIdempotencyKeyProvider, PlatformIdentityProvider,
    PlatformIdentityProviderOptions, PlatformPendingSign, PlatformPendingSignResolver,
};
use aep_core::{
    AssertionOperation, ClientAssertionClaims, HttpRequest, HttpResponse, SigningAlgorithm,
};
use async_trait::async_trait;
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;

use crate::{AdapterRequest, expected, input, object_value, role::ScriptedTransport};

const ORIGIN: &str = "https://p.example";
const LIST: &str = "/v1/aep/agent-identities";
const SERVICE: &str = "did:web:api.service.example";
const SIGN_KEY: &str = "01J0AEPSIGNINITIAL0000000001";

struct FixedClock;
impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::parse("2026-07-06T12:00:00Z", &Rfc3339).expect("fixture time")
    }
}

struct Keys(Mutex<std::collections::VecDeque<String>>);
impl PlatformIdempotencyKeyProvider for Keys {
    fn create_key(&self) -> Result<String, AgentError> {
        self.0
            .lock()
            .expect("keys lock")
            .pop_front()
            .ok_or_else(|| AgentError::Identity("unexpected idempotency key request".into()))
    }
}

struct Context(Value);
#[async_trait]
impl PlatformContextProvider for Context {
    async fn context(
        &self,
        _: &AgentIdentity,
        _: &ClientAssertionClaims,
    ) -> Result<BTreeMap<String, Value>, AgentError> {
        serde_json::from_value(self.0.clone()).map_err(AgentError::from)
    }
}

#[derive(Default)]
struct Pending(Mutex<Vec<PlatformPendingSign>>);
#[async_trait]
impl PlatformPendingSignResolver for Pending {
    async fn resolve(
        &self,
        pending: PlatformPendingSign,
    ) -> Result<BTreeMap<String, Value>, AgentError> {
        let context = pending.platform_context.clone();
        self.0.lock().expect("pending lock").push(pending);
        Ok(context)
    }
}

fn discovery() -> Value {
    json!({"aep_version":"1.0", "endpoints": {
        "hosted_verification":"/v1/aep/verifications", "lifecycle":"/v1/aep/agent-identities/{agent_identity_id}",
        "list":LIST, "provision":LIST, "sign":"/v1/aep/agent-identities/{agent_identity_id}/sign"},
        "http":{"endpoint_base":"/v1/aep"},
        "identity":{"did_methods":["did:web"],"did_url_template":"https://p.example/a/{agent_did_id}/did.json"},
        "platform":{"did":"did:web:p.example","hosted_verification":true,"name":"Example Platform"},
        "signing":{"algorithms":["ES256"],"default_lifetime_seconds":"300"}})
}

fn identity(service: &str) -> Value {
    json!({"agent_did":"did:web:p.example:a:4Yf7p2xQd9",
        "agent_identity_id":"pai_01J0AEPPLATFORM000000000001",
        "created_at":"2026-07-06T12:00:00Z", "updated_at":"2026-07-06T12:00:00Z",
        "did_document_url":"https://p.example/a/4Yf7p2xQd9/did.json",
        "key_id":"did:web:p.example:a:4Yf7p2xQd9", "service_did":service,
        "signing_algorithms":["ES256"],"status":"active"})
}

fn provider(
    transport: Arc<ScriptedTransport>,
    keys: Vec<String>,
    context: Value,
    pending: Option<Arc<Pending>>,
) -> Result<Arc<PlatformIdentityProvider>, String> {
    let mut options = PlatformIdentityProviderOptions::new(ORIGIN);
    options.transport = Some(transport);
    options.clock = Some(Arc::new(FixedClock));
    options.authorization = Some("Bearer platform-secret".into());
    options.idempotency_keys = Some(Arc::new(Keys(Mutex::new(keys.into()))));
    options.platform_context = Some(Arc::new(Context(context)));
    options.pending_sign_resolver =
        pending.map(|value| value as Arc<dyn PlatformPendingSignResolver>);
    PlatformIdentityProvider::new(options).map_err(|error| error.to_string())
}

fn response(
    transport: &ScriptedTransport,
    path: &str,
    status: StatusCode,
    body: Value,
) -> Result<(), String> {
    transport.push_json_at(
        status,
        body,
        Url::parse(&format!("{ORIGIN}{path}")).map_err(|e| e.to_string())?,
    )
}

fn setup(document: Value) -> Result<Arc<ScriptedTransport>, String> {
    let transport = Arc::new(ScriptedTransport::default());
    response(
        &transport,
        "/.well-known/aep-platform",
        StatusCode::OK,
        document,
    )?;
    Ok(transport)
}

async fn provision(
    provider: &PlatformIdentityProvider,
    service: &str,
) -> Result<AgentIdentity, AgentError> {
    let url = Url::parse("https://api.service.example/")?;
    let inspection = Inspection {
        document: serde_json::from_value(crate::role::inspect_document_for(service))?,
        service_url: url.clone(),
        inspect_url: url.join("/.well-known/aep")?,
        final_url: url,
        cache_control: None,
        etag: None,
        last_modified: None,
    };
    provider
        .get_or_create_identity(IdentityRequest { inspection })
        .await
}

fn identity_matches(actual: &AgentIdentity, wire: &Value) -> bool {
    actual.agent_did == wire["agent_did"]
        && actual.service_did == wire["service_did"]
        && serde_json::to_value(&actual.signing_algorithms)
            .ok()
            .as_ref()
            == Some(&wire["signing_algorithms"])
        && [
            "agent_identity_id",
            "created_at",
            "updated_at",
            "did_document_url",
            "key_id",
            "status",
        ]
        .into_iter()
        .all(|key| actual.metadata.get(key).map(String::as_str) == wire[key].as_str())
}

fn requests_valid(requests: &[HttpRequest]) -> bool {
    !requests.is_empty()
        && requests.iter().all(|request| {
            request.url.origin().ascii_serialization() == ORIGIN
                && request
                    .headers
                    .get(header::ACCEPT)
                    .is_some_and(|value| value == aep_core::MEDIA_TYPE)
                && if request.url.path() == "/.well-known/aep-platform" {
                    request.method == Method::GET
                        && !request.headers.contains_key(header::AUTHORIZATION)
                } else {
                    request
                        .headers
                        .get(header::AUTHORIZATION)
                        .is_some_and(|value| value == "Bearer platform-secret")
                        && if request.method == Method::POST {
                            request
                                .headers
                                .get(header::CONTENT_TYPE)
                                .is_some_and(|value| value == aep_core::MEDIA_TYPE)
                                && request
                                    .headers
                                    .get("idempotency-key")
                                    .is_some_and(|value| !value.is_empty())
                        } else {
                            request.method == Method::GET
                                && !request.headers.contains_key("idempotency-key")
                        }
                }
        })
}

pub async fn evaluate(request: &AdapterRequest) -> Result<bool, String> {
    match request.vector.id.as_str() {
        "discovery" | "list-response" => listing(request).await,
        "provision-request" | "provision-response" | "provision-response-distinct-services" => {
            provisioning(request).await
        }
        "sign-request" | "sign-response" | "sign-response-pending" => signing(request).await,
        "idempotency-replay-conflict" => conflict(request).await,
        other => Err(format!("no hosted Agent operation maps vector {other}")),
    }
}

async fn listing(request: &AdapterRequest) -> Result<bool, String> {
    let document = if request.vector.id == "discovery" {
        object_value(&request.case.expected)
    } else {
        discovery()
    };
    let wire = if request.vector.id == "list-response" {
        object_value(&request.case.expected)
    } else {
        json!({"count":"1","total":"1","data":[identity(SERVICE)]})
    };
    let service = wire["data"][0]["service_did"]
        .as_str()
        .ok_or("missing Service")?;
    let transport = setup(document)?;
    response(
        &transport,
        &format!(
            "{LIST}?descending=true&limit=100&service_did={}",
            url::form_urlencoded::byte_serialize(service.as_bytes()).collect::<String>()
        ),
        StatusCode::OK,
        wire.clone(),
    )?;
    let result = provider(transport.clone(), vec![], json!({}), None)?
        .find_identity_by_service_did(service)
        .await
        .map_err(|e| e.to_string())?;
    let requests = transport.requests()?;
    Ok(result
        .as_ref()
        .is_some_and(|actual| identity_matches(actual, &wire["data"][0]))
        && requests_valid(&requests)
        && requests.len() == 2
        && requests[1].url.path() == LIST
        && requests[1]
            .url
            .query_pairs()
            .any(|(key, value)| key == "service_did" && value == service))
}

async fn provisioning(request: &AdapterRequest) -> Result<bool, String> {
    let distinct = request.vector.id == "provision-response-distinct-services";
    let cases = if distinct {
        vec![
            (
                request.case.input["first_request"]["service_did"].clone(),
                request.case.expected["first_response"].clone(),
                request.case.input["first_request"]["idempotency_key_header"].clone(),
            ),
            (
                request.case.input["second_request"]["service_did"].clone(),
                request.case.expected["second_response"].clone(),
                request.case.input["second_request"]["idempotency_key_header"].clone(),
            ),
        ]
    } else if request.vector.id == "provision-response" {
        vec![(
            request.case.expected["service_did"].clone(),
            object_value(&request.case.expected),
            json!("provision"),
        )]
    } else {
        vec![(
            request.case.input["service_did"].clone(),
            identity(&input::<String>(request, "service_did")?),
            request.case.expected["idempotency_key_header"].clone(),
        )]
    };
    let transport = setup(discovery())?;
    let keys = cases
        .iter()
        .map(|(_, _, key)| {
            key.as_str()
                .map(str::to_owned)
                .ok_or("missing key".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let provider = provider(transport.clone(), keys.clone(), json!({}), None)?;
    let mut results = Vec::new();
    for (service, wire, _) in &cases {
        let service = service.as_str().ok_or("missing Service")?;
        response(
            &transport,
            &format!(
                "{LIST}?descending=true&limit=100&service_did={}",
                url::form_urlencoded::byte_serialize(service.as_bytes()).collect::<String>()
            ),
            StatusCode::OK,
            json!({"count":"0","total":"0","data":[]}),
        )?;
        response(&transport, LIST, StatusCode::CREATED, wire.clone())?;
        let actual = provision(&provider, service)
            .await
            .map_err(|e| e.to_string())?;
        if !identity_matches(&actual, wire) {
            return Ok(false);
        }
        results.push(actual);
    }
    let requests = transport.requests()?;
    let posts = requests
        .iter()
        .filter(|request| request.method == Method::POST)
        .collect::<Vec<_>>();
    Ok(requests_valid(&requests)
        && posts.len() == cases.len()
        && posts
            .iter()
            .zip(cases.iter().zip(keys))
            .all(|(request, ((service, _, _), key))| {
                request.url.path() == LIST
                    && request.headers["idempotency-key"] == key
                    && serde_json::from_slice::<Value>(&request.body).ok()
                        == Some(json!({"service_did":service}))
            })
        && (!distinct
            || (results[0].agent_did != results[1].agent_did
                && results[0].service_did != results[1].service_did)))
}

async fn signing(request: &AdapterRequest) -> Result<bool, String> {
    let wire_identity = identity(SERVICE);
    let pending = request.vector.id == "sign-response-pending";
    let body = if request.vector.id == "sign-request" {
        object_value(&request.case.input)
    } else {
        json!({"jti":request.case.expected.get("jti").cloned().unwrap_or(json!("01J0AEPASSERTION0000000001")),
            "lifetime_seconds":"300","op":"enroll","platform_context":{"authorization_handle":"opaque-value"},"service_did":SERVICE})
    };
    let initial_key = if request.vector.id == "sign-request" {
        expected::<String>(request, "idempotency_key_header")?
    } else if pending {
        input::<String>(request, "idempotency_key_header")?
    } else {
        SIGN_KEY.into()
    };
    let transport = setup(discovery())?;
    let list_url =
        format!("{LIST}?descending=true&limit=100&service_did=did%3Aweb%3Aapi.service.example");
    response(
        &transport,
        &list_url,
        StatusCode::OK,
        json!({"count":"1","total":"1","data":[wire_identity.clone()]}),
    )?;
    let continuation = Arc::new(Pending::default());
    let provider = provider(
        transport.clone(),
        vec![initial_key.clone(), "final-key".into()],
        body["platform_context"].clone(),
        Some(continuation.clone()),
    )?;
    let agent = provider
        .find_identity_by_service_did(SERVICE)
        .await
        .map_err(|e| e.to_string())?
        .ok_or("missing identity")?;
    let claims = ClientAssertionClaims {
        additional: BTreeMap::new(),
        aud: SERVICE.into(),
        exp: FixedClock.now().unix_timestamp() + 300,
        iat: FixedClock.now().unix_timestamp(),
        iss: agent.agent_did.clone(),
        sub: agent.agent_did.clone(),
        jti: body["jti"].as_str().ok_or("missing jti")?.into(),
        op: serde_json::from_value::<AssertionOperation>(body["op"].clone())
            .map_err(|e| e.to_string())?,
        resource: None,
    };
    let sign_url = format!(
        "{LIST}/{}/sign",
        agent.metadata["agent_identity_id"].replace('_', "%5F")
    );
    let completed = if request.vector.id == "sign-response" {
        object_value(&request.case.expected)
    } else {
        // These vectors test the Agent's HTTP contract. Signature verification belongs to
        // the receiving Service and is exercised by the assertion and Service vectors.
        json!({"status":"completed","client_assertion":"platform-signed-assertion","agent_did":agent.agent_did,
            "service_did":SERVICE,"jti":claims.jti,"issued_at":"2026-07-06T12:00:00Z","expires_at":"2026-07-06T12:05:00Z"})
    };
    if pending {
        response(
            &transport,
            &sign_url,
            StatusCode::ACCEPTED,
            object_value(&request.case.expected),
        )?;
    }
    response(&transport, &sign_url, StatusCode::OK, completed.clone())?;
    let token = provider
        .signer_for(&agent)
        .await
        .map_err(|e| e.to_string())?
        .sign(&claims, &[SigningAlgorithm::Es256])
        .await
        .map_err(|e| e.to_string())?;
    let requests = transport.requests()?;
    let posts = requests
        .iter()
        .filter(|request| request.method == Method::POST)
        .collect::<Vec<_>>();
    let observed = continuation.0.lock().map_err(|e| e.to_string())?;
    let continuation_context = request
        .case
        .expected
        .get("platform_context")
        .cloned()
        .unwrap_or(json!({}));
    Ok(requests_valid(&requests)
        && token == completed["client_assertion"]
        && posts.len() == if pending { 2 } else { 1 }
        && posts.iter().enumerate().all(|(index, request)| {
            let mut expected_body = body.clone();
            if index > 0 && pending {
                expected_body["platform_context"] = continuation_context.clone();
            }
            request.url.path() == sign_url
                && request.headers["idempotency-key"]
                    == if index == 0 {
                        initial_key.as_str()
                    } else {
                        "final-key"
                    }
                && serde_json::from_slice::<Value>(&request.body).ok() == Some(expected_body)
        })
        && if pending {
            observed.len() == 1
                && observed[0].identity == agent
                && observed[0].retry_after
                    == Duration::from_secs(
                        request.case.expected["retry_after_seconds"]
                            .as_str()
                            .ok_or("missing cadence")?
                            .parse::<u64>()
                            .map_err(|e| e.to_string())?,
                    )
                && serde_json::to_value(&observed[0].platform_context).ok()
                    == Some(continuation_context)
        } else {
            observed.is_empty()
        })
}

async fn conflict(request: &AdapterRequest) -> Result<bool, String> {
    let transport = setup(discovery())?;
    response(
        &transport,
        &format!("{LIST}?descending=true&limit=100&service_did=did%3Aweb%3Aapi.service.example"),
        StatusCode::OK,
        json!({"count":"0","total":"0","data":[]}),
    )?;
    let status: u16 = expected(request, "changed_input_or_operation_status")?;
    let code: String = expected(request, "changed_input_or_operation_code")?;
    if status != 409 || code != "idempotency_conflict" {
        return Ok(false);
    }
    transport.push_response(HttpResponse { status:StatusCode::from_u16(status).map_err(|e|e.to_string())?,
        final_url:Url::parse(&format!("{ORIGIN}{LIST}")).map_err(|e|e.to_string())?,
        headers:HeaderMap::from_iter([(header::CONTENT_TYPE,HeaderValue::from_static(aep_core::PROBLEM_MEDIA_TYPE))]),
        body:serde_json::to_vec(&json!({"type":format!("urn:aep:error:{code}"),"title":"Idempotency conflict","status":status,"code":code})).map_err(|e|e.to_string())? })?;
    let key = input::<String>(request, "initial_sign_key")?;
    let provider = provider(transport.clone(), vec![key.clone()], json!({}), None)?;
    let result = provision(&provider, SERVICE).await;
    let requests = transport.requests()?;
    Ok(requests_valid(&requests)
        && requests.len() == 3
        && requests[2].headers["idempotency-key"] == key
        && matches!(result,Err(AgentError::PlatformCommand {status:actual,problem:Some(problem)}) if actual == status && problem.code.as_str() == code))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AdapterCase, VectorMetadata};

    fn request(id: &str, input: Value, expected: Value) -> AdapterRequest {
        AdapterRequest {
            case: AdapterCase {
                input: input.as_object().expect("input").clone(),
                expected: expected.as_object().expect("expected").clone(),
            },
            expectation: "required".into(),
            profile: "platform-hosted-identity".into(),
            protocol_version: "1".into(),
            role: "agent".into(),
            sequence: 1,
            vector: VectorMetadata {
                category: "platform".into(),
                drafts: vec!["draft-kavian-aep-platform-hosted-identity-01".into()],
                id: id.into(),
                title: id.into(),
            },
        }
    }

    #[tokio::test]
    async fn discovery_is_validated_before_authenticated_commands() {
        let mut request = request("discovery", json!({}), discovery());
        assert!(crate::evaluate(&request).await.expect("valid discovery"));
        for (member, invalid) in [
            ("aep_version", json!("2.0")),
            (
                "endpoints",
                json!({"list":"https://attacker.example/identities"}),
            ),
            (
                "signing",
                json!({"algorithms":[],"default_lifetime_seconds":"300"}),
            ),
        ] {
            request.case.expected = discovery().as_object().expect("document").clone();
            request.case.expected.insert(member.into(), invalid);
            assert!(crate::evaluate(&request).await.is_err(), "{member}");
        }
    }

    #[tokio::test]
    async fn provision_response_requires_valid_active_identity_metadata() {
        let mut request = request("provision-response", json!({}), identity(SERVICE));
        assert!(crate::evaluate(&request).await.expect("valid identity"));
        for (member, invalid) in [
            ("status", json!("suspended")),
            ("key_id", json!("did:web:elsewhere.example")),
            ("created_at", json!("not-a-time")),
            ("signing_algorithms", json!([])),
        ] {
            request.case.expected = identity(SERVICE).as_object().expect("identity").clone();
            request.case.expected.insert(member.into(), invalid);
            assert!(crate::evaluate(&request).await.is_err(), "{member}");
        }
    }

    #[tokio::test]
    async fn pending_sign_checks_cadence_and_preserves_context() {
        let pending = json!({"status":"pending","retry_after_seconds":"5",
            "platform_context":{"authorization_handle":"opaque-value"}});
        let mut request = request(
            "sign-response-pending",
            json!({"idempotency_key_header":SIGN_KEY}),
            pending.clone(),
        );
        assert!(
            crate::evaluate(&request)
                .await
                .expect("pending continuation")
        );
        request.case.expected.insert(
            "platform_context".into(),
            json!({"authorization_handle":"different-value",
            "nested":{"approved":true,"items":["opaque",3]}}),
        );
        assert!(
            crate::evaluate(&request)
                .await
                .expect("opaque continuation context")
        );
        for cadence in [json!("0"), json!("301"), json!(5), Value::Null] {
            request.case.expected = pending.as_object().expect("pending").clone();
            request
                .case
                .expected
                .insert("retry_after_seconds".into(), cadence);
            assert!(crate::evaluate(&request).await.is_err());
        }
    }

    #[tokio::test]
    async fn conflict_checks_the_standard_status_and_code() {
        let mut request = request(
            "idempotency-replay-conflict",
            json!({"initial_sign_key":SIGN_KEY}),
            json!({"changed_input_or_operation_status":409,"changed_input_or_operation_code":"idempotency_conflict"}),
        );
        assert!(crate::evaluate(&request).await.expect("conflict"));
        request
            .case
            .expected
            .insert("changed_input_or_operation_status".into(), json!(400));
        assert!(!crate::evaluate(&request).await.expect("wrong status"));
        request
            .case
            .expected
            .insert("changed_input_or_operation_status".into(), json!(409));
        request.case.expected.insert(
            "changed_input_or_operation_code".into(),
            json!("another_error"),
        );
        assert!(!crate::evaluate(&request).await.expect("wrong code"));
    }
}
