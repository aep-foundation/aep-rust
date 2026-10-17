mod assertions;
mod hosted_agent;
mod hosted_service;
mod platform;
mod protected;
mod role;
mod shared;

use std::io::{self, BufRead as _, Write as _};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Deserialize)]
struct AdapterRequest {
    case: AdapterCase,
    expectation: String,
    profile: String,
    protocol_version: String,
    role: String,
    sequence: u64,
    vector: VectorMetadata,
}

#[derive(Debug, Deserialize)]
struct AdapterCase {
    expected: Map<String, Value>,
    input: Map<String, Value>,
}

#[derive(Debug, Deserialize)]
struct VectorMetadata {
    category: String,
    drafts: Vec<String>,
    id: String,
    title: String,
}

#[derive(Serialize)]
struct AdapterResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    protocol_version: &'static str,
    sequence: u64,
    status: &'static str,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let role = std::env::args()
        .nth(1)
        .ok_or_else(|| "usage: aep-conformance agent|platform|service".to_owned())?;
    if !matches!(role.as_str(), "agent" | "platform" | "service") {
        return Err("usage: aep-conformance agent|platform|service".to_owned());
    }
    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line.map_err(|error| error.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let request: AdapterRequest =
            serde_json::from_str(&line).map_err(|error| error.to_string())?;
        validate_request(&request, &role)?;
        let response = evaluate_response(&request).await;
        serde_json::to_writer(&mut stdout, &response).map_err(|error| error.to_string())?;
        writeln!(stdout).map_err(|error| error.to_string())?;
        stdout.flush().map_err(|error| error.to_string())?;
    }
    Ok(())
}

async fn evaluate_response(request: &AdapterRequest) -> AdapterResponse {
    if request.role == "service"
        && request.vector.category == "platform"
        && request.vector.id == "discovery"
        && request.expectation == "optional"
    {
        return AdapterResponse {
            message: Some("Platform discovery is not implemented by the Service package; its hosted verifier uses a configured endpoint".into()),
            protocol_version: "1", sequence: request.sequence, status: "skipped",
        };
    }
    match evaluate(request).await {
        Ok(true) => AdapterResponse {
            message: None,
            protocol_version: "1",
            sequence: request.sequence,
            status: "passed",
        },
        Ok(false) => AdapterResponse {
            message: Some("Public Rust API result did not match the vector".to_owned()),
            protocol_version: "1",
            sequence: request.sequence,
            status: "failed",
        },
        Err(message) => AdapterResponse {
            message: Some(truncate(message, 1024)),
            protocol_version: "1",
            sequence: request.sequence,
            status: "failed",
        },
    }
}

fn validate_request(request: &AdapterRequest, role: &str) -> Result<(), String> {
    if request.protocol_version != "1" || request.role != role {
        return Err("adapter request does not match the process contract".to_owned());
    }
    if request.expectation != "required" && request.expectation != "optional" {
        return Err("adapter request has an unknown expectation".to_owned());
    }
    if request.profile.is_empty()
        || request.vector.category.is_empty()
        || request.vector.drafts.is_empty()
        || request.vector.title.is_empty()
    {
        return Err("adapter request metadata is incomplete".to_owned());
    }
    Ok(())
}

async fn evaluate(request: &AdapterRequest) -> Result<bool, String> {
    if request.role == "platform" {
        return platform::evaluate(request).await;
    }
    if request.role == "agent" && request.vector.category == "platform" {
        return hosted_agent::evaluate(request).await;
    }
    if request.role == "service" && request.vector.category == "platform" {
        return hosted_service::evaluate(request).await;
    }
    if let Some(result) = shared::evaluate(request).await? {
        return Ok(result);
    }
    match request.role.as_str() {
        "agent" => shared::evaluate_agent(request).await,
        "service" => shared::evaluate_service(request).await,
        _ => Err(format!("unsupported role {}", request.role)),
    }
}

fn truncate(mut value: String, maximum: usize) -> String {
    if value.len() <= maximum {
        return value;
    }
    let mut end = maximum;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    value
}

fn input<T: serde::de::DeserializeOwned>(
    request: &AdapterRequest,
    name: &str,
) -> Result<T, String> {
    field(&request.case.input, name)
}

fn expected<T: serde::de::DeserializeOwned>(
    request: &AdapterRequest,
    name: &str,
) -> Result<T, String> {
    field(&request.case.expected, name)
}

fn field<T: serde::de::DeserializeOwned>(
    object: &Map<String, Value>,
    name: &str,
) -> Result<T, String> {
    let value = object
        .get(name)
        .ok_or_else(|| format!("required field {name:?} is missing"))?;
    serde_json::from_value(value.clone()).map_err(|error| format!("decode field {name:?}: {error}"))
}

fn object_value(object: &Map<String, Value>) -> Value {
    Value::Object(object.clone())
}

#[cfg(test)]
mod tests {
    use super::{
        AdapterCase, AdapterRequest, VectorMetadata, evaluate, evaluate_response, truncate,
    };
    use serde_json::{Value, json};

    fn request(role: &str, id: &str, input: Value, expected: Value) -> AdapterRequest {
        AdapterRequest {
            case: AdapterCase {
                input: input.as_object().expect("object input").clone(),
                expected: expected.as_object().expect("object expectations").clone(),
            },
            expectation: "required".to_owned(),
            profile: "core-http".to_owned(),
            protocol_version: "1".to_owned(),
            role: role.to_owned(),
            sequence: 1,
            vector: VectorMetadata {
                category: "protected-resource".to_owned(),
                drafts: vec!["draft-kavian-agent-enrollment-protocol-04".to_owned()],
                id: id.to_owned(),
                title: id.to_owned(),
            },
        }
    }

    #[test]
    fn truncation_preserves_complete_utf8_characters() {
        for text in ["plain", "éclair", "a€b", "a𐐀b"] {
            for maximum in 0..=text.len() + 1 {
                let result = truncate(text.to_owned(), maximum);
                let end = (0..=maximum.min(text.len()))
                    .rev()
                    .find(|end| text.is_char_boundary(*end))
                    .expect("zero is a character boundary");
                assert_eq!(result, &text[..end]);
            }
        }
    }

    #[tokio::test]
    async fn hosted_verification_key_vector_uses_an_authorized_identity() {
        let mut request = request(
            "platform",
            "verification-request",
            json!({"client_assertion":"unrecognized-assertion","op":"enroll","service_did":"did:web:api.service.example"}),
            json!({"idempotency_key_header":"verification-key"}),
        );
        assert!(evaluate(&request).await.expect("authorized key validation"));
        request
            .case
            .expected
            .insert("idempotency_key_header".into(), json!(""));
        assert!(!evaluate(&request).await.expect("empty expected key"));
    }

    #[tokio::test]
    async fn service_hosted_vectors_execute_the_verifier_and_detect_wrong_expectations() {
        let service_did = "did:web:api.service.example";
        let agent_did = "did:web:p.example:a:4Yf7p2xQd9";
        let recognized = json!({
            "agent_did":agent_did, "op":"enroll", "reason":"verified",
            "service_did":service_did, "verified":true
        });
        let mut response = request(
            "service",
            "verification-response-recognized",
            json!({}),
            recognized,
        );
        response.vector.category = "platform".into();
        assert!(evaluate(&response).await.expect("recognized"));
        response.case.expected.remove("agent_did");
        assert!(
            !evaluate(&response)
                .await
                .expect("incomplete recognized response")
        );
        response.vector.id = "verification-response-unrecognized".into();
        response.case.expected =
            json!({"reason":"not_recognized","service_did":service_did,"verified":false})
                .as_object()
                .expect("object")
                .clone();
        assert!(evaluate(&response).await.expect("unrecognized"));

        let token = crate::assertions::sign_raw(
            json!({
                "aud":service_did, "exp":1783425900, "iat":1783425600,
                "iss":agent_did, "sub":agent_did, "jti":"request-vector", "op":"enroll"
            }),
            Some(agent_did),
            "JWT",
        )
        .expect("signed assertion");
        response.vector.id = "verification-request".into();
        response.case.input =
            json!({"client_assertion":token,"op":"enroll","service_did":service_did})
                .as_object()
                .expect("input")
                .clone();
        response.case.expected = json!({"idempotency_key_header":"command-key"})
            .as_object()
            .expect("expected")
            .clone();
        assert!(evaluate(&response).await.expect("request"));
        response
            .case
            .expected
            .insert("idempotency_key_header".into(), json!(""));
        assert!(!evaluate(&response).await.expect("empty illustrative key"));

        response.vector.id = "verification-authenticate-missing-resource".into();
        response.case.input = json!({"request":{"op":"authenticate","service_did":service_did,"client_assertion":"header.payload.signature"}})
            .as_object().expect("input").clone();
        response.case.expected = json!({"valid":false})
            .as_object()
            .expect("expected")
            .clone();
        assert!(evaluate(&response).await.expect("missing resource"));
        response.case.expected.insert("valid".into(), json!(true));
        assert!(!evaluate(&response).await.expect("wrong expected validity"));
    }

    #[tokio::test]
    async fn only_optional_service_platform_discovery_is_reported_as_unsupported() {
        let mut request = request("service", "discovery", json!({}), json!({}));
        request.vector.category = "platform".into();
        request.profile = "platform-hosted-identity".into();
        request.expectation = "optional".into();
        let result = evaluate_response(&request).await;
        assert_eq!(result.status, "skipped");
        assert!(
            result
                .message
                .expect("explanation")
                .contains("configured endpoint")
        );
        request.expectation = "required".into();
        assert_eq!(evaluate_response(&request).await.status, "failed");
        request.vector.id = "unknown-hosted-operation".into();
        request.expectation = "optional".into();
        assert_eq!(evaluate_response(&request).await.status, "failed");
    }

    #[tokio::test]
    async fn security_inheritance_checks_all_six_expectations() {
        let mut request = request(
            "agent",
            "security-inheritance",
            json!({
                "security_scheme": {"type":"http", "scheme":"AEP", "x-aep-authentication-method":"aep-jwt"}
            }),
            json!({
                "root_inherited":"required",
                "operation_empty_array":"public",
                "empty_requirement_alternative":"optional-anonymous",
                "multiple_objects":"alternatives",
                "multiple_schemes_one_object":"all-required",
                "unsupported_compound":"fallback-live-challenge"
            }),
        );
        assert!(evaluate(&request).await.expect("evaluate valid vector"));
        for (name, value) in request.case.expected.clone() {
            request
                .case
                .expected
                .insert(name.clone(), json!("incorrect"));
            assert!(
                !evaluate(&request)
                    .await
                    .expect("evaluate mismatched expectation"),
                "{name}"
            );
            request.case.expected.insert(name, value);
        }
    }

    #[tokio::test]
    async fn service_checks_all_signed_operation_target_pairs() {
        let mut request = request(
            "service",
            "operation-substitution-rejected",
            json!({
                "operations":["enroll","grant","revoke","status","authenticate"],
                "command_endpoints":["enroll","grant","revoke","status"],
                "protected_resource":"https://api.example.com/orders"
            }),
            json!({
                "allowed":["enroll:enroll","grant:grant","revoke:revoke","status:status","authenticate:protected-resource"],
                "all_other_pairs":"not_recognized"
            }),
        );
        assert!(evaluate(&request).await.expect("evaluate operation matrix"));
        request
            .case
            .expected
            .insert("allowed".to_owned(), json!(["enroll:status"]));
        assert!(
            !evaluate(&request)
                .await
                .expect("evaluate invalid operation matrix")
        );
    }

    #[tokio::test]
    async fn service_rejects_stale_and_cross_origin_resource_assertions() {
        let request = request(
            "service",
            "redirect-safety",
            json!({
                "source":"https://api.example.com/orders/1",
                "same_origin":"https://api.example.com/orders/2",
                "cross_origin":"https://other.example.com/orders/1"
            }),
            json!({}),
        );
        assert!(evaluate(&request).await.expect("evaluate resource binding"));
    }

    #[tokio::test]
    async fn agent_redirect_vector_exercises_header_binding_and_origin_refusal() {
        let mut request = request(
            "agent",
            "redirect-safety",
            json!({
                "source":"https://api.example.com:8443/orders/1?variant=black",
                "same_origin":"https://api.example.com:8443/orders/2?variant=blue",
                "cross_origin":"https://other.example.com/orders/1"
            }),
            json!({
                "same_origin": {
                    "credential_forwarded":false,
                    "new_authenticate_assertion_resource":"https://api.example.com:8443/orders/2?variant=blue"
                },
                "cross_origin": {
                    "anonymous_restart":true,
                    "assertion_forwarded":false,
                    "session_credential_forwarded":false,
                    "api_key_header_forwarded":false
                }
            }),
        );
        assert!(
            evaluate(&request)
                .await
                .expect("evaluate Agent header generation")
        );
        request.case.input.insert(
            "cross_origin".to_owned(),
            json!("https://api.example.com:9443/orders/1"),
        );
        assert!(
            evaluate(&request)
                .await
                .expect("refuse a different port on the same host")
        );
        request.case.input.insert(
            "cross_origin".to_owned(),
            json!("https://api.example.com:8443/orders/3"),
        );
        assert!(
            !evaluate(&request)
                .await
                .expect("reject same-origin cross-origin fixture")
        );
    }

    #[tokio::test]
    async fn platform_denial_checks_one_platform_and_existing_identity() {
        let request = request(
            "platform",
            "authorization-required",
            json!({}),
            json!({
                "management_denied_status":404,
                "management_denied_code":"not_recognized",
                "verification_denied":{"verified":false,"reason":"not_recognized"},
                "did_document_public":true,
                "side_effects":false,
                "missing_authorizer":"construction-error"
            }),
        );
        assert!(
            evaluate(&request)
                .await
                .expect("evaluate management authorization")
        );
    }

    #[tokio::test]
    async fn pending_sign_runs_the_platform_handler() {
        let request = request(
            "platform",
            "sign-response-pending",
            json!({
                "idempotency_key_header":"pending-sign-test"
            }),
            json!({
                "status":"pending",
                "platform_context":{"authorization_handle":"opaque-value"},
                "retry_after_seconds":"5"
            }),
        );
        assert!(evaluate(&request).await.expect("evaluate pending signing"));
    }

    #[tokio::test]
    async fn assertion_vector_executes_every_rejection() {
        let mut vector = request(
            "service",
            "validation-requirements",
            json!({
                "agent_did":"did:web:agent.example", "service_did":"did:web:service.example",
                "algorithm":"ES256", "issued_at":1788177600, "expires_at":1788177660, "jti":"validation"
            }),
            json!({
                "header":{"alg":"ES256", "kid":"did:web:agent.example", "typ":"JWT"},
                "claims":{"aud":"did:web:service.example", "exp":1788177660,"iat":1788177600,
                    "iss":"did:web:agent.example","jti":"validation","op":"enroll","sub":"did:web:agent.example"},
                "reject":["excessive_lifetime","fragmented_resource","insecure_resource","mismatched_kid",
                    "mismatched_subject","missing_kid","missing_resource","nonpositive_lifetime","unexpected_resource","wrong_typ"]
            }),
        );
        assert!(evaluate(&vector).await.expect("real assertion validation"));
        vector
            .case
            .expected
            .insert("reject".to_owned(), json!(["unimplemented-rejection"]));
        assert!(evaluate(&vector).await.is_err());
    }

    #[tokio::test]
    async fn credential_failure_vectors_exercise_service_errors_and_agent_propagation() {
        for role in ["service", "agent"] {
            let mut vector = request(
                role,
                "assertion-and-credential-failures",
                json!({
                    "cases":["wrong_audience","expired_assertion","replayed_assertion","malformed_credential",
                        "expired_credential","unsupported_method","insufficient_scope"]
                }),
                json!({
                    "wrong_audience":"not_recognized", "expired_assertion":"not_recognized", "replayed_assertion":"not_recognized",
                    "malformed_credential":"not_recognized", "expired_credential":"not_recognized",
                    "unsupported_method":"unsupported_authentication_method", "insufficient_scope":"insufficient_scope"
                }),
            );
            assert!(
                evaluate(&vector).await.expect("actual failure behavior"),
                "{role}"
            );
            vector.case.expected.insert(
                "malformed_credential".to_owned(),
                json!("authentication_required"),
            );
            assert!(
                !evaluate(&vector)
                    .await
                    .expect("reject an incorrect expected failure"),
                "{role}"
            );
        }
    }

    #[tokio::test]
    async fn command_vectors_exercise_actual_agent_headers_and_service_key_validation() {
        for role in ["service", "agent"] {
            let vector = request(
                role,
                "command-header",
                json!({
                    "commands":["enroll","grant","revoke"], "idempotency_key":"header-vector"
                }),
                json!({
                    "header_required":true,"enroll_body_key":"optional","missing_or_empty_status":400,
                    "missing_or_empty_code":"invalid_request","mismatched_enroll_body_status":400
                }),
            );
            assert!(
                evaluate(&vector)
                    .await
                    .expect("command idempotency contract"),
                "{role}"
            );
        }
    }
}
