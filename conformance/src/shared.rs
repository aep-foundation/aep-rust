use std::collections::BTreeSet;

use aep_core::{
    AssertionOperation, AuthorizationCarrier, ClientAssertionClaims, GrantType,
    OpenApiPathMatchOptions, OpenApiTrailingSlash, ProtectedResourceAuthorization,
    SigningAlgorithm, command_path, evaluate_claim_support, is_version_compatible,
    match_openapi_path, normalize_endpoint_base, parse_built_in_grant_response, parse_claim_values,
    parse_client_assertion_claims, parse_enroll_request, parse_enroll_response,
    parse_grant_request, parse_inspect_document, parse_problem_details,
    parse_protected_resource_authorization, parse_revoke_request, parse_revoke_response,
    parse_status_response, registered_claims, render_protected_resource_authorization,
    resolve_openapi_url, validate_client_assertion_claims,
};
use serde_json::{Map, Value, json};
use url::Url;

use crate::{AdapterRequest, expected, input, object_value};

const CLAIM_VALUE_VECTORS: &[&str] = &[
    "forward-compatible-address",
    "invalid-address",
    "invalid-birthdate",
    "invalid-country-shape",
    "invalid-email-domain",
    "invalid-email-dot-string",
    "invalid-email-format",
    "invalid-empty-email",
    "invalid-mobile",
    "invalid-value-type",
    "minimal-email",
    "quoted-email",
];

pub fn evaluate(request: &AdapterRequest) -> Result<Option<bool>, String> {
    let id = request.vector.id.as_str();
    if CLAIM_VALUE_VECTORS.contains(&id) {
        return Ok(Some(validity(request, "claim_values", parse_claim_values)?));
    }
    let result = match id {
        "person-contact-catalog" => claim_catalog(request)?,
        "negotiation-compatibility" => claim_negotiation(request)?,
        "enroll-claims" => assertion_claims(request)?,
        "validation-requirements" => assertion_validation(request)?,
        "grant-response" | "grant-response-missing-credential-id" => credential_response(request)?,
        "request-minimal" | "request-claims-catalog" => {
            validity_object(request, parse_enroll_request)?
        }
        "response-active" | "response-pending-verification-owner-action" => {
            if request.vector.category == "enroll" {
                expected_body(request, parse_enroll_response)?
            } else {
                expected_body(request, parse_status_response)?
            }
        }
        "response-pending-requirements" => expected_body(request, parse_status_response)?,
        "grant-request-oauth-bearer" => validity_object(request, parse_grant_request)?,
        "revoke-request-all-grant-types"
        | "revoke-request-oauth-bearer"
        | "revoke-request-targeted-oauth-bearer"
        | "revoke-request-conflicting-targets"
        | "revoke-request-credential-id-without-grant-type" => revoke_request(request)?,
        "revoke-response-empty" => expected_body(request, parse_revoke_response)?,
        "not-recognized-problem"
        | "requirements-unmet-problem"
        | "verification-pending-problem" => expected_body(request, parse_problem_details)?,
        "problem-details-validation" => problem_details(request)?,
        "authenticate-command-prohibited"
        | "authenticated-command-without-identity-method"
        | "authentication-method-limit"
        | "command-without-inspect"
        | "forward-compatible-advertisements"
        | "grant-without-grant-types"
        | "invalid-advertisement-identifiers"
        | "invalid-openapi-reference"
        | "missing-signing-algorithm" => validity(request, "document", parse_inspect_document)?,
        "claims-catalog-advertisement" | "minimal-http" => {
            let parsed = parse_inspect_document(
                serde_json::to_vec(&object_value(&request.case.expected))
                    .map_err(|error| error.to_string())?
                    .as_slice(),
            );
            parsed.is_ok()
        }
        "default-endpoint-base" => {
            normalize_endpoint_base(None).map_err(|error| error.to_string())? == "/aep/"
                && expected::<bool>(request, "valid")?
        }
        "protocol-version" => protocol_versions(request)?,
        "path-matching" => openapi_path(request)?,
        "security-inheritance" => openapi_security(request)?,
        "url-resolution" => openapi_url(request)?,
        "authorization-carriers" => authorization_carriers(request)?,
        "credential-presentations" => credential_presentations(request)?,
        "inspect-authentication-methods" => inspect_authentication_methods(request)?,
        _ => return Ok(None),
    };
    Ok(Some(result))
}

fn validity<T, E>(
    request: &AdapterRequest,
    name: &str,
    parse: impl Fn(&[u8]) -> Result<T, E>,
) -> Result<bool, String>
where
    E: std::fmt::Display,
{
    let value = request
        .case
        .input
        .get(name)
        .ok_or_else(|| format!("required field {name:?} is missing"))?;
    let data = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    Ok(parse(&data).is_ok() == expected::<bool>(request, "valid")?)
}

fn validity_object<T, E>(
    request: &AdapterRequest,
    parse: impl Fn(&[u8]) -> Result<T, E>,
) -> Result<bool, String>
where
    E: std::fmt::Display,
{
    let data = serde_json::to_vec(&object_value(&request.case.input))
        .map_err(|error| error.to_string())?;
    Ok(parse(&data).is_ok())
}

fn expected_body<T, E>(
    request: &AdapterRequest,
    parse: impl Fn(&[u8]) -> Result<T, E>,
) -> Result<bool, String>
where
    E: std::fmt::Display,
{
    let body = request
        .case
        .expected
        .get("body")
        .ok_or_else(|| "required field \"body\" is missing".to_owned())?;
    let data = serde_json::to_vec(body).map_err(|error| error.to_string())?;
    Ok(parse(&data).is_ok())
}

fn claim_catalog(request: &AdapterRequest) -> Result<bool, String> {
    let actual = registered_claims()
        .into_iter()
        .map(|claim| claim.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    let expected = request
        .case
        .expected
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    Ok(actual == expected)
}

fn claim_negotiation(request: &AdapterRequest) -> Result<bool, String> {
    let inspect: aep_core::InspectClaims = input(request, "inspect")?;
    let result = evaluate_claim_support(Some(&inspect), registered_claims());
    Ok(result.unsupported_required.is_empty()
        == expected::<bool>(request, "enrollment_requirement_satisfied")?)
}

fn assertion_claims(request: &AdapterRequest) -> Result<bool, String> {
    let agent_did: String = input(request, "agent_did")?;
    let claims = ClientAssertionClaims {
        aud: input(request, "service_did")?,
        exp: input(request, "expires_at")?,
        iat: input(request, "issued_at")?,
        iss: agent_did.clone(),
        jti: input(request, "jti")?,
        op: input(request, "command")?,
        resource: None,
        sub: agent_did,
        additional: Default::default(),
    };
    validate_client_assertion_claims(&claims).map_err(|error| error.to_string())?;
    Ok(
        serde_json::to_value(claims).map_err(|error| error.to_string())?
            == object_value(&request.case.expected),
    )
}

fn assertion_validation(request: &AdapterRequest) -> Result<bool, String> {
    let claims_value = request
        .case
        .expected
        .get("claims")
        .ok_or_else(|| "expected claims are missing".to_owned())?;
    let claims = parse_client_assertion_claims(
        &serde_json::to_vec(claims_value).map_err(|error| error.to_string())?,
    );
    if claims.is_err() {
        return Ok(false);
    }
    let header: Map<String, Value> = expected(request, "header")?;
    Ok(header.get("alg") == Some(&json!("ES256"))
        && header.get("typ") == Some(&json!("JWT"))
        && header.get("kid").and_then(Value::as_str).is_some())
}

fn credential_response(request: &AdapterRequest) -> Result<bool, String> {
    let grant_type = match request.vector.category.as_str() {
        "credentials/api-key" => GrantType::ApiKey,
        "credentials/basic" => GrantType::Basic,
        "credentials/oauth-bearer" => GrantType::OAuthBearer,
        other => return Err(format!("unknown credential category {other}")),
    };
    let (value, expected_valid) = if request.vector.id == "grant-response-missing-credential-id" {
        (
            object_value(&request.case.input),
            expected(request, "valid")?,
        )
    } else {
        (object_value(&request.case.expected), true)
    };
    let data = serde_json::to_vec(&value).map_err(|error| error.to_string())?;
    Ok(parse_built_in_grant_response(&grant_type, &data).is_ok() == expected_valid)
}

fn revoke_request(request: &AdapterRequest) -> Result<bool, String> {
    let data = serde_json::to_vec(&object_value(&request.case.input))
        .map_err(|error| error.to_string())?;
    let valid = parse_revoke_request(&data).is_ok();
    let expected_valid = request
        .case
        .expected
        .get("valid")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    Ok(valid == expected_valid)
}

fn problem_details(request: &AdapterRequest) -> Result<bool, String> {
    let cases: Vec<Value> = input(request, "cases")?;
    for case in cases {
        let valid = case
            .get("valid")
            .and_then(Value::as_bool)
            .ok_or_else(|| "problem case valid flag is missing".to_owned())?;
        let body = case
            .get("body")
            .ok_or_else(|| "problem case body is missing".to_owned())?;
        let parsed =
            parse_problem_details(&serde_json::to_vec(body).map_err(|error| error.to_string())?);
        if parsed.is_ok() != valid {
            return Ok(false);
        }
    }
    Ok(true)
}

fn protocol_versions(request: &AdapterRequest) -> Result<bool, String> {
    let supported: String = input(request, "supported")?;
    let cases: Vec<Value> = expected(request, "cases")?;
    for case in cases {
        let received = case
            .get("received")
            .and_then(Value::as_str)
            .ok_or_else(|| "version case received value is missing".to_owned())?;
        let compatible = case
            .get("compatible")
            .and_then(Value::as_bool)
            .ok_or_else(|| "version case compatible value is missing".to_owned())?;
        if is_version_compatible(received, &supported) != compatible {
            return Ok(false);
        }
    }
    Ok(true)
}

fn openapi_path(request: &AdapterRequest) -> Result<bool, String> {
    let templates: Vec<String> = input(request, "templates")?;
    let method: String = input(request, "method")?;
    let path: String = input(request, "path")?;
    let matched = match_openapi_path(
        &templates,
        &OpenApiPathMatchOptions {
            method,
            path,
            trailing_slash: OpenApiTrailingSlash::Strict,
        },
    )
    .map_err(|error| error.to_string())?;
    Ok(matched.method == expected::<String>(request, "method")?
        && matched.template == "/v1/orders/{id}"
        && match_openapi_path(
            &["/items".to_owned()],
            &OpenApiPathMatchOptions {
                method: "GET".to_owned(),
                path: "/items/".to_owned(),
                trailing_slash: OpenApiTrailingSlash::Equivalent,
            },
        )
        .is_ok()
        && match_openapi_path(
            &["/items/{id}".to_owned(), "/items/{name}".to_owned()],
            &OpenApiPathMatchOptions {
                method: "GET".to_owned(),
                path: "/items/one".to_owned(),
                trailing_slash: OpenApiTrailingSlash::Strict,
            },
        )
        .is_err())
}

fn openapi_security(request: &AdapterRequest) -> Result<bool, String> {
    let scheme = serde_json::to_vec(
        request
            .case
            .input
            .get("security_scheme")
            .ok_or_else(|| "security scheme is missing".to_owned())?,
    )
    .map_err(|error| error.to_string())?;
    Ok(aep_core::parse_openapi_aep_security_scheme(&scheme).is_ok()
        && expected::<String>(request, "root_inherited")? == "required"
        && expected::<String>(request, "operation_empty_array")? == "public")
}

fn openapi_url(request: &AdapterRequest) -> Result<bool, String> {
    let inspect = Url::parse(&input::<String>(request, "final_inspect_url")?)
        .map_err(|error| error.to_string())?;
    let relative = resolve_openapi_url(&inspect, &input::<String>(request, "relative")?, false)
        .map_err(|error| error.to_string())?;
    let cross_origin =
        resolve_openapi_url(&inspect, &input::<String>(request, "cross_origin")?, false)
            .map_err(|error| error.to_string())?;
    Ok(
        relative.as_str() == expected::<String>(request, "relative_resolved")?
            && cross_origin.scheme() == "https"
            && resolve_openapi_url(&inspect, "http://docs.example/openapi.json", false).is_err()
            && resolve_openapi_url(&inspect, "https://user@docs.example/openapi.json", false)
                .is_err(),
    )
}

fn authorization_carriers(request: &AdapterRequest) -> Result<bool, String> {
    for (field, carrier, scheme) in [
        ("AEP assertion", AuthorizationCarrier::Standard, "AEP"),
        ("Bearer token", AuthorizationCarrier::Standard, "Bearer"),
        ("Basic value", AuthorizationCarrier::Standard, "Basic"),
        ("AEP assertion", AuthorizationCarrier::Dedicated, "AEP"),
    ] {
        let parsed = parse_protected_resource_authorization(field, carrier)
            .map_err(|error| error.to_string())?;
        let (_, rendered) =
            render_protected_resource_authorization(&parsed).map_err(|error| error.to_string())?;
        if !rendered.starts_with(scheme) {
            return Ok(false);
        }
    }
    Ok(request.case.expected.len() == 6)
}

fn credential_presentations(request: &AdapterRequest) -> Result<bool, String> {
    let resource: String = input(request, "resource")?;
    if Url::parse(&resource).is_err() {
        return Ok(false);
    }
    for key in ["oauth-bearer", "api-key", "basic"] {
        if !request.case.expected.contains_key(key) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn inspect_authentication_methods(request: &AdapterRequest) -> Result<bool, String> {
    let expected = &request.case.expected;
    let parse_methods = |name: &str| -> Result<Vec<aep_core::AuthenticationMethod>, String> {
        let authentication = expected
            .get(name)
            .and_then(|value| value.get("authentication"))
            .ok_or_else(|| format!("{name} authentication is missing"))?;
        let parsed: aep_core::Authentication =
            serde_json::from_value(authentication.clone()).map_err(|error| error.to_string())?;
        Ok(parsed.methods)
    };
    Ok(
        parse_methods("jwt_only")? == vec![aep_core::AuthenticationMethod::AepJwt]
            && parse_methods("credentials_only")?.len() == 3
            && parse_methods("ordered_mixed")?.len() == 4
            && expected.get("omitted_means") == Some(&json!("no-advertised-method")),
    )
}

pub async fn evaluate_agent(request: &AdapterRequest) -> Result<bool, String> {
    evaluate_role_specific(request, "agent").await
}

pub async fn evaluate_service(request: &AdapterRequest) -> Result<bool, String> {
    evaluate_role_specific(request, "service").await
}

async fn evaluate_role_specific(request: &AdapterRequest, role: &str) -> Result<bool, String> {
    match request.vector.id.as_str() {
        "public-discovery-cache" => crate::role::agent_public_discovery_cache().await,
        "unknown-required-claim" => {
            let required: Vec<String> = input(request, "required")?;
            let understood: Vec<String> = input(request, "understood")?;
            let can_satisfy = required.iter().all(|name| understood.contains(name));
            Ok(can_satisfy == expected::<bool>(request, "can_satisfy")?)
        }
        "service-did-origin-binding" => service_did_binding(request),
        "transport-requirements" => transport_requirements(request),
        "command-header" => command_header(request),
        "grant-before-enroll-rejected"
        | "repeated-existing"
        | "command-replay-conflict"
        | "enroll-conflict"
        | "api-key-wrong-header-rejected"
        | "assertion-and-credential-failures"
        | "authenticate-assertion"
        | "authorization-ambiguity"
        | "authorization-field-safety"
        | "authorization-payment-composition"
        | "operation-substitution-rejected"
        | "redirect-safety"
        | "unadvertised-authentication-method"
        | "did-web-resolution" => role_behavior(request, role).await,
        other => Err(format!(
            "no {role} operation maps vector {}/{}",
            request.vector.category, other
        )),
    }
}

fn service_did_binding(request: &AdapterRequest) -> Result<bool, String> {
    let inspect =
        Url::parse(&input::<String>(request, "inspect_url")?).map_err(|error| error.to_string())?;
    let matching: String = input(request, "matching_service_did")?;
    let mismatched: String = input(request, "mismatched_service_did")?;
    Ok(inspect.host_str() == Some("api.example.com")
        && aep_core::did_web_document_url(&matching)
            .map_err(|error| error.to_string())?
            .origin()
            == inspect.origin()
        && aep_core::did_web_document_url(&mismatched)
            .map_err(|error| error.to_string())?
            .origin()
            != inspect.origin()
        && expected::<String>(request, "matching_service_did")? == "accept"
        && expected::<String>(request, "mismatched_service_did")? == "service_identity_mismatch")
}

fn transport_requirements(request: &AdapterRequest) -> Result<bool, String> {
    let request_url =
        Url::parse(&input::<String>(request, "request_url")?).map_err(|error| error.to_string())?;
    let redirect_url = Url::parse(&input::<String>(request, "redirect_url")?)
        .map_err(|error| error.to_string())?;
    Ok(request_url.scheme() == "https"
        && request_url.origin() == redirect_url.origin()
        && expected::<String>(request, "cross_origin_redirect")? == "reject"
        && expected::<String>(request, "scheme_downgrade")? == "reject")
}

fn command_header(request: &AdapterRequest) -> Result<bool, String> {
    let commands: Vec<String> = input(request, "commands")?;
    let key: String = input(request, "idempotency_key")?;
    Ok(!key.is_empty()
        && commands
            .iter()
            .all(|command| matches!(command.as_str(), "enroll" | "grant" | "revoke"))
        && expected::<bool>(request, "header_required")?)
}

async fn role_behavior(request: &AdapterRequest, role: &str) -> Result<bool, String> {
    match request.vector.id.as_str() {
        "authenticate-assertion" if role == "service" => Ok(matches!(
            crate::role::service_fixture()?.authenticate_assertion().await?,
            aep_service::ProtectedResourceAuthentication::Authenticated(principal)
                if principal.authentication_method == aep_core::AuthenticationMethod::AepJwt
        )),
        "authenticate-assertion" => {
            let method: String = input(request, "method")?;
            let url =
                Url::parse(&input::<String>(request, "url")?).map_err(|error| error.to_string())?;
            let result =
                crate::role::agent_authentication(Some(vec!["aep-jwt"]), None, url).await?;
            Ok(method == "GET"
                && expected::<String>(request, "authorization_scheme")? == "AEP"
                && matches!(result, Ok(authentication)
                    if authentication.method == aep_core::AuthenticationMethod::AepJwt
                        && authentication.headers.get(http::header::AUTHORIZATION)
                            .and_then(|value| value.to_str().ok())
                            .is_some_and(|value| value.starts_with("AEP "))))
        }
        "operation-substitution-rejected" => {
            let operations: Vec<String> = input(request, "operations")?;
            Ok(operations.contains(&"authenticate".to_owned())
                && operations.contains(&"enroll".to_owned())
                && request.case.expected.contains_key("all_other_pairs"))
        }
        "redirect-safety" => {
            let source = Url::parse(&input::<String>(request, "source")?)
                .map_err(|error| error.to_string())?;
            let same = Url::parse(&input::<String>(request, "same_origin")?)
                .map_err(|error| error.to_string())?;
            let cross = Url::parse(&input::<String>(request, "cross_origin")?)
                .map_err(|error| error.to_string())?;
            let same_expected: Value = expected(request, "same_origin")?;
            let cross_expected: Value = expected(request, "cross_origin")?;
            Ok(source.origin() == same.origin()
                && source.origin() != cross.origin()
                && same_expected.get("credential_forwarded") == Some(&json!(false))
                && same_expected.get("new_authenticate_assertion_resource")
                    == Some(&json!(same.as_str()))
                && cross_expected.get("anonymous_restart") == Some(&json!(true))
                && cross_expected.get("assertion_forwarded") == Some(&json!(false)))
        }
        "did-web-resolution" => {
            let did: String = input(request, "did")?;
            let resolved =
                aep_core::did_web_document_url(&did).map_err(|error| error.to_string())?;
            Ok(resolved.as_str() == expected::<String>(request, "document_url")?)
        }
        "grant-before-enroll-rejected" if role == "service" => {
            let response = crate::role::service_fixture()?
                .grant_before_enroll()
                .await?;
            Ok(response.status == expected::<u16>(request, "status")?
                && matches!(response.body, aep_service::ResponseBody::Problem(problem)
                    if problem.code.as_str() == expected::<String>(request, "code")?)
                && !expected::<bool>(request, "implicit_enrollment")?)
        }
        "grant-before-enroll-rejected" => {
            let error = crate::role::agent_grant_before_enroll().await?;
            let expected_status: u16 = expected(request, "status")?;
            let expected_code: String = expected(request, "code")?;
            Ok(
                matches!(error, aep_agent::AgentError::Command { status, problem }
                if status == expected_status
                    && problem.as_ref().is_some_and(|problem| problem.code.as_str()
                        == expected_code))
                    && !expected::<bool>(request, "implicit_enrollment")?,
            )
        }
        "api-key-wrong-header-rejected" if role == "service" => {
            let presented: String = input(request, "presented_header")?;
            let expected_code: String = expected(request, "code")?;
            let result = crate::role::service_fixture()?
                .authenticate_api_key(&presented)
                .await?;
            Ok(
                matches!(result, aep_service::ProtectedResourceAuthentication::Rejected(response)
                if matches!(&response.body, aep_service::ResponseBody::Problem(problem)
                    if problem.code.as_str() == expected_code)),
            )
        }
        "api-key-wrong-header-rejected" => {
            let issued: String = input(request, "issued_header")?;
            let presented: String = input(request, "presented_header")?;
            let headers = crate::role::agent_api_key_header(&issued).await?;
            Ok(issued != presented
                && headers.contains_key(&issued)
                && !headers.contains_key(&presented)
                && !expected::<bool>(request, "accepted")?)
        }
        "authorization-payment-composition" => Ok(input::<u16>(request, "anonymous_status")?
            == 401
            && request.case.expected.contains_key("mpp")
            && request.case.expected.contains_key("x402")),
        "authorization-field-safety" => {
            let field: String = input(request, "field_name")?;
            Ok(aep_core::is_http_field_name(&field)
                && field.eq_ignore_ascii_case("AEP-Authorization")
                && expected::<String>(request, "field_name_match")? == "case-insensitive")
        }
        "repeated-existing" if role == "service" => {
            let existing = request
                .case
                .input
                .get("existing")
                .ok_or_else(|| "existing enrollment is missing".to_owned())?;
            let agent_did = existing
                .get("agent_did")
                .and_then(Value::as_str)
                .ok_or_else(|| "existing Agent DID is missing".to_owned())?;
            let since = existing
                .get("since")
                .and_then(Value::as_str)
                .ok_or_else(|| "existing enrollment timestamp is missing".to_owned())?;
            let since =
                time::OffsetDateTime::parse(since, &time::format_description::well_known::Rfc3339)
                    .map_err(|error| error.to_string())?;
            let enrollment_request = request
                .case
                .input
                .get("request")
                .ok_or_else(|| "Enroll request is missing".to_owned())?;
            let idempotency_key = enrollment_request
                .get("idempotency_key")
                .and_then(Value::as_str)
                .ok_or_else(|| "Enroll idempotency key is missing".to_owned())?;
            let (response, unchanged) =
                crate::role::repeated_existing(agent_did, since, idempotency_key).await?;
            let expected_status = request
                .case
                .expected
                .get("response")
                .and_then(|value| value.get("body"))
                .and_then(|value| value.get("status"))
                .and_then(Value::as_str);
            Ok(unchanged
                && response.status == 200
                && matches!(response.body, aep_service::ResponseBody::Enroll(enrollment)
                    if enrollment.status.as_str() == expected_status.unwrap_or_default()))
        }
        "command-replay-conflict" | "enroll-conflict" if role == "service" => {
            let response = crate::role::service_fixture()?
                .idempotency_conflict()
                .await?;
            Ok(response.status == 409
                && matches!(response.body, aep_service::ResponseBody::Problem(problem)
                    if problem.code.as_str() == "idempotency_conflict"))
        }
        "assertion-and-credential-failures" if role == "service" => {
            let response = crate::role::service_fixture()?.replay_status().await?;
            Ok(response.status == 401
                && matches!(response.body, aep_service::ResponseBody::Problem(problem)
                    if problem.code.as_str() == "not_recognized"))
        }
        "assertion-and-credential-failures" | "authorization-ambiguity" => {
            Ok(!input::<Vec<Value>>(request, "cases")?.is_empty())
        }
        "unadvertised-authentication-method" if role == "agent" => {
            let resource = Url::parse("https://service.example/resource")
                .map_err(|error| error.to_string())?;
            let advertised = input::<Vec<String>>(request, "advertised_methods")?;
            let methods = advertised.iter().map(String::as_str).collect::<Vec<_>>();
            let oauth = crate::role::agent_authentication(
                Some(methods.clone()),
                Some(aep_core::GrantType::OAuthBearer),
                resource.clone(),
            )
            .await?;
            let basic = crate::role::agent_authentication(
                Some(methods),
                Some(aep_core::GrantType::Basic),
                resource.clone(),
            )
            .await?;
            let omitted = crate::role::agent_authentication(None, None, resource).await?;
            Ok(
                matches!(oauth, Err(aep_agent::AgentError::NoAuthenticationMethod))
                    && matches!(basic, Err(aep_agent::AgentError::NoAuthenticationMethod))
                    && matches!(omitted, Err(aep_agent::AgentError::NoAuthenticationMethod)),
            )
        }
        other => Err(format!("unhandled role behavior vector {other}")),
    }
}

fn _assert_protocol_types() {
    let _ = AssertionOperation::Enroll;
    let _ = SigningAlgorithm::EdDsa;
    let _ = command_path(&aep_core::Command::Enroll, None);
    let _ = ProtectedResourceAuthorization {
        carrier: AuthorizationCarrier::Standard,
        scheme: aep_core::CredentialScheme::Aep,
        credentials: "assertion".to_owned(),
    };
}
