use std::collections::BTreeSet;

use aep_core::{
    AUTHORIZATION_HEADER, ApiKeyGrantResponse, AssertionOperation, AuthorizationCarrier,
    ClientAssertionClaims, GrantType, OpenApiPathMatchOptions, OpenApiTrailingSlash,
    ProtectedResourceAuthorization, SigningAlgorithm, command_path, evaluate_claim_support,
    is_version_compatible, match_openapi_path, normalize_endpoint_base,
    parse_built_in_grant_response, parse_claim_values, parse_enroll_request, parse_enroll_response,
    parse_grant_request, parse_inspect_document, parse_problem_details,
    parse_protected_resource_authorization, parse_revoke_request, parse_revoke_response,
    parse_status_response, registered_claims, render_protected_resource_authorization,
    resolve_openapi_url, validate_api_key_grant_response, validate_client_assertion_claims,
};
use serde_json::{Map, Value, json};
use url::Url;

use crate::{
    AdapterRequest, expected, input, object_value,
    platform::{expected_string, expected_u16},
};

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

pub async fn evaluate(request: &AdapterRequest) -> Result<Option<bool>, String> {
    let id = request.vector.id.as_str();
    if CLAIM_VALUE_VECTORS.contains(&id) {
        return Ok(Some(validity(request, "claim_values", parse_claim_values)?));
    }
    let result = match id {
        "person-contact-catalog" => claim_catalog(request)?,
        "negotiation-compatibility" => claim_negotiation(request)?,
        "enroll-claims" => assertion_claims(request)?,
        "validation-requirements" => crate::assertions::validation(request)?,
        "grant-response" | "grant-response-missing-credential-id" => credential_response(request)?,
        "request-minimal" | "request-claims-catalog" => {
            command_request(request, &aep_core::Command::Enroll, parse_enroll_request).await?
        }
        "response-active" | "response-pending-verification-owner-action" => {
            if request.vector.category == "enroll" {
                expected_body(request, parse_enroll_response)?
            } else {
                expected_body(request, parse_status_response)?
            }
        }
        "response-pending-requirements" => expected_body(request, parse_status_response)?,
        "grant-request-oauth-bearer" => {
            command_request(request, &aep_core::Command::Grant, parse_grant_request).await?
        }
        "revoke-request-all-grant-types"
        | "revoke-request-oauth-bearer"
        | "revoke-request-targeted-oauth-bearer" => {
            command_request(request, &aep_core::Command::Revoke, parse_revoke_request).await?
        }
        "revoke-request-conflicting-targets"
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
        "credential-presentations" => credential_presentations(request).await?,
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

/// Checks one published command request against the wire contract the vector states for it: the
/// body has to parse and round-trip to the document the vector expects, and the request line,
/// media type, authorization scheme, assertion operation and idempotency key have to be the ones
/// the specification pairs with that command.
///
/// The endpoint base is the one this adapter's Service fixture advertises; the resulting URL is
/// compared against the path the vector publishes rather than derived from it.
async fn command_request<T, E>(
    request: &AdapterRequest,
    command: &aep_core::Command,
    parse: impl Fn(&[u8]) -> Result<T, E>,
) -> Result<bool, String>
where
    T: serde::Serialize,
    E: std::fmt::Display,
{
    let data = serde_json::to_vec(&object_value(&request.case.input))
        .map_err(|error| error.to_string())?;
    let Ok(parsed) = parse(&data) else {
        return Ok(false);
    };
    let operation = match command {
        aep_core::Command::Enroll => AssertionOperation::Enroll,
        aep_core::Command::Grant => AssertionOperation::Grant,
        aep_core::Command::Revoke => AssertionOperation::Revoke,
        other => return Err(format!("{other:?} carries no command request")),
    };
    let path = command_path(command, Some("/aep")).map_err(|error| error.to_string())?;
    if expected::<String>(request, "method")? != "POST"
        || expected::<String>(request, "path")? != path
        || expected::<String>(request, "content_type")? != aep_core::MEDIA_TYPE
        || expected::<String>(request, "authorization_scheme")? != aep_core::AUTHORIZATION_SCHEME
        || expected::<Value>(request, "client_assertion_op")?
            != serde_json::to_value(operation).map_err(|error| error.to_string())?
    {
        return Ok(false);
    }
    if let Some(key) = request.case.expected.get("idempotency_key")
        && request.case.input.get("idempotency_key") != Some(key)
    {
        return Ok(false);
    }
    let encoded = serde_json::to_value(&parsed).map_err(|error| error.to_string())?;
    if let Some(body) = request.case.expected.get("body")
        && &encoded != body
    {
        return Ok(false);
    }
    if let Some(absent) = request.case.expected.get("must_not_contain") {
        let members: Vec<String> =
            serde_json::from_value(absent.clone()).map_err(|error| error.to_string())?;
        if members.iter().any(|member| encoded.get(member).is_some()) {
            return Ok(false);
        }
    }
    if request.role == "service" {
        return Ok(crate::role::service_command(
            command.as_str(),
            object_value(&request.case.input),
            request
                .case
                .input
                .get("idempotency_key")
                .and_then(Value::as_str)
                .unwrap_or("wire-vector"),
        )
        .await?
        .status
            == 200);
    }
    let body = object_value(&request.case.input);
    let answer = match command {
        aep_core::Command::Enroll => json!({
            "agent_did": body.get("agent_did"), "status":"active", "since":"2026-08-31T12:00:00Z"
        }),
        aep_core::Command::Grant => crate::role::grant_payload(&input(request, "grant_type")?),
        _ => json!({}),
    };
    let key = body
        .get("idempotency_key")
        .and_then(Value::as_str)
        .unwrap_or("wire-vector")
        .to_owned();
    let (requests, result) = crate::role::agent_command(
        command.as_str(),
        body,
        Some(key.clone()),
        answer,
        http::StatusCode::OK,
    )
    .await?;
    result.map_err(|error| error.to_string())?;
    let Some(sent) = requests.last() else {
        return Ok(false);
    };
    if sent.method != http::Method::POST
        || sent.url.path() != path
        || sent
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            != Some(aep_core::MEDIA_TYPE)
        || sent
            .headers
            .get("idempotency-key")
            .and_then(|value| value.to_str().ok())
            != Some(key.as_str())
    {
        return Ok(false);
    }
    let Some(token) = sent
        .headers
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("AEP "))
    else {
        return Ok(false);
    };
    let claims = aep_core::verify_client_assertion(
        token,
        &aep_core::ClientAssertionSigningKey::ed25519_from_seed([5; 32]).verifying_key(),
        &aep_core::VerifyClientAssertionOptions {
            audience: Some("did:web:service.example".to_owned()),
            operation: Some(operation),
            current_time: Some(1_788_177_600),
            ..Default::default()
        },
    )
    .map_err(|error| error.to_string())?;
    let actual_body: Value =
        serde_json::from_slice(&sent.body).map_err(|error| error.to_string())?;
    Ok(claims.op == operation && actual_body == encoded)
}

/// CORE-PR-002: each assertion operation is bound to the one target it names, so every other
/// pairing of an operation with a target is refused. The command operations reach their own
/// command endpoint and `authenticate` reaches only a protected resource.
async fn operation_substitution(request: &AdapterRequest) -> Result<bool, String> {
    let protected_resource: String = input(request, "protected_resource")?;
    let command_endpoints: Vec<String> = input(request, "command_endpoints")?;
    let allowed: Vec<String> = expected(request, "allowed")?;
    if expected::<String>(request, "all_other_pairs")?
        != aep_core::ErrorCode::NotRecognized.as_str()
    {
        return Ok(false);
    }
    let operations: Vec<String> = input(request, "operations")?;
    if allowed.len() != operations.len() {
        return Ok(false);
    }
    for operation in &operations {
        let command = aep_core::Command::from(operation.as_str());
        // `authenticate` is an assertion operation with no command endpoint of its own; every
        // other operation reaches the command endpoint of the same name.
        let target = match command_path(&command, Some("/aep")) {
            Ok(path) => {
                if !command_endpoints.contains(operation) {
                    return Ok(false);
                }
                path.trim_start_matches("/aep/").to_owned()
            }
            Err(_) => {
                if operation != "authenticate" || Url::parse(&protected_resource).is_err() {
                    return Ok(false);
                }
                "protected-resource".to_owned()
            }
        };
        if !allowed.contains(&format!("{operation}:{target}")) {
            return Ok(false);
        }
    }
    crate::protected::agent_operations(request).await
}

async fn service_operation_substitution(request: &AdapterRequest) -> Result<bool, String> {
    let operations: Vec<AssertionOperation> = input(request, "operations")?;
    let endpoints: Vec<String> = input(request, "command_endpoints")?;
    let resource: String = input(request, "protected_resource")?;
    let allowed: Vec<String> = expected(request, "allowed")?;
    let rejected_code: String = expected(request, "all_other_pairs")?;
    for operation in operations {
        for target in endpoints
            .iter()
            .map(String::as_str)
            .chain(["protected-resource"])
        {
            let pair = format!("{}:{target}", operation.as_str());
            let fixture = crate::role::signed_service_fixture()?;
            let assertion = crate::role::signed_assertion(
                operation,
                (operation == AssertionOperation::Authenticate).then_some(resource.as_str()),
                &pair,
            )?;
            let should_accept = allowed.contains(&pair);
            if target == "protected-resource" {
                let result =
                    crate::role::resource_with_assertion(&fixture, &assertion, &resource).await?;
                match result {
                    aep_service::ProtectedResourceAuthentication::Authenticated(_)
                        if should_accept => {}
                    aep_service::ProtectedResourceAuthentication::Rejected(response)
                        if !should_accept =>
                    {
                        if response.status != 401
                            || !matches!(response.body,
                            aep_service::ResponseBody::Problem(problem) if problem.code.as_str() == rejected_code)
                        {
                            return Ok(false);
                        }
                    }
                    _ => return Ok(false),
                }
            } else {
                let response =
                    crate::role::command_with_assertion(&fixture, target, &assertion, &pair)
                        .await?;
                if should_accept {
                    if response.status != 200 {
                        return Ok(false);
                    }
                } else if response.status != 401
                    || !matches!(response.body,
                    aep_service::ResponseBody::Problem(problem) if problem.code.as_str() == rejected_code)
                {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

async fn service_redirect_safety(request: &AdapterRequest) -> Result<bool, String> {
    let source: String = input(request, "source")?;
    let same: String = input(request, "same_origin")?;
    let cross: String = input(request, "cross_origin")?;
    let fixture = crate::role::signed_service_fixture()?;
    for (jti, bound, target, accepted) in [
        ("stale", source.as_str(), same.as_str(), false),
        ("rebound", same.as_str(), same.as_str(), true),
        ("cross-origin", source.as_str(), cross.as_str(), false),
    ] {
        let assertion =
            crate::role::signed_assertion(AssertionOperation::Authenticate, Some(bound), jti)?;
        let result = crate::role::resource_with_assertion(&fixture, &assertion, target).await?;
        match result {
            aep_service::ProtectedResourceAuthentication::Authenticated(_) if accepted => {}
            aep_service::ProtectedResourceAuthentication::Rejected(response) if !accepted => {
                if response.status != 401
                    || !matches!(response.body,
                    aep_service::ResponseBody::Problem(problem) if problem.code == aep_core::ErrorCode::NotRecognized)
                {
                    return Ok(false);
                }
            }
            _ => return Ok(false),
        }
    }
    Ok(true)
}

async fn command_retention(request: &AdapterRequest) -> Result<bool, String> {
    use aep_service::{
        CommandIdempotencyInput, CommandIdempotencyResult, CommandIdempotencyStore as _,
        IdempotentCommand, MemoryCommandIdempotencyStore,
    };
    use std::sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    };
    struct Clock(AtomicI64);
    impl aep_service::Clock for Clock {
        fn now(&self) -> time::OffsetDateTime {
            time::OffsetDateTime::from_unix_timestamp(self.0.load(Ordering::SeqCst))
                .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
        }
    }
    let clock = Arc::new(Clock(AtomicI64::new(1_788_177_600)));
    let store = MemoryCommandIdempotencyStore::with_clock(clock.clone());
    let parse_command = |name: &str| -> Result<IdempotentCommand, String> {
        match name {
            "enroll" => Ok(IdempotentCommand::Enroll),
            "grant" => Ok(IdempotentCommand::Grant),
            "revoke" => Ok(IdempotentCommand::Revoke),
            other => Err(format!("unknown idempotent command {other}")),
        }
    };
    let first = CommandIdempotencyInput {
        agent_did: input(request, "agent_did")?,
        command: parse_command(&input::<String>(request, "first_command")?)?,
        idempotency_key: input(request, "idempotency_key")?,
        request_hash: input(request, "first_body_hash")?,
    };
    let response = crate::role::service_command(
        "enroll",
        json!({"agent_did":"did:web:agent.example"}),
        "store-fixture",
    )
    .await?;
    let saved = response.clone();
    if !matches!(
        store
            .execute(
                first.clone(),
                Box::new(move || Box::pin(async move { Ok(saved) }))
            )
            .await
            .map_err(|error| error.to_string())?,
        CommandIdempotencyResult::Created(_)
    ) {
        return Ok(false);
    }
    let no_execution = || -> aep_service::CommandOperation {
        Box::new(|| {
            Box::pin(async {
                Err(aep_service::ServiceError::Handler(
                    "cached request executed its operation".to_owned(),
                ))
            })
        })
    };
    let mut body_changed = first.clone();
    body_changed.request_hash = input(request, "second_body_hash")?;
    let mut command_changed = first.clone();
    command_changed.command = parse_command(&input::<String>(request, "second_command")?)?;
    for changed in [body_changed, command_changed] {
        if !matches!(
            store
                .execute(changed, no_execution())
                .await
                .map_err(|error| error.to_string())?,
            CommandIdempotencyResult::Conflict
        ) {
            return Ok(false);
        }
    }
    let mut other_agent = first.clone();
    other_agent.agent_did = "did:web:another-agent.example".to_owned();
    let saved = response.clone();
    if !matches!(
        store
            .execute(
                other_agent,
                Box::new(move || Box::pin(async move { Ok(saved) }))
            )
            .await
            .map_err(|error| error.to_string())?,
        CommandIdempotencyResult::Created(_)
    ) {
        return Ok(false);
    }
    let retention: i64 = expected(request, "retention_seconds_minimum")?;
    clock.0.store(1_788_177_600 + retention, Ordering::SeqCst);
    Ok(
        matches!(store.execute(first, no_execution()).await.map_err(|error| error.to_string())?,
        CommandIdempotencyResult::Replayed(replayed) if replayed == response),
    )
}

/// CORE-PR-006: composing AEP with a payment protocol keeps each credential in its own field, so
/// no request carries two AEP-recognized carriers and neither composition is ambiguous.
async fn payment_composition(request: &AdapterRequest) -> Result<bool, String> {
    if input::<u16>(request, "anonymous_status")? != 401
        || input::<String>(request, "anonymous_challenge")? != aep_core::AUTHORIZATION_SCHEME
        || !expected::<bool>(request, "payment_advertised_after_aep")?
    {
        return Ok(false);
    }
    for composition in ["mpp", "x402"] {
        let fields: Map<String, Value> = expected(request, composition)?;
        if fields.get("ambiguous") != Some(&Value::Bool(false)) {
            return Ok(false);
        }
        // The AEP credential travels in the dedicated field, and it has to be one the AEP
        // grammar recognizes on its own.
        let Some(aep) = fields.get(AUTHORIZATION_HEADER).and_then(Value::as_str) else {
            return Ok(false);
        };
        if parse_protected_resource_authorization(aep, AuthorizationCarrier::Dedicated).is_err() {
            return Ok(false);
        }
        // Every other field the composition names carries the payment credential, which the AEP
        // carrier never encodes alongside its own.
        if fields
            .keys()
            .filter(|name| name.as_str() != AUTHORIZATION_HEADER && name.as_str() != "ambiguous")
            .count()
            != 1
        {
            return Ok(false);
        }
    }
    crate::protected::composition(request).await
}

/// CORE-PR-010/018 and CORE-ERR-011: an ambiguous presentation is refused as `not_recognized`
/// with no fallback and nothing disclosed about which credential was read.
async fn authorization_ambiguity(request: &AdapterRequest) -> Result<bool, String> {
    let cases: Vec<String> = input(request, "cases")?;
    if cases.is_empty()
        || expected::<String>(request, "code")? != aep_core::ErrorCode::NotRecognized.as_str()
        || expected::<String>(request, "disclosure")? != "none"
        || expected::<bool>(request, "fallback")?
        || request.case.expected.get("selected_credential") != Some(&Value::Null)
    {
        return Ok(false);
    }
    // A dedicated field value that encodes more than one credential is not a presentation the
    // grammar recognizes, whichever of the published shapes it takes.
    for value in [
        "AEP first, Bearer second",
        "AEP first,AEP second",
        "AEP first second",
    ] {
        let refused =
            parse_protected_resource_authorization(value, AuthorizationCarrier::Dedicated);
        if !matches!(
            refused,
            Err(error) if error.code == aep_core::ErrorCode::NotRecognized
        ) {
            return Ok(false);
        }
    }
    crate::protected::ambiguity(request).await
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
    if aep_core::parse_openapi_aep_security_scheme(&scheme).is_err() {
        return Ok(false);
    }
    let supported = vec!["aep".to_owned(), "session".to_owned()];
    let root = vec![vec!["aep".to_owned()]];
    let cases = [
        ("root_inherited", None),
        ("operation_empty_array", Some(vec![])),
        (
            "empty_requirement_alternative",
            Some(vec![vec![], vec!["aep".to_owned()]]),
        ),
        (
            "multiple_objects",
            Some(vec![vec!["aep".to_owned()], vec!["session".to_owned()]]),
        ),
        (
            "multiple_schemes_one_object",
            Some(vec![vec!["aep".to_owned(), "session".to_owned()]]),
        ),
        (
            "unsupported_compound",
            Some(vec![vec!["aep".to_owned(), "unsupported".to_owned()]]),
        ),
    ];
    for (name, operation) in cases {
        let resolved =
            aep_core::resolve_openapi_security(Some(&root), operation.as_deref(), &supported);
        if resolved.disposition.as_str() != expected::<String>(request, name)? {
            return Ok(false);
        }
        if matches!(
            name,
            "operation_empty_array" | "empty_requirement_alternative" | "unsupported_compound"
        ) && !resolved.satisfiable.is_empty()
        {
            return Ok(false);
        }
    }
    Ok(true)
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
    for (name, presentation) in &request.case.expected {
        let carrier_name = member(presentation, name, "carrier")?;
        let scheme = member(presentation, name, "scheme")?;
        let credentials = member(presentation, name, "credentials")?;
        let carrier = match carrier_name {
            "Authorization" => AuthorizationCarrier::Standard,
            "AEP-Authorization" => AuthorizationCarrier::Dedicated,
            other => return Err(format!("{name} names an unknown carrier {other:?}")),
        };
        let field_value = format!("{scheme} {credentials}");
        let Ok(parsed) = parse_protected_resource_authorization(&field_value, carrier) else {
            return Ok(false);
        };
        let Ok((rendered_carrier, rendered_value)) =
            render_protected_resource_authorization(&parsed)
        else {
            return Ok(false);
        };
        if parsed.scheme.as_str() != scheme
            || parsed.credentials != credentials
            || parsed.carrier != carrier
            || rendered_carrier != carrier_name
            || rendered_value != field_value
        {
            return Ok(false);
        }
    }
    Ok(!request.case.expected.is_empty())
}

/// Reads one string member of a vector's expectation, naming the entry it belongs to when it is
/// absent so that a vector change is reported rather than silently passing.
fn member<'a>(value: &'a Value, entry: &str, name: &str) -> Result<&'a str, String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{entry} is missing the {name:?} member"))
}

async fn credential_presentations(request: &AdapterRequest) -> Result<bool, String> {
    let resource: String = input(request, "resource")?;
    if Url::parse(&resource).is_err() {
        return Ok(false);
    }
    for (grant_type, presentation) in &request.case.expected {
        let header = member(presentation, grant_type, "header")?;
        if !aep_core::is_http_field_name(header) {
            return Ok(false);
        }
        // An API key names its own field and carries an opaque value; the other two are
        // authorization schemes, so each one has to render into the field the vector names.
        if let Some(value) = presentation.get("value").and_then(Value::as_str) {
            let response = ApiKeyGrantResponse {
                api_key: value.to_owned(),
                credential_id: "credential-1".to_owned(),
                expires_at: "2026-05-28T12:00:00Z".to_owned(),
                header: header.to_owned(),
                scopes: Vec::new(),
                additional: Default::default(),
            };
            if validate_api_key_grant_response(&response).is_err() {
                return Ok(false);
            }
            continue;
        }
        let scheme = member(presentation, grant_type, "scheme")?;
        let Ok(parsed) = parse_protected_resource_authorization(
            &format!("{scheme} opaque-credentials"),
            AuthorizationCarrier::Standard,
        ) else {
            return Ok(false);
        };
        let Ok((rendered_header, rendered_value)) =
            render_protected_resource_authorization(&parsed)
        else {
            return Ok(false);
        };
        if rendered_header != header || rendered_value != format!("{scheme} opaque-credentials") {
            return Ok(false);
        }
    }
    Ok(!request.case.expected.is_empty() && crate::protected::presentations(request).await?)
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
    if !(parse_methods("jwt_only")? == vec![aep_core::AuthenticationMethod::AepJwt]
        && parse_methods("credentials_only")?.len() == 3
        && parse_methods("ordered_mixed")?.len() == 4
        && expected.get("omitted_means") == Some(&json!("no-advertised-method")))
    {
        return Ok(false);
    }
    for name in ["jwt_only", "credentials_only", "ordered_mixed"] {
        let methods = parse_methods(name)?;
        let document = crate::role::authentication_document(methods.clone())?;
        if document
            .authentication
            .map(|authentication| authentication.methods)
            != Some(methods)
        {
            return Ok(false);
        }
    }
    Ok(crate::role::authentication_document(vec![])?
        .authentication
        .is_none())
}

pub async fn evaluate_agent(request: &AdapterRequest) -> Result<bool, String> {
    evaluate_role_specific(request, "agent").await
}

pub async fn evaluate_service(request: &AdapterRequest) -> Result<bool, String> {
    evaluate_role_specific(request, "service").await
}

async fn evaluate_role_specific(request: &AdapterRequest, role: &str) -> Result<bool, String> {
    match request.vector.id.as_str() {
        "public-discovery-cache" => {
            crate::role::agent_public_discovery_cache(&request.case.expected).await
        }
        "unknown-required-claim" => {
            let claims = aep_core::InspectClaims {
                required: input(request, "required")?,
                ..Default::default()
            };
            let understood: Vec<aep_core::ClaimName> = input(request, "understood")?;
            let support = evaluate_claim_support(Some(&claims), understood);
            Ok(support.can_satisfy_required == expected::<bool>(request, "can_satisfy")?)
        }
        "service-did-origin-binding" => service_did_binding(request).await,
        "transport-requirements" => transport_requirements(request).await,
        "command-header" => command_header(request).await,
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

async fn service_did_binding(request: &AdapterRequest) -> Result<bool, String> {
    let inspect =
        Url::parse(&input::<String>(request, "inspect_url")?).map_err(|error| error.to_string())?;
    for case in [
        "matching_service_did",
        "mismatched_service_did",
        "unsupported_service_did",
    ] {
        let did: String = input(request, case)?;
        let response = inspect_response(&inspect, &did, aep_core::MEDIA_TYPE)?;
        let (sent, result) = crate::role::inspect_responses(&inspect, vec![response], None).await?;
        let expected: String = expected(request, case)?;
        if expected == "accept" {
            if result.is_err() {
                return Ok(false);
            }
        } else if expected != "service_identity_mismatch"
            || !matches!(
                result,
                Err(aep_agent::AgentError::Inspect {
                    code: aep_agent::InspectErrorCode::ServiceIdentityMismatch,
                    ..
                })
            )
        {
            return Ok(false);
        }
        if sent.len() != 1
            || sent[0].headers.contains_key(http::header::AUTHORIZATION)
            || sent[0].headers.contains_key(aep_core::AUTHORIZATION_HEADER)
            || !sent[0].body.is_empty()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn inspect_response(
    url: &Url,
    did: &str,
    media_type: &str,
) -> Result<aep_core::HttpResponse, String> {
    Ok(aep_core::HttpResponse {
        body: serde_json::to_vec(&crate::role::inspect_document_for(did))
            .map_err(|error| error.to_string())?,
        final_url: url.clone(),
        headers: http::HeaderMap::from_iter([(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_str(media_type).map_err(|error| error.to_string())?,
        )]),
        status: http::StatusCode::OK,
    })
}

async fn transport_requirements(request: &AdapterRequest) -> Result<bool, String> {
    let request_url =
        Url::parse(&input::<String>(request, "request_url")?).map_err(|error| error.to_string())?;
    let redirect_url = Url::parse(&input::<String>(request, "redirect_url")?)
        .map_err(|error| error.to_string())?;
    if !(request_url.scheme() == "https"
        && request_url.origin() == redirect_url.origin()
        && expected::<String>(request, "cross_origin_redirect")? == "reject"
        && expected::<String>(request, "scheme_downgrade")? == "reject")
    {
        return Ok(false);
    }
    let redirect = |target: &Url| -> Result<aep_core::HttpResponse, String> {
        Ok(aep_core::HttpResponse {
            body: Vec::new(),
            final_url: request_url.clone(),
            headers: http::HeaderMap::from_iter([(
                http::header::LOCATION,
                http::HeaderValue::from_str(target.as_str()).map_err(|error| error.to_string())?,
            )]),
            status: http::StatusCode::FOUND,
        })
    };
    let did = format!(
        "did:web:{}",
        request_url
            .host_str()
            .ok_or_else(|| "Inspect host is missing".to_owned())?
    );
    let response = inspect_response(
        &redirect_url,
        &did,
        &input::<String>(request, "content_type")?,
    )?;
    let (sent, result) = crate::role::inspect_responses(
        &request_url,
        vec![redirect(&redirect_url)?, response],
        None,
    )
    .await?;
    if sent.len() != 2 || !matches!(result, Ok(inspection) if inspection.final_url == redirect_url)
    {
        return Ok(false);
    }
    let mut cross_origin = redirect_url.clone();
    cross_origin
        .set_host(Some("other.example.net"))
        .map_err(|error| error.to_string())?;
    let mut downgraded = redirect_url.clone();
    downgraded
        .set_scheme("http")
        .map_err(|()| "invalid downgrade fixture".to_owned())?;
    for target in [cross_origin, downgraded] {
        let (sent, result) =
            crate::role::inspect_responses(&request_url, vec![redirect(&target)?], None).await?;
        if sent.len() != 1
            || !matches!(
                result,
                Err(aep_agent::AgentError::Inspect {
                    code: aep_agent::InspectErrorCode::InvalidRedirect,
                    ..
                })
            )
        {
            return Ok(false);
        }
    }
    let response = inspect_response(&request_url, &did, aep_core::MEDIA_TYPE)?;
    let limit = response.body.len() - 1;
    let (_, result) =
        crate::role::inspect_responses(&request_url, vec![response], Some(limit)).await?;
    Ok(
        expected::<String>(request, "partial_document_after_bound")? == "reject"
            && matches!(
                result,
                Err(aep_agent::AgentError::Inspect {
                    code: aep_agent::InspectErrorCode::ResponseTooLarge,
                    ..
                })
            ),
    )
}

async fn command_header(request: &AdapterRequest) -> Result<bool, String> {
    let commands: Vec<String> = input(request, "commands")?;
    let key: String = input(request, "idempotency_key")?;
    if !(!key.is_empty()
        && commands
            .iter()
            .all(|command| matches!(command.as_str(), "enroll" | "grant" | "revoke"))
        && expected::<bool>(request, "header_required")?)
    {
        return Ok(false);
    }
    for command in commands {
        let body = match command.as_str() {
            "enroll" => json!({"agent_did":"did:web:agent.example"}),
            "grant" => json!({"grant_type":"oauth-bearer"}),
            _ => json!({"all_grant_types":"true"}),
        };
        if request.role == "service" {
            let response = crate::role::service_command(&command, body.clone(), "").await?;
            if response.status != expected::<u16>(request, "missing_or_empty_status")?
                || !matches!(response.body, aep_service::ResponseBody::Problem(problem)
                    if problem.code.as_str() == expected::<String>(request, "missing_or_empty_code")?)
            {
                return Ok(false);
            }
            if crate::role::service_command(&command, body.clone(), &key)
                .await?
                .status
                != 200
            {
                return Ok(false);
            }
            if command == "enroll" {
                let mut mismatched = body;
                mismatched["idempotency_key"] = json!(format!("{key}-different"));
                if crate::role::service_command(&command, mismatched, &key)
                    .await?
                    .status
                    != expected::<u16>(request, "mismatched_enroll_body_status")?
                {
                    return Ok(false);
                }
            }
        } else {
            let answer = match command.as_str() {
                "enroll" => {
                    json!({"agent_did":"did:web:agent.example", "status":"active", "since":"2026-08-31T12:00:00Z"})
                }
                "grant" => crate::role::grant_payload(&GrantType::OAuthBearer),
                _ => json!({}),
            };
            let (sent, result) = crate::role::agent_command(
                &command,
                body,
                Some(key.clone()),
                answer,
                http::StatusCode::OK,
            )
            .await?;
            result.map_err(|error| error.to_string())?;
            let Some(sent) = sent.last() else {
                return Ok(false);
            };
            if sent
                .headers
                .get("idempotency-key")
                .and_then(|value| value.to_str().ok())
                != Some(key.as_str())
            {
                return Ok(false);
            }
            if command == "enroll" {
                let body: Value =
                    serde_json::from_slice(&sent.body).map_err(|error| error.to_string())?;
                if body.get("idempotency_key").and_then(Value::as_str) != Some(key.as_str()) {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

async fn role_behavior(request: &AdapterRequest, role: &str) -> Result<bool, String> {
    match request.vector.id.as_str() {
        // CORE-PR-038 and CORE-CA-016: an unauthenticated request is answered with the published
        // challenge, and the assertion that satisfies it carries the claims the vector states.
        "authenticate-assertion" if role == "service" => {
            let fixture = crate::role::service_fixture()?;
            let scheme = expected_string(request, "authorization_scheme")?;
            let challenge: Map<String, Value> = expected(request, "challenge")?;
            let claims: Map<String, Value> = expected(request, "claims")?;
            if scheme != aep_core::AUTHORIZATION_SCHEME
                || challenge.get("scheme").and_then(Value::as_str) != Some(scheme.as_str())
                || challenge.get("reason").and_then(Value::as_str)
                    != Some(aep_core::ErrorCode::AuthenticationRequired.as_str())
                || claims.get("op").and_then(Value::as_str)
                    != Some(AssertionOperation::Authenticate.as_str())
                || claims.get("iss") != claims.get("sub")
                || claims.get("resource").and_then(Value::as_str)
                    != Some(input::<String>(request, "url")?.as_str())
            {
                return Ok(false);
            }
            // The published window is the one AEP core admits for an assertion.
            let window = claims
                .get("exp")
                .and_then(Value::as_i64)
                .zip(claims.get("iat").and_then(Value::as_i64))
                .map(|(expires, issued)| expires - issued);
            if !matches!(window, Some(1..=300)) {
                return Ok(false);
            }
            // A request with no credential is answered with a challenge naming this Service.
            let refusal = fixture.unauthenticated_resource().await?;
            let aep_service::ProtectedResourceAuthentication::Rejected(refusal) = refusal else {
                return Ok(false);
            };
            let Some(header) = refusal
                .headers
                .get(http::header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok())
            else {
                return Ok(false);
            };
            if !header.starts_with(&format!("{scheme} "))
                || !header.contains("service_did=")
                || !header.contains("inspect=")
                || !header.contains(&format!(
                    "reason=\"{}\"",
                    aep_core::ErrorCode::AuthenticationRequired.as_str()
                ))
            {
                return Ok(false);
            }
            Ok(matches!(
                fixture.authenticate_assertion().await?,
                aep_service::ProtectedResourceAuthentication::Authenticated(principal)
                    if principal.authentication_method == aep_core::AuthenticationMethod::AepJwt
            ))
        }
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
        "operation-substitution-rejected" if role == "service" => {
            service_operation_substitution(request).await
        }
        "operation-substitution-rejected" => operation_substitution(request).await,
        "redirect-safety" if role == "service" => service_redirect_safety(request).await,
        "redirect-safety" => {
            let source = Url::parse(&input::<String>(request, "source")?)
                .map_err(|error| error.to_string())?;
            let same = Url::parse(&input::<String>(request, "same_origin")?)
                .map_err(|error| error.to_string())?;
            let cross = Url::parse(&input::<String>(request, "cross_origin")?)
                .map_err(|error| error.to_string())?;
            let same_expected: Value = expected(request, "same_origin")?;
            let cross_expected: Value = expected(request, "cross_origin")?;
            if !(source.origin() == same.origin()
                && source.origin() != cross.origin()
                && same_expected.get("credential_forwarded") == Some(&json!(false))
                && same_expected.get("new_authenticate_assertion_resource")
                    == Some(&json!(same.as_str()))
                && cross_expected.get("anonymous_restart") == Some(&json!(true))
                && cross_expected.get("assertion_forwarded") == Some(&json!(false))
                && cross_expected.get("session_credential_forwarded") == Some(&json!(false))
                && cross_expected.get("api_key_header_forwarded") == Some(&json!(false)))
            {
                return Ok(false);
            }
            // The Agent returns headers; the application owns HTTP requests and redirects.
            crate::role::agent_redirect_authentication(&source, &same, &cross).await
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
        "authorization-payment-composition" => payment_composition(request).await,
        "authorization-field-safety" => {
            let field: String = input(request, "field_name")?;
            Ok(aep_core::is_http_field_name(&field)
                && field.eq_ignore_ascii_case("AEP-Authorization")
                && expected::<String>(request, "field_name_match")? == "case-insensitive"
                && crate::protected::field_safety(request).await?)
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
            let (response, unchanged, policy_evaluated) =
                crate::role::repeated_existing(agent_did, since, idempotency_key).await?;
            let expected_status = request
                .case
                .expected
                .get("response")
                .and_then(|value| value.get("body"))
                .and_then(|value| value.get("status"))
                .and_then(Value::as_str);
            Ok(unchanged != expected::<bool>(request, "record_replaced")?
                && policy_evaluated == expected::<bool>(request, "policy_evaluated")?
                && response.status == 200
                && matches!(response.body, aep_service::ResponseBody::Enroll(enrollment)
                    if enrollment.status.as_str() == expected_status.unwrap_or_default()))
        }
        // CORE-IDP-004/006/009: an exact retry replays the stored result, the same key with other
        // material conflicts, and the record is scoped to the Agent and the key.
        "command-replay-conflict" | "enroll-conflict" if role == "service" => {
            let fixture = crate::role::service_fixture()?;
            let (status, code) = if request.vector.id == "enroll-conflict" {
                if expected_string(request, "content_type")? != aep_core::PROBLEM_MEDIA_TYPE {
                    return Ok(false);
                }
                let body: Map<String, Value> = expected(request, "body")?;
                let code = body
                    .get("code")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "expectation body is missing the code".to_owned())?;
                if body.get("type").and_then(Value::as_str)
                    != Some(&format!("urn:aep:error:{code}"))
                    || body.get("status").and_then(Value::as_i64)
                        != Some(i64::from(expected_u16(request, "status")?))
                    || body
                        .get("title")
                        .and_then(Value::as_str)
                        .is_none_or(str::is_empty)
                {
                    return Ok(false);
                }
                (expected_u16(request, "status")?, code.to_owned())
            } else {
                let changed_body: Map<String, Value> = expected(request, "changed_body")?;
                let changed_command: Map<String, Value> = expected(request, "changed_command")?;
                let scope: Vec<String> = expected(request, "scope")?;
                if changed_body != changed_command
                    || scope != vec!["agent_did".to_owned(), "idempotency_key".to_owned()]
                    || expected_string(request, "exact_retry")? != "cached_or_equivalent_success"
                    || request
                        .case
                        .expected
                        .get("retention_seconds_minimum")
                        .and_then(Value::as_u64)
                        != Some(3600)
                {
                    return Ok(false);
                }
                let status = changed_body
                    .get("status")
                    .and_then(Value::as_u64)
                    .and_then(|value| u16::try_from(value).ok())
                    .ok_or_else(|| "expectation is missing the conflict status".to_owned())?;
                let code = changed_body
                    .get("code")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "expectation is missing the conflict code".to_owned())?;
                (status, code.to_owned())
            };
            // An exact retry returns the stored result rather than running the command again.
            let (first, replay) = fixture.idempotent_replay().await?;
            if first.to_json().map_err(|error| error.to_string())?
                != replay.to_json().map_err(|error| error.to_string())?
            {
                return Ok(false);
            }
            let response = fixture.idempotency_conflict().await?;
            let matched = response.status == status
                && matches!(response.body, aep_service::ResponseBody::Problem(problem)
                    if problem.code.as_str() == code);
            Ok(matched
                && (request.vector.id == "enroll-conflict" || command_retention(request).await?))
        }
        "assertion-and-credential-failures" => crate::protected::failures(request).await,
        "authorization-ambiguity" => authorization_ambiguity(request).await,
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
            let credential = crate::role::agent_authentication_selected(
                Some(methods),
                None,
                resource.clone(),
                AuthorizationCarrier::Standard,
                Some("credential-1".to_owned()),
            )
            .await?;
            let omitted = crate::role::agent_authentication(None, None, resource).await?;
            // The vector names each outcome, including that an omitted `authentication` object
            // infers no method at all.
            Ok(
                expected::<String>(request, "explicit_unadvertised_credential")? == "reject"
                    && expected::<String>(request, "explicit_unadvertised_grant_type")? == "reject"
                    && expected::<String>(request, "omitted_authentication")? == "reject"
                    && request.case.expected.get("inferred_method") == Some(&Value::Null)
                    && matches!(oauth, Err(aep_agent::AgentError::NoAuthenticationMethod))
                    && matches!(
                        credential,
                        Err(aep_agent::AgentError::NoAuthenticationMethod)
                    )
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
