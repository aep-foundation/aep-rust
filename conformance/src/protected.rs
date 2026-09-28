use std::sync::Arc;

use aep_core::{AssertionOperation, AuthorizationCarrier, ErrorCode, GrantType};
use aep_service::{
    IdempotentCommandOptions, ProtectedResourceAuthentication, ProtectedResourceRequest,
    ResponseBody, Service, ServiceCredentialStore as _,
};
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use serde_json::{Value, json};
use time::OffsetDateTime;
use url::Url;

use crate::{AdapterRequest, expected, input, role};

const RESOURCE: &str = "https://service.example/resource";

pub async fn agent_operations(request: &AdapterRequest) -> Result<bool, String> {
    let resource: String = input(request, "protected_resource")?;
    let endpoints: Vec<String> = input(request, "command_endpoints")?;
    let allowed: Vec<String> = expected(request, "allowed")?;
    for operation in input::<Vec<AssertionOperation>>(request, "operations")? {
        let (token, audience) = if operation == AssertionOperation::Authenticate {
            let resource = Url::parse(&resource).map_err(|error| error.to_string())?;
            let authentication =
                role::agent_authentication(Some(vec!["aep-jwt"]), None, resource.clone())
                    .await?
                    .map_err(|error| error.to_string())?;
            let value = authentication
                .headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("AEP "))
                .ok_or_else(|| "Agent omitted its assertion".to_owned())?;
            let host = resource
                .host_str()
                .ok_or_else(|| "resource host missing".to_owned())?;
            let audience = match resource.port() {
                Some(port) => format!("did:web:{host}%3A{port}"),
                None => format!("did:web:{host}"),
            };
            (value.to_owned(), audience)
        } else {
            let body = match operation {
                AssertionOperation::Enroll => json!({"agent_did":"did:web:agent.example"}),
                AssertionOperation::Grant => json!({"grant_type":"oauth-bearer"}),
                AssertionOperation::Revoke => json!({"all_grant_types":"true"}),
                _ => json!({}),
            };
            let answer = match operation {
                AssertionOperation::Grant => role::grant_payload(&GrantType::OAuthBearer),
                AssertionOperation::Revoke => json!({}),
                _ => {
                    json!({"agent_did":"did:web:agent.example", "status":"active", "since":"2026-08-31T12:00:00Z"})
                }
            };
            let (sent, result) = role::agent_command(
                operation.as_str(),
                body,
                Some("operation-vector".to_owned()),
                answer,
                StatusCode::OK,
            )
            .await?;
            result.map_err(|error| error.to_string())?;
            let sent = sent
                .last()
                .ok_or_else(|| "Agent sent no command".to_owned())?;
            if sent.url.path() != format!("/aep/{}", operation.as_str()) {
                return Ok(false);
            }
            let token = sent
                .headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("AEP "))
                .ok_or_else(|| "Agent omitted its command assertion".to_owned())?;
            (token.to_owned(), "did:web:service.example".to_owned())
        };
        for target in endpoints
            .iter()
            .map(String::as_str)
            .chain(["protected-resource"])
        {
            let target_operation = if target == "protected-resource" {
                AssertionOperation::Authenticate
            } else {
                serde_json::from_value(json!(target)).map_err(|error| error.to_string())?
            };
            let result = aep_core::verify_client_assertion(
                &token,
                &aep_core::ClientAssertionSigningKey::ed25519_from_seed([5; 32]).verifying_key(),
                &aep_core::VerifyClientAssertionOptions {
                    audience: Some(audience.clone()),
                    operation: Some(target_operation),
                    issuer: Some("did:web:agent.example".to_owned()),
                    subject: Some("did:web:agent.example".to_owned()),
                    current_time: Some(1_788_177_600),
                    resource: (target == "protected-resource").then(|| resource.clone()),
                    ..Default::default()
                },
            );
            if result.is_ok() != allowed.contains(&format!("{}:{target}", operation.as_str())) {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

async fn authenticate(
    service: &Arc<Service>,
    headers: HeaderMap,
) -> Result<ProtectedResourceAuthentication, String> {
    service
        .authenticate_protected_resource(ProtectedResourceRequest {
            headers,
            method: Method::GET,
            url: Url::parse(RESOURCE).map_err(|error| error.to_string())?,
        })
        .await
        .map_err(|error| error.to_string())
}

fn headers(name: &str, value: &str) -> Result<HeaderMap, String> {
    Ok(HeaderMap::from_iter([(
        http::HeaderName::from_bytes(name.as_bytes()).map_err(|error| error.to_string())?,
        HeaderValue::from_str(value).map_err(|error| error.to_string())?,
    )]))
}

async fn issue_oauth(service: &Arc<Service>) -> Result<String, String> {
    let response = service
        .grant(
            br#"{"grant_type":"oauth-bearer"}"#,
            IdempotentCommandOptions {
                client_assertion: role::signed_assertion(
                    AssertionOperation::Grant,
                    None,
                    "issue-oauth",
                )?,
                idempotency_key: "issue-oauth".to_owned(),
            },
        )
        .await
        .map_err(|error| error.to_string())?;
    let ResponseBody::Grant(body) = response.body else {
        return Err("OAuth Grant failed".to_owned());
    };
    body.get("access_token")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "OAuth Grant omitted access_token".to_owned())
}

pub async fn composition(request: &AdapterRequest) -> Result<bool, String> {
    let (service, _) = role::authentication_service()?;
    let token = issue_oauth(&service).await?;
    let anonymous = authenticate(&service, HeaderMap::new()).await?;
    let ProtectedResourceAuthentication::Rejected(anonymous) = anonymous else {
        return Ok(false);
    };
    if anonymous.status != input::<u16>(request, "anonymous_status")?
        || !anonymous
            .headers
            .get(header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("AEP "))
    {
        return Ok(false);
    }
    for (name, grant_type) in [("mpp", None), ("x402", Some(GrantType::OAuthBearer))] {
        let mut fields = if request.role == "agent" {
            let methods = if grant_type.is_some() {
                vec!["oauth-bearer"]
            } else {
                vec!["aep-jwt"]
            };
            role::agent_authentication_with_carrier(
                Some(methods),
                grant_type.clone(),
                Url::parse(RESOURCE).map_err(|error| error.to_string())?,
                AuthorizationCarrier::Dedicated,
            )
            .await?
            .map_err(|error| error.to_string())?
            .headers
        } else {
            let value = if grant_type.is_some() {
                format!("Bearer {token}")
            } else {
                format!(
                    "AEP {}",
                    role::signed_assertion(
                        AssertionOperation::Authenticate,
                        Some(RESOURCE),
                        "payment"
                    )?
                )
            };
            headers("AEP-Authorization", &value)?
        };
        if fields.len() != 1 || !fields.contains_key(aep_core::AUTHORIZATION_HEADER) {
            return Ok(false);
        }
        let expected: Value = expected(request, name)?;
        let payment_name = if name == "mpp" {
            "Authorization"
        } else {
            "PAYMENT-SIGNATURE"
        };
        let payment = expected
            .get(payment_name)
            .and_then(Value::as_str)
            .ok_or_else(|| "payment credential fixture is missing".to_owned())?;
        fields.extend(headers(payment_name, payment)?);
        if !matches!(
            authenticate(&service, fields).await?,
            ProtectedResourceAuthentication::Authenticated(_)
        ) {
            return Ok(false);
        }
    }
    Ok(true)
}

pub async fn ambiguity(request: &AdapterRequest) -> Result<bool, String> {
    if request.role == "agent" {
        for carrier in [
            AuthorizationCarrier::Standard,
            AuthorizationCarrier::Dedicated,
        ] {
            let result = role::agent_authentication_with_carrier(
                Some(vec!["aep-jwt"]),
                None,
                Url::parse(RESOURCE).map_err(|error| error.to_string())?,
                carrier,
            )
            .await?
            .map_err(|error| error.to_string())?;
            if result.headers.len() != 1 {
                return Ok(false);
            }
        }
        return Ok(true);
    }
    let (service, _) = role::authentication_service()?;
    let bearer = format!("Bearer {}", issue_oauth(&service).await?);
    for case in input::<Vec<String>>(request, "cases")? {
        let assertion = format!(
            "AEP {}",
            role::signed_assertion(AssertionOperation::Authenticate, Some(RESOURCE), &case)?
        );
        let mut fields = headers("AEP-Authorization", &assertion)?;
        match case.as_str() {
            "both-aep-recognized" => fields.extend(headers("Authorization", &bearer)?),
            "invalid-dedicated-plus-valid-standard" => {
                fields = headers("AEP-Authorization", "malformed")?;
                fields.extend(headers("Authorization", &bearer)?);
            }
            "duplicate-dedicated-lines" => {
                fields.append(
                    "aep-authorization",
                    HeaderValue::from_str(&assertion).map_err(|error| error.to_string())?,
                );
            }
            "combined-dedicated-values" => {
                fields = headers("AEP-Authorization", &format!("{assertion}, {bearer}"))?
            }
            other => return Err(format!("unhandled carrier ambiguity {other}")),
        }
        let ProtectedResourceAuthentication::Rejected(response) =
            authenticate(&service, fields).await?
        else {
            return Ok(false);
        };
        if response.status != 401
            || !matches!(response.body, ResponseBody::Problem(problem)
            if problem.code.as_str() == expected::<String>(request, "code")?)
        {
            return Ok(false);
        }
    }
    Ok(matches!(
        authenticate(&service, headers("Authorization", &bearer)?).await?,
        ProtectedResourceAuthentication::Authenticated(_)
    ))
}

pub async fn failures(request: &AdapterRequest) -> Result<bool, String> {
    for case in input::<Vec<String>>(request, "cases")? {
        let (status, body) = failure(&case).await?;
        let code: String = expected(request, &case)?;
        if body.get("code").and_then(Value::as_str) != Some(code.as_str())
            || body.get("status").and_then(Value::as_u64) != Some(u64::from(status))
        {
            return Ok(false);
        }
        if request.role == "agent" {
            // Resource HTTP belongs to the application; command HTTP uses the same Problem Details contract.
            let (_, result) = role::agent_command(
                "status",
                json!({}),
                None,
                body,
                StatusCode::from_u16(status).map_err(|error| error.to_string())?,
            )
            .await?;
            if !matches!(result, Err(aep_agent::AgentError::Command { status: actual, problem: Some(problem) })
                if actual == status && problem.code.as_str() == code)
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

async fn failure(case: &str) -> Result<(u16, Value), String> {
    let (service, store) = role::authentication_service()?;
    let assertion = role::signed_assertion(AssertionOperation::Authenticate, Some(RESOURCE), case)?;
    let fields = match case {
        "wrong_audience" | "expired_assertion" => {
            let decoded =
                aep_core::decode_jwt_unverified(&assertion).map_err(|error| error.to_string())?;
            let mut payload =
                serde_json::to_value(decoded.payload).map_err(|error| error.to_string())?;
            if case == "wrong_audience" {
                payload["aud"] = json!("did:web:other.example");
            } else {
                let issued = payload
                    .get("iat")
                    .and_then(Value::as_i64)
                    .ok_or_else(|| "assertion omitted iat".to_owned())?;
                payload["iat"] = json!(issued - 120);
                payload["exp"] = json!(issued - 60);
            }
            let token =
                crate::assertions::sign_raw(payload, Some("did:web:agent.example#key-1"), "JWT")?;
            headers("Authorization", &format!("AEP {token}"))?
        }
        "replayed_assertion" => {
            let fields = headers("Authorization", &format!("AEP {assertion}"))?;
            if !matches!(
                authenticate(&service, fields.clone()).await?,
                ProtectedResourceAuthentication::Authenticated(_)
            ) {
                return Err("initial assertion failed before replay".to_owned());
            }
            fields
        }
        "malformed_credential" => headers("Authorization", "Bearer first second")?,
        "expired_credential" => {
            let decoded =
                aep_core::decode_jwt_unverified(&assertion).map_err(|error| error.to_string())?;
            let now = decoded
                .payload
                .get("iat")
                .and_then(Value::as_i64)
                .ok_or_else(|| "assertion omitted iat".to_owned())?;
            let expires =
                OffsetDateTime::from_unix_timestamp(now - 60).map_err(|error| error.to_string())?;
            let mut payload = role::grant_payload(&GrantType::OAuthBearer);
            payload["expires_at"] = json!(
                expires
                    .format(&time::format_description::well_known::Rfc3339)
                    .map_err(|error| error.to_string())?
            );
            store
                .save(aep_service::ServiceCredentialRecord {
                    agent_did: "did:web:agent.example".to_owned(),
                    created_at: expires - time::Duration::hours(1),
                    credential: aep_core::BuiltInGrantResponse::OAuthBearer(
                        serde_json::from_value(payload).map_err(|error| error.to_string())?,
                    ),
                    credential_id: "credential-1".to_owned(),
                    expires_at: expires,
                    grant_type: GrantType::OAuthBearer,
                })
                .await
                .map_err(|error| error.to_string())?;
            headers("Authorization", "Bearer secret")?
        }
        "unsupported_method" => {
            let fixture = role::service_fixture()?;
            return rejected(
                authenticate(&fixture.service, headers("Authorization", "Bearer secret")?).await?,
            );
        }
        "insufficient_scope" => {
            let ProtectedResourceAuthentication::Authenticated(principal) = authenticate(
                &service,
                headers("Authorization", &format!("AEP {assertion}"))?,
            )
            .await?
            else {
                return Err("scope test requires successful authentication".to_owned());
            };
            if principal.scopes.iter().any(|scope| scope == "orders:write") {
                return Err("scope fixture unexpectedly authorizes writing".to_owned());
            }
            // Application authorization follows authentication; the SDK constructs its standardized failure.
            return Ok((
                403,
                serde_json::to_value(aep_core::new_problem_details(
                    ErrorCode::InsufficientScope,
                    "Writing orders requires orders:write",
                    403,
                ))
                .map_err(|error| error.to_string())?,
            ));
        }
        other => return Err(format!("unhandled protected-resource failure {other}")),
    };
    rejected(authenticate(&service, fields).await?)
}

fn rejected(result: ProtectedResourceAuthentication) -> Result<(u16, Value), String> {
    let ProtectedResourceAuthentication::Rejected(response) = result else {
        return Err("invalid credential was accepted".to_owned());
    };
    Ok((
        response.status,
        response.to_json().map_err(|error| error.to_string())?,
    ))
}

pub async fn presentations(request: &AdapterRequest) -> Result<bool, String> {
    let resource =
        Url::parse(&input::<String>(request, "resource")?).map_err(|error| error.to_string())?;
    for (name, expected) in &request.case.expected {
        let grant_type = GrantType::from(name.as_str());
        let authentication = role::agent_authentication(
            Some(vec![name.as_str()]),
            Some(grant_type.clone()),
            resource.clone(),
        )
        .await?
        .map_err(|error| error.to_string())?;
        let header = expected
            .get("header")
            .and_then(Value::as_str)
            .ok_or_else(|| "presentation header is missing".to_owned())?;
        let Some(value) = authentication
            .headers
            .get(header)
            .and_then(|value| value.to_str().ok())
        else {
            return Ok(false);
        };
        if let Some(expected_value) = expected.get("value").and_then(Value::as_str) {
            if value != expected_value {
                return Ok(false);
            }
        } else {
            let scheme = expected
                .get("scheme")
                .and_then(Value::as_str)
                .ok_or_else(|| "presentation scheme is missing".to_owned())?;
            if !value.starts_with(&format!("{scheme} ")) {
                return Ok(false);
            }
        }
        if authentication.headers.len() != 1 || format!("{authentication:?}").contains(value) {
            return Ok(false);
        }
        if request.role == "service" {
            let (service, _) = role::authentication_service()?;
            let response = service
                .grant(
                    &serde_json::to_vec(&json!({"grant_type":name}))
                        .map_err(|error| error.to_string())?,
                    IdempotentCommandOptions {
                        client_assertion: role::signed_assertion(
                            AssertionOperation::Grant,
                            None,
                            "presentation-grant",
                        )?,
                        idempotency_key: "presentation-grant".to_owned(),
                    },
                )
                .await
                .map_err(|error| error.to_string())?;
            if response.status != 200 {
                return Ok(false);
            }
            let result = service
                .authenticate_protected_resource(ProtectedResourceRequest {
                    headers: authentication.headers,
                    method: Method::GET,
                    url: resource.clone(),
                })
                .await
                .map_err(|error| error.to_string())?;
            if !matches!(result, ProtectedResourceAuthentication::Authenticated(principal)
                if principal.grant_type == Some(grant_type))
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

pub async fn field_safety(request: &AdapterRequest) -> Result<bool, String> {
    let name: String = input(request, "field_name")?;
    let authentication = role::agent_authentication_with_carrier(
        Some(vec!["aep-jwt"]),
        None,
        Url::parse(RESOURCE).map_err(|error| error.to_string())?,
        AuthorizationCarrier::Dedicated,
    )
    .await?
    .map_err(|error| error.to_string())?;
    let Some(value) = authentication.headers.get(&name) else {
        return Ok(false);
    };
    let mut fields = HeaderMap::new();
    fields.insert(
        http::HeaderName::from_bytes(name.as_bytes()).map_err(|error| error.to_string())?,
        value.clone(),
    );
    fields.insert(
        "payment-signature",
        HeaderValue::from_static("payment-secret"),
    );
    let request = ProtectedResourceRequest {
        headers: fields,
        method: Method::GET,
        url: Url::parse(RESOURCE).map_err(|error| error.to_string())?,
    };
    let value = value.to_str().map_err(|error| error.to_string())?;
    if format!("{authentication:?}").contains(value)
        || format!("{request:?}").contains(value)
        || format!("{request:?}").contains("payment-secret")
    {
        return Ok(false);
    }
    let (service, _) = role::authentication_service()?;
    Ok(matches!(
        service
            .authenticate_protected_resource(request)
            .await
            .map_err(|error| error.to_string())?,
        ProtectedResourceAuthentication::Authenticated(_)
    ))
}
