use std::sync::OnceLock;

use regex::Regex;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;

use crate::{
    ApiKeyGrantResponse, AssertionOperation, BasicGrantResponse, BuiltInGrantResponse,
    ClientAssertionClaims, EnrollRequest, EnrollResponse, ErrorCode, GrantRequest, GrantType,
    IdempotencyMetadata, MAX_ASSERTION_LIFETIME, OAuthBearerGrantResponse,
    OpenApiAepSecurityScheme, ParseError, ProblemDetails, RevokeRequest, RevokeResponse,
    StatusResponse, StringBoolean, ValidationError, ValidationIssue,
    claims::validate_claim_values,
    openapi::is_loopback_host,
    validation::{
        issue, parse_and_validate, require_non_empty, result, validate_non_empty_strings,
    },
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClientAssertionValidationOptions {
    pub allow_insecure_loopback: bool,
}

pub fn parse_enroll_request(data: &[u8]) -> Result<EnrollRequest, ParseError> {
    parse_and_validate(data, "Enroll request", validate_enroll_request)
}

pub fn validate_enroll_request(value: &EnrollRequest) -> Result<(), ValidationError> {
    let mut issues = Vec::new();
    require_non_empty(&value.agent_did, "$.agent_did", &mut issues);
    if value.idempotency_key.as_deref() == Some("") {
        issues.push(issue("$.idempotency_key", "Expected a non-empty string."));
    }
    if let Some(claims) = &value.claims
        && let Err(error) = validate_claim_values(claims)
    {
        issues.extend(error.issues);
    }
    result("Enroll request", issues)
}

pub fn parse_enroll_response(data: &[u8]) -> Result<EnrollResponse, ParseError> {
    parse_and_validate(data, "Enroll response", validate_enroll_response)
}

pub fn validate_enroll_response(value: &EnrollResponse) -> Result<(), ValidationError> {
    let mut issues = Vec::new();
    validate_optional_non_empty_unique(
        value.verification_pending.as_deref(),
        "$.verification_pending",
        &mut issues,
    );
    validate_optional_non_empty_unique(
        value.requirements_pending.as_deref(),
        "$.requirements_pending",
        &mut issues,
    );
    result("Enroll response", issues)
}

pub fn parse_status_response(data: &[u8]) -> Result<StatusResponse, ParseError> {
    parse_and_validate(data, "Status response", validate_status_response)
}

pub fn validate_status_response(value: &StatusResponse) -> Result<(), ValidationError> {
    let mut issues = Vec::new();
    validate_optional_non_empty_unique(
        value.verification_pending.as_deref(),
        "$.verification_pending",
        &mut issues,
    );
    validate_optional_non_empty_unique(
        value.requirements_pending.as_deref(),
        "$.requirements_pending",
        &mut issues,
    );
    if value
        .since
        .as_deref()
        .is_some_and(|since| !is_rfc3339(since))
    {
        issues.push(issue("$.since", "Expected an RFC 3339 date-time."));
    }
    result("Status response", issues)
}

pub fn parse_grant_request(data: &[u8]) -> Result<GrantRequest, ParseError> {
    parse_and_validate(data, "Grant request", validate_grant_request)
}

pub fn validate_grant_request(value: &GrantRequest) -> Result<(), ValidationError> {
    let mut issues = Vec::new();
    require_non_empty(value.grant_type.as_str(), "$.grant_type", &mut issues);
    validate_strings(&value.requested_scopes, "$.requested_scopes", &mut issues);
    result("Grant request", issues)
}

pub fn parse_revoke_request(data: &[u8]) -> Result<RevokeRequest, ParseError> {
    parse_and_validate(data, "Revoke request", validate_revoke_request)
}

pub fn validate_revoke_request(value: &RevokeRequest) -> Result<(), ValidationError> {
    let mut issues = Vec::new();
    let has_all = value.all_grant_types.is_some();
    let has_credential = value.credential_id.is_some();
    let has_grant = value.grant_type.is_some();
    if value.all_grant_types == Some(StringBoolean::False) {
        issues.push(issue("$.all_grant_types", "Expected true."));
    }
    if value.credential_id.as_deref() == Some("") {
        issues.push(issue("$.credential_id", "Expected a non-empty string."));
    }
    if has_all == has_grant || (has_all && has_credential) {
        issues.push(issue(
            "$",
            "Expected grant_type, grant_type with credential_id, or all_grant_types.",
        ));
    }
    result("Revoke request", issues)
}

pub fn parse_revoke_response(data: &[u8]) -> Result<RevokeResponse, ParseError> {
    parse_and_validate(data, "Revoke response", validate_revoke_response)
}

pub fn validate_revoke_response(_value: &RevokeResponse) -> Result<(), ValidationError> {
    Ok(())
}

pub fn parse_idempotency_metadata(data: &[u8]) -> Result<IdempotencyMetadata, ParseError> {
    parse_and_validate(data, "Idempotency metadata", validate_idempotency_metadata)
}

pub fn validate_idempotency_metadata(value: &IdempotencyMetadata) -> Result<(), ValidationError> {
    let mut issues = Vec::new();
    require_non_empty(&value.idempotency_key, "$.idempotency_key", &mut issues);
    if value.agent_did.as_deref() == Some("") {
        issues.push(issue("$.agent_did", "Expected a non-empty string."));
    }
    validate_body_hash(
        value.first_body_hash.as_deref(),
        "$.first_body_hash",
        &mut issues,
    );
    validate_body_hash(
        value.second_body_hash.as_deref(),
        "$.second_body_hash",
        &mut issues,
    );
    result("Idempotency metadata", issues)
}

pub fn parse_openapi_aep_security_scheme(
    data: &[u8],
) -> Result<OpenApiAepSecurityScheme, ParseError> {
    parse_and_validate(
        data,
        "OpenAPI AEP security scheme",
        validate_openapi_aep_security_scheme,
    )
}

pub fn validate_openapi_aep_security_scheme(
    value: &OpenApiAepSecurityScheme,
) -> Result<(), ValidationError> {
    let issues = if advertisement_pattern().is_match(value.authentication_method.as_str()) {
        Vec::new()
    } else {
        vec![issue(
            "$.x-aep-authentication-method",
            "Expected a lowercase authentication-method identifier.",
        )]
    };
    result("OpenAPI AEP security scheme", issues)
}

pub fn parse_client_assertion_claims(data: &[u8]) -> Result<ClientAssertionClaims, ParseError> {
    parse_client_assertion_claims_with_options(data, ClientAssertionValidationOptions::default())
}

pub fn parse_client_assertion_claims_with_options(
    data: &[u8],
    options: ClientAssertionValidationOptions,
) -> Result<ClientAssertionClaims, ParseError> {
    parse_and_validate(data, "client assertion claims", |value| {
        validate_client_assertion_claims_with_options(value, options)
    })
}

pub fn validate_client_assertion_claims(
    value: &ClientAssertionClaims,
) -> Result<(), ValidationError> {
    validate_client_assertion_claims_with_options(
        value,
        ClientAssertionValidationOptions::default(),
    )
}

pub fn validate_client_assertion_claims_with_options(
    value: &ClientAssertionClaims,
    options: ClientAssertionValidationOptions,
) -> Result<(), ValidationError> {
    let mut issues = Vec::new();
    require_non_empty(&value.iss, "$.iss", &mut issues);
    require_non_empty(&value.sub, "$.sub", &mut issues);
    if !value.iss.is_empty() && !value.sub.is_empty() && value.iss != value.sub {
        issues.push(issue("$.sub", "Expected sub to equal iss."));
    }
    require_non_empty(&value.aud, "$.aud", &mut issues);
    require_non_empty(&value.jti, "$.jti", &mut issues);
    if value.op == AssertionOperation::Authenticate {
        if value.resource.as_deref().is_none_or(|resource| {
            !is_protected_resource_uri(resource, options.allow_insecure_loopback)
        }) {
            issues.push(issue(
                "$.resource",
                "Expected an HTTPS protected-resource URI without a fragment.",
            ));
        }
    } else if value.resource.is_some() {
        issues.push(issue(
            "$.resource",
            "resource is only valid for authenticate.",
        ));
    }
    if value.exp <= value.iat {
        issues.push(issue("$.exp", "Expected exp after iat."));
    } else if value.exp.saturating_sub(value.iat) > MAX_ASSERTION_LIFETIME.as_secs() as i64 {
        issues.push(issue(
            "$.exp",
            "Expected an assertion lifetime no greater than 300 seconds.",
        ));
    }
    result("client assertion claims", issues)
}

pub fn new_problem_details(
    code: ErrorCode,
    title: impl Into<String>,
    status: i64,
) -> ProblemDetails {
    ProblemDetails {
        problem_type: format!("urn:aep:error:{}", code.as_str()),
        title: title.into(),
        status,
        detail: None,
        instance: None,
        code,
        owner_action_required: None,
        requirements_pending: None,
        verification_pending: None,
        additional: Default::default(),
    }
}

pub fn parse_problem_details(data: &[u8]) -> Result<ProblemDetails, ParseError> {
    parse_and_validate(data, "Problem Details", validate_problem_details)
}

pub fn validate_problem_details(value: &ProblemDetails) -> Result<(), ValidationError> {
    let mut issues = Vec::new();
    if value.problem_type != format!("urn:aep:error:{}", value.code.as_str()) {
        issues.push(issue("$.type", "Expected an AEP error URN matching code."));
    }
    require_non_empty(&value.title, "$.title", &mut issues);
    if value.status == 0 {
        issues.push(issue("$.status", "Expected an integer HTTP status."));
    }
    require_non_empty(value.code.as_str(), "$.code", &mut issues);
    if value.owner_action_required == Some(StringBoolean::False) {
        issues.push(issue("$.owner_action_required", "Expected true."));
    }
    validate_optional_non_empty_unique(
        value.verification_pending.as_deref(),
        "$.verification_pending",
        &mut issues,
    );
    validate_optional_non_empty_unique(
        value.requirements_pending.as_deref(),
        "$.requirements_pending",
        &mut issues,
    );
    if value.code == ErrorCode::NotRecognized
        && (value.owner_action_required.is_some()
            || value.verification_pending.is_some()
            || value.requirements_pending.is_some())
    {
        issues.push(issue(
            "$",
            "not_recognized must not expose pending or owner-action metadata.",
        ));
    }
    result("Problem Details", issues)
}

pub fn parse_built_in_grant_response(
    grant_type: &GrantType,
    data: &[u8],
) -> Result<BuiltInGrantResponse, ParseError> {
    match grant_type {
        GrantType::OAuthBearer => {
            parse_oauth_bearer_grant_response(data).map(BuiltInGrantResponse::OAuthBearer)
        }
        GrantType::ApiKey => parse_api_key_grant_response(data).map(BuiltInGrantResponse::ApiKey),
        GrantType::Basic => parse_basic_grant_response(data).map(BuiltInGrantResponse::Basic),
        GrantType::Other(_) => Err(ParseError::Validation(ValidationError {
            document_type: "Grant response".to_owned(),
            issues: vec![issue("$.grant_type", "Expected a built-in AEP grant type.")],
        })),
    }
}

pub fn validate_built_in_grant_response(
    grant_type: &GrantType,
    value: &BuiltInGrantResponse,
) -> Result<(), ValidationError> {
    match (grant_type, value) {
        (GrantType::OAuthBearer, BuiltInGrantResponse::OAuthBearer(value)) => {
            validate_oauth_bearer_grant_response(value)
        }
        (GrantType::ApiKey, BuiltInGrantResponse::ApiKey(value)) => {
            validate_api_key_grant_response(value)
        }
        (GrantType::Basic, BuiltInGrantResponse::Basic(value)) => {
            validate_basic_grant_response(value)
        }
        _ => result(
            "Grant response",
            vec![issue(
                "$.grant_type",
                "Expected the selected built-in AEP grant type.",
            )],
        ),
    }
}

pub fn parse_oauth_bearer_grant_response(
    data: &[u8],
) -> Result<OAuthBearerGrantResponse, ParseError> {
    parse_and_validate(
        data,
        "OAuth Bearer Grant response",
        validate_oauth_bearer_grant_response,
    )
}

pub fn validate_oauth_bearer_grant_response(
    value: &OAuthBearerGrantResponse,
) -> Result<(), ValidationError> {
    let mut issues = Vec::new();
    require_non_empty(&value.access_token, "$.access_token", &mut issues);
    require_credential_fields(
        &value.credential_id,
        &value.expires_at,
        &value.scopes,
        &mut issues,
    );
    if value.token_type != "Bearer" {
        issues.push(issue("$.token_type", "Expected Bearer."));
    }
    result("OAuth Bearer Grant response", issues)
}

pub fn parse_api_key_grant_response(data: &[u8]) -> Result<ApiKeyGrantResponse, ParseError> {
    parse_and_validate(
        data,
        "API-key Grant response",
        validate_api_key_grant_response,
    )
}

pub fn validate_api_key_grant_response(value: &ApiKeyGrantResponse) -> Result<(), ValidationError> {
    let mut issues = Vec::new();
    require_non_empty(&value.api_key, "$.api_key", &mut issues);
    require_non_empty(&value.header, "$.header", &mut issues);
    if !value.api_key.is_empty() && !valid_api_key_value(&value.api_key) {
        issues.push(issue(
            "$.api_key",
            "Expected an unambiguous HTTP field value.",
        ));
    }
    if !value.header.is_empty() && !is_http_field_name(&value.header) {
        issues.push(issue("$.header", "Expected an HTTP field name."));
    }
    require_credential_fields(
        &value.credential_id,
        &value.expires_at,
        &value.scopes,
        &mut issues,
    );
    result("API-key Grant response", issues)
}

pub fn parse_basic_grant_response(data: &[u8]) -> Result<BasicGrantResponse, ParseError> {
    parse_and_validate(data, "Basic Grant response", validate_basic_grant_response)
}

pub fn validate_basic_grant_response(value: &BasicGrantResponse) -> Result<(), ValidationError> {
    let mut issues = Vec::new();
    require_non_empty(&value.password, "$.password", &mut issues);
    require_non_empty(&value.username, "$.username", &mut issues);
    if !value.username.is_empty()
        && (value.username.contains(':') || contains_control_character(&value.username))
    {
        issues.push(issue(
            "$.username",
            "Expected an RFC 7617 username without a colon or control character.",
        ));
    }
    if !value.password.is_empty() && contains_control_character(&value.password) {
        issues.push(issue(
            "$.password",
            "Expected a value without control characters.",
        ));
    }
    if value.realm.as_deref() == Some("") {
        issues.push(issue("$.realm", "Expected a non-empty string."));
    }
    require_credential_fields(
        &value.credential_id,
        &value.expires_at,
        &value.scopes,
        &mut issues,
    );
    result("Basic Grant response", issues)
}

pub fn is_http_field_name(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn require_credential_fields(
    credential_id: &str,
    expires_at: &str,
    scopes: &[String],
    issues: &mut Vec<ValidationIssue>,
) {
    require_non_empty(credential_id, "$.credential_id", issues);
    require_non_empty(expires_at, "$.expires_at", issues);
    if !expires_at.is_empty() && !is_rfc3339(expires_at) {
        issues.push(issue("$.expires_at", "Expected an RFC 3339 date-time."));
    }
    validate_strings(scopes, "$.scopes", issues);
}

fn validate_optional_non_empty_unique(
    values: Option<&[String]>,
    path: &str,
    issues: &mut Vec<ValidationIssue>,
) {
    if let Some(values) = values {
        validate_non_empty_strings(values, path, true, issues);
    }
}

fn validate_strings(values: &[String], path: &str, issues: &mut Vec<ValidationIssue>) {
    for (index, value) in values.iter().enumerate() {
        if value.is_empty() {
            issues.push(issue(format!("{path}[{index}]"), "Expected a string."));
        }
    }
}

fn validate_body_hash(value: Option<&str>, path: &str, issues: &mut Vec<ValidationIssue>) {
    if value.is_some_and(|value| !body_hash_pattern().is_match(value)) {
        issues.push(issue(path, "Expected a lowercase SHA-256 body hash."));
    }
}

fn is_rfc3339(value: &str) -> bool {
    OffsetDateTime::parse(value, &Rfc3339).is_ok()
}

fn is_protected_resource_uri(value: &str, allow_insecure_loopback: bool) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    if url.host_str().is_none() || url.fragment().is_some() {
        return false;
    }
    url.scheme() == "https"
        || (allow_insecure_loopback
            && url.scheme() == "http"
            && url.host_str().is_some_and(is_loopback_host))
}

fn valid_api_key_value(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            (0x21..=0x7e).contains(&byte) && !matches!(byte, b'"' | b',' | b';' | b'\\')
        })
}

fn contains_control_character(value: &str) -> bool {
    value.chars().any(char::is_control)
}

fn body_hash_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"^sha256:[0-9a-f]{64}$").expect("valid body hash pattern"))
}

fn advertisement_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"^[a-z0-9]+(?:-[a-z0-9]+)*$").expect("valid advertisement pattern")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::to_string;

    #[test]
    fn validates_core_messages() {
        parse_enroll_request(br#"{"agent_did":"did:web:agent.example","idempotency_key":"key-1"}"#)
            .expect("enroll request");
        parse_revoke_request(br#"{"all_grant_types":"true"}"#).expect("revoke request");
        parse_revoke_response(br#"{}"#).expect("revoke response");
        assert!(
            parse_enroll_request(br#"{"agent_did":"did:web:agent.example","claims":null}"#)
                .is_err()
        );
        assert!(
            parse_status_response(br#"{"status":"pending","verification_pending":[]}"#).is_err()
        );
        assert!(parse_revoke_response(br#"{"unexpected":true}"#).is_err());
    }

    #[test]
    fn validates_built_in_credentials() {
        let response = parse_built_in_grant_response(
            &GrantType::OAuthBearer,
            br#"{"access_token":"token","credential_id":"id","expires_at":"2027-01-01T00:00:00Z","scopes":null,"token_type":"Bearer"}"#,
        )
        .expect("OAuth response");
        assert_eq!(response.grant_type(), GrantType::OAuthBearer);
        assert!(parse_api_key_grant_response(
            br#"{"api_key":"unsafe value","credential_id":"id","expires_at":"2027-01-01T00:00:00Z","header":"X-API-Key"}"#,
        )
        .is_err());
    }

    #[test]
    fn protects_recognition_failure_metadata() {
        let mut problem = new_problem_details(ErrorCode::NotRecognized, "Not recognized", 401);
        problem.requirements_pending = Some(vec!["contact.email".to_owned()]);
        assert!(validate_problem_details(&problem).is_err());

        problem.requirements_pending = None;
        problem.owner_action_required = Some(StringBoolean::True);
        assert!(validate_problem_details(&problem).is_err());
    }

    #[test]
    fn requires_problem_type_to_match_code() {
        let mut problem = new_problem_details(ErrorCode::NotRecognized, "Not recognized", 401);
        validate_problem_details(&problem).expect("matching Problem Details");
        assert!(
            parse_problem_details(
                br#"{"type":"urn:aep:error:not_recognized","status":401,"code":"not_recognized"}"#,
            )
            .is_err()
        );
        assert!(
            parse_problem_details(
                br#"{"type":"urn:aep:error:not_recognized","title":null,"status":401,"code":"not_recognized"}"#,
            )
            .is_err()
        );
        problem.problem_type = "urn:aep:error:invalid_request".to_owned();
        assert!(validate_problem_details(&problem).is_err());
    }

    #[test]
    fn validates_enroll_and_status_responses() {
        let enroll = parse_enroll_response(
            br#"{"status":"pending","owner_action_required":"false","verification_pending":["email"]}"#,
        )
        .expect("Enroll response");
        assert_eq!(
            to_string(&enroll).expect("serialized response"),
            r#"{"status":"pending","verification_pending":["email"]}"#
        );
        parse_status_response(br#"{"status":"active","since":"2026-08-29T12:00:00Z"}"#)
            .expect("Status response");
        assert!(
            parse_status_response(
                br#"{"status":"pending","requirements_pending":["email","email"]}"#,
            )
            .is_err()
        );
        assert!(parse_status_response(br#"{"status":"active","since":"not-a-date"}"#).is_err());
    }

    #[test]
    fn validates_revoke_selectors() {
        parse_revoke_request(br#"{"grant_type":"oauth-bearer","credential_id":"credential-1"}"#)
            .expect("targeted Revoke");
        for invalid in [
            r#"{}"#,
            r#"{"credential_id":"credential-1"}"#,
            r#"{"all_grant_types":"true","grant_type":"oauth-bearer"}"#,
            r#"{"all_grant_types":"false"}"#,
        ] {
            assert!(
                parse_revoke_request(invalid.as_bytes()).is_err(),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn validates_metadata_and_openapi_security() {
        let hash = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        parse_idempotency_metadata(
            format!(r#"{{"idempotency_key":"key-1","first_body_hash":"{hash}"}}"#).as_bytes(),
        )
        .expect("idempotency metadata");
        assert!(
            parse_idempotency_metadata(
                br#"{"idempotency_key":"key-1","first_body_hash":"invalid"}"#,
            )
            .is_err()
        );
        parse_openapi_aep_security_scheme(br#"{"x-aep-authentication-method":"oauth-bearer"}"#)
            .expect("OpenAPI security scheme");
        assert!(
            parse_openapi_aep_security_scheme(
                br#"{"x-aep-authentication-method":"OAuth Bearer"}"#,
            )
            .is_err()
        );
    }

    #[test]
    fn validates_assertion_claim_relationships() {
        let mut claims = ClientAssertionClaims {
            aud: "did:web:service.example".to_owned(),
            exp: 61,
            iat: 1,
            iss: "did:web:agent.example".to_owned(),
            jti: "jti".to_owned(),
            op: AssertionOperation::Status,
            resource: None,
            sub: "did:web:agent.example".to_owned(),
            additional: Default::default(),
        };
        validate_client_assertion_claims(&claims).expect("valid assertion claims");
        claims.op = AssertionOperation::Authenticate;
        assert!(validate_client_assertion_claims(&claims).is_err());
        claims.resource = Some("https://service.example/private".to_owned());
        validate_client_assertion_claims(&claims).expect("protected-resource assertion");
        claims.exp = 302;
        assert!(validate_client_assertion_claims(&claims).is_err());
    }

    #[test]
    fn validates_each_built_in_credential_shape() {
        parse_api_key_grant_response(
            br#"{"api_key":"secret","credential_id":"id","expires_at":"2027-01-01T00:00:00Z","header":"X-API-Key"}"#,
        )
        .expect("API-key response");
        parse_basic_grant_response(
            br#"{"credential_id":"id","expires_at":"2027-01-01T00:00:00Z","password":"secret","username":"agent"}"#,
        )
        .expect("Basic response");
        assert!(
            parse_basic_grant_response(
                br#"{"credential_id":"id","expires_at":"2027-01-01T00:00:00Z","password":"secret","username":"agent:name"}"#,
            )
            .is_err()
        );
        let wrong = BuiltInGrantResponse::Basic(BasicGrantResponse {
            credential_id: "id".to_owned(),
            expires_at: "2027-01-01T00:00:00Z".to_owned(),
            password: "secret".to_owned(),
            realm: None,
            scopes: Vec::new(),
            username: "agent".to_owned(),
            additional: Default::default(),
        });
        assert!(validate_built_in_grant_response(&GrantType::ApiKey, &wrong).is_err());
    }
}
