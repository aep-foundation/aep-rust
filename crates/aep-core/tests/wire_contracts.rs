//! Wire model parsing and validation, driven from the shapes the specification publishes.

use aep_core::*;

fn parses<T, E>(result: Result<T, E>) -> bool {
    result.is_ok()
}

#[test]
fn enroll_request_shapes() {
    assert!(parses(parse_enroll_request(
        br#"{"agent_did":"did:web:agent.example.com:agents:123"}"#
    )));
    assert!(parses(parse_enroll_request(
        br#"{"agent_did":"did:web:agent.example.com:agents:123",
            "idempotency_key":"9f8a4d2e-1c3b-4f5e-8b7a-000000000000",
            "claims":{"contact.email":"owner@example.com"}}"#
    )));
    for body in [
        &br#"{}"#[..],
        br#"{"agent_did":""}"#,
        br#"{"agent_did":"did:web:agent.example.com","idempotency_key":""}"#,
        br#"[]"#,
    ] {
        assert!(
            !parses(parse_enroll_request(body)),
            "{:?}",
            String::from_utf8_lossy(body)
        );
    }
}

#[test]
fn lifecycle_response_shapes() {
    assert!(parses(parse_enroll_response(br#"{"status":"active"}"#)));
    assert!(parses(parse_enroll_response(
        br#"{"owner_action_required":"true","status":"pending",
            "verification_pending":["contact.email"]}"#
    )));
    assert!(parses(parse_status_response(
        br#"{"since":"2026-05-28T12:00:00Z","status":"active"}"#
    )));
    assert!(parses(parse_status_response(
        br#"{"requirements_pending":["company.registration"],
            "since":"2026-07-10T12:00:00Z","status":"pending"}"#
    )));
    for body in [
        &br#"{}"#[..],
        br#"{"status":"unknown-state"}"#,
        br#"{"status":"pending","verification_pending":[]}"#,
        br#"{"status":"pending","verification_pending":[""]}"#,
        br#"{"status":"pending","verification_pending":["a","a"]}"#,
        br#"{"status":"active","since":"not-a-timestamp"}"#,
    ] {
        assert!(
            !parses(parse_status_response(body)),
            "{:?}",
            String::from_utf8_lossy(body)
        );
    }
}

#[test]
fn grant_request_shapes() {
    assert!(parses(parse_grant_request(
        br#"{"grant_type":"oauth-bearer"}"#
    )));
    assert!(parses(parse_grant_request(
        br#"{"grant_type":"oauth-bearer","requested_scopes":["orders:read"]}"#
    )));
    assert!(!parses(parse_grant_request(br#"{"grant_type":""}"#)));
    assert!(!parses(parse_grant_request(br#"{}"#)));
    assert!(!parses(parse_grant_request(
        br#"{"grant_type":"oauth-bearer","requested_scopes":[""]}"#
    )));
}

/// A Revoke request selects a grant type, a grant type with a credential, or all grant types;
/// conflicting or incomplete selectors are refused.
#[test]
fn revoke_request_selectors() {
    for body in [
        &br#"{"all_grant_types":"true"}"#[..],
        br#"{"grant_type":"oauth-bearer"}"#,
        br#"{"credential_id":"tok_01HZY8W7Q2F8J7D3P9G9Z1N6TT","grant_type":"oauth-bearer"}"#,
    ] {
        assert!(
            parses(parse_revoke_request(body)),
            "{:?}",
            String::from_utf8_lossy(body)
        );
    }
    for body in [
        &br#"{"all_grant_types":"true","grant_type":"oauth-bearer"}"#[..],
        br#"{"credential_id":"tok_01HZY8W7Q2F8J7D3P9G9Z1N6TT"}"#,
        br#"{}"#,
        br#"{"all_grant_types":"false"}"#,
        br#"{"grant_type":""}"#,
    ] {
        assert!(
            !parses(parse_revoke_request(body)),
            "{:?}",
            String::from_utf8_lossy(body)
        );
    }
    assert!(parses(parse_revoke_response(br#"{}"#)));
}

/// CORE-ERR: `type` is the AEP error URN matching `code`, and `not_recognized` discloses no
/// pending metadata.
#[test]
fn problem_details_shapes() {
    assert!(parses(parse_problem_details(
        br#"{"type":"urn:aep:error:not_recognized","title":"Not recognized",
            "status":401,"code":"not_recognized"}"#
    )));
    assert!(parses(parse_problem_details(
        br#"{"type":"urn:aep:error:requirements_unmet","title":"Requirements unmet",
            "status":422,"code":"requirements_unmet",
            "requirements_pending":["company.registration"]}"#
    )));
    for body in [
        // title omitted, null, and empty
        &br#"{"type":"urn:aep:error:not_recognized","status":401,"code":"not_recognized"}"#[..],
        br#"{"type":"urn:aep:error:not_recognized","title":null,"status":401,"code":"not_recognized"}"#,
        br#"{"type":"urn:aep:error:not_recognized","title":"","status":401,"code":"not_recognized"}"#,
        // the URN and the code disagree
        br#"{"type":"urn:aep:error:invalid_request","title":"Not recognized","status":401,"code":"not_recognized"}"#,
        // not_recognized must not disclose pending metadata
        br#"{"type":"urn:aep:error:not_recognized","title":"Not recognized","status":401,
            "code":"not_recognized","owner_action_required":"true"}"#,
        br#"{"type":"urn:aep:error:not_recognized","title":"Not recognized","status":401,
            "code":"not_recognized","verification_pending":["contact.email"]}"#,
        br#"{"type":"urn:aep:error:not_recognized","title":"Not recognized","status":401,
            "code":"not_recognized","requirements_pending":["company.registration"]}"#,
        // the code uses the registered error-code syntax
        br#"{"type":"urn:aep:error:Not_Recognized","title":"x","status":401,"code":"Not_Recognized"}"#,
    ] {
        assert!(
            !parses(parse_problem_details(body)),
            "{:?}",
            String::from_utf8_lossy(body)
        );
    }
}

#[test]
fn idempotency_metadata_shapes() {
    assert!(parses(parse_idempotency_metadata(
        br#"{"idempotency_key":"9f8a4d2e-1c3b-4f5e-8b7a-000000000000"}"#
    )));
    assert!(parses(parse_idempotency_metadata(
        br#"{"idempotency_key":"key","agent_did":"did:web:agent.example",
            "first_body_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}"#
    )));
    for body in [
        &br#"{}"#[..],
        br#"{"idempotency_key":""}"#,
        br#"{"idempotency_key":"key","first_body_hash":"sha256:not-a-digest"}"#,
        br#"{"idempotency_key":"key","first_body_hash":"0000"}"#,
    ] {
        assert!(
            !parses(parse_idempotency_metadata(body)),
            "{:?}",
            String::from_utf8_lossy(body)
        );
    }
}

/// CORE-OAS-012 binds the extension to one registered authentication method identifier.
#[test]
fn openapi_security_scheme_shapes() {
    assert!(parses(parse_openapi_aep_security_scheme(
        br#"{"type":"http","scheme":"AEP","x-aep-authentication-method":"aep-jwt"}"#
    )));
    for body in [
        &br#"{"type":"http","scheme":"AEP"}"#[..],
        br#"{"x-aep-authentication-method":""}"#,
        br#"{"x-aep-authentication-method":"AEP-JWT"}"#,
    ] {
        assert!(
            !parses(parse_openapi_aep_security_scheme(body)),
            "{:?}",
            String::from_utf8_lossy(body)
        );
    }
}

/// The published assertion claims validate, and each rejection the vector names is refused.
#[test]
fn client_assertion_claim_shapes() {
    let published = br#"{"aud":"did:web:api.example.com","exp":1748428860,"iat":1748428800,
        "iss":"did:web:agent.example.com:agents:123","jti":"01J0AEPVECTORASSERTION00000001",
        "op":"enroll","sub":"did:web:agent.example.com:agents:123"}"#;
    assert!(parses(parse_client_assertion_claims(published)));

    let claims = |body: &str| format!("{{{body}}}");
    let base = r#""aud":"did:web:api.example.com","iss":"did:web:agent.example","#.to_owned()
        + r#""sub":"did:web:agent.example","jti":"assertion-1""#;
    for (name, body) in [
        (
            "excessive_lifetime",
            format!("{base},\"iat\":1000,\"exp\":1301,\"op\":\"enroll\""),
        ),
        (
            "nonpositive_lifetime",
            format!("{base},\"iat\":1000,\"exp\":1000,\"op\":\"enroll\""),
        ),
        (
            "mismatched_subject",
            r#""aud":"did:web:api.example.com","iss":"did:web:agent.example","sub":"did:web:other.example","jti":"a","iat":1000,"exp":1060,"op":"enroll""#
                .to_owned(),
        ),
        (
            "unexpected_resource",
            format!(
                "{base},\"iat\":1000,\"exp\":1060,\"op\":\"enroll\",\"resource\":\"https://api.example.com/orders\""
            ),
        ),
        (
            "missing_resource",
            format!("{base},\"iat\":1000,\"exp\":1060,\"op\":\"authenticate\""),
        ),
        (
            "insecure_resource",
            format!(
                "{base},\"iat\":1000,\"exp\":1060,\"op\":\"authenticate\",\"resource\":\"http://api.example.com/orders\""
            ),
        ),
        (
            "fragmented_resource",
            format!(
                "{base},\"iat\":1000,\"exp\":1060,\"op\":\"authenticate\",\"resource\":\"https://api.example.com/orders#part\""
            ),
        ),
    ] {
        assert!(
            !parses(parse_client_assertion_claims(claims(&body).as_bytes())),
            "{name}"
        );
    }
    assert!(parses(parse_client_assertion_claims(
        claims(&format!(
            "{base},\"iat\":1000,\"exp\":1060,\"op\":\"authenticate\",\"resource\":\"https://api.example.com/orders\""
        ))
        .as_bytes()
    )));
}

#[test]
fn built_in_grant_response_shapes() {
    assert!(parses(parse_built_in_grant_response(
        &GrantType::OAuthBearer,
        br#"{"access_token":"opaque","credential_id":"c1","expires_at":"2027-01-01T00:00:00Z",
            "token_type":"Bearer","scopes":[]}"#
    )));
    assert!(parses(parse_built_in_grant_response(
        &GrantType::ApiKey,
        br#"{"api_key":"opaque","credential_id":"c1","expires_at":"2027-01-01T00:00:00Z",
            "header":"X-API-Key","scopes":[]}"#
    )));
    assert!(parses(parse_built_in_grant_response(
        &GrantType::Basic,
        br#"{"username":"agent","password":"secret","credential_id":"c1",
            "expires_at":"2027-01-01T00:00:00Z","scopes":[]}"#
    )));
    // A credential without a stable identifier cannot be revoked individually.
    assert!(!parses(parse_built_in_grant_response(
        &GrantType::OAuthBearer,
        br#"{"access_token":"opaque","expires_at":"2027-01-01T00:00:00Z","token_type":"Bearer"}"#
    )));
    assert!(!parses(parse_built_in_grant_response(
        &GrantType::ApiKey,
        br#"{"api_key":"opaque","credential_id":"c1","expires_at":"2027-01-01T00:00:00Z",
            "header":"not a field name"}"#
    )));
}
