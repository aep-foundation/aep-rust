//! The refusal and dispatch paths that the shape-driven suites do not reach: every branch here is
//! one the protocol relies on to reject a malformed document or to route a well-formed one.

use aep_core::*;

fn rejected<T>(result: Result<T, ParseError>) -> bool {
    result.is_err()
}

#[test]
fn enroll_request_carries_claim_issues() {
    // A request body embeds the claim document, so a claim the catalogue refuses has to surface as
    // a request issue rather than being validated only on its own.
    let error = parse_enroll_request(
        br#"{"agent_did":"did:web:agent.example","claims":{"contact.email":"owner at example.com"}}"#,
    )
    .expect_err("claim issue");
    let ParseError::Validation(error) = error else {
        panic!("expected a validation error");
    };
    assert_eq!(error.document_type, "Enroll request");
    assert!(
        error
            .issues
            .iter()
            .any(|issue| issue.path == "$.claims.contact.email"),
        "{:?}",
        error.issues
    );
}

#[test]
fn revoke_and_idempotency_selectors_reject_empty_members() {
    assert!(rejected(parse_revoke_request(
        br#"{"grant_type":"oauth-bearer","credential_id":""}"#
    )));
    assert!(rejected(parse_idempotency_metadata(
        br#"{"idempotency_key":"9f8a","agent_did":""}"#
    )));
    assert!(
        parse_idempotency_metadata(
            br#"{"idempotency_key":"9f8a","agent_did":"did:web:agent.example"}"#
        )
        .is_ok()
    );
}

#[test]
fn problem_details_reject_an_absent_status_and_a_false_owner_flag() {
    let problem = |body: &str| {
        parse_problem_details(
            format!(
                r#"{{"type":"urn:aep:error:invalid_request","title":"Invalid request",{body}
                "code":"invalid_request"}}"#
            )
            .as_bytes(),
        )
    };
    assert!(problem(r#""status":400,"#).is_ok());
    assert!(rejected(problem(r#""status":0,"#)));
    assert!(rejected(problem(
        r#""status":400,"owner_action_required":"false","#
    )));
}

#[test]
fn grant_responses_dispatch_on_the_granted_type() {
    let oauth = br#"{"access_token":"t","credential_id":"c","expires_at":"2026-05-28T12:00:00Z",
        "token_type":"Bearer"}"#;
    let api_key = br#"{"api_key":"k","credential_id":"c","expires_at":"2026-05-28T12:00:00Z",
        "header":"X-API-Key"}"#;
    let basic = br#"{"credential_id":"c","expires_at":"2026-05-28T12:00:00Z","password":"p",
        "username":"u"}"#;
    for (grant_type, body) in [
        (GrantType::OAuthBearer, &oauth[..]),
        (GrantType::ApiKey, &api_key[..]),
        (GrantType::Basic, &basic[..]),
    ] {
        let response =
            parse_built_in_grant_response(&grant_type, body).expect("built-in grant response");
        assert_eq!(response.grant_type(), grant_type);
        assert!(validate_built_in_grant_response(&grant_type, &response).is_ok());
    }
    // A grant type outside the three built-in registrations has no response schema to parse
    // against, and a response may not be validated against a type it was not granted under.
    assert!(rejected(parse_built_in_grant_response(
        &GrantType::from("vendor-token"),
        &oauth[..]
    )));
    let response = parse_built_in_grant_response(&GrantType::ApiKey, &api_key[..]).expect("parsed");
    assert!(validate_built_in_grant_response(&GrantType::Basic, &response).is_err());
}

#[test]
fn credential_responses_reject_unusable_credential_material() {
    assert!(rejected(parse_oauth_bearer_grant_response(
        br#"{"access_token":"t","credential_id":"c","expires_at":"2026-05-28T12:00:00Z",
            "token_type":"MAC"}"#
    )));
    assert!(rejected(parse_oauth_bearer_grant_response(
        br#"{"access_token":"t","credential_id":"c","expires_at":"next tuesday",
            "token_type":"Bearer"}"#
    )));
    assert!(rejected(parse_basic_grant_response(
        br#"{"credential_id":"c","expires_at":"2026-05-28T12:00:00Z","password":"p\u0007q",
            "username":"u"}"#
    )));
    assert!(rejected(parse_basic_grant_response(
        br#"{"credential_id":"c","expires_at":"2026-05-28T12:00:00Z","password":"p",
            "realm":"","username":"u"}"#
    )));
}

#[test]
fn authenticate_assertions_require_a_protected_resource_url() {
    let claims = |resource: &str| {
        format!(
            r#"{{"aud":"https://api.example.com","exp":1300,"iat":1000,
            "iss":"did:web:agent.example","jti":"n","op":"authenticate","resource":"{resource}",
            "sub":"did:web:agent.example"}}"#
        )
    };
    assert!(rejected(parse_client_assertion_claims(
        claims("not a url").as_bytes()
    )));
    assert!(rejected(parse_client_assertion_claims(
        claims("http://127.0.0.1:8080/orders").as_bytes()
    )));
    // Loopback over plain HTTP is a development affordance, so it is admitted only when the caller
    // asks for it.
    assert!(
        parse_client_assertion_claims_with_options(
            claims("http://127.0.0.1:8080/orders").as_bytes(),
            ClientAssertionValidationOptions {
                allow_insecure_loopback: true,
            },
        )
        .is_ok()
    );
}

#[test]
fn a_document_ends_where_its_json_value_ends() {
    // Trailing content would let a peer append a second document to a body that already parsed.
    assert!(rejected(parse_enroll_request(
        br#"{"agent_did":"did:web:agent.example"} {"agent_did":"did:web:other.example"}"#
    )));
}

#[test]
fn a_root_level_type_error_is_reported_against_the_document_root() {
    let ParseError::Validation(error) = parse_enroll_request(b"5").expect_err("type error") else {
        panic!("expected a validation error");
    };
    assert_eq!(
        error
            .issues
            .iter()
            .map(|issue| issue.path.as_str())
            .collect::<Vec<_>>(),
        vec!["$"]
    );

    // A member inside an array is named the way every validator in the crate names one.
    let ParseError::Validation(error) =
        parse_grant_request(br#"{"grant_type":"oauth-bearer","requested_scopes":[1]}"#)
            .expect_err("type error")
    else {
        panic!("expected a validation error");
    };
    assert_eq!(
        error
            .issues
            .iter()
            .map(|issue| issue.path.as_str())
            .collect::<Vec<_>>(),
        vec!["$.requested_scopes[0]"]
    );
}

#[test]
fn command_paths_cover_every_command_with_an_endpoint() {
    for (command, expected) in [
        (Command::Enroll, "/aep/enroll"),
        (Command::Grant, "/aep/grant"),
        (Command::Revoke, "/aep/revoke"),
        (Command::Status, "/aep/status"),
    ] {
        assert_eq!(
            command_path(&command, Some("/aep")).expect("command path"),
            expected
        );
    }
    // Inspect is reached at its own well-known location, and an unregistered command has no
    // advertised path at all.
    assert!(command_path(&Command::Inspect, Some("/aep")).is_err());
    assert!(command_path(&Command::Other("audit".to_owned()), Some("/aep")).is_err());

    let document = parse_inspect_document(
        br#"{"aep_version":"1.0","bindings":{"supported":["http"]},
        "commands":{"supported":["inspect"]},"core":{"signing_algorithms":["EdDSA","ES256"]},
        "http":{"endpoint_base":"/agent"},"identity":{"methods":[]},
        "service":{"did":"did:web:api.example.com"}}"#,
    )
    .expect("inspect document");
    assert_eq!(
        command_path_from_inspect(&document, &Command::Enroll).expect("command path"),
        "/agent/enroll"
    );
}

#[test]
fn the_dedicated_carrier_names_the_aep_authorization_field() {
    assert_eq!(
        protected_resource_authorization_header(AuthorizationCarrier::Standard),
        "Authorization"
    );
    assert_eq!(
        protected_resource_authorization_header(AuthorizationCarrier::Dedicated),
        "AEP-Authorization"
    );
}

#[test]
fn a_field_value_without_a_separator_is_not_a_credential_presentation() {
    for carrier in [
        AuthorizationCarrier::Standard,
        AuthorizationCarrier::Dedicated,
    ] {
        assert!(parse_protected_resource_authorization("AEP", carrier).is_err());
        assert!(parse_protected_resource_authorization("", carrier).is_err());
    }
}

#[test]
fn inspect_documents_reject_an_unusable_version_or_identity_method() {
    let document = |body: &str| {
        format!(
            r#"{{"bindings":{{"supported":["http"]}},"commands":{{"supported":["inspect"]}},
            "core":{{"signing_algorithms":["EdDSA","ES256"]}},"http":{{}},
            "service":{{"did":"did:web:api.example.com"}},{body}}}"#
        )
    };
    let accepted = |json: String| {
        parse_inspect_document(json.as_bytes())
            .is_ok_and(|document| validate_inspect_document(&document).is_ok())
    };
    assert!(accepted(document(
        r#""aep_version":"1.0","identity":{"methods":["did:web"]}"#
    )));
    assert!(!accepted(document(
        r#""aep_version":"1","identity":{"methods":[]}"#
    )));
    assert!(!accepted(document(
        r#""aep_version":"1.0","identity":{"methods":["Did Web"]}"#
    )));
}

#[test]
fn required_claim_names_are_matched_against_every_catalogued_value() {
    let values = parse_claim_values(
        br#"{"contact.address.primary":{"country":"US","first_name":"Ada",
            "last_name":"Lovelace","line1":"1 Main St","city":"Springfield"},
            "contact.email":"owner@example.com","contact.mobile":"+15551234567",
            "person.birthdate":"1990-01-01","person.first_name":"Ada",
            "person.last_name":"Lovelace","person.username":"ada","vendor.tier":"gold"}"#,
    )
    .expect("claim values");
    let required = [
        ClaimName::ContactAddressPrimary,
        ClaimName::ContactEmail,
        ClaimName::ContactMobile,
        ClaimName::PersonBirthdate,
        ClaimName::PersonFirstName,
        ClaimName::PersonLastName,
        ClaimName::PersonUsername,
        ClaimName::from("vendor.tier"),
    ];
    assert!(missing_required_claim_names(&required, Some(&values)).is_empty());
    assert_eq!(
        missing_required_claim_names(&required, Some(&ClaimValues::default())),
        required
    );
    assert_eq!(missing_required_claim_names(&required, None), required);
}

#[test]
fn an_unterminated_quoted_local_part_is_not_a_mailbox() {
    for address in [r#""unterminated@example.com"#, r#""@example.com"#] {
        assert!(
            rejected(parse_claim_values(
                serde_json::json!({ "contact.email": address })
                    .to_string()
                    .as_bytes()
            )),
            "{address}"
        );
    }
}

#[test]
fn openapi_operation_targets_must_name_a_method_and_a_path() {
    let templates = vec!["/aep/enroll".to_owned(), "/aep/{command}".to_owned()];
    let matched = |method: &str, path: &str| {
        match_openapi_path(
            &templates,
            &OpenApiPathMatchOptions {
                method: method.to_owned(),
                path: path.to_owned(),
                trailing_slash: OpenApiTrailingSlash::Strict,
            },
        )
    };
    // A literal segment outranks a template variable, whichever order the document lists them in.
    assert_eq!(
        matched("post", "/aep/enroll").expect("match").template,
        "/aep/enroll"
    );
    assert_eq!(
        matched("post", "/aep/enroll").expect("match").method,
        "POST"
    );
    assert_eq!(
        matched("post", "/aep/grant").expect("match").template,
        "/aep/{command}"
    );
    // A query string belongs to the request target rather than the path, and a path of a different
    // depth matches no template at all.
    assert!(matched("", "/aep/enroll").is_err());
    assert!(matched("post", "").is_err());
    assert!(matched("post", "/aep/enroll?dry_run=1").is_err());
    assert!(matched("post", "/aep/enroll/extra").is_err());
}

#[test]
fn openapi_urls_resolve_only_against_a_usable_inspect_url() {
    let inspect = |value: &str| url::Url::parse(value).expect("url");
    assert_eq!(
        resolve_openapi_url(
            &inspect("https://api.example.com/.well-known/aep"),
            "openapi.json",
            false
        )
        .expect("resolved")
        .as_str(),
        "https://api.example.com/.well-known/openapi.json"
    );
    for base in [
        "http://api.example.com/.well-known/aep",
        "https://user@api.example.com/.well-known/aep",
        "https://api.example.com/.well-known/aep#section",
    ] {
        assert!(
            resolve_openapi_url(&inspect(base), "openapi.json", false).is_err(),
            "{base}"
        );
    }
    // A fragment on the resolved document would name a position inside it rather than the document.
    assert!(
        resolve_openapi_url(
            &inspect("https://api.example.com/.well-known/aep"),
            "openapi.json#/paths",
            false
        )
        .is_err()
    );
    assert!(
        resolve_openapi_url(
            &inspect("https://api.example.com/.well-known/aep"),
            "https://[",
            false,
        )
        .is_err()
    );
}

#[test]
fn openapi_resolution_supports_the_explicit_loopback_development_option() {
    for host in ["localhost", "127.0.0.1", "[::1]"] {
        let inspect =
            url::Url::parse(&format!("http://{host}:8080/.well-known/aep")).expect("Inspect URL");
        assert_eq!(
            resolve_openapi_url(&inspect, "/openapi.json", true)
                .expect("development OpenAPI URL")
                .as_str(),
            format!("http://{host}:8080/openapi.json")
        );
        assert!(resolve_openapi_url(&inspect, "/openapi.json", false).is_err());
    }
    let remote = url::Url::parse("http://service.example/.well-known/aep").expect("URL");
    assert!(resolve_openapi_url(&remote, "/openapi.json", true).is_err());
}

#[test]
fn extensible_identifiers_round_trip_through_their_wire_form() {
    let request =
        parse_grant_request(br#"{"grant_type":"vendor-token","requested_scopes":["read"]}"#)
            .expect("grant request");
    assert_eq!(
        serde_json::to_value(&request).expect("serialized"),
        serde_json::json!({"grant_type":"vendor-token","requested_scopes":["read"]})
    );
    assert_eq!(
        GrantType::from("oauth-bearer".to_owned()),
        GrantType::OAuthBearer
    );
}
