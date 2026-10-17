//! Inspect document validation, driven from the shapes the specification publishes.

use aep_core::*;

fn accepted(json: &str) -> bool {
    parse_inspect_document(json.as_bytes())
        .is_ok_and(|document| validate_inspect_document(&document).is_ok())
}

/// The baseline document every case below varies one member of.
fn document(body: &str) -> String {
    format!(
        r#"{{"aep_version":"1.0","bindings":{{"supported":["http"]}},
        "core":{{"signing_algorithms":["EdDSA","ES256"]}},"http":{{}},
        "identity":{{"methods":[]}},"service":{{"did":"did:web:api.example.com"}},{body}}}"#
    )
}

#[test]
fn accepts_the_published_minimal_document() {
    assert!(accepted(&document(
        r#""commands":{"supported":["inspect"]}"#
    )));
}

/// Inspect is unauthenticated and always advertised; `authenticate` is an assertion operation
/// rather than a command.
#[test]
fn command_advertisements() {
    assert!(!accepted(&document(
        r#""commands":{"supported":["enroll"]}"#
    )));
    assert!(!accepted(&document(
        r#""commands":{"supported":["inspect","authenticate"]}"#
    )));
}

/// Grant and Revoke need at least one grant type, and configuration may only name an advertised
/// one under the registered identifier syntax.
#[test]
fn grant_type_advertisements() {
    assert!(!accepted(&document(
        r#""commands":{"supported":["grant","inspect"]}"#
    )));
    assert!(!accepted(&document(
        r#""commands":{"supported":["revoke","inspect"]}"#
    )));
    // Grant is an authenticated command, so these cases also advertise an identity method.
    let enrolled = |body: &str| {
        document(body).replace(
            r#""identity":{"methods":[]}"#,
            r#""identity":{"methods":["did:web"]}"#,
        )
    };
    assert!(accepted(&enrolled(
        r#""commands":{"supported":["grant","inspect"],"grant_types":["oauth-bearer"]}"#
    )));
    assert!(!accepted(&enrolled(
        r#""commands":{"supported":["grant","inspect"],"grant_types":["oauth_bearer"]}"#
    )));
    assert!(!accepted(&enrolled(
        r#""commands":{"supported":["grant","inspect"],"grant_types":["oauth-bearer"],
           "grant_types_config":{"api-key":{}}}"#
    )));
    assert!(!accepted(&enrolled(
        r#""commands":{"supported":["grant","inspect"],"grant_types":["oauth-bearer"],
           "grant_types_config":{"Oauth-Bearer":{}}}"#
    )));
    assert!(accepted(&enrolled(
        r#""commands":{"supported":["grant","inspect"],"grant_types":["oauth-bearer"],
           "grant_types_config":{"oauth-bearer":{"supports_per_credential_revoke":"true"}}}"#
    )));
}

/// An authenticated command needs an identity method to authenticate with.
#[test]
fn authenticated_commands_require_an_identity_method() {
    for command in ["enroll", "grant", "revoke", "status"] {
        let body = format!(r#""commands":{{"supported":["inspect","{command}"]}}"#);
        assert!(!accepted(&document(&body)), "{command}");
    }
    assert!(accepted(
        &document(r#""commands":{"supported":["inspect","status"]}"#).replace(
            r#""identity":{"methods":[]}"#,
            r#""identity":{"methods":["did:web"]}"#
        )
    ));
}

/// Both core signing algorithms are required.
#[test]
fn signing_algorithm_advertisements() {
    let with = |algorithms: &str| {
        document(r#""commands":{"supported":["inspect"]}"#).replace(
            r#""signing_algorithms":["EdDSA","ES256"]"#,
            &format!(r#""signing_algorithms":{algorithms}"#),
        )
    };
    assert!(!accepted(&with(r#"["ES256"]"#)));
    assert!(!accepted(&with(r#"["EdDSA"]"#)));
    assert!(!accepted(&with("[]")));
    assert!(accepted(&with(r#"["EdDSA","ES256"]"#)));
}

/// The authentication method list is bounded and uses the registered identifier syntax.
#[test]
fn authentication_method_advertisements() {
    let methods: Vec<String> = (1..=17)
        .map(|index| format!("\"method-{index:02}\""))
        .collect();
    let body = format!(
        r#""commands":{{"supported":["inspect"]}},"authentication":{{"methods":[{}]}}"#,
        methods.join(",")
    );
    assert!(!accepted(&document(&body)));
    assert!(accepted(&document(
        r#""commands":{"supported":["inspect"]},"authentication":{"methods":["aep-jwt"]}"#
    )));
    assert!(!accepted(&document(
        r#""commands":{"supported":["inspect"]},"authentication":{"methods":["AEP-JWT"]}"#
    )));
    assert!(!accepted(&document(
        r#""commands":{"supported":["inspect"]},"authentication":{"methods":["aep-jwt","aep-jwt"]}"#
    )));
}

/// Claim names use the registered claim-name syntax; unknown names stay acceptable.
#[test]
fn claim_advertisements() {
    assert!(!accepted(&document(
        r#""commands":{"supported":["inspect"]},"claims":{"required":["Contact.Email"]}"#
    )));
    assert!(accepted(&document(
        r#""commands":{"supported":["inspect"]},"claims":{"required":["example.future.claim"]}"#
    )));
}

/// The OpenAPI reference is a URI reference with a trailing-slash mode.
#[test]
fn openapi_advertisements() {
    let with = |http: &str| {
        document(r#""commands":{"supported":["inspect"]}"#)
            .replace(r#""http":{}"#, &format!(r#""http":{http}"#))
    };
    assert!(accepted(&with(
        r#"{"openapi":{"path_matching":{"trailing_slash":"strict"},"url":"/openapi.json"}}"#
    )));
    assert!(!accepted(&with(
        r#"{"openapi":{"path_matching":{"trailing_slash":"strict"},"url":"not a URI"}}"#
    )));
    assert!(!accepted(&with(
        r#"{"openapi":{"path_matching":{"trailing_slash":"strict"},"url":""}}"#
    )));
}

/// CORE-HTTP-004 appends the command path to `endpoint_base`, so the base has to be able to
/// carry one.
#[test]
fn endpoint_base_advertisements() {
    let with = |base: &str| {
        document(r#""commands":{"supported":["inspect"]}"#).replace(
            r#""http":{}"#,
            &format!(r#""http":{{"endpoint_base":"{base}"}}"#),
        )
    };
    assert!(accepted(&with("/aep/")));
    assert!(accepted(&with("/aep")));
    for base in ["aep/", "//evil.example/", "/aep/?next=", "/aep/#fragment"] {
        assert!(!accepted(&with(base)), "{base}");
    }
}

/// The Service identity is a DID, and extensions are absolute URIs.
#[test]
fn service_and_extension_advertisements() {
    let base = document(r#""commands":{"supported":["inspect"]}"#);
    assert!(!accepted(&base.replace(
        r#""did":"did:web:api.example.com""#,
        r#""did":"https://api.example.com""#
    )));
    assert!(accepted(&document(
        r#""commands":{"supported":["inspect"]},"extensions":{"supported":[]}"#
    )));
    assert!(!accepted(&document(
        r#""commands":{"supported":["inspect"]},"extensions":{"supported":["openapi-authentication"]}"#
    )));
}

/// Unknown members and unknown advertisement values are carried for forward compatibility.
#[test]
fn forward_compatible_advertisements() {
    assert!(accepted(&document(
        r#""commands":{"supported":["inspect","future-command"]},"future_section":{"enabled":true}"#
    )
    .replace(r#""supported":["http"]"#, r#""supported":["http","future-binding"]"#)
    .replace(r#""aep_version":"1.0""#, r#""aep_version":"1.7""#)));
}

/// The binding list must advertise the HTTP binding this document describes.
#[test]
fn binding_advertisements() {
    let base = document(r#""commands":{"supported":["inspect"]}"#);
    assert!(!accepted(
        &base.replace(r#""supported":["http"]"#, r#""supported":[]"#)
    ));
    assert!(!accepted(&base.replace(
        r#""supported":["http"]"#,
        r#""supported":["future"]"#
    )));
}

#[test]
fn version_compatibility() {
    assert!(is_version_compatible("1.0", "1.0"));
    assert!(is_version_compatible("1.7", "1.0"));
    assert!(!is_version_compatible("2.0", "1.0"));
    assert!(!is_version_compatible("1", "1.0"));
    assert!(!is_version_compatible("1.0", "bad"));
    assert!(!is_version_compatible("01.0", "1.0"));
}

#[test]
fn rejects_documents_that_are_not_objects() {
    assert!(parse_inspect_document(b"[]").is_err());
    assert!(parse_inspect_document(b"not json").is_err());
    assert!(parse_inspect_document(b"{}").is_err());
}
