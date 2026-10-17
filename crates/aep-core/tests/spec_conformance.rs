//! Behaviour the specifications require of the core primitives, exercised through the public API.

use aep_core::*;

fn authorization(credentials: &str) -> ProtectedResourceAuthorization {
    ProtectedResourceAuthorization {
        carrier: AuthorizationCarrier::Standard,
        scheme: CredentialScheme::Aep,
        credentials: credentials.to_owned(),
    }
}

/// CORE-AUTH-001 spells the presentation as `"AEP" 1*SP compact-jws`, so repeated separators are
/// grammar and a field value may carry trailing optional whitespace.
#[test]
fn authorization_separator_follows_the_grammar() {
    for value in [
        "AEP  assertion",
        "AEP\tassertion",
        "AEP assertion ",
        "AEP   assertion\t",
    ] {
        let parsed = parse_protected_resource_authorization(value, AuthorizationCarrier::Standard)
            .expect("conforming presentation");
        assert_eq!(parsed.credentials, "assertion", "{value:?}");
    }
}

/// CORE-PR-018 forbids a combined value encoding more than one AEP credential, and CORE-AUTH-001
/// makes the credential a visible US-ASCII token with no space.
#[test]
fn authorization_refuses_a_value_carrying_more_than_one_credential() {
    for value in [
        "AEP one two",
        "AEP one\ttwo",
        "AEP one\u{7f}",
        "AEP caf\u{e9}",
    ] {
        for carrier in [
            AuthorizationCarrier::Standard,
            AuthorizationCarrier::Dedicated,
        ] {
            let error = parse_protected_resource_authorization(value, carrier)
                .expect_err("ambiguous presentation");
            assert_eq!(error.code, ErrorCode::NotRecognized, "{value:?}");
        }
    }
}

/// A credential carrying CR, LF, NUL, or a space would split or extend the rendered field, so the
/// library refuses to render one rather than emitting it.
#[test]
fn rendering_refuses_credentials_that_are_not_a_field_value() {
    for credentials in [
        "one two",
        "one\ttwo",
        "line\r\nInjected: header",
        "null\u{0}byte",
        "caf\u{e9}",
        "",
    ] {
        let error = render_protected_resource_authorization(&authorization(credentials))
            .expect_err("unrenderable credential");
        assert_eq!(error.code, ErrorCode::InvalidRequest, "{credentials:?}");
    }
    let (header, value) =
        render_protected_resource_authorization(&authorization("compact.jws.signature"))
            .expect("renderable credential");
    assert_eq!(header, "Authorization");
    assert_eq!(value, "AEP compact.jws.signature");
}

/// CORE-HTTP-004 appends the command path with exactly one `/` separator, so a base carrying a
/// query, a fragment, or a dot segment cannot carry a command.
#[test]
fn endpoint_base_must_be_able_to_carry_a_command_path() {
    for base in [
        "/aep/?next=",
        "/aep/#fragment",
        "/aep/../admin/",
        "/aep/./",
        "//evil.example/",
        "aep/",
        "/\\elsewhere.example/",
        "/\\\\elsewhere.example/",
        "/\t/elsewhere.example/",
        "/aep/%2e%2e/admin/",
    ] {
        assert!(normalize_endpoint_base(Some(base)).is_err(), "{base:?}");
        assert!(
            command_path(&Command::Enroll, Some(base)).is_err(),
            "{base:?}"
        );
    }
    assert_eq!(
        command_path(&Command::Enroll, Some("/aep")).expect("valid base"),
        "/aep/enroll"
    );
    for base in ["/aep/{tenant}", "/aep//v1", "/aep/%252e%252e"] {
        assert_eq!(
            command_path(&Command::Enroll, Some(base)).expect("literal path"),
            format!("{base}/enroll")
        );
    }
}

/// DWB-RES-001 maps `did:web:<host>:<path>` onto `https://<host>/<path>/did.json`. A segment
/// decoding to a separator, a query, a fragment, or a dot segment leaves that path, so the
/// identifier would resolve to a document it never named.
#[test]
fn did_web_path_segments_stay_inside_the_path_they_name() {
    for did in [
        "did:web:example.com:a:%2E%2E",
        "did:web:example.com:a:%2Fevil",
        "did:web:example.com:a:%5Cevil",
        "did:web:example.com:a:%23fragment",
        "did:web:example.com:a:%3Fquery",
        "did:web:example.com::a",
        "did:web:example.com:a:.",
    ] {
        assert!(did_web_document_url(did).is_err(), "{did:?}");
    }
    assert_eq!(
        did_web_document_url("did:web:example.com:agents:one")
            .expect("valid identifier")
            .as_str(),
        "https://example.com/agents/one/did.json"
    );
}

/// The host is checked before the URL parser sees it, because the parser drops tabs and line
/// breaks and would resolve two different identifiers to one document URL.
#[test]
fn did_web_host_is_checked_before_the_url_parser_rewrites_it() {
    for did in [
        "did:web:exa%0Dmple.com",
        "did:web:exa%0Ample.com",
        "did:web:exa%09mple.com",
        "did:web:%20example.com",
        "did:web:example.com%20",
        "did:web:user%40example.com",
        "did:web:example.com%2Fpath",
        "did:web:example.com%3Fquery",
        "did:web:",
    ] {
        assert!(did_web_document_url(did).is_err(), "{did:?}");
    }
    for did in [
        "did:web:example.com",
        "did:web:example.com%3A8443",
        "did:web:%5B%3A%3A1%5D",
    ] {
        assert!(did_web_document_url(did).is_ok(), "{did:?}");
    }
}

fn names(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

/// CORE-OAS-011: operation security replaces the root value, an empty list is public, an empty
/// requirement object is an anonymous alternative, several objects are alternatives, and several
/// schemes in one object are compound.
#[test]
fn openapi_security_inheritance() {
    let root = vec![names(&["aepScheme"])];
    let supported = names(&["aepScheme", "apiKeyScheme"]);
    let cases: Vec<(Option<Vec<Vec<String>>>, OpenApiSecurityDisposition)> = vec![
        (None, OpenApiSecurityDisposition::Required),
        (Some(Vec::new()), OpenApiSecurityDisposition::Public),
        (
            Some(vec![Vec::new(), names(&["aepScheme"])]),
            OpenApiSecurityDisposition::OptionalAnonymous,
        ),
        (
            Some(vec![names(&["aepScheme"]), names(&["apiKeyScheme"])]),
            OpenApiSecurityDisposition::Alternatives,
        ),
        (
            Some(vec![names(&["aepScheme", "apiKeyScheme"])]),
            OpenApiSecurityDisposition::AllRequired,
        ),
    ];
    for (operation, disposition) in cases {
        let resolved = resolve_openapi_security(Some(&root), operation.as_deref(), &supported);
        assert_eq!(resolved.disposition, disposition);
    }
    assert_eq!(
        resolve_openapi_security(None, None, &supported).disposition,
        OpenApiSecurityDisposition::Public
    );
}

/// CORE-OAS-013 makes a compound requirement unsupported when any member is, and CORE-OAS-015
/// forbids reducing it to the member the Agent does support.
#[test]
fn openapi_security_refuses_to_reduce_a_compound_requirement() {
    let compound = vec![names(&["aepScheme", "mtlsScheme"])];
    let resolved = resolve_openapi_security(None, Some(&compound), &names(&["aepScheme"]));
    assert_eq!(
        resolved.disposition,
        OpenApiSecurityDisposition::FallbackLiveChallenge
    );
    assert!(resolved.satisfiable.is_empty());

    // CORE-OAS-014 permits another complete alternative when a compound requirement is unsupported.
    let alternatives = vec![
        names(&["aepScheme", "mtlsScheme"]),
        names(&["apiKeyScheme"]),
    ];
    let selected = resolve_openapi_security(
        None,
        Some(&alternatives),
        &names(&["aepScheme", "apiKeyScheme"]),
    );
    assert_eq!(
        selected.disposition,
        OpenApiSecurityDisposition::Alternatives
    );
    assert_eq!(selected.satisfiable, vec![names(&["apiKeyScheme"])]);
}

#[test]
fn openapi_security_dispositions_carry_their_wire_values() {
    for (disposition, value) in [
        (OpenApiSecurityDisposition::Public, "public"),
        (
            OpenApiSecurityDisposition::OptionalAnonymous,
            "optional-anonymous",
        ),
        (OpenApiSecurityDisposition::Required, "required"),
        (OpenApiSecurityDisposition::Alternatives, "alternatives"),
        (OpenApiSecurityDisposition::AllRequired, "all-required"),
        (
            OpenApiSecurityDisposition::FallbackLiveChallenge,
            "fallback-live-challenge",
        ),
    ] {
        assert_eq!(disposition.as_str(), value);
    }
}
