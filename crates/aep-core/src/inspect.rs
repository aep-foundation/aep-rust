use std::sync::OnceLock;

use regex::Regex;
use url::Url;

use crate::{
    Authentication, Binding, Command, GrantType, InspectClaims, InspectDocument,
    MAX_AUTHENTICATION_METHODS, ParseError, SigningAlgorithm, VERSION, ValidationError,
    validation::{issue, parse_and_validate, require_unique, result},
};

pub fn parse_inspect_document(data: &[u8]) -> Result<InspectDocument, ParseError> {
    parse_and_validate(data, "Inspect document", validate_inspect_document)
}

pub fn validate_inspect_document(document: &InspectDocument) -> Result<(), ValidationError> {
    let mut issues = Vec::new();
    if !version_pattern().is_match(&document.aep_version) {
        issues.push(issue(
            "$.aep_version",
            "Expected major.minor version syntax.",
        ));
    } else if !is_version_compatible(&document.aep_version, VERSION) {
        issues.push(issue(
            "$.aep_version",
            format!("Unsupported AEP major version: {}.", document.aep_version),
        ));
    }
    validate_authentication(document.authentication.as_ref(), &mut issues);
    validate_advertisements(
        document.bindings.supported.iter().map(Binding::as_str),
        "$.bindings.supported",
        true,
        &mut issues,
    );
    if !document.bindings.supported.contains(&Binding::Http) {
        issues.push(issue(
            "$.bindings.supported",
            "Expected http to be advertised.",
        ));
    }
    validate_claims(document.claims.as_ref(), &mut issues);
    validate_advertisements(
        document.commands.supported.iter().map(Command::as_str),
        "$.commands.supported",
        true,
        &mut issues,
    );
    if !document.commands.supported.contains(&Command::Inspect) {
        issues.push(issue(
            "$.commands.supported",
            "Expected inspect to be advertised.",
        ));
    }
    if document
        .commands
        .supported
        .iter()
        .any(|command| command.as_str() == "authenticate")
    {
        issues.push(issue(
            "$.commands.supported",
            "authenticate is an assertion operation, not a command.",
        ));
    }
    validate_advertisements(
        document.commands.grant_types.iter().map(GrantType::as_str),
        "$.commands.grant_types",
        false,
        &mut issues,
    );
    for name in document.commands.grant_types_config.keys() {
        let path = format!("$.commands.grant_types_config.{name}");
        if !advertisement_pattern().is_match(name) {
            issues.push(issue(&path, "Expected a lowercase grant-type identifier."));
        }
        if !document
            .commands
            .grant_types
            .iter()
            .any(|grant_type| grant_type.as_str() == name)
        {
            issues.push(issue(
                &path,
                "Expected configuration for an advertised grant type.",
            ));
        }
    }
    let advertises_grant_or_revoke = document
        .commands
        .supported
        .iter()
        .any(|command| matches!(command, Command::Grant | Command::Revoke));
    if advertises_grant_or_revoke && document.commands.grant_types.is_empty() {
        issues.push(issue(
            "$.commands.grant_types",
            "Expected at least one grant type when Grant or Revoke is advertised.",
        ));
    }
    if document.core.signing_algorithms.is_empty() {
        issues.push(issue(
            "$.core.signing_algorithms",
            "Expected at least one signing algorithm.",
        ));
    }
    if !document
        .core
        .signing_algorithms
        .contains(&SigningAlgorithm::EdDsa)
    {
        issues.push(issue(
            "$.core.signing_algorithms",
            "Expected EdDSA to be advertised.",
        ));
    }
    if !document
        .core
        .signing_algorithms
        .contains(&SigningAlgorithm::Es256)
    {
        issues.push(issue(
            "$.core.signing_algorithms",
            "Expected ES256 to be advertised.",
        ));
    }
    if let Some(extensions) = &document.extensions {
        for (index, extension) in extensions.supported.iter().enumerate() {
            if Url::parse(extension).is_err() {
                issues.push(issue(
                    format!("$.extensions.supported[{index}]"),
                    "Expected an absolute URI.",
                ));
            }
        }
    }
    if let Some(endpoint_base) = &document.http.endpoint_base
        && (!endpoint_base.starts_with('/') || endpoint_base.starts_with("//"))
    {
        issues.push(issue(
            "$.http.endpoint_base",
            "Expected an origin-relative absolute path.",
        ));
    }
    if let Some(openapi) = &document.http.openapi
        && (openapi.url.is_empty()
            || openapi.url.chars().any(char::is_whitespace)
            || Url::parse(&openapi.url).is_err() && !is_relative_reference(&openapi.url))
    {
        issues.push(issue("$.http.openapi.url", "Expected a URI reference."));
    }
    for (index, method) in document.identity.methods.iter().enumerate() {
        if !identity_pattern().is_match(method.as_str()) {
            issues.push(issue(
                format!("$.identity.methods[{index}]"),
                "Expected an identity-method identifier.",
            ));
        }
    }
    let authenticated = document.commands.supported.iter().any(|command| {
        matches!(
            command,
            Command::Enroll | Command::Grant | Command::Revoke | Command::Status
        )
    });
    if authenticated && document.identity.methods.is_empty() {
        issues.push(issue(
            "$.identity.methods",
            "Expected at least one identity method for authenticated commands.",
        ));
    }
    if !document.service.did.starts_with("did:") {
        issues.push(issue("$.service.did", "Expected a DID."));
    }
    result("Inspect document", issues)
}

pub fn is_version_compatible(received: &str, supported: &str) -> bool {
    if !version_pattern().is_match(received) || !version_pattern().is_match(supported) {
        return false;
    }
    received.split_once('.').map(|parts| parts.0) == supported.split_once('.').map(|parts| parts.0)
}

fn validate_authentication(
    authentication: Option<&Authentication>,
    issues: &mut Vec<crate::ValidationIssue>,
) {
    let Some(authentication) = authentication else {
        return;
    };
    if authentication.methods.is_empty() {
        issues.push(issue(
            "$.authentication.methods",
            "Expected at least one item.",
        ));
    }
    if authentication.methods.len() > MAX_AUTHENTICATION_METHODS {
        issues.push(issue(
            "$.authentication.methods",
            "Expected at most 16 items.",
        ));
    }
    validate_advertisements(
        authentication.methods.iter().map(|method| method.as_str()),
        "$.authentication.methods",
        false,
        issues,
    );
    require_unique(&authentication.methods, "$.authentication.methods", issues);
}

fn validate_claims(claims: Option<&InspectClaims>, issues: &mut Vec<crate::ValidationIssue>) {
    let Some(claims) = claims else {
        return;
    };
    for (group, values) in [
        ("required", &claims.required),
        ("preferred", &claims.preferred),
        ("optional", &claims.optional),
    ] {
        for (index, value) in values.iter().enumerate() {
            if !claim_name_pattern().is_match(value.as_str()) {
                issues.push(issue(
                    format!("$.claims.{group}[{index}]"),
                    "Expected a registered claim-name shape.",
                ));
            }
        }
    }
}

fn validate_advertisements<'a>(
    values: impl Iterator<Item = &'a str>,
    path: &str,
    require_item: bool,
    issues: &mut Vec<crate::ValidationIssue>,
) {
    let values = values.collect::<Vec<_>>();
    if require_item && values.is_empty() {
        issues.push(issue(path, "Expected at least one item."));
    }
    for (index, value) in values.into_iter().enumerate() {
        if !advertisement_pattern().is_match(value) {
            issues.push(issue(
                format!("{path}[{index}]"),
                "Expected a lowercase advertisement identifier.",
            ));
        }
    }
}

fn is_relative_reference(value: &str) -> bool {
    !value.is_empty() && !value.starts_with("//") && !value.contains('#')
}

fn version_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$").expect("valid version pattern")
    })
}

fn advertisement_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"^[a-z0-9]+(?:-[a-z0-9]+)*$").expect("valid advertisement pattern")
    })
}

fn identity_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"^[a-z0-9]+(?::[a-z0-9]+)*(?:-[a-z0-9]+)*$")
            .expect("valid identity method pattern")
    })
}

fn claim_name_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$").expect("valid claim name pattern")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_document() -> InspectDocument {
        parse_inspect_document(
            br#"{
                "aep_version":"1.0",
                "bindings":{"supported":["http"]},
                "commands":{"supported":["inspect","enroll"]},
                "core":{"signing_algorithms":["EdDSA","ES256"]},
                "http":{},
                "identity":{"methods":["did:web"]},
                "service":{"did":"did:web:service.example"}
            }"#,
        )
        .expect("valid Inspect document")
    }

    #[test]
    fn accepts_unknown_well_formed_advertisements() {
        let document = parse_inspect_document(
            br#"{
                "aep_version":"1.1",
                "bindings":{"supported":["http","future-binding"]},
                "commands":{"supported":["inspect","future-command"]},
                "core":{"signing_algorithms":["EdDSA","ES256","future"]},
                "http":{},
                "identity":{"methods":[]},
                "service":{"did":"did:web:service.example"}
            }"#,
        )
        .expect("same-major additive document");
        assert_eq!(document.commands.supported[1].as_str(), "future-command");
    }

    #[test]
    fn rejects_an_incompatible_major_version() {
        let error = parse_inspect_document(
            br#"{"aep_version":"2.0","bindings":{"supported":["http"]},"commands":{"supported":["inspect"]},"core":{"signing_algorithms":["EdDSA","ES256"]},"http":{},"identity":{"methods":[]},"service":{"did":"did:web:service.example"}}"#,
        )
        .expect_err("major version must fail");
        assert!(matches!(error, ParseError::Validation(_)));
    }

    #[test]
    fn rejects_invalid_required_advertisements() {
        let mut document = valid_document();
        document.bindings.supported.clear();
        assert!(validate_inspect_document(&document).is_err());

        let mut document = valid_document();
        document.commands.supported = vec![Command::Enroll];
        document.commands.grant_types.clear();
        assert!(validate_inspect_document(&document).is_err());

        let mut document = valid_document();
        document.core.signing_algorithms = vec![SigningAlgorithm::EdDsa];
        assert!(validate_inspect_document(&document).is_err());

        let mut document = valid_document();
        document.identity.methods.clear();
        assert!(validate_inspect_document(&document).is_err());

        let mut document = valid_document();
        document
            .commands
            .supported
            .push(Command::Other("authenticate".to_owned()));
        assert!(validate_inspect_document(&document).is_err());
    }

    #[test]
    fn rejects_invalid_optional_advertisements() {
        let mut document = valid_document();
        document.authentication = Some(Authentication { methods: vec![] });
        assert!(validate_inspect_document(&document).is_err());

        let mut document = valid_document();
        document.http.endpoint_base = Some("//wrong".to_owned());
        assert!(validate_inspect_document(&document).is_err());

        let mut document = valid_document();
        document.extensions = Some(crate::Extensions {
            supported: vec!["relative".to_owned()],
            additional: Default::default(),
        });
        assert!(validate_inspect_document(&document).is_err());

        let mut document = valid_document();
        document.service.did = "not-a-did".to_owned();
        assert!(validate_inspect_document(&document).is_err());
    }

    #[test]
    fn compares_only_compatible_major_versions() {
        assert!(is_version_compatible("1.9", "1.0"));
        assert!(!is_version_compatible("2.0", "1.0"));
        assert!(!is_version_compatible("invalid", "1.0"));
    }
}
