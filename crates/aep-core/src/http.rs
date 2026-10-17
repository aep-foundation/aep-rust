use crate::{
    AUTHORIZATION_HEADER, AuthorizationCarrier, AuthorizationCarrierError, Command,
    CredentialScheme, DEFAULT_HTTP_ENDPOINT_BASE, ErrorCode, InspectDocument,
    ProtectedResourceAuthorization,
};

/// Visible US-ASCII excluding space, which is what the `AEP`, `Bearer`, and `Basic` credential
/// syntaxes admit. Excluding everything else keeps CR, LF, NUL, and other control characters out
/// of a rendered field value, and keeps one field value from carrying two credentials.
fn is_credential_token(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

/// Reports whether a value can carry a command path appended to it.
///
/// [`command_path`] appends the relative path with exactly one `/` separator, so a base carrying a
/// query, a fragment, or a dot segment cannot satisfy that: the command name would land in the
/// query string or walk out of the advertised base.
fn is_endpoint_path(value: &str) -> bool {
    value.starts_with('/')
        && !value.starts_with("//")
        && !value.contains('?')
        && !value.contains('#')
        && !value.contains('\\')
        && !value.chars().any(char::is_control)
        && !value.split('/').any(|segment| {
            matches!(
                percent_encoding::percent_decode_str(segment)
                    .decode_utf8()
                    .as_deref(),
                Ok("." | "..")
            )
        })
}

pub fn normalize_endpoint_base(endpoint_base: Option<&str>) -> Result<String, crate::CoreError> {
    let endpoint_base = endpoint_base.unwrap_or(DEFAULT_HTTP_ENDPOINT_BASE);
    if !is_endpoint_path(endpoint_base) {
        return Err(crate::CoreError::Invalid(
            "AEP endpoint_base must be an origin-relative absolute path".to_owned(),
        ));
    }
    if endpoint_base.ends_with('/') {
        Ok(endpoint_base.to_owned())
    } else {
        Ok(format!("{endpoint_base}/"))
    }
}

pub fn command_path(
    command: &Command,
    endpoint_base: Option<&str>,
) -> Result<String, crate::CoreError> {
    let relative = match command {
        Command::Enroll => "enroll",
        Command::Grant => "grant",
        Command::Revoke => "revoke",
        Command::Status => "status",
        Command::Inspect | Command::Other(_) => {
            return Err(crate::CoreError::Invalid(
                "AEP command has no HTTP endpoint path".to_owned(),
            ));
        }
    };
    Ok(format!(
        "{}{relative}",
        normalize_endpoint_base(endpoint_base)?
    ))
}

pub fn command_path_from_inspect(
    document: &InspectDocument,
    command: &Command,
) -> Result<String, crate::CoreError> {
    command_path(command, document.http.endpoint_base.as_deref())
}

pub const fn protected_resource_authorization_header(
    carrier: AuthorizationCarrier,
) -> &'static str {
    match carrier {
        AuthorizationCarrier::Standard => "Authorization",
        AuthorizationCarrier::Dedicated => AUTHORIZATION_HEADER,
    }
}

pub fn render_protected_resource_authorization(
    value: &ProtectedResourceAuthorization,
) -> Result<(String, String), AuthorizationCarrierError> {
    validate_protected_resource_authorization(value)?;
    Ok((
        protected_resource_authorization_header(value.carrier).to_owned(),
        format!("{} {}", value.scheme.as_str(), value.credentials),
    ))
}

pub fn validate_protected_resource_authorization(
    value: &ProtectedResourceAuthorization,
) -> Result<(), AuthorizationCarrierError> {
    if value.credentials.is_empty() {
        return Err(AuthorizationCarrierError {
            code: ErrorCode::InvalidRequest,
            message: "authorization credentials must not be empty".to_owned(),
        });
    }
    if !is_credential_token(&value.credentials) {
        return Err(AuthorizationCarrierError {
            code: ErrorCode::InvalidRequest,
            message: "authorization credentials must not contain whitespace or control characters"
                .to_owned(),
        });
    }
    Ok(())
}

pub fn parse_protected_resource_authorization(
    field_value: &str,
    carrier: AuthorizationCarrier,
) -> Result<ProtectedResourceAuthorization, AuthorizationCarrierError> {
    if carrier == AuthorizationCarrier::Dedicated && field_value.contains(',') {
        return Err(not_recognized(
            "the dedicated authorization field is ambiguous",
        ));
    }
    // CORE-AUTH-001 spells the presentation as `"AEP" 1*SP compact-jws`, so repeated separators
    // belong to the grammar and a field value may carry trailing optional whitespace. The
    // credential itself is a visible US-ASCII token, which is what keeps one field value from
    // encoding more than one credential (CORE-PR-018).
    let Some(separator) = field_value.find([' ', '\t']) else {
        return Err(not_recognized(
            "the authorization presentation was not recognized",
        ));
    };
    let (scheme, remainder) = field_value.split_at(separator);
    let credentials = remainder.trim_matches([' ', '\t']);
    if scheme.is_empty() || !is_credential_token(credentials) {
        return Err(not_recognized(
            "the authorization presentation was not recognized",
        ));
    }
    let scheme = if scheme.eq_ignore_ascii_case("aep") {
        CredentialScheme::Aep
    } else if scheme.eq_ignore_ascii_case("bearer") {
        CredentialScheme::Bearer
    } else if scheme.eq_ignore_ascii_case("basic") {
        CredentialScheme::Basic
    } else {
        return Err(not_recognized(
            "the authorization presentation was not recognized",
        ));
    };
    Ok(ProtectedResourceAuthorization {
        carrier,
        scheme,
        credentials: credentials.to_owned(),
    })
}

fn not_recognized(message: &str) -> AuthorizationCarrierError {
    AuthorizationCarrierError {
        code: ErrorCode::NotRecognized,
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn normalizes_command_paths() {
        assert_eq!(
            command_path(&Command::Enroll, Some("/custom")).expect("valid path"),
            "/custom/enroll"
        );
    }

    #[test]
    fn rejects_ambiguous_dedicated_authorization() {
        let error = parse_protected_resource_authorization(
            "AEP first, AEP second",
            AuthorizationCarrier::Dedicated,
        )
        .expect_err("combined dedicated field must fail");
        assert_eq!(error.code, ErrorCode::NotRecognized);
    }

    #[test]
    fn parses_and_renders_supported_authorization_schemes() {
        for (field, rendered_field, scheme) in [
            ("AEP assertion", "AEP assertion", CredentialScheme::Aep),
            ("bearer token", "Bearer token", CredentialScheme::Bearer),
            ("Basic value", "Basic value", CredentialScheme::Basic),
        ] {
            let parsed =
                parse_protected_resource_authorization(field, AuthorizationCarrier::Standard)
                    .expect("recognized authorization");
            assert_eq!(parsed.scheme, scheme);
            let (header, rendered) =
                render_protected_resource_authorization(&parsed).expect("rendered authorization");
            assert_eq!(header, "Authorization");
            assert_eq!(rendered, rendered_field);
        }
        assert!(
            parse_protected_resource_authorization("Digest value", AuthorizationCarrier::Standard)
                .is_err()
        );
        assert!(
            validate_protected_resource_authorization(&ProtectedResourceAuthorization {
                carrier: AuthorizationCarrier::Dedicated,
                scheme: CredentialScheme::Aep,
                credentials: String::new(),
            })
            .is_err()
        );
    }

    #[test]
    fn rejects_commands_without_http_paths() {
        assert!(command_path(&Command::Inspect, None).is_err());
        assert!(normalize_endpoint_base(Some("https://service.example/aep")).is_err());
    }

    proptest! {
        #[test]
        fn normalized_paths_always_end_in_a_single_separator(
            segments in proptest::collection::vec("[a-z]{1,8}", 1..5)
        ) {
            let input = format!("/{}", segments.join("/"));
            let normalized = normalize_endpoint_base(Some(&input)).expect("valid path");
            prop_assert!(normalized.starts_with('/'));
            prop_assert!(!normalized.starts_with("//"));
            prop_assert!(normalized.ends_with('/'));
        }
    }
}
