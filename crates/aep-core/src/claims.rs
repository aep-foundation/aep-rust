use std::{collections::HashSet, net::IpAddr, str::FromStr, sync::OnceLock};

use regex::Regex;
use time::{Date, Month};

use crate::{
    ClaimName, ClaimValues, InspectClaims, ParseError, ValidationError,
    validation::{issue, parse_and_validate, result, validate_optional_non_empty},
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ClaimSupportEvaluation {
    pub can_satisfy_required: bool,
    pub supported_optional: Vec<ClaimName>,
    pub supported_preferred: Vec<ClaimName>,
    pub unsupported_required: Vec<ClaimName>,
}

pub fn parse_claim_values(data: &[u8]) -> Result<ClaimValues, ParseError> {
    parse_and_validate(data, "Claim Values", validate_claim_values)
}

pub fn validate_claim_values(value: &ClaimValues) -> Result<(), ValidationError> {
    let mut issues = Vec::new();
    if let Some(address) = &value.contact_address_primary {
        let path = "$.contact.address.primary";
        if !country_pattern().is_match(&address.country) {
            issues.push(issue(
                format!("{path}.country"),
                "Expected a two-letter uppercase country code.",
            ));
        }
        validate_optional_non_empty(
            Some(address.first_name.as_str()),
            &format!("{path}.first_name"),
            &mut issues,
        );
        validate_optional_non_empty(
            Some(address.last_name.as_str()),
            &format!("{path}.last_name"),
            &mut issues,
        );
        validate_optional_non_empty(
            Some(address.line1.as_str()),
            &format!("{path}.line1"),
            &mut issues,
        );
        validate_optional_non_empty(
            address.city.as_deref(),
            &format!("{path}.city"),
            &mut issues,
        );
        if address.additional.contains_key("postal_code") {
            issues.push(issue(
                format!("{path}.postal_code"),
                "Expected the postcode member.",
            ));
        }
    }
    if value
        .contact_email
        .as_deref()
        .is_some_and(|email| email.len() < 3 || !is_email_mailbox(email))
    {
        issues.push(issue("$.contact.email", "Expected an RFC 5321 Mailbox."));
    }
    if value
        .contact_mobile
        .as_deref()
        .is_some_and(|mobile| !e164_pattern().is_match(mobile))
    {
        issues.push(issue(
            "$.contact.mobile",
            "Expected an E.164 telephone number.",
        ));
    }
    if value
        .person_birthdate
        .as_deref()
        .is_some_and(|birthdate| !is_full_date(birthdate))
    {
        issues.push(issue(
            "$.person.birthdate",
            "Expected an RFC 3339 full-date.",
        ));
    }
    validate_optional_non_empty(
        value.person_first_name.as_deref(),
        "$.person.first_name",
        &mut issues,
    );
    validate_optional_non_empty(
        value.person_last_name.as_deref(),
        "$.person.last_name",
        &mut issues,
    );
    validate_optional_non_empty(
        value.person_username.as_deref(),
        "$.person.username",
        &mut issues,
    );
    result("Claim Values", issues)
}

pub fn evaluate_claim_support(
    requested: Option<&InspectClaims>,
    supported_claim_names: impl IntoIterator<Item = ClaimName>,
) -> ClaimSupportEvaluation {
    let supported = supported_claim_names.into_iter().collect::<HashSet<_>>();
    let Some(requested) = requested else {
        return ClaimSupportEvaluation {
            can_satisfy_required: true,
            ..ClaimSupportEvaluation::default()
        };
    };
    let unsupported_required = requested
        .required
        .iter()
        .filter(|name| !supported.contains(*name))
        .cloned()
        .collect::<Vec<_>>();
    ClaimSupportEvaluation {
        can_satisfy_required: unsupported_required.is_empty(),
        supported_optional: requested
            .optional
            .iter()
            .filter(|name| supported.contains(*name))
            .cloned()
            .collect(),
        supported_preferred: requested
            .preferred
            .iter()
            .filter(|name| supported.contains(*name))
            .cloned()
            .collect(),
        unsupported_required,
    }
}

pub fn missing_required_claim_names(
    required: &[ClaimName],
    values: Option<&ClaimValues>,
) -> Vec<ClaimName> {
    required
        .iter()
        .filter(|name| values.is_none_or(|values| !has_claim(values, name)))
        .cloned()
        .collect()
}

fn has_claim(values: &ClaimValues, name: &ClaimName) -> bool {
    match name {
        ClaimName::ContactAddressPrimary => values.contact_address_primary.is_some(),
        ClaimName::ContactEmail => values.contact_email.is_some(),
        ClaimName::ContactMobile => values.contact_mobile.is_some(),
        ClaimName::PersonBirthdate => values.person_birthdate.is_some(),
        ClaimName::PersonFirstName => values.person_first_name.is_some(),
        ClaimName::PersonLastName => values.person_last_name.is_some(),
        ClaimName::PersonUsername => values.person_username.is_some(),
        ClaimName::Other(name) => values.additional.contains_key(name),
    }
}

fn e164_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"^\+[1-9][0-9]{1,14}$").expect("valid E.164 pattern"))
}

fn country_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"^[A-Z]{2}$").expect("valid country pattern"))
}

fn atom_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+$").expect("valid mailbox atom pattern")
    })
}

fn domain_label_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$")
            .expect("valid domain label pattern")
    })
}

fn is_email_mailbox(value: &str) -> bool {
    let Some(separator) = mailbox_separator(value) else {
        return false;
    };
    if separator == 0 || separator == value.len() - 1 {
        return false;
    }
    let (local, domain_with_at) = value.split_at(separator);
    let domain = &domain_with_at[1..];
    local.len() <= 64 && domain.len() <= 255 && is_local_part(local) && is_mailbox_domain(domain)
}

fn mailbox_separator(value: &str) -> Option<usize> {
    if !value.starts_with('"') {
        let separator = value.find('@')?;
        return (value.rfind('@') == Some(separator)).then_some(separator);
    }
    let bytes = value.as_bytes();
    let mut escaped = false;
    for index in 1..bytes.len() {
        if escaped {
            escaped = false;
        } else if bytes[index] == b'\\' {
            escaped = true;
        } else if bytes[index] == b'"' {
            return (bytes.get(index + 1) == Some(&b'@')).then_some(index + 1);
        }
    }
    None
}

fn is_local_part(value: &str) -> bool {
    if value.starts_with('"') {
        return is_quoted_local_part(value);
    }
    value.split('.').all(|atom| atom_pattern().is_match(atom))
}

fn is_quoted_local_part(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 2 || bytes.last() != Some(&b'"') {
        return false;
    }
    let mut index = 1;
    while index < bytes.len() - 1 {
        let byte = bytes[index];
        if byte == b'\\' {
            index += 1;
            if index >= bytes.len() - 1 || !(32..=126).contains(&bytes[index]) {
                return false;
            }
        } else if !((32..=33).contains(&byte)
            || (35..=91).contains(&byte)
            || (93..=126).contains(&byte))
        {
            return false;
        }
        index += 1;
    }
    true
}

fn is_mailbox_domain(value: &str) -> bool {
    if value.starts_with('[') || value.ends_with(']') {
        return is_address_literal(value);
    }
    value
        .split('.')
        .all(|label| label.len() <= 63 && domain_label_pattern().is_match(label))
}

fn is_address_literal(value: &str) -> bool {
    let Some(content) = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    else {
        return false;
    };
    if content.contains('.') && IpAddr::from_str(content).is_ok() {
        return true;
    }
    if let Some(ipv6) = content.strip_prefix("IPv6:") {
        return IpAddr::from_str(ipv6).is_ok();
    }
    let Some((tag, literal)) = content.split_once(':') else {
        return false;
    };
    !tag.is_empty()
        && !literal.is_empty()
        && tag.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (byte == b'-' && index + 1 < tag.len())
        })
        && literal
            .bytes()
            .all(|byte| (33..=90).contains(&byte) || (94..=126).contains(&byte))
}

fn is_full_date(value: &str) -> bool {
    if value.len() != 10 || value.as_bytes()[4] != b'-' || value.as_bytes()[7] != b'-' {
        return false;
    }
    let Ok(year) = value[0..4].parse::<i32>() else {
        return false;
    };
    let Ok(month_number) = value[5..7].parse::<u8>() else {
        return false;
    };
    let Ok(month) = Month::try_from(month_number) else {
        return false;
    };
    let Ok(day) = value[8..10].parse::<u8>() else {
        return false;
    };
    Date::from_calendar_date(year, month, day).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_registered_claim_shapes() {
        let claims = parse_claim_values(
            br#"{
                "contact.address.primary": {
                    "country": "US",
                    "first_name": "Ada",
                    "last_name": "Lovelace",
                    "line1": "1 Example Way"
                },
                "contact.email": "ada@example.com",
                "contact.mobile": "+14155550100",
                "person.birthdate": "1815-12-10"
            }"#,
        )
        .expect("valid claims");
        assert_eq!(claims.contact_email.as_deref(), Some("ada@example.com"));
    }

    #[test]
    fn rejects_legacy_postal_code() {
        let error = parse_claim_values(
            br#"{"contact.address.primary":{"country":"US","first_name":"Ada","last_name":"Lovelace","line1":"1 Example Way","postal_code":"12345"}}"#,
        )
        .expect_err("legacy member must fail");
        assert!(matches!(error, ParseError::Validation(_)));
    }

    #[test]
    fn rejects_invalid_registered_claim_shapes() {
        for document in [
            r#"{"contact.email":"not-an-address"}"#,
            r#"{"contact.mobile":"4155550100"}"#,
            r#"{"person.birthdate":"2025-02-29"}"#,
            r#"{"person.first_name":""}"#,
            r#"{"contact.address.primary":{"country":"usa","first_name":"Ada","last_name":"Lovelace","line1":"1 Way"}}"#,
        ] {
            assert!(
                parse_claim_values(document.as_bytes()).is_err(),
                "accepted {document}"
            );
        }
    }

    #[test]
    fn evaluates_supported_and_missing_claims() {
        let requested = InspectClaims {
            required: vec![ClaimName::ContactEmail, ClaimName::ContactMobile],
            preferred: vec![ClaimName::PersonFirstName],
            optional: vec![ClaimName::PersonUsername],
            additional: Default::default(),
        };
        let evaluation = evaluate_claim_support(
            Some(&requested),
            [ClaimName::ContactEmail, ClaimName::PersonFirstName],
        );
        assert!(!evaluation.can_satisfy_required);
        assert_eq!(
            evaluation.unsupported_required,
            vec![ClaimName::ContactMobile]
        );
        assert_eq!(
            evaluation.supported_preferred,
            vec![ClaimName::PersonFirstName]
        );
        assert_eq!(
            missing_required_claim_names(
                &requested.required,
                Some(&ClaimValues {
                    contact_email: Some("ada@example.com".to_owned()),
                    ..ClaimValues::default()
                })
            ),
            vec![ClaimName::ContactMobile]
        );
        assert!(evaluate_claim_support(None, []).can_satisfy_required);
    }
}
