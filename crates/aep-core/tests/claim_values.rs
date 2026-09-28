//! Claim-value syntax, exercised through the public parse and validate entry points.

use aep_core::*;

fn accepted(json: &str) -> bool {
    parse_claim_values(json.as_bytes()).is_ok_and(|values| validate_claim_values(&values).is_ok())
}

fn email(address: &str) -> String {
    format!(
        "{{\"contact.email\":{}}}",
        serde_json::to_string(address).expect("json")
    )
}

/// CLM-CAT-001 binds `contact.email` to the RFC 5321 Mailbox rule as the JSON Schema `email`
/// format references it, which is ASCII. A Unicode mailbox is the separate `idn-email` format.
#[test]
fn mailbox_is_ascii() {
    for address in [
        "owner@ex\u{e1}mple.com",
        "owner@ex\u{663}mple.com",
        "\u{f3}wner@example.com",
        "owner@\u{435}xample.com",
    ] {
        assert!(!accepted(&email(address)), "{address:?}");
    }
}

/// CLM-CAT-003 rejects empty strings, a missing `@`, consecutive dots in an unquoted local part,
/// and a domain label beginning with a hyphen; a quoted local part containing a space is valid,
/// and the minimum length is three.
#[test]
fn mailbox_shapes_the_specification_publishes() {
    for address in ["a@b", "\"quoted local\"@example.com", "owner@example.com"] {
        assert!(accepted(&email(address)), "{address:?}");
    }
    for address in [
        "",
        "owner.example.com",
        "owner..name@example.com",
        "owner@-example.com",
        "owner@example-.com",
        "owner@exa..mple.com",
        "@example.com",
        "owner@",
        "one@two@example.com",
    ] {
        assert!(!accepted(&email(address)), "{address:?}");
    }
}

#[test]
fn quoted_local_parts_follow_the_quoted_string_rule() {
    // A quoted local part admits space and the printable characters outside `"` and `\`, and
    // carries either of those when escaped.
    for address in [
        r#""with space"@example.com"#,
        r#""a"@example.com"#,
        r#""esc\"quote"@example.com"#,
        r#""esc\\slash"@example.com"#,
    ] {
        assert!(accepted(&email(address)), "{address:?}");
    }
    for address in [
        r#""unterminated@example.com"#,
        "\"bad\u{1}control\"@example.com",
        "\"esc\\\u{7f}\"@example.com",
        r#""quoted"example.com"#,
    ] {
        assert!(!accepted(&email(address)), "{address:?}");
    }
}

#[test]
fn address_literals_are_accepted_only_in_their_published_forms() {
    for address in [
        "owner@[192.0.2.1]",
        "owner@[IPv6:2001:db8::1]",
        "owner@[tag:literal]",
    ] {
        assert!(accepted(&email(address)), "{address:?}");
    }
    for address in [
        "owner@[not-an-address]",
        "owner@[IPv6:not-an-address]",
        "owner@[IPv6:192.0.2.1]",
        "owner@[:literal]",
        "owner@[tag:]",
        "owner@[tag-:literal]",
        "owner@[ta!g:literal]",
        "owner@[192.0.2.999]",
        "owner@[unclosed",
    ] {
        assert!(!accepted(&email(address)), "{address:?}");
    }
}

#[test]
fn mailbox_length_bounds() {
    let long_local = format!("{}@example.com", "a".repeat(65));
    let long_domain = format!("owner@{}.com", "a".repeat(256));
    let long_label = format!("owner@{}.com", "a".repeat(64));
    for address in [long_local, long_domain, long_label] {
        assert!(!accepted(&email(&address)), "{address:?}");
    }
}

/// `person.birthdate` is an RFC 3339 full-date, so a calendar-invalid day is refused.
#[test]
fn birthdate_is_a_calendar_date() {
    for value in ["1970-01-01", "2024-02-29"] {
        assert!(
            accepted(&format!("{{\"person.birthdate\":\"{value}\"}}")),
            "{value}"
        );
    }
    for value in [
        "2025-02-30",
        "2025-13-01",
        "2025-00-10",
        "2025-01-32",
        "2025-1-01",
        "20250101",
        "2025-01-01T00:00:00Z",
        "abcd-01-01",
        "2025-ab-01",
        "2025-01-ab",
    ] {
        assert!(
            !accepted(&format!("{{\"person.birthdate\":\"{value}\"}}")),
            "{value}"
        );
    }
}

#[test]
fn mobile_uses_e164_form() {
    assert!(accepted("{\"contact.mobile\":\"+14155550100\"}"));
    for value in ["(415) 555-0100", "+0155501", "14155550100", "+", "+1"] {
        assert!(
            !accepted(&format!("{{\"contact.mobile\":\"{value}\"}}")),
            "{value}"
        );
    }
}

/// The address object requires country, first_name, last_name and line1, uses a two-letter
/// uppercase country, and tolerates members it does not define.
#[test]
fn primary_address_shape() {
    let complete = r#"{"contact.address.primary":{"city":"San Francisco","country":"US",
        "delivery_instructions":"Reception desk","first_name":"Grace","last_name":"Hopper",
        "line1":"123 Market Street"}}"#;
    assert!(accepted(complete));
    for address in [
        r#"{"contact.address.primary":{"city":"San Francisco","first_name":"Grace",
            "last_name":"Hopper","line1":"123 Market Street"}}"#,
        r#"{"contact.address.primary":{"country":"us","first_name":"Grace",
            "last_name":"Hopper","line1":"123 Market Street"}}"#,
        r#"{"contact.address.primary":{"country":"USA","first_name":"Grace",
            "last_name":"Hopper","line1":"123 Market Street"}}"#,
        r#"{"contact.address.primary":{"country":"US","first_name":"","last_name":"Hopper",
            "line1":"123 Market Street"}}"#,
        r#"{"contact.address.primary":{"country":"US","first_name":"Grace","last_name":"Hopper",
            "line1":""}}"#,
    ] {
        assert!(!accepted(address), "{address}");
    }
}

#[test]
fn registered_string_claims_reject_the_wrong_json_type() {
    assert!(parse_claim_values(br#"{"person.first_name":42}"#).is_err());
    assert!(parse_claim_values(br#"{"contact.email":[]}"#).is_err());
    assert!(parse_claim_values(b"[]").is_err());
    assert!(parse_claim_values(b"not json").is_err());
}

#[test]
fn registered_person_claims_must_not_be_empty() {
    for name in ["person.first_name", "person.last_name", "person.username"] {
        assert!(!accepted(&format!("{{\"{name}\":\"\"}}")), "{name}");
        assert!(accepted(&format!("{{\"{name}\":\"value\"}}")), "{name}");
    }
}

/// Unknown claim names are carried for forward compatibility rather than refused.
#[test]
fn unknown_claim_names_are_tolerated() {
    assert!(accepted(r#"{"example.future.claim":"value"}"#));
    assert!(accepted("{}"));
}
