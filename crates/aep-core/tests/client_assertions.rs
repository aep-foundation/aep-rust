//! Client assertion signing and verification.

use aep_core::*;

const AGENT_DID: &str = "did:web:agent.example";
const SERVICE_DID: &str = "did:web:api.example.com";

fn signing_key() -> ClientAssertionSigningKey {
    ClientAssertionSigningKey::ed25519_from_seed([7u8; 32])
}

fn claims(operation: AssertionOperation, resource: Option<&str>) -> ClientAssertionClaims {
    ClientAssertionClaims {
        aud: SERVICE_DID.to_owned(),
        exp: 1_000_060,
        iat: 1_000_000,
        iss: AGENT_DID.to_owned(),
        jti: "assertion-1".to_owned(),
        op: operation,
        resource: resource.map(str::to_owned),
        sub: AGENT_DID.to_owned(),
        additional: Default::default(),
    }
}

fn sign(
    key: &ClientAssertionSigningKey,
    key_id: &str,
    value: &ClientAssertionClaims,
) -> Result<String, CoreError> {
    sign_client_assertion(
        value,
        SignClientAssertionOptions {
            allow_insecure_loopback: false,
            key,
            key_id,
        },
    )
}

fn verify(
    assertion: &str,
    key: &ClientAssertionVerifyingKey,
    options: VerifyClientAssertionOptions,
) -> Result<ClientAssertionClaims, CoreError> {
    verify_client_assertion(assertion, key, &options)
}

fn at(current_time: i64) -> VerifyClientAssertionOptions {
    VerifyClientAssertionOptions {
        current_time: Some(current_time),
        ..VerifyClientAssertionOptions::default()
    }
}

fn sign_raw_payload(payload: serde_json::Value, key_id: &str) -> String {
    use jwt_compact::{AlgorithmExt, Claims, Header, alg::Ed25519};

    let value: Claims<serde_json::Value> = serde_json::from_value(payload).expect("claims");
    Ed25519
        .token(
            &Header::empty().with_key_id(key_id).with_token_type("JWT"),
            &value,
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
        )
        .expect("signed assertion")
}

#[test]
fn round_trips_an_assertion() {
    let key = signing_key();
    let assertion =
        sign(&key, AGENT_DID, &claims(AssertionOperation::Enroll, None)).expect("signed");
    let verified = verify(&assertion, &key.verifying_key(), at(1_000_030)).expect("verified");
    assert_eq!(verified.iss, AGENT_DID);
    assert_eq!(verified.op, AssertionOperation::Enroll);
    assert_eq!(key.algorithm(), SigningAlgorithm::EdDsa);
    assert_eq!(key.verifying_key().algorithm(), SigningAlgorithm::EdDsa);
}

/// DWB-ID-003: the DID portion of `kid` must equal the Agent DID, with or without a fragment.
#[test]
fn key_id_binds_to_the_agent_did() {
    let key = signing_key();
    let value = claims(AssertionOperation::Enroll, None);
    assert!(sign(&key, &format!("{AGENT_DID}#key-1"), &value).is_ok());
    assert!(sign(&key, "did:web:other.example", &value).is_err());
    assert!(sign(&key, "", &value).is_err());
}

/// Signing refuses claims that do not validate, so an invalid assertion is never produced.
#[test]
fn signing_validates_the_claims_first() {
    let key = signing_key();
    let mut excessive = claims(AssertionOperation::Enroll, None);
    excessive.exp = excessive.iat + 301;
    assert!(sign(&key, AGENT_DID, &excessive).is_err());

    let mut unexpected_resource = claims(AssertionOperation::Enroll, None);
    unexpected_resource.resource = Some("https://api.example.com/orders".to_owned());
    assert!(sign(&key, AGENT_DID, &unexpected_resource).is_err());

    assert!(
        sign(
            &key,
            AGENT_DID,
            &claims(AssertionOperation::Authenticate, None)
        )
        .is_err()
    );
    assert!(
        sign(
            &key,
            AGENT_DID,
            &claims(
                AssertionOperation::Authenticate,
                Some("https://api.example.com/orders")
            )
        )
        .is_ok()
    );
}

/// The assertion is only valid inside its own time window, widened by the configured tolerance.
#[test]
fn verification_enforces_the_time_window() {
    let key = signing_key();
    let assertion =
        sign(&key, AGENT_DID, &claims(AssertionOperation::Enroll, None)).expect("signed");
    let verifying = key.verifying_key();
    // Pinned to zero tolerance so the boundaries are the claims' own, not the recommended skew.
    let exact = |current_time: i64| VerifyClientAssertionOptions {
        clock_tolerance_seconds: Some(0),
        current_time: Some(current_time),
        ..VerifyClientAssertionOptions::default()
    };
    assert!(verify(&assertion, &verifying, exact(999_999)).is_err());
    assert!(verify(&assertion, &verifying, exact(1_000_060)).is_err());
    assert!(verify(&assertion, &verifying, exact(1_000_000)).is_ok());
    assert!(verify(&assertion, &verifying, exact(1_000_059)).is_ok());
    // The recommended skew widens both ends for a clock that is a little behind or ahead.
    assert!(verify(&assertion, &verifying, at(999_999)).is_ok());
    assert!(
        verify(
            &assertion,
            &verifying,
            VerifyClientAssertionOptions {
                clock_tolerance_seconds: Some(30),
                ..at(1_000_080)
            }
        )
        .is_ok()
    );
}

/// Each expected claim the caller pins must match the assertion.
#[test]
fn verification_matches_the_expected_claims() {
    let key = signing_key();
    let assertion =
        sign(&key, AGENT_DID, &claims(AssertionOperation::Enroll, None)).expect("signed");
    let verifying = key.verifying_key();
    let expectations = [
        VerifyClientAssertionOptions {
            audience: Some("did:web:other.example".to_owned()),
            ..at(1_000_030)
        },
        VerifyClientAssertionOptions {
            issuer: Some("did:web:other.example".to_owned()),
            ..at(1_000_030)
        },
        VerifyClientAssertionOptions {
            subject: Some("did:web:other.example".to_owned()),
            ..at(1_000_030)
        },
        VerifyClientAssertionOptions {
            operation: Some(AssertionOperation::Status),
            ..at(1_000_030)
        },
        VerifyClientAssertionOptions {
            resource: Some("https://api.example.com/orders".to_owned()),
            ..at(1_000_030)
        },
    ];
    for options in expectations {
        assert!(verify(&assertion, &verifying, options).is_err());
    }
    assert!(
        verify(
            &assertion,
            &verifying,
            VerifyClientAssertionOptions {
                audience: Some(SERVICE_DID.to_owned()),
                issuer: Some(AGENT_DID.to_owned()),
                subject: Some(AGENT_DID.to_owned()),
                operation: Some(AssertionOperation::Enroll),
                ..at(1_000_030)
            }
        )
        .is_ok()
    );
}

/// Only the algorithms the caller allows may verify an assertion.
#[test]
fn verification_restricts_the_signing_algorithm() {
    let key = signing_key();
    let assertion =
        sign(&key, AGENT_DID, &claims(AssertionOperation::Enroll, None)).expect("signed");
    let verifying = key.verifying_key();
    assert!(
        verify(
            &assertion,
            &verifying,
            VerifyClientAssertionOptions {
                algorithms: vec![SigningAlgorithm::Es256],
                ..at(1_000_030)
            }
        )
        .is_err()
    );
    assert!(
        verify(
            &assertion,
            &verifying,
            VerifyClientAssertionOptions {
                algorithms: vec![SigningAlgorithm::EdDsa],
                ..at(1_000_030)
            }
        )
        .is_ok()
    );
}

/// A tampered or malformed assertion never verifies.
#[test]
fn verification_refuses_malformed_assertions() {
    let key = signing_key();
    let verifying = key.verifying_key();
    let assertion =
        sign(&key, AGENT_DID, &claims(AssertionOperation::Enroll, None)).expect("signed");
    let mut tampered = assertion.clone();
    tampered.pop();
    tampered.push(if assertion.ends_with('A') { 'B' } else { 'A' });
    for value in ["", "not.a.jwt", "a.b", &tampered] {
        assert!(
            verify(value, &verifying, at(1_000_030)).is_err(),
            "{value:?}"
        );
    }
}

/// The unverified decode exposes the header and claims without asserting the signature.
#[test]
fn unverified_decoding_exposes_the_header_and_claims() {
    let key = signing_key();
    let assertion =
        sign(&key, AGENT_DID, &claims(AssertionOperation::Enroll, None)).expect("signed");
    let decoded = decode_jwt_unverified(&assertion).expect("decoded");
    assert_eq!(decoded.payload["iss"], AGENT_DID);
    assert_eq!(decoded.header.token_type.as_deref(), Some("JWT"));
    assert_eq!(decoded.header.key_id.as_deref(), Some(AGENT_DID));
    assert_eq!(decoded.header.algorithm, SigningAlgorithm::EdDsa);
    for value in ["", "not-a-jwt", "a.b.c"] {
        assert!(decode_jwt_unverified(value).is_err(), "{value:?}");
    }
}

/// An ES256 key round-trips the same contract.
#[test]
fn es256_keys_round_trip() {
    let key = ClientAssertionSigningKey::es256_from_bytes(&[3u8; 32]).expect("key");
    assert_eq!(key.algorithm(), SigningAlgorithm::Es256);
    let assertion =
        sign(&key, AGENT_DID, &claims(AssertionOperation::Grant, None)).expect("signed");
    assert!(verify(&assertion, &key.verifying_key(), at(1_000_030)).is_ok());
}

#[test]
fn key_material_is_checked_when_it_is_loaded() {
    assert!(ClientAssertionSigningKey::es256_from_bytes(&[0u8; 8]).is_err());
    assert!(ClientAssertionSigningKey::ed25519_from_pkcs8_pem("not a pem").is_err());
    assert!(ClientAssertionSigningKey::es256_from_pkcs8_pem("not a pem").is_err());
    assert!(ClientAssertionVerifyingKey::ed25519_from_bytes(&[0u8; 8]).is_err());
    assert!(ClientAssertionVerifyingKey::es256_from_sec1_bytes(&[0u8; 8]).is_err());
}

/// The JOSE header is inspected before the signature is checked, so a token that is not a JWT or
/// that demands unimplemented processing is refused without the key being used at all.
#[test]
fn unusable_jose_headers_are_refused_before_verification() {
    let key = signing_key().verifying_key();
    // `{"alg":"EdDSA","kid":"did:web:agent.example#key-1","typ":"JOSE"}.{}` with a stub signature.
    let typ_jose = "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWI6YWdlbnQuZXhhbXBsZSNrZXktMSIsInR5cCI6IkpPU0UifQ.e30.AAAA";
    // The same header with `typ` of `JWT` and a `crit` member naming `b64`.
    let crit = "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImtpZCI6ImRpZDp3ZWI6YWdlbnQuZXhhbXBsZSNrZXktMSIsInR5cCI6IkpXVCJ9.e30.AAAA";
    let missing_key_id = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.e30.AAAA";
    for assertion in [typ_jose, crit, missing_key_id] {
        assert!(
            verify(assertion, &key, at(1_000_030)).is_err(),
            "{assertion}"
        );
    }
}

/// Verification re-validates the claims under its own options, so an assertion signed with a
/// development affordance enabled does not verify where that affordance is off.
#[test]
fn verification_revalidates_claims_under_its_own_options() {
    let key = signing_key();
    let mut value = claims(
        AssertionOperation::Authenticate,
        Some("http://127.0.0.1:8080/orders"),
    );
    value.jti = "assertion-loopback".to_owned();
    let assertion = sign_client_assertion(
        &value,
        SignClientAssertionOptions {
            allow_insecure_loopback: true,
            key: &key,
            key_id: AGENT_DID,
        },
    )
    .expect("signed");
    assert!(verify(&assertion, &key.verifying_key(), at(1_000_030)).is_err());
    assert!(
        verify(
            &assertion,
            &key.verifying_key(),
            VerifyClientAssertionOptions {
                allow_insecure_loopback: true,
                current_time: Some(1_000_030),
                ..VerifyClientAssertionOptions::default()
            },
        )
        .is_ok()
    );
}

#[test]
fn signed_assertions_reject_an_explicit_null_resource() {
    let assertion = sign_raw_payload(
        serde_json::json!({
            "aud": SERVICE_DID,
            "iat": 1_000_000,
            "exp": 1_000_060,
            "iss": AGENT_DID,
            "jti": "null-resource",
            "op": "enroll",
            "resource": null,
            "sub": AGENT_DID,
        }),
        AGENT_DID,
    );
    assert!(verify(&assertion, &signing_key().verifying_key(), at(1_000_030)).is_err());
}

#[test]
fn signed_assertions_require_both_time_claims() {
    let payload = serde_json::to_value(claims(AssertionOperation::Enroll, None)).expect("claims");
    for missing in ["iat", "exp"] {
        let mut invalid = payload.clone();
        invalid.as_object_mut().expect("object").remove(missing);
        let assertion = sign_raw_payload(invalid, AGENT_DID);
        assert!(verify(&assertion, &signing_key().verifying_key(), at(1_000_030)).is_err());
    }
}

#[test]
fn verification_binds_a_valid_signature_to_the_header_key_identifier() {
    let payload = serde_json::to_value(claims(AssertionOperation::Enroll, None)).expect("claims");
    let assertion = sign_raw_payload(payload, "did:web:other.example#key-1");
    assert!(verify(&assertion, &signing_key().verifying_key(), at(1_000_030)).is_err());
}

#[test]
fn es256_verification_refuses_a_signature_from_another_key() {
    let key = ClientAssertionSigningKey::es256_from_bytes(&[3; 32]).expect("key");
    let other = ClientAssertionSigningKey::es256_from_bytes(&[4; 32]).expect("other key");
    let assertion =
        sign(&key, AGENT_DID, &claims(AssertionOperation::Enroll, None)).expect("signed assertion");
    assert!(verify(&assertion, &other.verifying_key(), at(1_000_030)).is_err());
}

#[test]
fn timestamp_and_tolerance_conversion_fail_without_panicking() {
    let key = signing_key();
    let mut value = claims(AssertionOperation::Enroll, None);
    value.iat = i64::MAX - 60;
    value.exp = i64::MAX;
    assert!(sign(&key, AGENT_DID, &value).is_err());

    let assertion =
        sign(&key, AGENT_DID, &claims(AssertionOperation::Enroll, None)).expect("signed assertion");
    let options = VerifyClientAssertionOptions {
        clock_tolerance_seconds: Some(u64::MAX),
        ..at(1_000_030)
    };
    assert!(verify(&assertion, &key.verifying_key(), options).is_err());
}

#[test]
fn verification_honors_an_optional_not_before_claim() {
    let key = signing_key();
    let mut value = claims(AssertionOperation::Enroll, None);
    value.additional.insert("nbf".to_owned(), 1_000_050.into());
    let assertion = sign(&key, AGENT_DID, &value).expect("signed assertion");
    let exact = |current_time| VerifyClientAssertionOptions {
        clock_tolerance_seconds: Some(0),
        ..at(current_time)
    };
    assert!(verify(&assertion, &key.verifying_key(), exact(1_000_030)).is_err());
    assert!(verify(&assertion, &key.verifying_key(), exact(1_000_050)).is_ok());
    assert!(verify(&assertion, &key.verifying_key(), at(1_000_030)).is_ok());
}

/// With no current time supplied the wall clock is read, so an assertion minted for 1970 is long
/// expired and one minted for now is inside its window.
#[test]
fn the_wall_clock_is_used_when_no_current_time_is_supplied() {
    let key = signing_key();
    let assertion =
        sign(&key, AGENT_DID, &claims(AssertionOperation::Enroll, None)).expect("signed");
    assert!(
        verify(
            &assertion,
            &key.verifying_key(),
            VerifyClientAssertionOptions::default()
        )
        .is_err()
    );

    let now = i64::try_from(
        std::time::SystemTime::UNIX_EPOCH
            .elapsed()
            .expect("clock")
            .as_secs(),
    )
    .expect("timestamp");
    let mut value = claims(AssertionOperation::Enroll, None);
    value.iat = now;
    value.exp = now + 60;
    let assertion = sign(&key, AGENT_DID, &value).expect("signed");
    assert!(
        verify(
            &assertion,
            &key.verifying_key(),
            VerifyClientAssertionOptions::default()
        )
        .is_ok()
    );
}
