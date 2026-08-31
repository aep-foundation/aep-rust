use std::{collections::BTreeMap, time::SystemTime};

use chrono::{DateTime, Utc};
use ed25519_dalek::pkcs8::DecodePrivateKey as _;
use jwt_compact::{
    AlgorithmExt, Claims, Header, UntrustedToken,
    alg::{Ed25519, Es256},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    AdditionalMembers, AssertionOperation, ClientAssertionClaims, ClientAssertionValidationOptions,
    CoreError, RECOMMENDED_CLOCK_SKEW, SigningAlgorithm,
    validate_client_assertion_claims_with_options,
};

#[derive(Clone)]
pub struct ClientAssertionSigningKey(SigningKeyInner);

#[derive(Clone)]
enum SigningKeyInner {
    Ed25519(ed25519_dalek::SigningKey),
    Es256(p256::ecdsa::SigningKey),
}

impl ClientAssertionSigningKey {
    pub fn ed25519_from_seed(seed: [u8; 32]) -> Self {
        Self(SigningKeyInner::Ed25519(
            ed25519_dalek::SigningKey::from_bytes(&seed),
        ))
    }

    pub fn ed25519_from_pkcs8_pem(pem: &str) -> Result<Self, CoreError> {
        ed25519_dalek::SigningKey::from_pkcs8_pem(pem)
            .map(|key| Self(SigningKeyInner::Ed25519(key)))
            .map_err(jwt_error)
    }

    pub fn es256_from_bytes(bytes: &[u8]) -> Result<Self, CoreError> {
        p256::ecdsa::SigningKey::from_slice(bytes)
            .map(|key| Self(SigningKeyInner::Es256(key)))
            .map_err(jwt_error)
    }

    pub fn es256_from_pkcs8_pem(pem: &str) -> Result<Self, CoreError> {
        p256::ecdsa::SigningKey::from_pkcs8_pem(pem)
            .map(|key| Self(SigningKeyInner::Es256(key)))
            .map_err(jwt_error)
    }

    pub fn algorithm(&self) -> SigningAlgorithm {
        match self.0 {
            SigningKeyInner::Ed25519(_) => SigningAlgorithm::EdDsa,
            SigningKeyInner::Es256(_) => SigningAlgorithm::Es256,
        }
    }

    pub fn verifying_key(&self) -> ClientAssertionVerifyingKey {
        match &self.0 {
            SigningKeyInner::Ed25519(key) => {
                ClientAssertionVerifyingKey(VerifyingKeyInner::Ed25519(key.verifying_key()))
            }
            SigningKeyInner::Es256(key) => {
                ClientAssertionVerifyingKey(VerifyingKeyInner::Es256(*key.verifying_key()))
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientAssertionVerifyingKey(VerifyingKeyInner);

#[derive(Clone, Debug, Eq, PartialEq)]
enum VerifyingKeyInner {
    Ed25519(ed25519_dalek::VerifyingKey),
    Es256(p256::ecdsa::VerifyingKey),
}

impl ClientAssertionVerifyingKey {
    pub fn ed25519_from_bytes(bytes: &[u8]) -> Result<Self, CoreError> {
        let bytes = <&[u8; 32]>::try_from(bytes)
            .map_err(|_| CoreError::Jwt("Ed25519 public key must contain 32 bytes".to_owned()))?;
        ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map(|key| Self(VerifyingKeyInner::Ed25519(key)))
            .map_err(jwt_error)
    }

    pub fn es256_from_sec1_bytes(bytes: &[u8]) -> Result<Self, CoreError> {
        p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
            .map(|key| Self(VerifyingKeyInner::Es256(key)))
            .map_err(jwt_error)
    }

    pub fn algorithm(&self) -> SigningAlgorithm {
        match self.0 {
            VerifyingKeyInner::Ed25519(_) => SigningAlgorithm::EdDsa,
            VerifyingKeyInner::Es256(_) => SigningAlgorithm::Es256,
        }
    }

    pub(crate) fn from_jwk(
        jwk: &jwt_compact::jwk::JsonWebKey<'_>,
        algorithm: &SigningAlgorithm,
    ) -> Result<Self, CoreError> {
        match algorithm {
            SigningAlgorithm::EdDsa => ed25519_dalek::VerifyingKey::try_from(jwk)
                .map(|key| Self(VerifyingKeyInner::Ed25519(key)))
                .map_err(jwt_error),
            SigningAlgorithm::Es256 => p256::ecdsa::VerifyingKey::try_from(jwk)
                .map(|key| Self(VerifyingKeyInner::Es256(key)))
                .map_err(jwt_error),
            SigningAlgorithm::Other(value) => Err(CoreError::Invalid(format!(
                "unsupported AEP signing algorithm {value:?}"
            ))),
        }
    }
}

pub struct SignClientAssertionOptions<'a> {
    pub allow_insecure_loopback: bool,
    pub key: &'a ClientAssertionSigningKey,
    pub key_id: &'a str,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VerifyClientAssertionOptions {
    pub algorithms: Vec<SigningAlgorithm>,
    pub allow_insecure_loopback: bool,
    pub audience: Option<String>,
    pub clock_tolerance_seconds: Option<u64>,
    pub current_time: Option<i64>,
    pub issuer: Option<String>,
    pub operation: Option<AssertionOperation>,
    pub resource: Option<String>,
    pub subject: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct JwtHeader {
    pub algorithm: SigningAlgorithm,
    pub key_id: Option<String>,
    pub token_type: Option<String>,
    pub additional: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DecodedJwt {
    pub header: JwtHeader,
    pub payload: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AssertionCustomClaims {
    aud: String,
    iss: String,
    jti: String,
    op: AssertionOperation,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource: Option<String>,
    sub: String,
    #[serde(flatten)]
    additional: AdditionalMembers,
}

pub fn sign_client_assertion(
    claims: &ClientAssertionClaims,
    options: SignClientAssertionOptions<'_>,
) -> Result<String, CoreError> {
    validate_client_assertion_claims_with_options(
        claims,
        ClientAssertionValidationOptions {
            allow_insecure_loopback: options.allow_insecure_loopback,
        },
    )?;
    validate_assertion_key_id(options.key_id, claims)?;
    let claims = to_compact_claims(claims)?;
    let header = Header::empty()
        .with_key_id(options.key_id)
        .with_token_type("JWT");
    match &options.key.0 {
        SigningKeyInner::Ed25519(key) => Ed25519.token(&header, &claims, key).map_err(jwt_error),
        SigningKeyInner::Es256(key) => Es256.token(&header, &claims, key).map_err(jwt_error),
    }
}

pub fn verify_client_assertion(
    assertion: &str,
    key: &ClientAssertionVerifyingKey,
    options: &VerifyClientAssertionOptions,
) -> Result<ClientAssertionClaims, CoreError> {
    let token =
        UntrustedToken::<BTreeMap<String, Value>>::try_from(assertion).map_err(jwt_error)?;
    if token.header().token_type.as_deref() != Some("JWT") {
        return Err(CoreError::Invalid(
            "AEP client assertion typ must be JWT".to_owned(),
        ));
    }
    if token.header().other_fields.contains_key("crit") {
        return Err(CoreError::Invalid(
            "AEP client assertion contains unsupported critical JOSE parameters".to_owned(),
        ));
    }
    let key_id = token
        .header()
        .key_id
        .as_deref()
        .ok_or_else(|| CoreError::Invalid("AEP client assertion kid is required".to_owned()))?;
    let algorithm = SigningAlgorithm::from(token.algorithm());
    validate_allowed_algorithm(&algorithm, key, options)?;
    let token = match &key.0 {
        VerifyingKeyInner::Ed25519(key) => Ed25519
            .validator::<AssertionCustomClaims>(key)
            .validate(&token)
            .map_err(jwt_error)?,
        VerifyingKeyInner::Es256(key) => Es256
            .validator::<AssertionCustomClaims>(key)
            .validate(&token)
            .map_err(jwt_error)?,
    };
    let claims = from_compact_claims(token.claims())?;
    validate_client_assertion_claims_with_options(
        &claims,
        ClientAssertionValidationOptions {
            allow_insecure_loopback: options.allow_insecure_loopback,
        },
    )?;
    validate_assertion_key_id(key_id, &claims)?;
    validate_expected_claims(&claims, options)?;
    Ok(claims)
}

pub fn decode_jwt_unverified(assertion: &str) -> Result<DecodedJwt, CoreError> {
    let token =
        UntrustedToken::<BTreeMap<String, Value>>::try_from(assertion).map_err(jwt_error)?;
    let claims = token
        .deserialize_claims_unchecked::<BTreeMap<String, Value>>()
        .map_err(jwt_error)?;
    let payload = serde_json::to_value(claims)?
        .as_object()
        .cloned()
        .ok_or_else(|| CoreError::Jwt("JWT claims must be a JSON object".to_owned()))?
        .into_iter()
        .collect();
    Ok(DecodedJwt {
        header: JwtHeader {
            algorithm: SigningAlgorithm::from(token.algorithm()),
            key_id: token.header().key_id.clone(),
            token_type: token.header().token_type.clone(),
            additional: token.header().other_fields.clone(),
        },
        payload,
    })
}

fn to_compact_claims(
    claims: &ClientAssertionClaims,
) -> Result<Claims<AssertionCustomClaims>, CoreError> {
    let mut compact = Claims::new(AssertionCustomClaims {
        aud: claims.aud.clone(),
        iss: claims.iss.clone(),
        jti: claims.jti.clone(),
        op: claims.op,
        resource: claims.resource.clone(),
        sub: claims.sub.clone(),
        additional: claims.additional.clone(),
    });
    compact.expiration = Some(timestamp(claims.exp)?);
    compact.issued_at = Some(timestamp(claims.iat)?);
    Ok(compact)
}

fn from_compact_claims(
    claims: &Claims<AssertionCustomClaims>,
) -> Result<ClientAssertionClaims, CoreError> {
    Ok(ClientAssertionClaims {
        aud: claims.custom.aud.clone(),
        exp: claims
            .expiration
            .ok_or_else(|| CoreError::Invalid("AEP client assertion exp is required".to_owned()))?
            .timestamp(),
        iat: claims
            .issued_at
            .ok_or_else(|| CoreError::Invalid("AEP client assertion iat is required".to_owned()))?
            .timestamp(),
        iss: claims.custom.iss.clone(),
        jti: claims.custom.jti.clone(),
        op: claims.custom.op,
        resource: claims.custom.resource.clone(),
        sub: claims.custom.sub.clone(),
        additional: claims.custom.additional.clone(),
    })
}

fn timestamp(value: i64) -> Result<DateTime<Utc>, CoreError> {
    DateTime::from_timestamp(value, 0)
        .ok_or_else(|| CoreError::Invalid("AEP client assertion timestamp is invalid".to_owned()))
}

fn validate_allowed_algorithm(
    algorithm: &SigningAlgorithm,
    key: &ClientAssertionVerifyingKey,
    options: &VerifyClientAssertionOptions,
) -> Result<(), CoreError> {
    if algorithm != &key.algorithm() {
        return Err(CoreError::Invalid(
            "AEP client assertion signing key does not match alg".to_owned(),
        ));
    }
    let allowed = if options.algorithms.is_empty() {
        matches!(algorithm, SigningAlgorithm::EdDsa | SigningAlgorithm::Es256)
    } else {
        options.algorithms.contains(algorithm)
    };
    if !allowed {
        return Err(CoreError::Invalid(
            "AEP client assertion signing algorithm is not allowed".to_owned(),
        ));
    }
    Ok(())
}

fn validate_expected_claims(
    claims: &ClientAssertionClaims,
    options: &VerifyClientAssertionOptions,
) -> Result<(), CoreError> {
    for (actual, expected, message) in [
        (&claims.aud, options.audience.as_ref(), "audience"),
        (&claims.iss, options.issuer.as_ref(), "issuer"),
        (&claims.sub, options.subject.as_ref(), "subject"),
    ] {
        if expected.is_some_and(|expected| actual != expected) {
            return Err(CoreError::Invalid(format!(
                "AEP client assertion {message} does not match"
            )));
        }
    }
    if options
        .operation
        .is_some_and(|operation| claims.op != operation)
    {
        return Err(CoreError::Invalid(
            "AEP client assertion operation does not match".to_owned(),
        ));
    }
    if options
        .resource
        .as_ref()
        .is_some_and(|resource| claims.resource.as_ref() != Some(resource))
    {
        return Err(CoreError::Invalid(
            "AEP client assertion resource does not match".to_owned(),
        ));
    }
    let now = options.current_time.unwrap_or_else(current_timestamp);
    let tolerance = options
        .clock_tolerance_seconds
        .unwrap_or(RECOMMENDED_CLOCK_SKEW.as_secs());
    let tolerance = i64::try_from(tolerance)
        .map_err(|_| CoreError::Invalid("clock tolerance is too large".to_owned()))?;
    if claims.iat > now.saturating_add(tolerance) || claims.exp < now.saturating_sub(tolerance) {
        return Err(CoreError::Invalid(
            "AEP client assertion is outside its validity window".to_owned(),
        ));
    }
    Ok(())
}

fn current_timestamp() -> i64 {
    SystemTime::UNIX_EPOCH
        .elapsed()
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or(i64::MAX)
}

fn validate_assertion_key_id(
    key_id: &str,
    claims: &ClientAssertionClaims,
) -> Result<(), CoreError> {
    if key_id.is_empty() {
        return Err(CoreError::Invalid(
            "AEP client assertion kid is required".to_owned(),
        ));
    }
    let key_did = key_id.split_once('#').map_or(key_id, |part| part.0);
    if key_did != claims.iss || key_did != claims.sub {
        return Err(CoreError::Invalid(
            "AEP client assertion kid must identify the Agent DID".to_owned(),
        ));
    }
    Ok(())
}

fn jwt_error(error: impl std::fmt::Display) -> CoreError {
    CoreError::Jwt(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(operation: AssertionOperation, jti: &str) -> ClientAssertionClaims {
        ClientAssertionClaims {
            aud: "did:web:service.example".to_owned(),
            exp: 1_748_428_860,
            iat: 1_748_428_800,
            iss: "did:web:agent.example".to_owned(),
            jti: jti.to_owned(),
            op: operation,
            resource: None,
            sub: "did:web:agent.example".to_owned(),
            additional: Default::default(),
        }
    }

    #[test]
    fn rejects_an_invalid_unverified_token() {
        assert!(decode_jwt_unverified("not-a-jwt").is_err());
    }

    #[test]
    fn imports_supported_key_encodings() {
        let ed25519_pem = r#"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f
-----END PRIVATE KEY-----"#;
        let ed25519 = ClientAssertionSigningKey::ed25519_from_pkcs8_pem(ed25519_pem)
            .expect("Ed25519 signing key");
        assert_eq!(ed25519.algorithm(), SigningAlgorithm::EdDsa);
        let ed25519_verifying = ed25519.verifying_key();
        let VerifyingKeyInner::Ed25519(ed25519_bytes) = &ed25519_verifying.0 else {
            panic!("expected Ed25519 key");
        };
        ClientAssertionVerifyingKey::ed25519_from_bytes(ed25519_bytes.as_bytes())
            .expect("Ed25519 verifying key");

        let es256_pem = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg8AF0ffHVA9WPTRaT
3ITlDvQ3VHQLX/xwgR6esnFXphKhRANCAAT6SMwbSLTZ9wPLUy5ilCP1HgjJ/xbS
HMacx3g7kP+jGzNEdPXNVpmcqyQxe3Ffb2VWVcxnWIu7fR1d/Il52p9E
-----END PRIVATE KEY-----"#;
        let es256 =
            ClientAssertionSigningKey::es256_from_pkcs8_pem(es256_pem).expect("ES256 signing key");
        assert_eq!(es256.algorithm(), SigningAlgorithm::Es256);
        let es256_verifying = es256.verifying_key();
        let VerifyingKeyInner::Es256(es256_key) = &es256_verifying.0 else {
            panic!("expected ES256 key");
        };
        let point = es256_key.to_encoded_point(false);
        ClientAssertionVerifyingKey::es256_from_sec1_bytes(point.as_bytes())
            .expect("ES256 verifying key");
    }

    #[test]
    fn signs_and_verifies_an_eddsa_assertion() {
        let signing_key = ClientAssertionSigningKey::ed25519_from_seed([7; 32]);
        let verifying_key = signing_key.verifying_key();
        let claims = claims(AssertionOperation::Status, "jti-1");
        let assertion = sign_client_assertion(
            &claims,
            SignClientAssertionOptions {
                allow_insecure_loopback: false,
                key: &signing_key,
                key_id: "did:web:agent.example#key-1",
            },
        )
        .expect("signed assertion");
        let verified = verify_client_assertion(
            &assertion,
            &verifying_key,
            &VerifyClientAssertionOptions {
                audience: Some(claims.aud.clone()),
                current_time: Some(1_748_428_830),
                operation: Some(AssertionOperation::Status),
                ..VerifyClientAssertionOptions::default()
            },
        )
        .expect("verified assertion");
        assert_eq!(verified.jti, "jti-1");
        assert!(
            verify_client_assertion(
                &assertion,
                &verifying_key,
                &VerifyClientAssertionOptions {
                    audience: Some("did:web:other.example".to_owned()),
                    current_time: Some(1_748_428_830),
                    ..VerifyClientAssertionOptions::default()
                },
            )
            .is_err()
        );
        let decoded = decode_jwt_unverified(&assertion).expect("decoded assertion");
        assert_eq!(
            decoded.header.key_id.as_deref(),
            Some("did:web:agent.example#key-1")
        );
        assert_eq!(decoded.payload.get("jti"), Some(&Value::from("jti-1")));
    }

    #[test]
    fn signs_and_verifies_an_es256_assertion() {
        let signing_key =
            ClientAssertionSigningKey::es256_from_bytes(&[3; 32]).expect("signing key");
        let verifying_key = signing_key.verifying_key();
        let claims = claims(AssertionOperation::Grant, "jti-2");
        let assertion = sign_client_assertion(
            &claims,
            SignClientAssertionOptions {
                allow_insecure_loopback: false,
                key: &signing_key,
                key_id: "did:web:agent.example#key-2",
            },
        )
        .expect("signed assertion");
        let verified = verify_client_assertion(
            &assertion,
            &verifying_key,
            &VerifyClientAssertionOptions {
                algorithms: vec![SigningAlgorithm::Es256],
                current_time: Some(1_748_428_830),
                ..VerifyClientAssertionOptions::default()
            },
        )
        .expect("verified assertion");
        assert_eq!(verified.jti, "jti-2");
    }

    #[test]
    fn rejects_a_mismatched_algorithm_and_key() {
        let ed25519 = ClientAssertionSigningKey::ed25519_from_seed([7; 32]);
        let es256 = ClientAssertionSigningKey::es256_from_bytes(&[3; 32])
            .expect("ES256 signing key")
            .verifying_key();
        let assertion = sign_client_assertion(
            &claims(AssertionOperation::Status, "jti-3"),
            SignClientAssertionOptions {
                allow_insecure_loopback: false,
                key: &ed25519,
                key_id: "did:web:agent.example#key-1",
            },
        )
        .expect("signed assertion");
        assert!(
            verify_client_assertion(
                &assertion,
                &es256,
                &VerifyClientAssertionOptions {
                    current_time: Some(1_748_428_830),
                    ..VerifyClientAssertionOptions::default()
                },
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_invalid_signing_inputs() {
        let key = ClientAssertionSigningKey::ed25519_from_seed([7; 32]);
        let claims = claims(AssertionOperation::Status, "jti");
        assert!(
            sign_client_assertion(
                &claims,
                SignClientAssertionOptions {
                    allow_insecure_loopback: false,
                    key: &key,
                    key_id: "did:web:other.example#key-1",
                },
            )
            .is_err()
        );
    }
}
