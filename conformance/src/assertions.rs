use std::collections::BTreeMap;

use aep_core::{
    AssertionOperation, ClientAssertionClaims, ClientAssertionSigningKey,
    SignClientAssertionOptions, SigningAlgorithm, VerifyClientAssertionOptions,
    decode_jwt_unverified, sign_client_assertion, verify_client_assertion,
};
use jwt_compact::{AlgorithmExt as _, Claims, Header, alg::Es256};
use serde_json::{Value, json};

use crate::{AdapterRequest, expected, input};

// Invalid assertions must be signed without the SDK's signing-time validation.
pub fn sign_raw(payload: Value, key_id: Option<&str>, token_type: &str) -> Result<String, String> {
    let claims: Claims<Value> =
        serde_json::from_value(payload).map_err(|error| error.to_string())?;
    let mut header = Header::empty().with_token_type(token_type);
    header.key_id = key_id.map(str::to_owned);
    let key = p256::ecdsa::SigningKey::from_slice(&[13; 32]).map_err(|error| error.to_string())?;
    Es256
        .token(&header, &claims, &key)
        .map_err(|error| error.to_string())
}

pub fn validation(request: &AdapterRequest) -> Result<bool, String> {
    let agent_did: String = input(request, "agent_did")?;
    let claims = ClientAssertionClaims {
        additional: BTreeMap::new(),
        aud: input(request, "service_did")?,
        exp: input(request, "expires_at")?,
        iat: input(request, "issued_at")?,
        iss: agent_did.clone(),
        jti: input(request, "jti")?,
        op: AssertionOperation::Enroll,
        resource: None,
        sub: agent_did.clone(),
    };
    let algorithm: SigningAlgorithm = input(request, "algorithm")?;
    let key = ClientAssertionSigningKey::es256_from_bytes(&[13; 32])
        .map_err(|error| error.to_string())?;
    if algorithm != key.algorithm() {
        return Ok(false);
    }
    let token = sign_client_assertion(
        &claims,
        SignClientAssertionOptions {
            allow_insecure_loopback: false,
            key: &key,
            key_id: &agent_did,
        },
    )
    .map_err(|error| error.to_string())?;
    let decoded = decode_jwt_unverified(&token).map_err(|error| error.to_string())?;
    let header: Value = expected(request, "header")?;
    if serde_json::to_value(&decoded.payload).map_err(|error| error.to_string())?
        != expected::<Value>(request, "claims")?
        || header
            != json!({"alg":algorithm, "kid":decoded.header.key_id, "typ":decoded.header.token_type})
    {
        return Ok(false);
    }
    let options = VerifyClientAssertionOptions {
        algorithms: vec![algorithm],
        audience: Some(claims.aud.clone()),
        current_time: Some(claims.iat),
        issuer: Some(agent_did.clone()),
        subject: Some(agent_did.clone()),
        operation: Some(AssertionOperation::Enroll),
        ..Default::default()
    };
    let public = key.verifying_key();
    if verify_client_assertion(&token, &public, &options).map_err(|error| error.to_string())?
        != claims
    {
        return Ok(false);
    }
    let cases: Vec<String> = expected(request, "reject")?;
    for case in cases {
        let mut payload = serde_json::to_value(&claims).map_err(|error| error.to_string())?;
        let mut kid = Some(agent_did.as_str());
        let mut typ = "JWT";
        let mut validation = options.clone();
        match case.as_str() {
            "excessive_lifetime" => payload["exp"] = json!(claims.iat + 301),
            "nonpositive_lifetime" => payload["exp"] = json!(claims.iat),
            "mismatched_subject" => payload["sub"] = json!("did:web:other.example"),
            "unexpected_resource" => payload["resource"] = json!("https://api.example.com/orders"),
            "mismatched_kid" => kid = Some("did:web:other.example#key-1"),
            "missing_kid" => kid = None,
            "wrong_typ" => typ = "application/aep",
            "fragmented_resource" | "insecure_resource" | "missing_resource" => {
                payload["op"] = json!("authenticate");
                validation.operation = Some(AssertionOperation::Authenticate);
                if case != "missing_resource" {
                    payload["resource"] = json!(if case == "fragmented_resource" {
                        "https://api.example.com/orders#item"
                    } else {
                        "http://api.example.com/orders"
                    });
                }
            }
            other => return Err(format!("unhandled assertion rejection {other}")),
        }
        let invalid = sign_raw(payload.clone(), kid, typ)?;
        if verify_client_assertion(&invalid, &public, &validation).is_ok() {
            return Ok(false);
        }
        if let Ok(invalid_claims) = serde_json::from_value::<ClientAssertionClaims>(payload)
            && case != "wrong_typ"
            && sign_client_assertion(
                &invalid_claims,
                SignClientAssertionOptions {
                    allow_insecure_loopback: false,
                    key: &key,
                    key_id: kid.unwrap_or_default(),
                },
            )
            .is_ok()
        {
            return Ok(false);
        }
    }
    Ok(true)
}
