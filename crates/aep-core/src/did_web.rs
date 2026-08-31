use http::{HeaderMap, HeaderValue, Method};
use percent_encoding::percent_decode_str;
use serde::Deserialize;
use serde_json::Value;
use url::Url;

use crate::{ClientAssertionVerifyingKey, CoreError, HttpRequest, HttpTransport, SigningAlgorithm};

const MAX_DID_DOCUMENT_BYTES: usize = 1 << 20;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DidWebDocumentUrlOptions {
    pub allow_insecure_loopback: bool,
}

pub struct ResolveDidWebPublicKeyOptions<'a> {
    pub algorithm: SigningAlgorithm,
    pub allow_insecure_loopback: bool,
    pub did: &'a str,
    pub key_id: &'a str,
    pub transport: &'a dyn HttpTransport,
}

pub fn did_web_document_url(did: &str) -> Result<Url, CoreError> {
    did_web_document_url_with_options(did, DidWebDocumentUrlOptions::default())
}

pub fn did_web_document_url_with_options(
    did: &str,
    options: DidWebDocumentUrlOptions,
) -> Result<Url, CoreError> {
    let Some(identifier) = did.strip_prefix("did:web:") else {
        return Err(CoreError::Invalid(format!("unsupported DID method: {did}")));
    };
    let mut parts = identifier.split(':');
    let encoded_host = parts
        .next()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| CoreError::Invalid(format!("invalid did:web identifier: {did}")))?;
    let host = decode_component(encoded_host, "did:web host")?;
    let authority = Url::parse(&format!("https://{host}"))?;
    if authority.host_str().is_none()
        || !authority.username().is_empty()
        || authority.password().is_some()
        || authority.path() != "/"
        || authority.query().is_some()
        || authority.fragment().is_some()
    {
        return Err(CoreError::Invalid(format!("invalid did:web host: {host}")));
    }
    let scheme = if options.allow_insecure_loopback
        && authority
            .host_str()
            .is_some_and(crate::openapi::is_loopback_host)
    {
        "http"
    } else {
        "https"
    };
    let decoded_path = parts
        .map(|part| decode_component(part, "did:web path"))
        .collect::<Result<Vec<_>, _>>()?;
    let path = if decoded_path.is_empty() {
        "/.well-known/did.json".to_owned()
    } else {
        format!("/{}/did.json", decoded_path.join("/"))
    };
    Url::parse(&format!("{scheme}://{host}{path}")).map_err(CoreError::from)
}

pub async fn resolve_did_web_public_key(
    options: ResolveDidWebPublicKeyOptions<'_>,
) -> Result<ClientAssertionVerifyingKey, CoreError> {
    if options.key_id.is_empty() {
        return Err(CoreError::Invalid(
            "AEP did:web key ID is required".to_owned(),
        ));
    }
    let key_did = options
        .key_id
        .split_once('#')
        .map_or(options.key_id, |part| part.0);
    if key_did != options.did {
        return Err(CoreError::Invalid(
            "AEP did:web key ID does not identify the assertion issuer".to_owned(),
        ));
    }
    let document_url = did_web_document_url_with_options(
        options.did,
        DidWebDocumentUrlOptions {
            allow_insecure_loopback: options.allow_insecure_loopback,
        },
    )?;
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::ACCEPT,
        HeaderValue::from_static("application/did+json, application/json"),
    );
    let response = options
        .transport
        .send(HttpRequest {
            method: Method::GET,
            url: document_url.clone(),
            headers,
            body: Vec::new(),
        })
        .await?;
    if response.final_url != document_url {
        return Err(CoreError::Invalid(
            "did:web document redirects are not allowed".to_owned(),
        ));
    }
    if !response.status.is_success() {
        return Err(CoreError::Invalid(format!(
            "fetch did:web document: HTTP {}",
            response.status.as_u16()
        )));
    }
    if response.body.len() > MAX_DID_DOCUMENT_BYTES {
        return Err(CoreError::Invalid(
            "did:web document exceeds the 1 MiB limit".to_owned(),
        ));
    }
    let document = serde_json::from_slice::<DidDocument>(&response.body)?;
    let method = document
        .verification_method
        .into_iter()
        .find(|method| method.id == options.key_id)
        .ok_or_else(|| CoreError::Invalid(format!("no public JWK found for {}", options.key_id)))?;
    let key_value = method
        .public_key_jwk
        .ok_or_else(|| CoreError::Invalid(format!("no public JWK found for {}", options.key_id)))?;
    validate_jwk_metadata(&key_value, options.key_id, &options.algorithm)?;
    let key = serde_json::from_value::<jwt_compact::jwk::JsonWebKey<'static>>(key_value)?;
    ClientAssertionVerifyingKey::from_jwk(&key, &options.algorithm)
}

fn validate_jwk_metadata(
    value: &Value,
    expected_key_id: &str,
    expected_algorithm: &SigningAlgorithm,
) -> Result<(), CoreError> {
    let object = value.as_object().ok_or_else(|| {
        CoreError::Invalid("AEP did:web publicKeyJwk must be an object".to_owned())
    })?;
    if let Some(algorithm) = object.get("alg")
        && algorithm.as_str() != Some(expected_algorithm.as_str())
    {
        return Err(CoreError::Invalid(
            "AEP did:web publicKeyJwk alg does not match the assertion".to_owned(),
        ));
    }
    if let Some(key_id) = object.get("kid")
        && key_id.as_str() != Some(expected_key_id)
    {
        return Err(CoreError::Invalid(
            "AEP did:web publicKeyJwk kid does not match the verification method".to_owned(),
        ));
    }
    if object.get("d").is_some() {
        return Err(CoreError::Invalid(
            "AEP did:web publicKeyJwk must not expose private key material".to_owned(),
        ));
    }
    if let Some(key_use) = object.get("use")
        && key_use.as_str() != Some("sig")
    {
        return Err(CoreError::Invalid(
            "AEP did:web publicKeyJwk use must be sig".to_owned(),
        ));
    }
    if let Some(key_operations) = object.get("key_ops")
        && !key_operations
            .as_array()
            .is_some_and(|operations| operations.iter().any(|operation| operation == "verify"))
    {
        return Err(CoreError::Invalid(
            "AEP did:web publicKeyJwk key_ops must allow verify".to_owned(),
        ));
    }
    Ok(())
}

fn decode_component(value: &str, label: &str) -> Result<String, CoreError> {
    percent_decode_str(value)
        .decode_utf8()
        .map(String::from)
        .map_err(|error| CoreError::Invalid(format!("decode {label}: {error}")))
}

#[derive(Deserialize)]
struct DidDocument {
    #[serde(default, rename = "verificationMethod")]
    verification_method: Vec<VerificationMethod>,
}

#[derive(Deserialize)]
struct VerificationMethod {
    id: String,
    #[serde(rename = "publicKeyJwk")]
    public_key_jwk: Option<Value>,
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use futures::executor::block_on;
    use http::StatusCode;

    use super::*;

    struct StubTransport;

    struct RedirectTransport;

    #[async_trait]
    impl HttpTransport for StubTransport {
        async fn send(
            &self,
            request: HttpRequest,
        ) -> Result<crate::HttpResponse, crate::TransportError> {
            Ok(crate::HttpResponse {
                status: StatusCode::OK,
                final_url: request.url,
                headers: HeaderMap::new(),
                body: br#"{
                    "verificationMethod": [{
                        "id": "did:web:agent.example#key-1",
                        "publicKeyJwk": {
                            "alg": "EdDSA",
                            "crv": "Ed25519",
                            "kid": "did:web:agent.example#key-1",
                            "kty": "OKP",
                            "use": "sig",
                            "x": "2-Jj2UvNCvQiUPNYRgSi0cJSPiJI6Rs6D0UTeEpQVj8"
                        }
                    }]
                }"#
                .to_vec(),
            })
        }
    }

    #[async_trait]
    impl HttpTransport for RedirectTransport {
        async fn send(
            &self,
            mut request: HttpRequest,
        ) -> Result<crate::HttpResponse, crate::TransportError> {
            request.url.set_path("/redirected/did.json");
            Ok(crate::HttpResponse {
                status: StatusCode::OK,
                final_url: request.url,
                headers: HeaderMap::new(),
                body: br#"{"verificationMethod":[]}"#.to_vec(),
            })
        }
    }

    #[test]
    fn maps_root_and_path_dids() {
        assert_eq!(
            did_web_document_url("did:web:api.example.com")
                .expect("root DID")
                .as_str(),
            "https://api.example.com/.well-known/did.json"
        );
        assert_eq!(
            did_web_document_url("did:web:127.0.0.1%3A4100:agents:one")
                .expect("path DID")
                .as_str(),
            "https://127.0.0.1:4100/agents/one/did.json"
        );
    }

    #[test]
    fn resolves_the_selected_public_key() {
        let key = block_on(resolve_did_web_public_key(ResolveDidWebPublicKeyOptions {
            algorithm: SigningAlgorithm::EdDsa,
            allow_insecure_loopback: false,
            did: "did:web:agent.example",
            key_id: "did:web:agent.example#key-1",
            transport: &StubTransport,
        }))
        .expect("resolved key");
        assert_eq!(key.algorithm(), SigningAlgorithm::EdDsa);
    }

    #[test]
    fn rejects_invalid_identifiers_and_redirects() {
        assert!(did_web_document_url("did:key:one").is_err());
        assert!(did_web_document_url("did:web:").is_err());
        assert!(
            block_on(resolve_did_web_public_key(ResolveDidWebPublicKeyOptions {
                algorithm: SigningAlgorithm::EdDsa,
                allow_insecure_loopback: false,
                did: "did:web:agent.example",
                key_id: "did:web:other.example#key-1",
                transport: &StubTransport,
            },))
            .is_err()
        );
        assert!(
            block_on(resolve_did_web_public_key(ResolveDidWebPublicKeyOptions {
                algorithm: SigningAlgorithm::EdDsa,
                allow_insecure_loopback: false,
                did: "did:web:agent.example",
                key_id: "did:web:agent.example#key-1",
                transport: &RedirectTransport,
            },))
            .is_err()
        );
    }
}
