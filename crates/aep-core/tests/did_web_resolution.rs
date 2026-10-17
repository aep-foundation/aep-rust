//! did:web resolution, exercised against a stub transport.

use aep_core::*;
use async_trait::async_trait;
use futures::executor::block_on;
use http::{HeaderMap, StatusCode};
use url::Url;

const AGENT_DID: &str = "did:web:agent.example";
const KEY_ID: &str = "did:web:agent.example#key-1";

/// A transport that answers every request with one canned document.
struct Canned {
    body: Vec<u8>,
    status: StatusCode,
    redirect: bool,
    failure: bool,
}

impl Canned {
    fn document(body: &str) -> Self {
        Self {
            body: body.as_bytes().to_vec(),
            status: StatusCode::OK,
            redirect: false,
            failure: false,
        }
    }
}

#[async_trait]
impl HttpTransport for Canned {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        if self.failure {
            return Err(TransportError::new("DID document unavailable"));
        }
        let final_url = if self.redirect {
            Url::parse("https://elsewhere.example/.well-known/did.json").expect("url")
        } else {
            request.url
        };
        Ok(HttpResponse {
            status: self.status,
            final_url,
            headers: HeaderMap::new(),
            body: self.body.clone(),
        })
    }
}

fn verification_method(jwk: &str) -> String {
    format!(
        r#"{{"id":"{AGENT_DID}","verificationMethod":[{{"id":"{KEY_ID}","publicKeyJwk":{jwk}}}]}}"#
    )
}

#[test]
fn the_document_must_identify_the_requested_did() {
    let valid = verification_method(&ed25519(""));
    for body in [
        valid.replace(&format!(r#""id":"{AGENT_DID}","#), ""),
        valid.replace(
            &format!(r#""id":"{AGENT_DID}""#),
            r#""id":"did:web:other.example""#,
        ),
        valid.replace(&format!(r#""id":"{AGENT_DID}""#), r#""id":null"#),
    ] {
        assert!(resolve(&Canned::document(&body), KEY_ID).is_err(), "{body}");
    }
    assert!(resolve(&Canned::document(&valid), KEY_ID).is_ok());
}

#[test]
fn encoded_path_segments_are_not_decoded_twice() {
    for segment in ["%252e%252e", "%252E", "one%3Atwo", "one%25two"] {
        let did = format!("did:web:example.com:agents:{segment}:key");
        assert_eq!(
            did_web_document_url(&did).expect("document URL").as_str(),
            format!("https://example.com/agents/{segment}/key/did.json")
        );
    }
}

#[test]
fn malformed_percent_escapes_are_not_did_components() {
    for segment in ["%", "%2", "%GG", "one%two", "%FF"] {
        let did = format!("did:web:example.com:agents:{segment}");
        assert!(did_web_document_url(&did).is_err(), "{did}");
    }
}

fn ed25519(extra: &str) -> String {
    format!(
        r#"{{"crv":"Ed25519","kty":"OKP","x":"2-Jj2UvNCvQiUPNYRgSi0cJSPiJI6Rs6D0UTeEpQVj8"{extra}}}"#
    )
}

fn resolve(
    transport: &dyn HttpTransport,
    key_id: &str,
) -> Result<ClientAssertionVerifyingKey, CoreError> {
    block_on(resolve_did_web_public_key(ResolveDidWebPublicKeyOptions {
        algorithm: SigningAlgorithm::EdDsa,
        allow_insecure_loopback: false,
        did: AGENT_DID,
        key_id,
        transport,
    }))
}

#[test]
fn resolves_the_referenced_verification_method() {
    let transport = Canned::document(&verification_method(&ed25519(
        r#","alg":"EdDSA","kid":"did:web:agent.example#key-1","use":"sig","key_ops":["verify"]"#,
    )));
    assert!(resolve(&transport, KEY_ID).is_ok());
}

/// DWB-ID-003: the DID portion of `kid` must equal the Agent DID.
#[test]
fn key_id_must_identify_the_issuer() {
    let transport = Canned::document(&verification_method(&ed25519("")));
    assert!(resolve(&transport, "did:web:other.example#key-1").is_err());
    assert!(resolve(&transport, "").is_err());
}

/// DWB-RES-003 and DWB-RES-006: the document must carry the verification method `kid` names.
#[test]
fn missing_verification_material_is_refused() {
    for body in [
        format!(r#"{{"id":"{AGENT_DID}","verificationMethod":[]}}"#),
        format!(r#"{{"id":"{AGENT_DID}"}}"#),
        format!(r#"{{"id":"{AGENT_DID}","verificationMethod":[{{"id":"{KEY_ID}"}}]}}"#),
        format!(r#"{{"id":"{AGENT_DID}","verificationMethod":[{{"id":"{AGENT_DID}#other"}}]}}"#),
    ] {
        let transport = Canned::document(&body);
        assert!(
            matches!(resolve(&transport, KEY_ID), Err(CoreError::Invalid(message))
                if message.starts_with("no public JWK found")),
            "{body}"
        );
    }
    assert!(matches!(
        resolve(&Canned::document("not json"), KEY_ID),
        Err(CoreError::Json(_))
    ));
}

/// The published key must match the assertion it is being used to verify, must not carry private
/// material, and must permit verification.
#[test]
fn verification_method_metadata_must_agree_with_the_assertion() {
    for extra in [
        r#","alg":"ES256""#,
        r#","kid":"did:web:agent.example#other""#,
        r#","d":"private-key-material""#,
        r#","use":"enc""#,
        r#","key_ops":["sign"]"#,
        r#","key_ops":"verify""#,
    ] {
        let transport = Canned::document(&verification_method(&ed25519(extra)));
        assert!(resolve(&transport, KEY_ID).is_err(), "{extra}");
    }
    let not_an_object = Canned::document(&verification_method(r#""a string""#));
    assert!(resolve(&not_an_object, KEY_ID).is_err());
}

/// DWB-RES-002 keeps resolution on the origin the identifier names, so a redirect is refused.
#[test]
fn redirects_and_failures_are_refused() {
    let mut redirected = Canned::document(&verification_method(&ed25519("")));
    redirected.redirect = true;
    assert!(resolve(&redirected, KEY_ID).is_err());

    let mut failed = Canned::document(&verification_method(&ed25519("")));
    failed.status = StatusCode::NOT_FOUND;
    assert!(resolve(&failed, KEY_ID).is_err());

    let mut unavailable = Canned::document(&verification_method(&ed25519("")));
    unavailable.failure = true;
    assert!(matches!(
        resolve(&unavailable, KEY_ID),
        Err(CoreError::Transport(_))
    ));
}

#[test]
fn malformed_public_key_material_is_refused() {
    let transport = Canned::document(&verification_method(r#"{"kty":"unsupported"}"#));
    assert!(resolve(&transport, KEY_ID).is_err());
    assert!(did_web_document_url("did:web:%FF").is_err());
}

/// The document is bounded, so an oversized body is refused rather than parsed.
#[test]
fn oversized_documents_are_refused() {
    let padding = " ".repeat((1 << 20) + 1);
    let transport = Canned::document(&format!("{}{padding}", verification_method(&ed25519(""))));
    assert!(resolve(&transport, KEY_ID).is_err());
}

/// DWB-RES-001 maps the identifier onto its document URL.
#[test]
fn document_urls_follow_the_published_mapping() {
    assert_eq!(
        did_web_document_url("did:web:example.com")
            .expect("url")
            .as_str(),
        "https://example.com/.well-known/did.json"
    );
    assert_eq!(
        did_web_document_url("did:web:example.com:agents:one")
            .expect("url")
            .as_str(),
        "https://example.com/agents/one/did.json"
    );
    assert_eq!(
        did_web_document_url("did:web:example.com%3A8443")
            .expect("url")
            .as_str(),
        "https://example.com:8443/.well-known/did.json"
    );
    assert!(did_web_document_url("did:key:z6Mk").is_err());
    assert!(did_web_document_url("did:web:example.com%3A99999").is_err());
    assert!(did_web_document_url("did:web:example.com%3A").is_err());
    assert!(did_web_document_url("did:web:%5Bnot-a-literal").is_err());
}

/// Loopback resolution is an explicit development opt-in and never the default.
#[test]
fn loopback_resolution_is_opt_in() {
    let secure = did_web_document_url("did:web:localhost%3A8080").expect("url");
    assert_eq!(secure.scheme(), "https");
    let insecure = did_web_document_url_with_options(
        "did:web:localhost%3A8080",
        DidWebDocumentUrlOptions {
            allow_insecure_loopback: true,
        },
    )
    .expect("url");
    assert_eq!(insecure.scheme(), "http");
    let remote = did_web_document_url_with_options(
        "did:web:example.com",
        DidWebDocumentUrlOptions {
            allow_insecure_loopback: true,
        },
    )
    .expect("url");
    assert_eq!(remote.scheme(), "https");
}

fn resolve_with(
    transport: &dyn HttpTransport,
    algorithm: SigningAlgorithm,
    did: &str,
    key_id: &str,
) -> Result<ClientAssertionVerifyingKey, CoreError> {
    block_on(resolve_did_web_public_key(ResolveDidWebPublicKeyOptions {
        algorithm,
        allow_insecure_loopback: false,
        did,
        key_id,
        transport,
    }))
}

/// ES256 verification methods resolve alongside Ed25519 ones; an algorithm outside the two the
/// specification registers has no key type to read the JWK as.
#[test]
fn resolves_the_registered_signing_algorithms() {
    let es256 = r#"{"crv":"P-256","kty":"EC","x":"-kjMG0i02fcDy1MuYpQj9R4Iyf8W0hzGnMd4O5D_oxs","y":"M0R09c1WmZyrJDF7cV9vZVZVzGdYi7t9HV38iXnan0Q"}"#;
    let transport = Canned::document(&verification_method(es256));
    let key = resolve_with(&transport, SigningAlgorithm::Es256, AGENT_DID, KEY_ID).expect("key");
    assert_eq!(key.algorithm(), SigningAlgorithm::Es256);
    assert!(
        resolve_with(
            &transport,
            SigningAlgorithm::from("RS256"),
            AGENT_DID,
            KEY_ID
        )
        .is_err()
    );
}

/// An identifier that does not map onto a document URL is refused before any request is made.
#[test]
fn an_unresolvable_identifier_is_refused_before_the_request() {
    let transport = Canned::document(&verification_method(&ed25519("")));
    assert!(
        resolve_with(
            &transport,
            SigningAlgorithm::EdDsa,
            "did:key:z6Mk",
            "did:key:z6Mk"
        )
        .is_err()
    );
    assert!(
        resolve_with(
            &transport,
            SigningAlgorithm::EdDsa,
            "did:web:agent.example:..",
            "did:web:agent.example:..",
        )
        .is_err()
    );
}

/// DWB-RES-001 admits an IPv6 literal and an explicit port in the host portion, and nothing else
/// after the closing bracket.
#[test]
fn host_portions_admit_literals_and_ports() {
    for (did, expected) in [
        (
            "did:web:agent.example%3A8443",
            "https://agent.example:8443/.well-known/did.json",
        ),
        (
            "did:web:%5B%3A%3A1%5D%3A8443",
            "https://[::1]:8443/.well-known/did.json",
        ),
        (
            "did:web:%5B%3A%3A1%5D",
            "https://[::1]/.well-known/did.json",
        ),
    ] {
        assert_eq!(
            did_web_document_url(did).expect(did).as_str(),
            expected,
            "{did}"
        );
    }
    for did in [
        "did:web:%5B%3A%3A1%5Dx",
        "did:web:%5B%3A%3A1",
        "did:web:agent.example%3A84430",
        "did:web:agent.example%3A",
        "did:web:agent.example%3Aweb",
    ] {
        assert!(did_web_document_url(did).is_err(), "{did}");
    }
}
