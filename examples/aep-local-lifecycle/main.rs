use std::{collections::BTreeMap, sync::Arc};

use aep_agent::{
    AgentError, AgentIdentity, AssertionSigner,
    AuthenticationOptions as AgentAuthenticationOptions, Client, ClientOptions, EnrollOptions,
    GrantOptions, IdentityProvider, IdentityRequest, RevokeOptions,
};
use aep_core::{
    ApiKeyGrantResponse, AuthenticationMethod, AuthorizationCarrier, BuiltInGrantResponse,
    ClaimName, ClaimValues, ClientAssertionClaims, ClientAssertionSigningKey, GrantType,
    GrantTypeConfig, HttpRequest, HttpResponse, HttpTransport, IdentityMethod,
    SignClientAssertionOptions, SigningAlgorithm, StringBoolean, TransportError,
    sign_client_assertion,
};
use aep_service::{
    DidWebClientAssertionVerifier, MemoryServiceCredentialStore, ProtectedResourceAuthentication,
    ProtectedResourceRequest, Service, ServiceError, ServiceOptions, StoredApiKeyGrantTypeOptions,
    stored_api_key_grant_type,
};
use aep_tower::CommandService;
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use ed25519_dalek::SigningKey;
use futures::FutureExt as _;
use http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use http_body_util::{BodyExt as _, Full};
use serde_json::json;
use time::{Duration, format_description::well_known::Rfc3339};
use url::Url;
use uuid::Uuid;

const AGENT_DID: &str = "did:web:127.0.0.1%3A4102";
const SERVICE_DID: &str = "did:web:127.0.0.1%3A4101";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = ClientAssertionSigningKey::ed25519_from_seed([7; 32]);
    let key_id = format!("{AGENT_DID}#key-1");
    let service = service(key_id.clone())?;
    let transport = Arc::new(ServiceTransport {
        commands: CommandService::new(service.clone(), 1 << 20)?,
    });
    let identity_provider = Arc::new(LocalIdentityProvider { key, key_id });
    let mut client_options = ClientOptions::new(identity_provider);
    client_options.allow_insecure_loopback = true;
    client_options.command_transport = Some(transport.clone());
    client_options.inspect_transport = Some(transport);
    let session = Client::new(client_options)?.service("http://127.0.0.1:4101")?;

    let inspection = session.inspect().await?;
    println!("Inspect: {}", inspection.document.service.did);

    let enrollment = session
        .enroll(EnrollOptions {
            claims: Some(ClaimValues {
                contact_email: Some("buyer@example.com".to_owned()),
                ..ClaimValues::default()
            }),
            idempotency_key: Some("example-enroll".to_owned()),
        })
        .await?;
    println!("Enroll: {}", enrollment.body.status.as_str());
    println!("Status: {}", session.status().await?.body.status.as_str());

    let grant = session
        .grant(GrantOptions {
            grant_type: Some(GrantType::ApiKey),
            idempotency_key: Some("example-grant".to_owned()),
            preferred_grant_types: Vec::new(),
            requested_scopes: vec!["resource:read".to_owned()],
        })
        .await?;
    let credential_id = grant
        .body
        .credential
        .as_ref()
        .map(|credential| match credential {
            BuiltInGrantResponse::OAuthBearer(value) => value.credential_id.clone(),
            BuiltInGrantResponse::ApiKey(value) => value.credential_id.clone(),
            BuiltInGrantResponse::Basic(value) => value.credential_id.clone(),
        })
        .ok_or("API-key credential was not returned")?;
    println!("Grant: api-key credential {credential_id}");

    let resource = Url::parse("http://127.0.0.1:4101/resource")?;
    let authentication = session
        .authentication(AgentAuthenticationOptions {
            carrier: AuthorizationCarrier::Standard,
            client_assertion_only: false,
            credential_id: None,
            grant_type: None,
            resource: resource.clone(),
        })
        .await?;
    authenticate_resource(&service, authentication.headers, resource.clone()).await?;
    println!("Protected resource: authenticated with api-key");

    session
        .revoke(RevokeOptions {
            all_grant_types: false,
            credential_id: Some(credential_id),
            grant_type: Some(GrantType::ApiKey),
            idempotency_key: Some("example-revoke".to_owned()),
        })
        .await?;
    let fallback = session
        .authentication(AgentAuthenticationOptions {
            carrier: AuthorizationCarrier::Dedicated,
            client_assertion_only: false,
            credential_id: None,
            grant_type: None,
            resource: resource.clone(),
        })
        .await?;
    authenticate_resource(&service, fallback.headers, resource).await?;
    println!("Revoke: API key removed; protected resource authenticated with aep-jwt");
    Ok(())
}

struct LocalIdentityProvider {
    key: ClientAssertionSigningKey,
    key_id: String,
}

#[async_trait]
impl IdentityProvider for LocalIdentityProvider {
    async fn get_or_create_identity(
        &self,
        request: IdentityRequest,
    ) -> Result<AgentIdentity, AgentError> {
        Ok(AgentIdentity {
            agent_did: AGENT_DID.to_owned(),
            identity_method: IdentityMethod::DidWeb,
            metadata: BTreeMap::new(),
            service_did: request.inspection.document.service.did,
            signing_algorithms: vec![SigningAlgorithm::EdDsa],
        })
    }

    async fn signer_for(
        &self,
        _identity: &AgentIdentity,
    ) -> Result<Arc<dyn AssertionSigner>, AgentError> {
        Ok(Arc::new(LocalSigner {
            key: self.key.clone(),
            key_id: self.key_id.clone(),
        }))
    }
}

struct LocalSigner {
    key: ClientAssertionSigningKey,
    key_id: String,
}

#[async_trait]
impl AssertionSigner for LocalSigner {
    async fn sign(
        &self,
        claims: &ClientAssertionClaims,
        _algorithms: &[SigningAlgorithm],
    ) -> Result<String, AgentError> {
        Ok(sign_client_assertion(
            claims,
            SignClientAssertionOptions {
                allow_insecure_loopback: true,
                key: &self.key,
                key_id: &self.key_id,
            },
        )?)
    }
}

struct DidTransport {
    document: Vec<u8>,
    url: Url,
}

#[async_trait]
impl HttpTransport for DidTransport {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        if request.url != self.url {
            return Err(TransportError::new("unexpected DID document URL"));
        }
        Ok(HttpResponse {
            body: self.document.clone(),
            final_url: request.url,
            headers: HeaderMap::from_iter([(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/did+json"),
            )]),
            status: StatusCode::OK,
        })
    }
}

#[derive(Clone)]
struct ServiceTransport {
    commands: CommandService,
}

#[async_trait]
impl HttpTransport for ServiceTransport {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let uri = request.url.query().map_or_else(
            || request.url.path().to_owned(),
            |query| format!("{}?{query}", request.url.path()),
        );
        let mut builder = Request::builder().method(request.method).uri(uri);
        *builder
            .headers_mut()
            .ok_or_else(|| TransportError::new("request headers"))? = request.headers;
        let response = self
            .commands
            .dispatch(
                builder
                    .body(Full::new(Bytes::from(request.body)))
                    .map_err(|error| TransportError::new(error.to_string()))?,
            )
            .await
            .map_err(|error| TransportError::new(error.to_string()))?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|error| TransportError::new(error.to_string()))?
            .to_bytes()
            .to_vec();
        Ok(HttpResponse {
            body,
            final_url: request.url,
            headers,
            status,
        })
    }
}

fn service(key_id: String) -> Result<Arc<Service>, Box<dyn std::error::Error>> {
    let public_key = SigningKey::from_bytes(&[7; 32]).verifying_key();
    let did_document = serde_json::to_vec(&json!({
        "id": AGENT_DID,
        "verificationMethod": [{
            "controller": AGENT_DID,
            "id": key_id,
            "publicKeyJwk": {
                "alg": "EdDSA",
                "crv": "Ed25519",
                "kid": key_id,
                "kty": "OKP",
                "use": "sig",
                "x": URL_SAFE_NO_PAD.encode(public_key.as_bytes())
            },
            "type": "JsonWebKey2020"
        }]
    }))?;
    let verifier = Arc::new(DidWebClientAssertionVerifier::new(
        Arc::new(DidTransport {
            document: did_document,
            url: Url::parse("http://127.0.0.1:4102/.well-known/did.json")?,
        }),
        true,
    ));
    let grant_type = stored_api_key_grant_type(StoredApiKeyGrantTypeOptions {
        config: GrantTypeConfig {
            additional: BTreeMap::from([("header_names".to_owned(), json!(["x-api-key"]))]),
            supports_per_credential_revoke: Some(StringBoolean::True),
        },
        issue: Arc::new(|request, context| {
            async move {
                let expires_at = (context.now + Duration::hours(1))
                    .format(&Rfc3339)
                    .map_err(|error| ServiceError::Handler(error.to_string()))?;
                Ok::<_, ServiceError>(ApiKeyGrantResponse {
                    additional: BTreeMap::new(),
                    api_key: Uuid::new_v4().to_string(),
                    credential_id: Uuid::new_v4().to_string(),
                    expires_at,
                    header: "x-api-key".to_owned(),
                    scopes: request.requested_scopes,
                })
            }
            .boxed()
        }),
        store: Arc::new(MemoryServiceCredentialStore::default()),
    })?;
    let mut options = ServiceOptions::new(SERVICE_DID, verifier);
    options.allow_insecure_loopback = true;
    options.authentication_methods =
        vec![AuthenticationMethod::ApiKey, AuthenticationMethod::AepJwt];
    options.claims.required = vec![ClaimName::ContactEmail];
    options.endpoint_base = Some("/aep".to_owned());
    options.grant_types = vec![grant_type];
    options.inspect_url = Some(Url::parse("http://127.0.0.1:4101/.well-known/aep")?);
    options.signing_algorithms = vec![SigningAlgorithm::EdDsa, SigningAlgorithm::Es256];
    Ok(Service::new(options)?)
}

async fn authenticate_resource(
    service: &Arc<Service>,
    headers: HeaderMap,
    url: Url,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = service
        .authenticate_protected_resource(ProtectedResourceRequest {
            headers,
            method: Method::GET,
            url,
        })
        .await?;
    match result {
        ProtectedResourceAuthentication::Authenticated(_) => Ok(()),
        ProtectedResourceAuthentication::Rejected(response) => Err(format!(
            "protected resource rejected authentication with {}",
            response.status
        )
        .into()),
    }
}
