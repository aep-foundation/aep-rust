use std::{collections::BTreeMap, sync::Arc};

use aep_core::{
    AssertionOperation, ClientAssertionClaims, ClientAssertionSigningKey,
    ClientAssertionVerifyingKey, SignClientAssertionOptions, SigningAlgorithm,
    sign_client_assertion,
};
use aep_platform::{
    AuthorizationRequest, Authorizer, DidVerificationMethod, DiscoveryOptions, IdentityRecord,
    KeyStore, Platform, PlatformError, PlatformOptions, PlatformResponse, ProvisionRequest,
    RequestContext, ResponseBody, ServiceDidResolver, SignRequest,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use serde_json::json;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let platform = platform()?;
    let context = RequestContext {
        idempotency_key: Some("example-provision".to_owned()),
        principal: "example-agent".to_owned(),
        ..RequestContext::default()
    };
    let identity = success(
        platform
            .provision(
                ProvisionRequest {
                    service_did: "did:web:service.example".to_owned(),
                },
                context,
            )
            .await?,
    )?;
    println!("Provisioned: {}", identity.agent_did);

    let did_id = identity
        .agent_did
        .rsplit(':')
        .next()
        .ok_or("provisioned Agent DID has no identifier")?;
    let document = success(platform.did_document(did_id).await?)?;
    println!("DID document: {}", document.id);

    let signed = success(
        platform
            .sign(
                &identity.agent_identity_id,
                SignRequest {
                    jti: Uuid::new_v4().to_string(),
                    lifetime_seconds: Some("300".to_owned()),
                    op: AssertionOperation::Enroll,
                    platform_context: BTreeMap::new(),
                    resource: None,
                    service_did: identity.service_did.clone(),
                },
                RequestContext {
                    idempotency_key: Some("example-sign".to_owned()),
                    principal: "example-agent".to_owned(),
                    ..RequestContext::default()
                },
            )
            .await?,
    )?;
    println!("Signed assertion: {:?}", signed.status);
    Ok(())
}

struct AllowExampleCaller;

#[async_trait]
impl Authorizer for AllowExampleCaller {
    async fn authorize(
        &self,
        _request: &AuthorizationRequest,
        context: &RequestContext,
    ) -> Result<bool, PlatformError> {
        Ok(context.principal == "example-agent")
    }
}

struct ExampleKeyStore {
    key: ClientAssertionSigningKey,
    public_key: [u8; 32],
}

impl ExampleKeyStore {
    fn new() -> Self {
        let seed = [9; 32];
        Self {
            key: ClientAssertionSigningKey::ed25519_from_seed(seed),
            public_key: *SigningKey::from_bytes(&seed).verifying_key().as_bytes(),
        }
    }
}

#[async_trait]
impl KeyStore for ExampleKeyStore {
    async fn create_key(&self, _identity: &IdentityRecord) -> Result<(), PlatformError> {
        Ok(())
    }

    async fn did_verification_method(
        &self,
        identity: &IdentityRecord,
    ) -> Result<DidVerificationMethod, PlatformError> {
        Ok(DidVerificationMethod {
            controller: identity.agent_did.clone(),
            id: identity.key_id.clone(),
            method_type: "JsonWebKey2020".to_owned(),
            public_key_jwk: json!({
                "alg": "EdDSA",
                "crv": "Ed25519",
                "kid": identity.key_id,
                "kty": "OKP",
                "use": "sig",
                "x": URL_SAFE_NO_PAD.encode(self.public_key)
            }),
        })
    }

    async fn sign(
        &self,
        identity: &IdentityRecord,
        claims: &ClientAssertionClaims,
    ) -> Result<String, PlatformError> {
        Ok(sign_client_assertion(
            claims,
            SignClientAssertionOptions {
                allow_insecure_loopback: false,
                key: &self.key,
                key_id: &identity.key_id,
            },
        )?)
    }

    async fn verification_key(
        &self,
        _identity: &IdentityRecord,
    ) -> Result<ClientAssertionVerifyingKey, PlatformError> {
        Ok(self.key.verifying_key())
    }
}

struct DidWebServiceResolver;

#[async_trait]
impl ServiceDidResolver for DidWebServiceResolver {
    async fn resolve(&self, service_did: &str) -> Result<bool, PlatformError> {
        Ok(service_did.starts_with("did:web:"))
    }
}

fn platform() -> Result<Arc<Platform>, PlatformError> {
    let mut options = PlatformOptions::new(
        Arc::new(AllowExampleCaller),
        Arc::new(ExampleKeyStore::new()),
        Arc::new(DidWebServiceResolver),
        "platform.example",
        "https://platform.example/agents/{agent_did_id}/did.json",
    );
    options.discovery = DiscoveryOptions {
        endpoint_base: "/v1/aep".to_owned(),
        lifecycle_endpoint: "/v1/aep/agent-identities/{agent_identity_id}".to_owned(),
        list_endpoint: "/v1/aep/agent-identities".to_owned(),
        platform_did: Some("did:web:platform.example".to_owned()),
        platform_name: "Ephemeral AEP Platform".to_owned(),
        provision_endpoint: "/v1/aep/agent-identities".to_owned(),
        sign_endpoint: "/v1/aep/agent-identities/{agent_identity_id}/sign".to_owned(),
        ..DiscoveryOptions::default()
    };
    options.signing_algorithms = vec![SigningAlgorithm::EdDsa];
    Platform::new(options)
}

fn success<T>(response: PlatformResponse<T>) -> Result<T, Box<dyn std::error::Error>> {
    match response.body {
        ResponseBody::Success(value) => Ok(value),
        ResponseBody::Problem(problem) => Err(format!(
            "Platform returned {} ({})",
            problem.code.as_str(),
            response.status
        )
        .into()),
    }
}
