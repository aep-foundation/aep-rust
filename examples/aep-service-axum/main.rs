use std::{collections::BTreeMap, sync::Arc, time::Duration};

use aep_axum::{AepPrincipal, AuthenticationOptions, authentication_layer, router};
use aep_core::{
    ApiKeyGrantResponse, AuthenticationMethod, GrantTypeConfig, SigningAlgorithm, StringBoolean,
};
use aep_service::{
    DidWebClientAssertionVerifier, MemoryServiceCredentialStore, ReqwestTransport, Service,
    ServiceError, ServiceOptions, StoredApiKeyGrantTypeOptions, stored_api_key_grant_type,
};
use axum::{Router, routing::get};
use futures::FutureExt as _;
use serde_json::json;
use time::{Duration as TimeDuration, format_description::well_known::Rfc3339};
use tokio::net::TcpListener;
use url::Url;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = std::env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let port = std::env::var("PORT").unwrap_or_else(|_| "4101".to_owned());
    let origin = Url::parse(&format!("http://{host}:{port}"))?;
    let service_did =
        std::env::var("SERVICE_DID").unwrap_or_else(|_| format!("did:web:{host}%3A{port}"));
    let service = service(service_did, &origin)?;

    let mut authentication = AuthenticationOptions::new(origin.clone());
    authentication.allow_insecure_loopback = true;
    let protected = Router::new()
        .route(
            "/resource",
            get(|principal: AepPrincipal| async move {
                axum::Json(json!({"agent_did": principal.agent_did}))
            }),
        )
        .route_layer(authentication_layer(service.clone(), authentication)?);
    let application = router(service, 1 << 20)?.merge(protected);
    let listener = TcpListener::bind(format!("{host}:{port}")).await?;

    println!("AEP Axum Service: {origin}");
    println!("Inspect: {origin}.well-known/aep");
    println!("Protected resource: {origin}resource");
    axum::serve(listener, application).await?;
    Ok(())
}

fn service(service_did: String, origin: &Url) -> Result<Arc<Service>, Box<dyn std::error::Error>> {
    let transport = Arc::new(ReqwestTransport::new(1 << 20, Duration::from_secs(10))?);
    let verifier = Arc::new(DidWebClientAssertionVerifier::new(transport, true));
    let credential_store = Arc::new(MemoryServiceCredentialStore::default());
    let grant_type = stored_api_key_grant_type(StoredApiKeyGrantTypeOptions {
        config: GrantTypeConfig {
            additional: BTreeMap::from([("header_names".to_owned(), json!(["x-api-key"]))]),
            supports_per_credential_revoke: Some(StringBoolean::True),
        },
        issue: Arc::new(|request, context| {
            async move {
                let expiration = (context.now + TimeDuration::hours(1))
                    .format(&Rfc3339)
                    .map_err(|error| ServiceError::Handler(error.to_string()))?;
                Ok::<_, ServiceError>(ApiKeyGrantResponse {
                    additional: BTreeMap::new(),
                    api_key: Uuid::new_v4().to_string(),
                    credential_id: Uuid::new_v4().to_string(),
                    expires_at: expiration,
                    header: "x-api-key".to_owned(),
                    scopes: request.requested_scopes,
                })
            }
            .boxed()
        }),
        store: credential_store,
    })?;
    let mut options = ServiceOptions::new(service_did, verifier);
    options.allow_insecure_loopback = true;
    options.authentication_methods = vec![AuthenticationMethod::ApiKey];
    options.endpoint_base = Some("/aep".to_owned());
    options.grant_types = vec![grant_type];
    options.inspect_url = Some(origin.join(".well-known/aep")?);
    options.signing_algorithms = vec![SigningAlgorithm::EdDsa, SigningAlgorithm::Es256];
    Ok(Service::new(options)?)
}
