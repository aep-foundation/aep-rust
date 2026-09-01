use std::{net::IpAddr, str::FromStr, sync::Arc, time::Duration};

use aep_core::{
    ClientAssertionClaims, DidWebDocumentUrlOptions, HttpTransport, IdentityMethod,
    MAX_ASSERTION_LIFETIME, SigningAlgorithm, did_web_document_url_with_options,
};
use url::Url;
use uuid::Uuid;

use crate::{
    AgentError, AgentIdentity, AssertionSigner, ClientOptions, Clock, CredentialStore, Delay,
    IdempotencyKeyProvider, IdentityProvider, IdentityRequest, IdentityStore, InspectCache,
    Inspection, MemoryCredentialStore, MemoryIdentityStore, MemoryInspectCache,
    RandomIdempotencyKeyProvider, ReqwestTransport, SystemClock, TimerDelay,
};

pub struct Client {
    pub(crate) allow_insecure_loopback: bool,
    pub(crate) assertion_lifetime: Duration,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) command_transport: Arc<dyn HttpTransport>,
    pub(crate) credential_store: Arc<dyn CredentialStore>,
    pub(crate) delay: Arc<dyn Delay>,
    pub(crate) identity_provider: Arc<dyn IdentityProvider>,
    pub(crate) identity_lock: futures::lock::Mutex<()>,
    pub(crate) identity_store: Arc<dyn IdentityStore>,
    pub(crate) idempotency_keys: Arc<dyn IdempotencyKeyProvider>,
    pub(crate) inspect_cache: Arc<dyn InspectCache>,
    pub(crate) inspect_transport: Arc<dyn HttpTransport>,
    pub(crate) maximum_response_bytes: usize,
}

impl Client {
    pub fn new(options: ClientOptions) -> Result<Arc<Self>, AgentError> {
        if options.assertion_lifetime < Duration::from_secs(1)
            || options.assertion_lifetime > MAX_ASSERTION_LIFETIME
            || options.assertion_lifetime.subsec_nanos() != 0
        {
            return Err(AgentError::InvalidConfiguration(
                "AEP Agent assertion lifetime must be whole seconds from 1 through 300".to_owned(),
            ));
        }
        if options.maximum_response_bytes == 0 {
            return Err(AgentError::InvalidConfiguration(
                "AEP Agent maximum response bytes must be positive".to_owned(),
            ));
        }
        if options.request_timeout.is_zero() {
            return Err(AgentError::InvalidConfiguration(
                "AEP Agent request timeout must be positive".to_owned(),
            ));
        }
        let clock = options.clock.unwrap_or_else(|| Arc::new(SystemClock));
        let new_transport = || -> Result<Arc<dyn HttpTransport>, AgentError> {
            Ok(Arc::new(
                ReqwestTransport::new(options.maximum_response_bytes, options.request_timeout)
                    .map_err(|error| AgentError::Transport(error.to_string()))?,
            ))
        };
        let default_transport =
            if options.inspect_transport.is_none() || options.command_transport.is_none() {
                Some(new_transport()?)
            } else {
                None
            };
        let inspect_transport = resolve_transport(options.inspect_transport, &default_transport)?;
        let command_transport = resolve_transport(options.command_transport, &default_transport)?;
        Ok(Arc::new(Self {
            allow_insecure_loopback: options.allow_insecure_loopback,
            assertion_lifetime: options.assertion_lifetime,
            command_transport,
            credential_store: options
                .credential_store
                .unwrap_or_else(|| Arc::new(MemoryCredentialStore::new(clock.clone()))),
            delay: options.delay.unwrap_or_else(|| Arc::new(TimerDelay)),
            identity_provider: options.identity_provider,
            identity_lock: futures::lock::Mutex::new(()),
            identity_store: options
                .identity_store
                .unwrap_or_else(|| Arc::new(MemoryIdentityStore::default())),
            idempotency_keys: options
                .idempotency_keys
                .unwrap_or_else(|| Arc::new(RandomIdempotencyKeyProvider)),
            inspect_cache: options
                .inspect_cache
                .unwrap_or_else(|| Arc::new(MemoryInspectCache::default())),
            inspect_transport,
            maximum_response_bytes: options.maximum_response_bytes,
            clock,
        }))
    }

    pub fn service(self: &Arc<Self>, reference: &str) -> Result<Session, AgentError> {
        Ok(Session {
            client: self.clone(),
            inspect_lock: Arc::new(futures::lock::Mutex::new(())),
            service_url: resolve_service_reference(reference, self.allow_insecure_loopback)?,
        })
    }

    pub(crate) async fn sign_assertion(
        &self,
        inspection: &Inspection,
        identity: &AgentIdentity,
        signer: &dyn AssertionSigner,
        operation: aep_core::AssertionOperation,
        resource: Option<&Url>,
    ) -> Result<String, AgentError> {
        validate_identity(identity, inspection)?;
        let iat = self.clock.now().unix_timestamp();
        let lifetime = i64::try_from(self.assertion_lifetime.as_secs())
            .map_err(|_| AgentError::Identity("AEP assertion lifetime is too large".to_owned()))?;
        let claims = ClientAssertionClaims {
            aud: inspection.document.service.did.clone(),
            exp: iat.checked_add(lifetime).ok_or_else(|| {
                AgentError::Identity(
                    "AEP assertion expiration exceeds the supported time range".to_owned(),
                )
            })?,
            iat,
            iss: identity.agent_did.clone(),
            jti: Uuid::new_v4().to_string(),
            op: operation,
            resource: resource.map(Url::to_string),
            sub: identity.agent_did.clone(),
            additional: Default::default(),
        };
        aep_core::validate_client_assertion_claims_with_options(
            &claims,
            aep_core::ClientAssertionValidationOptions {
                allow_insecure_loopback: self.allow_insecure_loopback,
            },
        )
        .map_err(aep_core::CoreError::from)?;
        let algorithms = compatible_algorithms(
            &identity.signing_algorithms,
            &inspection.document.core.signing_algorithms,
        );
        if algorithms.is_empty() {
            return Err(AgentError::Identity(
                "AEP identity and Service have no compatible signing algorithm".to_owned(),
            ));
        }
        let assertion = signer.sign(&claims, &algorithms).await?;
        if assertion.is_empty() {
            return Err(AgentError::Identity(
                "AEP assertion signer returned an empty assertion".to_owned(),
            ));
        }
        Ok(assertion)
    }
}

fn resolve_transport(
    provided: Option<Arc<dyn HttpTransport>>,
    default: &Option<Arc<dyn HttpTransport>>,
) -> Result<Arc<dyn HttpTransport>, AgentError> {
    provided.or_else(|| default.clone()).ok_or_else(|| {
        AgentError::InvalidConfiguration("AEP Agent HTTP transport is unavailable".to_owned())
    })
}

#[derive(Clone)]
pub struct Session {
    pub(crate) client: Arc<Client>,
    pub(crate) inspect_lock: Arc<futures::lock::Mutex<()>>,
    pub(crate) service_url: Url,
}

impl Session {
    pub fn service_url(&self) -> &Url {
        &self.service_url
    }

    pub async fn identity(&self) -> Result<AgentIdentity, AgentError> {
        let inspection = self.inspect().await?;
        self.resolve_identity(&inspection, true).await
    }

    pub(crate) async fn resolve_identity(
        &self,
        inspection: &Inspection,
        create: bool,
    ) -> Result<AgentIdentity, AgentError> {
        let _guard = self.client.identity_lock.lock().await;
        let service_did = &inspection.document.service.did;
        if let Some(identity) = self.client.identity_store.find(service_did).await? {
            validate_identity(&identity, inspection)?;
            return Ok(identity);
        }
        if !create {
            return Err(AgentError::Identity(
                "AEP Grant requires an existing enrolled identity".to_owned(),
            ));
        }
        let identity = self
            .client
            .identity_provider
            .get_or_create_identity(IdentityRequest {
                inspection: inspection.clone(),
            })
            .await?;
        validate_identity(&identity, inspection)?;
        self.client.identity_store.save(identity.clone()).await?;
        Ok(identity)
    }
}

fn resolve_service_reference(
    reference: &str,
    allow_insecure_loopback: bool,
) -> Result<Url, AgentError> {
    let value = reference.trim();
    if value.is_empty() {
        return Err(AgentError::InvalidServiceReference(
            "invalid AEP Service reference".to_owned(),
        ));
    }
    let mut url = if value.starts_with("did:web:") {
        let document = did_web_document_url_with_options(
            value,
            DidWebDocumentUrlOptions {
                allow_insecure_loopback,
            },
        )?;
        let mut origin = document;
        origin.set_path("/");
        origin.set_query(None);
        origin.set_fragment(None);
        origin
    } else {
        Url::parse(value).or_else(|_| Url::parse(&format!("https://{value}")))?
    };
    if !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
        || url.cannot_be_a_base()
    {
        return Err(AgentError::InvalidServiceReference(
            "invalid AEP Service reference".to_owned(),
        ));
    }
    if url.scheme() != "https"
        && !(allow_insecure_loopback && url.scheme() == "http" && is_loopback(&url))
    {
        return Err(AgentError::InvalidServiceReference(
            "AEP Service references require HTTPS".to_owned(),
        ));
    }
    url.set_path("/");
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

pub(crate) fn is_loopback(url: &Url) -> bool {
    url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || IpAddr::from_str(host).is_ok_and(|address| address.is_loopback())
    })
}

pub(crate) fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme().eq_ignore_ascii_case(right.scheme())
        && left
            .host_str()
            .zip(right.host_str())
            .is_some_and(|(left, right)| left.eq_ignore_ascii_case(right))
        && left.port_or_known_default() == right.port_or_known_default()
}

pub(crate) fn validate_identity(
    identity: &AgentIdentity,
    inspection: &Inspection,
) -> Result<(), AgentError> {
    if !identity.agent_did.starts_with("did:")
        || identity.service_did != inspection.document.service.did
        || identity.signing_algorithms.is_empty()
    {
        return Err(AgentError::Identity(
            "AEP identity provider returned an invalid Service-scoped identity".to_owned(),
        ));
    }
    if identity.identity_method != IdentityMethod::DidWeb
        || !identity.agent_did.starts_with("did:web:")
    {
        return Err(AgentError::Identity(
            "AEP Agent identity method has no supported origin binding".to_owned(),
        ));
    }
    if !inspection
        .document
        .identity
        .methods
        .contains(&identity.identity_method)
    {
        return Err(AgentError::Identity(
            "AEP Service does not advertise the Agent identity method".to_owned(),
        ));
    }
    if compatible_algorithms(
        &identity.signing_algorithms,
        &inspection.document.core.signing_algorithms,
    )
    .is_empty()
    {
        return Err(AgentError::Identity(
            "AEP identity and Service have no compatible signing algorithm".to_owned(),
        ));
    }
    Ok(())
}

fn compatible_algorithms(
    available: &[SigningAlgorithm],
    advertised: &[SigningAlgorithm],
) -> Vec<SigningAlgorithm> {
    advertised
        .iter()
        .filter(|algorithm| available.contains(algorithm))
        .cloned()
        .collect()
}
