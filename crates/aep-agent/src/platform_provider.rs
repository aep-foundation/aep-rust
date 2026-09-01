use std::{collections::BTreeMap, fmt, sync::Arc, time::Duration};

use aep_core::{
    ClientAssertionClaims, DidWebDocumentUrlOptions, HttpRequest, HttpResponse, HttpTransport,
    IdentityMethod, MEDIA_TYPE, PROBLEM_MEDIA_TYPE, SigningAlgorithm, VERSION,
    did_web_document_url_with_options, is_version_compatible, parse_problem_details,
};
use async_trait::async_trait;
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use serde::Deserialize;
use serde_json::Value;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use crate::{
    AgentError, AgentIdentity, AssertionSigner, Clock, IdentityProvider, IdentityRequest,
    ReqwestTransport, SystemClock, is_loopback, same_origin,
};

const PLATFORM_WELL_KNOWN_PATH: &str = "/.well-known/aep-platform";
const MAXIMUM_REDIRECTS: usize = 5;
const DEFAULT_DISCOVERY_FRESHNESS: Duration = Duration::from_secs(300);

#[async_trait]
pub trait PlatformAuthenticationHeaders: Send + Sync {
    async fn headers(&self) -> Result<HeaderMap, AgentError>;
}

pub trait PlatformIdempotencyKeyProvider: Send + Sync {
    fn create_key(&self) -> Result<String, AgentError>;
}

#[async_trait]
pub trait PlatformContextProvider: Send + Sync {
    async fn context(
        &self,
        identity: &AgentIdentity,
        claims: &ClientAssertionClaims,
    ) -> Result<BTreeMap<String, Value>, AgentError>;
}

#[derive(Clone, PartialEq)]
pub struct PlatformPendingSign {
    pub identity: AgentIdentity,
    pub platform_context: BTreeMap<String, Value>,
    pub retry_after: Duration,
}

impl fmt::Debug for PlatformPendingSign {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlatformPendingSign")
            .field("identity", &self.identity)
            .field("platform_context", &"[REDACTED]")
            .field("retry_after", &self.retry_after)
            .finish()
    }
}

#[async_trait]
pub trait PlatformPendingSignResolver: Send + Sync {
    async fn resolve(
        &self,
        pending: PlatformPendingSign,
    ) -> Result<BTreeMap<String, Value>, AgentError>;
}

#[derive(Clone)]
pub struct PlatformIdentityProviderOptions {
    pub allow_insecure_loopback: bool,
    pub authentication_headers: Option<Arc<dyn PlatformAuthenticationHeaders>>,
    pub authorization: Option<String>,
    pub clock: Option<Arc<dyn Clock>>,
    pub idempotency_keys: Option<Arc<dyn PlatformIdempotencyKeyProvider>>,
    pub maximum_response_bytes: usize,
    pub pending_sign_resolver: Option<Arc<dyn PlatformPendingSignResolver>>,
    pub platform_context: Option<Arc<dyn PlatformContextProvider>>,
    pub platform_url: String,
    pub request_timeout: Duration,
    pub transport: Option<Arc<dyn HttpTransport>>,
}

impl PlatformIdentityProviderOptions {
    pub fn new(platform_url: impl Into<String>) -> Self {
        Self {
            allow_insecure_loopback: false,
            authentication_headers: None,
            authorization: None,
            clock: None,
            idempotency_keys: None,
            maximum_response_bytes: 1 << 20,
            pending_sign_resolver: None,
            platform_context: None,
            platform_url: platform_url.into(),
            request_timeout: Duration::from_secs(30),
            transport: None,
        }
    }
}

#[derive(Clone)]
pub struct PlatformIdentityProvider {
    allow_insecure_loopback: bool,
    authentication_headers: Option<Arc<dyn PlatformAuthenticationHeaders>>,
    authorization: Option<HeaderValue>,
    clock: Arc<dyn Clock>,
    discovery: Arc<futures::lock::Mutex<Option<DiscoveryCacheEntry>>>,
    idempotency_keys: Arc<dyn PlatformIdempotencyKeyProvider>,
    maximum_response_bytes: usize,
    pending_sign_resolver: Option<Arc<dyn PlatformPendingSignResolver>>,
    platform_context: Option<Arc<dyn PlatformContextProvider>>,
    platform_url: Url,
    transport: Arc<dyn HttpTransport>,
}

impl PlatformIdentityProvider {
    pub fn new(options: PlatformIdentityProviderOptions) -> Result<Arc<Self>, AgentError> {
        if options.maximum_response_bytes == 0 {
            return Err(AgentError::InvalidConfiguration(
                "AEP Platform maximum response bytes must be positive".to_owned(),
            ));
        }
        if options.request_timeout.is_zero() {
            return Err(AgentError::InvalidConfiguration(
                "AEP Platform request timeout must be positive".to_owned(),
            ));
        }
        let platform_url = platform_url(&options.platform_url, options.allow_insecure_loopback)?;
        let authorization = options
            .authorization
            .as_deref()
            .map(HeaderValue::from_str)
            .transpose()
            .map_err(|_| {
                AgentError::InvalidConfiguration(
                    "AEP Platform authorization is not a valid HTTP field value".to_owned(),
                )
            })?;
        let transport = match options.transport {
            Some(transport) => transport,
            None => Arc::new(
                ReqwestTransport::new(options.maximum_response_bytes, options.request_timeout)
                    .map_err(|error| AgentError::Transport(error.to_string()))?,
            ),
        };
        Ok(Arc::new(Self {
            allow_insecure_loopback: options.allow_insecure_loopback,
            authentication_headers: options.authentication_headers,
            authorization,
            clock: options.clock.unwrap_or_else(|| Arc::new(SystemClock)),
            discovery: Arc::new(futures::lock::Mutex::new(None)),
            idempotency_keys: options
                .idempotency_keys
                .unwrap_or_else(|| Arc::new(RandomPlatformIdempotencyKeyProvider)),
            maximum_response_bytes: options.maximum_response_bytes,
            pending_sign_resolver: options.pending_sign_resolver,
            platform_context: options.platform_context,
            platform_url,
            transport,
        }))
    }

    pub async fn find_identity_by_service_did(
        &self,
        service_did: &str,
    ) -> Result<Option<AgentIdentity>, AgentError> {
        validate_did(service_did, "AEP Service DID")?;
        let discovery = self.discover().await?;
        let mut endpoint = self.endpoint(&discovery.document.endpoints.list, None)?;
        endpoint
            .query_pairs_mut()
            .append_pair("descending", "true")
            .append_pair("limit", "100")
            .append_pair("service_did", service_did);
        let response: PlatformCommandResult<PlatformIdentityList> =
            self.command(Method::GET, endpoint, None, None).await?;
        validate_identity_list(&response.body, self.allow_insecure_loopback)?;
        response
            .body
            .data
            .into_iter()
            .find(|identity| identity.service_did == service_did && identity.status == "active")
            .map(|identity| self.agent_identity(identity))
            .transpose()
    }

    async fn discover(&self) -> Result<DiscoveryCacheEntry, AgentError> {
        let mut cache = self.discovery.lock().await;
        if let Some(entry) = cache
            .as_ref()
            .filter(|entry| discovery_fresh(entry, self.clock.now()))
        {
            return Ok(entry.clone());
        }
        let discovery_url = self.platform_url.join(PLATFORM_WELL_KNOWN_PATH)?;
        let mut current = cache
            .as_ref()
            .map_or_else(|| discovery_url.clone(), |entry| entry.final_url.clone());
        for redirects in 0..=MAXIMUM_REDIRECTS {
            let mut headers = HeaderMap::new();
            headers.insert(header::ACCEPT, HeaderValue::from_static(MEDIA_TYPE));
            if let Some(entry) = cache.as_ref() {
                if let Some(value) = entry.etag.as_deref().and_then(header_value) {
                    headers.insert(header::IF_NONE_MATCH, value);
                }
                if let Some(value) = entry.last_modified.as_deref().and_then(header_value) {
                    headers.insert(header::IF_MODIFIED_SINCE, value);
                }
            }
            let response = self
                .send(Method::GET, current.clone(), headers, Vec::new())
                .await?;
            if response.final_url != current {
                return Err(AgentError::Transport(
                    "AEP Platform transport followed a discovery redirect".to_owned(),
                ));
            }
            if is_redirect(response.status) {
                if redirects == MAXIMUM_REDIRECTS {
                    return Err(AgentError::Transport(
                        "AEP Platform discovery exceeded five redirects".to_owned(),
                    ));
                }
                let location = response
                    .headers
                    .get(header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .ok_or_else(|| {
                        AgentError::Transport(
                            "AEP Platform discovery redirect omitted Location".to_owned(),
                        )
                    })?;
                let next = current.join(location).map_err(|_| {
                    AgentError::Transport(
                        "AEP Platform discovery redirect Location is invalid".to_owned(),
                    )
                })?;
                if !safe_discovery_target(&next, &current) {
                    return Err(AgentError::Transport(
                        "AEP Platform discovery redirect changed origin or scheme".to_owned(),
                    ));
                }
                current = next;
                continue;
            }
            let entry = if response.status == StatusCode::NOT_MODIFIED {
                let mut entry = cache.clone().ok_or_else(|| {
                    AgentError::Transport(
                        "AEP Platform discovery returned 304 without a cached document".to_owned(),
                    )
                })?;
                entry.cached_at = self.clock.now();
                entry.final_url = current;
                merge_cache_headers(&mut entry, &response.headers);
                entry
            } else {
                self.parse_discovery(response, current)?
            };
            if cache_directive(entry.cache_control.as_deref(), "no-store").is_some() {
                *cache = None;
            } else {
                *cache = Some(entry.clone());
            }
            return Ok(entry);
        }
        unreachable!("discovery redirect loop returns or continues within its bound")
    }

    fn parse_discovery(
        &self,
        response: HttpResponse,
        final_url: Url,
    ) -> Result<DiscoveryCacheEntry, AgentError> {
        if !response.status.is_success() {
            return Err(AgentError::Transport(format!(
                "AEP Platform discovery failed with HTTP {}",
                response.status.as_u16()
            )));
        }
        validate_media_type(&response.headers, MEDIA_TYPE, "discovery")?;
        self.validate_response_size(&response.body)?;
        let document: PlatformDiscovery = serde_json::from_slice(&response.body).map_err(|_| {
            AgentError::Identity("AEP Platform discovery document is invalid".to_owned())
        })?;
        validate_discovery(&document, self.allow_insecure_loopback)?;
        Ok(DiscoveryCacheEntry {
            cache_control: header_string(&response.headers, header::CACHE_CONTROL),
            cached_at: self.clock.now(),
            document,
            etag: header_string(&response.headers, header::ETAG),
            final_url,
            last_modified: header_string(&response.headers, header::LAST_MODIFIED),
        })
    }

    async fn command<T: for<'de> Deserialize<'de>>(
        &self,
        method: Method,
        endpoint: Url,
        idempotency_key: Option<&str>,
        body: Option<Value>,
    ) -> Result<PlatformCommandResult<T>, AgentError> {
        let mut headers = self.headers().await?;
        headers.insert(header::ACCEPT, HeaderValue::from_static(MEDIA_TYPE));
        let encoded = body
            .map(|value| serde_json::to_vec(&value))
            .transpose()?
            .unwrap_or_default();
        if !encoded.is_empty() {
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(MEDIA_TYPE));
        }
        if let Some(key) = idempotency_key {
            headers.insert(
                "idempotency-key",
                HeaderValue::from_str(key).map_err(|_| {
                    AgentError::InvalidConfiguration(
                        "AEP Platform idempotency key is not a valid HTTP field value".to_owned(),
                    )
                })?,
            );
        }
        let response = self
            .send(method, endpoint.clone(), headers, encoded)
            .await?;
        if response.final_url != endpoint {
            return Err(AgentError::Transport(
                "AEP Platform command redirects are not allowed".to_owned(),
            ));
        }
        self.validate_response_size(&response.body)?;
        if !response.status.is_success() {
            let problem = media_type_matches(&response.headers, PROBLEM_MEDIA_TYPE)
                .then(|| parse_problem_details(&response.body).ok())
                .flatten()
                .filter(|problem| problem.status == i64::from(response.status.as_u16()))
                .map(Box::new);
            return Err(AgentError::PlatformCommand {
                status: response.status.as_u16(),
                problem,
            });
        }
        validate_media_type(&response.headers, MEDIA_TYPE, "command")?;
        let body = serde_json::from_slice(&response.body).map_err(|_| {
            AgentError::Identity("AEP Platform response is invalid JSON".to_owned())
        })?;
        Ok(PlatformCommandResult {
            body,
            headers: response.headers,
            status: response.status,
        })
    }

    async fn headers(&self) -> Result<HeaderMap, AgentError> {
        let mut headers = HeaderMap::new();
        if let Some(value) = &self.authorization {
            headers.insert(header::AUTHORIZATION, value.clone());
        }
        if let Some(provider) = &self.authentication_headers {
            for (name, value) in provider.headers().await? {
                let Some(name) = name else { continue };
                if name == header::ACCEPT
                    || name == header::CONTENT_TYPE
                    || name.as_str().eq_ignore_ascii_case("idempotency-key")
                {
                    continue;
                }
                headers.insert(name, value);
            }
        }
        Ok(headers)
    }

    async fn send(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: Vec<u8>,
    ) -> Result<HttpResponse, AgentError> {
        self.transport
            .send(HttpRequest {
                method,
                url,
                headers,
                body,
            })
            .await
            .map_err(|error| AgentError::Transport(error.to_string()))
    }

    fn endpoint(&self, path: &str, identity_id: Option<&str>) -> Result<Url, AgentError> {
        let path = match identity_id {
            Some(identity_id) => path.replace("{agent_identity_id}", &encode_path(identity_id)),
            None => path.to_owned(),
        };
        if !valid_endpoint_path(&path) || path.contains('{') {
            return Err(AgentError::Identity(
                "AEP Platform advertised an invalid endpoint".to_owned(),
            ));
        }
        let endpoint = self.platform_url.join(&path)?;
        if !same_origin(&endpoint, &self.platform_url) {
            return Err(AgentError::Identity(
                "AEP Platform endpoint changed origin".to_owned(),
            ));
        }
        Ok(endpoint)
    }

    fn agent_identity(&self, identity: PlatformAgentIdentity) -> Result<AgentIdentity, AgentError> {
        validate_platform_identity(&identity, self.allow_insecure_loopback)?;
        Ok(AgentIdentity {
            agent_did: identity.agent_did,
            identity_method: IdentityMethod::DidWeb,
            service_did: identity.service_did,
            signing_algorithms: identity.signing_algorithms,
            metadata: BTreeMap::from([
                ("agent_identity_id".to_owned(), identity.agent_identity_id),
                ("created_at".to_owned(), identity.created_at),
                ("did_document_url".to_owned(), identity.did_document_url),
                ("key_id".to_owned(), identity.key_id),
                ("platform_url".to_owned(), self.platform_url.to_string()),
                ("status".to_owned(), identity.status),
                ("updated_at".to_owned(), identity.updated_at),
            ]),
        })
    }

    fn validate_owned_identity(&self, identity: &AgentIdentity) -> Result<String, AgentError> {
        let Some(identity_id) = identity
            .metadata
            .get("agent_identity_id")
            .filter(|value| !value.is_empty())
            .cloned()
        else {
            return Err(AgentError::Identity(
                "AEP identity is not an active identity from this Platform".to_owned(),
            ));
        };
        if identity.identity_method != IdentityMethod::DidWeb
            || !identity.agent_did.starts_with("did:web:")
            || identity.service_did.is_empty()
            || identity.signing_algorithms.is_empty()
            || identity.metadata.get("platform_url") != Some(&self.platform_url.to_string())
            || identity.metadata.get("status").map(String::as_str) != Some("active")
        {
            return Err(AgentError::Identity(
                "AEP identity is not an active identity from this Platform".to_owned(),
            ));
        }
        Ok(identity_id)
    }

    fn validate_response_size(&self, body: &[u8]) -> Result<(), AgentError> {
        if body.len() > self.maximum_response_bytes {
            return Err(AgentError::Transport(
                "AEP Platform response exceeds the configured limit".to_owned(),
            ));
        }
        Ok(())
    }

    fn idempotency_key(&self) -> Result<String, AgentError> {
        let key = self.idempotency_keys.create_key()?;
        if key.trim().is_empty() {
            return Err(AgentError::InvalidConfiguration(
                "AEP Platform idempotency key provider returned an empty key".to_owned(),
            ));
        }
        Ok(key)
    }
}

#[async_trait]
impl IdentityProvider for PlatformIdentityProvider {
    async fn get_or_create_identity(
        &self,
        request: IdentityRequest,
    ) -> Result<AgentIdentity, AgentError> {
        let service_did = request.inspection.document.service.did;
        if let Some(identity) = self.find_identity_by_service_did(&service_did).await? {
            return Ok(identity);
        }
        let discovery = self.discover().await?;
        let endpoint = self.endpoint(&discovery.document.endpoints.provision, None)?;
        let key = self.idempotency_key()?;
        let provisioned: PlatformCommandResult<PlatformAgentIdentity> = self
            .command(
                Method::POST,
                endpoint,
                Some(&key),
                Some(serde_json::json!({ "service_did": service_did })),
            )
            .await?;
        if provisioned.body.service_did != service_did || provisioned.body.status != "active" {
            return Err(AgentError::Identity(
                "AEP Platform provisioned an identity outside the requested Service scope"
                    .to_owned(),
            ));
        }
        self.agent_identity(provisioned.body)
    }

    async fn signer_for(
        &self,
        identity: &AgentIdentity,
    ) -> Result<Arc<dyn AssertionSigner>, AgentError> {
        let identity_id = self.validate_owned_identity(identity)?;
        Ok(Arc::new(PlatformAssertionSigner {
            identity: identity.clone(),
            identity_id,
            provider: Arc::new(self.clone()),
        }))
    }
}

struct PlatformAssertionSigner {
    identity: AgentIdentity,
    identity_id: String,
    provider: Arc<PlatformIdentityProvider>,
}

#[async_trait]
impl AssertionSigner for PlatformAssertionSigner {
    async fn sign(
        &self,
        claims: &ClientAssertionClaims,
        algorithms: &[SigningAlgorithm],
    ) -> Result<String, AgentError> {
        if claims.iss != self.identity.agent_did
            || claims.sub != self.identity.agent_did
            || claims.aud != self.identity.service_did
        {
            return Err(AgentError::Identity(
                "AEP Platform signer received claims for another identity".to_owned(),
            ));
        }
        if !algorithms
            .iter()
            .any(|algorithm| self.identity.signing_algorithms.contains(algorithm))
        {
            return Err(AgentError::Identity(
                "AEP Platform and Service have no compatible signing algorithm".to_owned(),
            ));
        }
        let mut context = match &self.provider.platform_context {
            Some(provider) => provider.context(&self.identity, claims).await?,
            None => BTreeMap::new(),
        };
        let mut previous_key = None;
        loop {
            let key = self.provider.idempotency_key()?;
            if previous_key.as_ref() == Some(&key) {
                return Err(AgentError::InvalidConfiguration(
                    "AEP Platform pending Sign stages require distinct idempotency keys".to_owned(),
                ));
            }
            let result = self.sign_once(claims, context, &key).await?;
            if result.body.status == "completed" {
                if result.status != StatusCode::OK {
                    return Err(AgentError::Identity(
                        "AEP Platform returned an invalid completed Sign response".to_owned(),
                    ));
                }
                return validate_completed_sign(&result.body, claims, &self.identity);
            }
            if result.status != StatusCode::ACCEPTED
                || result.headers.contains_key(header::RETRY_AFTER)
            {
                return Err(AgentError::Identity(
                    "AEP Platform returned an invalid pending Sign response".to_owned(),
                ));
            }
            let retry_after = validate_pending_sign(&result.body)?;
            let pending = PlatformPendingSign {
                identity: self.identity.clone(),
                platform_context: result.body.platform_context,
                retry_after,
            };
            let Some(resolver) = &self.provider.pending_sign_resolver else {
                return Err(AgentError::PlatformSignPending {
                    pending: Box::new(pending),
                });
            };
            previous_key = Some(key);
            context = resolver.resolve(pending).await?;
        }
    }
}

impl PlatformAssertionSigner {
    async fn sign_once(
        &self,
        claims: &ClientAssertionClaims,
        platform_context: BTreeMap<String, Value>,
        key: &str,
    ) -> Result<PlatformCommandResult<PlatformSignResponse>, AgentError> {
        let discovery = self.provider.discover().await?;
        let endpoint = self
            .provider
            .endpoint(&discovery.document.endpoints.sign, Some(&self.identity_id))?;
        let lifetime = claims.exp.checked_sub(claims.iat).ok_or_else(|| {
            AgentError::Identity("AEP Platform signing lifetime is invalid".to_owned())
        })?;
        let mut body = serde_json::Map::from_iter([
            ("jti".to_owned(), Value::String(claims.jti.clone())),
            (
                "lifetime_seconds".to_owned(),
                Value::String(lifetime.to_string()),
            ),
            ("op".to_owned(), serde_json::to_value(claims.op)?),
            (
                "platform_context".to_owned(),
                serde_json::to_value(platform_context)?,
            ),
            ("service_did".to_owned(), Value::String(claims.aud.clone())),
        ]);
        if let Some(resource) = &claims.resource {
            body.insert("resource".to_owned(), Value::String(resource.clone()));
        }
        self.provider
            .command(Method::POST, endpoint, Some(key), Some(Value::Object(body)))
            .await
    }
}

struct RandomPlatformIdempotencyKeyProvider;

impl PlatformIdempotencyKeyProvider for RandomPlatformIdempotencyKeyProvider {
    fn create_key(&self) -> Result<String, AgentError> {
        Ok(Uuid::new_v4().to_string())
    }
}

#[derive(Clone, Debug, Deserialize)]
struct PlatformDiscovery {
    aep_version: String,
    endpoints: PlatformEndpoints,
    http: PlatformHttp,
    identity: PlatformIdentityConfiguration,
    platform: PlatformDescription,
    signing: PlatformSigning,
}

#[derive(Clone, Debug, Deserialize)]
struct PlatformEndpoints {
    hosted_verification: Option<String>,
    lifecycle: String,
    list: String,
    provision: String,
    sign: String,
}

#[derive(Clone, Debug, Deserialize)]
struct PlatformHttp {
    endpoint_base: String,
}

#[derive(Clone, Debug, Deserialize)]
struct PlatformIdentityConfiguration {
    did_methods: Vec<String>,
    did_url_template: String,
}

#[derive(Clone, Debug, Deserialize)]
struct PlatformDescription {
    did: Option<String>,
    hosted_verification: bool,
    name: String,
}

#[derive(Clone, Debug, Deserialize)]
struct PlatformSigning {
    algorithms: Vec<SigningAlgorithm>,
    default_lifetime_seconds: String,
}

#[derive(Clone, Debug, Deserialize)]
struct PlatformAgentIdentity {
    agent_did: String,
    agent_identity_id: String,
    created_at: String,
    did_document_url: String,
    key_id: String,
    service_did: String,
    signing_algorithms: Vec<SigningAlgorithm>,
    status: String,
    updated_at: String,
}

#[derive(Deserialize)]
struct PlatformIdentityList {
    count: String,
    data: Vec<PlatformAgentIdentity>,
    total: String,
}

#[derive(Deserialize)]
struct PlatformSignResponse {
    agent_did: Option<String>,
    client_assertion: Option<String>,
    expires_at: Option<String>,
    issued_at: Option<String>,
    jti: Option<String>,
    #[serde(default)]
    platform_context: BTreeMap<String, Value>,
    retry_after_seconds: Option<String>,
    service_did: Option<String>,
    status: String,
}

struct PlatformCommandResult<T> {
    body: T,
    headers: HeaderMap,
    status: StatusCode,
}

#[derive(Clone)]
struct DiscoveryCacheEntry {
    cache_control: Option<String>,
    cached_at: OffsetDateTime,
    document: PlatformDiscovery,
    etag: Option<String>,
    final_url: Url,
    last_modified: Option<String>,
}

fn platform_url(value: &str, allow_insecure_loopback: bool) -> Result<Url, AgentError> {
    let mut url = Url::parse(value.trim())
        .map_err(|_| AgentError::InvalidConfiguration("invalid AEP Platform URL".to_owned()))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
        || url.cannot_be_a_base()
        || (url.scheme() != "https"
            && !(allow_insecure_loopback && url.scheme() == "http" && is_loopback(&url)))
    {
        return Err(AgentError::InvalidConfiguration(
            "invalid AEP Platform URL".to_owned(),
        ));
    }
    url.set_path("/");
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

fn validate_discovery(
    document: &PlatformDiscovery,
    allow_insecure_loopback: bool,
) -> Result<(), AgentError> {
    let lifetime = document
        .signing
        .default_lifetime_seconds
        .parse::<u64>()
        .ok();
    let paths = [
        &document.http.endpoint_base,
        &document.endpoints.lifecycle,
        &document.endpoints.list,
        &document.endpoints.provision,
        &document.endpoints.sign,
    ];
    if !is_version_compatible(&document.aep_version, VERSION)
        || document.platform.name.is_empty()
        || document
            .identity
            .did_methods
            .iter()
            .all(|method| method != "did:web")
        || document.signing.algorithms.is_empty()
        || lifetime.is_none_or(|value| value == 0 || value > 300)
        || paths.iter().any(|path| !valid_endpoint_path(path))
        || document
            .endpoints
            .lifecycle
            .matches("{agent_identity_id}")
            .count()
            != 1
        || document
            .endpoints
            .sign
            .matches("{agent_identity_id}")
            .count()
            != 1
        || document.endpoints.list.contains('{')
        || document.endpoints.provision.contains('{')
        || document.http.endpoint_base.contains('{')
        || document
            .identity
            .did_url_template
            .matches("{agent_did_id}")
            .count()
            != 1
        || document.platform.hosted_verification != document.endpoints.hosted_verification.is_some()
        || document
            .platform
            .did
            .as_deref()
            .is_some_and(|did| !did.starts_with("did:"))
        || document.signing.algorithms.iter().any(|algorithm| {
            !matches!(algorithm, SigningAlgorithm::EdDsa | SigningAlgorithm::Es256)
        })
    {
        return invalid_discovery();
    }
    if document
        .endpoints
        .hosted_verification
        .as_deref()
        .is_some_and(|path| !valid_endpoint_path(path) || path.contains('{'))
    {
        return invalid_discovery();
    }
    let did_url = document
        .identity
        .did_url_template
        .replace("{agent_did_id}", "validation");
    let parsed = Url::parse(&did_url).map_err(|_| invalid_discovery_error())?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.host_str().is_none()
        || parsed.fragment().is_some()
        || (parsed.scheme() != "https"
            && !(allow_insecure_loopback && parsed.scheme() == "http" && is_loopback(&parsed)))
    {
        return invalid_discovery();
    }
    Ok(())
}

fn invalid_discovery<T>() -> Result<T, AgentError> {
    Err(invalid_discovery_error())
}

fn invalid_discovery_error() -> AgentError {
    AgentError::Identity("AEP Platform discovery document is invalid".to_owned())
}

fn validate_identity_list(
    response: &PlatformIdentityList,
    allow_insecure_loopback: bool,
) -> Result<(), AgentError> {
    let count = response.count.parse::<usize>().ok();
    let total = response.total.parse::<usize>().ok();
    if count != Some(response.data.len()) || total.is_none_or(|total| total < response.data.len()) {
        return Err(AgentError::Identity(
            "AEP Platform returned an invalid identity list".to_owned(),
        ));
    }
    for identity in &response.data {
        validate_platform_identity(identity, allow_insecure_loopback)?;
    }
    Ok(())
}

fn validate_platform_identity(
    identity: &PlatformAgentIdentity,
    allow_insecure_loopback: bool,
) -> Result<(), AgentError> {
    let valid_status = matches!(
        identity.status.as_str(),
        "active" | "revoked" | "suspended" | "terminated"
    );
    if identity.agent_identity_id.is_empty()
        || !identity.agent_did.starts_with("did:web:")
        || identity.key_id != identity.agent_did
        || !identity.service_did.starts_with("did:")
        || identity.signing_algorithms.is_empty()
        || identity.signing_algorithms.iter().any(|algorithm| {
            !matches!(algorithm, SigningAlgorithm::EdDsa | SigningAlgorithm::Es256)
        })
        || !valid_status
        || OffsetDateTime::parse(
            &identity.created_at,
            &time::format_description::well_known::Rfc3339,
        )
        .is_err()
        || OffsetDateTime::parse(
            &identity.updated_at,
            &time::format_description::well_known::Rfc3339,
        )
        .is_err()
    {
        return Err(AgentError::Identity(
            "AEP Platform returned an invalid identity".to_owned(),
        ));
    }
    let document_url = Url::parse(&identity.did_document_url).map_err(|_| {
        AgentError::Identity("AEP Platform returned an invalid DID document URL".to_owned())
    })?;
    let expected = did_web_document_url_with_options(
        &identity.agent_did,
        DidWebDocumentUrlOptions {
            allow_insecure_loopback,
        },
    )?;
    if document_url != expected {
        return Err(AgentError::Identity(
            "AEP Platform DID document URL does not match the Agent DID".to_owned(),
        ));
    }
    Ok(())
}

fn validate_completed_sign(
    response: &PlatformSignResponse,
    claims: &ClientAssertionClaims,
    identity: &AgentIdentity,
) -> Result<String, AgentError> {
    let issued_at = response.issued_at.as_deref().and_then(|value| {
        OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).ok()
    });
    let expires_at = response.expires_at.as_deref().and_then(|value| {
        OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).ok()
    });
    let Some(assertion) = response
        .client_assertion
        .as_deref()
        .filter(|assertion| !assertion.is_empty())
    else {
        return Err(AgentError::Identity(
            "AEP Platform returned an invalid completed Sign response".to_owned(),
        ));
    };
    if response.agent_did.as_deref() != Some(identity.agent_did.as_str())
        || response.service_did.as_deref() != Some(identity.service_did.as_str())
        || response.jti.as_deref() != Some(claims.jti.as_str())
        || issued_at.map(OffsetDateTime::unix_timestamp) != Some(claims.iat)
        || expires_at.map(OffsetDateTime::unix_timestamp) != Some(claims.exp)
    {
        return Err(AgentError::Identity(
            "AEP Platform returned an invalid completed Sign response".to_owned(),
        ));
    }
    Ok(assertion.to_owned())
}

fn validate_pending_sign(response: &PlatformSignResponse) -> Result<Duration, AgentError> {
    if response.status != "pending"
        || response.client_assertion.is_some()
        || response.agent_did.is_some()
        || response.service_did.is_some()
        || response.jti.is_some()
        || response.issued_at.is_some()
        || response.expires_at.is_some()
    {
        return Err(AgentError::Identity(
            "AEP Platform returned an invalid Sign status".to_owned(),
        ));
    }
    let seconds = response
        .retry_after_seconds
        .as_deref()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| (1..=300).contains(value))
        .ok_or_else(|| {
            AgentError::Identity(
                "AEP Platform returned an invalid pending Sign response".to_owned(),
            )
        })?;
    Ok(Duration::from_secs(seconds))
}

fn validate_did(value: &str, name: &str) -> Result<(), AgentError> {
    if !value.starts_with("did:") || value.len() <= 4 {
        return Err(AgentError::Identity(format!("invalid {name}")));
    }
    Ok(())
}

fn valid_endpoint_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("//")
        && Url::parse(&format!("https://validation.example{path}"))
            .is_ok_and(|url| url.query().is_none() && url.fragment().is_none())
}

fn encode_path(value: &str) -> String {
    percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
}

fn discovery_fresh(entry: &DiscoveryCacheEntry, now: OffsetDateTime) -> bool {
    if cache_directive(entry.cache_control.as_deref(), "no-cache").is_some()
        || cache_directive(entry.cache_control.as_deref(), "no-store").is_some()
    {
        return false;
    }
    let freshness = match cache_directive(entry.cache_control.as_deref(), "max-age") {
        Some(value) => match value.parse::<u64>() {
            Ok(value) => Duration::from_secs(value),
            Err(_) => return false,
        },
        None => DEFAULT_DISCOVERY_FRESHNESS,
    };
    let Ok(freshness) = time::Duration::try_from(freshness) else {
        return false;
    };
    entry
        .cached_at
        .checked_add(freshness)
        .is_some_and(|expires| expires > now)
}

fn cache_directive<'a>(value: Option<&'a str>, name: &str) -> Option<&'a str> {
    value?.split(',').find_map(|part| {
        let mut fields = part.trim().splitn(2, '=');
        let field = fields.next()?;
        field
            .eq_ignore_ascii_case(name)
            .then(|| fields.next().unwrap_or("").trim_matches('"'))
    })
}

fn merge_cache_headers(entry: &mut DiscoveryCacheEntry, headers: &HeaderMap) {
    if let Some(value) = header_string(headers, header::CACHE_CONTROL) {
        entry.cache_control = Some(value);
    }
    if let Some(value) = header_string(headers, header::ETAG) {
        entry.etag = Some(value);
    }
    if let Some(value) = header_string(headers, header::LAST_MODIFIED) {
        entry.last_modified = Some(value);
    }
}

fn validate_media_type(headers: &HeaderMap, expected: &str, kind: &str) -> Result<(), AgentError> {
    if media_type_matches(headers, expected) {
        return Ok(());
    }
    Err(AgentError::Transport(format!(
        "AEP Platform {kind} response media type is invalid"
    )))
}

fn media_type_matches(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case(expected))
}

fn safe_discovery_target(target: &Url, reference: &Url) -> bool {
    target.username().is_empty()
        && target.password().is_none()
        && target.fragment().is_none()
        && target.scheme() == reference.scheme()
        && same_origin(target, reference)
}

fn is_redirect(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

fn header_string(headers: &HeaderMap, name: header::HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn header_value(value: &str) -> Option<HeaderValue> {
    HeaderValue::from_str(value).ok()
}

#[cfg(test)]
#[path = "platform_provider_tests.rs"]
mod tests;
