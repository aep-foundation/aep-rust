use std::{collections::BTreeMap, sync::Arc, time::Duration};

use aep_core::{
    AssertionOperation, ClientAssertionClaims, ErrorCode, ProblemDetails, SigningAlgorithm,
    VerifyClientAssertionOptions, decode_jwt_unverified, new_problem_details,
    verify_client_assertion,
};
use futures::FutureExt as _;
use http::{HeaderMap, HeaderValue, header};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::{
    AgentIdentity, AgentIdentityListResponse, AuthorizationRequest, Authorizer, Clock,
    DID_MEDIA_TYPE, DefaultLifecyclePolicy, DidDocument, DiscoveryDocument, IdempotencyInput,
    IdempotencyResult, IdempotencyStore, IdempotentOperation, IdentityListQuery, IdentityRecord,
    IdentityStore, KeyStore, LifecyclePolicy, LifecycleRequest, ManagedAgentStatus,
    MemoryIdempotencyStore, MemoryIdentityStore, PlatformError, PlatformOptions, PlatformResponse,
    ReplayStore, RequestContext, ResponseBody, ServiceDidResolver, SignHandler, SignRequest,
    SignResponse, SignStatus, StoredResponse, SystemClock, VerificationRequest,
    VerificationResponse, create_did_document, create_discovery_document,
    create_service_scoped_agent_did, is_absolute_https_url, is_did, lifecycle_error_code,
    render_did_url,
};

const MAXIMUM_LIST_LIMIT: usize = 100;

pub struct Platform {
    agent_did_id_generator: Arc<dyn Fn() -> Result<String, PlatformError> + Send + Sync>,
    authorizer: Arc<dyn Authorizer>,
    clock: Arc<dyn Clock>,
    default_lifetime: Duration,
    did_host: String,
    did_path_prefix: String,
    did_url_template: String,
    discovery: DiscoveryDocument,
    hosted_verification: bool,
    identifier: Arc<dyn Fn() -> Result<String, PlatformError> + Send + Sync>,
    idempotency_store: Arc<dyn IdempotencyStore>,
    identity_store: Arc<dyn IdentityStore>,
    key_store: Arc<dyn KeyStore>,
    lifecycle_policy: Arc<dyn LifecyclePolicy>,
    maximum_lifetime: Duration,
    pub(crate) replay_store: Option<Arc<dyn ReplayStore>>,
    service_did_resolver: Arc<dyn ServiceDidResolver>,
    sign_handler: Option<Arc<dyn SignHandler>>,
    signing_algorithms: Vec<SigningAlgorithm>,
}

impl Platform {
    pub fn new(options: PlatformOptions) -> Result<Arc<Self>, PlatformError> {
        create_service_scoped_agent_did(&options.did_host, &options.did_path_prefix, "validation")?;
        validate_signing_algorithms(&options.signing_algorithms)?;
        validate_lifetime(
            "maximum",
            options.maximum_lifetime,
            aep_core::MAX_ASSERTION_LIFETIME,
        )?;
        validate_lifetime(
            "default",
            options.default_lifetime,
            options.maximum_lifetime,
        )?;
        if options.hosted_verification && options.replay_store.is_none() {
            return Err(PlatformError::InvalidConfiguration(
                "AEP Platform hosted verification requires a replay store".to_owned(),
            ));
        }
        let discovery = create_discovery_document(
            &options.discovery,
            &options.did_url_template,
            options.hosted_verification,
            options.signing_algorithms.clone(),
            options.default_lifetime,
        )?;
        let clock = options.clock.unwrap_or_else(|| Arc::new(SystemClock));
        let idempotency_store = options
            .idempotency_store
            .unwrap_or_else(|| Arc::new(MemoryIdempotencyStore::new(clock.clone())));
        Ok(Arc::new(Self {
            agent_did_id_generator: options
                .agent_did_id_generator
                .unwrap_or_else(|| Arc::new(random_identifier)),
            authorizer: options.authorizer,
            clock,
            default_lifetime: options.default_lifetime,
            did_host: options.did_host,
            did_path_prefix: options.did_path_prefix,
            did_url_template: options.did_url_template,
            discovery,
            hosted_verification: options.hosted_verification,
            identifier: options
                .identifier
                .unwrap_or_else(|| Arc::new(random_identifier)),
            idempotency_store,
            identity_store: options
                .identity_store
                .unwrap_or_else(|| Arc::new(MemoryIdentityStore::default())),
            key_store: options.key_store,
            lifecycle_policy: options
                .lifecycle_policy
                .unwrap_or_else(|| Arc::new(DefaultLifecyclePolicy)),
            maximum_lifetime: options.maximum_lifetime,
            replay_store: options.replay_store,
            service_did_resolver: options.service_did_resolver,
            sign_handler: options.sign_handler,
            signing_algorithms: options.signing_algorithms,
        }))
    }

    pub fn discovery(&self) -> PlatformResponse<DiscoveryDocument> {
        let mut response = success(200, self.discovery.clone());
        response.headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("max-age=300"),
        );
        response
    }

    pub async fn did_document(
        &self,
        agent_did_id: &str,
    ) -> Result<PlatformResponse<DidDocument>, PlatformError> {
        let Some(identity) = self
            .identity_store
            .find_by_agent_did_id(agent_did_id)
            .await?
        else {
            return Ok(problem(404, ErrorCode::NotRecognized));
        };
        if identity.status != ManagedAgentStatus::Active {
            return Ok(problem(404, ErrorCode::NotRecognized));
        }
        let method = self.key_store.did_verification_method(&identity).await?;
        let document = create_did_document(&identity, method)?;
        let mut response = success(200, document);
        response.headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(DID_MEDIA_TYPE),
        );
        response.headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("max-age=300"),
        );
        Ok(response)
    }

    pub async fn get_identity(
        &self,
        agent_identity_id: &str,
        context: &RequestContext,
    ) -> Result<PlatformResponse<AgentIdentity>, PlatformError> {
        let Some(identity) = self
            .authorized_identity(agent_identity_id, context, |identity| {
                AuthorizationRequest::GetIdentity { identity }
            })
            .await?
        else {
            return Ok(problem(404, ErrorCode::NotRecognized));
        };
        Ok(success(200, agent_identity(&identity)?))
    }

    pub async fn list(
        &self,
        mut query: IdentityListQuery,
        context: &RequestContext,
    ) -> Result<PlatformResponse<AgentIdentityListResponse>, PlatformError> {
        if query.limit > MAXIMUM_LIST_LIMIT
            || query
                .service_did
                .as_ref()
                .is_some_and(|service_did| !is_did(service_did))
        {
            return Ok(problem(400, ErrorCode::InvalidRequest));
        }
        if query.limit == 0 {
            query.limit = MAXIMUM_LIST_LIMIT;
        }
        let authorized = self
            .authorizer
            .authorize(
                &AuthorizationRequest::ListIdentities {
                    query: query.clone(),
                },
                context,
            )
            .await?;
        if !authorized || context.principal.is_empty() {
            return Ok(problem(404, ErrorCode::NotRecognized));
        }
        let result = self.identity_store.list(&context.principal, &query).await?;
        let data = result
            .identities
            .iter()
            .map(agent_identity)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(success(
            200,
            AgentIdentityListResponse {
                additional: BTreeMap::new(),
                count: data.len().to_string(),
                data,
                total: result.total.to_string(),
            },
        ))
    }

    pub async fn provision(
        self: &Arc<Self>,
        request: crate::ProvisionRequest,
        context: RequestContext,
    ) -> Result<PlatformResponse<AgentIdentity>, PlatformError> {
        if !is_did(&request.service_did) {
            return Ok(problem(400, ErrorCode::InvalidRequest));
        }
        let material = request.clone();
        let platform = self.clone();
        self.execute_idempotent(
            IdempotentOperation::Provision,
            &material,
            context.clone(),
            move || async move {
                let authorized = platform
                    .authorizer
                    .authorize(
                        &AuthorizationRequest::Provision {
                            request: request.clone(),
                        },
                        &context,
                    )
                    .await?;
                if !authorized {
                    return Ok(problem(404, ErrorCode::NotRecognized));
                }
                if !platform
                    .service_did_resolver
                    .resolve(&request.service_did)
                    .await?
                {
                    return Ok(problem(400, ErrorCode::InvalidRequest));
                }
                let creation_platform = platform.clone();
                let principal = context.principal.clone();
                let service_did = request.service_did.clone();
                let creation_principal = principal.clone();
                let creation_service_did = service_did.clone();
                let identity = platform
                    .identity_store
                    .find_or_create(
                        &principal,
                        &service_did,
                        Box::new(move || {
                            async move {
                                creation_platform
                                    .create_identity(creation_principal, creation_service_did)
                                    .await
                            }
                            .boxed()
                        }),
                    )
                    .await?;
                Ok(success(200, agent_identity(&identity)?))
            },
        )
        .await
    }

    pub async fn sign(
        self: &Arc<Self>,
        agent_identity_id: &str,
        request: SignRequest,
        context: RequestContext,
    ) -> Result<PlatformResponse<SignResponse>, PlatformError> {
        let lifetime = match self.sign_lifetime(&request) {
            Ok(lifetime) => lifetime,
            Err(_) => return Ok(problem(400, ErrorCode::InvalidRequest)),
        };
        #[derive(Serialize)]
        struct SignMaterial {
            agent_identity_id: String,
            request: SignRequest,
        }
        let material = SignMaterial {
            agent_identity_id: agent_identity_id.to_owned(),
            request: request.clone(),
        };
        let platform = self.clone();
        let agent_identity_id = agent_identity_id.to_owned();
        self.execute_idempotent(
            IdempotentOperation::Sign,
            &material,
            context.clone(),
            move || async move {
                let Some(identity) = platform
                    .authorized_identity(&agent_identity_id, &context, |identity| {
                        AuthorizationRequest::Sign {
                            identity,
                            request: request.clone(),
                        }
                    })
                    .await?
                else {
                    return Ok(problem(404, ErrorCode::NotRecognized));
                };
                if identity.service_did != request.service_did {
                    return Ok(problem(404, ErrorCode::NotRecognized));
                }
                if !platform
                    .lifecycle_policy
                    .can_sign(&identity, &context)
                    .await?
                {
                    return Ok(problem(403, lifecycle_error_code(identity.status)));
                }
                if let Some(handler) = &platform.sign_handler
                    && let Some(response) = handler.sign(&identity, &request, &context).await?
                {
                    validate_sign_response(&response, &identity, &request)?;
                    return Ok(response);
                }
                let now = context.now.unwrap_or_else(|| platform.clock.now());
                let expires_at = now + lifetime;
                let claims = ClientAssertionClaims {
                    additional: BTreeMap::new(),
                    aud: request.service_did.clone(),
                    exp: expires_at.unix_timestamp(),
                    iat: now.unix_timestamp(),
                    iss: identity.agent_did.clone(),
                    jti: request.jti.clone(),
                    op: request.op,
                    resource: request.resource.clone(),
                    sub: identity.agent_did.clone(),
                };
                let assertion = platform.key_store.sign(&identity, &claims).await?;
                if assertion.is_empty() {
                    return Err(PlatformError::Handler(
                        "AEP Platform key store returned an empty assertion".to_owned(),
                    ));
                }
                Ok(success(
                    200,
                    SignResponse {
                        additional: BTreeMap::new(),
                        agent_did: Some(identity.agent_did),
                        client_assertion: Some(assertion),
                        expires_at: Some(format_time(expires_at)?),
                        issued_at: Some(format_time(now)?),
                        jti: Some(request.jti),
                        platform_context: request.platform_context,
                        retry_after_seconds: None,
                        service_did: Some(request.service_did),
                        status: SignStatus::Completed,
                    },
                ))
            },
        )
        .await
    }

    pub async fn update_identity(
        &self,
        agent_identity_id: &str,
        request: LifecycleRequest,
        context: &RequestContext,
    ) -> Result<PlatformResponse<AgentIdentity>, PlatformError> {
        let Some(identity) = self
            .authorized_identity(agent_identity_id, context, |identity| {
                AuthorizationRequest::UpdateIdentity {
                    identity,
                    request: request.clone(),
                }
            })
            .await?
        else {
            return Ok(problem(404, ErrorCode::NotRecognized));
        };
        if !self
            .lifecycle_policy
            .can_transition(&identity, request.status, context)
            .await?
        {
            return Ok(problem(403, lifecycle_error_code(identity.status)));
        }
        let Some(updated) = self
            .identity_store
            .update_status(agent_identity_id, request.status, self.clock.now())
            .await?
        else {
            return Ok(problem(404, ErrorCode::NotRecognized));
        };
        Ok(success(200, agent_identity(&updated)?))
    }

    pub async fn verify(
        self: &Arc<Self>,
        request: VerificationRequest,
        context: RequestContext,
    ) -> Result<PlatformResponse<VerificationResponse>, PlatformError> {
        if !self.hosted_verification {
            return Ok(problem(404, ErrorCode::NotRecognized));
        }
        if request.client_assertion.is_empty()
            || !is_did(&request.service_did)
            || match (&request.op, &request.resource) {
                (AssertionOperation::Authenticate, Some(resource)) => {
                    !is_absolute_https_url(resource)
                }
                (AssertionOperation::Authenticate, None) => true,
                (_, Some(_)) => true,
                (_, None) => false,
            }
        {
            return Ok(problem(400, ErrorCode::InvalidRequest));
        }
        let material = request.clone();
        let platform = self.clone();
        self.execute_idempotent(
            IdempotentOperation::HostedVerification,
            &material,
            context.clone(),
            move || async move { platform.verify_assertion(request, context).await },
        )
        .await
    }

    async fn verify_assertion(
        &self,
        request: VerificationRequest,
        context: RequestContext,
    ) -> Result<PlatformResponse<VerificationResponse>, PlatformError> {
        let unrecognized = || {
            success(
                200,
                VerificationResponse {
                    additional: BTreeMap::new(),
                    agent_did: None,
                    agent_identity_id: None,
                    op: None,
                    reason: "not_recognized".to_owned(),
                    service_did: request.service_did.clone(),
                    status: None,
                    verified: false,
                },
            )
        };
        let Ok(decoded) = decode_jwt_unverified(&request.client_assertion) else {
            return Ok(unrecognized());
        };
        let Some(agent_did) = decoded
            .payload
            .get("iss")
            .and_then(serde_json::Value::as_str)
        else {
            return Ok(unrecognized());
        };
        let subject = decoded
            .payload
            .get("sub")
            .and_then(serde_json::Value::as_str);
        if subject != Some(agent_did) || decoded.header.key_id.as_deref() != Some(agent_did) {
            return Ok(unrecognized());
        }
        let Some(identity) = self.identity_store.find_by_agent_did(agent_did).await? else {
            return Ok(unrecognized());
        };
        if identity.service_did != request.service_did
            || identity.principal != context.principal
            || context.principal.is_empty()
        {
            return Ok(unrecognized());
        }
        let authorized = self
            .authorizer
            .authorize(
                &AuthorizationRequest::Verify {
                    identity: identity.clone(),
                    request: request.clone(),
                },
                &context,
            )
            .await?;
        if !authorized
            || !self
                .lifecycle_policy
                .can_verify(&identity, &context)
                .await?
        {
            return Ok(unrecognized());
        }
        let key = self.key_store.verification_key(&identity).await?;
        let now = context.now.unwrap_or_else(|| self.clock.now());
        let verified = verify_client_assertion(
            &request.client_assertion,
            &key,
            &VerifyClientAssertionOptions {
                algorithms: identity.signing_algorithms.clone(),
                audience: Some(request.service_did.clone()),
                current_time: Some(now.unix_timestamp()),
                issuer: Some(agent_did.to_owned()),
                operation: Some(request.op),
                resource: request.resource.clone(),
                subject: Some(agent_did.to_owned()),
                ..VerifyClientAssertionOptions::default()
            },
        );
        let Ok(claims) = verified else {
            return Ok(unrecognized());
        };
        if request.op != AssertionOperation::Authenticate && claims.resource.is_some() {
            return Ok(unrecognized());
        }
        let replay_key = format!(
            "{}\0{}\0{}\0{}",
            request.service_did,
            request.op.as_str(),
            agent_did,
            claims.jti
        );
        let Some(replay_store) = &self.replay_store else {
            return Err(PlatformError::InvalidConfiguration(
                "AEP Platform hosted verification requires a replay store".to_owned(),
            ));
        };
        let expires_at = OffsetDateTime::from_unix_timestamp(claims.exp)
            .map_err(|error| PlatformError::Handler(error.to_string()))?;
        if !replay_store.consume(&replay_key, expires_at, now).await? {
            return Ok(unrecognized());
        }
        Ok(success(
            200,
            VerificationResponse {
                additional: BTreeMap::new(),
                agent_did: Some(identity.agent_did),
                agent_identity_id: Some(identity.agent_identity_id),
                op: Some(request.op),
                reason: "verified".to_owned(),
                service_did: request.service_did,
                status: Some(identity.status),
                verified: true,
            },
        ))
    }

    async fn create_identity(
        &self,
        principal: String,
        service_did: String,
    ) -> Result<IdentityRecord, PlatformError> {
        let mut agent_identity_id = (self.identifier)()?;
        if agent_identity_id.is_empty() {
            return Err(PlatformError::Handler(
                "AEP Platform identity generator returned an empty identifier".to_owned(),
            ));
        }
        if !agent_identity_id.starts_with("pai_") {
            agent_identity_id = format!("pai_{agent_identity_id}");
        }
        let agent_did_id = (self.agent_did_id_generator)()?;
        let agent_did =
            create_service_scoped_agent_did(&self.did_host, &self.did_path_prefix, &agent_did_id)?;
        let now = self.clock.now();
        let identity = IdentityRecord {
            agent_did: agent_did.clone(),
            agent_did_id: agent_did_id.clone(),
            agent_identity_id,
            created_at: now,
            did_document_url: render_did_url(&self.did_url_template, &agent_did_id)?,
            key_id: agent_did,
            principal,
            service_did,
            signing_algorithms: self.signing_algorithms.clone(),
            status: ManagedAgentStatus::Active,
            updated_at: now,
        };
        self.key_store.create_key(&identity).await?;
        Ok(identity)
    }

    async fn authorized_identity(
        &self,
        agent_identity_id: &str,
        context: &RequestContext,
        request: impl FnOnce(IdentityRecord) -> AuthorizationRequest,
    ) -> Result<Option<IdentityRecord>, PlatformError> {
        let Some(identity) = self.identity_store.get(agent_identity_id).await? else {
            return Ok(None);
        };
        let authorized = self
            .authorizer
            .authorize(&request(identity.clone()), context)
            .await?;
        if !authorized || context.principal.is_empty() || identity.principal != context.principal {
            return Ok(None);
        }
        Ok(Some(identity))
    }

    fn sign_lifetime(&self, request: &SignRequest) -> Result<Duration, PlatformError> {
        if request.jti.is_empty() || !is_did(&request.service_did) {
            return Err(PlatformError::InvalidConfiguration(
                "AEP Platform signing request is invalid".to_owned(),
            ));
        }
        match (&request.op, &request.resource) {
            (AssertionOperation::Authenticate, Some(resource))
                if is_absolute_https_url(resource) => {}
            (AssertionOperation::Authenticate, _) => {
                return Err(PlatformError::InvalidConfiguration(
                    "AEP Platform authenticate signing requires an HTTPS resource".to_owned(),
                ));
            }
            (_, None) => {}
            (_, Some(_)) => {
                return Err(PlatformError::InvalidConfiguration(
                    "AEP Platform resource is only permitted for authenticate".to_owned(),
                ));
            }
        }
        let Some(seconds) = &request.lifetime_seconds else {
            return Ok(self.default_lifetime);
        };
        let seconds = seconds.parse::<u64>().map_err(|_| {
            PlatformError::InvalidConfiguration(
                "AEP Platform lifetime_seconds must be a positive integer string".to_owned(),
            )
        })?;
        let lifetime = Duration::from_secs(seconds);
        validate_lifetime("requested", lifetime, self.maximum_lifetime)?;
        Ok(lifetime)
    }

    async fn execute_idempotent<T, M, Execute, Future>(
        &self,
        operation: IdempotentOperation,
        material: &M,
        context: RequestContext,
        execute: Execute,
    ) -> Result<PlatformResponse<T>, PlatformError>
    where
        T: DeserializeOwned + Serialize + Send + 'static,
        M: Serialize + ?Sized,
        Execute: FnOnce() -> Future + Send + 'static,
        Future: std::future::Future<Output = Result<PlatformResponse<T>, PlatformError>>
            + Send
            + 'static,
    {
        let Some(idempotency_key) = context.idempotency_key.clone() else {
            return Ok(problem(400, ErrorCode::InvalidRequest));
        };
        if idempotency_key.is_empty() || context.principal.is_empty() {
            return Ok(problem(400, ErrorCode::InvalidRequest));
        }
        let request_hash = format!("{:x}", Sha256::digest(serde_json::to_vec(material)?));
        let result = self
            .idempotency_store
            .execute(
                IdempotencyInput {
                    idempotency_key,
                    operation,
                    principal: context.principal,
                    request_hash,
                },
                Box::new(move || {
                    async move {
                        let response = execute().await?;
                        store_response(response)
                    }
                    .boxed()
                }),
            )
            .await?;
        match result {
            IdempotencyResult::Conflict => Ok(problem(409, ErrorCode::IdempotencyConflict)),
            IdempotencyResult::Created(response) | IdempotencyResult::Replayed(response) => {
                restore_response(response)
            }
        }
    }
}

pub(crate) fn success<T>(status: u16, body: T) -> PlatformResponse<T> {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(aep_core::MEDIA_TYPE),
    );
    PlatformResponse {
        body: ResponseBody::Success(body),
        headers,
        status,
    }
}

pub(crate) fn problem<T>(status: u16, code: ErrorCode) -> PlatformResponse<T> {
    let title = code
        .as_str()
        .split('_')
        .map(|part| {
            let mut characters = part.chars();
            characters.next().map_or_else(String::new, |first| {
                first.to_uppercase().collect::<String>() + characters.as_str()
            })
        })
        .collect::<Vec<_>>()
        .join(" ");
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(aep_core::PROBLEM_MEDIA_TYPE),
    );
    PlatformResponse {
        body: ResponseBody::Problem(Box::new(new_problem_details(
            code,
            title,
            i64::from(status),
        ))),
        headers,
        status,
    }
}

fn store_response<T: Serialize>(
    response: PlatformResponse<T>,
) -> Result<StoredResponse, PlatformError> {
    let content_type = response
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or(aep_core::MEDIA_TYPE)
        .to_owned();
    let body = match response.body {
        ResponseBody::Success(body) => serde_json::to_vec(&body)?,
        ResponseBody::Problem(body) => serde_json::to_vec(&body)?,
    };
    Ok(StoredResponse {
        body,
        content_type,
        created_at: OffsetDateTime::UNIX_EPOCH,
        headers: response.headers,
        status: response.status,
    })
}

fn restore_response<T: DeserializeOwned>(
    stored: StoredResponse,
) -> Result<PlatformResponse<T>, PlatformError> {
    let body = if stored.content_type == aep_core::PROBLEM_MEDIA_TYPE {
        ResponseBody::Problem(Box::new(serde_json::from_slice::<ProblemDetails>(
            &stored.body,
        )?))
    } else {
        ResponseBody::Success(serde_json::from_slice(&stored.body)?)
    };
    Ok(PlatformResponse {
        body,
        headers: stored.headers,
        status: stored.status,
    })
}

fn agent_identity(identity: &IdentityRecord) -> Result<AgentIdentity, PlatformError> {
    Ok(AgentIdentity {
        additional: BTreeMap::new(),
        agent_did: identity.agent_did.clone(),
        agent_identity_id: identity.agent_identity_id.clone(),
        created_at: format_time(identity.created_at)?,
        did_document_url: identity.did_document_url.clone(),
        key_id: identity.key_id.clone(),
        service_did: identity.service_did.clone(),
        signing_algorithms: identity.signing_algorithms.clone(),
        status: identity.status,
        updated_at: format_time(identity.updated_at)?,
    })
}

fn validate_signing_algorithms(algorithms: &[SigningAlgorithm]) -> Result<(), PlatformError> {
    if algorithms.is_empty()
        || algorithms.iter().enumerate().any(|(index, algorithm)| {
            !matches!(algorithm, SigningAlgorithm::EdDsa | SigningAlgorithm::Es256)
                || algorithms[..index].contains(algorithm)
        })
    {
        return Err(PlatformError::InvalidConfiguration(
            "AEP Platform requires unique supported signing algorithms".to_owned(),
        ));
    }
    Ok(())
}

fn validate_lifetime(
    name: &str,
    lifetime: Duration,
    maximum: Duration,
) -> Result<(), PlatformError> {
    if lifetime.is_zero()
        || lifetime > maximum
        || lifetime > aep_core::MAX_ASSERTION_LIFETIME
        || lifetime.subsec_nanos() != 0
    {
        return Err(PlatformError::InvalidConfiguration(format!(
            "AEP Platform {name} assertion lifetime must be whole seconds within the supported maximum"
        )));
    }
    Ok(())
}

fn validate_sign_response(
    response: &PlatformResponse<SignResponse>,
    identity: &IdentityRecord,
    request: &SignRequest,
) -> Result<(), PlatformError> {
    match &response.body {
        ResponseBody::Problem(problem) => {
            if response.status != u16::try_from(problem.status).unwrap_or_default() {
                return Err(PlatformError::Handler(
                    "AEP Platform sign handler returned invalid Problem Details".to_owned(),
                ));
            }
        }
        ResponseBody::Success(body) if body.status == SignStatus::Pending => {
            let retry = body
                .retry_after_seconds
                .as_deref()
                .and_then(|value| value.parse::<u16>().ok());
            if response.status != 202
                || !matches!(retry, Some(1..=300))
                || response.headers.contains_key(header::RETRY_AFTER)
                || body.agent_did.is_some()
                || body.client_assertion.is_some()
                || body.expires_at.is_some()
                || body.issued_at.is_some()
                || body.jti.is_some()
                || body.service_did.is_some()
            {
                return Err(PlatformError::Handler(
                    "AEP Platform sign handler returned an invalid pending response".to_owned(),
                ));
            }
        }
        ResponseBody::Success(body) => {
            let issued_at = body
                .issued_at
                .as_deref()
                .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok());
            let expires_at = body
                .expires_at
                .as_deref()
                .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok());
            if response.status != 200
                || body.status != SignStatus::Completed
                || body.agent_did.as_deref() != Some(&identity.agent_did)
                || body.client_assertion.as_deref().is_none_or(str::is_empty)
                || body.jti.as_deref() != Some(&request.jti)
                || body.service_did.as_deref() != Some(&request.service_did)
                || !matches!((issued_at, expires_at), (Some(issued), Some(expires)) if expires > issued && expires - issued <= aep_core::MAX_ASSERTION_LIFETIME)
                || body.retry_after_seconds.is_some()
            {
                return Err(PlatformError::Handler(
                    "AEP Platform sign handler returned an invalid completed response".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn format_time(value: OffsetDateTime) -> Result<String, PlatformError> {
    value
        .format(&Rfc3339)
        .map_err(|error| PlatformError::Handler(error.to_string()))
}

fn random_identifier() -> Result<String, PlatformError> {
    Ok(Uuid::new_v4().simple().to_string())
}
