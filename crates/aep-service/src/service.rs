use std::{collections::BTreeMap, sync::Arc};

use aep_core::{
    AgentStatus, AssertionOperation, Authentication, AuthenticationMethod, Binding, Bindings,
    Command, Commands, CoreConfiguration, EnrollRequest, EnrollResponse, EnrollmentDecisionStatus,
    ErrorCode, Extensions, GrantType, HttpConfiguration, Identity, InspectClaims, InspectDocument,
    RevokeResponse, ServiceIdentity, StatusResponse, StringBoolean, VERSION,
    missing_required_claim_names, parse_enroll_request, parse_grant_request, parse_revoke_request,
    validate_inspect_document,
};
use futures::FutureExt as _;
use http::{HeaderMap, HeaderValue, header};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use time::format_description::well_known::Rfc3339;

use crate::{
    AuthenticatedCommandOptions, AuthenticatedPrincipal, AuthenticationKind,
    ClientAssertionReplayStore, Clock, CommandIdempotencyInput, CommandIdempotencyResult,
    CommandIdempotencyStore, EnrollmentPolicy, EnrollmentRecord, EnrollmentStore, GrantContext,
    IdempotentCommand, IdempotentCommandOptions, MemoryClientAssertionReplayStore,
    MemoryCommandIdempotencyStore, MemoryEnrollmentStore, ProtectedResourceAuthentication,
    ProtectedResourceRequest, ResponseBody, ServiceConfiguration, ServiceError, ServiceOptions,
    ServiceResponse, StaticEnrollmentPolicy, SystemClock,
    authentication::{
        AssertionAuthentication, SelectedAuthorization, authenticate_assertion,
        select_authorization,
    },
    problem,
};

pub struct Service {
    clock: Arc<dyn Clock>,
    configuration: ServiceConfiguration,
    enrollment_policy: Arc<dyn EnrollmentPolicy>,
    enrollment_store: Arc<dyn EnrollmentStore>,
    idempotency_store: Arc<dyn CommandIdempotencyStore>,
    replay_store: Arc<dyn ClientAssertionReplayStore>,
    verifier: Arc<dyn crate::ClientAssertionVerifier>,
    allow_insecure_loopback: bool,
}

impl Service {
    pub fn new(options: ServiceOptions) -> Result<Arc<Self>, ServiceError> {
        let configuration = build_configuration(&options)?;
        Ok(Arc::new(Self {
            allow_insecure_loopback: options.allow_insecure_loopback,
            clock: options.clock.unwrap_or_else(|| Arc::new(SystemClock)),
            configuration,
            enrollment_policy: options
                .enrollment_policy
                .unwrap_or_else(|| Arc::new(StaticEnrollmentPolicy::default())),
            enrollment_store: options
                .enrollment_store
                .unwrap_or_else(|| Arc::new(MemoryEnrollmentStore::default())),
            idempotency_store: options
                .idempotency_store
                .unwrap_or_else(|| Arc::new(MemoryCommandIdempotencyStore::default())),
            replay_store: options
                .replay_store
                .unwrap_or_else(|| Arc::new(MemoryClientAssertionReplayStore::default())),
            verifier: options.verifier,
        }))
    }

    pub fn inspect_document(&self) -> InspectDocument {
        self.configuration.inspect_document.clone()
    }

    pub async fn enroll(
        self: &Arc<Self>,
        request: &[u8],
        options: IdempotentCommandOptions,
    ) -> Result<ServiceResponse, ServiceError> {
        let Some(claims) = self
            .authenticate_command(
                &options.client_assertion,
                AssertionOperation::Enroll,
                Some(&options.idempotency_key),
            )
            .await?
        else {
            return Ok(problem(ErrorCode::NotRecognized, 401));
        };
        let Ok(request) = parse_enroll_request(request) else {
            return Ok(problem(ErrorCode::InvalidRequest, 400));
        };
        if request.agent_did != claims.sub || options.idempotency_key.is_empty() {
            return Ok(if options.idempotency_key.is_empty() {
                problem(ErrorCode::InvalidRequest, 400)
            } else {
                problem(ErrorCode::NotRecognized, 401)
            });
        }
        if request
            .idempotency_key
            .as_ref()
            .is_some_and(|key| key != &options.idempotency_key)
        {
            return Ok(problem(ErrorCode::InvalidRequest, 400));
        }
        let input = idempotency_input(
            &claims.sub,
            IdempotentCommand::Enroll,
            &options.idempotency_key,
            &request,
        )?;
        let service = self.clone();
        let result = self
            .idempotency_store
            .execute(
                input,
                Box::new(move || async move { service.execute_enroll(request).await }.boxed()),
            )
            .await?;
        Ok(idempotency_response(result))
    }

    pub async fn status(
        &self,
        options: AuthenticatedCommandOptions,
    ) -> Result<ServiceResponse, ServiceError> {
        let Some(claims) = self
            .authenticate_command(&options.client_assertion, AssertionOperation::Status, None)
            .await?
        else {
            return Ok(problem(ErrorCode::NotRecognized, 401));
        };
        let Some(enrollment) = self.enrollment_store.find(&claims.sub).await? else {
            return Ok(problem(ErrorCode::NotRecognized, 401));
        };
        Ok(success(ResponseBody::Status(status_response(&enrollment))))
    }

    pub async fn grant(
        self: &Arc<Self>,
        request: &[u8],
        options: IdempotentCommandOptions,
    ) -> Result<ServiceResponse, ServiceError> {
        let Some(claims) = self
            .authenticate_command(
                &options.client_assertion,
                AssertionOperation::Grant,
                Some(&options.idempotency_key),
            )
            .await?
        else {
            return Ok(problem(ErrorCode::NotRecognized, 401));
        };
        let Ok(request) = parse_grant_request(request) else {
            return Ok(problem(ErrorCode::InvalidRequest, 400));
        };
        if options.idempotency_key.is_empty() {
            return Ok(problem(ErrorCode::InvalidRequest, 400));
        }
        let Some(enrollment) = self.enrollment_store.find(&claims.sub).await? else {
            return Ok(problem(ErrorCode::NotRecognized, 401));
        };
        if let Some(response) = blocked_enrollment(&enrollment) {
            return Ok(response);
        }
        let Some(handler) = self
            .configuration
            .grant_handlers
            .get(request.grant_type.as_str())
            .cloned()
        else {
            return Ok(problem(ErrorCode::UnsupportedGrantType, 400));
        };
        let input = idempotency_input(
            &claims.sub,
            IdempotentCommand::Grant,
            &options.idempotency_key,
            &request,
        )?;
        let agent_did = claims.sub;
        let result = self
            .idempotency_store
            .execute(
                input,
                Box::new(move || {
                    async move {
                        let context = GrantContext {
                            agent_did,
                            enrollment,
                            grant_type: request.grant_type.clone(),
                        };
                        let response = handler.grant(&request, &context).await?;
                        if !response.as_object().is_some_and(|response| {
                            response
                                .get("credential_id")
                                .and_then(Value::as_str)
                                .is_some_and(|credential_id| !credential_id.is_empty())
                        }) {
                            return Err(ServiceError::Handler(
                                "Grant handler response requires a non-empty credential_id"
                                    .to_owned(),
                            ));
                        }
                        Ok(success(ResponseBody::Grant(response)))
                    }
                    .boxed()
                }),
            )
            .await?;
        Ok(idempotency_response(result))
    }

    pub async fn revoke(
        self: &Arc<Self>,
        request: &[u8],
        options: IdempotentCommandOptions,
    ) -> Result<ServiceResponse, ServiceError> {
        let Some(claims) = self
            .authenticate_command(
                &options.client_assertion,
                AssertionOperation::Revoke,
                Some(&options.idempotency_key),
            )
            .await?
        else {
            return Ok(problem(ErrorCode::NotRecognized, 401));
        };
        let Ok(request) = parse_revoke_request(request) else {
            return Ok(problem(ErrorCode::InvalidRequest, 400));
        };
        if options.idempotency_key.is_empty() {
            return Ok(problem(ErrorCode::InvalidRequest, 400));
        }
        let Some(enrollment) = self.enrollment_store.find(&claims.sub).await? else {
            return Ok(problem(ErrorCode::NotRecognized, 401));
        };
        let handlers = match &request.grant_type {
            Some(grant_type) => {
                let Some(handler) = self
                    .configuration
                    .grant_handlers
                    .get(grant_type.as_str())
                    .cloned()
                else {
                    return Ok(problem(ErrorCode::UnsupportedGrantType, 400));
                };
                vec![(grant_type.clone(), handler)]
            }
            None => self
                .configuration
                .grant_handlers
                .iter()
                .map(|(grant_type, handler)| (GrantType::from(grant_type.clone()), handler.clone()))
                .collect(),
        };
        let input = idempotency_input(
            &claims.sub,
            IdempotentCommand::Revoke,
            &options.idempotency_key,
            &request,
        )?;
        let agent_did = claims.sub;
        let result = self
            .idempotency_store
            .execute(
                input,
                Box::new(move || {
                    async move {
                        for (grant_type, handler) in handlers {
                            let context = GrantContext {
                                agent_did: agent_did.clone(),
                                enrollment: enrollment.clone(),
                                grant_type,
                            };
                            handler.revoke(&request, &context).await?;
                        }
                        Ok(success(ResponseBody::Revoke(RevokeResponse::default())))
                    }
                    .boxed()
                }),
            )
            .await?;
        Ok(idempotency_response(result))
    }

    pub async fn authenticate_protected_resource(
        &self,
        request: ProtectedResourceRequest,
    ) -> Result<ProtectedResourceAuthentication, ServiceError> {
        let selected = match select_authorization(&request.headers) {
            Ok(selected) => selected,
            Err(()) => return Ok(self.authentication_failure(ErrorCode::NotRecognized, &request)),
        };
        if let SelectedAuthorization::Aep(assertion) = selected {
            if !self
                .configuration
                .authentication_methods
                .contains(&AuthenticationMethod::AepJwt)
            {
                return Ok(self
                    .authentication_failure(ErrorCode::UnsupportedAuthenticationMethod, &request));
            }
            let Some(claims) = self
                .authenticate_assertion(
                    &assertion,
                    AssertionOperation::Authenticate,
                    None,
                    Some(&request.url),
                )
                .await?
            else {
                return Ok(self.authentication_failure(ErrorCode::NotRecognized, &request));
            };
            let Some(enrollment) = self.enrollment_store.find(&claims.sub).await? else {
                return Ok(self.authentication_failure(ErrorCode::NotRecognized, &request));
            };
            if enrollment.status != AgentStatus::Active {
                return Ok(self.authentication_failure(ErrorCode::NotRecognized, &request));
            }
            return Ok(ProtectedResourceAuthentication::Authenticated(
                AuthenticatedPrincipal {
                    agent_did: claims.sub,
                    authentication_kind: AuthenticationKind::ClientAssertion,
                    authentication_method: AuthenticationMethod::AepJwt,
                    credential_id: None,
                    grant_type: None,
                    scopes: Vec::new(),
                },
            ));
        }
        if let SelectedAuthorization::Session(method) = &selected
            && !self.configuration.authentication_methods.contains(method)
        {
            return Ok(
                self.authentication_failure(ErrorCode::UnsupportedAuthenticationMethod, &request)
            );
        }
        let input = crate::CredentialAuthenticationInput {
            headers: request.headers.clone(),
            now: self.clock.now(),
        };
        let mut presented = matches!(selected, SelectedAuthorization::Session(_));
        for method in &self.configuration.authentication_methods {
            if method == &AuthenticationMethod::AepJwt {
                continue;
            }
            let Some(handler) = self.configuration.grant_handlers.get(method.as_str()) else {
                continue;
            };
            presented |= handler.has_presentation(&input).await?;
            if let Some(principal) = handler.authenticate(&input).await? {
                if principal.agent_did.is_empty()
                    || principal.authentication_kind != AuthenticationKind::SessionCredential
                    || principal.authentication_method != *method
                    || principal.grant_type.as_ref().map(GrantType::as_str) != Some(method.as_str())
                {
                    return Ok(self.authentication_failure(ErrorCode::NotRecognized, &request));
                }
                let Some(enrollment) = self.enrollment_store.find(&principal.agent_did).await?
                else {
                    return Ok(self.authentication_failure(ErrorCode::NotRecognized, &request));
                };
                if enrollment.status != AgentStatus::Active {
                    return Ok(self.authentication_failure(ErrorCode::NotRecognized, &request));
                }
                return Ok(ProtectedResourceAuthentication::Authenticated(principal));
            }
        }
        let code = if presented {
            ErrorCode::NotRecognized
        } else {
            ErrorCode::AuthenticationRequired
        };
        Ok(self.authentication_failure(code, &request))
    }

    async fn execute_enroll(
        &self,
        request: EnrollRequest,
    ) -> Result<ServiceResponse, ServiceError> {
        if let Some(existing) = self.enrollment_store.find(&request.agent_did).await? {
            return Ok(success(ResponseBody::Enroll(enroll_response(&existing))));
        }
        let missing = missing_required_claim_names(
            &self.configuration.claims.required,
            request.claims.as_ref(),
        );
        if !missing.is_empty() {
            let mut response = problem(ErrorCode::RequirementsUnmet, 403);
            let ResponseBody::Problem(details) = &mut response.body else {
                unreachable!();
            };
            details.requirements_pending = Some(
                missing
                    .into_iter()
                    .map(|claim| claim.as_str().to_owned())
                    .collect(),
            );
            return Ok(response);
        }
        let now = self.clock.now();
        let decision = self.enrollment_policy.decide(&request, now).await?;
        let record = self
            .enrollment_store
            .save(EnrollmentRecord {
                agent_did: request.agent_did,
                claims: request.claims.unwrap_or_default(),
                created_at: now,
                owner_action_required: decision.owner_action_required,
                requirements_pending: decision.requirements_pending,
                since: now,
                status: decision_status(decision.status),
                updated_at: now,
                verification_pending: decision.verification_pending,
            })
            .await?;
        Ok(success(ResponseBody::Enroll(enroll_response(&record))))
    }

    async fn authenticate_command(
        &self,
        assertion: &str,
        operation: AssertionOperation,
        idempotency_key: Option<&str>,
    ) -> Result<Option<aep_core::ClientAssertionClaims>, ServiceError> {
        self.authenticate_assertion(assertion, operation, idempotency_key, None)
            .await
    }

    async fn authenticate_assertion(
        &self,
        assertion: &str,
        operation: AssertionOperation,
        idempotency_key: Option<&str>,
        resource: Option<&url::Url>,
    ) -> Result<Option<aep_core::ClientAssertionClaims>, ServiceError> {
        authenticate_assertion(AssertionAuthentication {
            allow_insecure_loopback: self.allow_insecure_loopback,
            assertion,
            clock: self.clock.as_ref(),
            idempotency_key,
            identity_methods: &self.configuration.inspect_document.identity.methods,
            maximum_clock_skew: self.configuration.maximum_clock_skew,
            operation,
            replay_store: &self.replay_store,
            resource,
            service_did: &self.configuration.service_did,
            signing_algorithms: &self.configuration.signing_algorithms,
            verifier: &self.verifier,
        })
        .await
    }

    fn authentication_failure(
        &self,
        code: ErrorCode,
        request: &ProtectedResourceRequest,
    ) -> ProtectedResourceAuthentication {
        let mut response = problem(code.clone(), 401);
        let inspect = self.configuration.inspect_url.clone().unwrap_or_else(|| {
            let mut inspect = request.url.clone();
            inspect.set_path(aep_core::WELL_KNOWN_PATH);
            inspect.set_query(None);
            inspect.set_fragment(None);
            inspect
        });
        let challenge = format!(
            "{} service_did=\"{}\", inspect=\"{}\", reason=\"{}\"",
            aep_core::AUTHORIZATION_SCHEME,
            self.configuration.service_did,
            inspect,
            code.as_str()
        );
        if let Ok(value) = HeaderValue::from_str(&challenge) {
            response.headers.insert(header::WWW_AUTHENTICATE, value);
        }
        ProtectedResourceAuthentication::Rejected(response)
    }
}

fn build_configuration(options: &ServiceOptions) -> Result<ServiceConfiguration, ServiceError> {
    if !options.service_did.starts_with("did:") {
        return Err(ServiceError::InvalidConfiguration(
            "Service DID must be a DID".to_owned(),
        ));
    }
    require_unique(
        options.identity_methods.iter().map(|value| value.as_str()),
        "identity methods",
    )?;
    require_unique(
        options
            .grant_types
            .iter()
            .map(|value| value.grant_type.as_str()),
        "grant types",
    )?;
    require_unique(
        options
            .authentication_methods
            .iter()
            .map(|value| value.as_str()),
        "authentication methods",
    )?;
    require_unique(
        options
            .signing_algorithms
            .iter()
            .map(|value| value.as_str()),
        "signing algorithms",
    )?;
    if options.identity_methods.is_empty() || options.signing_algorithms.is_empty() {
        return Err(ServiceError::InvalidConfiguration(
            "identity methods and signing algorithms must not be empty".to_owned(),
        ));
    }
    let mut grant_handlers = BTreeMap::new();
    let mut grant_types_config = BTreeMap::new();
    for definition in &options.grant_types {
        let Some(handler) = &definition.handler else {
            return Err(ServiceError::InvalidConfiguration(format!(
                "grant type {} requires a handler",
                definition.grant_type.as_str()
            )));
        };
        grant_handlers.insert(definition.grant_type.as_str().to_owned(), handler.clone());
        if let Some(config) = &definition.config {
            grant_types_config.insert(definition.grant_type.as_str().to_owned(), config.clone());
        }
    }
    for method in &options.authentication_methods {
        if method != &AuthenticationMethod::AepJwt && !grant_handlers.contains_key(method.as_str())
        {
            return Err(ServiceError::InvalidConfiguration(format!(
                "authentication method {} requires a matching grant type handler",
                method.as_str()
            )));
        }
    }
    let commands = if options.grant_types.is_empty() {
        vec![Command::Enroll, Command::Inspect, Command::Status]
    } else {
        vec![
            Command::Enroll,
            Command::Grant,
            Command::Inspect,
            Command::Revoke,
            Command::Status,
        ]
    };
    let inspect_document = InspectDocument {
        aep_version: VERSION.to_owned(),
        authentication: (!options.authentication_methods.is_empty()).then(|| Authentication {
            methods: options.authentication_methods.clone(),
        }),
        bindings: Bindings {
            supported: vec![Binding::Http],
            additional: BTreeMap::new(),
        },
        claims: Some(InspectClaims {
            optional: options.claims.optional.clone(),
            preferred: options.claims.preferred.clone(),
            required: options.claims.required.clone(),
            additional: BTreeMap::new(),
        }),
        commands: Commands {
            grant_types: options
                .grant_types
                .iter()
                .map(|definition| definition.grant_type.clone())
                .collect(),
            grant_types_config,
            supported: commands,
            additional: BTreeMap::new(),
        },
        core: CoreConfiguration {
            signing_algorithms: options.signing_algorithms.clone(),
            additional: BTreeMap::new(),
        },
        extensions: Some(Extensions {
            supported: options.extensions.clone(),
            additional: BTreeMap::new(),
        }),
        http: HttpConfiguration {
            endpoint_base: options.endpoint_base.clone(),
            openapi: options
                .openapi
                .as_ref()
                .map(|openapi| aep_core::OpenApiReference {
                    path_matching: aep_core::OpenApiPathMatching {
                        trailing_slash: openapi.trailing_slash,
                    },
                    url: openapi.url.clone(),
                }),
            additional: BTreeMap::new(),
        },
        identity: Identity {
            methods: options.identity_methods.clone(),
            additional: BTreeMap::new(),
        },
        service: ServiceIdentity {
            did: options.service_did.clone(),
            additional: BTreeMap::new(),
        },
        additional: BTreeMap::new(),
    };
    validate_inspect_document(&inspect_document).map_err(aep_core::CoreError::from)?;
    Ok(ServiceConfiguration {
        authentication_methods: options.authentication_methods.clone(),
        claims: options.claims.clone(),
        grant_handlers,
        inspect_document,
        inspect_url: options.inspect_url.clone(),
        maximum_clock_skew: options.maximum_clock_skew,
        service_did: options.service_did.clone(),
        signing_algorithms: options.signing_algorithms.clone(),
    })
}

fn enroll_response(record: &EnrollmentRecord) -> EnrollResponse {
    EnrollResponse {
        additional: BTreeMap::new(),
        owner_action_required: record.owner_action_required.then_some(StringBoolean::True),
        requirements_pending: non_empty(&record.requirements_pending),
        status: record.status,
        verification_pending: non_empty(&record.verification_pending),
    }
}

fn status_response(record: &EnrollmentRecord) -> StatusResponse {
    StatusResponse {
        additional: BTreeMap::new(),
        owner_action_required: record.owner_action_required.then_some(StringBoolean::True),
        requirements_pending: non_empty(&record.requirements_pending),
        since: record.since.format(&Rfc3339).ok(),
        status: record.status,
        verification_pending: non_empty(&record.verification_pending),
    }
}

fn non_empty(values: &[String]) -> Option<Vec<String>> {
    (!values.is_empty()).then(|| values.to_vec())
}

fn decision_status(status: EnrollmentDecisionStatus) -> AgentStatus {
    match status {
        EnrollmentDecisionStatus::Active => AgentStatus::Active,
        EnrollmentDecisionStatus::Pending => AgentStatus::Pending,
        EnrollmentDecisionStatus::Rejected => AgentStatus::Rejected,
    }
}

fn blocked_enrollment(enrollment: &EnrollmentRecord) -> Option<ServiceResponse> {
    let code = match enrollment.status {
        AgentStatus::Active => return None,
        AgentStatus::Pending => ErrorCode::VerificationPending,
        AgentStatus::Rejected => ErrorCode::NotRecognized,
        AgentStatus::Suspended => ErrorCode::IdentitySuspended,
        AgentStatus::Terminated => ErrorCode::IdentityTerminated,
        AgentStatus::Unavailable => ErrorCode::IdentityUnavailable,
    };
    let status = if code == ErrorCode::NotRecognized {
        401
    } else {
        403
    };
    let mut response = problem(code, status);
    if enrollment.status == AgentStatus::Pending {
        let ResponseBody::Problem(details) = &mut response.body else {
            unreachable!();
        };
        details.owner_action_required = enrollment
            .owner_action_required
            .then_some(StringBoolean::True);
        details.requirements_pending = non_empty(&enrollment.requirements_pending);
        details.verification_pending = non_empty(&enrollment.verification_pending);
    }
    Some(response)
}

fn idempotency_input(
    agent_did: &str,
    command: IdempotentCommand,
    idempotency_key: &str,
    request: &impl Serialize,
) -> Result<CommandIdempotencyInput, ServiceError> {
    let canonical = serde_json::to_vec(request)?;
    Ok(CommandIdempotencyInput {
        agent_did: agent_did.to_owned(),
        command,
        idempotency_key: idempotency_key.to_owned(),
        request_hash: format!("sha256:{:x}", Sha256::digest(canonical)),
    })
}

fn idempotency_response(result: CommandIdempotencyResult) -> ServiceResponse {
    match result {
        CommandIdempotencyResult::Created(response)
        | CommandIdempotencyResult::Replayed(response) => response,
        CommandIdempotencyResult::Conflict => problem(ErrorCode::IdempotencyConflict, 409),
    }
}

fn success(body: ResponseBody) -> ServiceResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(body.content_type()),
    );
    ServiceResponse {
        body,
        headers,
        status: 200,
    }
}

fn require_unique<'a>(
    values: impl IntoIterator<Item = &'a str>,
    name: &str,
) -> Result<(), ServiceError> {
    let mut unique = std::collections::BTreeSet::new();
    if values.into_iter().any(|value| !unique.insert(value)) {
        return Err(ServiceError::InvalidConfiguration(format!(
            "{name} must not contain duplicates"
        )));
    }
    Ok(())
}
