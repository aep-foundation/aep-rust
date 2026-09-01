use aep_core::{
    AUTHORIZATION_SCHEME, AgentStatus, BuiltInGrantResponse, Command, EnrollRequest,
    EnrollResponse, GrantRequest, GrantType, HttpRequest, MEDIA_TYPE, RevokeRequest,
    RevokeResponse, StatusResponse, StringBoolean, parse_built_in_grant_response,
    parse_enroll_response, parse_grant_request, parse_problem_details, parse_revoke_response,
    parse_status_response, validate_enroll_request, validate_revoke_request,
};
use http::{HeaderMap, HeaderValue, Method, header};
use serde::Serialize;
use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    AgentError, AgentIdentity, AssertionSigner, CommandResult, CredentialRecord, EnrollOptions,
    GrantOptions, GrantResult, Inspection, OperationKey, RevokeOptions, Session, WaitOptions,
    assertion_operation,
};

impl Session {
    pub async fn enroll(
        &self,
        options: EnrollOptions,
    ) -> Result<CommandResult<EnrollResponse>, AgentError> {
        let (inspection, identity, signer) = self.command_context(&Command::Enroll, true).await?;
        let required = inspection
            .document
            .claims
            .as_ref()
            .map_or(&[][..], |claims| claims.required.as_slice());
        let missing = aep_core::missing_required_claim_names(required, options.claims.as_ref());
        if !missing.is_empty() {
            return Err(AgentError::claims(missing));
        }
        let key = self
            .idempotency_key(
                &inspection,
                &Command::Enroll,
                None,
                None,
                options.idempotency_key,
            )
            .await?;
        let body = EnrollRequest {
            agent_did: identity.agent_did.clone(),
            claims: options.claims,
            idempotency_key: Some(key.clone()),
            additional: Default::default(),
        };
        validate_enroll_request(&body).map_err(aep_core::CoreError::from)?;
        self.execute_command(
            CommandRequest {
                inspection: &inspection,
                identity: &identity,
                signer: signer.as_ref(),
                command: &Command::Enroll,
                method: Method::POST,
                body: Some(&body),
                idempotency_key: Some(&key),
            },
            parse_enroll_response,
        )
        .await
    }

    pub async fn status(&self) -> Result<CommandResult<StatusResponse>, AgentError> {
        let (inspection, identity, signer) = self.command_context(&Command::Status, true).await?;
        self.execute_command::<Value, StatusResponse>(
            CommandRequest {
                inspection: &inspection,
                identity: &identity,
                signer: signer.as_ref(),
                command: &Command::Status,
                method: Method::GET,
                body: None,
                idempotency_key: None,
            },
            parse_status_response,
        )
        .await
    }

    pub async fn wait_for_active(
        &self,
        options: WaitOptions,
    ) -> Result<CommandResult<StatusResponse>, AgentError> {
        if options.interval.is_zero() || options.timeout.is_zero() {
            return Err(AgentError::InvalidConfiguration(
                "AEP Status polling interval and timeout must be positive".to_owned(),
            ));
        }
        let started = self.client.clock.now();
        loop {
            let result = self.status().await?;
            if result.body.status == AgentStatus::Active {
                return Ok(result);
            }
            if matches!(
                result.body.status,
                AgentStatus::Rejected | AgentStatus::Suspended | AgentStatus::Terminated
            ) {
                return Err(AgentError::EnrollmentState {
                    status: result.body.status,
                });
            }
            let elapsed = self.client.clock.now() - started;
            let timeout = time::Duration::try_from(options.timeout).map_err(|_| {
                AgentError::InvalidConfiguration(
                    "AEP Status polling timeout is too large".to_owned(),
                )
            })?;
            if elapsed >= timeout {
                return Err(AgentError::PollingTimeout);
            }
            self.client.delay.sleep(options.interval).await;
        }
    }

    pub async fn grant(
        &self,
        options: GrantOptions,
    ) -> Result<CommandResult<GrantResult>, AgentError> {
        let (inspection, identity, signer) = self.command_context(&Command::Grant, false).await?;
        let grant_type = select_grant_type(
            &inspection,
            options.grant_type.as_ref(),
            &options.preferred_grant_types,
        )?;
        if !inspection
            .document
            .commands
            .supported
            .contains(&Command::Status)
        {
            return Err(AgentError::CommandNotAdvertised(
                "status required by grant".to_owned(),
            ));
        }
        let status = self
            .execute_command::<Value, StatusResponse>(
                CommandRequest {
                    inspection: &inspection,
                    identity: &identity,
                    signer: signer.as_ref(),
                    command: &Command::Status,
                    method: Method::GET,
                    body: None,
                    idempotency_key: None,
                },
                parse_status_response,
            )
            .await?;
        if status.body.status != AgentStatus::Active {
            return Err(AgentError::Command {
                status: 401,
                problem: None,
            });
        }
        let key = self
            .idempotency_key(
                &inspection,
                &Command::Grant,
                Some(grant_type.clone()),
                None,
                options.idempotency_key,
            )
            .await?;
        let body = GrantRequest {
            grant_type: grant_type.clone(),
            requested_scopes: options.requested_scopes,
            additional: Default::default(),
        };
        parse_grant_request(&serde_json::to_vec(&body)?)?;
        let raw = self
            .execute_raw(CommandRequest {
                inspection: &inspection,
                identity: &identity,
                signer: signer.as_ref(),
                command: &Command::Grant,
                method: Method::POST,
                body: Some(&body),
                idempotency_key: Some(&key),
            })
            .await?;
        let value: Value = serde_json::from_slice(&raw.body)?;
        if !value.is_object() {
            return Err(AgentError::Credential(
                "AEP Grant response must be a JSON object".to_owned(),
            ));
        }
        let credential = match grant_type {
            GrantType::OAuthBearer | GrantType::ApiKey | GrantType::Basic => {
                Some(parse_built_in_grant_response(&grant_type, &raw.body)?)
            }
            GrantType::Other(_) => None,
        };
        if let Some(credential) = credential.as_ref() {
            self.client
                .credential_store
                .save(credential_record(
                    credential,
                    value.clone(),
                    &inspection,
                    self.client.clock.now(),
                )?)
                .await?;
        }
        Ok(CommandResult {
            body: GrantResult {
                credential,
                grant_type,
                raw: value,
            },
            status: raw.status,
            url: raw.url,
        })
    }

    pub async fn revoke(
        &self,
        options: RevokeOptions,
    ) -> Result<CommandResult<RevokeResponse>, AgentError> {
        if options.all_grant_types
            && (options.grant_type.is_some() || options.credential_id.is_some())
        {
            return Err(AgentError::InvalidConfiguration(
                "AEP all-grant-types Revoke cannot include a grant type or credential ID"
                    .to_owned(),
            ));
        }
        let (inspection, identity, signer) = self.command_context(&Command::Revoke, true).await?;
        let body = RevokeRequest {
            grant_type: options.grant_type.clone(),
            credential_id: options.credential_id.clone(),
            all_grant_types: options.all_grant_types.then_some(StringBoolean::True),
            additional: Default::default(),
        };
        validate_revoke_request(&body).map_err(aep_core::CoreError::from)?;
        if body.credential_id.is_some() {
            let advertised = body
                .grant_type
                .as_ref()
                .and_then(|grant_type| {
                    inspection
                        .document
                        .commands
                        .grant_types_config
                        .get(grant_type.as_str())
                })
                .and_then(|config| config.supports_per_credential_revoke)
                == Some(StringBoolean::True);
            if !advertised {
                return Err(AgentError::Credential(
                    "AEP Service does not advertise per-credential Revoke".to_owned(),
                ));
            }
        }
        let key = self
            .idempotency_key(
                &inspection,
                &Command::Revoke,
                body.grant_type.clone(),
                body.credential_id.clone(),
                options.idempotency_key,
            )
            .await?;
        let result = self
            .execute_command(
                CommandRequest {
                    inspection: &inspection,
                    identity: &identity,
                    signer: signer.as_ref(),
                    command: &Command::Revoke,
                    method: Method::POST,
                    body: Some(&body),
                    idempotency_key: Some(&key),
                },
                parse_revoke_response,
            )
            .await?;
        self.delete_revoked_credentials(&inspection.document.service.did, &body)
            .await?;
        Ok(result)
    }

    async fn command_context(
        &self,
        command: &Command,
        create_identity: bool,
    ) -> Result<
        (
            Inspection,
            AgentIdentity,
            std::sync::Arc<dyn AssertionSigner>,
        ),
        AgentError,
    > {
        let inspection = self.inspect().await?;
        if !inspection.document.commands.supported.contains(command) {
            return Err(AgentError::CommandNotAdvertised(
                command.as_str().to_owned(),
            ));
        }
        let identity = self.resolve_identity(&inspection, create_identity).await?;
        let signer = self.client.identity_provider.signer_for(&identity).await?;
        Ok((inspection, identity, signer))
    }

    async fn execute_command<B: Serialize + ?Sized, T>(
        &self,
        request: CommandRequest<'_, B>,
        parser: fn(&[u8]) -> Result<T, aep_core::ParseError>,
    ) -> Result<CommandResult<T>, AgentError> {
        let raw = self.execute_raw(request).await?;
        Ok(CommandResult {
            body: parser(&raw.body)?,
            status: raw.status,
            url: raw.url,
        })
    }

    async fn execute_raw<B: Serialize + ?Sized>(
        &self,
        request: CommandRequest<'_, B>,
    ) -> Result<RawCommandResult, AgentError> {
        let url = request.inspection.command_url(request.command)?;
        let operation = assertion_operation(request.command)
            .ok_or_else(|| AgentError::CommandNotAdvertised(request.command.as_str().to_owned()))?;
        let assertion = self
            .client
            .sign_assertion(
                request.inspection,
                request.identity,
                request.signer,
                operation,
                None,
            )
            .await?;
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, HeaderValue::from_static(MEDIA_TYPE));
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("{AUTHORIZATION_SCHEME} {assertion}")).map_err(
                |_| {
                    AgentError::Identity("AEP assertion is not a valid HTTP field value".to_owned())
                },
            )?,
        );
        let encoded = request
            .body
            .map(serde_json::to_vec)
            .transpose()?
            .unwrap_or_default();
        if request.body.is_some() {
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(MEDIA_TYPE));
        }
        if let Some(key) = request.idempotency_key {
            headers.insert(
                "idempotency-key",
                HeaderValue::from_str(key).map_err(|_| {
                    AgentError::InvalidConfiguration(
                        "AEP idempotency key is not a valid HTTP field value".to_owned(),
                    )
                })?,
            );
        }
        let response = self
            .client
            .command_transport
            .send(HttpRequest {
                method: request.method,
                url: url.clone(),
                headers,
                body: encoded,
            })
            .await
            .map_err(|error| AgentError::Transport(error.to_string()))?;
        if response.final_url != url {
            return Err(AgentError::Transport(
                "AEP command redirects are not allowed".to_owned(),
            ));
        }
        if response.body.len() > self.client.maximum_response_bytes {
            return Err(AgentError::Transport(
                "AEP command response exceeds the configured limit".to_owned(),
            ));
        }
        if !response.status.is_success() {
            return Err(AgentError::Command {
                status: response.status.as_u16(),
                problem: parse_problem_details(&response.body).ok().map(Box::new),
            });
        }
        if !media_type_matches(&response.headers) {
            return Err(AgentError::Transport(
                "AEP command response media type is invalid".to_owned(),
            ));
        }
        Ok(RawCommandResult {
            body: response.body,
            status: response.status.as_u16(),
            url,
        })
    }

    async fn idempotency_key(
        &self,
        inspection: &Inspection,
        command: &Command,
        grant_type: Option<GrantType>,
        credential_id: Option<String>,
        provided: Option<String>,
    ) -> Result<String, AgentError> {
        if let Some(value) = provided {
            if value.is_empty() {
                return Err(AgentError::InvalidConfiguration(
                    "AEP idempotency key must not be empty".to_owned(),
                ));
            }
            return Ok(value);
        }
        let value = self
            .client
            .idempotency_keys
            .create_key(&OperationKey {
                command: command.clone(),
                credential_id,
                grant_type,
                service_did: inspection.document.service.did.clone(),
                service_url: self.service_url.clone(),
            })
            .await?;
        if value.is_empty() {
            return Err(AgentError::InvalidConfiguration(
                "AEP idempotency key provider returned an empty key".to_owned(),
            ));
        }
        Ok(value)
    }

    async fn delete_revoked_credentials(
        &self,
        service_did: &str,
        selector: &RevokeRequest,
    ) -> Result<(), AgentError> {
        for record in self.client.credential_store.list(service_did).await? {
            let matches = selector.all_grant_types == Some(StringBoolean::True)
                || selector.credential_id.as_deref() == Some(record.credential_id.as_str())
                || (selector.credential_id.is_none()
                    && selector.grant_type.as_ref() == Some(&record.grant_type));
            if matches {
                self.client
                    .credential_store
                    .delete(service_did, &record.credential_id)
                    .await?;
            }
        }
        Ok(())
    }
}

struct RawCommandResult {
    body: Vec<u8>,
    status: u16,
    url: url::Url,
}

struct CommandRequest<'a, B: ?Sized> {
    inspection: &'a Inspection,
    identity: &'a AgentIdentity,
    signer: &'a dyn AssertionSigner,
    command: &'a Command,
    method: Method,
    body: Option<&'a B>,
    idempotency_key: Option<&'a str>,
}

fn select_grant_type(
    inspection: &Inspection,
    selected: Option<&GrantType>,
    preferred: &[GrantType],
) -> Result<GrantType, AgentError> {
    let advertised = &inspection.document.commands.grant_types;
    if let Some(selected) = selected {
        return advertised
            .contains(selected)
            .then(|| selected.clone())
            .ok_or(AgentError::NoCompatibleGrantType);
    }
    let candidates = if preferred.is_empty() {
        advertised
    } else {
        preferred
    };
    candidates
        .iter()
        .find(|candidate| advertised.contains(candidate))
        .cloned()
        .ok_or(AgentError::NoCompatibleGrantType)
}

fn credential_record(
    credential: &BuiltInGrantResponse,
    payload: Value,
    inspection: &Inspection,
    issued_at: OffsetDateTime,
) -> Result<CredentialRecord, AgentError> {
    let (credential_id, expires_at) = match credential {
        BuiltInGrantResponse::OAuthBearer(value) => (&value.credential_id, &value.expires_at),
        BuiltInGrantResponse::ApiKey(value) => (&value.credential_id, &value.expires_at),
        BuiltInGrantResponse::Basic(value) => (&value.credential_id, &value.expires_at),
    };
    let expires_at = OffsetDateTime::parse(expires_at, &Rfc3339).map_err(|_| {
        AgentError::Credential("AEP credential expiration is not RFC 3339".to_owned())
    })?;
    Ok(CredentialRecord {
        credential_id: credential_id.clone(),
        expires_at,
        grant_type: credential.grant_type(),
        issued_at,
        payload,
        service_did: inspection.document.service.did.clone(),
        service_url: inspection.service_url.clone(),
    })
}

fn media_type_matches(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case(MEDIA_TYPE))
}
