use aep_core::{
    AssertionOperation, AuthenticationMethod, AuthorizationCarrier, BuiltInGrantResponse,
    CredentialScheme, parse_built_in_grant_response, render_protected_resource_authorization,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use http::{HeaderMap, HeaderName, HeaderValue};

use crate::{
    AgentError, AuthenticationOptions, AuthenticationResult, CredentialRecord, Inspection, Session,
    authorization, same_origin,
};

impl Session {
    pub async fn authentication(
        &self,
        options: AuthenticationOptions,
    ) -> Result<AuthenticationResult, AgentError> {
        if options.client_assertion_only
            && (options.credential_id.is_some() || options.grant_type.is_some())
        {
            return Err(AgentError::InvalidConfiguration("AEP credential selection cannot be combined with client-assertion-only authentication".to_owned()));
        }
        validate_resource(
            &options.resource,
            &self.service_url,
            self.client.allow_insecure_loopback,
        )?;
        let inspection = self.inspect().await?;
        let methods = inspection
            .document
            .authentication
            .as_ref()
            .map_or(&[][..], |authentication| authentication.methods.as_slice());
        if let Some(grant_type) = options.grant_type.as_ref()
            && !methods
                .iter()
                .any(|method| method.as_str() == grant_type.as_str())
        {
            return Err(AgentError::NoAuthenticationMethod);
        }
        if !options.client_assertion_only {
            let credential_methods = implicit_credential_methods(methods, &options);
            if !credential_methods.is_empty()
                || options.credential_id.is_some()
                || options.grant_type.is_some()
            {
                if let Some(record) = self
                    .find_credential(&inspection, credential_methods, &options)
                    .await?
                {
                    return credential_authentication(
                        &record,
                        options.carrier,
                        self.client.clock.now(),
                    );
                }
                if options.credential_id.is_some() || options.grant_type.is_some() {
                    return Err(AgentError::Credential(
                        "requested AEP credential was not found".to_owned(),
                    ));
                }
            }
        }
        if !methods.contains(&AuthenticationMethod::AepJwt) {
            return Err(AgentError::NoAuthenticationMethod);
        }
        let identity = self.resolve_identity(&inspection, true).await?;
        let signer = self.client.identity_provider.signer_for(&identity).await?;
        let assertion = self
            .client
            .sign_assertion(
                &inspection,
                &identity,
                signer.as_ref(),
                AssertionOperation::Authenticate,
                Some(&options.resource),
            )
            .await?;
        let (name, value) = render_protected_resource_authorization(&authorization(
            options.carrier,
            CredentialScheme::Aep,
            assertion,
        ))
        .map_err(|error| AgentError::Credential(error.to_string()))?;
        Ok(AuthenticationResult {
            headers: one_header(&name, &value)?,
            method: AuthenticationMethod::AepJwt,
        })
    }

    pub async fn forget_credential(&self, credential_id: &str) -> Result<(), AgentError> {
        if credential_id.is_empty() {
            return Err(AgentError::Credential(
                "AEP credential ID is required".to_owned(),
            ));
        }
        let inspection = self.inspect().await?;
        self.client
            .credential_store
            .delete(&inspection.document.service.did, credential_id)
            .await
    }

    async fn find_credential(
        &self,
        inspection: &Inspection,
        methods: &[AuthenticationMethod],
        options: &AuthenticationOptions,
    ) -> Result<Option<CredentialRecord>, AgentError> {
        let service_did = &inspection.document.service.did;
        if let Some(credential_id) = options.credential_id.as_deref() {
            let Some(record) = self
                .client
                .credential_store
                .find(service_did, credential_id)
                .await?
            else {
                return Ok(None);
            };
            validate_record(&record, service_did, self.client.clock.now())?;
            if options
                .grant_type
                .as_ref()
                .is_some_and(|grant_type| grant_type != &record.grant_type)
            {
                return Err(AgentError::Credential(
                    "stored AEP credential does not match the requested grant type".to_owned(),
                ));
            }
            if !methods
                .iter()
                .any(|method| method.as_str() == record.grant_type.as_str())
            {
                return Err(AgentError::NoAuthenticationMethod);
            }
            return Ok(Some(record));
        }
        let records = self.client.credential_store.list(service_did).await?;
        for method in methods {
            if let Some(record) = records.iter().find(|record| {
                method.as_str() == record.grant_type.as_str()
                    && options
                        .grant_type
                        .as_ref()
                        .is_none_or(|grant_type| grant_type == &record.grant_type)
            }) {
                validate_record(record, service_did, self.client.clock.now())?;
                return Ok(Some(record.clone()));
            }
        }
        Ok(None)
    }
}

fn implicit_credential_methods<'a>(
    methods: &'a [AuthenticationMethod],
    options: &AuthenticationOptions,
) -> &'a [AuthenticationMethod] {
    if options.credential_id.is_some() || options.grant_type.is_some() {
        return methods;
    }
    methods
        .iter()
        .position(|method| method == &AuthenticationMethod::AepJwt)
        .map_or(methods, |index| &methods[..index])
}

fn credential_authentication(
    record: &CredentialRecord,
    carrier: AuthorizationCarrier,
    now: time::OffsetDateTime,
) -> Result<AuthenticationResult, AgentError> {
    validate_record(record, &record.service_did, now)?;
    let encoded = serde_json::to_vec(&record.payload)?;
    let credential = parse_built_in_grant_response(&record.grant_type, &encoded)?;
    match credential {
        BuiltInGrantResponse::OAuthBearer(value) => {
            let (name, value) = render_protected_resource_authorization(&authorization(
                carrier,
                CredentialScheme::Bearer,
                value.access_token,
            ))
            .map_err(|error| AgentError::Credential(error.to_string()))?;
            Ok(AuthenticationResult {
                headers: one_header(&name, &value)?,
                method: AuthenticationMethod::OAuthBearer,
            })
        }
        BuiltInGrantResponse::ApiKey(value) => Ok(AuthenticationResult {
            headers: one_header(&value.header, &value.api_key)?,
            method: AuthenticationMethod::ApiKey,
        }),
        BuiltInGrantResponse::Basic(value) => {
            let credentials = STANDARD.encode(format!("{}:{}", value.username, value.password));
            let (name, value) = render_protected_resource_authorization(&authorization(
                carrier,
                CredentialScheme::Basic,
                credentials,
            ))
            .map_err(|error| AgentError::Credential(error.to_string()))?;
            Ok(AuthenticationResult {
                headers: one_header(&name, &value)?,
                method: AuthenticationMethod::Basic,
            })
        }
    }
}

pub(crate) fn validate_record(
    record: &CredentialRecord,
    service_did: &str,
    now: time::OffsetDateTime,
) -> Result<(), AgentError> {
    if record.credential_id.is_empty()
        || record.service_did != service_did
        || record.expires_at <= now
    {
        return Err(AgentError::Credential(
            "stored AEP credential metadata is invalid".to_owned(),
        ));
    }
    let encoded = serde_json::to_vec(&record.payload)?;
    let credential = parse_built_in_grant_response(&record.grant_type, &encoded)?;
    let (credential_id, expires_at) = match credential {
        BuiltInGrantResponse::OAuthBearer(value) => (value.credential_id, value.expires_at),
        BuiltInGrantResponse::ApiKey(value) => (value.credential_id, value.expires_at),
        BuiltInGrantResponse::Basic(value) => (value.credential_id, value.expires_at),
    };
    let expires_at =
        time::OffsetDateTime::parse(&expires_at, &time::format_description::well_known::Rfc3339)
            .map_err(|_| {
                AgentError::Credential("stored AEP credential expiration is invalid".to_owned())
            })?;
    if credential_id != record.credential_id || expires_at != record.expires_at {
        return Err(AgentError::Credential(
            "stored AEP credential metadata does not match its payload".to_owned(),
        ));
    }
    Ok(())
}

fn validate_resource(
    resource: &url::Url,
    service: &url::Url,
    allow_insecure_loopback: bool,
) -> Result<(), AgentError> {
    if !resource.username().is_empty()
        || resource.password().is_some()
        || resource.fragment().is_some()
        || resource.host_str().is_none()
    {
        return Err(AgentError::InvalidServiceReference(
            "AEP protected resource URL is invalid".to_owned(),
        ));
    }
    if resource.scheme() != "https"
        && !(allow_insecure_loopback && resource.scheme() == "http" && crate::is_loopback(resource))
    {
        return Err(AgentError::InvalidServiceReference(
            "AEP protected resource requires HTTPS".to_owned(),
        ));
    }
    if !same_origin(resource, service) {
        return Err(AgentError::InvalidServiceReference(
            "AEP protected resource must use the Service origin".to_owned(),
        ));
    }
    Ok(())
}

fn one_header(name: &str, value: &str) -> Result<HeaderMap, AgentError> {
    let name = HeaderName::from_bytes(name.as_bytes())
        .map_err(|_| AgentError::Credential("AEP credential header name is invalid".to_owned()))?;
    let value = HeaderValue::from_str(value)
        .map_err(|_| AgentError::Credential("AEP credential header value is invalid".to_owned()))?;
    let mut headers = HeaderMap::new();
    headers.insert(name, value);
    Ok(headers)
}
