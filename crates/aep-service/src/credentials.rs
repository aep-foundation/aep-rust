use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use aep_core::{
    AUTHORIZATION_HEADER, AuthenticationMethod, AuthorizationCarrier, BuiltInGrantResponse,
    CredentialScheme, GrantRequest, GrantType, GrantTypeConfig, RevokeRequest, StringBoolean,
    parse_protected_resource_authorization, validate_built_in_grant_response,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use http::{HeaderMap, HeaderName, header};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    AuthenticatedPrincipal, AuthenticationKind, CredentialAuthenticationInput, CredentialMatch,
    GrantContext, GrantTypeDefinition, GrantTypeHandler, ServiceCredentialRecord,
    ServiceCredentialStore, ServiceError, StoredApiKeyGrantTypeOptions,
    StoredBasicGrantTypeOptions, StoredCredentialGrantTypeOptions,
    StoredOAuthBearerGrantTypeOptions,
};

pub fn stored_oauth_bearer_grant_type(
    options: StoredOAuthBearerGrantTypeOptions,
) -> Result<GrantTypeDefinition, ServiceError> {
    stored_credential_grant_type(GrantType::OAuthBearer, options, |credential| {
        BuiltInGrantResponse::OAuthBearer(credential)
    })
}

pub fn stored_api_key_grant_type(
    options: StoredApiKeyGrantTypeOptions,
) -> Result<GrantTypeDefinition, ServiceError> {
    configured_api_key_headers(&options.config)?;
    stored_credential_grant_type(GrantType::ApiKey, options, |credential| {
        BuiltInGrantResponse::ApiKey(credential)
    })
}

pub fn stored_basic_grant_type(
    options: StoredBasicGrantTypeOptions,
) -> Result<GrantTypeDefinition, ServiceError> {
    stored_credential_grant_type(GrantType::Basic, options, |credential| {
        BuiltInGrantResponse::Basic(credential)
    })
}

fn stored_credential_grant_type<T>(
    grant_type: GrantType,
    options: StoredCredentialGrantTypeOptions<T>,
    into_credential: fn(T) -> BuiltInGrantResponse,
) -> Result<GrantTypeDefinition, ServiceError>
where
    T: Serialize + Send + 'static,
{
    let mut config = options.config;
    config.supports_per_credential_revoke = Some(StringBoolean::True);
    Ok(GrantTypeDefinition {
        config: Some(config.clone()),
        grant_type: grant_type.clone(),
        handler: Some(Arc::new(StoredCredentialHandler {
            config,
            grant_type,
            into_credential,
            issue: options.issue,
            store: options.store,
        })),
    })
}

struct StoredCredentialHandler<T> {
    config: GrantTypeConfig,
    grant_type: GrantType,
    into_credential: fn(T) -> BuiltInGrantResponse,
    issue: crate::BuiltInCredentialIssuer<T>,
    store: Arc<dyn ServiceCredentialStore>,
}

#[async_trait]
impl<T> GrantTypeHandler for StoredCredentialHandler<T>
where
    T: Serialize + Send + 'static,
{
    async fn grant(
        &self,
        request: &GrantRequest,
        context: &GrantContext,
    ) -> Result<serde_json::Value, ServiceError> {
        let issued = (self.issue)(request.clone(), context.clone()).await?;
        let response = serde_json::to_value(&issued)?;
        let credential = (self.into_credential)(issued);
        validate_built_in_grant_response(&self.grant_type, &credential)
            .map_err(aep_core::CoreError::from)?;
        validate_issued_credential_config(&credential, &self.config)?;
        self.store
            .save(service_credential_record(
                context.agent_did.clone(),
                credential.clone(),
                context.now,
            )?)
            .await?;
        Ok(response)
    }

    async fn revoke(
        &self,
        request: &RevokeRequest,
        context: &GrantContext,
    ) -> Result<(), ServiceError> {
        if let Some(credential_id) = &request.credential_id {
            self.store
                .revoke_credential(
                    &context.agent_did,
                    &self.grant_type,
                    credential_id,
                    context.now,
                )
                .await
        } else {
            self.store
                .revoke_grant_type(&context.agent_did, &self.grant_type, context.now)
                .await
        }
    }

    async fn authenticate(
        &self,
        input: &CredentialAuthenticationInput,
    ) -> Result<Option<AuthenticatedPrincipal>, ServiceError> {
        let Some(matched) = self.store.authenticate(&self.grant_type, input).await? else {
            return Ok(None);
        };
        if matched.agent_did.is_empty()
            || matched.credential_id.is_empty()
            || matched.expires_at <= input.now
            || matched.grant_type != self.grant_type
        {
            return Err(ServiceError::Store(
                "AEP credential store returned an invalid match".to_owned(),
            ));
        }
        Ok(Some(AuthenticatedPrincipal {
            agent_did: matched.agent_did,
            authentication_kind: AuthenticationKind::SessionCredential,
            authentication_method: authentication_method(&self.grant_type)?,
            credential_id: Some(matched.credential_id),
            grant_type: Some(matched.grant_type),
            scopes: matched.scopes,
        }))
    }

    async fn has_presentation(
        &self,
        input: &CredentialAuthenticationInput,
    ) -> Result<bool, ServiceError> {
        self.store.has_presentation(&self.grant_type, input).await
    }
}

fn authentication_method(grant_type: &GrantType) -> Result<AuthenticationMethod, ServiceError> {
    match grant_type {
        GrantType::OAuthBearer => Ok(AuthenticationMethod::OAuthBearer),
        GrantType::ApiKey => Ok(AuthenticationMethod::ApiKey),
        GrantType::Basic => Ok(AuthenticationMethod::Basic),
        GrantType::Other(_) => Err(ServiceError::InvalidConfiguration(
            "stored credentials require a built-in AEP grant type".to_owned(),
        )),
    }
}

fn validate_issued_credential_config(
    credential: &BuiltInGrantResponse,
    config: &GrantTypeConfig,
) -> Result<(), ServiceError> {
    let BuiltInGrantResponse::ApiKey(value) = credential else {
        return Ok(());
    };
    let Some(headers) = configured_api_key_headers(config)? else {
        return Ok(());
    };
    if headers
        .iter()
        .any(|header| header == &canonical_header(&value.header))
    {
        Ok(())
    } else {
        Err(ServiceError::Handler(
            "issued API-key header is not advertised by the Service".to_owned(),
        ))
    }
}

fn configured_api_key_headers(
    config: &GrantTypeConfig,
) -> Result<Option<Vec<String>>, ServiceError> {
    let Some(value) = config.additional.get("header_names") else {
        return Ok(None);
    };
    let headers = serde_json::from_value::<Vec<String>>(value.clone()).map_err(|_| {
        ServiceError::InvalidConfiguration(
            "API-key header_names must be an array of HTTP field names".to_owned(),
        )
    })?;
    let mut canonical = Vec::with_capacity(headers.len());
    for value in headers {
        let name = HeaderName::try_from(value.as_str()).map_err(|_| {
            ServiceError::InvalidConfiguration(
                "API-key header_names contains an invalid HTTP field name".to_owned(),
            )
        })?;
        let name = name.as_str().to_owned();
        if canonical.contains(&name) {
            return Err(ServiceError::InvalidConfiguration(
                "API-key header_names contains a duplicate HTTP field name".to_owned(),
            ));
        }
        canonical.push(name);
    }
    Ok(Some(canonical))
}

fn service_credential_record(
    agent_did: String,
    credential: BuiltInGrantResponse,
    created_at: OffsetDateTime,
) -> Result<ServiceCredentialRecord, ServiceError> {
    if agent_did.is_empty() {
        return Err(ServiceError::Handler(
            "issued credential requires an Agent DID".to_owned(),
        ));
    }
    let (credential_id, expires_at, _) = credential_metadata(&credential);
    let expires_at = OffsetDateTime::parse(expires_at, &Rfc3339).map_err(|_| {
        ServiceError::Handler("issued credential has an invalid expiration".to_owned())
    })?;
    if expires_at <= created_at {
        return Err(ServiceError::Handler(
            "issued credential must expire after issuance".to_owned(),
        ));
    }
    Ok(ServiceCredentialRecord {
        agent_did,
        created_at,
        credential_id: credential_id.to_owned(),
        expires_at,
        grant_type: credential.grant_type(),
        credential,
    })
}

#[derive(Clone)]
struct MemoryCredentialRecord {
    agent_did: String,
    credential_id: String,
    expires_at: OffsetDateTime,
    grant_type: GrantType,
    header: String,
    revoked_at: Option<OffsetDateTime>,
    scopes: Vec<String>,
    verifier: [u8; 32],
}

#[derive(Default)]
pub struct MemoryServiceCredentialStore {
    records: Mutex<BTreeMap<String, MemoryCredentialRecord>>,
}

impl MemoryServiceCredentialStore {
    pub fn new(
        records: impl IntoIterator<Item = ServiceCredentialRecord>,
    ) -> Result<Self, ServiceError> {
        let store = Self::default();
        {
            let mut destination = store.records.lock().map_err(lock_error)?;
            for record in records {
                save_record(&mut destination, memory_credential_record(record)?)?;
            }
        }
        Ok(store)
    }
}

#[async_trait]
impl ServiceCredentialStore for MemoryServiceCredentialStore {
    async fn authenticate(
        &self,
        grant_type: &GrantType,
        input: &CredentialAuthenticationInput,
    ) -> Result<Option<CredentialMatch>, ServiceError> {
        let records = self.records.lock().map_err(lock_error)?;
        let presentations = presentations(grant_type, &input.headers, records.values());
        if presentations.len() != 1 {
            return Ok(None);
        }
        let presentation = &presentations[0];
        let candidate: [u8; 32] = Sha256::digest(presentation.value.as_bytes()).into();
        for record in records.values() {
            if &record.grant_type == grant_type
                && record.header == presentation.header
                && record.revoked_at.is_none()
                && record.expires_at > input.now
                && bool::from(record.verifier.ct_eq(&candidate))
            {
                return Ok(Some(CredentialMatch {
                    agent_did: record.agent_did.clone(),
                    credential_id: record.credential_id.clone(),
                    expires_at: record.expires_at,
                    grant_type: record.grant_type.clone(),
                    scopes: record.scopes.clone(),
                }));
            }
        }
        Ok(None)
    }

    async fn has_presentation(
        &self,
        grant_type: &GrantType,
        input: &CredentialAuthenticationInput,
    ) -> Result<bool, ServiceError> {
        let records = self.records.lock().map_err(lock_error)?;
        if !presentations(grant_type, &input.headers, records.values()).is_empty() {
            return Ok(true);
        }
        if grant_type != &GrantType::ApiKey {
            return Ok(false);
        }
        for value in input.headers.values() {
            let Ok(value) = value.to_str() else {
                continue;
            };
            let candidate: [u8; 32] = Sha256::digest(value.as_bytes()).into();
            if records.values().any(|record| {
                record.grant_type == GrantType::ApiKey
                    && bool::from(record.verifier.ct_eq(&candidate))
            }) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn revoke_credential(
        &self,
        agent_did: &str,
        grant_type: &GrantType,
        credential_id: &str,
        revoked_at: OffsetDateTime,
    ) -> Result<(), ServiceError> {
        let mut records = self.records.lock().map_err(lock_error)?;
        if let Some(record) = records.get_mut(credential_id)
            && record.agent_did == agent_did
            && &record.grant_type == grant_type
        {
            record.revoked_at = Some(revoked_at);
        }
        Ok(())
    }

    async fn revoke_grant_type(
        &self,
        agent_did: &str,
        grant_type: &GrantType,
        revoked_at: OffsetDateTime,
    ) -> Result<(), ServiceError> {
        for record in self.records.lock().map_err(lock_error)?.values_mut() {
            if record.agent_did == agent_did && &record.grant_type == grant_type {
                record.revoked_at = Some(revoked_at);
            }
        }
        Ok(())
    }

    async fn save(&self, record: ServiceCredentialRecord) -> Result<(), ServiceError> {
        let record = memory_credential_record(record)?;
        let mut records = self.records.lock().map_err(lock_error)?;
        save_record(&mut records, record)
    }
}

fn save_record(
    records: &mut BTreeMap<String, MemoryCredentialRecord>,
    record: MemoryCredentialRecord,
) -> Result<(), ServiceError> {
    if records.contains_key(&record.credential_id) {
        return Err(ServiceError::Store(
            "AEP credential identifier has already been issued".to_owned(),
        ));
    }
    if records.values().any(|existing| {
        existing.grant_type == record.grant_type
            && existing.header == record.header
            && bool::from(existing.verifier.ct_eq(&record.verifier))
    }) {
        return Err(ServiceError::Store(
            "AEP credential secret has already been issued".to_owned(),
        ));
    }
    records.insert(record.credential_id.clone(), record);
    Ok(())
}

fn memory_credential_record(
    record: ServiceCredentialRecord,
) -> Result<MemoryCredentialRecord, ServiceError> {
    validate_built_in_grant_response(&record.grant_type, &record.credential)
        .map_err(aep_core::CoreError::from)?;
    let (credential_id, expires_at, scopes) = credential_metadata(&record.credential);
    let parsed_expiry = OffsetDateTime::parse(expires_at, &Rfc3339).map_err(|_| {
        ServiceError::Store("AEP credential record has an invalid expiration".to_owned())
    })?;
    if record.agent_did.is_empty()
        || credential_id != record.credential_id
        || parsed_expiry != record.expires_at
        || record.expires_at <= record.created_at
        || record.grant_type != record.credential.grant_type()
    {
        return Err(ServiceError::Store(
            "AEP credential store received an invalid record".to_owned(),
        ));
    }
    let (header, secret) = match &record.credential {
        BuiltInGrantResponse::OAuthBearer(value) => (
            canonical_header(header::AUTHORIZATION.as_str()),
            value.access_token.clone(),
        ),
        BuiltInGrantResponse::ApiKey(value) => {
            (canonical_header(&value.header), value.api_key.clone())
        }
        BuiltInGrantResponse::Basic(value) => (
            canonical_header(header::AUTHORIZATION.as_str()),
            STANDARD.encode(format!("{}:{}", value.username, value.password)),
        ),
    };
    Ok(MemoryCredentialRecord {
        agent_did: record.agent_did,
        credential_id: record.credential_id,
        expires_at: record.expires_at,
        grant_type: record.grant_type,
        header,
        revoked_at: None,
        scopes: scopes.to_vec(),
        verifier: Sha256::digest(secret.as_bytes()).into(),
    })
}

fn credential_metadata(credential: &BuiltInGrantResponse) -> (&str, &str, &[String]) {
    match credential {
        BuiltInGrantResponse::OAuthBearer(value) => {
            (&value.credential_id, &value.expires_at, &value.scopes)
        }
        BuiltInGrantResponse::ApiKey(value) => {
            (&value.credential_id, &value.expires_at, &value.scopes)
        }
        BuiltInGrantResponse::Basic(value) => {
            (&value.credential_id, &value.expires_at, &value.scopes)
        }
    }
}

struct CredentialPresentation {
    header: String,
    value: String,
}

fn presentations<'a>(
    grant_type: &GrantType,
    headers: &HeaderMap,
    records: impl Iterator<Item = &'a MemoryCredentialRecord>,
) -> Vec<CredentialPresentation> {
    if grant_type == &GrantType::ApiKey {
        let unique_headers = records
            .filter(|record| record.grant_type == GrantType::ApiKey)
            .map(|record| record.header.clone())
            .collect::<std::collections::BTreeSet<_>>();
        return unique_headers
            .iter()
            .flat_map(|name| header_values(headers, name))
            .map(|(header, value)| CredentialPresentation { header, value })
            .collect();
    }
    let expected = if grant_type == &GrantType::OAuthBearer {
        CredentialScheme::Bearer
    } else if grant_type == &GrantType::Basic {
        CredentialScheme::Basic
    } else {
        return Vec::new();
    };
    [
        (
            header::AUTHORIZATION.as_str(),
            AuthorizationCarrier::Standard,
        ),
        (AUTHORIZATION_HEADER, AuthorizationCarrier::Dedicated),
    ]
    .into_iter()
    .flat_map(|(name, carrier)| {
        header_values(headers, name).filter_map(move |(_, value)| {
            parse_protected_resource_authorization(&value, carrier)
                .ok()
                .filter(|parsed| parsed.scheme == expected)
                .map(|parsed| CredentialPresentation {
                    header: canonical_header(header::AUTHORIZATION.as_str()),
                    value: parsed.credentials,
                })
        })
    })
    .collect()
}

fn header_values<'a>(
    headers: &'a HeaderMap,
    name: &'a str,
) -> impl Iterator<Item = (String, String)> + 'a {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(move |value| (canonical_header(name), value.to_owned()))
}

fn canonical_header(value: &str) -> String {
    value.to_ascii_lowercase()
}

fn lock_error<T>(_error: std::sync::PoisonError<T>) -> ServiceError {
    ServiceError::Store("AEP Service credential memory store lock is poisoned".to_owned())
}
