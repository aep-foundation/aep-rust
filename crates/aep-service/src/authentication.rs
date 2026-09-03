use std::{sync::Arc, time::Duration};

use aep_core::{
    AUTHORIZATION_HEADER, AssertionOperation, AuthenticationMethod, AuthorizationCarrier,
    ClientAssertionClaims, CredentialScheme, IdentityMethod, ResolveDidWebPublicKeyOptions,
    VerifyClientAssertionOptions, decode_jwt_unverified, parse_protected_resource_authorization,
    resolve_did_web_public_key, validate_client_assertion_claims_with_options,
    verify_client_assertion,
};
use async_trait::async_trait;
use http::{HeaderMap, header};
use time::{Duration as TimeDuration, OffsetDateTime};
use url::Url;

use crate::{
    ClientAssertionReplayRecord, ClientAssertionReplayStore, ClientAssertionVerificationContext,
    ClientAssertionVerifier, Clock, ServiceError,
};

pub(crate) struct AssertionAuthentication<'a> {
    pub allow_insecure_loopback: bool,
    pub assertion: &'a str,
    pub clock: &'a dyn Clock,
    pub idempotency_key: Option<&'a str>,
    pub identity_methods: &'a [IdentityMethod],
    pub maximum_clock_skew: Duration,
    pub operation: AssertionOperation,
    pub replay_store: &'a Arc<dyn ClientAssertionReplayStore>,
    pub resource: Option<&'a Url>,
    pub service_did: &'a str,
    pub signing_algorithms: &'a [aep_core::SigningAlgorithm],
    pub verifier: &'a Arc<dyn ClientAssertionVerifier>,
}

pub(crate) async fn authenticate_assertion(
    options: AssertionAuthentication<'_>,
) -> Result<Option<ClientAssertionClaims>, ServiceError> {
    let now = options.clock.now();
    let context = ClientAssertionVerificationContext {
        assertion: options.assertion.to_owned(),
        current_time: now,
        idempotency_key: options.idempotency_key.map(str::to_owned),
        operation: options.operation,
        resource: options.resource.cloned(),
        service_did: options.service_did.to_owned(),
        signing_algorithms: options.signing_algorithms.to_vec(),
    };
    let Ok(claims) = options.verifier.verify(context).await else {
        return Ok(None);
    };
    if validate_client_assertion_claims_with_options(
        &claims,
        aep_core::ClientAssertionValidationOptions {
            allow_insecure_loopback: options.allow_insecure_loopback,
        },
    )
    .is_err()
        || claims.aud != options.service_did
        || claims.iss != claims.sub
        || claims.op != options.operation
        || claims.resource.as_deref() != options.resource.map(Url::as_str)
        || !supports_identity_method(&claims.sub, options.identity_methods)
        || !inside_validity_window(&claims, now, options.maximum_clock_skew)
    {
        return Ok(None);
    }
    let skew = TimeDuration::try_from(options.maximum_clock_skew)
        .map_err(|_| ServiceError::InvalidConfiguration("clock skew is too large".to_owned()))?;
    let Some(expiration) = OffsetDateTime::from_unix_timestamp(claims.exp)
        .ok()
        .and_then(|expiration| expiration.checked_add(skew))
    else {
        return Ok(None);
    };
    let consumed = options
        .replay_store
        .consume(
            ClientAssertionReplayRecord {
                expires_at: expiration,
                jti: claims.jti.clone(),
                sub: claims.sub.clone(),
            },
            now,
        )
        .await?;
    Ok(consumed.then_some(claims))
}

#[async_trait]
impl crate::ClientAssertionVerifier for crate::DidWebClientAssertionVerifier {
    async fn verify(
        &self,
        context: ClientAssertionVerificationContext,
    ) -> Result<ClientAssertionClaims, ServiceError> {
        let decoded = decode_jwt_unverified(&context.assertion)?;
        let issuer = decoded
            .payload
            .get("iss")
            .and_then(|value| value.as_str())
            .ok_or_else(|| ServiceError::Handler("client assertion iss is required".to_owned()))?;
        let key_id =
            decoded.header.key_id.as_deref().ok_or_else(|| {
                ServiceError::Handler("client assertion kid is required".to_owned())
            })?;
        let key = resolve_did_web_public_key(ResolveDidWebPublicKeyOptions {
            algorithm: decoded.header.algorithm,
            allow_insecure_loopback: self.allow_insecure_loopback,
            did: issuer,
            key_id,
            transport: self.transport.as_ref(),
        })
        .await?;
        verify_client_assertion(
            &context.assertion,
            &key,
            &VerifyClientAssertionOptions {
                algorithms: context.signing_algorithms,
                allow_insecure_loopback: self.allow_insecure_loopback,
                audience: Some(context.service_did),
                current_time: Some(context.current_time.unix_timestamp()),
                issuer: Some(issuer.to_owned()),
                operation: Some(context.operation),
                resource: context.resource.map(|resource| resource.to_string()),
                subject: Some(issuer.to_owned()),
                ..VerifyClientAssertionOptions::default()
            },
        )
        .map_err(ServiceError::from)
    }
}

pub(crate) enum SelectedAuthorization {
    Aep(String),
    Session(AuthenticationMethod),
    Unrelated,
    Unauthenticated,
}

pub(crate) fn select_authorization(headers: &HeaderMap) -> Result<SelectedAuthorization, ()> {
    let dedicated_values = headers
        .get_all(AUTHORIZATION_HEADER)
        .iter()
        .collect::<Vec<_>>();
    if dedicated_values.len() > 1 {
        return Err(());
    }
    let standard_values = headers
        .get_all(header::AUTHORIZATION)
        .iter()
        .collect::<Vec<_>>();
    if standard_values.len() > 1 {
        return Err(());
    }
    if let Some(value) = dedicated_values.first() {
        let value = value.to_str().map_err(|_| ())?;
        let parsed = parse_protected_resource_authorization(value, AuthorizationCarrier::Dedicated)
            .map_err(|_| ())?;
        if standard_values.first().is_some_and(|standard| {
            standard.to_str().is_ok_and(|standard| {
                parse_protected_resource_authorization(standard, AuthorizationCarrier::Standard)
                    .is_ok()
            })
        }) {
            return Err(());
        }
        return match parsed.scheme {
            CredentialScheme::Aep => Ok(SelectedAuthorization::Aep(parsed.credentials)),
            CredentialScheme::Bearer => Ok(SelectedAuthorization::Session(
                AuthenticationMethod::OAuthBearer,
            )),
            CredentialScheme::Basic => {
                Ok(SelectedAuthorization::Session(AuthenticationMethod::Basic))
            }
        };
    }
    let Some(value) = standard_values.first() else {
        return Ok(SelectedAuthorization::Unauthenticated);
    };
    let Ok(value) = value.to_str() else {
        return Ok(SelectedAuthorization::Unrelated);
    };
    match parse_protected_resource_authorization(value, AuthorizationCarrier::Standard) {
        Ok(parsed) if parsed.scheme == CredentialScheme::Aep => {
            Ok(SelectedAuthorization::Aep(parsed.credentials))
        }
        Ok(parsed) if parsed.scheme == CredentialScheme::Bearer => Ok(
            SelectedAuthorization::Session(AuthenticationMethod::OAuthBearer),
        ),
        Ok(parsed) if parsed.scheme == CredentialScheme::Basic => {
            Ok(SelectedAuthorization::Session(AuthenticationMethod::Basic))
        }
        Ok(_) | Err(_) => Ok(SelectedAuthorization::Unrelated),
    }
}

fn inside_validity_window(
    claims: &ClientAssertionClaims,
    now: OffsetDateTime,
    maximum_clock_skew: Duration,
) -> bool {
    let Ok(skew) = i64::try_from(maximum_clock_skew.as_secs()) else {
        return false;
    };
    let timestamp = now.unix_timestamp();
    claims.iat <= timestamp.saturating_add(skew) && claims.exp > timestamp.saturating_sub(skew)
}

fn supports_identity_method(agent_did: &str, methods: &[IdentityMethod]) -> bool {
    methods.iter().any(|method| match method {
        IdentityMethod::DidWeb => agent_did.starts_with("did:web:"),
        IdentityMethod::Other(method) => agent_did.starts_with(&format!("{method}:")),
    })
}
