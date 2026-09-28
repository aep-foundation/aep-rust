use std::{sync::Arc, time::Duration};

use aep_core::{
    ClientAssertionClaims, HttpRequest, HttpTransport, decode_jwt_unverified,
    parse_client_assertion_claims,
};
use async_trait::async_trait;
use futures::future::{Either, select};
use http::{HeaderMap, HeaderValue, Method, header};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use url::Url;

use crate::{
    ClientAssertionVerificationContext, ClientAssertionVerifier, ReqwestTransport, ServiceError,
};

#[derive(Clone)]
pub struct HostedPlatformClientAssertionVerifierOptions {
    pub authorization: Option<String>,
    pub endpoint: String,
    pub maximum_response_bytes: usize,
    pub request_timeout: Duration,
    pub transport: Option<Arc<dyn HttpTransport>>,
}

impl HostedPlatformClientAssertionVerifierOptions {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            authorization: None,
            endpoint: endpoint.into(),
            maximum_response_bytes: 1 << 20,
            request_timeout: Duration::from_secs(30),
            transport: None,
        }
    }
}

pub struct HostedPlatformClientAssertionVerifier {
    authorization: Option<HeaderValue>,
    endpoint: Url,
    maximum_response_bytes: usize,
    request_timeout: Duration,
    transport: Arc<dyn HttpTransport>,
}

impl HostedPlatformClientAssertionVerifier {
    pub fn new(
        options: HostedPlatformClientAssertionVerifierOptions,
    ) -> Result<Self, ServiceError> {
        let endpoint = Url::parse(&options.endpoint).map_err(|_| ServiceError::InvalidConfiguration(
            "AEP hosted verification requires an HTTPS endpoint without credentials or a fragment".into()))?;
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(ServiceError::InvalidConfiguration(
                "AEP hosted verification requires an HTTPS endpoint without credentials or a fragment".into()));
        }
        if options.maximum_response_bytes == 0 || options.request_timeout.is_zero() {
            return Err(ServiceError::InvalidConfiguration(
                "AEP hosted verification response limit and timeout must be positive".into(),
            ));
        }
        let authorization = options
            .authorization
            .as_deref()
            .map(|value| {
                let mut value = HeaderValue::from_str(value).map_err(|_| {
                    ServiceError::InvalidConfiguration(
                        "AEP hosted verification authorization is not a valid HTTP field value"
                            .into(),
                    )
                })?;
                value.set_sensitive(true);
                Ok::<_, ServiceError>(value)
            })
            .transpose()?;
        let transport = match options.transport {
            Some(transport) => transport,
            None => Arc::new(
                ReqwestTransport::new(options.maximum_response_bytes, options.request_timeout)
                    .map_err(|_| {
                        ServiceError::InvalidConfiguration(
                            "AEP hosted verification HTTP client could not be created".into(),
                        )
                    })?,
            ),
        };
        Ok(Self {
            authorization,
            endpoint,
            maximum_response_bytes: options.maximum_response_bytes,
            request_timeout: options.request_timeout,
            transport,
        })
    }
}

#[derive(Deserialize)]
struct VerificationResponse {
    agent_did: Option<String>,
    op: Option<aep_core::AssertionOperation>,
    #[serde(rename = "reason")]
    _reason: String,
    service_did: String,
    verified: bool,
}

#[async_trait]
impl ClientAssertionVerifier for HostedPlatformClientAssertionVerifier {
    async fn verify(
        &self,
        context: ClientAssertionVerificationContext,
    ) -> Result<ClientAssertionClaims, ServiceError> {
        let decoded = decode_jwt_unverified(&context.assertion)?;
        if !context
            .signing_algorithms
            .contains(&decoded.header.algorithm)
        {
            return Err(ServiceError::Handler(
                "AEP client assertion algorithm was not advertised by the Service".into(),
            ));
        }
        let claims = parse_client_assertion_claims(&serde_json::to_vec(&decoded.payload)?)
            .map_err(|_| ServiceError::Handler("AEP client assertion claims are invalid".into()))?;
        let mut body = json!({"client_assertion":context.assertion,"op":context.operation,"service_did":context.service_did});
        if let Some(resource) = &context.resource {
            body["resource"] = json!(resource.as_str());
        }
        let body = serde_json::to_vec(&body)?;
        // Command retries use fresh assertions; the key identifies this exact verification body.
        let key: String = Sha256::digest(&body)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let mut headers = HeaderMap::from_iter([
            (
                header::ACCEPT,
                HeaderValue::from_static(aep_core::MEDIA_TYPE),
            ),
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static(aep_core::MEDIA_TYPE),
            ),
            (
                http::HeaderName::from_static("idempotency-key"),
                HeaderValue::from_str(&key).map_err(|_| {
                    ServiceError::Handler("AEP hosted verification key is invalid".into())
                })?,
            ),
        ]);
        if let Some(authorization) = &self.authorization {
            headers.insert(header::AUTHORIZATION, authorization.clone());
        }
        let request = HttpRequest {
            method: Method::POST,
            url: self.endpoint.clone(),
            headers,
            body,
        };
        let response = match select(
            self.transport.send(request),
            Box::pin(futures_timer::Delay::new(self.request_timeout)),
        )
        .await
        {
            Either::Left((result, _)) => result.map_err(|_| {
                ServiceError::Handler("AEP hosted verification request failed".into())
            })?,
            Either::Right(_) => {
                return Err(ServiceError::Handler(
                    "AEP hosted verification request timed out".into(),
                ));
            }
        };
        if response.final_url != self.endpoint {
            return Err(ServiceError::Handler(
                "AEP hosted verification redirects are not allowed".into(),
            ));
        }
        if !response.status.is_success() {
            return Err(ServiceError::Handler(format!(
                "AEP hosted verification failed with HTTP {}",
                response.status.as_u16()
            )));
        }
        if response.body.len() > self.maximum_response_bytes {
            return Err(ServiceError::Handler(
                "AEP hosted verification response exceeds the configured limit".into(),
            ));
        }
        let result: VerificationResponse =
            serde_json::from_slice(&response.body).map_err(|_| {
                ServiceError::Handler("AEP hosted verification response is invalid".into())
            })?;
        if !result.verified
            || result.agent_did.as_deref() != Some(claims.sub.as_str())
            || result.op != Some(context.operation)
            || result.service_did != context.service_did
        {
            return Err(ServiceError::Handler(
                "AEP hosted verification did not recognize the client assertion".into(),
            ));
        }
        Ok(claims)
    }
}
