use std::{
    sync::Arc,
    task::{Context, Poll},
};

use aep_service::{ProtectedResourceAuthentication, ProtectedResourceRequest, Service};
use futures::{FutureExt as _, future::BoxFuture};
use http::{Request, Response};
use http_body_util::{Either, Full};
use tower::{Layer, Service as TowerService};
use url::Url;

use crate::{
    TowerError,
    response::{internal_error, service_response},
    url::{request_url, validate_origin},
};

#[derive(Clone, Debug)]
pub struct AuthenticationOptions {
    pub allow_insecure_loopback: bool,
    pub origin: Url,
}

impl AuthenticationOptions {
    pub fn new(origin: Url) -> Self {
        Self {
            allow_insecure_loopback: false,
            origin,
        }
    }
}

#[derive(Clone)]
pub struct AuthenticationLayer {
    options: AuthenticationOptions,
    service: Arc<Service>,
}

impl AuthenticationLayer {
    pub fn new(service: Arc<Service>, options: AuthenticationOptions) -> Result<Self, TowerError> {
        validate_origin(&options.origin, options.allow_insecure_loopback)?;
        Ok(Self { options, service })
    }
}

impl<S> Layer<S> for AuthenticationLayer {
    type Service = AuthenticationService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthenticationService {
            inner,
            options: self.options.clone(),
            service: self.service.clone(),
        }
    }
}

#[derive(Clone)]
pub struct AuthenticationService<S> {
    inner: S,
    options: AuthenticationOptions,
    service: Arc<Service>,
}

impl<S, RequestBody, ResponseBody> TowerService<Request<RequestBody>> for AuthenticationService<S>
where
    S: TowerService<Request<RequestBody>, Response = Response<ResponseBody>>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    RequestBody: Send + 'static,
    ResponseBody: Send + 'static,
{
    type Response = Response<Either<Full<bytes::Bytes>, ResponseBody>>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, mut request: Request<RequestBody>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let options = self.options.clone();
        let service = self.service.clone();
        async move {
            let authentication = match build_protected_resource_request(&options, &request) {
                Ok(request) => service
                    .authenticate_protected_resource(request)
                    .await
                    .map_err(TowerError::from),
                Err(error) => Err(error),
            };
            match authentication {
                Ok(ProtectedResourceAuthentication::Authenticated(principal)) => {
                    request.extensions_mut().insert(principal);
                    let response = inner.call(request).await?;
                    Ok(response.map(Either::Right))
                }
                Ok(ProtectedResourceAuthentication::Rejected(response)) => {
                    Ok(service_response(response)
                        .unwrap_or_else(|_| internal_error())
                        .map(Either::Left))
                }
                Err(_) => Ok(internal_error().map(Either::Left)),
            }
        }
        .boxed()
    }
}

pub fn protected_resource_request<B>(
    options: &AuthenticationOptions,
    request: &Request<B>,
) -> Result<ProtectedResourceRequest, TowerError> {
    validate_origin(&options.origin, options.allow_insecure_loopback)?;
    build_protected_resource_request(options, request)
}

fn build_protected_resource_request<B>(
    options: &AuthenticationOptions,
    request: &Request<B>,
) -> Result<ProtectedResourceRequest, TowerError> {
    Ok(ProtectedResourceRequest {
        headers: request.headers().clone(),
        method: request.method().clone(),
        url: request_url(&options.origin, request.uri())?,
    })
}
