use std::{
    convert::Infallible,
    error::Error,
    sync::Arc,
    task::{Context, Poll},
};

use aep_core::{
    AuthorizationCarrier, Command, CredentialScheme, ErrorCode, command_path_from_inspect,
    parse_protected_resource_authorization,
};
use aep_service::{AuthenticatedCommandOptions, IdempotentCommandOptions, Service};
use bytes::{Buf, Bytes};
use futures::{FutureExt as _, future::BoxFuture};
use http::{HeaderMap, Method, Request, StatusCode, header};
use http_body::Body;
use http_body_util::{BodyExt as _, LengthLimitError, Limited};
use tower::Service as TowerService;

use crate::{
    HttpResponse, TowerError,
    response::{
        empty_response, internal_error, json_response, method_not_allowed, problem_response,
        service_response,
    },
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandPaths {
    pub enroll: String,
    pub grant: String,
    pub inspect: String,
    pub revoke: String,
    pub status: String,
}

impl CommandPaths {
    fn new(service: &Service) -> Result<Self, TowerError> {
        let inspect = service.inspect_document();
        Ok(Self {
            enroll: command_path_from_inspect(&inspect, &Command::Enroll)?,
            grant: command_path_from_inspect(&inspect, &Command::Grant)?,
            inspect: aep_core::WELL_KNOWN_PATH.to_owned(),
            revoke: command_path_from_inspect(&inspect, &Command::Revoke)?,
            status: command_path_from_inspect(&inspect, &Command::Status)?,
        })
    }
}

#[derive(Clone)]
pub struct CommandService {
    maximum_request_bytes: usize,
    paths: CommandPaths,
    service: Arc<Service>,
}

impl CommandService {
    pub fn new(service: Arc<Service>, maximum_request_bytes: usize) -> Result<Self, TowerError> {
        if maximum_request_bytes == 0 {
            return Err(TowerError::InvalidConfiguration(
                "request body limit must be positive".to_owned(),
            ));
        }
        Ok(Self {
            maximum_request_bytes,
            paths: CommandPaths::new(&service)?,
            service,
        })
    }

    pub const fn paths(&self) -> &CommandPaths {
        &self.paths
    }

    pub async fn dispatch<B>(&self, request: Request<B>) -> Result<HttpResponse, TowerError>
    where
        B: Body + Send + 'static,
        B::Data: Buf + Send,
        B::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        let route = self.route(request.method(), request.uri().path());
        match route {
            Route::Unknown => return Ok(empty_response(StatusCode::NOT_FOUND)),
            Route::MethodNotAllowed(method) => return Ok(method_not_allowed(method)),
            Route::Inspect => {
                return json_response(
                    StatusCode::OK,
                    aep_core::MEDIA_TYPE,
                    &self.service.inspect_document(),
                );
            }
            Route::Status => {
                let response = self
                    .service
                    .status(AuthenticatedCommandOptions {
                        client_assertion: client_assertion(request.headers()),
                    })
                    .await?;
                return service_response(response);
            }
            Route::Enroll | Route::Grant | Route::Revoke => {}
        }
        if !is_aep_content_type(request.headers()) {
            return Ok(problem_response(
                ErrorCode::InvalidRequest,
                StatusCode::BAD_REQUEST,
            ));
        }
        let client_assertion = client_assertion(request.headers());
        let idempotency_key = header_value(request.headers(), "idempotency-key");
        let body = collect_body(request.into_body(), self.maximum_request_bytes).await?;
        let options = IdempotentCommandOptions {
            client_assertion,
            idempotency_key,
        };
        let response = match route {
            Route::Enroll => self.service.enroll(&body, options).await,
            Route::Grant => self.service.grant(&body, options).await,
            Route::Revoke => self.service.revoke(&body, options).await,
            Route::Inspect | Route::Status | Route::Unknown | Route::MethodNotAllowed(_) => {
                unreachable!()
            }
        }?;
        service_response(response)
    }

    fn route(&self, method: &Method, path: &str) -> Route {
        for (candidate, expected, route) in [
            (self.paths.inspect.as_str(), Method::GET, Route::Inspect),
            (self.paths.enroll.as_str(), Method::POST, Route::Enroll),
            (self.paths.status.as_str(), Method::GET, Route::Status),
            (self.paths.grant.as_str(), Method::POST, Route::Grant),
            (self.paths.revoke.as_str(), Method::POST, Route::Revoke),
        ] {
            if path == candidate {
                return if method == expected {
                    route
                } else {
                    Route::MethodNotAllowed(if expected == Method::GET {
                        "GET"
                    } else {
                        "POST"
                    })
                };
            }
        }
        Route::Unknown
    }
}

impl<B> TowerService<Request<B>> for CommandService
where
    B: Body + Send + 'static,
    B::Data: Buf + Send,
    B::Error: Into<Box<dyn Error + Send + Sync>>,
{
    type Response = HttpResponse;
    type Error = Infallible;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let service = self.clone();
        async move {
            let response = match service.dispatch(request).await {
                Ok(response) => response,
                Err(TowerError::RequestTooLarge) => {
                    problem_response(ErrorCode::InvalidRequest, StatusCode::PAYLOAD_TOO_LARGE)
                }
                Err(_) => internal_error(),
            };
            Ok(response)
        }
        .boxed()
    }
}

#[derive(Clone, Copy)]
enum Route {
    Enroll,
    Grant,
    Inspect,
    MethodNotAllowed(&'static str),
    Revoke,
    Status,
    Unknown,
}

async fn collect_body<B>(body: B, maximum_bytes: usize) -> Result<Bytes, TowerError>
where
    B: Body,
    B::Data: Buf,
    B::Error: Into<Box<dyn Error + Send + Sync>>,
{
    Limited::new(body, maximum_bytes)
        .collect()
        .await
        .map(|body| body.to_bytes())
        .map_err(|error| {
            if error.downcast_ref::<LengthLimitError>().is_some() {
                TowerError::RequestTooLarge
            } else {
                TowerError::RequestBody(error.to_string())
            }
        })
}

fn client_assertion(headers: &HeaderMap) -> String {
    let values = headers
        .get_all(header::AUTHORIZATION)
        .iter()
        .collect::<Vec<_>>();
    if values.len() != 1 {
        return String::new();
    }
    let Ok(value) = values[0].to_str() else {
        return String::new();
    };
    let Ok(parsed) = parse_protected_resource_authorization(value, AuthorizationCarrier::Standard)
    else {
        return String::new();
    };
    if parsed.scheme == CredentialScheme::Aep {
        parsed.credentials
    } else {
        String::new()
    }
}

fn header_value(headers: &HeaderMap, name: &str) -> String {
    let values = headers.get_all(name).iter().collect::<Vec<_>>();
    if values.len() == 1 {
        values[0].to_str().unwrap_or_default().to_owned()
    } else {
        String::new()
    }
}

fn is_aep_content_type(headers: &HeaderMap) -> bool {
    let values = headers
        .get_all(header::CONTENT_TYPE)
        .iter()
        .collect::<Vec<_>>();
    values.len() == 1
        && values[0].to_str().is_ok_and(|value| {
            value.split(';').next().is_some_and(|media_type| {
                media_type.trim().eq_ignore_ascii_case(aep_core::MEDIA_TYPE)
            })
        })
}
