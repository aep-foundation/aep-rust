use aep_core::{ErrorCode, new_problem_details};
use aep_service::ServiceResponse;
use bytes::Bytes;
use http::{HeaderValue, Response, StatusCode, header};
use http_body_util::Full;

use crate::TowerError;

pub type HttpResponse = Response<Full<Bytes>>;

pub(crate) fn service_response(response: ServiceResponse) -> Result<HttpResponse, TowerError> {
    let status = StatusCode::from_u16(response.status).map_err(|_| {
        TowerError::InvalidConfiguration("Service returned an invalid HTTP status".to_owned())
    })?;
    let body = serde_json::to_vec(&response.to_json()?)?;
    let mut result = Response::new(Full::new(Bytes::from(body)));
    *result.status_mut() = status;
    *result.headers_mut() = response.headers;
    Ok(result)
}

pub(crate) fn json_response(
    status: StatusCode,
    content_type: &'static str,
    value: &impl serde::Serialize,
) -> Result<HttpResponse, TowerError> {
    let mut response = Response::new(Full::new(Bytes::from(serde_json::to_vec(value)?)));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    Ok(response)
}

pub(crate) fn problem_response(code: ErrorCode, status: StatusCode) -> HttpResponse {
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
    let problem = new_problem_details(code, title, i64::from(status.as_u16()));
    json_response(status, aep_core::PROBLEM_MEDIA_TYPE, &problem)
        .unwrap_or_else(|_| empty_response(StatusCode::INTERNAL_SERVER_ERROR))
}

pub(crate) fn method_not_allowed(method: &'static str) -> HttpResponse {
    let mut response = empty_response(StatusCode::METHOD_NOT_ALLOWED);
    response
        .headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static(method));
    response
}

pub(crate) fn empty_response(status: StatusCode) -> HttpResponse {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = status;
    response
}

pub(crate) fn internal_error() -> HttpResponse {
    empty_response(StatusCode::INTERNAL_SERVER_ERROR)
}
