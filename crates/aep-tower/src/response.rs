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
    // The registry spells each code in lower snake case and the published titles are the same
    // words as one sentence, so only the first letter is capitalised. Title-casing every word
    // would disagree with the Problem Details the Service itself emits for the same code.
    let mut characters = code.as_str().replace('_', " ").into_bytes();
    if let Some(first) = characters.first_mut() {
        first.make_ascii_uppercase();
    }
    let title = String::from_utf8(characters).unwrap_or_else(|_| code.as_str().to_owned());
    let problem = new_problem_details(code, title, i64::from(status.as_u16()));
    json_response(status, aep_core::PROBLEM_MEDIA_TYPE, &problem)
        .unwrap_or_else(|_| empty_response(StatusCode::INTERNAL_SERVER_ERROR))
}

/// Builds the `405` for a known AEP endpoint reached with the wrong method.
///
/// RFC 9110 Section 15.5.6 requires the `Allow` field to name every method the target resource
/// supports, and the body is AEP Problem Details so that a caller parses this failure the same
/// way it parses every other one.
pub(crate) fn method_not_allowed(allow: &'static str) -> HttpResponse {
    let mut response = problem_response(ErrorCode::InvalidRequest, StatusCode::METHOD_NOT_ALLOWED);
    response
        .headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static(allow));
    response
}

/// Reduces a `GET` response to the `HEAD` response for the same target.
///
/// RFC 9110 Section 9.3.2 makes `HEAD` identical to `GET` except that no content is sent, and the
/// representation metadata is unchanged, so `Content-Length` keeps the length the `GET` response
/// would have carried.
pub(crate) fn head_response(response: HttpResponse) -> HttpResponse {
    let (mut parts, body) = response.into_parts();
    let length = http_body::Body::size_hint(&body).exact().unwrap_or(0);
    parts
        .headers
        .insert(header::CONTENT_LENGTH, HeaderValue::from(length));
    Response::from_parts(parts, Full::new(Bytes::new()))
}

pub(crate) fn empty_response(status: StatusCode) -> HttpResponse {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = status;
    response
}

pub(crate) fn internal_error() -> HttpResponse {
    empty_response(StatusCode::INTERNAL_SERVER_ERROR)
}
