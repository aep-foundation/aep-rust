use std::time::{Duration, Instant};

use aep_core::{
    MAX_SERVICE_DOCUMENT_BYTES, PortableServiceDocument, ServiceDocument,
    parse_portable_service_document, validate_service_document,
};
use futures::StreamExt as _;
use http::header;

use crate::{AgentError, http_response::media_type_matches};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DocumentFallback {
    NotAdvertised,
    UnavailableOrUnsupported,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DocumentReadResult {
    pub descriptor: ServiceDocument,
    pub web_url: String,
    pub document: Option<PortableServiceDocument>,
    pub fallback: Option<DocumentFallback>,
}

pub async fn read_service_document(
    descriptor: &ServiceDocument,
    timeout: Duration,
) -> Result<DocumentReadResult, AgentError> {
    validate_service_document(descriptor).map_err(aep_core::CoreError::from)?;
    if timeout.is_zero() || Instant::now().checked_add(timeout).is_none() {
        return Err(AgentError::InvalidConfiguration(
            "Document timeout must be positive and bounded".to_owned(),
        ));
    }
    let mut result = DocumentReadResult {
        descriptor: descriptor.clone(),
        web_url: descriptor
            .representations
            .iter()
            .find(|item| item.media_type == "text/html")
            .expect("validated HTML representation")
            .url
            .clone(),
        document: None,
        fallback: Some(DocumentFallback::NotAdvertised),
    };
    let Some(portable) = descriptor
        .representations
        .iter()
        .find(|item| item.media_type == "application/json")
    else {
        return Ok(result);
    };
    result.document = download_document(&portable.url, &descriptor.id, timeout).await;
    result.fallback = result
        .document
        .is_none()
        .then_some(DocumentFallback::UnavailableOrUnsupported);
    Ok(result)
}

async fn download_document(
    url: &str,
    id: &str,
    timeout: Duration,
) -> Option<PortableServiceDocument> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .build()
        .ok()?;
    let response = client
        .get(url)
        .header(header::ACCEPT, "application/json")
        .header(header::ACCEPT_ENCODING, "identity")
        .send()
        .await
        .ok()?;
    if !response.status().is_success()
        || !media_type_matches(response.headers(), "application/json")
    {
        return None;
    }
    for parameter in response
        .headers()
        .get(header::CONTENT_TYPE)?
        .to_str()
        .ok()?
        .split(';')
        .skip(1)
    {
        if let Some((key, value)) = parameter.trim().split_once('=')
            && key.trim().eq_ignore_ascii_case("charset")
            && !value.trim().trim_matches('"').eq_ignore_ascii_case("utf-8")
        {
            return None;
        }
    }
    if response
        .headers()
        .get(header::CONTENT_ENCODING)
        .is_some_and(|value| !value.as_bytes().eq_ignore_ascii_case(b"identity"))
    {
        return None;
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.ok()?;
        if body.len().saturating_add(chunk.len()) > MAX_SERVICE_DOCUMENT_BYTES {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    parse_portable_service_document(&body, id).ok()
}
