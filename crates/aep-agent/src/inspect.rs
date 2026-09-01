use std::time::Duration;

use aep_core::{
    DEFAULT_INSPECT_FRESHNESS, DidWebDocumentUrlOptions, HttpRequest, MEDIA_TYPE, WELL_KNOWN_PATH,
    did_web_document_url_with_options, parse_inspect_document,
};
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use time::OffsetDateTime;
use url::Url;

use crate::{AgentError, InspectCacheEntry, InspectErrorCode, Inspection, Session, same_origin};

const MAXIMUM_REDIRECTS: usize = 5;

impl Session {
    pub async fn inspect(&self) -> Result<Inspection, AgentError> {
        let _guard = self.inspect_lock.lock().await;
        let inspect_url = self.service_url.join(WELL_KNOWN_PATH)?;
        let mut cached = self.client.inspect_cache.find(&inspect_url).await?;
        if let Some(entry) = &cached
            && cache_fresh(entry, self.client.clock.now())
        {
            return inspection_from_cache(
                &self.service_url,
                &inspect_url,
                entry.clone(),
                self.client.allow_insecure_loopback,
            );
        }
        if cached
            .as_ref()
            .is_some_and(|entry| !safe_target(&entry.final_url, &inspect_url))
        {
            self.client.inspect_cache.delete(&inspect_url).await?;
            cached = None;
        }
        let mut current = cached
            .as_ref()
            .map_or_else(|| inspect_url.clone(), |entry| entry.final_url.clone());
        for redirects in 0..=MAXIMUM_REDIRECTS {
            let mut headers = HeaderMap::new();
            headers.insert(header::ACCEPT, HeaderValue::from_static(MEDIA_TYPE));
            if let Some(entry) = &cached {
                if let Some(value) = entry.etag.as_deref().and_then(header_value) {
                    headers.insert(header::IF_NONE_MATCH, value);
                }
                if let Some(value) = entry.last_modified.as_deref().and_then(header_value) {
                    headers.insert(header::IF_MODIFIED_SINCE, value);
                }
            }
            let response = self
                .client
                .inspect_transport
                .send(HttpRequest {
                    method: Method::GET,
                    url: current.clone(),
                    headers,
                    body: Vec::new(),
                })
                .await
                .map_err(|error| {
                    inspect_error(InspectErrorCode::HttpError, error.to_string(), None)
                })?;
            if response.final_url != current {
                return Err(inspect_error(
                    InspectErrorCode::InvalidRedirect,
                    "transport followed an Inspect redirect",
                    Some(response.status.as_u16()),
                ));
            }
            if is_redirect(response.status) {
                if redirects == MAXIMUM_REDIRECTS {
                    return Err(inspect_error(
                        InspectErrorCode::InvalidRedirect,
                        "exceeded five redirects",
                        Some(response.status.as_u16()),
                    ));
                }
                let location = response
                    .headers
                    .get(header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .ok_or_else(|| {
                        inspect_error(
                            InspectErrorCode::InvalidRedirect,
                            "redirect omitted Location",
                            Some(response.status.as_u16()),
                        )
                    })?;
                let next = current.join(location).map_err(|_| {
                    inspect_error(
                        InspectErrorCode::InvalidRedirect,
                        "redirect Location is invalid",
                        Some(response.status.as_u16()),
                    )
                })?;
                if !safe_target(&next, &current) {
                    return Err(inspect_error(
                        InspectErrorCode::InvalidRedirect,
                        "redirect changed origin or scheme",
                        Some(response.status.as_u16()),
                    ));
                }
                current = next;
                continue;
            }
            let inspection = if response.status == StatusCode::NOT_MODIFIED {
                let mut entry = cached.clone().ok_or_else(|| {
                    inspect_error(
                        InspectErrorCode::HttpError,
                        "returned 304 without a cached document",
                        Some(304),
                    )
                })?;
                entry.cached_at = self.client.clock.now();
                entry.final_url = current.clone();
                merge_cache_headers(&mut entry, &response.headers);
                inspection_from_cache(
                    &self.service_url,
                    &inspect_url,
                    entry,
                    self.client.allow_insecure_loopback,
                )?
            } else {
                parse_response(self, &inspect_url, &current, response)?
            };
            let entry = InspectCacheEntry {
                cache_control: inspection.cache_control.clone(),
                cached_at: self.client.clock.now(),
                document: inspection.document.clone(),
                etag: inspection.etag.clone(),
                final_url: inspection.final_url.clone(),
                last_modified: inspection.last_modified.clone(),
            };
            if directive(inspection.cache_control.as_deref(), "no-store").is_some() {
                self.client.inspect_cache.delete(&inspect_url).await?;
            } else {
                self.client.inspect_cache.save(&inspect_url, entry).await?;
            }
            return Ok(inspection);
        }
        unreachable!("redirect loop returns or continues within its bound")
    }
}

fn parse_response(
    session: &Session,
    inspect_url: &Url,
    current: &Url,
    response: aep_core::HttpResponse,
) -> Result<Inspection, AgentError> {
    let status = response.status.as_u16();
    if !response.status.is_success() {
        return Err(inspect_error(
            InspectErrorCode::HttpError,
            format!("HTTP {status}"),
            Some(status),
        ));
    }
    if !media_type_matches(response.headers.get(header::CONTENT_TYPE), MEDIA_TYPE) {
        return Err(inspect_error(
            InspectErrorCode::InvalidMediaType,
            "response media type is invalid",
            Some(status),
        ));
    }
    if response.body.len() > session.client.maximum_response_bytes {
        return Err(inspect_error(
            InspectErrorCode::ResponseTooLarge,
            "response exceeds the configured limit",
            Some(status),
        ));
    }
    let document = parse_inspect_document(&response.body).map_err(|error| {
        let code = if serde_json::from_slice::<serde_json::Value>(&response.body).is_err() {
            InspectErrorCode::InvalidJson
        } else {
            InspectErrorCode::ValidationFailed
        };
        inspect_error(code, error.to_string(), Some(status))
    })?;
    let inspection = Inspection {
        cache_control: header_string(&response.headers, header::CACHE_CONTROL),
        document,
        etag: header_string(&response.headers, header::ETAG),
        final_url: current.clone(),
        inspect_url: inspect_url.clone(),
        last_modified: header_string(&response.headers, header::LAST_MODIFIED),
        service_url: session.service_url.clone(),
    };
    validate_service_identity(&inspection, session.client.allow_insecure_loopback)?;
    Ok(inspection)
}

fn inspection_from_cache(
    service_url: &Url,
    inspect_url: &Url,
    entry: InspectCacheEntry,
    allow_insecure_loopback: bool,
) -> Result<Inspection, AgentError> {
    let inspection = Inspection {
        cache_control: entry.cache_control,
        document: entry.document,
        etag: entry.etag,
        final_url: entry.final_url,
        inspect_url: inspect_url.clone(),
        last_modified: entry.last_modified,
        service_url: service_url.clone(),
    };
    validate_service_identity(&inspection, allow_insecure_loopback)?;
    Ok(inspection)
}

fn validate_service_identity(
    inspection: &Inspection,
    allow_insecure_loopback: bool,
) -> Result<(), AgentError> {
    let did = &inspection.document.service.did;
    if !did.starts_with("did:web:") {
        return Err(inspect_error(
            InspectErrorCode::ServiceIdentityMismatch,
            "Service DID has no supported origin binding",
            None,
        ));
    }
    let document_url = did_web_document_url_with_options(
        did,
        DidWebDocumentUrlOptions {
            allow_insecure_loopback,
        },
    )
    .map_err(|_| {
        inspect_error(
            InspectErrorCode::ServiceIdentityMismatch,
            "Service DID does not match the Inspect origin",
            None,
        )
    })?;
    if !same_origin(&document_url, &inspection.final_url) {
        return Err(inspect_error(
            InspectErrorCode::ServiceIdentityMismatch,
            "Service DID does not match the Inspect origin",
            None,
        ));
    }
    Ok(())
}

fn cache_fresh(entry: &InspectCacheEntry, now: OffsetDateTime) -> bool {
    if directive(entry.cache_control.as_deref(), "no-cache").is_some()
        || directive(entry.cache_control.as_deref(), "no-store").is_some()
    {
        return false;
    }
    let freshness = match directive(entry.cache_control.as_deref(), "max-age") {
        Some(value) => match value.parse::<u64>() {
            Ok(value) => Duration::from_secs(value),
            Err(_) => return false,
        },
        None => DEFAULT_INSPECT_FRESHNESS,
    };
    let Ok(freshness) = time::Duration::try_from(freshness) else {
        return false;
    };
    entry
        .cached_at
        .checked_add(freshness)
        .is_some_and(|expires| expires > now)
}

fn directive<'a>(value: Option<&'a str>, name: &str) -> Option<&'a str> {
    value?.split(',').find_map(|part| {
        let mut fields = part.trim().splitn(2, '=');
        let field = fields.next()?;
        field
            .eq_ignore_ascii_case(name)
            .then(|| fields.next().unwrap_or("").trim_matches('"'))
    })
}

fn merge_cache_headers(entry: &mut InspectCacheEntry, headers: &HeaderMap) {
    if let Some(value) = header_string(headers, header::CACHE_CONTROL) {
        entry.cache_control = Some(value);
    }
    if let Some(value) = header_string(headers, header::ETAG) {
        entry.etag = Some(value);
    }
    if let Some(value) = header_string(headers, header::LAST_MODIFIED) {
        entry.last_modified = Some(value);
    }
}

fn media_type_matches(value: Option<&HeaderValue>, expected: &str) -> bool {
    value
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case(expected))
}

fn safe_target(target: &Url, reference: &Url) -> bool {
    target.username().is_empty()
        && target.password().is_none()
        && target.fragment().is_none()
        && target.scheme() == reference.scheme()
        && same_origin(target, reference)
}

fn is_redirect(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

fn header_string(headers: &HeaderMap, name: header::HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn header_value(value: &str) -> Option<HeaderValue> {
    HeaderValue::from_str(value).ok()
}

fn inspect_error(
    code: InspectErrorCode,
    message: impl Into<String>,
    status: Option<u16>,
) -> AgentError {
    AgentError::Inspect {
        code,
        message: message.into(),
        status,
    }
}
