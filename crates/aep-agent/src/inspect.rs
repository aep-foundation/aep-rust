use aep_core::{
    DidWebDocumentUrlOptions, HttpRequest, MEDIA_TYPE, WELL_KNOWN_PATH,
    did_web_document_url_with_options, parse_inspect_document,
};
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use time::OffsetDateTime;
use url::Url;

use crate::http_response::{
    cache_fresh, cache_headers, cache_storable, header_string, media_type_matches,
};
use crate::{AgentError, InspectCacheEntry, InspectErrorCode, Inspection, Session, same_origin};

const MAXIMUM_REDIRECTS: usize = 5;

impl Session {
    pub async fn inspect(&self) -> Result<Inspection, AgentError> {
        let _guard = self.inspect_lock.lock().await;
        let inspect_url = self.service_url.join(WELL_KNOWN_PATH)?;
        let mut cached = self.client.inspect_cache.find(&inspect_url).await?;
        // Custom caches cannot make an unsafe redirect or a no-store representation reusable.
        if cached.as_ref().is_some_and(|entry| {
            !safe_target(&entry.final_url, &inspect_url) || !cache_storable(&entry.headers)
        }) {
            self.client.inspect_cache.delete(&inspect_url).await?;
            if let Some(entry) = &cached
                && entry.final_url != inspect_url
                && safe_target(&entry.final_url, &inspect_url)
            {
                self.client.inspect_cache.delete(&entry.final_url).await?;
            }
            cached = None;
        }
        if let Some(entry) = &cached
            && cache_fresh(&entry.headers, entry.cached_at, self.client.clock.now())
        {
            return inspection_from_cache(
                &self.service_url,
                &inspect_url,
                entry.clone(),
                self.client.allow_insecure_loopback,
            );
        }
        let mut current = cached
            .as_ref()
            .map_or_else(|| inspect_url.clone(), |entry| entry.final_url.clone());
        for redirects in 0..=MAXIMUM_REDIRECTS {
            let mut headers = HeaderMap::new();
            headers.insert(header::ACCEPT, HeaderValue::from_static(MEDIA_TYPE));
            if let Some(entry) = &cached {
                if let Some(value) = entry.headers.get(header::ETAG) {
                    headers.insert(header::IF_NONE_MATCH, value.clone());
                }
                if let Some(value) = entry.headers.get(header::LAST_MODIFIED) {
                    headers.insert(header::IF_MODIFIED_SINCE, value.clone());
                }
            }
            let requested_at = self.client.clock.now();
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
            let received_at = self.client.clock.now();
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
            let entry = if response.status == StatusCode::NOT_MODIFIED {
                let mut entry = cached.clone().ok_or_else(|| {
                    inspect_error(
                        InspectErrorCode::HttpError,
                        "returned 304 without a cached document",
                        Some(304),
                    )
                })?;
                entry.cached_at = received_at;
                entry.final_url = current.clone();
                entry.headers = cache_headers(
                    &response.headers,
                    Some(&entry.headers),
                    requested_at,
                    received_at,
                );
                entry
            } else {
                parse_response(self, &current, response, requested_at, received_at)?
            };
            let inspection = inspection_from_cache(
                &self.service_url,
                &inspect_url,
                entry.clone(),
                self.client.allow_insecure_loopback,
            )?;
            if let Some(previous) = &cached
                && previous.final_url != inspect_url
                && previous.final_url != inspection.final_url
            {
                self.client
                    .inspect_cache
                    .delete(&previous.final_url)
                    .await?;
            }
            // CORE-CACHE-007 keys the entry by the requested advertised URL and updates that key
            // to the final URL once a redirect is accepted, so the document is reachable under
            // either spelling. `no-store` removes both.
            let mut keys = vec![inspect_url.clone()];
            if inspection.final_url != inspect_url {
                keys.push(inspection.final_url.clone());
            }
            for key in keys {
                if !cache_storable(&entry.headers) {
                    self.client.inspect_cache.delete(&key).await?;
                } else {
                    self.client.inspect_cache.save(&key, entry.clone()).await?;
                }
            }
            return Ok(inspection);
        }
        unreachable!("redirect loop returns or continues within its bound")
    }
}

fn parse_response(
    session: &Session,
    current: &Url,
    response: aep_core::HttpResponse,
    requested_at: OffsetDateTime,
    received_at: OffsetDateTime,
) -> Result<InspectCacheEntry, AgentError> {
    let status = response.status.as_u16();
    if !response.status.is_success() {
        return Err(inspect_error(
            InspectErrorCode::HttpError,
            format!("HTTP {status}"),
            Some(status),
        ));
    }
    if !media_type_matches(&response.headers, MEDIA_TYPE) {
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
    Ok(InspectCacheEntry {
        cached_at: received_at,
        document,
        final_url: current.clone(),
        headers: cache_headers(&response.headers, None, requested_at, received_at),
    })
}

fn inspection_from_cache(
    service_url: &Url,
    inspect_url: &Url,
    entry: InspectCacheEntry,
    allow_insecure_loopback: bool,
) -> Result<Inspection, AgentError> {
    let inspection = Inspection {
        cache_control: header_string(&entry.headers, header::CACHE_CONTROL),
        document: entry.document,
        etag: header_string(&entry.headers, header::ETAG),
        final_url: entry.final_url,
        inspect_url: inspect_url.clone(),
        last_modified: header_string(&entry.headers, header::LAST_MODIFIED),
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
