use aep_core::{HttpRequest, HttpResponse, HttpTransport, TransportError};
use async_trait::async_trait;
use futures::StreamExt as _;

pub struct ReqwestTransport {
    client: reqwest::Client,
    maximum_response_bytes: usize,
}

impl ReqwestTransport {
    pub fn new(
        maximum_response_bytes: usize,
        timeout: std::time::Duration,
    ) -> Result<Self, TransportError> {
        if maximum_response_bytes == 0 || timeout.is_zero() {
            return Err(TransportError::new(
                "HTTP response limit and timeout must be positive",
            ));
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()
            .map_err(|error| TransportError::with_source("build HTTP client", error))?;
        Ok(Self {
            client,
            maximum_response_bytes,
        })
    }
}

#[async_trait]
impl HttpTransport for ReqwestTransport {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let mut builder = self
            .client
            .request(request.method, request.url.clone())
            .headers(request.headers);
        if !request.body.is_empty() {
            builder = builder.body(request.body);
        }
        let response = builder
            .send()
            .await
            .map_err(|error| TransportError::with_source("send HTTP request", error))?;
        let status = response.status();
        let final_url = response.url().clone();
        let headers = response.headers().clone();
        let mut stream = response.bytes_stream();
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk =
                chunk.map_err(|error| TransportError::with_source("read HTTP response", error))?;
            if body.len().saturating_add(chunk.len()) > self.maximum_response_bytes {
                return Err(TransportError::new(
                    "HTTP response exceeds the configured limit",
                ));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(HttpResponse {
            status,
            final_url,
            headers,
            body,
        })
    }
}
