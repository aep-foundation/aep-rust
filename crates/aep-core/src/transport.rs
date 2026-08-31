use async_trait::async_trait;
use http::{HeaderMap, Method, StatusCode};
use std::error::Error as StdError;

use thiserror::Error;
use url::Url;

#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub method: Method,
    pub url: Url,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: StatusCode,
    pub final_url: Url,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct TransportError {
    message: String,
    #[source]
    source: Option<Box<dyn StdError + Send + Sync>>,
}

impl TransportError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    pub fn with_source(
        message: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }
}

#[async_trait]
pub trait HttpTransport: Send + Sync {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError>;
}

#[cfg(test)]
mod tests {
    use std::fmt;

    use super::*;

    #[derive(Debug)]
    struct ExampleError;

    impl fmt::Display for ExampleError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("cause")
        }
    }

    impl StdError for ExampleError {}

    #[test]
    fn preserves_transport_error_context() {
        assert_eq!(
            TransportError::new("request failed").to_string(),
            "request failed"
        );
        let error = TransportError::with_source("request failed", ExampleError);
        assert_eq!(error.to_string(), "request failed");
        assert_eq!(
            StdError::source(&error).map(ToString::to_string),
            Some("cause".to_owned())
        );
    }
}
