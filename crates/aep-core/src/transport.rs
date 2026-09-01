use async_trait::async_trait;
use http::{HeaderMap, Method, StatusCode};
use std::{error::Error as StdError, fmt};

use thiserror::Error;
use url::Url;

#[derive(Clone)]
pub struct HttpRequest {
    pub method: Method,
    pub url: Url,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &"[REDACTED]")
            .field("headers", &"[REDACTED]")
            .field("body", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone)]
pub struct HttpResponse {
    pub status: StatusCode,
    pub final_url: Url,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("final_url", &"[REDACTED]")
            .field("headers", &"[REDACTED]")
            .field("body", &"[REDACTED]")
            .finish()
    }
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

    #[test]
    fn redacts_http_messages_from_debug_output() {
        let request = HttpRequest {
            method: Method::POST,
            url: Url::parse("https://service.example/path?token=secret").expect("URL"),
            headers: HeaderMap::from_iter([(
                http::header::AUTHORIZATION,
                "Bearer secret".parse().expect("header"),
            )]),
            body: b"secret body".to_vec(),
        };
        let response = HttpResponse {
            status: StatusCode::OK,
            final_url: request.url.clone(),
            headers: request.headers.clone(),
            body: request.body.clone(),
        };
        for output in [format!("{request:?}"), format!("{response:?}")] {
            assert!(!output.contains("secret"));
            assert!(output.contains("[REDACTED]"));
        }
    }
}
