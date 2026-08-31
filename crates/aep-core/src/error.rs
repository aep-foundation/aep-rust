use thiserror::Error;

use crate::ErrorCode;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationIssue {
    pub message: String,
    pub path: String,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("invalid AEP {document_type}")]
pub struct ValidationError {
    pub document_type: String,
    pub issues: Vec<ValidationIssue>,
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("invalid JSON in AEP {document_type}: {source}")]
    Json {
        document_type: String,
        #[source]
        source: serde_json::Error,
    },
    #[error(transparent)]
    Validation(#[from] ValidationError),
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("{message}")]
pub struct AuthorizationCarrierError {
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("{0}")]
    Invalid(String),
    #[error("invalid AEP JWT: {0}")]
    Jwt(String),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Transport(#[from] crate::TransportError),
    #[error(transparent)]
    Url(#[from] url::ParseError),
    #[error(transparent)]
    Validation(#[from] ValidationError),
}
