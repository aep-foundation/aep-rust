use thiserror::Error;

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("invalid AEP Platform configuration: {0}")]
    InvalidConfiguration(String),
    #[error("AEP Platform store failed: {0}")]
    Store(String),
    #[error("AEP Platform handler failed: {0}")]
    Handler(String),
    #[error(transparent)]
    Core(#[from] aep_core::CoreError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Url(#[from] url::ParseError),
}
