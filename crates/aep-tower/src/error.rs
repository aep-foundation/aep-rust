use thiserror::Error;

#[derive(Debug, Error)]
pub enum TowerError {
    #[error(transparent)]
    Core(#[from] aep_core::CoreError),
    #[error("invalid AEP HTTP adapter configuration: {0}")]
    InvalidConfiguration(String),
    #[error("read AEP HTTP request body: {0}")]
    RequestBody(String),
    #[error("AEP HTTP request exceeds the configured body limit")]
    RequestTooLarge,
    #[error(transparent)]
    Service(#[from] aep_service::ServiceError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Url(#[from] url::ParseError),
}
