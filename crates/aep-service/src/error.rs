use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("invalid AEP Service configuration: {0}")]
    InvalidConfiguration(String),
    #[error("AEP Service store failed: {0}")]
    Store(String),
    #[error("AEP Service handler failed: {0}")]
    Handler(String),
    #[error(transparent)]
    Core(#[from] aep_core::CoreError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
