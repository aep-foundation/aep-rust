use aep_core::{AgentStatus, ClaimName, ProblemDetails};
use thiserror::Error;

use crate::PlatformPendingSign;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InspectErrorCode {
    HttpError,
    InvalidJson,
    InvalidMediaType,
    InvalidRedirect,
    ResponseTooLarge,
    ServiceIdentityMismatch,
    ValidationFailed,
}

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("{0}")]
    InvalidConfiguration(String),
    #[error("{0}")]
    InvalidServiceReference(String),
    #[error("AEP Inspect failed: {message}")]
    Inspect {
        code: InspectErrorCode,
        message: String,
        status: Option<u16>,
    },
    #[error("AEP Service does not advertise {0}")]
    CommandNotAdvertised(String),
    #[error("AEP command failed with HTTP {status}")]
    Command {
        status: u16,
        problem: Option<Box<ProblemDetails>>,
    },
    #[error("AEP Agent cannot satisfy the Service's required Claim Names: {names}")]
    ClaimRequirements {
        missing: Vec<ClaimName>,
        names: String,
    },
    #[error("AEP Agent identity did not become active: {}", status.as_str())]
    EnrollmentState { status: AgentStatus },
    #[error("AEP Status polling timed out")]
    PollingTimeout,
    #[error("AEP Platform signing is pending")]
    PlatformSignPending { pending: Box<PlatformPendingSign> },
    #[error("AEP Platform command failed with HTTP {status}")]
    PlatformCommand {
        status: u16,
        problem: Option<Box<ProblemDetails>>,
    },
    #[error("AEP Service does not advertise a compatible grant type")]
    NoCompatibleGrantType,
    #[error("AEP Service does not advertise a compatible protected-resource authentication method")]
    NoAuthenticationMethod,
    #[error("{0}")]
    Identity(String),
    #[error("{0}")]
    Credential(String),
    #[error("{0}")]
    Store(String),
    #[error("{0}")]
    Transport(String),
    #[error(transparent)]
    Core(#[from] aep_core::CoreError),
    #[error(transparent)]
    Parse(#[from] aep_core::ParseError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Url(#[from] url::ParseError),
}

impl AgentError {
    pub(crate) fn claims(missing: Vec<ClaimName>) -> Self {
        let names = missing
            .iter()
            .map(ClaimName::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        Self::ClaimRequirements { missing, names }
    }
}
