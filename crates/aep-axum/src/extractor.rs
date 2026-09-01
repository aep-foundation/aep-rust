use std::{ops::Deref, sync::Arc};

use aep_service::{AuthenticatedPrincipal, Service};
use aep_tower::AuthenticationLayer;
use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
    response::{IntoResponse as _, Response},
};

use crate::{AuthenticationOptions, TowerError};

#[derive(Clone, Debug)]
pub struct AepPrincipal(pub AuthenticatedPrincipal);

impl Deref for AepPrincipal {
    type Target = AuthenticatedPrincipal;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> FromRequestParts<S> for AepPrincipal
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthenticatedPrincipal>()
            .cloned()
            .map(Self)
            .ok_or_else(|| StatusCode::INTERNAL_SERVER_ERROR.into_response())
    }
}

pub fn authentication_layer(
    service: Arc<Service>,
    options: AuthenticationOptions,
) -> Result<AuthenticationLayer, TowerError> {
    AuthenticationLayer::new(service, options)
}
