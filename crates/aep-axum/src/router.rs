use std::sync::Arc;

use aep_service::Service;
use aep_tower::CommandService;
use axum::Router;

use crate::TowerError;

pub fn router(service: Arc<Service>, maximum_request_bytes: usize) -> Result<Router, TowerError> {
    let commands = CommandService::new(service, maximum_request_bytes)?;
    let paths = commands.paths().clone();
    Ok(Router::new()
        .route_service(&paths.inspect, commands.clone())
        .route_service(&paths.enroll, commands.clone())
        .route_service(&paths.status, commands.clone())
        .route_service(&paths.grant, commands.clone())
        .route_service(&paths.revoke, commands))
}
