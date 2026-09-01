# aep-tower

`aep-tower` connects the framework-neutral `aep-service` engine to Tower-compatible HTTP stacks.
It provides a command service for the AEP discovery and lifecycle endpoints and an authentication
layer for protected application resources.

## Install

```toml
[dependencies]
aep-service = "0.1"
aep-tower = "0.1"
```

## Command endpoints

```rust
use std::sync::Arc;

use aep_service::Service;
use aep_tower::CommandService;

# fn example(service: Arc<Service>) -> Result<(), aep_tower::TowerError> {
let commands = CommandService::new(service, 1 << 20)?;
# let _ = commands;
# Ok(())
# }
```

Mount the paths returned by `CommandService::paths()` into the application's router. The adapter
handles Inspect, Enroll, Status, Grant, and Revoke while enforcing the methods, authentication,
idempotency, body limit, and AEP response media types.

## Protected resources

Apply `AuthenticationLayer` to application resources that require an enrolled Agent. Successful
authentication inserts `AuthenticatedPrincipal` into the request extensions. The configured
origin is used to construct the absolute protected-resource URL bound into JWT client assertions.
Plaintext HTTP is rejected unless explicitly enabled for a loopback origin.

The underlying `aep-service` crate remains usable without Tower. See the
[workspace guide](../../README.md) and the
[AEP specifications](https://github.com/aep-foundation/aep-specs).
