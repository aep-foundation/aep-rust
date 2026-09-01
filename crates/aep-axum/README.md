# aep-axum

`aep-axum` provides direct Axum integration for an `aep-service` Service. It mounts the AEP
discovery and lifecycle routes and provides an extractor for authenticated application resources.

## Install

```toml
[dependencies]
aep-axum = "0.1"
aep-service = "0.1"
axum = "0.8"
url = "2.5"
```

## Mount AEP and protect application routes

```rust
use std::sync::Arc;

use aep_axum::{AepPrincipal, AuthenticationOptions, authentication_layer, router};
use aep_service::Service;
use axum::{Router, routing::get};
use url::Url;

# fn example(service: Arc<Service>) -> Result<(), Box<dyn std::error::Error>> {
let protected = Router::new()
    .route("/private", get(|principal: AepPrincipal| async move { principal.agent_did.clone() }))
    .route_layer(authentication_layer(
        service.clone(),
        AuthenticationOptions::new(Url::parse("https://service.example")?),
    )?);

let application = router(service, 1 << 20)?.merge(protected);
# let _ = application;
# Ok(())
# }
```

The command router honors the Service's configured `endpoint_base`. Apply the authentication layer
only to protected application routes. Successful authentication makes `AepPrincipal` available to
the handler; rejected authentication returns the complete AEP challenge without running it.

The underlying `aep-service` and `aep-tower` crates remain independently usable. See the
[workspace guide](../../README.md) and the
[AEP specifications](https://github.com/aep-foundation/aep-specs).
