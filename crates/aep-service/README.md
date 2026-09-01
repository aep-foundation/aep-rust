# aep-service

`aep-service` provides the framework-neutral Service implementation for the Agent Enrollment
Protocol. It builds the Inspect document, verifies client assertions, enforces replay and
idempotency rules, manages enrollment lifecycle state, dispatches Grant and Revoke handlers, and
authenticates protected resources.

## Install

```toml
[dependencies]
aep-service = "0.1"
```

## Create a Service

```rust
use std::{sync::Arc, time::Duration};

use aep_service::{
    DidWebClientAssertionVerifier, ReqwestTransport, Service, ServiceOptions,
};

let transport = Arc::new(ReqwestTransport::new(
    1 << 20,
    Duration::from_secs(10),
)?);
let verifier = Arc::new(DidWebClientAssertionVerifier::new(transport, false));
let options = ServiceOptions::new("did:web:service.example", verifier);
let service = Service::new(options)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

The default Service supports Inspect, Enroll, and Status with in-memory enrollment, assertion
replay, and command-idempotency stores. Set `ServiceOptions` fields to advertise Claims,
authentication methods, Grant Types, OpenAPI metadata, and extensions. Replace the memory stores
with durable implementations before running more than one process or retaining state across
restarts.

## Connect HTTP routes

Expose `service.inspect_document()` at `/.well-known/aep`. Route the four authenticated commands to
`Service::enroll`, `Service::status`, `Service::grant`, and `Service::revoke`. Each command returns a
`ServiceResponse` containing the HTTP status, headers, and a typed `ResponseBody`; use
`ResponseBody::to_json()` for the wire body.

`Enroll`, `Grant`, and `Revoke` require a non-empty `Idempotency-Key` value through
`IdempotentCommandOptions`. `Status` uses `AuthenticatedCommandOptions`. The application adapter is
responsible for extracting the AEP client assertion and idempotency header from the incoming
request without logging either value.

Call `Service::authenticate_protected_resource` before serving an authenticated application
resource. It accepts typed headers, method, and URL and returns either an `AuthenticatedPrincipal`
or the complete `401` AEP challenge response.

## Grant Types

Register each advertised Grant Type with a `GrantTypeDefinition` and a `GrantTypeHandler`. The
handler issues a JSON object containing a non-empty, globally unique `credential_id`, revokes the
credential targets described by `RevokeRequest`, and may authenticate its credential presentation
at protected resources. A Service does not advertise Grant or Revoke when no Grant Types are
configured.

## Verification boundary

`DidWebClientAssertionVerifier` performs real EdDSA or ES256 verification after resolving the
assertion key from the Agent's `did:web` document. Supply an alternate `ClientAssertionVerifier`
for a different supported identity or hosted verification boundary. The Service independently
checks audience, operation, resource, validity window, identity method, and atomic replay
consumption after verification.

See the [workspace guide](../../README.md) and the
[AEP specifications](https://github.com/aep-foundation/aep-specs).
