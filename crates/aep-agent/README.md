# aep-agent

Agent-side inspection, enrollment, credential, lifecycle, and protected-resource authentication
workflows for the Agent Enrollment Protocol.

## Install

```toml
[dependencies]
aep-agent = "0.1"
```

## What it provides

- `Client` and Service-scoped `Session` handles for Inspect, Enroll, Status, Grant, and Revoke.
- same-origin Inspect redirects, bounded responses, HTTP caching, and conditional revalidation;
- required-Claim checks before Enroll;
- Service-scoped identity storage, local identity-provider contracts, and a production HTTP client
  for Platform-hosted identities;
- credential storage, expiration, selection, presentation, revocation, and explicit local removal;
- cancellable Status polling through ordinary Rust future cancellation; and
- protected-resource authentication selected in the Service's advertised order.

The application supplies an `IdentityProvider`. It may keep signing keys locally or use
`PlatformIdentityProvider` to recover or provision a Service-scoped identity and delegate signing
to an AEP Platform. `IdentityStore`, `CredentialStore`, `InspectCache`, `HttpTransport`, `Clock`,
`Delay`, and `IdempotencyKeyProvider` can also be replaced. In-memory stores and a Rustls-backed
HTTP transport are the defaults.

## Workflow

Create the Agent once, then create inexpensive Service sessions:

```rust,no_run
# use std::sync::Arc;
# use aep_agent::{Client, ClientOptions, IdentityProvider};
# fn identity_provider() -> Arc<dyn IdentityProvider> { unimplemented!() }
let client = Client::new(ClientOptions::new(identity_provider()))?;
let service = client.service("https://service.example")?;

# Ok::<(), aep_agent::AgentError>(())
```

For an HTTP Platform, supply its API authorization and use the provider directly as the Agent's
identity boundary:

```rust,no_run
use aep_agent::{Client, ClientOptions, PlatformIdentityProvider, PlatformIdentityProviderOptions};

let mut platform = PlatformIdentityProviderOptions::new("https://platform.example");
platform.authorization = Some("Bearer platform-access-token".to_owned());
let identity_provider = PlatformIdentityProvider::new(platform)?;
let client = Client::new(ClientOptions::new(identity_provider))?;
let service = client.service("https://service.example")?;

# Ok::<(), aep_agent::AgentError>(())
```

Platform Discovery is cached according to its HTTP freshness and validator metadata. Identity
lookup precedes provisioning so a missing local identity can be recovered without creating a
duplicate. Provision and Sign use distinct idempotency keys. When delegated signing returns a
pending response, the provider either calls the configured `PlatformPendingSignResolver` or
returns `AgentError::PlatformSignPending` with the opaque Platform context and retry interval.

Call `inspect` before presenting capabilities, `enroll` with the requested Claim values, and
`wait_for_active` when Enroll returns a pending state. Grant stores built-in credentials after it
confirms active enrollment. `authentication` returns the HTTP fields for a protected resource on
the same Service origin.

The [`aep-local-lifecycle`](../../examples/aep-local-lifecycle/) example executes Inspect, Enroll,
Status, API-key Grant, protected-resource authentication, targeted Revoke, and JWT fallback with
real assertions and the Service implementation.

Authentication methods are never inferred. If Inspect omits `authentication`, protected-resource
authentication fails. When credentials and `aep-jwt` are advertised, the Agent tries stored
credentials that occur before `aep-jwt` and uses the client assertion only when the advertised
ordering reaches it. Callers can request one credential or require a client assertion explicitly.

The default stores are process-local. Applications that need credentials or identities after a
restart must provide durable store implementations. Secret-bearing store implementations are
responsible for encryption and access control appropriate to their environment.

See the [workspace guide](../../README.md), the [`aep-core` models](../aep-core/README.md), and the
[AEP specifications](https://github.com/aep-foundation/aep-specs).
