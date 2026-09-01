# aep-agent

Agent-side inspection, enrollment, credential, lifecycle, and protected-resource authentication
workflows for the Agent Enrollment Protocol.

## What it provides

- `Client` and Service-scoped `Session` handles for Inspect, Enroll, Status, Grant, and Revoke.
- same-origin Inspect redirects, bounded responses, HTTP caching, and conditional revalidation;
- required-Claim checks before Enroll;
- Service-scoped identity storage and signed client assertions;
- credential storage, expiration, selection, presentation, revocation, and explicit local removal;
- cancellable Status polling through ordinary Rust future cancellation; and
- protected-resource authentication selected in the Service's advertised order.

The application supplies an `IdentityProvider`. It may keep signing keys locally or delegate
provisioning and signing to an AEP Platform. `IdentityStore`, `CredentialStore`, `InspectCache`,
`HttpTransport`, `Clock`, `Delay`, and `IdempotencyKeyProvider` can also be replaced. In-memory
stores and a Rustls-backed HTTP transport are the defaults.

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

Call `inspect` before presenting capabilities, `enroll` with the requested Claim values, and
`wait_for_active` when Enroll returns a pending state. Grant stores built-in credentials after it
confirms active enrollment. `authentication` returns the HTTP fields for a protected resource on
the same Service origin.

Authentication methods are never inferred. If Inspect omits `authentication`, protected-resource
authentication fails. When credentials and `aep-jwt` are advertised, the Agent tries stored
credentials that occur before `aep-jwt` and uses the client assertion only when the advertised
ordering reaches it. Callers can request one credential or require a client assertion explicitly.

The default stores are process-local. Applications that need credentials or identities after a
restart must provide durable store implementations. Secret-bearing store implementations are
responsible for encryption and access control appropriate to their environment.

See the [workspace guide](../../README.md), the [`aep-core` models](../aep-core/README.md), and the
[AEP specifications](https://github.com/aep-foundation/aep-specs).
