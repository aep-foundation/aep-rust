# aep-agent

Agent-side inspection, enrollment, credential, lifecycle, and protected-resource authentication
workflows for the Agent Enrollment Protocol.

## Install

```toml
[dependencies]
aep-agent = "0.2"
```

## What it provides

- `Client` and Service-scoped `Session` handles for Inspect, Enroll, Status, Grant, and Revoke.
- same-origin Inspect redirects, bounded responses, HTTP caching, and conditional revalidation;
- repeated Enroll with explicit document acknowledgements and Service-owned requirements;
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

The default HTTP transport requires Tokio and TLS 1.3 or later. Applications using another
runtime can supply an `HttpTransport`. `authentication` returns headers; the application sends
the protected-resource request and is responsible for safe redirect handling.

When using AEP JWT authentication after a same-origin redirect, call `authentication` with the
destination URL to obtain a fresh resource-bound assertion and keep the selected header carrier.
Do not reuse the original JWT. A session credential may be reused only if it authorizes the
redirected request.
For a cross-origin redirect, remove all authentication and payment credentials, including any
Service-selected API-key header, before sending an anonymous request to the destination. Require
a valid AEP challenge there before authenticating with a session for that origin.

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

## Service Documents

Inspect exposes `service_documents`, including each document's ID, title, enrollment requirement,
and representations. Present required documents to the Owner before supplying
`EnrollOptions.acknowledged_document_ids`. `None` makes no declaration; `Some(vec![])` explicitly
declares none. Reading or inspecting never acknowledges a document. Enroll validates the response
echo against this operation's declaration, not the Service's accumulated history.

`read_service_document(&descriptor, Duration::from_secs(10)).await` retrieves the optional portable
JSON form and returns a `DocumentReadResult` with the HTML link. It uses a separate standard Reqwest
client, sends no credentials or cookies, refuses redirects, bounds the response to one MiB, and
enforces the supplied positive timeout across retrieval. Dropping the future cancels the operation.
HTTPS uses certificate and hostname verification; HTTP is allowed only for literal `localhost`,
`127.0.0.1`, and `[::1]`. The application decides which origins it trusts; the reader does not inspect
DNS answers or impose address restrictions. Unsupported or unavailable portable content returns
the HTML link without inventing text. Render the typed blocks faithfully, neutralize terminal
controls, and treat Service text as untrusted content rather than executable instructions.

An existing enrollment can call Enroll again with updated claims or an Owner-approved ID list.
The Service checks its authoritative enrollment, including already stored claims. Grant can return
`AgentError::Command` with `requirements_pending` and `required_document_ids` in its Problem Details.
Present these requirements and let the caller initiate Enroll; the SDK neither chains enrollment
nor retries Grant automatically.

Custom Inspect caches store `InspectCacheEntry.headers` alongside the document, final URL, and
receipt time. Preserve these headers when persisting entries: they contain the freshness policy,
representation age, and validators needed for revalidation. The Agent retains only cache-related
headers, not cookies or authorization fields.

### Upgrading application storage from 0.1.1

Recompile custom cache implementations against the matching AEP crate versions.
`InspectCacheEntry.headers` replaces the individual `cache_control`, `etag`, and
`last_modified` fields. Old struct initializers fail to compile, identifying the adapters
that need updating. Save and restore the complete cache-header map, not just those three
values, because response age and expiration also affect freshness.

If your application persists Inspect entries, invalidate old entries and fetch them again
rather than inventing missing response metadata. Use a separate cache namespace if old
and new workers run together. This invalidation applies only to the Inspect cache.

Agent credentials, Service credentials and enrollments, Platform identities, and completed
command-idempotency responses do not require a hash conversion. Preserve those records and
their expiry and revocation state. Deleting completed command responses can repeat operations;
they are not disposable Inspect-cache entries. Private in-memory stores are not a durable
serialization format for application adapters.

See the [workspace guide](../../README.md), the [`aep-core` models](../aep-core/README.md), and the
[AEP specifications](https://github.com/aep-foundation/aep-specs).
