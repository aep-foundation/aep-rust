# aep-service

`aep-service` provides the framework-neutral Service implementation for the Agent Enrollment
Protocol. It builds the Inspect document, verifies client assertions, enforces replay and
idempotency rules, manages enrollment lifecycle state, dispatches Grant and Revoke handlers, and
authenticates protected resources.

## Install

```toml
[dependencies]
aep-service = "0.3"
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

Use [`aep-axum`](../aep-axum/) for direct Axum integration or [`aep-tower`](../aep-tower/) for a
reusable Tower Service and authentication layer. Both adapters are optional.

When integrating another HTTP stack, expose `service.inspect_document()` at `/.well-known/aep`.
Route the four authenticated commands to `Service::enroll`, `Service::status`, `Service::grant`,
and `Service::revoke`. Each command returns a `ServiceResponse` containing the HTTP status, headers,
and a typed `ResponseBody`; use `ResponseBody::to_json()` for the wire body.

The [`aep-service-axum`](../../examples/aep-service-axum/) example mounts every command and protects
an application resource. The [`aep-local-lifecycle`](../../examples/aep-local-lifecycle/) example
shows the direct Service boundary without a web framework.

`Enroll`, `Grant`, and `Revoke` require a non-empty `Idempotency-Key` value through
`IdempotentCommandOptions`. `Status` uses `AuthenticatedCommandOptions`. The application adapter is
responsible for extracting the AEP client assertion and idempotency header from the incoming
request without logging either value.

The memory command-idempotency store retains completed responses for one hour after
execution completes. A failed operation releases its key for a retry; an exact retry
of a completed operation returns the stored response. Custom stores must retain
responses for at least one hour and bind each key to its Agent, command and request body.
A command retry keeps its idempotency key but uses a fresh client assertion; assertion replay
protection also applies to retries.

Call `Service::authenticate_protected_resource` before serving an authenticated application
resource. It accepts typed headers, method, and URL and returns either an `AuthenticatedPrincipal`
or the complete `401` AEP challenge response.

The default `ReqwestTransport` requires Tokio and TLS 1.3 or later for HTTPS. Applications using
another runtime supply an `HttpTransport` with equivalent HTTPS, redirect and response-size controls.

## Repeated enrollment decisions

Valid Enroll requests evaluate the enrollment policy, including requests for an existing Agent.
Policies consult their own authoritative storage when deciding whether to accept an update.
Accepted updates merge supplied claims while preserving identity, creation time, lifecycle status,
and issued credentials. A rejected decision leaves the stored enrollment unchanged;
`update_existing: false` returns it unchanged.

In `EnrollmentDecision`, `owner_action_required`, `requirements_pending`, and
`verification_pending` use `Option`: `None` preserves the stored value on a repeat and defaults
to `false` or an empty list on initial enrollment. `Some` replaces the value, including
`Some(false)` and `Some(vec![])`. Stored enrollment records retain concrete values.

## Service Documents

Set `ServiceOptions.extensions` to include `aep_core::SERVICE_DOCUMENTS_EXTENSION` and populate
`service_documents` with the advertised descriptors. Each descriptor needs a unique ID and an HTML
link; portable JSON is optional. Host the representations anonymously. Document types are open
strings; `aep_core::SERVICE_DOCUMENT_TYPES` lists the preferred values.

Persist `EnrollmentRecord.acknowledged_document_ids` and `required_document_ids` in custom stores.
Acknowledged IDs accumulate only from explicit declarations of known documents. The Enroll response
echoes only the current declaration, including an empty list; omission never implies acceptance.
A new required document does not invalidate an otherwise valid, explicitly supplied declaration.
Grant checks remaining requirements and returns HTTP 422 `requirements_unmet` before credential
issuance. A previously satisfied document can require another decision by adding its ID to the
record's `required_document_ids`; explicit acknowledgement clears that requirement.

Repeated enrollment preserves lifecycle status, original timestamps, unrelated claims, and issued
credentials. The enrollment policy still decides whether to apply updates, leave the record
unchanged, or reject the request. Store implementations define concurrency guarantees; the SDK
does not add a locking contract. Document IDs identify documents, not immutable content versions.

## Grant Types

Register each advertised Grant Type with a `GrantTypeDefinition` and a `GrantTypeHandler`. The
handler issues a JSON object containing a non-empty, globally unique `credential_id`, revokes the
credential targets described by `RevokeRequest`, and may authenticate its credential presentation
at protected resources. A Service does not advertise Grant or Revoke when no Grant Types are
configured.

For built-in credentials, use `stored_api_key_grant_type`, `stored_basic_grant_type`, or
`stored_oauth_bearer_grant_type` with an issuer callback and a `ServiceCredentialStore`.
The issuer supplies credential material, expiry, and a unique identifier; API-key secrets and
Basic passwords require at least 128 bits of entropy. The memory store retains one-way secret
verifiers. A custom store receives usable credentials in `save`. API-key stores must retain
salted hashes or equivalent one-way verifiers; Basic stores must apply strong password-storage
controls. Protect stored records, honor expiry and revocation, and do not log credential material.
The application remains responsible for authorizing resource access using the returned principal
and scopes.

## Verification boundary

`DidWebClientAssertionVerifier` performs real EdDSA or ES256 verification after resolving the
assertion key from the Agent's `did:web` document. Supply an alternate `ClientAssertionVerifier`
for a different supported identity or hosted verification boundary. The Service independently
checks audience, operation, resource, validity window, identity method, and atomic replay
consumption after verification.

### Hosted Platform verification

`HostedPlatformClientAssertionVerifier` calls a trusted Platform's verification endpoint using
the Service's own Platform credential. The Platform's `Authorizer` must permit that Service to
verify assertions for its Service DID. The Service does not need to own the Agent identity, and
verification permission does not grant signing or lifecycle-management permission.

```rust,no_run
use std::sync::Arc;
use aep_service::{
    HostedPlatformClientAssertionVerifier, HostedPlatformClientAssertionVerifierOptions,
    Service, ServiceOptions,
};

let mut options = HostedPlatformClientAssertionVerifierOptions::new(
    "https://platform.example/v1/aep/verifications",
);
options.authorization = Some("Bearer service-platform-token".to_owned());
let verifier = Arc::new(HostedPlatformClientAssertionVerifier::new(options)?);
Service::new(ServiceOptions::new("did:web:api.example.com", verifier))?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

The default HTTP transport uses TLS 1.3, refuses redirects, and limits responses to 1 MiB.
`request_timeout` defaults to 30 seconds and bounds injected transports too. Custom transports
must enforce TLS 1.3, avoid redirects, and bound response reads. Configure a trusted endpoint;
the Agent's assertion does not choose where the Service sends its Platform credential.

The verification request's idempotency key is derived from its complete body, not the Service command's
idempotency key. An exact verification retry uses the same key; a fresh assertion uses a new key.
The Service still checks the returned claims and consumes its own replay record, so a cached
Platform verification cannot authenticate the same assertion twice at the Service.

Hosted verification is optional. Keep local `did:web` verification available as required by the
AEP draft; the application selects its verification policy. This helper does not automatically
fall back to local verification when a Platform refuses or cannot complete a request.

See the [workspace guide](../../README.md) and the
[AEP specifications](https://github.com/aep-foundation/aep-specs).
