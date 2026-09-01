# aep-platform

Platform-hosted Agent identity provisioning, delegated signing, lifecycle, and verification support
for the Agent Enrollment Protocol.

Use this crate when operating an AEP Platform that holds Agent signing keys. Agent applications that
consume a Platform use `aep-agent` and provide its `IdentityProvider` boundary instead.

## Install

```toml
[dependencies]
aep-platform = "0.1"
```

## Responsibilities

`Platform` implements the transport-independent behavior behind:

- `/.well-known/aep-platform` discovery;
- Service-scoped Agent DID provisioning and public DID-document generation;
- authorized identity listing and lifecycle management;
- delegated client-assertion signing with completed or pending responses;
- idempotent provisioning, signing, and hosted verification; and
- optional hosted verification with assertion-replay protection.

The application owns HTTP routing and caller authentication. It supplies implementations of
`Authorizer`, `IdentityStore`, `KeyStore`, `ServiceDidResolver`, and, when hosted verification is
enabled, `ReplayStore`. Every private operation calls `Authorizer` and fails closed. DID-document
retrieval remains public so Services can verify Agent assertions locally.

`MemoryIdentityStore`, `MemoryIdempotencyStore`, and `MemoryReplayStore` support tests and
prototypes. Production deployments provide durable implementations and keep private key material
behind `KeyStore`; this crate never exports private keys.

Framework integration and runnable Platform examples are developed separately from the protocol
engine so that the public API remains independent of Axum, Tower, Tokio, and application storage.

The [`aep-platform-ephemeral`](../../examples/aep-platform-ephemeral/) example supplies each
required boundary, provisions an identity, renders its DID document, and signs an assertion. Its
in-memory stores and fixed example authorization policy are not production defaults.

See the [workspace guide](../../README.md) and the
[AEP specifications](https://github.com/aep-foundation/aep-specs).
