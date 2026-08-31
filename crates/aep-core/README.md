# aep-core

Transport-independent models, validation, identity, assertion, and HTTP-binding primitives for the
Agent Enrollment Protocol.

## Install

```toml
[dependencies]
aep-core = "0.1"
```

## Parse protocol documents

Parsing applies AEP's bounded native validation and preserves well-formed additive members and
advertisements:

```rust
use aep_core::{Command, command_path_from_inspect, parse_inspect_document};

let document = parse_inspect_document(br#"{
  "aep_version": "1.0",
  "bindings": {"supported": ["http"]},
  "commands": {"supported": ["inspect", "enroll"]},
  "core": {"signing_algorithms": ["EdDSA", "ES256"]},
  "http": {},
  "identity": {"methods": ["did:web"]},
  "service": {"did": "did:web:service.example"}
}"#)?;

assert_eq!(
    command_path_from_inspect(&document, &Command::Enroll)?,
    "/aep/enroll"
);
# Ok::<(), Box<dyn std::error::Error>>(())
```

The crate provides equivalent parse and validation functions for claims, enrollment, status,
grant, revoke, Problem Details, idempotency metadata, credential responses, client assertions, and
OpenAPI AEP security metadata.

## Assertions and identity

`sign_client_assertion` and `verify_client_assertion` support the required EdDSA and ES256
algorithms. `decode_jwt_unverified` exposes the JOSE header before verification so a Service can
select the advertised algorithm and resolve the `kid`. `did_web_document_url` and
`resolve_did_web_public_key` implement the `did:web` resolution rules, including the HTTPS default,
the one-mebibyte document limit, exact verification-method selection, and redirect rejection.

Keys use AEP-owned types rather than exposing the underlying JSON Web Token library. Ed25519 seeds,
PKCS #8 PEM private keys, raw Ed25519 public keys, ES256 private scalars, PKCS #8 PEM private keys,
and SEC1 ES256 public keys are supported:

```rust
use aep_core::{ClientAssertionSigningKey, SigningAlgorithm};

let key = ClientAssertionSigningKey::ed25519_from_seed([7; 32]);
assert_eq!(key.algorithm(), SigningAlgorithm::EdDsa);
let public_key = key.verifying_key();
# let _ = public_key;
```

Both algorithms use pure-Rust cryptographic implementations. A signing key selects the JOSE
algorithm, which prevents an algorithm option from disagreeing with the supplied key.

HTTP access remains injectable through `HttpTransport`; the Core crate does not select an async
runtime or networking client. The Agent, Service, and Platform crates provide the role-level
composition.

## HTTP and OpenAPI

The Core helpers normalize command paths, parse and render protected-resource authorization,
resolve OpenAPI references, and deterministically select the most specific matching OpenAPI path
template. Plaintext HTTP is rejected except when a caller explicitly enables the loopback-only
development option.

See the [workspace guide](../../README.md) and the
[AEP specifications](https://github.com/aep-foundation/aep-specs).
