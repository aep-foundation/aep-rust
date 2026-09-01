# Agent Enrollment Protocol for Rust

[![CI](https://github.com/aep-foundation/aep-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/aep-foundation/aep-rust/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/Rust-1.88%2B-000000?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

Official Rust development kits for the
[Agent Enrollment Protocol](https://www.aep.foundation/), the open protocol for Agent enrollment,
Service-issued credentials, and authenticated Agent access.

## Workspace

| Goal                                               | Crate          | Guide                                      |
| -------------------------------------------------- | -------------- | ------------------------------------------ |
| Use protocol models, validation, and cryptography  | `aep-core`     | [Core](./crates/aep-core)                  |
| Inspect, enroll with, and authenticate to Services | `aep-agent`    | [Agent](./crates/aep-agent)                |
| Integrate enrollment into a Service                | `aep-service`  | [Service](./crates/aep-service)            |
| Host managed Agent identities                      | `aep-platform` | [Platform](./crates/aep-platform)          |
| Add reusable HTTP middleware to a Service          | `aep-tower`    | [Tower adapter](./crates/aep-tower)        |
| Integrate a Service with Axum                      | `aep-axum`     | [Axum adapter](./crates/aep-axum)          |

The crates share one version. Core remains transport-independent. Service and Platform depend
toward Core, while Agent composes Core with an injected identity provider without creating a
dependency on Platform or Service implementations. Tower and Axum are optional adapters;
integrators can use either, both, or neither.

Public asynchronous APIs do not expose a particular runtime. Default networking uses a
Rustls-backed HTTP client while transports, clocks, and delays remain injectable at integration
boundaries.

## Installation

An Agent normally needs only:

```toml
[dependencies]
aep-agent = "0.1"
```

A framework-neutral Service uses `aep-service`. Add `aep-tower` for reusable HTTP middleware or
`aep-axum` for direct Axum integration:

```toml
[dependencies]
aep-axum = "0.1"
aep-service = "0.1"
```

An Agent that delegates identity custody to a remote Platform uses the `PlatformIdentityProvider`
included in `aep-agent`. An application that operates the Platform uses `aep-platform`. Add
`aep-core` explicitly only when the application names its protocol models or cryptographic types
directly. All crates share one version.

## Integration paths

Agents provide an `IdentityProvider`, create a `Client`, inspect each Service, enroll, and optionally
request a Service credential. Services create a framework-neutral `Service`, configure Claims and
Grant Types, and connect its command and protected-resource boundaries to HTTP. Platforms provide
authorization, identity, key, and Service-DID resolution boundaries before exposing hosted identity
operations through their chosen HTTP stack.

Runnable examples cover a complete local Agent and Service lifecycle, an Axum Service, and an
ephemeral Platform:

```sh
cargo run -p aep-examples --bin aep-local-lifecycle
cargo run -p aep-examples --bin aep-service-axum
cargo run -p aep-examples --bin aep-platform-ephemeral
```

See the [examples guide](./examples/) for what each process demonstrates and which shortcuts are
appropriate only for development.

## Development

Rust 1.88 or newer is required. Run the complete merge gate with:

```sh
make verify
```

Generate the local coverage report with:

```sh
make coverage
```

Run the shared AEP conformance harness for the Agent, Service, and Platform roles with:

```sh
make conformance
```

The harness writes machine-readable reports to `.conformance/reports/`.

See [DEVELOPMENT.md](./DEVELOPMENT.md) for the contributor workflow and
[`aep-specs`](https://github.com/aep-foundation/aep-specs) for the normative drafts, schemas,
registries, examples, and test vectors.

## Security

See [SECURITY.md](./SECURITY.md) for vulnerability reporting.

## License

MIT.
