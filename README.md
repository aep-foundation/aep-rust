# Agent Enrollment Protocol for Rust

[![CI](https://github.com/aep-foundation/aep-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/aep-foundation/aep-rust/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/Rust-1.88%2B-000000?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

Official Rust development kits for the
[Agent Enrollment Protocol](https://www.aep.foundation/), the open protocol for Agent enrollment,
Service-issued credentials, and authenticated Agent access.

## Workspace

| Goal                                               | Crate          |
| -------------------------------------------------- | -------------- |
| Use protocol models, validation, and cryptography  | `aep-core`     |
| Inspect, enroll with, and authenticate to Services | `aep-agent`    |
| Integrate enrollment into a Service                | `aep-service`  |
| Host managed Agent identities                      | `aep-platform` |

The four crates share one version. Core remains transport-independent. Service and Platform depend
toward Core, while Agent composes Core with an injected identity provider without creating a
dependency on Platform or Service implementations.

Public asynchronous APIs do not expose a particular runtime. Default networking will use a
Rustls-backed HTTP client while transports, clocks, and delays remain injectable at integration
boundaries.

## Development

Rust 1.88 or newer is required. Run the complete merge gate with:

```sh
make verify
```

Generate the local coverage report with:

```sh
make coverage
```

See [DEVELOPMENT.md](./DEVELOPMENT.md) for the contributor workflow and
[`aep-specs`](https://github.com/aep-foundation/aep-specs) for the normative drafts, schemas,
registries, examples, and test vectors.

## Security

See [SECURITY.md](./SECURITY.md) for vulnerability reporting.

## License

MIT.
