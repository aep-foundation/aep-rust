# Development

## Requirements

- Rust 1.88 or newer.
- `cargo-deny` for the complete local merge gate.
- `cargo-llvm-cov` for coverage generation.

## Verification

Run the complete repository gate before merging:

```sh
make verify
```

The gate checks formatting, Clippy with warnings denied, tests, Rust documentation, publishable
package contents, security advisories, licenses, sources, and dependency policy. Continuous
integration runs it on Rust 1.88 and current stable Rust.

Coverage is generated separately once the crates contain executable source because it requires
LLVM instrumentation:

```sh
make coverage
```

## Package boundaries

`aep-core` owns transport-independent protocol behavior. `aep-agent`, `aep-service`, and
`aep-platform` are role crates. Agent may compose Platform for hosted identity workflows; Service
does not depend on Agent behavior. All crate versions advance together.

The normative protocol is maintained in `aep-foundation/aep-specs`. Confirm draft, schema,
registry, and conformance behavior there before implementing or changing wire behavior.
