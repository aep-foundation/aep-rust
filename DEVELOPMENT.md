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

## Conformance

Run the shared AEP conformance harness against the public Rust role APIs with:

```sh
make conformance
```

The command uses `../aep-specs` by default. Set `AEP_SPECS_DIR` to another checkout when needed.
Agent, Service, and Platform reports are written to `.conformance/reports/`. The conformance
adapter is development tooling and is excluded from published crates and library coverage.

## Package boundaries

`aep-core` owns transport-independent protocol behavior. `aep-agent`, `aep-service`, and
`aep-platform` are role crates. `aep-tower` and `aep-axum` are optional Service adapters; the role
crates do not depend on either. Agent may compose Platform for hosted identity workflows; Service
does not depend on Agent behavior. All publishable crate versions advance together.

The non-publishable `aep-examples` package must compile under the same workspace gates. Run a
specific walkthrough with `cargo run -p aep-examples --bin <name>`.

The normative protocol is maintained in `aep-foundation/aep-specs`. Confirm draft, schema,
registry, and conformance behavior there before implementing or changing wire behavior.

## Releases

All publishable crates share one stable semantic version and are published in dependency order.
The manual GitHub `Release` workflow accepts only `main`, executes the complete verification,
consumer, conformance, and interoperability gates, and authenticates to crates.io through Trusted
Publishing. The workflow verifies a fresh registry consumer before creating the matching tag and
GitHub release.
