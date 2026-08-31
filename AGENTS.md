# AGENTS.md

## Repository

This workspace contains the official Rust crates for AEP:

- `aep-core`: transport-independent protocol primitives.
- `aep-agent`: Agent-side enrollment and credential workflows.
- `aep-service`: Service-side enrollment, credential issuance, and authentication integration.
- `aep-platform`: Platform-hosted Agent identity integration.

The normative protocol is maintained in `aep-foundation/aep-specs`. Check that source before
implementing or changing wire behavior. Use `aep-node` as a reference implementation after the
specification and recorded user decisions.

## Verification

Run `make verify` before merging. Public APIs must be backed by tests and authoritative protocol
behavior. Run `make coverage` when executable source changes.

## Conventions

- Support Rust 1.88 and newer with Rust 2024 Edition; continuous integration covers the minimum
  supported compiler and current stable Rust.
- Keep all four publishable crates on one workspace version.
- Keep `aep-core` independent of asynchronous runtimes and HTTP clients.
- Keep public asynchronous APIs runtime-neutral. Default networking uses Reqwest with Rustls;
  transports, clocks, and delays remain injectable.
- Ship the complete AEP command, Claim, credential-profile, EdDSA, and ES256 contract without
  protocol feature flags.
- Keep Service integration independent of Axum, Tower, and other application frameworks until the
  adapter decision is made from a concrete Service HTTP boundary.
- Forbid unsafe code in every workspace crate.
- Return typed errors rather than logging from library crates.
- Do not implement JOSE or JWT cryptography directly; use narrowly vetted dependencies.
- Do not add a runtime JSON Schema engine. AEP uses bounded native wire validation.
- Centralize dependency versions in the workspace and disable unnecessary default features.
- Keep dependency direction aligned with the crate responsibilities above.
- Describe current behavior; do not leave speculative or historical comments.
- Keep public APIs small, idiomatic, and backed by tests.
