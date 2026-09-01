# Axum Service

This example mounts the AEP Inspect, Enroll, Status, Grant, and Revoke commands through
`aep-axum`. It advertises an API-key credential and applies the AEP authentication layer to
`GET /resource`.

Run it from the repository root:

```sh
cargo run -p aep-examples --bin aep-service-axum
```

The Service prints its origin, Inspect URL, and protected-resource URL at startup. Its in-memory
state is discarded when the process exits. An Agent must use a resolvable `did:web` identity whose
DID document contains the assertion key.
