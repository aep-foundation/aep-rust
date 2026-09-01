# Local Agent and Service lifecycle

This self-contained example executes Inspect, Enroll, Status, API-key Grant, protected-resource
authentication, targeted Revoke, and JWT fallback. It uses real EdDSA client assertions, the real
Agent and Service implementations, and an in-memory transport so no external process is required.

Run it from the repository root:

```sh
cargo run -p aep-examples --bin aep-local-lifecycle
```

The transport is local, but the protocol messages, assertion verification, replay protection,
idempotency, enrollment state, credential storage, credential presentation, and revocation are the
same public APIs used by networked integrations.
