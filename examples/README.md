# Runnable examples

| Example | Purpose |
| --- | --- |
| [`aep-local-lifecycle`](aep-local-lifecycle/) | Runs a complete in-process Agent and Service lifecycle with real EdDSA assertions and an API-key credential. |
| [`aep-service-axum`](aep-service-axum/) | Mounts AEP commands and protects an application resource in a real Axum server. |
| [`aep-platform-ephemeral`](aep-platform-ephemeral/) | Provisions a Service-scoped Agent identity, publishes its DID document, and signs an assertion through the Platform API. |

Run an example from the repository root:

```sh
cargo run -p aep-examples --bin aep-local-lifecycle
cargo run -p aep-examples --bin aep-service-axum
cargo run -p aep-examples --bin aep-platform-ephemeral
```

The local lifecycle and Platform examples are self-contained. The Axum Service listens on
`127.0.0.1:4101` by default and accepts `HOST`, `PORT`, and `SERVICE_DID` environment variables.
It uses process-local stores intended for development; production Services provide durable
enrollment, replay, idempotency, and credential stores.
