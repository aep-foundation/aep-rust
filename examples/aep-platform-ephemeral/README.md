# Ephemeral Platform

This example constructs the framework-neutral AEP Platform with process-local identity and
idempotency stores. It authorizes a caller, provisions one Service-scoped Agent identity,
publishes that identity's DID document, and signs an Enroll assertion.

Run it from the repository root:

```sh
cargo run -p aep-examples --bin aep-platform-ephemeral
```

The example keeps private key material inside its `KeyStore`. A production Platform supplies
durable stores, authenticates its callers before creating `RequestContext`, and mounts the Platform
responses through its HTTP framework.
