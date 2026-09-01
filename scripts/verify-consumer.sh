#!/usr/bin/env bash
set -euo pipefail

repository=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
consumer=$(mktemp -d)
trap 'rm -rf "$consumer"' EXIT
mkdir -p "$consumer/src"

source=${AEP_CONSUMER_SOURCE:-path}
if [[ "$source" == "path" ]]; then
  dependencies=$(cat <<EOF
aep-agent = { path = "$repository/crates/aep-agent" }
aep-axum = { path = "$repository/crates/aep-axum" }
aep-core = { path = "$repository/crates/aep-core" }
aep-platform = { path = "$repository/crates/aep-platform" }
aep-service = { path = "$repository/crates/aep-service" }
aep-tower = { path = "$repository/crates/aep-tower" }
EOF
)
elif [[ "$source" == "registry" ]]; then
  version=${AEP_RUST_VERSION:?AEP_RUST_VERSION is required for a registry consumer check}
  dependencies=$(cat <<EOF
aep-agent = "=$version"
aep-axum = "=$version"
aep-core = "=$version"
aep-platform = "=$version"
aep-service = "=$version"
aep-tower = "=$version"
EOF
)
else
  echo "AEP_CONSUMER_SOURCE must be path or registry." >&2
  exit 1
fi

cat > "$consumer/Cargo.toml" <<EOF
[package]
name = "aep-rust-consumer"
version = "0.1.0"
edition = "2024"

[dependencies]
$dependencies
EOF

cat > "$consumer/src/main.rs" <<'EOF'
use aep_agent::Client;
use aep_axum::AepPrincipal;
use aep_core::{Command, VERSION};
use aep_platform::DiscoveryOptions;
use aep_service::MemoryServiceCredentialStore;
use aep_tower::CommandService;

fn main() {
    let _ = VERSION;
    let _ = Command::Enroll;
    let _ = DiscoveryOptions::default();
    let _ = MemoryServiceCredentialStore::default();
    let _ = std::mem::size_of::<Option<Client>>();
    let _ = std::mem::size_of::<Option<AepPrincipal>>();
    let _ = std::mem::size_of::<Option<CommandService>>();
}
EOF

cargo generate-lockfile --manifest-path "$consumer/Cargo.toml"
cargo check --locked --manifest-path "$consumer/Cargo.toml"
