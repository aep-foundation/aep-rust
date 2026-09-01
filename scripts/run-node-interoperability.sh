#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
node_repository="${AEP_NODE_DIR:-${repository_root}/../aep-node}"
output_directory="${AEP_INTEROP_OUTPUT_DIR:-${repository_root}/.interop/reports}"
work_directory="${repository_root}/.interop/work"
node_platform_port="${AEP_NODE_PLATFORM_PORT:-4310}"
node_service_port="${AEP_NODE_SERVICE_PORT:-4300}"
rust_server_port="${AEP_RUST_SERVER_PORT:-4320}"

wait_for_url() {
  local url="$1"
  local process="$2"
  local name="$3"
  local log_file="$4"
  for _ in {1..80}; do
    if curl --fail --silent --show-error "${url}" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "${process}" 2>/dev/null; then
      echo "${name} exited before it became ready." >&2
      sed -n '1,240p' "${log_file}" >&2
      return 1
    fi
    sleep 0.25
  done
  echo "${name} did not become ready." >&2
  sed -n '1,240p' "${log_file}" >&2
  return 1
}

if [[ ! -f "${node_repository}/package.json" ]]; then
  echo "AEP_NODE_DIR must identify an aep-node checkout." >&2
  exit 1
fi

mkdir -p "${output_directory}" "${work_directory}"
cargo build --locked -p aep-examples --bin aep-interop
(
  cd "${node_repository}"
  corepack pnpm build
)

processes=()
cleanup() {
  for process in "${processes[@]:-}"; do
    kill "${process}" 2>/dev/null || true
    wait "${process}" 2>/dev/null || true
  done
}
trap cleanup EXIT

PUBLIC_BASE_URL="http://127.0.0.1:${node_platform_port}" \
  DID_HOST="127.0.0.1:${node_platform_port}" \
  PORT="${node_platform_port}" \
  node "${node_repository}/examples/aep-platform-ephemeral/dist/index.js" \
  >"${work_directory}/node-platform.log" 2>&1 &
node_platform_process=$!
processes+=("${node_platform_process}")

SERVICE_DID="did:web:127.0.0.1%3A${node_service_port}:services:example-service" \
  PORT="${node_service_port}" \
  node "${node_repository}/examples/aep-service-credential-api-key/dist/index.js" \
  >"${work_directory}/node-service.log" 2>&1 &
node_service_process=$!
processes+=("${node_service_process}")

wait_for_url "http://127.0.0.1:${node_platform_port}/health" "${node_platform_process}" "Node Platform" "${work_directory}/node-platform.log"
wait_for_url "http://127.0.0.1:${node_service_port}/.well-known/aep" "${node_service_process}" "Node Service" "${work_directory}/node-service.log"

"${repository_root}/target/debug/aep-interop" agent \
  --platform-url "http://127.0.0.1:${node_platform_port}" \
  --service-url "http://127.0.0.1:${node_service_port}" \
  >"${work_directory}/rust-agent-node.json"

cleanup
processes=()

"${repository_root}/target/debug/aep-interop" server --listen "127.0.0.1:${rust_server_port}" \
  >"${work_directory}/rust-server.log" 2>&1 &
rust_server_process=$!
processes+=("${rust_server_process}")

wait_for_url "http://127.0.0.1:${rust_server_port}/health" "${rust_server_process}" "Rust Server" "${work_directory}/rust-server.log"

PLATFORM_URL="http://127.0.0.1:${rust_server_port}" \
  SERVICE_URL="http://127.0.0.1:${rust_server_port}" \
  node "${node_repository}/examples/aep-agent-did-web-grant-status-revoke/dist/index.js" \
  >"${work_directory}/node-agent-rust.json"

node "${repository_root}/scripts/verify-node-interoperability.mjs" \
  "${work_directory}/rust-agent-node.json" \
  "${work_directory}/node-agent-rust.json" \
  "${output_directory}/aep-rust-node-interoperability.json"

echo "Interoperability report: ${output_directory}/aep-rust-node-interoperability.json"
