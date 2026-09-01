#!/usr/bin/env bash
set -euo pipefail

version=${1:?version is required}
user_agent="aep-rust-release/$version (nas@inflowpay.ai)"
maximum_visibility_attempts=60
visibility_interval_seconds=5

published() {
  local package=$1
  curl --fail --silent --user-agent "$user_agent" \
    "https://crates.io/api/v1/crates/$package/$version" >/dev/null
}

wait_until_published() {
  local package=$1
  local attempt
  for ((attempt = 1; attempt <= maximum_visibility_attempts; attempt++)); do
    if published "$package"; then
      return 0
    fi
    if ((attempt < maximum_visibility_attempts)); then
      sleep "$visibility_interval_seconds"
    fi
  done
  echo "$package $version did not become visible on crates.io." >&2
  return 1
}

for package in aep-core aep-platform aep-agent aep-service aep-tower aep-axum; do
  if published "$package"; then
    echo "$package $version is already published."
    continue
  fi
  cargo publish --locked -p "$package"
  wait_until_published "$package"
done
