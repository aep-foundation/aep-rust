#!/usr/bin/env bash
set -euo pipefail

version=${1:?version is required}
user_agent="aep-rust-release/$version (nas@inflowpay.ai)"

for package in aep-core aep-platform aep-agent aep-service aep-tower aep-axum; do
  if curl --fail --silent --show-error --user-agent "$user_agent" \
    "https://crates.io/api/v1/crates/$package/$version" >/dev/null; then
    echo "$package $version is already published."
    continue
  fi
  cargo publish --locked -p "$package"
done
