#!/usr/bin/env bash
set -euo pipefail

version=${1:?version is required}
release_directory=.release
mkdir -p "$release_directory"
rm -f "$release_directory"/*.crate

for package in aep-core aep-platform aep-agent aep-service aep-tower aep-axum; do
  cargo package --locked -p "$package"
  cp "target/package/$package-$version.crate" "$release_directory/"
done
