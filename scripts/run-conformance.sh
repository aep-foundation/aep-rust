#!/bin/sh
set -eu

specs_dir=${AEP_SPECS_DIR:-../aep-specs}
output_dir=${AEP_CONFORMANCE_OUTPUT:-.conformance/reports}
implementation_version=${AEP_RUST_VERSION:-0.0.0-development}
implementation_version=${implementation_version#v}
adapter=target/debug/aep-conformance
manifest=.conformance/capability-manifest.json

mkdir -p "$output_dir"
cargo build --locked -p aep-conformance

printf '%s\n' "{\"claims\":[{\"profiles\":[\"core-http\",\"claims\",\"api-key\",\"basic\",\"oauth-bearer\"],\"role\":\"agent\"},{\"profiles\":[\"platform-hosted-identity\"],\"role\":\"platform\"},{\"profiles\":[\"core-http\",\"claims\",\"api-key\",\"basic\",\"oauth-bearer\"],\"role\":\"service\"}],\"implementation\":{\"name\":\"aep-rust\",\"version\":\"$implementation_version\"},\"manifest_version\":\"1\"}" > "$manifest"

for role in agent platform service; do
  BUNDLE_GEMFILE="$specs_dir/ietf/Gemfile" bundle exec ruby "$specs_dir/ietf/scripts/run_conformance.rb" \
    --role "$role" \
    --manifest "$manifest" \
    --output "$output_dir/$role.json" \
    -- "$adapter" "$role"
done
