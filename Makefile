.PHONY: conformance coverage dependency docs format format-check interoperability lint package test verify

conformance:
	./scripts/run-conformance.sh

coverage:
	cargo llvm-cov --workspace --all-features --locked --exclude aep-conformance --lcov --output-path lcov.info

dependency:
	cargo deny check

docs:
	RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked

format:
	cargo fmt --all

format-check:
	cargo fmt --all --check

interoperability:
	./scripts/run-node-interoperability.sh

lint:
	cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

package:
	cargo package -p aep-core --allow-dirty --locked
	cargo package -p aep-platform --allow-dirty --locked --list
	cargo package -p aep-agent --allow-dirty --locked --list
	cargo package -p aep-service --allow-dirty --locked --list
	cargo package -p aep-tower --allow-dirty --locked --list
	cargo package -p aep-axum --allow-dirty --locked --list

test:
	cargo test --workspace --all-features --locked

verify: format-check lint test docs package dependency
