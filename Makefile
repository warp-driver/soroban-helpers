.PHONY: check test fmt fmt-check lint build-wasi publish all

check:
	cargo check --workspace

test:
	cargo test --workspace

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

lint:
	cargo clippy --workspace --all-targets -- -D warnings

build-wasi:
	rustup target add wasm32-wasip2
	RUSTFLAGS="--cfg tokio_unstable" cargo build --target wasm32-wasip2 -p wasi-soroban-rs

publish:
	cargo publish -p wasi-soroban-rs-macros
	cargo publish -p wasi-soroban-test-helpers
	cargo publish -p wasi-soroban-rs

all: check test build-wasi
