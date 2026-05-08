.PHONY: check test fmt fmt-check lint build-wasi all

check:
	cargo check -p soroban-rs

test:
	cargo test -p soroban-rs

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

lint:
	cargo clippy --workspace --all-targets -- -D warnings

build-wasi:
	rustup target add wasm32-wasip2
	RUSTFLAGS="--cfg tokio_unstable" cargo build --target wasm32-wasip2 -p soroban-rs

all: check test build-wasi
