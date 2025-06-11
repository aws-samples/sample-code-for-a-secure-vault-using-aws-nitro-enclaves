.PHONY: build build-docker build-enclave run-enclave create-private-key clean

# ARCH := x86_64
ARCH := aarch64

RUST_DIR := $(shell readlink -m $(shell dirname $(firstword $(MAKEFILE_LIST))))

build:
	curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh -s -- -y
	rustup target install ${ARCH}-unknown-linux-musl
	cargo build --manifest-path=${RUST_DIR}/Cargo.toml --target=${ARCH}-unknown-linux-musl --release --color never

build-docker:
	docker build --build-arg TARGETPLATFORM=${ARCH}-unknown-linux-musl -t enclave-vault -f Dockerfile .

build-enclave:
	nitro-cli build-enclave --docker-uri enclave-vault:latest --output-file enclave-vault.eif

run-enclave:
	nitro-cli run-enclave --cpu-count 2 --memory 512 --eif-path enclave-vault.eif --debug-mode

create-private-key:
	openssl ecparam -name secp384r1 -genkey -out nitro_vault_key.pem

clean:
	cargo clean
