.PHONY: build build-docker clean

ARCH := x86_64
# ARCH := aarch64

RUST_DIR := $(shell readlink -m $(shell dirname $(firstword $(MAKEFILE_LIST))))

build:
	curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh -s -- -y
	rustup target install ${ARCH}-unknown-linux-gnu
	cargo build --manifest-path=${RUST_DIR}/Cargo.toml --target=${ARCH}-unknown-linux-gnu --release --color never

build-docker:
	docker build --build-arg TARGETPLATFORM=${ARCH}-unknown-linux-gnu -t parent-vault:latest -f Dockerfile .
	CONTAINER_ID=$(docker create parent-vault:latest)
	docker cp $CONTAINER_ID:/app/parent-vault ./parent-vault
	docker rm $CONTAINER_ID

clean:
	cargo clean
