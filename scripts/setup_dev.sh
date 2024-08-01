#!/bin/sh

# Install Rust
curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

dnf install -y aws-nitro-enclaves-cli-devel git gcc
