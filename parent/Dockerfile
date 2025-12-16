# Copyright 2020-2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

####################################################################################################
## Builder image - Use AL2023 to match production glibc version
####################################################################################################
FROM public.ecr.aws/amazonlinux/amazonlinux:2023 AS builder
ARG TARGETPLATFORM

WORKDIR /app

# Install build dependencies
RUN dnf install -y gcc gcc-c++ make openssl-devel pkg-config

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup target add $TARGETPLATFORM

# Install cargo-chef for caching
RUN cargo install cargo-chef --locked

# Prepare recipe
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Cook dependencies
RUN cargo chef cook --release --target $TARGETPLATFORM --recipe-path recipe.json

# Build the application
RUN cargo build --target $TARGETPLATFORM --release --color never

####################################################################################################
## Final image
####################################################################################################
FROM public.ecr.aws/amazonlinux/amazonlinux:2023-minimal
ARG TARGETPLATFORM

WORKDIR /app

# Copy our build
COPY --from=builder /app/target/${TARGETPLATFORM}/release/parent-vault /app/parent-vault

CMD ["/app/parent-vault", "--host", "127.0.0.1"]
