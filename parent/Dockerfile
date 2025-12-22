# Copyright 2020-2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# Reproducible builds: pin base images to SHA256 digest
# Update these digests when upgrading base images

####################################################################################################
## Chef image - using Amazon Linux to ensure glibc compatibility at runtime
####################################################################################################
FROM public.ecr.aws/amazonlinux/amazonlinux:2023@sha256:dc1dacae45ec346969d430237ddd1a282170ec9f322d4b3cf28ac8f1975070a1 AS chef
ARG TARGETPLATFORM
ARG SOURCE_DATE_EPOCH

WORKDIR /app
RUN dnf install -y gcc gcc-c++ make openssl-devel pkg-config
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup target add $TARGETPLATFORM
RUN cargo install cargo-chef --locked

####################################################################################################
## Planner image
####################################################################################################
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

####################################################################################################
## Builder image
####################################################################################################
FROM chef AS builder
ARG TARGETPLATFORM
ARG SOURCE_DATE_EPOCH

COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --target $TARGETPLATFORM --recipe-path recipe.json
COPY . .
RUN cargo build --target $TARGETPLATFORM --release --color never

####################################################################################################
## Final image - used only for extracting the built binary
## Binary is deployed to EC2 via CloudFormation (vault_template.yml)
####################################################################################################
FROM public.ecr.aws/amazonlinux/amazonlinux:2023-minimal@sha256:3f6c5a2858113e9bb6710dfccdace7dc698e83f7a012240a1d07b3a46d273999
ARG TARGETPLATFORM

WORKDIR /app

# Copy our build
COPY --from=builder /app/target/${TARGETPLATFORM}/release/parent-vault /app/parent-vault

CMD ["/app/parent-vault", "--host", "127.0.0.1"]
