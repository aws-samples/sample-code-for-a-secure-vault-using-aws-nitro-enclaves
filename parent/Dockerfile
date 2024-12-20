# Copyright 2020-2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

####################################################################################################
## Chef image
####################################################################################################
FROM public.ecr.aws/docker/library/rust:latest AS chef
ARG TARGETPLATFORM

WORKDIR /app
RUN apt-get update && apt-get install -y build-essential
RUN rustup target add $TARGETPLATFORM
RUN cargo install cargo-chef --locked

####################################################################################################
## Planner image
####################################################################################################
FROM chef AS planner
COPY . .
RUN cargo chef prepare  --recipe-path recipe.json

####################################################################################################
## Builder image
####################################################################################################
FROM chef AS builder
ARG TARGETPLATFORM

COPY --from=planner /app/recipe.json recipe.json
RUN cargo install cargo-chef --locked
RUN cargo chef cook --release --target $TARGETPLATFORM --recipe-path recipe.json
COPY . .
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
