# Copyright 2020-2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

####################################################################################################
## kmstool-enclave-cli image
##
## based on https://github.com/aws/aws-nitro-enclaves-acm/blob/main/env/enclave/Dockerfile
####################################################################################################
FROM public.ecr.aws/docker/library/rust:alpine AS kmstool

ARG TARGETPLATFORM
ENV RUSTFLAGS="-C target-feature=-crt-static"
ENV CMAKE_POLICY_VERSION_MINIMUM=3.5

# Install system dependencies / packages.
RUN apk --no-cache add \
    p11-kit-server \
    ca-certificates \
    cmake \
    g++ \
    gcc \
    git \
    go \
    perl \
    curl \
    make \
    linux-headers \
    shadow \
    sudo

RUN ln -s /usr/lib /usr/lib64

WORKDIR /tmp/crt-builder

# Build AWS libcrypto
RUN git clone --depth 1 -b v1.41.1 https://github.com/awslabs/aws-lc.git
RUN cmake \
    -DCMAKE_PREFIX_PATH=/usr \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DBUILD_TESTING=0 \
    -S aws-lc \
    -B aws-lc/build
RUN cmake --build aws-lc/build --parallel $(nproc) --target install

# AWS-S2N
RUN git clone --depth 1 -b v1.3.46 https://github.com/aws/s2n-tls.git
RUN cmake \
    -DCMAKE_PREFIX_PATH=/usr \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DBUILD_TESTING=0 \
    -S s2n-tls \
    -B s2n-tls/build
RUN cmake --build s2n-tls/build --parallel $(nproc) --target install

# AWS-C-COMMON
RUN git clone --depth 1 -b v0.8.0 https://github.com/awslabs/aws-c-common.git
RUN cmake \
    -DCMAKE_PREFIX_PATH=/usr \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DBUILD_TESTING=0 \
    -S aws-c-common \
    -B aws-c-common/build
RUN cmake --build aws-c-common/build --parallel $(nproc) --target install

# AWS-C-SDKUTILS
RUN git clone --depth 1 -b v0.1.2 https://github.com/awslabs/aws-c-sdkutils
RUN cmake \
    -DCMAKE_PREFIX_PATH=/usr \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DBUILD_TESTING=0 \
    -S aws-c-sdkutils \
    -B aws-c-sdkutils/build
RUN cmake --build aws-c-sdkutils/build --parallel $(nproc) --target install

# AWS-C-CAL
RUN git clone --depth 1 -b v0.5.18 https://github.com/awslabs/aws-c-cal.git
RUN cmake \
    -DCMAKE_PREFIX_PATH=/usr \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DBUILD_TESTING=0 \
    -S aws-c-cal \
    -B aws-c-cal/build
RUN cmake --build aws-c-cal/build --parallel $(nproc) --target install

# AWS-C-IO
RUN git clone --depth 1 -b v0.11.0 https://github.com/awslabs/aws-c-io.git
RUN cmake \
    -DUSE_VSOCK=1 \
    -DCMAKE_PREFIX_PATH=/usr \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DBUILD_TESTING=0 \
    -S aws-c-io \
    -B aws-c-io/build
RUN cmake --build aws-c-io/build --parallel $(nproc) --target install

# AWS-C-COMPRESSION
RUN git clone --depth 1 -b v0.2.14 https://github.com/awslabs/aws-c-compression.git
RUN cmake \
    -DCMAKE_PREFIX_PATH=/usr \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DBUILD_TESTING=0 \
    -S aws-c-compression \
    -B aws-c-compression/build
RUN cmake --build aws-c-compression/build --parallel $(nproc) --target install

# AWS-C-HTTP
RUN git clone --depth 1 -b v0.6.19 https://github.com/awslabs/aws-c-http.git
RUN cmake \
    -DCMAKE_PREFIX_PATH=/usr \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DBUILD_TESTING=0 \
    -S aws-c-http \
    -B aws-c-http/build
RUN cmake --build aws-c-http/build --parallel $(nproc) --target install

# AWS-C-AUTH
RUN git clone --depth 1 -b v0.6.15 https://github.com/awslabs/aws-c-auth.git
RUN cmake \
    -DCMAKE_PREFIX_PATH=/usr \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DBUILD_TESTING=0 \
    -S aws-c-auth \
    -B aws-c-auth/build
RUN cmake --build aws-c-auth/build --parallel $(nproc) --target install

# JSON-C library
RUN git clone --depth 1 -b json-c-0.18-20240915 https://github.com/json-c/json-c.git
RUN cmake \
    -DCMAKE_PREFIX_PATH=/usr \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DBUILD_TESTING=0 \
    -S json-c \
    -B json-c/build
RUN cmake --build json-c/build --parallel $(nproc) --target install

# NSM LIB
RUN git clone --depth 1 -b v0.4.0 "https://github.com/aws/aws-nitro-enclaves-nsm-api"
RUN rustup target add $TARGETPLATFORM
RUN cd aws-nitro-enclaves-nsm-api \
    && PATH="$PATH:/root/.cargo/bin" cargo build --release --target $TARGETPLATFORM --jobs $(nproc) -p nsm-lib \
    && mv target/$TARGETPLATFORM/release/libnsm.so /usr/lib/ \
    && mv target/$TARGETPLATFORM/release/nsm.h /usr/include/

# AWS Nitro Enclaves SDK
RUN git clone --depth 1 -b v0.4.2 "https://github.com/aws/aws-nitro-enclaves-sdk-c"
RUN cmake \
    -DCMAKE_PREFIX_PATH=/usr \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DBUILD_TESTING=0 \
    -S aws-nitro-enclaves-sdk-c \
    -B aws-nitro-enclaves-sdk-c/build
RUN cmake --build aws-nitro-enclaves-sdk-c/build --parallel $(nproc) --target install

####################################################################################################
## Chef image
####################################################################################################
FROM public.ecr.aws/docker/library/rust:alpine AS chef
ARG TARGETPLATFORM

WORKDIR /app
RUN apk add --no-cache build-base
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

COPY --from=planner /app/recipe.json recipe.json
RUN cargo install cargo-chef --locked
RUN cargo chef cook --release --target $TARGETPLATFORM --recipe-path recipe.json
COPY . .
RUN cargo build --target $TARGETPLATFORM --release --color never

####################################################################################################
## Final image
####################################################################################################
FROM public.ecr.aws/docker/library/alpine:latest AS runtime
ARG TARGETPLATFORM

RUN apk add --no-cache ca-certificates libgcc
RUN addgroup -S vault && adduser -S vault -G vault

WORKDIR /app

# Copy our build
COPY --from=builder /app/target/${TARGETPLATFORM}/release/enclave-vault /app/enclave-vault

# Copy shared libraries for FFI wrapper (replacing kmstool_enclave_cli binary)
# Core AWS libraries
COPY --from=kmstool /usr/lib/libaws-nitro-enclaves-sdk-c.so* /usr/lib/
COPY --from=kmstool /usr/lib/libaws-c-common.so* /usr/lib/
COPY --from=kmstool /usr/lib/libaws-c-sdkutils.so* /usr/lib/
COPY --from=kmstool /usr/lib/libaws-c-cal.so* /usr/lib/
COPY --from=kmstool /usr/lib/libaws-c-io.so* /usr/lib/
COPY --from=kmstool /usr/lib/libaws-c-compression.so* /usr/lib/
COPY --from=kmstool /usr/lib/libaws-c-http.so* /usr/lib/
COPY --from=kmstool /usr/lib/libaws-c-auth.so* /usr/lib/
# TLS and crypto libraries
COPY --from=kmstool /usr/lib/libs2n.so* /usr/lib/
COPY --from=kmstool /usr/lib/libcrypto.so* /usr/lib/
# JSON library
COPY --from=kmstool /usr/lib/libjson-c.so* /usr/lib/
# NSM library for attestation
COPY --from=kmstool /usr/lib/libnsm.so /usr/lib/libnsm.so

ENV LD_LIBRARY_PATH="/usr/lib":"/lib"

RUN chmod +x /app/enclave-vault

CMD ["/app/enclave-vault"]
