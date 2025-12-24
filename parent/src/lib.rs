// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

//! # Parent Vault
//!
//! The parent tier of the AWS Nitro Enclaves secure vault solution.
//!
//! This crate provides an HTTP API server that acts as a bridge between external
//! clients and Nitro Enclaves. It handles credential management, enclave lifecycle,
//! and secure communication over vsock.
//!
//! ## Architecture
//!
//! ```text
//! Client -> HTTP API -> Parent (this crate) -> vsock -> Enclave
//!                            |
//!                            +-> IMDS (credentials)
//!                            +-> nitro-cli (enclave management)
//! ```
//!
//! The parent tier runs on an EC2 instance with Nitro Enclave support and provides:
//!
//! - **HTTP API**: Axum-based server with rate limiting, timeouts, and body limits
//! - **Credential Management**: Caches IAM credentials from IMDS with automatic refresh
//! - **Enclave Management**: Discovers and launches Nitro Enclaves via `nitro-cli`
//! - **vsock Communication**: Length-prefixed JSON protocol for enclave requests
//!
//! ## Modules
//!
//! - [`application`]: HTTP server setup with Axum, rate limiting, and timeouts
//! - [`configuration`]: CLI argument parsing with clap
//! - [`constants`]: Configuration constants for the application
//! - [`enclaves`]: Nitro Enclave management and vsock communication
//! - [`errors`]: Application error types with HTTP response mapping
//! - [`imds`]: IAM credential caching from EC2 Instance Metadata Service
//! - [`models`]: Request/response types with validation
//! - [`protocol`]: vsock message framing protocol (length-prefixed)
//! - [`routes`]: HTTP route handlers (health, decrypt, get_enclaves)
//!
//! ## Usage
//!
//! ```bash
//! parent-vault --host 127.0.0.1 --port 8080 --role my-iam-role
//! ```
//!
//! ## Security Considerations
//!
//! - Credentials are cached with automatic refresh 60 seconds before expiry
//! - All sensitive credential data is zeroized on drop
//! - Request validation enforces strict size limits to prevent abuse
//! - Rate limiting (100 req/s) protects against denial of service
//! - 30-second request timeout prevents resource exhaustion

pub mod application;
pub mod attestation;
pub mod configuration;
pub mod constants;
pub mod enclaves;
pub mod errors;
pub mod imds;
pub mod models;
pub mod nitro_root_cert;
pub mod protocol;
pub mod routes;
