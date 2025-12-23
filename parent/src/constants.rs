// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

//! Configuration constants for the parent vault application.
//!
//! This module contains all compile-time constants used throughout the parent tier,
//! including enclave configuration, timing parameters, and request validation limits.

use std::time::Duration;

/// Prefix used to identify vault enclaves when listing via `nitro-cli describe-enclaves`.
/// Only enclaves with names starting with this prefix are managed by this application.
pub const ENCLAVE_PREFIX: &str = "enclave-vault";

/// The vsock port number that enclaves listen on for incoming requests.
pub const ENCLAVE_PORT: u32 = 5050;

/// Maximum number of enclaves to run per EC2 instance.
///
/// Note: One enclave slot may be consumed by the Nitro ACM service if enabled.
/// See: <https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html#nitro-enclave-considerations>
pub const MAX_ENCLAVES_PER_INSTANCE: usize = 2;

/// Path to the Enclave Image File (EIF) used when launching new enclaves.
pub const RUN_ENCLAVE_EIF_PATH: &str = "/home/ec2-user/enclave-vault.eif";

/// Number of vCPUs to allocate to each enclave.
pub const RUN_ENCLAVE_CPU_COUNT: &str = "1";

/// Memory in MiB to allocate to each enclave.
pub const RUN_ENCLAVE_MEMORY_SIZE: &str = "512";

/// Interval between enclave refresh cycles.
///
/// The parent periodically checks the status of running enclaves and launches
/// new ones if needed to maintain [`MAX_ENCLAVES_PER_INSTANCE`].
pub const REFRESH_ENCLAVES_INTERVAL: Duration = Duration::from_secs(10);

/// Time-to-live for IMDS session tokens.
///
/// The parent uses these tokens to authenticate with the EC2 Instance Metadata
/// Service when fetching IAM credentials.
pub const IMDS_TOKEN_TTL: Duration = Duration::from_secs(300);

/// Buffer time before credential expiry to trigger a refresh.
///
/// Credentials are refreshed this many seconds before they actually expire
/// to ensure uninterrupted access to AWS services.
pub const CREDENTIAL_REFRESH_BUFFER: Duration = Duration::from_secs(60);

/// Maximum size in bytes for messages sent over vsock.
///
/// Messages larger than this limit will be rejected to prevent memory exhaustion.
pub const MAX_MESSAGE_SIZE: u64 = 10 * 1024 * 1024;

/// Maximum length of the `vault_id` field in [`crate::models::ParentRequest`].
pub const MAX_VAULT_ID_LENGTH: u64 = 256;

/// Maximum length of the `region` field in [`crate::models::ParentRequest`].
pub const MAX_REGION_LENGTH: u64 = 64;

/// Maximum length of the `suite_id` field in [`crate::models::ParentRequest`].
pub const MAX_SUITE_ID_LENGTH: u64 = 1024;

/// Maximum length of the `encrypted_private_key` field in [`crate::models::ParentRequest`].
pub const MAX_ENCRYPTED_KEY_LENGTH: u64 = 8192;

/// Maximum length of the `encoding` field in [`crate::models::ParentRequest`].
pub const MAX_ENCODING_LENGTH: u64 = 32;

/// Maximum number of fields allowed in the `fields` map of [`crate::models::ParentRequest`].
pub const MAX_FIELDS_COUNT: usize = 100;

/// Maximum number of expressions allowed in the `expressions` map of [`crate::models::ParentRequest`].
pub const MAX_EXPRESSIONS_COUNT: usize = 100;

/// Maximum request body size (1 MB).
///
/// HTTP requests with bodies larger than this limit will receive a 413 Payload Too Large response.
pub const REQUEST_BODY_LIMIT: usize = 1024 * 1024;

/// Request timeout duration (30 seconds).
///
/// HTTP requests that take longer than this duration will receive a 408 Request Timeout response.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
