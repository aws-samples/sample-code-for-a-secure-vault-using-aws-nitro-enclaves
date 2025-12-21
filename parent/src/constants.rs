// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use std::time::Duration;

pub const ENCLAVE_PREFIX: &str = "enclave-vault";
pub const ENCLAVE_PORT: u32 = 5050;
/// https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html#nitro-enclave-considerations
/// one enclave is consumed for the Nitro ACM service
pub const MAX_ENCLAVES_PER_INSTANCE: usize = 2;
pub const RUN_ENCLAVE_EIF_PATH: &str = "/home/ec2-user/enclave-vault.eif";
pub const RUN_ENCLAVE_CPU_COUNT: &str = "1";
pub const RUN_ENCLAVE_MEMORY_SIZE: &str = "512";
pub const REFRESH_ENCLAVES_INTERVAL: Duration = Duration::from_secs(10);
pub const IMDS_TOKEN_TTL: Duration = Duration::from_secs(300); // 5 minutes
pub const CREDENTIAL_REFRESH_BUFFER: Duration = Duration::from_secs(60); // refresh 60s before expiry
pub const MAX_MESSAGE_SIZE: u64 = 10 * 1024 * 1024; // 10 MB

// Validation constants for ParentRequest
pub const MAX_VAULT_ID_LENGTH: u64 = 256;
pub const MAX_REGION_LENGTH: u64 = 64;
pub const MAX_SUITE_ID_LENGTH: u64 = 1024;
pub const MAX_ENCRYPTED_KEY_LENGTH: u64 = 8192;
pub const MAX_ENCODING_LENGTH: u64 = 32;
pub const MAX_FIELDS_COUNT: usize = 100;
pub const MAX_EXPRESSIONS_COUNT: usize = 100;
