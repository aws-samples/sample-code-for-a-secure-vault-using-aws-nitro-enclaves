// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use std::time::Duration;

pub const ENCLAVE_PREFIX: &str = "enclave-vault";
pub const ENCLAVE_PORT: u32 = 5050;
/// https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html#nitro-enclave-considerations
/// one enclave is consumed for the Nitro ACM service
pub const MAX_ENCLAVES_PER_INSTANCE: usize = 3;
pub const RUN_ENCLAVE_EIF_PATH: &str = "/home/ec2-user/enclave-vault.eif";
pub const RUN_ENCLAVE_CPU_COUNT: &str = "2";
pub const RUN_ENCLAVE_MEMORY_SIZE: &str = "512";
pub const REFRESH_ENCLAVES_INTERVAL: Duration = Duration::from_secs(10);
pub const IMDS_TOKEN_TTL: Duration = Duration::from_secs(300); // 5 minutes
