// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

pub const ENCLAVE_PORT: u32 = 5050;

/// Maximum concurrent connections to prevent resource exhaustion DoS attacks.
/// Each connection spawns a thread (~8KB stack minimum), so this limits memory usage.
/// With 32 connections and 10MB max message size, worst case is ~320MB memory.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 32;

/// Maximum allowed message size (10 MB) to prevent memory exhaustion DoS attacks
pub const MAX_MESSAGE_SIZE: u64 = 10 * 1024 * 1024;

/// Maximum number of fields allowed per request to prevent resource exhaustion
pub const MAX_FIELDS: usize = 1000;

/// Maximum allowed expression length (10 KB) to prevent resource exhaustion attacks
pub const MAX_EXPRESSION_LENGTH: usize = 10 * 1024;

// build_suite_id(0x0010u16, 0x0001u16, 0x0002u16) - DH_KEM_P256_HKDF_SHA256_AES_256
pub const P256: &[u8; 10] = &[72, 80, 75, 69, 0, 16, 0, 1, 0, 2];
// build_suite_id(0x0011u16, 0x0002u16, 0x0002u16) - DH_KEM_P384_HKDF_SHA384_AES_256
pub const P384: &[u8; 10] = &[72, 80, 75, 69, 0, 17, 0, 2, 0, 2];
// build_suite_id(0x0012u16, 0x0003u16, 0x0002u16) - DH_KEM_P521_HKDF_SHA512_AES_256
pub const P521: &[u8; 10] = &[72, 80, 75, 69, 0, 18, 0, 3, 0, 2];

pub const ENCODING_HEX: &str = "1";
pub const ENCODING_BINARY: &str = "2";

// NSM (Nitro Secure Module) constants for attestation

/// Minimum nonce length in bytes (128 bits) per Trail of Bits recommendations.
///
/// Reference: <https://blog.trailofbits.com/2024/09/24/notes-on-aws-nitro-enclaves-attack-surface/>
pub const MIN_NONCE_LENGTH: usize = 16;

/// Maximum nonce length in bytes (NSM limit)
pub const MAX_NONCE_LENGTH: usize = 512;

/// Maximum user_data length in bytes (NSM limit)
pub const MAX_USER_DATA_LENGTH: usize = 512;

/// Maximum public_key length in bytes (NSM limit)
pub const MAX_PUBLIC_KEY_LENGTH: usize = 1024;
