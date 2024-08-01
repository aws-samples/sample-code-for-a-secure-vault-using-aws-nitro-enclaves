// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

pub const ENCLAVE_PORT: u32 = 5050;
pub const PLAINTEXT_PREFIX: &str = "PLAINTEXT: ";

// build_suite_id(0x0010u16, 0x0001u16, 0x0002u16) - DH_KEM_P256_HKDF_SHA256_AES_256
pub const P256: &[u8; 10] = &[72, 80, 75, 69, 0, 16, 0, 1, 0, 2];
// build_suite_id(0x0011u16, 0x0002u16, 0x0002u16) - DH_KEM_P384_HKDF_SHA384_AES_256
pub const P384: &[u8; 10] = &[72, 80, 75, 69, 0, 17, 0, 2, 0, 2];
// build_suite_id(0x0012u16, 0x0003u16, 0x0002u16) - DH_KEM_P521_HKDF_SHA512_AES_256
pub const P521: &[u8; 10] = &[72, 80, 75, 69, 0, 18, 0, 3, 0, 2];
