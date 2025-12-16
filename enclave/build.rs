// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

//! Build script for enclave-vault crate.
//!
//! Links against the AWS Nitro Enclaves SDK C libraries required for FFI bindings.

fn main() {
    // Link against aws-c-common library (provides aws_allocator, aws_string, aws_byte_buf)
    println!("cargo:rustc-link-lib=dylib=aws-c-common");

    // Link against aws-nitro-enclaves-sdk-c library (provides KMS client and attestation)
    println!("cargo:rustc-link-lib=dylib=aws-nitro-enclaves-sdk-c");
}
