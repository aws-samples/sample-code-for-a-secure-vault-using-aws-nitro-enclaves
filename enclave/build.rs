// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

//! Build script for enclave-vault crate.
//!
//! Links against the AWS Nitro Enclaves SDK C libraries required for FFI bindings.

fn main() {
    // Add library search path for the AWS SDK libraries
    println!("cargo:rustc-link-search=native=/usr/lib");

    // Link against aws-nitro-enclaves-sdk-c and all its dependencies
    // Order matters: dependent libraries must come after the libraries that use them

    // Main SDK library
    println!("cargo:rustc-link-lib=static=aws-nitro-enclaves-sdk-c");

    // AWS C libraries (in dependency order)
    println!("cargo:rustc-link-lib=static=aws-c-auth");
    println!("cargo:rustc-link-lib=static=aws-c-http");
    println!("cargo:rustc-link-lib=static=aws-c-compression");
    println!("cargo:rustc-link-lib=static=aws-c-io");
    println!("cargo:rustc-link-lib=static=aws-c-cal");
    println!("cargo:rustc-link-lib=static=aws-c-sdkutils");
    println!("cargo:rustc-link-lib=static=aws-c-common");

    // TLS library
    println!("cargo:rustc-link-lib=static=s2n");

    // JSON library
    println!("cargo:rustc-link-lib=static=json-c");

    // NSM library for attestation (dynamic - built from Rust crate)
    println!("cargo:rustc-link-lib=dylib=nsm");

    // Crypto library (from aws-lc build)
    println!("cargo:rustc-link-lib=static=crypto");
}
