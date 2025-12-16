// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

//! FFI declarations for the AWS Nitro Enclaves SDK C library.
//!
//! This module provides low-level bindings to the aws-nitro-enclaves-sdk-c library,
//! following the pattern from aws-nitro-enclaves-acm.

use libc::c_int;
#[cfg(target_os = "linux")]
use libc::c_void;

// =============================================================================
// Constants
// =============================================================================

/// Parent CID for vsock communication ("3\0")
pub const AWS_NE_VSOCK_PROXY_ADDR: [u8; 2] = [0x33, 0x00];

/// Vsock proxy port for KMS communication
pub const AWS_NE_VSOCK_PROXY_PORT: u16 = 8000;

/// Vsock socket domain constant
pub const AWS_SOCKET_VSOCK_DOMAIN: c_int = 3;

/// Maximum length for socket address
pub const AWS_ADDRESS_MAX_LEN: usize = 108;

// =============================================================================
// Opaque Pointer Types
// =============================================================================

/// Opaque allocator type from aws-c-common
#[repr(C)]
pub struct aws_allocator {
    _ph: [u8; 0],
}

/// Opaque string type from aws-c-common
#[repr(C)]
pub struct aws_string {
    _ph: [u8; 0],
}

/// Opaque KMS client type
#[repr(C)]
pub struct aws_nitro_enclaves_kms_client {
    _ph: [u8; 0],
}

/// Opaque KMS client configuration type
#[repr(C)]
pub struct aws_nitro_enclaves_kms_client_configuration {
    _ph: [u8; 0],
}

// =============================================================================
// Concrete Structs
// =============================================================================

/// Byte buffer struct from aws-c-common
#[repr(C)]
pub struct aws_byte_buf {
    /// Number of bytes currently in the buffer
    pub len: usize,
    /// Pointer to the buffer data
    pub buffer: *mut u8,
    /// Total capacity of the buffer
    pub capacity: usize,
    /// Allocator used for this buffer
    pub allocator: *mut aws_allocator,
}

/// Socket endpoint struct for vsock communication
#[repr(C)]
pub struct aws_socket_endpoint {
    /// Address string (null-terminated)
    pub address: [u8; AWS_ADDRESS_MAX_LEN],
    /// Port number
    pub port: u16,
}

// =============================================================================
// External Function Declarations (Linux only - requires AWS Nitro Enclaves SDK)
// =============================================================================

#[cfg(target_os = "linux")]
unsafe extern "C" {
    // -------------------------------------------------------------------------
    // SDK Lifecycle
    // -------------------------------------------------------------------------

    /// Initialize the Nitro Enclaves library
    pub fn aws_nitro_enclaves_library_init(allocator: *mut aws_allocator);

    /// Clean up the Nitro Enclaves library
    pub fn aws_nitro_enclaves_library_clean_up();

    /// Get the allocator for Nitro Enclaves operations
    pub fn aws_nitro_enclaves_get_allocator() -> *mut aws_allocator;

    // -------------------------------------------------------------------------
    // String Operations
    // -------------------------------------------------------------------------

    /// Create a new aws_string from a byte array
    pub fn aws_string_new_from_array(
        allocator: *mut aws_allocator,
        bytes: *const u8,
        len: usize,
    ) -> *mut aws_string;

    /// Securely destroy an aws_string (zeroes memory before freeing)
    pub fn aws_string_destroy_secure(string: *mut aws_string);

    // -------------------------------------------------------------------------
    // Buffer Operations
    // -------------------------------------------------------------------------

    /// Create an aws_byte_buf from a byte array (does not copy data)
    pub fn aws_byte_buf_from_array(bytes: *mut c_void, len: usize) -> aws_byte_buf;

    /// Securely clean up an aws_byte_buf (zeroes memory before freeing)
    pub fn aws_byte_buf_clean_up_secure(buf: *mut aws_byte_buf);

    // -------------------------------------------------------------------------
    // KMS Client Configuration
    // -------------------------------------------------------------------------

    /// Create a default KMS client configuration
    pub fn aws_nitro_enclaves_kms_client_config_default(
        region: *mut aws_string,
        endpoint: *mut aws_socket_endpoint,
        domain: c_int,
        access_key_id: *mut aws_string,
        secret_access_key: *mut aws_string,
        session_token: *mut aws_string,
    ) -> *mut aws_nitro_enclaves_kms_client_configuration;

    /// Destroy a KMS client configuration
    pub fn aws_nitro_enclaves_kms_client_config_destroy(
        config: *mut aws_nitro_enclaves_kms_client_configuration,
    );

    // -------------------------------------------------------------------------
    // KMS Client
    // -------------------------------------------------------------------------

    /// Create a new KMS client from configuration
    pub fn aws_nitro_enclaves_kms_client_new(
        config: *mut aws_nitro_enclaves_kms_client_configuration,
    ) -> *mut aws_nitro_enclaves_kms_client;

    /// Destroy a KMS client
    pub fn aws_nitro_enclaves_kms_client_destroy(client: *mut aws_nitro_enclaves_kms_client);

    /// Perform a blocking KMS decrypt operation
    pub fn aws_kms_decrypt_blocking(
        client: *mut aws_nitro_enclaves_kms_client,
        key_id: *mut aws_string,
        encryption_algorithm: *mut aws_string,
        ciphertext: *const aws_byte_buf,
        plaintext: *mut aws_byte_buf,
    ) -> c_int;
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// **Feature: kms-ffi-wrapper, Property 1: Vsock endpoint constants are correctly defined**
    /// **Validates: Requirements 2.4**
    ///
    /// Verifies that the vsock endpoint constants are correctly defined:
    /// - Parent CID is "3" (0x33 followed by null terminator)
    /// - Proxy port is 8000
    #[test]
    fn test_vsock_constants() {
        // Parent CID should be "3" (ASCII 0x33) followed by null terminator
        assert_eq!(
            AWS_NE_VSOCK_PROXY_ADDR[0], 0x33,
            "Parent CID should be '3' (0x33)"
        );
        assert_eq!(
            AWS_NE_VSOCK_PROXY_ADDR[1], 0x00,
            "Address should be null-terminated"
        );

        // Proxy port should be 8000
        assert_eq!(AWS_NE_VSOCK_PROXY_PORT, 8000, "Proxy port should be 8000");

        // Vsock domain constant
        assert_eq!(AWS_SOCKET_VSOCK_DOMAIN, 3, "Vsock domain should be 3");

        // Address max length should be 108 (standard sockaddr_un size)
        assert_eq!(AWS_ADDRESS_MAX_LEN, 108, "Address max length should be 108");
    }
}
