// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

//! AWS Nitro Enclaves SDK FFI wrapper module.
//!
//! This module provides safe Rust wrappers around the aws-nitro-enclaves-sdk-c library
//! for KMS operations within Nitro Enclaves.

pub mod ffi;

use std::fmt;

#[cfg(target_os = "linux")]
use std::ptr;
#[cfg(target_os = "linux")]
use std::slice;

#[cfg(target_os = "linux")]
use ffi::{
    aws_allocator, aws_byte_buf, aws_byte_buf_clean_up_secure, aws_kms_decrypt_blocking,
    aws_nitro_enclaves_get_allocator, aws_nitro_enclaves_kms_client,
    aws_nitro_enclaves_kms_client_config_default, aws_nitro_enclaves_kms_client_config_destroy,
    aws_nitro_enclaves_kms_client_configuration, aws_nitro_enclaves_kms_client_destroy,
    aws_nitro_enclaves_kms_client_new, aws_nitro_enclaves_library_clean_up,
    aws_nitro_enclaves_library_init, aws_socket_endpoint, aws_string, aws_string_destroy_secure,
    aws_string_new_from_array, AWS_ADDRESS_MAX_LEN, AWS_NE_VSOCK_PROXY_ADDR,
    AWS_NE_VSOCK_PROXY_PORT, AWS_SOCKET_VSOCK_DOMAIN,
};

/// Errors that can occur during KMS operations via FFI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// SDK initialization failed (aws_nitro_enclaves_library_init or get_allocator)
    SdkInitError,
    /// Generic SDK error (string allocation failed)
    SdkGenericError,
    /// KMS client configuration failed
    SdkKmsConfigError,
    /// KMS client creation failed
    SdkKmsClientError,
    /// KMS decrypt operation failed
    SdkKmsDecryptError,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::SdkInitError => write!(f, "Failed to initialize Nitro Enclaves SDK"),
            Error::SdkGenericError => write!(f, "SDK memory allocation failed"),
            Error::SdkKmsConfigError => write!(f, "Failed to configure KMS client"),
            Error::SdkKmsClientError => write!(f, "Failed to create KMS client"),
            Error::SdkKmsDecryptError => write!(f, "KMS decrypt operation failed"),
        }
    }
}

impl std::error::Error for Error {}

/// Helper struct to track allocated resources for cleanup
#[cfg(target_os = "linux")]
struct KmsResources {
    allocator: *mut aws_allocator,
    region: *mut aws_string,
    access_key_id: *mut aws_string,
    secret_access_key: *mut aws_string,
    session_token: *mut aws_string,
    config: *mut aws_nitro_enclaves_kms_client_configuration,
    client: *mut aws_nitro_enclaves_kms_client,
    plaintext_buf: Option<aws_byte_buf>,
}

#[cfg(target_os = "linux")]
impl KmsResources {
    fn new() -> Self {
        Self {
            allocator: ptr::null_mut(),
            region: ptr::null_mut(),
            access_key_id: ptr::null_mut(),
            secret_access_key: ptr::null_mut(),
            session_token: ptr::null_mut(),
            config: ptr::null_mut(),
            client: ptr::null_mut(),
            plaintext_buf: None,
        }
    }

    /// Clean up all allocated resources in reverse order of allocation.
    /// Uses secure cleanup functions to zero memory before freeing.
    ///
    /// # Safety
    ///
    /// Caller must ensure this is called from within an unsafe context and that
    /// all pointers stored in this struct are valid or null.
    unsafe fn cleanup(&mut self) {
        // Clean up plaintext buffer (securely erase decrypted data)
        if let Some(ref mut buf) = self.plaintext_buf {
            unsafe { aws_byte_buf_clean_up_secure(buf) };
        }
        self.plaintext_buf = None;

        // Destroy KMS client
        if !self.client.is_null() {
            unsafe { aws_nitro_enclaves_kms_client_destroy(self.client) };
            self.client = ptr::null_mut();
        }

        // Destroy KMS client config
        if !self.config.is_null() {
            unsafe { aws_nitro_enclaves_kms_client_config_destroy(self.config) };
            self.config = ptr::null_mut();
        }

        // Securely destroy credential strings (in reverse order of creation)
        if !self.session_token.is_null() {
            unsafe { aws_string_destroy_secure(self.session_token) };
            self.session_token = ptr::null_mut();
        }

        if !self.secret_access_key.is_null() {
            unsafe { aws_string_destroy_secure(self.secret_access_key) };
            self.secret_access_key = ptr::null_mut();
        }

        if !self.access_key_id.is_null() {
            unsafe { aws_string_destroy_secure(self.access_key_id) };
            self.access_key_id = ptr::null_mut();
        }

        if !self.region.is_null() {
            unsafe { aws_string_destroy_secure(self.region) };
            self.region = ptr::null_mut();
        }

        // Clean up SDK (must be last)
        unsafe { aws_nitro_enclaves_library_clean_up() };
    }
}

/// Decrypt ciphertext using KMS with Nitro Enclave attestation.
///
/// This function initializes the SDK, performs decryption, and cleans up
/// all resources before returning. The SDK automatically generates an
/// attestation document and sends it to KMS for verification.
///
/// # Arguments
///
/// * `aws_region` - AWS region (e.g., "us-east-1")
/// * `aws_key_id` - AWS access key ID
/// * `aws_secret_key` - AWS secret access key
/// * `aws_session_token` - AWS session token
/// * `ciphertext` - The encrypted data to decrypt
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The decrypted plaintext
/// * `Err(Error)` - An error if any step fails
///
/// # Safety
///
/// This function contains unsafe code to call C FFI functions. All resources
/// are properly cleaned up on both success and error paths using secure
/// cleanup functions that zero memory before freeing.
#[cfg(target_os = "linux")]
pub fn kms_decrypt(
    aws_region: &[u8],
    aws_key_id: &[u8],
    aws_secret_key: &[u8],
    aws_session_token: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut resources = KmsResources::new();

    unsafe {
        // Step 1: Initialize SDK with null allocator (uses default)
        aws_nitro_enclaves_library_init(ptr::null_mut());

        // Step 2: Get allocator for subsequent allocations
        resources.allocator = aws_nitro_enclaves_get_allocator();
        if resources.allocator.is_null() {
            resources.cleanup();
            return Err(Error::SdkInitError);
        }

        // Step 3: Create aws_string instances for credentials
        resources.region =
            aws_string_new_from_array(resources.allocator, aws_region.as_ptr(), aws_region.len());
        if resources.region.is_null() {
            resources.cleanup();
            return Err(Error::SdkGenericError);
        }

        resources.access_key_id =
            aws_string_new_from_array(resources.allocator, aws_key_id.as_ptr(), aws_key_id.len());
        if resources.access_key_id.is_null() {
            resources.cleanup();
            return Err(Error::SdkGenericError);
        }

        resources.secret_access_key = aws_string_new_from_array(
            resources.allocator,
            aws_secret_key.as_ptr(),
            aws_secret_key.len(),
        );
        if resources.secret_access_key.is_null() {
            resources.cleanup();
            return Err(Error::SdkGenericError);
        }

        resources.session_token = aws_string_new_from_array(
            resources.allocator,
            aws_session_token.as_ptr(),
            aws_session_token.len(),
        );
        if resources.session_token.is_null() {
            resources.cleanup();
            return Err(Error::SdkGenericError);
        }

        // Step 4: Configure vsock endpoint (CID 3, port 8000)
        let mut endpoint = aws_socket_endpoint {
            address: [0u8; AWS_ADDRESS_MAX_LEN],
            port: AWS_NE_VSOCK_PROXY_PORT,
        };
        // Copy parent CID address ("3\0")
        endpoint.address[..AWS_NE_VSOCK_PROXY_ADDR.len()].copy_from_slice(&AWS_NE_VSOCK_PROXY_ADDR);

        // Step 5: Create KMS client configuration
        resources.config = aws_nitro_enclaves_kms_client_config_default(
            resources.region,
            &mut endpoint,
            AWS_SOCKET_VSOCK_DOMAIN,
            resources.access_key_id,
            resources.secret_access_key,
            resources.session_token,
        );
        if resources.config.is_null() {
            resources.cleanup();
            return Err(Error::SdkKmsConfigError);
        }

        // Step 6: Create KMS client
        resources.client = aws_nitro_enclaves_kms_client_new(resources.config);
        if resources.client.is_null() {
            resources.cleanup();
            return Err(Error::SdkKmsClientError);
        }

        // Step 7: Prepare ciphertext buffer (does not copy data)
        let ciphertext_buf = aws_byte_buf {
            len: ciphertext.len(),
            buffer: ciphertext.as_ptr() as *mut u8,
            capacity: ciphertext.len(),
            allocator: ptr::null_mut(),
        };

        // Step 8: Prepare plaintext output buffer (will be allocated by SDK)
        let mut plaintext_buf = aws_byte_buf {
            len: 0,
            buffer: ptr::null_mut(),
            capacity: 0,
            allocator: ptr::null_mut(),
        };

        // Step 9: Call KMS decrypt (generates attestation document internally)
        // Pass null for key_id and encryption_algorithm to use defaults
        let rc = aws_kms_decrypt_blocking(
            resources.client,
            ptr::null_mut(), // key_id (use default from ciphertext)
            ptr::null_mut(), // encryption_algorithm (use default)
            &ciphertext_buf,
            &mut plaintext_buf,
        );

        if rc != 0 {
            // Store buffer for cleanup even on error
            resources.plaintext_buf = Some(plaintext_buf);
            resources.cleanup();
            return Err(Error::SdkKmsDecryptError);
        }

        // Step 10: Copy plaintext to Vec<u8> before cleanup
        let plaintext = if !plaintext_buf.buffer.is_null() && plaintext_buf.len > 0 {
            slice::from_raw_parts(plaintext_buf.buffer, plaintext_buf.len).to_vec()
        } else {
            Vec::new()
        };

        // Step 11: Store buffer for secure cleanup
        resources.plaintext_buf = Some(plaintext_buf);

        // Step 12: Clean up all resources in reverse order
        resources.cleanup();

        Ok(plaintext)
    }
}

/// Stub implementation for non-Linux platforms (compilation only).
/// This function will panic if called - it's only meant to allow compilation
/// on development machines. The actual implementation requires the AWS Nitro
/// Enclaves SDK which is only available on Linux.
#[cfg(not(target_os = "linux"))]
pub fn kms_decrypt(
    _aws_region: &[u8],
    _aws_key_id: &[u8],
    _aws_secret_key: &[u8],
    _aws_session_token: &[u8],
    _ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    panic!("kms_decrypt is only available on Linux with AWS Nitro Enclaves SDK")
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// **Feature: kms-ffi-wrapper, Property 2: Error enum is convertible to anyhow::Error**
    /// **Validates: Requirements 3.3**
    ///
    /// Verifies that all Error variants can be converted to anyhow::Error
    /// with descriptive messages. Since Error implements std::error::Error
    /// and Display, it can be converted via anyhow's blanket From implementation.
    #[test]
    fn test_error_conversion_to_anyhow() {
        // Test all error variants can be converted to anyhow::Error
        let errors = [
            Error::SdkInitError,
            Error::SdkGenericError,
            Error::SdkKmsConfigError,
            Error::SdkKmsClientError,
            Error::SdkKmsDecryptError,
        ];

        let expected_messages = [
            "Failed to initialize Nitro Enclaves SDK",
            "SDK memory allocation failed",
            "Failed to configure KMS client",
            "Failed to create KMS client",
            "KMS decrypt operation failed",
        ];

        for (error, expected_msg) in errors.iter().zip(expected_messages.iter()) {
            // Convert to anyhow::Error using the blanket From implementation
            let anyhow_err: anyhow::Error = (*error).into();

            // Verify the error message is descriptive
            let err_string = anyhow_err.to_string();
            assert!(
                err_string.contains(expected_msg),
                "Error {:?} should contain '{}', got '{}'",
                error,
                expected_msg,
                err_string
            );
        }
    }

    /// Test that Error implements std::error::Error trait
    #[test]
    fn test_error_implements_std_error() {
        fn assert_std_error<E: std::error::Error>() {}
        assert_std_error::<Error>();
    }

    /// Test that Error implements Display trait with descriptive messages
    #[test]
    fn test_error_display() {
        assert_eq!(
            Error::SdkInitError.to_string(),
            "Failed to initialize Nitro Enclaves SDK"
        );
        assert_eq!(
            Error::SdkGenericError.to_string(),
            "SDK memory allocation failed"
        );
        assert_eq!(
            Error::SdkKmsConfigError.to_string(),
            "Failed to configure KMS client"
        );
        assert_eq!(
            Error::SdkKmsClientError.to_string(),
            "Failed to create KMS client"
        );
        assert_eq!(
            Error::SdkKmsDecryptError.to_string(),
            "KMS decrypt operation failed"
        );
    }
}
