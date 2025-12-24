// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

//! Nitro Secure Module (NSM) interface for attestation document generation.
//!
//! This module provides a wrapper around the AWS Nitro Enclaves NSM API
//! to generate attestation documents that can be used to prove the enclave's
//! identity and configuration to external verifiers.
//!
//! # Security
//!
//! - Enforces minimum nonce length (16 bytes) per Trail of Bits recommendations
//! - All sensitive data is handled securely within the NSM device
//! - Attestation documents are signed by the Nitro hypervisor

use anyhow::{Result, anyhow, bail};

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

/// Generate an attestation document from the Nitro Secure Module.
///
/// This function requests an attestation document from the NSM device,
/// which contains cryptographic proof of the enclave's identity including:
/// - PCR values (enclave image hash, kernel, application)
/// - Module ID
/// - Timestamp
/// - Optional user-provided data (nonce, user_data, public_key)
///
/// # Arguments
///
/// * `user_data` - Optional application-specific data to include (max 512 bytes)
/// * `nonce` - Nonce for freshness guarantee (min 16 bytes, max 512 bytes)
/// * `public_key` - Optional public key for encrypted responses (max 1024 bytes)
///
/// # Returns
///
/// COSE Sign1 encoded attestation document as raw bytes.
///
/// # Errors
///
/// Returns an error if:
/// - Nonce is provided but shorter than MIN_NONCE_LENGTH (16 bytes)
/// - Any field exceeds its maximum length
/// - NSM device communication fails
/// - Running outside a Nitro Enclave environment
///
/// # Security
///
/// The minimum nonce length is enforced to prevent weak nonces that could
/// enable replay attacks. Per Trail of Bits recommendations, clients should
/// provide a cryptographically random nonce of at least 16 bytes.
#[cfg(target_env = "musl")]
pub fn get_attestation_document(
    user_data: Option<&[u8]>,
    nonce: Option<&[u8]>,
    public_key: Option<&[u8]>,
) -> Result<Vec<u8>> {
    use aws_nitro_enclaves_nsm_api::api::{Request, Response};
    use aws_nitro_enclaves_nsm_api::driver;

    // Validate nonce length (minimum enforced per Trail of Bits)
    if let Some(n) = nonce {
        if n.len() < MIN_NONCE_LENGTH {
            bail!(
                "nonce must be at least {} bytes, got {}",
                MIN_NONCE_LENGTH,
                n.len()
            );
        }
        if n.len() > MAX_NONCE_LENGTH {
            bail!(
                "nonce must be at most {} bytes, got {}",
                MAX_NONCE_LENGTH,
                n.len()
            );
        }
    }

    // Validate user_data length
    if let Some(ud) = user_data {
        if ud.len() > MAX_USER_DATA_LENGTH {
            bail!(
                "user_data must be at most {} bytes, got {}",
                MAX_USER_DATA_LENGTH,
                ud.len()
            );
        }
    }

    // Validate public_key length
    if let Some(pk) = public_key {
        if pk.len() > MAX_PUBLIC_KEY_LENGTH {
            bail!(
                "public_key must be at most {} bytes, got {}",
                MAX_PUBLIC_KEY_LENGTH,
                pk.len()
            );
        }
    }

    // Open NSM device
    let nsm_fd = driver::nsm_init();
    if nsm_fd < 0 {
        bail!("failed to initialize NSM device: fd={}", nsm_fd);
    }

    // Build attestation request
    let request = Request::Attestation {
        user_data: user_data.map(|d| d.to_vec()),
        nonce: nonce.map(|n| n.to_vec()),
        public_key: public_key.map(|pk| pk.to_vec()),
    };

    // Process request through NSM
    let response = driver::nsm_process_request(nsm_fd, request);

    // Close NSM device
    driver::nsm_exit(nsm_fd);

    // Extract attestation document from response
    match response {
        Response::Attestation { document } => Ok(document),
        Response::Error(error_code) => {
            bail!("NSM attestation failed with error code: {:?}", error_code)
        }
        _ => bail!("unexpected NSM response type"),
    }
}

/// Stub implementation for non-musl targets (development/testing).
///
/// Returns an error indicating that attestation is only available inside
/// a Nitro Enclave (musl target).
#[cfg(not(target_env = "musl"))]
pub fn get_attestation_document(
    _user_data: Option<&[u8]>,
    nonce: Option<&[u8]>,
    _public_key: Option<&[u8]>,
) -> Result<Vec<u8>> {
    // Validate nonce length for testing (same validation as production)
    if let Some(n) = nonce {
        if n.len() < MIN_NONCE_LENGTH {
            bail!(
                "nonce must be at least {} bytes, got {}",
                MIN_NONCE_LENGTH,
                n.len()
            );
        }
        if n.len() > MAX_NONCE_LENGTH {
            bail!(
                "nonce must be at most {} bytes, got {}",
                MAX_NONCE_LENGTH,
                n.len()
            );
        }
    }

    Err(anyhow!(
        "attestation documents are only available inside a Nitro Enclave (musl target)"
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_min_nonce_length_constant() {
        assert_eq!(MIN_NONCE_LENGTH, 16, "minimum nonce should be 16 bytes (128 bits)");
    }

    #[test]
    fn test_nonce_too_short() {
        let short_nonce = vec![0u8; MIN_NONCE_LENGTH - 1];
        let result = get_attestation_document(None, Some(&short_nonce), None);

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("nonce must be at least"));
        assert!(err.contains(&MIN_NONCE_LENGTH.to_string()));
    }

    #[test]
    fn test_nonce_exactly_min_length() {
        let valid_nonce = vec![0u8; MIN_NONCE_LENGTH];
        let result = get_attestation_document(None, Some(&valid_nonce), None);

        // On non-musl targets, this will fail with "not in enclave" error
        // but it should NOT fail with "nonce too short" error
        if let Err(err) = result {
            assert!(
                !err.to_string().contains("nonce must be at least"),
                "nonce of exactly MIN_NONCE_LENGTH should not be rejected for length"
            );
        }
    }

    #[test]
    fn test_nonce_none_is_allowed() {
        // None nonce should be allowed (though not recommended)
        let result = get_attestation_document(None, None, None);

        // On non-musl targets, this will fail with "not in enclave" error
        // but it should NOT fail with nonce validation error
        if let Err(err) = result {
            assert!(
                !err.to_string().contains("nonce"),
                "None nonce should be allowed"
            );
        }
    }

    #[test]
    fn test_nonce_too_long() {
        let long_nonce = vec![0u8; MAX_NONCE_LENGTH + 1];
        let result = get_attestation_document(None, Some(&long_nonce), None);

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("nonce must be at most"));
    }

    #[cfg(not(target_env = "musl"))]
    #[test]
    fn test_non_musl_returns_error() {
        let nonce = vec![0u8; MIN_NONCE_LENGTH];
        let result = get_attestation_document(None, Some(&nonce), None);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Nitro Enclave"));
    }
}
