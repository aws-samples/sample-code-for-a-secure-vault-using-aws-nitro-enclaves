// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

//! KMS integration module for the Nitro Enclave.
//!
//! This module provides functionality to decrypt KMS-encrypted private keys using
//! the AWS Nitro Enclaves SDK FFI wrapper. The decrypted private keys are used
//! for HPKE decryption of vault field values.
//!
//! # Security
//!
//! - Private key material is zeroized immediately after extraction
//! - KMS decryption is performed via the Nitro Enclaves SDK which uses
//!   attestation-based access control
//! - The KMS key policy must allow the enclave's PCR values to decrypt

use anyhow::{Result, anyhow};
use aws_lc_rs::encoding::AsBigEndian;
use aws_lc_rs::signature::{EcdsaKeyPair, EcdsaSigningAlgorithm};
use rustls::crypto::hpke::HpkePrivateKey;
use zeroize::Zeroize;

use crate::aws_ne;
use crate::models::{Credential, EnclaveRequest};
use crate::utils::base64_decode;

/// Calls KMS decrypt via the Nitro Enclaves SDK FFI wrapper.
///
/// # Arguments
///
/// * `credential` - AWS credentials for KMS access
/// * `ciphertext` - Base64-encoded ciphertext to decrypt
/// * `region` - AWS region where the KMS key resides
///
/// # Returns
///
/// Returns the decrypted plaintext bytes.
fn call_kms_decrypt(credential: &Credential, ciphertext: &str, region: &str) -> Result<Vec<u8>> {
    // Base64 decode the ciphertext
    let ciphertext_bytes = base64_decode(ciphertext)?;

    // Call FFI wrapper directly instead of spawning subprocess
    aws_ne::kms_decrypt(
        region.as_bytes(),
        credential.access_key_id.as_bytes(),
        credential.secret_access_key.as_bytes(),
        credential.session_token.as_bytes(),
        &ciphertext_bytes,
    )
    .map_err(|e| anyhow!("KMS decrypt failed: {}", e))
}

/// Decrypts and extracts the HPKE private key from a KMS-encrypted payload.
///
/// This function:
/// 1. Decrypts the KMS-encrypted private key using the provided credentials
/// 2. Parses the DER-encoded PKCS#8 private key
/// 3. Extracts the raw private key bytes for HPKE use
/// 4. Zeroizes all intermediate key material
///
/// # Arguments
///
/// * `alg` - The ECDSA signing algorithm matching the key's curve
/// * `payload` - The enclave request containing credentials and encrypted key
///
/// # Returns
///
/// Returns the HPKE private key ready for decryption operations.
///
/// # Security
///
/// The plaintext private key material is zeroized immediately after extraction,
/// even if an error occurs during processing.
pub fn get_secret_key(
    alg: &'static EcdsaSigningAlgorithm,
    payload: &EnclaveRequest,
) -> Result<HpkePrivateKey> {
    // Call KMS decrypt via FFI wrapper - returns plaintext bytes directly
    let mut plaintext_sk = call_kms_decrypt(
        &payload.credential,
        &payload.request.encrypted_private_key, // base64 encoded
        &payload.request.region,
    )
    .map_err(|err| anyhow!("failed to call KMS: {err:?}"))?;

    // Process key and ensure zeroization on all paths
    let result = (|| -> Result<HpkePrivateKey> {
        // Decode the DER PKCS#8 secret key
        let sk = EcdsaKeyPair::from_private_key_der(alg, &plaintext_sk)
            .map_err(|err| anyhow!("unable to decode PKCS#8 private key: {err:?}"))?;
        let sk_bytes = sk
            .private_key()
            .as_be_bytes()
            .map_err(|err| anyhow!("unable to get private key bytes: {err:?}"))?;
        let sk_ref = sk_bytes.as_ref();

        Ok(sk_ref.to_vec().into())
    })();

    // Always zeroize the plaintext key material
    plaintext_sk.zeroize();

    result
}
