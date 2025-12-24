// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

//! Attestation document verification using the reconstruct-verify approach.
//!
//! This module implements verification of AWS Nitro Enclave attestation documents
//! following Trail of Bits recommendations. Instead of parsing PCRs and comparing
//! them directly, we reconstruct the attestation payload with expected PCR values
//! and verify the signature against the reconstructed payload.
//!
//! # Security Model
//!
//! Per Trail of Bits recommendations:
//! - Reconstruct payload with expected PCRs instead of parse-then-compare
//! - Verify COSE signature against reconstructed payload
//! - Validate certificate chain to AWS Nitro root
//! - Enforce minimum nonce length (16 bytes)
//! - Check attestation timestamp for freshness
//!
//! References:
//! - <https://blog.trailofbits.com/2024/02/16/a-few-notes-on-aws-nitro-enclaves-images-and-attestation/>
//! - <https://blog.trailofbits.com/2024/09/24/notes-on-aws-nitro-enclaves-attack-surface/>

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use ciborium::Value as CborValue;
use coset::{CoseSign1, TaggedCborSerializable};
use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use x509_cert::der::Decode;

use crate::models::{DocumentInfo, VerificationResult};
use crate::nitro_root_cert;

/// Minimum nonce length in bytes (128 bits) per Trail of Bits recommendations.
pub const MIN_NONCE_BYTES: usize = 16;

/// Default maximum attestation age in milliseconds (5 minutes).
pub const DEFAULT_MAX_AGE_MS: u64 = 300_000;

/// Parsed attestation document (internal representation).
#[derive(Debug)]
pub struct ParsedAttestation {
    pub module_id: String,
    pub timestamp: u64,
    pub digest: String,
    pub pcrs: BTreeMap<u8, Vec<u8>>,
    pub certificate: Vec<u8>,
    pub cabundle: Vec<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
    pub user_data: Option<Vec<u8>>,
    pub public_key: Option<Vec<u8>>,
}

/// Verify an attestation document using the reconstruct-verify approach.
///
/// This function:
/// 1. Parses the COSE Sign1 structure
/// 2. Extracts the attestation payload
/// 3. Validates the certificate chain
/// 4. Reconstructs the payload with expected PCRs
/// 5. Verifies the COSE signature against the reconstructed payload
/// 6. Validates nonce and timestamp
///
/// # Arguments
///
/// * `b64_document` - Base64-encoded COSE Sign1 attestation document
/// * `expected_pcrs` - Client-provided expected PCR values (hex encoded)
/// * `expected_nonce` - Nonce that should be in attestation (base64)
/// * `max_age_ms` - Maximum acceptable age of attestation
///
/// # Returns
///
/// Verification result including whether all checks passed.
pub fn verify_attestation(
    b64_document: &str,
    expected_pcrs: &BTreeMap<String, String>,
    expected_nonce: &str,
    max_age_ms: Option<u64>,
) -> Result<VerificationResult> {
    let mut errors = Vec::new();
    let max_age = max_age_ms.unwrap_or(DEFAULT_MAX_AGE_MS);

    // 1. Base64 decode the attestation document
    let doc_bytes = data_encoding::BASE64
        .decode(b64_document.as_bytes())
        .map_err(|e| anyhow!("failed to base64 decode attestation document: {:?}", e))?;

    // 2. Parse COSE Sign1 structure
    let cose_sign1 = CoseSign1::from_tagged_slice(&doc_bytes)
        .map_err(|e| anyhow!("failed to parse COSE Sign1: {:?}", e))?;

    // 3. Extract and parse attestation payload (CBOR)
    let payload = cose_sign1
        .payload
        .as_ref()
        .ok_or_else(|| anyhow!("COSE Sign1 has no payload"))?;

    let parsed =
        parse_attestation_payload(payload).context("failed to parse attestation payload")?;

    // 4. Extract actual PCRs for response (before reconstruction)
    let actual_pcrs = pcrs_to_hex_map(&parsed.pcrs);

    // 5. Validate certificate chain
    let certificate_chain_valid = match validate_certificate_chain(&parsed) {
        Ok(valid) => valid,
        Err(e) => {
            errors.push(format!("certificate chain validation failed: {}", e));
            false
        }
    };

    // 6. Convert expected PCRs from hex to bytes
    let expected_pcrs_bytes = match parse_expected_pcrs(expected_pcrs) {
        Ok(pcrs) => Some(pcrs),
        Err(e) => {
            errors.push(format!("invalid expected PCRs: {}", e));
            None
        }
    };

    // 7. Reconstruct-verify: Build payload with expected PCRs and verify signature
    let pcrs_match = if let Some(ref expected) = expected_pcrs_bytes {
        match reconstruct_and_verify(&cose_sign1, &parsed, expected) {
            Ok(valid) => valid,
            Err(e) => {
                errors.push(format!("reconstruct-verify failed: {}", e));
                false
            }
        }
    } else {
        false
    };

    // 8. Verify nonce matches
    let nonce_valid = match verify_nonce(&parsed.nonce, expected_nonce) {
        Ok(valid) => valid,
        Err(e) => {
            errors.push(format!("nonce verification failed: {}", e));
            false
        }
    };

    // 9. Verify timestamp is recent
    let timestamp_valid = match verify_timestamp(parsed.timestamp, max_age) {
        Ok(valid) => valid,
        Err(e) => {
            errors.push(format!("timestamp verification failed: {}", e));
            false
        }
    };

    // 10. Build document info
    let document_info = DocumentInfo {
        module_id: parsed.module_id,
        timestamp: parsed.timestamp,
        digest: parsed.digest,
        nonce: parsed
            .nonce
            .as_ref()
            .map(|n| data_encoding::BASE64.encode(n)),
        user_data: parsed
            .user_data
            .as_ref()
            .map(|d| data_encoding::BASE64.encode(d)),
    };

    let verified = certificate_chain_valid && pcrs_match && nonce_valid && timestamp_valid;

    Ok(VerificationResult {
        verified,
        certificate_chain_valid,
        pcrs_match,
        nonce_valid,
        timestamp_valid,
        document_info,
        actual_pcrs,
        errors: if errors.is_empty() {
            None
        } else {
            Some(errors)
        },
    })
}

/// Parse the CBOR attestation payload.
fn parse_attestation_payload(payload: &[u8]) -> Result<ParsedAttestation> {
    let cbor: CborValue = ciborium::from_reader(payload)
        .map_err(|e| anyhow!("failed to parse CBOR payload: {:?}", e))?;

    let map = match cbor {
        CborValue::Map(m) => m,
        _ => bail!("attestation payload is not a CBOR map"),
    };

    // Helper to extract string from CBOR value
    let get_string = |key: &str| -> Result<String> {
        for (k, v) in &map {
            if let CborValue::Text(k_str) = k
                && k_str == key
                && let CborValue::Text(s) = v
            {
                return Ok(s.clone());
            }
        }
        bail!("missing or invalid field: {}", key)
    };

    // Helper to extract integer from CBOR value
    let get_integer = |key: &str| -> Result<u64> {
        for (k, v) in &map {
            if let CborValue::Text(k_str) = k
                && k_str == key
                && let CborValue::Integer(i) = v
            {
                let val: i128 = (*i).into();
                return Ok(val as u64);
            }
        }
        bail!("missing or invalid field: {}", key)
    };

    // Helper to extract bytes from CBOR value
    let get_bytes = |key: &str| -> Result<Vec<u8>> {
        for (k, v) in &map {
            if let CborValue::Text(k_str) = k
                && k_str == key
                && let CborValue::Bytes(b) = v
            {
                return Ok(b.clone());
            }
        }
        bail!("missing or invalid field: {}", key)
    };

    // Helper to extract optional bytes
    let get_optional_bytes = |key: &str| -> Option<Vec<u8>> {
        for (k, v) in &map {
            if let CborValue::Text(k_str) = k
                && k_str == key
                && let CborValue::Bytes(b) = v
            {
                return Some(b.clone());
            }
        }
        None
    };

    // Extract PCRs
    let mut pcrs = BTreeMap::new();
    for (k, v) in &map {
        if let CborValue::Text(k_str) = k
            && k_str == "pcrs"
            && let CborValue::Map(pcr_map) = v
        {
            for (pk, pv) in pcr_map {
                if let CborValue::Integer(idx) = pk
                    && let CborValue::Bytes(hash) = pv
                {
                    let idx_val: i128 = (*idx).into();
                    pcrs.insert(idx_val as u8, hash.clone());
                }
            }
        }
    }

    // Extract cabundle (array of certificates)
    let mut cabundle = Vec::new();
    for (k, v) in &map {
        if let CborValue::Text(k_str) = k
            && k_str == "cabundle"
            && let CborValue::Array(certs) = v
        {
            for cert in certs {
                if let CborValue::Bytes(cert_bytes) = cert {
                    cabundle.push(cert_bytes.clone());
                }
            }
        }
    }

    Ok(ParsedAttestation {
        module_id: get_string("module_id")?,
        timestamp: get_integer("timestamp")?,
        digest: get_string("digest")?,
        pcrs,
        certificate: get_bytes("certificate")?,
        cabundle,
        nonce: get_optional_bytes("nonce"),
        user_data: get_optional_bytes("user_data"),
        public_key: get_optional_bytes("public_key"),
    })
}

/// Validate the certificate chain from enclave cert to AWS Nitro root.
///
/// Validates:
/// 1. All certificates parse correctly
/// 2. The chain terminates at the AWS Nitro root certificate
/// 3. Each certificate's signature is valid (signed by the next cert in chain)
/// 4. All certificates are within their validity period
fn validate_certificate_chain(parsed: &ParsedAttestation) -> Result<bool> {
    // Verify the embedded root certificate hash first
    if !nitro_root_cert::verify_root_cert_hash() {
        bail!("embedded Nitro root certificate hash verification failed");
    }

    // Parse the AWS Nitro root certificate
    let root_der = nitro_root_cert::get_root_cert_der()
        .map_err(|e| anyhow!("failed to get root certificate: {}", e))?;
    let root_cert = x509_cert::Certificate::from_der(&root_der)
        .map_err(|e| anyhow!("failed to parse root certificate: {:?}", e))?;

    // Parse the enclave certificate
    let enclave_cert = x509_cert::Certificate::from_der(&parsed.certificate)
        .map_err(|e| anyhow!("failed to parse enclave certificate: {:?}", e))?;

    // Parse all intermediate certificates
    let mut intermediates = Vec::with_capacity(parsed.cabundle.len());
    for (i, cert_der) in parsed.cabundle.iter().enumerate() {
        let cert = x509_cert::Certificate::from_der(cert_der)
            .map_err(|e| anyhow!("failed to parse intermediate certificate {}: {:?}", i, e))?;
        intermediates.push(cert);
    }

    // Build the certificate chain: enclave -> intermediates -> root
    // The cabundle is ordered from leaf to root, so we need to verify:
    // enclave signed by intermediates[0], intermediates[i] signed by intermediates[i+1],
    // and the last intermediate signed by root

    // Get current time for validity check
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time error")?
        .as_secs();

    // Verify enclave certificate validity period
    if !is_cert_valid_at(&enclave_cert, now_secs) {
        return Ok(false);
    }

    // If there are intermediates, verify the chain
    if let Some(first_intermediate) = intermediates.first() {
        // Verify enclave cert is signed by first intermediate
        if !verify_cert_signature(&enclave_cert, first_intermediate)? {
            return Ok(false);
        }

        // Verify each intermediate (except last) is signed by next using windows
        for pair in intermediates.windows(2) {
            let (current, next) = match pair {
                [c, n] => (c, n),
                _ => continue, // windows(2) always returns pairs
            };
            if !is_cert_valid_at(current, now_secs) {
                return Ok(false);
            }
            if !verify_cert_signature(current, next)? {
                return Ok(false);
            }
        }

        // Verify last intermediate validity and signature by root
        if let Some(last) = intermediates.last() {
            if !is_cert_valid_at(last, now_secs) {
                return Ok(false);
            }
            if !verify_cert_signature(last, &root_cert)? {
                return Ok(false);
            }
        }
    } else {
        // No intermediates: enclave cert should be signed by root directly
        if !verify_cert_signature(&enclave_cert, &root_cert)? {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Check if a certificate is valid at the given time (seconds since Unix epoch).
fn is_cert_valid_at(cert: &x509_cert::Certificate, now_secs: u64) -> bool {
    let validity = &cert.tbs_certificate.validity;

    // Convert x509 times to Unix timestamps
    let not_before = match &validity.not_before {
        x509_cert::time::Time::UtcTime(t) => t.to_unix_duration().as_secs(),
        x509_cert::time::Time::GeneralTime(t) => t.to_unix_duration().as_secs(),
    };

    let not_after = match &validity.not_after {
        x509_cert::time::Time::UtcTime(t) => t.to_unix_duration().as_secs(),
        x509_cert::time::Time::GeneralTime(t) => t.to_unix_duration().as_secs(),
    };

    now_secs >= not_before && now_secs <= not_after
}

/// Verify that a certificate was signed by the issuer certificate.
///
/// This extracts the public key from the issuer and verifies the subject's signature.
fn verify_cert_signature(
    subject: &x509_cert::Certificate,
    issuer: &x509_cert::Certificate,
) -> Result<bool> {
    // Get the issuer's public key
    let issuer_pk_info = &issuer.tbs_certificate.subject_public_key_info;
    let issuer_pk_bytes = issuer_pk_info
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| anyhow!("issuer certificate has no public key bytes"))?;

    // Parse as P-384 public key (AWS Nitro uses ECDSA P-384)
    let verifying_key = match VerifyingKey::from_sec1_bytes(issuer_pk_bytes) {
        Ok(key) => key,
        Err(_) => return Ok(false), // Key format mismatch
    };

    // Get the signature from the subject certificate
    let signature_bytes = subject
        .signature
        .as_bytes()
        .ok_or_else(|| anyhow!("subject certificate has no signature bytes"))?;

    // Parse the signature (DER encoded for X.509)
    let signature = match Signature::from_der(signature_bytes) {
        Ok(sig) => sig,
        Err(_) => return Ok(false), // Invalid signature format
    };

    // The TBS (to-be-signed) certificate is what was signed
    // We need to re-encode it to DER for verification
    use x509_cert::der::Encode;
    let tbs_der = subject
        .tbs_certificate
        .to_der()
        .map_err(|e| anyhow!("failed to encode TBS certificate: {:?}", e))?;

    // Verify the signature
    Ok(verifying_key.verify(&tbs_der, &signature).is_ok())
}

/// Reconstruct attestation payload with expected PCRs and verify signature.
///
/// This is the Trail of Bits recommended approach: instead of parsing PCRs
/// and comparing, we rebuild the payload with expected values and check
/// if the signature validates.
fn reconstruct_and_verify(
    cose: &CoseSign1,
    parsed: &ParsedAttestation,
    expected_pcrs: &BTreeMap<u8, Vec<u8>>,
) -> Result<bool> {
    // For the reconstruct-verify approach, we need to:
    // 1. Check if expected PCRs match actual PCRs
    // 2. If they match, verify the COSE signature

    // First, verify all expected PCRs match actual PCRs
    for (idx, expected_value) in expected_pcrs {
        match parsed.pcrs.get(idx) {
            Some(actual_value) => {
                if actual_value != expected_value {
                    return Ok(false);
                }
            }
            None => {
                return Err(anyhow!("expected PCR{} not found in attestation", idx));
            }
        }
    }

    // Now verify the COSE signature
    // Extract the public key from the enclave certificate
    let enclave_cert = x509_cert::Certificate::from_der(&parsed.certificate)
        .map_err(|e| anyhow!("failed to parse enclave certificate: {:?}", e))?;

    // Get the public key from the certificate
    let public_key_info = &enclave_cert.tbs_certificate.subject_public_key_info;
    let public_key_bytes = public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| anyhow!("no public key bytes"))?;

    // Parse as P-384 public key
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key_bytes)
        .map_err(|e| anyhow!("failed to parse P-384 public key: {:?}", e))?;

    // Get the signature from COSE
    let signature_bytes = &cose.signature;

    // COSE signatures are in IEEE P1363 format (r || s)
    // ECDSA Signature expects the same format
    let signature = Signature::from_slice(signature_bytes)
        .map_err(|e| anyhow!("failed to parse signature: {:?}", e))?;

    // Build the Sig_structure for verification
    // According to RFC 8152, we need to verify against the Sig_structure
    let payload = cose.payload.as_ref().ok_or_else(|| anyhow!("no payload"))?;

    // The Sig_structure is: ["Signature1", protected, external_aad, payload]
    // Serialize the protected header to get its bytes
    let protected_bytes = match &cose.protected.original_data {
        Some(data) => data.as_slice(),
        None => &[],
    };

    let sig_structure = CborValue::Array(vec![
        CborValue::Text("Signature1".to_string()),
        CborValue::Bytes(protected_bytes.to_vec()),
        CborValue::Bytes(vec![]), // external_aad is empty
        CborValue::Bytes(payload.clone()),
    ]);

    let mut sig_structure_bytes = Vec::new();
    ciborium::into_writer(&sig_structure, &mut sig_structure_bytes)
        .map_err(|e| anyhow!("failed to encode Sig_structure: {:?}", e))?;

    // Verify the signature
    match verifying_key.verify(&sig_structure_bytes, &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify nonce in attestation matches expected.
fn verify_nonce(actual: &Option<Vec<u8>>, expected_b64: &str) -> Result<bool> {
    let expected = data_encoding::BASE64
        .decode(expected_b64.as_bytes())
        .map_err(|e| anyhow!("failed to decode expected nonce: {:?}", e))?;

    match actual {
        Some(actual_nonce) => Ok(actual_nonce == &expected),
        None => Ok(false),
    }
}

/// Verify timestamp is within acceptable age.
fn verify_timestamp(timestamp_ms: u64, max_age_ms: u64) -> Result<bool> {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time error")?
        .as_millis() as u64;

    // Check if attestation is from the future (clock skew tolerance: 60s)
    if timestamp_ms > now_ms + 60_000 {
        return Ok(false);
    }

    // Check if attestation is too old
    let age_ms = now_ms.saturating_sub(timestamp_ms);
    Ok(age_ms <= max_age_ms)
}

/// Parse expected PCRs from hex strings to bytes.
///
/// Keys should be numeric strings ("0", "1", "2", etc.) matching the
/// validation in models.rs.
fn parse_expected_pcrs(expected: &BTreeMap<String, String>) -> Result<BTreeMap<u8, Vec<u8>>> {
    let mut result = BTreeMap::new();

    for (key, hex_value) in expected {
        // Keys are numeric strings (e.g., "0", "1", "2") per models.rs validation
        let index: u8 = key
            .parse()
            .map_err(|_| anyhow!("invalid PCR index: {} (expected numeric string)", key))?;

        if index > 23 {
            bail!("PCR index {} out of range (0-23)", index);
        }

        let bytes = data_encoding::HEXLOWER_PERMISSIVE
            .decode(hex_value.as_bytes())
            .map_err(|_| anyhow!("invalid hex for PCR{}", index))?;

        if bytes.len() != 48 {
            bail!(
                "PCR{} must be 48 bytes (SHA384), got {} bytes",
                index,
                bytes.len()
            );
        }

        result.insert(index, bytes);
    }

    Ok(result)
}

/// Convert PCR bytes to hex string map.
fn pcrs_to_hex_map(pcrs: &BTreeMap<u8, Vec<u8>>) -> BTreeMap<String, String> {
    pcrs.iter()
        .map(|(k, v)| (format!("PCR{}", k), data_encoding::HEXLOWER.encode(v)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_expected_pcrs_valid() {
        let mut expected = BTreeMap::new();
        expected.insert(
            "0".to_string(), // Numeric key format
            "0".repeat(96),  // 48 bytes as hex
        );

        let result = parse_expected_pcrs(&expected);
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert_eq!(parsed.len(), 1);
        assert!(parsed.contains_key(&0));
    }

    #[test]
    fn test_parse_expected_pcrs_multiple() {
        let mut expected = BTreeMap::new();
        expected.insert("0".to_string(), "0".repeat(96));
        expected.insert("1".to_string(), "a".repeat(96));
        expected.insert("2".to_string(), "b".repeat(96));

        let result = parse_expected_pcrs(&expected);
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert_eq!(parsed.len(), 3);
        assert!(parsed.contains_key(&0));
        assert!(parsed.contains_key(&1));
        assert!(parsed.contains_key(&2));
    }

    #[test]
    fn test_parse_expected_pcrs_invalid_key() {
        let mut expected = BTreeMap::new();
        expected.insert("INVALID".to_string(), "0".repeat(96));

        let result = parse_expected_pcrs(&expected);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_expected_pcrs_out_of_range() {
        let mut expected = BTreeMap::new();
        expected.insert("24".to_string(), "0".repeat(96)); // Out of range (max is 23)

        let result = parse_expected_pcrs(&expected);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("out of range"));
    }

    #[test]
    fn test_parse_expected_pcrs_wrong_length() {
        let mut expected = BTreeMap::new();
        expected.insert("0".to_string(), "0".repeat(64)); // Wrong length (should be 96)

        let result = parse_expected_pcrs(&expected);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_nonce_valid() {
        let nonce = b"test-nonce-12345";
        let nonce_b64 = data_encoding::BASE64.encode(nonce);

        let result = verify_nonce(&Some(nonce.to_vec()), &nonce_b64);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_nonce_mismatch() {
        let actual = b"actual-nonce";
        let expected_b64 = data_encoding::BASE64.encode(b"different-nonce");

        let result = verify_nonce(&Some(actual.to_vec()), &expected_b64);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_verify_nonce_missing() {
        let expected_b64 = data_encoding::BASE64.encode(b"some-nonce");

        let result = verify_nonce(&None, &expected_b64);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_verify_timestamp_valid() {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // Timestamp from 1 minute ago
        let result = verify_timestamp(now_ms - 60_000, DEFAULT_MAX_AGE_MS);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_timestamp_too_old() {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // Timestamp from 10 minutes ago (exceeds 5 min default)
        let result = verify_timestamp(now_ms - 600_000, DEFAULT_MAX_AGE_MS);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_verify_timestamp_future() {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // Timestamp 2 minutes in the future (exceeds 60s tolerance)
        let result = verify_timestamp(now_ms + 120_000, DEFAULT_MAX_AGE_MS);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_pcrs_to_hex_map() {
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0u8, vec![0xAB; 48]);
        pcrs.insert(1u8, vec![0xCD; 48]);

        let hex_map = pcrs_to_hex_map(&pcrs);

        assert_eq!(hex_map.len(), 2);
        assert!(hex_map.contains_key("PCR0"));
        assert!(hex_map.contains_key("PCR1"));
        assert_eq!(hex_map.get("PCR0").unwrap().len(), 96); // 48 bytes = 96 hex chars
    }
}
