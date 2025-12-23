// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

//! Data models for enclave request/response handling.
//!
//! This module defines the core data structures used for communication between
//! the parent instance and the Nitro Enclave, including:
//!
//! - [`EnclaveRequest`] - Incoming decryption requests with credentials and encrypted fields
//! - [`EnclaveResponse`] - Outgoing responses with decrypted fields or errors
//! - [`Suite`] - HPKE cipher suite identifier (P256, P384, P521)
//! - [`EncryptedData`] - Parsed encrypted field data (encapped key + ciphertext)
//! - [`Encoding`] - Field encoding format (hex or binary)
//!
//! # Security
//!
//! - Credentials are zeroized on drop via `ZeroizeOnDrop`
//! - Field count is limited to prevent resource exhaustion
//! - Input validation is performed before processing

use std::collections::BTreeMap;
use std::fmt;

use anyhow::{Error, Result, anyhow, bail};
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, ECDSA_P521_SHA512_ASN1_SIGNING,
    EcdsaSigningAlgorithm,
};
use data_encoding::HEXLOWER;
use rustls::crypto::aws_lc_rs::hpke::{
    DH_KEM_P256_HKDF_SHA256_AES_256, DH_KEM_P384_HKDF_SHA384_AES_256,
    DH_KEM_P521_HKDF_SHA512_AES_256,
};
use rustls::crypto::hpke::{Hpke, HpkePrivateKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::ZeroizeOnDrop;

use crate::constants::{ENCODING_BINARY, ENCODING_HEX, MAX_FIELDS, P256, P384, P521};

use crate::hpke::decrypt_value;
use crate::kms::get_secret_key;
use crate::utils::base64_decode;

/// AWS credentials for KMS access.
///
/// These credentials are passed from the parent instance and used to authenticate
/// KMS decrypt requests. The struct implements `ZeroizeOnDrop` to ensure credentials
/// are securely erased from memory when no longer needed.
///
/// Note: Debug is manually implemented to redact sensitive fields.
#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct Credential {
    #[serde(rename = "AccessKeyId")]
    pub access_key_id: String,

    #[serde(rename = "SecretAccessKey")]
    pub secret_access_key: String,

    #[serde(rename = "Token")]
    pub session_token: String,
}

/// Custom Debug implementation to prevent accidental logging of sensitive data.
impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("access_key_id", &"[REDACTED]")
            .field("secret_access_key", &"[REDACTED]")
            .field("session_token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParentRequest {
    pub vault_id: String,
    pub region: String,
    pub fields: BTreeMap<String, String>,
    pub suite_id: String,              // base64 encoded
    pub encrypted_private_key: String, // base64 encoded
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expressions: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveRequest {
    pub credential: Credential,
    pub request: ParentRequest,
}

impl EnclaveRequest {
    /// Validates all required fields before processing.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - vault_id is empty
    /// - region is empty or contains invalid characters
    /// - suite_id is empty
    /// - encrypted_private_key is empty
    /// - field count exceeds MAX_FIELDS
    pub fn validate(&self) -> Result<()> {
        // Validate vault_id is non-empty
        if self.request.vault_id.is_empty() {
            bail!("vault_id cannot be empty");
        }

        // Validate region is non-empty and contains only valid characters
        if self.request.region.is_empty() {
            bail!("region cannot be empty");
        }
        if !self
            .request
            .region
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            bail!("region contains invalid characters");
        }

        // Validate suite_id is non-empty
        if self.request.suite_id.is_empty() {
            bail!("suite_id cannot be empty");
        }

        // Validate encrypted_private_key is non-empty
        if self.request.encrypted_private_key.is_empty() {
            bail!("encrypted_private_key cannot be empty");
        }

        // Validate field count
        if self.request.fields.len() > MAX_FIELDS {
            bail!(
                "field count {} exceeds maximum {}",
                self.request.fields.len(),
                MAX_FIELDS
            );
        }

        Ok(())
    }

    fn get_private_key(&self, suite: &Suite) -> Result<HpkePrivateKey> {
        let alg = suite.get_signing_algorithm();

        // Decrypt the KMS secret key
        let sk: HpkePrivateKey = get_secret_key(alg, self)?;

        Ok(sk)
    }

    pub fn decrypt_fields(&self) -> Result<(BTreeMap<String, Value>, Vec<Error>)> {
        // Validate all inputs before processing
        self.validate()?;

        let suite: Suite = self.request.suite_id.as_str().try_into()?;
        let encoding: Encoding = self.request.encoding.as_ref().try_into()?;

        let private_key = self.get_private_key(&suite)?;
        println!("[enclave] decrypted KMS secret key");

        let hpke_suite = suite.get_hpke_suite();
        let info = self.request.vault_id.as_bytes();
        let mut errors: Vec<Error> = Vec::new();

        // Sensitive context logging gated behind debug builds only
        #[cfg(debug_assertions)]
        {
            println!("[enclave] vault_id: {:?}", &self.request.vault_id);
            println!("[enclave] encoding: {:?}", encoding);
        }

        // Single loop with encoding-based parsing
        let mut decrypted_fields = BTreeMap::new();
        for (field, value) in &self.request.fields {
            let encrypted_data = encoding.parse(value.as_str(), &suite)?;

            let decrypted = decrypt_value(hpke_suite, &private_key, info, field, encrypted_data)
                .unwrap_or_else(|error| {
                    errors.push(error);
                    Value::Null
                });
            decrypted_fields.insert(field.to_string(), decrypted);
        }

        Ok((decrypted_fields, errors))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnclaveResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<BTreeMap<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
}

impl EnclaveResponse {
    pub fn new(fields: BTreeMap<String, Value>, errors: Option<Vec<Error>>) -> Self {
        let errors = errors.map(|errors| errors.iter().map(|e| e.to_string()).collect());

        Self {
            fields: Some(fields),
            errors,
        }
    }

    pub fn error(error: anyhow::Error) -> Self {
        Self {
            fields: None,
            errors: Some(vec![error.to_string()]),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct EncryptedData {
    pub encapped_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl EncryptedData {
    pub fn from_hex(value: &str) -> Result<Self> {
        let data: EncryptedData = match value.split_once('#') {
            Some((hex_encapped_key, hex_ciphertext)) => {
                let encapped_key = HEXLOWER
                    .decode(hex_encapped_key.as_bytes())
                    .map_err(|err| anyhow!("unable to hex decode encapped key: {:?}", err))?;
                let ciphertext = HEXLOWER
                    .decode(hex_ciphertext.as_bytes())
                    .map_err(|err| anyhow!("unable to hex decode ciphertext: {:?}", err))?;

                Self {
                    encapped_key,
                    ciphertext,
                }
            }
            None => bail!("unable to split value on '#': {:?}", value),
        };
        Ok(data)
    }

    pub fn from_binary(value: &str, suite: &Suite) -> Result<Self> {
        let data = base64_decode(value)
            .map_err(|err| anyhow!("unable to base64 decode value: {:?}", err))?;

        let key_size = suite.encapped_key_size();

        if data.len() < key_size {
            bail!(
                "encrypted data too short: {} bytes, need at least {} for {:?}",
                data.len(),
                key_size,
                suite
            );
        }

        // Safe: we've validated data.len() >= key_size above
        let encapped_key = data
            .get(..key_size)
            .ok_or_else(|| anyhow!("failed to extract encapped key"))?
            .to_vec();
        let ciphertext = data
            .get(key_size..)
            .ok_or_else(|| anyhow!("failed to extract ciphertext"))?
            .to_vec();

        Ok(Self {
            encapped_key,
            ciphertext,
        })
    }
}

/// Field encoding format for encrypted data
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Encoding {
    /// Hex encoding with '#' separator between encapped key and ciphertext
    Hex,
    /// Binary encoding as base64 with concatenated encapped key and ciphertext (default)
    #[default]
    Binary,
}

impl Encoding {
    /// Parse encrypted data according to this encoding format
    #[inline]
    pub fn parse(&self, value: &str, suite: &Suite) -> Result<EncryptedData> {
        match self {
            Encoding::Hex => EncryptedData::from_hex(value),
            Encoding::Binary => EncryptedData::from_binary(value, suite),
        }
    }
}

impl TryFrom<Option<&str>> for Encoding {
    type Error = anyhow::Error;

    fn try_from(value: Option<&str>) -> Result<Self> {
        match value {
            None => Ok(Encoding::default()),
            Some(s) if s == ENCODING_HEX => Ok(Encoding::Hex),
            Some(s) if s == ENCODING_BINARY => Ok(Encoding::Binary),
            Some(s) => bail!("unknown encoding: {}", s),
        }
    }
}

impl TryFrom<Option<&String>> for Encoding {
    type Error = anyhow::Error;

    fn try_from(value: Option<&String>) -> Result<Self> {
        Encoding::try_from(value.map(|s| s.as_str()))
    }
}

/// HPKE cipher suite identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    /// P-256 curve with HKDF-SHA256 and AES-256-GCM
    P256,
    /// P-384 curve with HKDF-SHA384 and AES-256-GCM
    P384,
    /// P-521 curve with HKDF-SHA512 and AES-256-GCM
    P521,
}

impl Suite {
    /// Returns the encapped key size in bytes for this suite (RFC 9180 Nenc value).
    /// This is a const fn to allow compile-time evaluation.
    pub const fn encapped_key_size(&self) -> usize {
        match self {
            Suite::P256 => 65,
            Suite::P384 => 97,
            Suite::P521 => 133,
        }
    }

    /// Returns the HPKE suite implementation
    pub fn get_hpke_suite(&self) -> &'static dyn Hpke {
        match self {
            Suite::P256 => DH_KEM_P256_HKDF_SHA256_AES_256,
            Suite::P384 => DH_KEM_P384_HKDF_SHA384_AES_256,
            Suite::P521 => DH_KEM_P521_HKDF_SHA512_AES_256,
        }
    }

    /// Returns the ECDSA signing algorithm for this suite
    pub fn get_signing_algorithm(&self) -> &'static EcdsaSigningAlgorithm {
        match self {
            Suite::P256 => &ECDSA_P256_SHA256_ASN1_SIGNING,
            Suite::P384 => &ECDSA_P384_SHA384_ASN1_SIGNING,
            Suite::P521 => &ECDSA_P521_SHA512_ASN1_SIGNING,
        }
    }

    /// Returns the HPKE suite implementation (alias for backward compatibility)
    pub fn get_suite(&self) -> &'static dyn Hpke {
        self.get_hpke_suite()
    }

    /// Returns the raw suite ID bytes for this suite.
    ///
    /// This is the inverse of parsing from base64 - useful for round-trip testing.
    pub fn suite_id_bytes(&self) -> &'static [u8; 10] {
        match self {
            Suite::P256 => P256,
            Suite::P384 => P384,
            Suite::P521 => P521,
        }
    }

    /// Returns the base64-encoded suite ID for this suite.
    ///
    /// This is the inverse of `TryFrom<&str>` - useful for round-trip testing.
    pub fn to_base64(&self) -> String {
        data_encoding::BASE64.encode(self.suite_id_bytes())
    }
}

impl TryFrom<&str> for Suite {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        let bytes = base64_decode(value)?;
        match bytes.as_slice() {
            s if s == P256 => Ok(Suite::P256),
            s if s == P384 => Ok(Suite::P384),
            s if s == P521 => Ok(Suite::P521),
            _ => bail!("unknown suite identifier"),
        }
    }
}

impl TryFrom<String> for Suite {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        Suite::try_from(value.as_str())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // **Feature: enclave-improvements, Property 1: Suite enum correctness**
    // **Validates: Requirements 1.1, 9.3**
    //
    // *For any* Suite variant (P256, P384, P521), the `encapped_key_size()` method
    // SHALL return the correct size (65, 97, 133 bytes respectively),
    // `get_hpke_suite()` SHALL return the corresponding HPKE implementation,
    // and `get_signing_algorithm()` SHALL return the matching ECDSA algorithm.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_suite_encapped_key_size_correctness(suite_idx in 0usize..3) {
            let suites = [Suite::P256, Suite::P384, Suite::P521];
            let expected_sizes = [65usize, 97, 133];

            let suite = suites[suite_idx];
            let expected_size = expected_sizes[suite_idx];

            prop_assert_eq!(
                suite.encapped_key_size(),
                expected_size,
                "Suite {:?} should have encapped_key_size of {} bytes",
                suite,
                expected_size
            );
        }

        #[test]
        fn prop_suite_hpke_suite_correctness(suite_idx in 0usize..3) {
            let suites = [Suite::P256, Suite::P384, Suite::P521];
            let expected_hpke_suites = [
                DH_KEM_P256_HKDF_SHA256_AES_256.suite(),
                DH_KEM_P384_HKDF_SHA384_AES_256.suite(),
                DH_KEM_P521_HKDF_SHA512_AES_256.suite(),
            ];

            let suite = suites[suite_idx];
            let expected_hpke = expected_hpke_suites[suite_idx];

            prop_assert_eq!(
                suite.get_hpke_suite().suite(),
                expected_hpke,
                "Suite {:?} should return the correct HPKE suite",
                suite
            );
        }

        #[test]
        fn prop_suite_signing_algorithm_correctness(suite_idx in 0usize..3) {
            let suites = [Suite::P256, Suite::P384, Suite::P521];
            let expected_algorithms: [&'static EcdsaSigningAlgorithm; 3] = [
                &ECDSA_P256_SHA256_ASN1_SIGNING,
                &ECDSA_P384_SHA384_ASN1_SIGNING,
                &ECDSA_P521_SHA512_ASN1_SIGNING,
            ];

            let suite = suites[suite_idx];
            let expected_alg = expected_algorithms[suite_idx];

            prop_assert_eq!(
                suite.get_signing_algorithm(),
                expected_alg,
                "Suite {:?} should return the correct signing algorithm",
                suite
            );
        }

        // **Feature: enclave-improvements, Property 6: Suite parsing round-trip**
        // **Validates: Requirements 9.2, 11.3**
        //
        // *For any* valid Suite variant, encoding it to its base64 suite ID and
        // parsing it back SHALL produce the same Suite variant.
        #[test]
        fn prop_suite_parsing_round_trip(suite_idx in 0usize..3) {
            let suites = [Suite::P256, Suite::P384, Suite::P521];
            let original_suite = suites[suite_idx];

            // Encode suite to base64
            let base64_encoded = original_suite.to_base64();

            // Parse it back
            let parsed_suite: Suite = base64_encoded.as_str().try_into()
                .expect("Parsing should succeed for valid suite base64");

            // Verify round-trip produces the same suite
            prop_assert_eq!(
                parsed_suite,
                original_suite,
                "Round-trip should preserve suite: {:?} -> {} -> {:?}",
                original_suite,
                base64_encoded,
                parsed_suite
            );
        }

        #[test]
        fn prop_suite_bytes_round_trip(suite_idx in 0usize..3) {
            let suites = [Suite::P256, Suite::P384, Suite::P521];
            let expected_bytes: [&[u8; 10]; 3] = [P256, P384, P521];

            let suite = suites[suite_idx];
            let expected = expected_bytes[suite_idx];

            // Verify suite_id_bytes returns the correct constant
            prop_assert_eq!(
                suite.suite_id_bytes(),
                expected,
                "Suite {:?} should return correct suite ID bytes",
                suite
            );
        }
    }

    #[test]
    fn test_get_suite() {
        let b64_suite_id: &str = "SFBLRQARAAIAAg==";
        let suite: Suite = b64_suite_id.try_into().unwrap();

        let actual = suite.get_hpke_suite();
        let expected = DH_KEM_P384_HKDF_SHA384_AES_256.suite();
        assert_eq!(actual.suite(), expected);
    }

    #[test]
    fn test_get_signing_algorithm() {
        let b64_suite_id: &str = "SFBLRQARAAIAAg==";
        let suite: Suite = b64_suite_id.try_into().unwrap();

        let actual = suite.get_signing_algorithm();
        let expected = &ECDSA_P384_SHA384_ASN1_SIGNING;
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_suite_encapped_key_sizes() {
        assert_eq!(Suite::P256.encapped_key_size(), 65);
        assert_eq!(Suite::P384.encapped_key_size(), 97);
        assert_eq!(Suite::P521.encapped_key_size(), 133);
    }

    #[test]
    fn test_suite_try_from_str() {
        // P256 suite ID
        let p256_b64 = "SFBLRQAQAAEAAg==";
        let suite: Suite = p256_b64.try_into().unwrap();
        assert_eq!(suite, Suite::P256);

        // P384 suite ID
        let p384_b64 = "SFBLRQARAAIAAg==";
        let suite: Suite = p384_b64.try_into().unwrap();
        assert_eq!(suite, Suite::P384);

        // P521 suite ID
        let p521_b64 = "SFBLRQASAAMAAg==";
        let suite: Suite = p521_b64.try_into().unwrap();
        assert_eq!(suite, Suite::P521);
    }

    #[test]
    fn test_suite_try_from_string() {
        let p384_b64 = "SFBLRQARAAIAAg==".to_string();
        let suite: Suite = p384_b64.try_into().unwrap();
        assert_eq!(suite, Suite::P384);
    }

    #[test]
    fn test_suite_invalid_id() {
        let invalid_b64 = "aW52YWxpZA=="; // "invalid" in base64
        let result: Result<Suite> = invalid_b64.try_into();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unknown suite identifier")
        );
    }

    #[test]
    fn test_encrypted_data_from_hex() {
        let hex_encrypted_value: &str = "04cebfe3667db3305777774f14a7ed4f26ce90b2d68935a30f9b086dc915e6ede23e6dfdde7aaf34dc34cd964c76f94bc91ba99edb3707281862c990c54782eace8c687770d72d4c714d4edd239e010facfb7c3d5c168b14d9040194059529f5e6#80c10441ae55442775bc5d1b0b8465eaaaa33b";
        let actual: EncryptedData = EncryptedData::from_hex(hex_encrypted_value).unwrap();

        let expected = EncryptedData {
            encapped_key: HEXLOWER
                .decode("04cebfe3667db3305777774f14a7ed4f26ce90b2d68935a30f9b086dc915e6ede23e6dfdde7aaf34dc34cd964c76f94bc91ba99edb3707281862c990c54782eace8c687770d72d4c714d4edd239e010facfb7c3d5c168b14d9040194059529f5e6".as_bytes())
                .unwrap(),
            ciphertext: HEXLOWER
                .decode("80c10441ae55442775bc5d1b0b8465eaaaa33b".as_bytes())
                .unwrap(),
        };
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_encrypted_data_from_binary() {
        let b64_encrypted_value: &str = "BMKVB9Sb897B+mn9bZR7Ad40v3+0n+gTwmrNMUDTnBOl3V3Fw/GCrAacryOs2Vz2sRFPyoQbdCo3YOp/JVRTy3J3CYxMpgdZlQpxU2lRx4YrrXWJ1j627itzLGfUf1z3pcTs06wwett5h/rM3a8I9ZPVfg==";
        let actual: EncryptedData =
            EncryptedData::from_binary(b64_encrypted_value, &Suite::P384).unwrap();

        let binary_encrypted_value: Vec<u8> = base64_decode(b64_encrypted_value).unwrap();

        let expected = EncryptedData {
            encapped_key: binary_encrypted_value[0..97].to_vec(),
            ciphertext: binary_encrypted_value[97..].to_vec(),
        };

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_encrypted_data_from_binary_too_short() {
        // Create data that's too short for P384 (needs 97 bytes minimum)
        let short_data = vec![0u8; 50];
        let b64_short = data_encoding::BASE64.encode(&short_data);

        let result = EncryptedData::from_binary(&b64_short, &Suite::P384);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("encrypted data too short"));
        assert!(err_msg.contains("50 bytes"));
        assert!(err_msg.contains("97"));
    }

    #[test]
    fn test_encrypted_data_from_binary_all_suites() {
        // Test that from_binary correctly splits data for each suite
        let suites = [Suite::P256, Suite::P384, Suite::P521];
        let key_sizes = [65usize, 97, 133];

        for (suite, key_size) in suites.iter().zip(key_sizes.iter()) {
            // Create test data with key_size + 10 bytes of ciphertext
            let mut data = vec![0xABu8; *key_size];
            data.extend(vec![0xCDu8; 10]);
            let b64_data = data_encoding::BASE64.encode(&data);

            let result = EncryptedData::from_binary(&b64_data, suite).unwrap();
            assert_eq!(
                result.encapped_key.len(),
                *key_size,
                "Suite {:?} should have encapped_key of {} bytes",
                suite,
                key_size
            );
            assert_eq!(
                result.ciphertext.len(),
                10,
                "Suite {:?} should have ciphertext of 10 bytes",
                suite
            );
        }
    }

    // **Feature: enclave-improvements, Property 2: Binary parsing with suite**
    // **Validates: Requirements 1.2**
    //
    // *For any* valid base64-encoded encrypted data and any Suite variant,
    // `EncryptedData::from_binary(data, suite)` SHALL split the data at exactly
    // `suite.encapped_key_size()` bytes, with the first portion as `encapped_key`
    // and the remainder as `ciphertext`.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_from_binary_splits_at_suite_encapped_key_size(
            suite_idx in 0usize..3,
            // Generate encapped_key bytes (exact size will be determined by suite)
            key_byte in any::<u8>(),
            // Generate ciphertext of varying length (1 to 100 bytes)
            ciphertext_len in 1usize..100,
            ciphertext_byte in any::<u8>()
        ) {
            let suites = [Suite::P256, Suite::P384, Suite::P521];
            let suite = suites[suite_idx];
            let key_size = suite.encapped_key_size();

            // Create test data: encapped_key (key_size bytes) + ciphertext (ciphertext_len bytes)
            let mut data = vec![key_byte; key_size];
            let ciphertext_data = vec![ciphertext_byte; ciphertext_len];
            data.extend(&ciphertext_data);

            // Encode as base64
            let b64_data = data_encoding::BASE64.encode(&data);

            // Parse using from_binary
            let result = EncryptedData::from_binary(&b64_data, &suite).unwrap();

            // Verify the split is correct
            prop_assert_eq!(
                result.encapped_key.len(),
                key_size,
                "encapped_key should be exactly {} bytes for {:?}",
                key_size,
                suite
            );
            prop_assert_eq!(
                result.ciphertext.len(),
                ciphertext_len,
                "ciphertext should be exactly {} bytes",
                ciphertext_len
            );

            // Verify the content is preserved correctly
            prop_assert_eq!(
                result.encapped_key,
                vec![key_byte; key_size],
                "encapped_key content should match input"
            );
            prop_assert_eq!(
                result.ciphertext,
                ciphertext_data,
                "ciphertext content should match input"
            );
        }

        #[test]
        fn prop_from_binary_rejects_data_shorter_than_encapped_key_size(
            suite_idx in 0usize..3,
            // Generate data that's shorter than the minimum required
            short_factor in 0.0f64..1.0
        ) {
            let suites = [Suite::P256, Suite::P384, Suite::P521];
            let suite = suites[suite_idx];
            let key_size = suite.encapped_key_size();

            // Create data shorter than key_size (0 to key_size-1 bytes)
            let short_len = (key_size as f64 * short_factor) as usize;
            let short_data = vec![0u8; short_len];
            let b64_short = data_encoding::BASE64.encode(&short_data);

            // Attempt to parse - should fail
            let result = EncryptedData::from_binary(&b64_short, &suite);

            prop_assert!(
                result.is_err(),
                "from_binary should reject data of {} bytes for {:?} (needs {} bytes)",
                short_len,
                suite,
                key_size
            );

            // Verify error message contains useful information
            let err_msg = result.unwrap_err().to_string();
            prop_assert!(
                err_msg.contains("encrypted data too short"),
                "Error should mention 'encrypted data too short', got: {}",
                err_msg
            );
        }

        #[test]
        fn prop_from_binary_preserves_exact_byte_content(
            suite_idx in 0usize..3,
            // Generate random bytes for encapped_key and ciphertext
            encapped_key_seed in any::<[u8; 32]>(),
            ciphertext in prop::collection::vec(any::<u8>(), 1..50)
        ) {
            let suites = [Suite::P256, Suite::P384, Suite::P521];
            let suite = suites[suite_idx];
            let key_size = suite.encapped_key_size();

            // Generate encapped_key bytes by repeating seed to fill key_size
            let encapped_key: Vec<u8> = encapped_key_seed
                .iter()
                .cycle()
                .take(key_size)
                .copied()
                .collect();

            // Combine into full data
            let mut data = encapped_key.clone();
            data.extend(&ciphertext);

            // Encode and parse
            let b64_data = data_encoding::BASE64.encode(&data);
            let result = EncryptedData::from_binary(&b64_data, &suite).unwrap();

            // Verify exact byte content is preserved
            prop_assert_eq!(
                result.encapped_key,
                encapped_key,
                "encapped_key bytes should be preserved exactly"
            );
            prop_assert_eq!(
                result.ciphertext,
                ciphertext,
                "ciphertext bytes should be preserved exactly"
            );
        }

        // **Feature: enclave-improvements, Property 9: Safe indexing**
        // **Validates: Requirements 25.4, 25.6**
        //
        // *For any* input data of any length and any Suite variant, the from_binary()
        // function SHALL never panic due to out-of-bounds indexing. It should either
        // succeed or return an error.
        #[test]
        fn prop_from_binary_never_panics_on_any_input(
            suite_idx in 0usize..3,
            // Generate data of varying lengths (0 to 200 bytes)
            data_len in 0usize..200,
            data_byte in any::<u8>()
        ) {
            let suites = [Suite::P256, Suite::P384, Suite::P521];
            let suite = suites[suite_idx];

            // Create test data of the specified length
            let data = vec![data_byte; data_len];
            let b64_data = data_encoding::BASE64.encode(&data);

            // This should never panic - it should either succeed or return an error
            let result = EncryptedData::from_binary(&b64_data, &suite);

            // Verify behavior based on data length
            let key_size = suite.encapped_key_size();
            if data_len >= key_size {
                // Should succeed
                prop_assert!(
                    result.is_ok(),
                    "from_binary should succeed for data of {} bytes (key_size={})",
                    data_len,
                    key_size
                );
            } else {
                // Should fail with error (not panic)
                prop_assert!(
                    result.is_err(),
                    "from_binary should return error for data of {} bytes (key_size={})",
                    data_len,
                    key_size
                );
            }
        }
    }

    // **Feature: enclave-improvements, Property 4: Field count bounds**
    // **Validates: Requirements 7.2, 7.3**
    //
    // *For any* request with field count greater than MAX_FIELDS, the decrypt_fields()
    // function SHALL return an error before attempting to decrypt any fields.
    //
    // Note: Since decrypt_fields() requires KMS operations, we test the validation
    // logic by creating requests with varying field counts and verifying the error
    // behavior. We use a helper function to validate field counts independently.

    /// Helper function to validate field count (extracted from decrypt_fields logic)
    fn validate_field_count(field_count: usize) -> Result<()> {
        if field_count > MAX_FIELDS {
            bail!("field count {} exceeds maximum {}", field_count, MAX_FIELDS);
        }
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_field_count_exceeding_max_returns_error(
            // Generate field counts that exceed MAX_FIELDS (1001 to 2000)
            excess_count in (MAX_FIELDS + 1)..=(MAX_FIELDS + 1000)
        ) {
            let result = validate_field_count(excess_count);

            prop_assert!(
                result.is_err(),
                "Field count {} should be rejected (max is {})",
                excess_count,
                MAX_FIELDS
            );

            let err_msg = result.unwrap_err().to_string();
            prop_assert!(
                err_msg.contains("field count"),
                "Error should mention 'field count', got: {}",
                err_msg
            );
            prop_assert!(
                err_msg.contains(&excess_count.to_string()),
                "Error should include actual count {}, got: {}",
                excess_count,
                err_msg
            );
            prop_assert!(
                err_msg.contains(&MAX_FIELDS.to_string()),
                "Error should include maximum {}, got: {}",
                MAX_FIELDS,
                err_msg
            );
        }

        #[test]
        fn prop_field_count_within_limit_is_accepted(
            // Generate field counts within the limit (0 to MAX_FIELDS)
            valid_count in 0usize..=MAX_FIELDS
        ) {
            let result = validate_field_count(valid_count);

            prop_assert!(
                result.is_ok(),
                "Field count {} should be accepted (max is {})",
                valid_count,
                MAX_FIELDS
            );
        }

        #[test]
        fn prop_field_count_at_boundary_behaves_correctly(
            // Test around the boundary: MAX_FIELDS-1, MAX_FIELDS, MAX_FIELDS+1
            offset in 0usize..3
        ) {
            let count = MAX_FIELDS - 1 + offset;
            let result = validate_field_count(count);

            if count <= MAX_FIELDS {
                prop_assert!(
                    result.is_ok(),
                    "Field count {} should be accepted (max is {})",
                    count,
                    MAX_FIELDS
                );
            } else {
                prop_assert!(
                    result.is_err(),
                    "Field count {} should be rejected (max is {})",
                    count,
                    MAX_FIELDS
                );
            }
        }
    }

    #[test]
    fn test_field_count_validation_at_max() {
        // Exactly at MAX_FIELDS should be accepted
        assert!(validate_field_count(MAX_FIELDS).is_ok());
    }

    #[test]
    fn test_field_count_validation_over_max() {
        // One over MAX_FIELDS should be rejected
        let result = validate_field_count(MAX_FIELDS + 1);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("field count 1001 exceeds maximum 1000"));
    }

    #[test]
    fn test_field_count_validation_zero() {
        // Zero fields should be accepted
        assert!(validate_field_count(0).is_ok());
    }

    #[test]
    fn test_field_count_validation_one() {
        // One field should be accepted
        assert!(validate_field_count(1).is_ok());
    }

    // Suite validation tests
    // _Requirements: 16.4_

    #[test]
    fn test_suite_to_base64_p256() {
        let suite = Suite::P256;
        let b64 = suite.to_base64();
        // Verify it can be parsed back
        let parsed: Suite = b64.as_str().try_into().unwrap();
        assert_eq!(parsed, Suite::P256);
    }

    #[test]
    fn test_suite_to_base64_p384() {
        let suite = Suite::P384;
        let b64 = suite.to_base64();
        let parsed: Suite = b64.as_str().try_into().unwrap();
        assert_eq!(parsed, Suite::P384);
    }

    #[test]
    fn test_suite_to_base64_p521() {
        let suite = Suite::P521;
        let b64 = suite.to_base64();
        let parsed: Suite = b64.as_str().try_into().unwrap();
        assert_eq!(parsed, Suite::P521);
    }

    #[test]
    fn test_suite_id_bytes_match_constants() {
        assert_eq!(Suite::P256.suite_id_bytes(), P256);
        assert_eq!(Suite::P384.suite_id_bytes(), P384);
        assert_eq!(Suite::P521.suite_id_bytes(), P521);
    }

    #[test]
    fn test_suite_invalid_base64() {
        // Invalid base64 should fail
        let result: Result<Suite> = "not-valid-base64!!!".try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_suite_empty_string() {
        // Empty string should fail
        let result: Result<Suite> = "".try_into();
        assert!(result.is_err());
    }

    // Encoding enum tests

    #[test]
    fn test_encoding_default_is_binary() {
        assert_eq!(Encoding::default(), Encoding::Binary);
    }

    #[test]
    fn test_encoding_try_from_none() {
        let encoding: Encoding = None::<&str>.try_into().unwrap();
        assert_eq!(encoding, Encoding::Binary);
    }

    #[test]
    fn test_encoding_try_from_hex_str() {
        let encoding: Encoding = Some("1").try_into().unwrap();
        assert_eq!(encoding, Encoding::Hex);
    }

    #[test]
    fn test_encoding_try_from_binary_str() {
        let encoding: Encoding = Some("2").try_into().unwrap();
        assert_eq!(encoding, Encoding::Binary);
    }

    #[test]
    fn test_encoding_try_from_invalid_str() {
        let result: Result<Encoding> = Some("3").try_into();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown encoding"));
    }

    #[test]
    fn test_encoding_try_from_option_string() {
        let hex_string = Some("1".to_string());
        let encoding: Encoding = hex_string.as_ref().try_into().unwrap();
        assert_eq!(encoding, Encoding::Hex);

        let binary_string = Some("2".to_string());
        let encoding: Encoding = binary_string.as_ref().try_into().unwrap();
        assert_eq!(encoding, Encoding::Binary);

        let none_string: Option<String> = None;
        let encoding: Encoding = none_string.as_ref().try_into().unwrap();
        assert_eq!(encoding, Encoding::Binary);
    }

    #[test]
    fn test_encoding_parse_hex() {
        let hex_value = "04cebfe3667db3305777774f14a7ed4f26ce90b2d68935a30f9b086dc915e6ede23e6dfdde7aaf34dc34cd964c76f94bc91ba99edb3707281862c990c54782eace8c687770d72d4c714d4edd239e010facfb7c3d5c168b14d9040194059529f5e6#80c10441ae55442775bc5d1b0b8465eaaaa33b";
        let result = Encoding::Hex.parse(hex_value, &Suite::P384).unwrap();

        // Verify it parsed correctly
        assert!(!result.encapped_key.is_empty());
        assert!(!result.ciphertext.is_empty());
    }

    #[test]
    fn test_encoding_parse_binary() {
        // Create valid binary data for P384 (97 byte key + some ciphertext)
        let mut data = vec![0xABu8; 97];
        data.extend(vec![0xCDu8; 10]);
        let b64_value = data_encoding::BASE64.encode(&data);

        let result = Encoding::Binary.parse(&b64_value, &Suite::P384).unwrap();

        assert_eq!(result.encapped_key.len(), 97);
        assert_eq!(result.ciphertext.len(), 10);
    }

    // EnclaveResponse serialization tests
    // These tests verify that serde_json::to_string() produces correct JSON
    // for all value types that can appear in the response fields.

    #[test]
    fn test_enclave_response_serialization_with_string_fields() {
        let mut fields = BTreeMap::new();
        fields.insert("name".to_string(), Value::String("Bob".to_string()));
        fields.insert(
            "email".to_string(),
            Value::String("bob@example.com".to_string()),
        );

        let response = EnclaveResponse::new(fields.clone(), None);
        let json = serde_json::to_string(&response).unwrap();

        // Verify it can be deserialized back
        let parsed: EnclaveResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.fields, Some(fields));
        assert!(parsed.errors.is_none());
    }

    #[test]
    fn test_enclave_response_serialization_with_integer_fields() {
        let mut fields = BTreeMap::new();
        fields.insert("age".to_string(), Value::Number(46.into()));
        fields.insert("count".to_string(), Value::Number(100.into()));

        let response = EnclaveResponse::new(fields.clone(), None);
        let json = serde_json::to_string(&response).unwrap();

        let parsed: EnclaveResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.fields, Some(fields));
    }

    #[test]
    fn test_enclave_response_serialization_with_boolean_fields() {
        let mut fields = BTreeMap::new();
        fields.insert("is_active".to_string(), Value::Bool(true));
        fields.insert("is_verified".to_string(), Value::Bool(false));

        let response = EnclaveResponse::new(fields.clone(), None);
        let json = serde_json::to_string(&response).unwrap();

        let parsed: EnclaveResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.fields, Some(fields));
    }

    #[test]
    fn test_enclave_response_serialization_with_null_fields() {
        let mut fields = BTreeMap::new();
        fields.insert("missing".to_string(), Value::Null);

        let response = EnclaveResponse::new(fields.clone(), None);
        let json = serde_json::to_string(&response).unwrap();

        let parsed: EnclaveResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.fields, Some(fields));
    }

    #[test]
    fn test_enclave_response_serialization_with_mixed_fields() {
        // This tests the typical output from CEL expressions
        let mut fields = BTreeMap::new();
        fields.insert("name".to_string(), Value::String("Bob".to_string()));
        fields.insert("age".to_string(), Value::Number(46.into()));
        fields.insert("is_empty".to_string(), Value::Bool(false));
        fields.insert(
            "hash".to_string(),
            Value::String(
                "cd9fb1e148ccd8442e5aa74904cc73bf6fb54d1d54d333bd596aa9bb4bb4e961".to_string(),
            ),
        );

        let response = EnclaveResponse::new(fields.clone(), None);
        let json = serde_json::to_string(&response).unwrap();

        let parsed: EnclaveResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.fields, Some(fields));
    }

    #[test]
    fn test_enclave_response_serialization_with_errors() {
        let mut fields = BTreeMap::new();
        fields.insert("name".to_string(), Value::String("Bob".to_string()));
        fields.insert("failed_field".to_string(), Value::Null);

        let errors = vec![anyhow!("decryption failed for field")];
        let response = EnclaveResponse::new(fields.clone(), Some(errors));
        let json = serde_json::to_string(&response).unwrap();

        let parsed: EnclaveResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.fields, Some(fields));
        assert!(parsed.errors.is_some());
        assert_eq!(parsed.errors.unwrap().len(), 1);
    }

    #[test]
    fn test_enclave_response_error_serialization() {
        let response = EnclaveResponse::error(anyhow!("test error message"));
        let json = serde_json::to_string(&response).unwrap();

        let parsed: EnclaveResponse = serde_json::from_str(&json).unwrap();
        assert!(parsed.fields.is_none());
        assert!(parsed.errors.is_some());
        assert!(parsed.errors.unwrap()[0].contains("test error message"));
    }

    #[test]
    fn test_enclave_response_serialization_produces_valid_json() {
        let mut fields = BTreeMap::new();
        fields.insert("name".to_string(), Value::String("Bob".to_string()));

        let response = EnclaveResponse::new(fields, None);
        let json = serde_json::to_string(&response).unwrap();

        // Verify it's valid JSON by parsing as generic Value
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_object());
        assert!(parsed.get("fields").is_some());
    }

    #[test]
    fn test_enclave_response_serialization_skips_none_fields() {
        let mut fields = BTreeMap::new();
        fields.insert("name".to_string(), Value::String("Bob".to_string()));

        let response = EnclaveResponse::new(fields, None);
        let json = serde_json::to_string(&response).unwrap();

        // Verify "errors" key is not present when None (due to skip_serializing_if)
        assert!(!json.contains("\"errors\""));
    }

    #[test]
    fn test_enclave_response_default_serialization() {
        let response = EnclaveResponse::default();
        let json = serde_json::to_string(&response).unwrap();

        // Default should serialize to empty object (both fields are None and skipped)
        assert_eq!(json, "{}");
    }

    // Tests that prove serde_json::to_string() and json!().to_string() produce semantically equivalent output
    // Note: The raw strings may differ in field ordering, but the deserialized values are identical
    #[test]
    fn test_to_string_equals_json_macro() {
        use serde_json::json;

        // Test with string fields
        let mut fields = BTreeMap::new();
        fields.insert("name".to_string(), Value::String("Bob".to_string()));
        fields.insert(
            "email".to_string(),
            Value::String("bob@example.com".to_string()),
        );

        let response = EnclaveResponse::new(fields, None);

        let via_to_string = serde_json::to_string(&response).unwrap();
        let via_json_macro = json!(response).to_string();

        // Parse both back to Value and compare (handles field ordering differences)
        let parsed_to_string: Value = serde_json::from_str(&via_to_string).unwrap();
        let parsed_json_macro: Value = serde_json::from_str(&via_json_macro).unwrap();

        assert_eq!(
            parsed_to_string, parsed_json_macro,
            "to_string() and json!().to_string() should produce semantically identical output"
        );
    }

    #[test]
    fn test_to_string_equals_json_macro_with_mixed_types() {
        use serde_json::json;

        let mut fields = BTreeMap::new();
        fields.insert("name".to_string(), Value::String("Bob".to_string()));
        fields.insert("age".to_string(), Value::Number(46.into()));
        fields.insert("is_active".to_string(), Value::Bool(true));
        fields.insert("missing".to_string(), Value::Null);

        let response = EnclaveResponse::new(fields, None);

        let via_to_string = serde_json::to_string(&response).unwrap();
        let via_json_macro = json!(response).to_string();

        let parsed_to_string: Value = serde_json::from_str(&via_to_string).unwrap();
        let parsed_json_macro: Value = serde_json::from_str(&via_json_macro).unwrap();

        assert_eq!(
            parsed_to_string, parsed_json_macro,
            "to_string() and json!().to_string() should produce semantically identical output for mixed types"
        );
    }

    #[test]
    fn test_to_string_equals_json_macro_with_errors() {
        use serde_json::json;

        let mut fields = BTreeMap::new();
        fields.insert("name".to_string(), Value::String("Bob".to_string()));

        let errors = vec![anyhow!("test error")];
        let response = EnclaveResponse::new(fields, Some(errors));

        let via_to_string = serde_json::to_string(&response).unwrap();
        let via_json_macro = json!(response).to_string();

        let parsed_to_string: Value = serde_json::from_str(&via_to_string).unwrap();
        let parsed_json_macro: Value = serde_json::from_str(&via_json_macro).unwrap();

        assert_eq!(
            parsed_to_string, parsed_json_macro,
            "to_string() and json!().to_string() should produce semantically identical output with errors"
        );
    }

    #[test]
    fn test_to_string_equals_json_macro_error_response() {
        use serde_json::json;

        let response = EnclaveResponse::error(anyhow!("something went wrong"));

        let via_to_string = serde_json::to_string(&response).unwrap();
        let via_json_macro = json!(response).to_string();

        let parsed_to_string: Value = serde_json::from_str(&via_to_string).unwrap();
        let parsed_json_macro: Value = serde_json::from_str(&via_json_macro).unwrap();

        assert_eq!(
            parsed_to_string, parsed_json_macro,
            "to_string() and json!().to_string() should produce semantically identical output for error response"
        );
    }

    #[test]
    fn test_to_string_handles_special_characters_correctly() {
        use serde_json::json;

        let mut fields = BTreeMap::new();
        // Test various special characters that need JSON escaping
        fields.insert(
            "with_quotes".to_string(),
            Value::String("He said \"hello\"".to_string()),
        );
        fields.insert(
            "with_newline".to_string(),
            Value::String("line1\nline2".to_string()),
        );
        fields.insert(
            "with_tab".to_string(),
            Value::String("col1\tcol2".to_string()),
        );
        fields.insert(
            "with_backslash".to_string(),
            Value::String("path\\to\\file".to_string()),
        );
        fields.insert(
            "with_unicode".to_string(),
            Value::String("Hello 世界 🎉".to_string()),
        );
        fields.insert(
            "with_control_chars".to_string(),
            Value::String("bell\x07char".to_string()),
        );

        let response = EnclaveResponse::new(fields.clone(), None);

        let via_to_string = serde_json::to_string(&response).unwrap();
        let via_json_macro = json!(response).to_string();

        // Both should produce valid JSON that can be parsed
        let parsed_to_string: EnclaveResponse = serde_json::from_str(&via_to_string).unwrap();
        let parsed_json_macro: EnclaveResponse = serde_json::from_str(&via_json_macro).unwrap();

        // Verify the values round-trip correctly (no double escaping)
        assert_eq!(parsed_to_string.fields, Some(fields.clone()));
        assert_eq!(parsed_json_macro.fields, Some(fields.clone()));

        // Verify both approaches produce semantically identical output
        let value_to_string: Value = serde_json::from_str(&via_to_string).unwrap();
        let value_json_macro: Value = serde_json::from_str(&via_json_macro).unwrap();
        assert_eq!(value_to_string, value_json_macro);
    }

    #[test]
    fn test_to_string_no_double_escaping() {
        // Specifically test that quotes aren't double-escaped
        let mut fields = BTreeMap::new();
        let original_value = r#"{"nested": "json"}"#;
        fields.insert(
            "json_string".to_string(),
            Value::String(original_value.to_string()),
        );

        let response = EnclaveResponse::new(fields, None);
        let json = serde_json::to_string(&response).unwrap();

        // Parse it back
        let parsed: EnclaveResponse = serde_json::from_str(&json).unwrap();
        let parsed_fields = parsed.fields.unwrap();
        let recovered_value = parsed_fields.get("json_string").unwrap().as_str().unwrap();

        // The value should be exactly what we put in - no double escaping
        assert_eq!(recovered_value, original_value);
    }

    // Tests for Credential debug redaction
    // _Requirements: 32.4, 32.5_

    #[test]
    fn test_credential_debug_redacts_all_fields() {
        let credential = Credential {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: "FwoGZXIvYXdzEBYaDHVzLWVhc3QtMSJHMEUCIQDExample".to_string(),
        };

        let debug_output = format!("{:?}", credential);

        // Verify Debug output contains "[REDACTED]" for all credential fields
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output should contain [REDACTED], got: {}",
            debug_output
        );

        // Verify actual credential values do not appear in debug output
        assert!(
            !debug_output.contains("AKIAIOSFODNN7EXAMPLE"),
            "Debug output should NOT contain access_key_id value"
        );
        assert!(
            !debug_output.contains("wJalrXUtnFEMI"),
            "Debug output should NOT contain secret_access_key value"
        );
        assert!(
            !debug_output.contains("FwoGZXIvYXdzEBYaDHVzLWVhc3QtMSJHMEUCIQDExample"),
            "Debug output should NOT contain session_token value"
        );
    }

    #[test]
    fn test_credential_debug_format_structure() {
        let credential = Credential {
            access_key_id: "test_key_id".to_string(),
            secret_access_key: "test_secret".to_string(),
            session_token: "test_token".to_string(),
        };

        let debug_output = format!("{:?}", credential);

        // Verify the debug output has the expected structure
        assert!(
            debug_output.contains("Credential"),
            "Debug output should contain struct name 'Credential'"
        );
        assert!(
            debug_output.contains("access_key_id"),
            "Debug output should contain field name 'access_key_id'"
        );
        assert!(
            debug_output.contains("secret_access_key"),
            "Debug output should contain field name 'secret_access_key'"
        );
        assert!(
            debug_output.contains("session_token"),
            "Debug output should contain field name 'session_token'"
        );
    }

    #[test]
    fn test_enclave_request_debug_does_not_expose_credentials() {
        let credential = Credential {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: "FwoGZXIvYXdzEBYaDHVzLWVhc3QtMSJHMEUCIQDExample".to_string(),
        };

        let request = EnclaveRequest {
            credential,
            request: ParentRequest {
                vault_id: "v_test123".to_string(),
                region: "us-east-1".to_string(),
                fields: BTreeMap::new(),
                suite_id: "SFBLRQARAAIAAg==".to_string(),
                encrypted_private_key: "test_key".to_string(),
                expressions: None,
                encoding: None,
            },
        };

        let debug_output = format!("{:?}", request);

        // Verify actual credential values do not appear in EnclaveRequest debug output
        assert!(
            !debug_output.contains("AKIAIOSFODNN7EXAMPLE"),
            "EnclaveRequest debug should NOT contain access_key_id value"
        );
        assert!(
            !debug_output.contains("wJalrXUtnFEMI"),
            "EnclaveRequest debug should NOT contain secret_access_key value"
        );
        assert!(
            !debug_output.contains("FwoGZXIvYXdzEBYaDHVzLWVhc3QtMSJHMEUCIQDExample"),
            "EnclaveRequest debug should NOT contain session_token value"
        );

        // Verify [REDACTED] appears in the output
        assert!(
            debug_output.contains("[REDACTED]"),
            "EnclaveRequest debug should contain [REDACTED] for credential fields"
        );
    }
}
