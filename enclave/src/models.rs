// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use std::collections::BTreeMap;

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

use crate::constants::{ENCODING_BINARY, P256, P384, P521};

use crate::hpke::decrypt_value;
use crate::kms::get_secret_key;
use crate::utils::base64_decode;

#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct Credential {
    #[serde(rename = "AccessKeyId")]
    pub access_key_id: String,

    #[serde(rename = "SecretAccessKey")]
    pub secret_access_key: String,

    #[serde(rename = "Token")]
    pub session_token: String,
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
    fn get_private_key(&self, suite: &Suite) -> Result<HpkePrivateKey> {
        let alg = suite.get_signing_algorithm();

        // Decrypt the KMS secret key
        let sk: HpkePrivateKey = get_secret_key(alg, self)?;

        Ok(sk)
    }

    pub fn decrypt_fields(&self) -> Result<(BTreeMap<String, Value>, Vec<Error>)> {
        let suite: Suite = self.request.suite_id.as_str().try_into()?;

        let private_key = self.get_private_key(&suite)?;
        println!("[enclave] decrypted KMS secret key");

        let hpke_suite = suite.get_hpke_suite();
        let info = self.request.vault_id.as_bytes();
        let mut errors: Vec<Error> = Vec::new();

        println!("[enclave] vault_id: {:?}", &self.request.vault_id);
        println!("[enclave] encoding: {:?}", &self.request.encoding);

        let decrypted_fields = match &self.request.encoding {
            Some(encoding) if encoding == ENCODING_BINARY => {
                let mut decrypted_fields = BTreeMap::new();
                for (field, value) in &self.request.fields {
                    let encrypted_data = EncryptedData::from_binary(value.as_str(), &suite)?;

                    let value = decrypt_value(hpke_suite, &private_key, info, field, encrypted_data)
                        .unwrap_or_else(|error| {
                            errors.push(error);
                            Value::Null
                        });
                    decrypted_fields.insert(field.to_string(), value);
                }
                decrypted_fields
            }
            _ => {
                // default HEX encoding
                let mut decrypted_fields = BTreeMap::new();
                for (field, value) in &self.request.fields {
                    let encrypted_data = EncryptedData::from_hex(value.as_str())?;

                    let value = decrypt_value(hpke_suite, &private_key, info, field, encrypted_data)
                        .unwrap_or_else(|error| {
                            errors.push(error);
                            Value::Null
                        });
                    decrypted_fields.insert(field.to_string(), value);
                }
                decrypted_fields
            }
        };

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

        Ok(Self {
            encapped_key: data[..key_size].to_vec(),
            ciphertext: data[key_size..].to_vec(),
        })
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
    /// Returns the encapped key size in bytes for this suite (RFC 9180 Nenc value)
    pub fn encapped_key_size(&self) -> usize {
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
        assert!(result.unwrap_err().to_string().contains("unknown suite identifier"));
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
        let actual: EncryptedData = EncryptedData::from_binary(b64_encrypted_value, &Suite::P384).unwrap();

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
            assert_eq!(result.encapped_key.len(), *key_size, "Suite {:?} should have encapped_key of {} bytes", suite, key_size);
            assert_eq!(result.ciphertext.len(), 10, "Suite {:?} should have ciphertext of 10 bytes", suite);
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
    }
}
