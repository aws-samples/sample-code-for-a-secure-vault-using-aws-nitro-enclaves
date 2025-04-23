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

use crate::constants::{P256, P384, P521};

use crate::hpke::decrypt_value;
use crate::kms::get_secret_key;
use crate::utils::base64_decode;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ENCODING {
    HEX = 1,
    BINARY = 2,
}

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
    pub encoding: Option<ENCODING>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveRequest {
    pub credential: Credential,
    pub request: ParentRequest,
}

impl EnclaveRequest {
    fn get_private_key(&self, suite: &Suite) -> Result<HpkePrivateKey> {
        let alg = suite.get_signing_algorithm()?;

        // Decrypt the KMS secret key
        let sk: HpkePrivateKey = get_secret_key(alg, self)?;

        Ok(sk)
    }

    pub fn decrypt_fields(&self) -> Result<(BTreeMap<String, Value>, Vec<Error>)> {
        let suite: Suite = self.request.suite_id.clone().try_into()?;

        let private_key = self.get_private_key(&suite)?;
        println!("[enclave] decrypted KMS secret key");

        let suite = suite.get_suite()?;
        let info = self.request.vault_id.as_bytes();
        let mut errors: Vec<Error> = Vec::new();

        let decrypted_fields = match self.request.encoding {
            Some(ENCODING::BINARY) => {
                let mut decrypted_fields = BTreeMap::new();
                for (field, value) in &self.request.fields {
                    let encrypted_data = EncryptedData::from_binary(value.as_str())?;

                    let value = decrypt_value(suite, &private_key, info, field, encrypted_data)
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

                    let value = decrypt_value(suite, &private_key, info, field, encrypted_data)
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

#[derive(Debug, Serialize, Deserialize)]
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

    pub fn from_binary(value: &str) -> Result<Self> {
        let data: EncryptedData = match base64_decode(value) {
            Ok(data) => {
                let encapped_key = data[0..32].to_vec();
                let ciphertext = data[32..].to_vec();

                Self {
                    encapped_key,
                    ciphertext,
                }
            }
            Err(err) => bail!("unable to base64 decode value: {:?}", err),
        };
        Ok(data)
    }
}

#[derive(Debug)]
pub struct Suite(pub Vec<u8>);

impl TryFrom<String> for Suite {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        let suite = base64_decode(&value)
            .map_err(|err| anyhow!("unable to base64 decode suite: {:?}", err))?;
        Ok(Suite(suite))
    }
}

impl Suite {
    pub fn get_suite(&self) -> Result<&dyn Hpke> {
        let suite_id = self.0.as_slice();

        if suite_id == P256 {
            return Ok(DH_KEM_P256_HKDF_SHA256_AES_256);
        } else if suite_id == P384 {
            return Ok(DH_KEM_P384_HKDF_SHA384_AES_256);
        } else if suite_id == P521 {
            return Ok(DH_KEM_P521_HKDF_SHA512_AES_256);
        }
        bail!("invalid suite_id")
    }

    pub fn get_signing_algorithm(&self) -> Result<&'static EcdsaSigningAlgorithm> {
        let suite_id = self.0.as_slice();

        if suite_id == P256 {
            return Ok(&ECDSA_P256_SHA256_ASN1_SIGNING);
        } else if suite_id == P384 {
            return Ok(&ECDSA_P384_SHA384_ASN1_SIGNING);
        } else if suite_id == P521 {
            return Ok(&ECDSA_P521_SHA512_ASN1_SIGNING);
        }
        bail!("invalid suite_id")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_suite() {
        let b64_suite_id: String = "SFBLRQARAAIAAg==".to_string();
        let suite: Suite = b64_suite_id.try_into().unwrap();

        let actual = suite.get_suite().unwrap();
        let expected = DH_KEM_P384_HKDF_SHA384_AES_256.suite();
        assert_eq!(actual.suite(), expected);
    }

    #[test]
    fn test_get_signing_algorithm() {
        let b64_suite_id: String = "SFBLRQARAAIAAg==".to_string();
        let suite: Suite = b64_suite_id.try_into().unwrap();

        let actual = suite.get_signing_algorithm().unwrap();
        let expected = &ECDSA_P384_SHA384_ASN1_SIGNING;
        assert_eq!(actual, expected);
    }
}
