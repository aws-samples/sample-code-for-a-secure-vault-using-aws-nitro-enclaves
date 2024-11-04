// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Error, Result};
use aws_lc_rs::signature::{
    EcdsaSigningAlgorithm, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING,
    ECDSA_P521_SHA512_ASN1_SIGNING,
};
use data_encoding::HEXLOWER;
use rustls::crypto::aws_lc_rs::hpke::{
    DH_KEM_P256_HKDF_SHA256_AES_256, DH_KEM_P384_HKDF_SHA384_AES_256,
    DH_KEM_P521_HKDF_SHA512_AES_256,
};
use rustls::crypto::hpke::Hpke;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::ZeroizeOnDrop;

use crate::constants::{P256, P384, P521};

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveRequest {
    pub credential: Credential,
    pub request: ParentRequest,
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

impl TryFrom<&str> for EncryptedData {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        let data: EncryptedData = match value.split_once('#') {
            Some((hex_encapped_key, hex_ciphertext)) => {
                let encapped_key = HEXLOWER
                    .decode(hex_encapped_key.as_bytes())
                    .map_err(|err| anyhow!("unable to hex decode encapped key: {:?}", err))?;
                let ciphertext = HEXLOWER
                    .decode(hex_ciphertext.as_bytes())
                    .map_err(|err| anyhow!("unable to hex decode ciphertext: {:?}", err))?;

                EncryptedData {
                    encapped_key,
                    ciphertext,
                }
            }
            None => bail!("unable to split value on '#': {:?}", value),
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

impl TryFrom<&String> for Suite {
    type Error = anyhow::Error;

    fn try_from(value: &String) -> Result<Self> {
        let suite = base64_decode(value)
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
