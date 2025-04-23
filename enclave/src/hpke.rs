// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use anyhow::{Result, anyhow};
use rustls::crypto::hpke::{EncapsulatedSecret, Hpke, HpkePrivateKey};
use serde_json::Value;

use crate::models::EncryptedData;

pub fn decrypt_value(
    suite: &dyn Hpke,
    private_key: &HpkePrivateKey,
    info: &[u8],
    field: &str,
    encrypted_data: EncryptedData,
) -> Result<Value> {
    let aad = field.to_lowercase();

    let enc = EncapsulatedSecret(encrypted_data.encapped_key);

    let plaintext_value = suite
        .open(
            &enc,
            info,
            aad.as_bytes(),
            &encrypted_data.ciphertext,
            private_key,
        )
        .map_err(|err| anyhow!("[{}] unable to decrypt data: {:?}", aad, err))?;

    let string_value = String::from_utf8(plaintext_value).map_err(|err| {
        anyhow!(
            "[{}] unable to convert plaintext data to string: {:?}",
            aad,
            err
        )
    })?;

    let value: Value = serde_json::to_value(string_value)
        .map_err(|err| anyhow!("[{}] unable to convert string to value: {:?}", aad, err))?;

    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{models::Suite, utils::base64_decode};
    use aws_lc_rs::{encoding::AsBigEndian, signature::EcdsaKeyPair};
    use serde_json::json;

    #[test]
    fn test_decrypt_value() {
        let vault_id = "v_2hRK9u2DOzmAPMhdVNt9qlJ3UvL";
        let b64_suite_id: String = "SFBLRQARAAIAAg==".to_string();
        let suite: Suite = b64_suite_id.try_into().unwrap();

        let b64_sk = "MIG/AgEAMBAGByqGSM49AgEGBSuBBAAiBIGnMIGkAgEBBDCt+Ad+qIiVIK4e/tj6u+boZ63IAgT2ZttR14ZGjL3XLjNC//WNJcFyNSOGDt2kNE+gBwYFK4EEACKhZANiAASMfDcAvCD3J8in7EzaM6hNvkQD+S6C0H2hI7biRlkHMXcIjZ/7LVNQ2+VMlFAWV8ESbahT0wKiYLNreDvPIDFJOZyzfURR/HTRtf5Vd+aEjXl9EI7XxRu6OILEfQC9afg=";
        let der_sk = base64_decode(b64_sk).unwrap();

        let algo = suite.get_signing_algorithm().unwrap();
        let sk = EcdsaKeyPair::from_private_key_der(algo, &der_sk).unwrap();
        let sk_bytes = sk.private_key().as_be_bytes().unwrap();
        let sk_ref = sk_bytes.as_ref();
        let secret_key: HpkePrivateKey = sk_ref.to_vec().into();

        let hex_encrypted_value: String = "04cebfe3667db3305777774f14a7ed4f26ce90b2d68935a30f9b086dc915e6ede23e6dfdde7aaf34dc34cd964c76f94bc91ba99edb3707281862c990c54782eace8c687770d72d4c714d4edd239e010facfb7c3d5c168b14d9040194059529f5e6#80c10441ae55442775bc5d1b0b8465eaaaa33b".to_string();
        let encrypted_data: EncryptedData =
            EncryptedData::from_hex(hex_encrypted_value.as_str()).unwrap();

        let suite = suite.get_suite().unwrap();
        let info = vault_id.as_bytes();
        let field = "first_name";

        let expected = json!("Bob");

        let actual = decrypt_value(suite, &secret_key, info, &field, encrypted_data).unwrap();

        assert_eq!(actual, expected);
    }
}
