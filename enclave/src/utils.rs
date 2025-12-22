// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use anyhow::{Result, anyhow};
use data_encoding::BASE64;

#[inline]
pub fn base64_decode(input: &str) -> Result<Vec<u8>> {
    let decoded = BASE64
        .decode(input.as_bytes())
        .map_err(|err| anyhow!("unable to base64 decode input: {:?}", err))?;
    Ok(decoded)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::constants::{P256, P384, P521};

    /// Builds an HPKE suite ID from KEM, KDF, and AEAD identifiers.
    /// This is used to verify the suite ID constants are correctly defined.
    /// Format: "HPKE" || kem_id (2 bytes BE) || kdf_id (2 bytes BE) || aead_id (2 bytes BE)
    #[inline]
    fn build_suite_id(kem_id: u16, kdf_id: u16, aead_id: u16) -> Vec<u8> {
        [
            &b"HPKE"[..],
            &kem_id.to_be_bytes(),
            &kdf_id.to_be_bytes(),
            &aead_id.to_be_bytes(),
        ]
        .concat()
    }

    #[test]
    fn test_base64_decode() {
        let input = "SFBLRQARAAIAAg==";
        let actual = base64_decode(input).unwrap();
        assert_eq!(actual, P384);
    }

    #[test]
    fn test_suite_id_constants_match_build_function() {
        // Verify P256 suite ID: DH_KEM_P256_HKDF_SHA256_AES_256
        // KEM: 0x0010, KDF: 0x0001, AEAD: 0x0002
        assert_eq!(
            build_suite_id(0x0010, 0x0001, 0x0002),
            P256.to_vec(),
            "P256 suite ID constant should match build_suite_id output"
        );

        // Verify P384 suite ID: DH_KEM_P384_HKDF_SHA384_AES_256
        // KEM: 0x0011, KDF: 0x0002, AEAD: 0x0002
        assert_eq!(
            build_suite_id(0x0011, 0x0002, 0x0002),
            P384.to_vec(),
            "P384 suite ID constant should match build_suite_id output"
        );

        // Verify P521 suite ID: DH_KEM_P521_HKDF_SHA512_AES_256
        // KEM: 0x0012, KDF: 0x0003, AEAD: 0x0002
        assert_eq!(
            build_suite_id(0x0012, 0x0003, 0x0002),
            P521.to_vec(),
            "P521 suite ID constant should match build_suite_id output"
        );
    }
}
