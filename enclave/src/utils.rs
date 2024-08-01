// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use anyhow::{anyhow, Result};
use base64::{prelude::BASE64_STANDARD, Engine as _};

#[inline]
pub fn base64_decode(input: &str) -> Result<Vec<u8>> {
    let decoded = BASE64_STANDARD
        .decode(input)
        .map_err(|err| anyhow!("unable to base64 decode input: {:?}", err))?;
    Ok(decoded)
}

#[inline]
pub fn build_suite_id(kem_id: u16, kdf_id: u16, aead_id: u16) -> Vec<u8> {
    [
        &b"HPKE"[..],
        &kem_id.to_be_bytes(),
        &kdf_id.to_be_bytes(),
        &aead_id.to_be_bytes(),
    ]
    .concat()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::P384;

    #[test]
    fn test_base64_decode() {
        let input = "SFBLRQARAAIAAg==";
        let actual = base64_decode(input).unwrap();
        assert_eq!(actual, P384);
    }
}
