// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use anyhow::{Result, anyhow};
use aws_lc_rs::encoding::AsBigEndian;
use aws_lc_rs::signature::{EcdsaKeyPair, EcdsaSigningAlgorithm};
use rustls::crypto::hpke::HpkePrivateKey;

use crate::aws_ne;
use crate::models::{Credential, EnclaveRequest};
use crate::utils::base64_decode;

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

pub fn get_secret_key(
    alg: &'static EcdsaSigningAlgorithm,
    payload: &EnclaveRequest,
) -> Result<HpkePrivateKey> {
    // Call KMS decrypt via FFI wrapper - returns plaintext bytes directly
    let plaintext_sk = call_kms_decrypt(
        &payload.credential,
        &payload.request.encrypted_private_key, // base64 encoded
        &payload.request.region,
    )
    .map_err(|err| anyhow!("failed to call KMS: {err:?}"))?;

    // Decode the DER PKCS#8 secret key
    let sk = EcdsaKeyPair::from_private_key_der(alg, &plaintext_sk)
        .map_err(|err| anyhow!("unable to decode PKCS#8 private key: {err:?}"))?;
    let sk_bytes = sk
        .private_key()
        .as_be_bytes()
        .map_err(|err| anyhow!("unable to get private key bytes: {err:?}"))?;
    let sk_ref = sk_bytes.as_ref();

    Ok(sk_ref.to_vec().into())
}
