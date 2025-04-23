// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use std::process::Command;

use anyhow::{Result, anyhow, bail};
use aws_lc_rs::encoding::AsBigEndian;
use aws_lc_rs::signature::{EcdsaKeyPair, EcdsaSigningAlgorithm};
use rustls::crypto::hpke::HpkePrivateKey;

use crate::constants::PLAINTEXT_PREFIX;
use crate::models::{Credential, EnclaveRequest};
use crate::utils::base64_decode;

fn call_kms_decrypt(credential: &Credential, ciphertext: &str, region: &str) -> Result<String> {
    // https://github.com/aws/aws-nitro-enclaves-sdk-c/blob/main/bin/kmstool-enclave-cli/README.md

    let output = Command::new("/app/kmstool_enclave_cli")
        .arg("decrypt")
        .args(["--region", region])
        .args(["--proxy-port", "8000"])
        .args(["--aws-access-key-id", credential.access_key_id.as_str()])
        .args([
            "--aws-secret-access-key",
            credential.secret_access_key.as_str(),
        ])
        .args(["--aws-session-token", credential.session_token.as_str()])
        .args(["--ciphertext", ciphertext])
        .output()
        .map_err(|err| anyhow!("Unable to call KMS decrypt: {:?}", err))?;

    if !output.status.success() {
        bail!(
            "Unable to decrypt key ({:?}): {}",
            output.status.code(),
            String::from_utf8_lossy(output.stderr.as_slice()).to_string()
        );
    }

    Ok(String::from_utf8_lossy(output.stdout.as_slice()).to_string())
}

pub fn get_secret_key(
    alg: &'static EcdsaSigningAlgorithm,
    payload: &EnclaveRequest,
) -> Result<HpkePrivateKey> {
    let kms_result = call_kms_decrypt(
        &payload.credential,
        &payload.request.encrypted_private_key, // base64 encoded
        &payload.request.region,
    )
    .map_err(|err| anyhow!("failed to call KMS: {:?}", err))?;

    // Strip prefix and newline added at https://github.com/aws/aws-nitro-enclaves-sdk-c/blob/main/bin/kmstool-enclave-cli/main.c#L514
    let b64_sk = kms_result.trim_start_matches(PLAINTEXT_PREFIX).trim_end();

    // Base64 decode the secret key
    let plaintext_sk = base64_decode(b64_sk)?;

    //let alg = suite.get_signing_algorithm()?;

    // Decode the DER PKCS#8 secret key
    let sk = EcdsaKeyPair::from_private_key_der(alg, &plaintext_sk)
        .map_err(|err| anyhow!("unable to decode PKCS#8 private key: {:?}", err))?;
    let sk_bytes = sk
        .private_key()
        .as_be_bytes()
        .map_err(|err| anyhow!("unable to get private key bytes: {:?}", err))?;
    let sk_ref = sk_bytes.as_ref();

    Ok(sk_ref.to_vec().into())
}
