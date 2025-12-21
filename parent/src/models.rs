// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use std::collections::BTreeMap;
use std::fmt;

use aws_credential_types::Credentials;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use validator::Validate;
use zeroize::ZeroizeOnDrop;

use crate::constants::{
    MAX_ENCODING_LENGTH, MAX_ENCRYPTED_KEY_LENGTH, MAX_EXPRESSIONS_COUNT, MAX_FIELDS_COUNT,
    MAX_REGION_LENGTH, MAX_SUITE_ID_LENGTH, MAX_VAULT_ID_LENGTH,
};

/// The information to be provided for a `describe-enclaves` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveDescribeInfo {
    /// Enclave name assigned by the user
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "EnclaveName")]
    pub enclave_name: Option<String>,
    #[serde(rename = "EnclaveID")]
    /// The full ID of the enclave.
    pub enclave_id: String,
    #[serde(rename = "ProcessID")]
    /// The PID of the enclave process which manages the enclave.
    pub process_id: u32,
    #[serde(rename = "EnclaveCID")]
    /// The enclave's CID.
    pub enclave_cid: u64,
    #[serde(rename = "NumberOfCPUs")]
    /// The number of CPUs used by the enclave.
    pub cpu_count: u64,
    #[serde(rename = "CPUIDs")]
    /// The IDs of the CPUs used by the enclave.
    pub cpu_ids: Vec<u32>,
    #[serde(rename = "MemoryMiB")]
    /// The memory provided to the enclave (in MiB).
    pub memory_mib: u64,
    #[serde(rename = "State")]
    /// The current state of the enclave.
    pub state: String,
    #[serde(rename = "Flags")]
    /// The bit-mask which provides the enclave's launch flags.
    pub flags: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    /// Build measurements containing PCRs
    pub build_info: Option<EnclaveBuildInfo>,
    /// Assigned or default EIF name
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "ImageName")]
    pub img_name: Option<String>,
    #[serde(rename = "ImageVersion")]
    /// Assigned or default EIF version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub img_version: Option<String>,
}

/// The information to be provided for a `run-enclave` request.
#[derive(Clone, Serialize, Deserialize)]
pub struct EnclaveRunInfo {
    #[serde(rename = "EnclaveName")]
    /// The name of the enclave.
    pub enclave_name: String,
    #[serde(rename = "EnclaveID")]
    /// The full ID of the enclave.
    pub enclave_id: String,
    #[serde(rename = "ProcessID")]
    /// The PID of the enclave process which manages the enclave.
    pub process_id: u32,
    #[serde(rename = "EnclaveCID")]
    /// The enclave's CID.
    pub enclave_cid: u64,
    #[serde(rename = "NumberOfCPUs")]
    /// The number of CPUs used by the enclave.
    pub cpu_count: usize,
    #[serde(rename = "CPUIDs")]
    /// The IDs of the CPUs used by the enclave.
    pub cpu_ids: Vec<u32>,
    #[serde(rename = "MemoryMiB")]
    /// The memory provided to the enclave (in MiB).
    pub memory_mib: u64,
}

/// The information to be provided for a `terminate-enclave` request.
#[derive(Clone, Serialize, Deserialize)]
pub struct EnclaveTerminateInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "EnclaveName")]
    /// The name of the enclave. Optional for older versions.
    pub enclave_name: Option<String>,
    #[serde(rename = "EnclaveID")]
    /// The full ID of the enclave.
    pub enclave_id: String,
    #[serde(rename = "Terminated")]
    /// A flag indicating if the enclave has terminated.
    pub terminated: bool,
}

/// The information to be provided for a `build-enclave` request.
#[derive(Serialize, Clone, Deserialize, Debug)]
pub struct EnclaveBuildInfo {
    #[serde(rename = "Measurements")]
    /// The measurement results (hashes) of various enclave properties.
    pub measurements: BTreeMap<String, String>,
}

#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct Credential {
    #[serde(rename = "AccessKeyId")]
    pub access_key_id: String,

    #[serde(rename = "SecretAccessKey")]
    pub secret_access_key: String,

    #[serde(rename = "Token")]
    pub session_token: String,
}

// Custom Debug implementation to prevent accidental logging of sensitive data
impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("access_key_id", &"[REDACTED]")
            .field("secret_access_key", &"[REDACTED]")
            .field("session_token", &"[REDACTED]")
            .finish()
    }
}

impl From<Credentials> for Credential {
    fn from(credential: Credentials) -> Self {
        let token = match credential.session_token() {
            Some(token) => token.to_string(),
            None => "".to_string(),
        };

        Self {
            access_key_id: credential.access_key_id().to_string(),
            secret_access_key: credential.secret_access_key().to_string(),
            session_token: token,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ParentRequest {
    #[validate(length(min = 1, max = "MAX_VAULT_ID_LENGTH"))]
    pub vault_id: String,

    #[validate(length(min = 1, max = "MAX_REGION_LENGTH"))]
    #[validate(custom(function = "validate_aws_region"))]
    pub region: String,

    #[validate(custom(function = "validate_fields_count"))]
    pub fields: BTreeMap<String, String>,

    #[validate(length(min = 1, max = "MAX_SUITE_ID_LENGTH"))]
    pub suite_id: String, // base64 encoded

    #[validate(length(min = 1, max = "MAX_ENCRYPTED_KEY_LENGTH"))]
    pub encrypted_private_key: String, // base64 encoded

    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(custom(function = "validate_expressions_count"))]
    pub expressions: Option<BTreeMap<String, String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = "MAX_ENCODING_LENGTH"))]
    pub encoding: Option<String>,
}

/// Validates AWS region format (e.g., "us-east-1", "eu-west-2")
/// Pattern: two lowercase letters, hyphen, lowercase letters, hyphen, digits
fn validate_aws_region(region: &str) -> Result<(), validator::ValidationError> {
    let parts: Vec<&str> = region.split('-').collect();
    if parts.len() < 3 {
        return Err(validator::ValidationError::new("invalid_aws_region"));
    }

    // First part: exactly 2 lowercase letters (e.g., "us", "eu", "ap")
    let first = parts[0];
    if first.len() != 2 || !first.chars().all(|c| c.is_ascii_lowercase()) {
        return Err(validator::ValidationError::new("invalid_aws_region"));
    }

    // Middle parts: lowercase letters (e.g., "east", "west", "southeast")
    for part in &parts[1..parts.len() - 1] {
        if part.is_empty() || !part.chars().all(|c| c.is_ascii_lowercase()) {
            return Err(validator::ValidationError::new("invalid_aws_region"));
        }
    }

    // Last part: digits (e.g., "1", "2")
    let last = parts[parts.len() - 1];
    if last.is_empty() || !last.chars().all(|c| c.is_ascii_digit()) {
        return Err(validator::ValidationError::new("invalid_aws_region"));
    }

    Ok(())
}

fn validate_fields_count(
    fields: &BTreeMap<String, String>,
) -> Result<(), validator::ValidationError> {
    if fields.len() > MAX_FIELDS_COUNT {
        return Err(validator::ValidationError::new("too_many_fields"));
    }
    Ok(())
}

fn validate_expressions_count(
    expressions: &BTreeMap<String, String>,
) -> Result<(), validator::ValidationError> {
    if expressions.len() > MAX_EXPRESSIONS_COUNT {
        return Err(validator::ValidationError::new("too_many_expressions"));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParentResponse {
    pub fields: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveRequest {
    pub credential: Credential,
    pub request: ParentRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<BTreeMap<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
}
