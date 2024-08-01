// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use std::collections::BTreeMap;

use aws_credential_types::Credentials;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::ZeroizeOnDrop;

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

#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct Credential {
    #[serde(rename = "AccessKeyId")]
    pub access_key_id: String,

    #[serde(rename = "SecretAccessKey")]
    pub secret_access_key: String,

    #[serde(rename = "Token")]
    pub session_token: String,
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
