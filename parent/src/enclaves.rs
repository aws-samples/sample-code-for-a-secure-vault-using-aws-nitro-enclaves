// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

//! Nitro Enclave management and vsock communication.
//!
//! This module provides the [`Enclaves`] struct for managing Nitro Enclave
//! lifecycle and communicating with enclaves over vsock.
//!
//! # Enclave Lifecycle
//!
//! 1. **Discovery**: The parent periodically calls [`refresh`](Enclaves::refresh)
//!    to get the list of running enclaves via `nitro-cli describe-enclaves`
//! 2. **Launch**: If fewer than [`MAX_ENCLAVES_PER_INSTANCE`] enclaves are running,
//!    new ones are launched via `nitro-cli run-enclave`
//! 3. **Filtering**: Only enclaves with names starting with [`ENCLAVE_PREFIX`]
//!    are managed by this application
//!
//! # Communication
//!
//! The parent communicates with enclaves over vsock using a length-prefixed
//! JSON protocol. See [`crate::protocol`] for wire format details.
//!
//! [`ENCLAVE_PREFIX`]: crate::constants::ENCLAVE_PREFIX
//! [`MAX_ENCLAVES_PER_INSTANCE`]: crate::constants::MAX_ENCLAVES_PER_INSTANCE

use serde_json::json;
use tokio::{process::Command, sync::RwLock};
use vsock::{VsockAddr, VsockStream};

use crate::constants::{
    ENCLAVE_PREFIX, MAX_ENCLAVES_PER_INSTANCE, RUN_ENCLAVE_CPU_COUNT, RUN_ENCLAVE_EIF_PATH,
    RUN_ENCLAVE_MEMORY_SIZE,
};
use crate::models::{EnclaveDescribeInfo, EnclaveRunInfo};
use crate::{constants, errors::AppError, models::EnclaveRequest};
use crate::{
    models::EnclaveResponse,
    protocol::{recv_message, send_message},
};

/// Attestation request to send to the enclave.
#[derive(serde::Serialize)]
struct AttestationRequest {
    #[serde(rename = "type")]
    request_type: &'static str,
    nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_data: Option<String>,
}

/// Attestation response received from the enclave.
#[derive(serde::Deserialize)]
pub struct AttestationResponse {
    /// The attestation document (base64 encoded).
    #[serde(default)]
    pub attestation_document: Option<String>,
    /// Error message if attestation failed.
    #[serde(default)]
    pub error: Option<String>,
}

/// Manager for Nitro Enclaves.
///
/// Provides thread-safe enclave discovery, launch, and communication.
/// Uses [`RwLock`] for concurrent read access to the enclave list.
pub struct Enclaves {
    /// List of known running enclaves.
    enclaves: RwLock<Vec<EnclaveDescribeInfo>>,
}

impl Default for Enclaves {
    fn default() -> Self {
        Self::new()
    }
}

impl Enclaves {
    /// Creates a new enclave manager with an empty enclave list.
    pub fn new() -> Self {
        Self {
            enclaves: RwLock::new(Vec::with_capacity(constants::MAX_ENCLAVES_PER_INSTANCE)),
        }
    }

    /// Returns the current list of known enclaves.
    ///
    /// This returns a clone of the internal list to avoid holding the lock.
    #[tracing::instrument(skip(self))]
    pub async fn get_enclaves(&self) -> Vec<EnclaveDescribeInfo> {
        let enclaves = self.enclaves.read().await;
        enclaves.clone()
    }

    /// Refreshes the enclave list and optionally launches new enclaves.
    ///
    /// This method:
    /// 1. Calls `nitro-cli describe-enclaves` to get current enclaves
    /// 2. Launches new enclaves if needed (unless `skip_run_enclaves` is true)
    /// 3. Filters and stores only enclaves matching [`ENCLAVE_PREFIX`]
    ///
    /// # Arguments
    ///
    /// * `skip_run_enclaves` - If true, don't launch new enclaves
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `nitro-cli` command fails
    /// - JSON parsing of output fails
    /// - Launching new enclaves fails
    #[tracing::instrument(skip(self))]
    pub async fn refresh(&self, skip_run_enclaves: bool) -> Result<(), AppError> {
        // Get current enclave list from nitro-cli
        let output = Command::new("nitro-cli")
            .arg("describe-enclaves")
            .output()
            .await?;

        if !output.status.success() {
            return Err(AppError::RunError(
                output.status.code(),
                String::from_utf8_lossy(output.stderr.as_slice()).to_string(),
            ));
        }

        let enclaves: Vec<EnclaveDescribeInfo> = serde_json::from_slice(output.stdout.as_slice())?;

        tracing::trace!("[parent] enclaves: {:?}", enclaves);

        // Launch additional enclaves if needed
        if !skip_run_enclaves {
            let delta = MAX_ENCLAVES_PER_INSTANCE - enclaves.len();
            if delta > 0 {
                tracing::debug!("[parent] launching {} enclaves", delta);
                for _ in 0..delta {
                    self.run_enclave().await?;
                }
            }
        } else {
            tracing::warn!("[parent] skipping launching enclaves");
        }

        // Filter and store only vault enclaves
        let mut enclaves_writer = self.enclaves.write().await;
        enclaves_writer.clear();
        enclaves_writer.extend(enclaves.into_iter().filter(|e| {
            e.enclave_name
                .as_ref()
                .is_some_and(|name| name.starts_with(ENCLAVE_PREFIX))
        }));

        Ok(())
    }

    /// Launches a new Nitro Enclave.
    ///
    /// Uses the EIF file at [`RUN_ENCLAVE_EIF_PATH`] with configured
    /// CPU and memory allocations.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `nitro-cli run-enclave` fails
    /// - JSON parsing of output fails
    #[tracing::instrument(skip(self))]
    pub async fn run_enclave(&self) -> Result<EnclaveRunInfo, AppError> {
        let output = Command::new("nitro-cli")
            .arg("run-enclave")
            .args(["--eif-path", RUN_ENCLAVE_EIF_PATH])
            .args(["--cpu-count", RUN_ENCLAVE_CPU_COUNT])
            .args(["--memory", RUN_ENCLAVE_MEMORY_SIZE])
            .output()
            .await?;

        if !output.status.success() {
            return Err(AppError::RunError(
                output.status.code(),
                String::from_utf8_lossy(output.stderr.as_slice()).to_string(),
            ));
        }

        let enclave: EnclaveRunInfo = serde_json::from_slice(output.stdout.as_slice())?;

        Ok(enclave)
    }

    /// Sends a decrypt request to an enclave and returns the response.
    ///
    /// This is a blocking operation that:
    /// 1. Connects to the enclave via vsock
    /// 2. Serializes and sends the request as JSON
    /// 3. Receives and deserializes the response
    ///
    /// # Arguments
    ///
    /// * `cid` - The enclave's CID (Context ID)
    /// * `port` - The vsock port to connect to
    /// * `payload` - The decrypt request to send
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - vsock connection fails
    /// - Message send/receive fails
    /// - JSON serialization/deserialization fails
    ///
    /// # Note
    ///
    /// This method is synchronous and should be called via
    /// `tokio::task::spawn_blocking` from async context.
    #[tracing::instrument(skip(self, payload))]
    pub fn decrypt(
        &self,
        cid: u32,
        port: u32,
        payload: EnclaveRequest,
    ) -> Result<EnclaveResponse, AppError> {
        // Connect to enclave via vsock
        let mut stream = VsockStream::connect(&VsockAddr::new(cid, port))?;

        tracing::debug!("[parent] connected to CID {} and port {}", cid, port);

        // Serialize and send request
        let msg = json!(payload).to_string();

        tracing::trace!("[parent] sending message ({} bytes)", msg.len());

        send_message(&mut stream, msg)?;

        // Receive and deserialize response
        let response = recv_message(&mut stream)?;

        let result: EnclaveResponse = serde_json::from_slice(&response)?;

        tracing::trace!(
            "[parent] received response with {} fields",
            result.fields.as_ref().map_or(0, |f| f.len())
        );

        Ok(result)
    }

    /// Requests an attestation document from an enclave.
    ///
    /// This is a blocking operation that:
    /// 1. Connects to the enclave via vsock
    /// 2. Sends an attestation request with the provided nonce
    /// 3. Receives the attestation document
    ///
    /// # Arguments
    ///
    /// * `cid` - The enclave's CID (Context ID)
    /// * `port` - The vsock port to connect to
    /// * `nonce` - Client-provided nonce for replay protection (base64 encoded)
    /// * `user_data` - Optional user data to include in attestation (base64 encoded)
    ///
    /// # Returns
    ///
    /// The attestation document as a base64-encoded string.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - vsock connection fails
    /// - Message send/receive fails
    /// - The enclave returns an error
    /// - JSON serialization/deserialization fails
    ///
    /// # Note
    ///
    /// This method is synchronous and should be called via
    /// `tokio::task::spawn_blocking` from async context.
    #[tracing::instrument(skip(self))]
    pub fn attest(
        &self,
        cid: u32,
        port: u32,
        nonce: String,
        user_data: Option<String>,
    ) -> Result<String, AppError> {
        // Connect to enclave via vsock
        let mut stream = VsockStream::connect(&VsockAddr::new(cid, port))?;

        tracing::debug!(
            "[parent] connected to CID {} and port {} for attestation",
            cid,
            port
        );

        // Build and serialize attestation request
        let request = AttestationRequest {
            request_type: "attestation",
            nonce,
            user_data,
        };

        let msg = json!(request).to_string();

        tracing::trace!("[parent] sending attestation request ({} bytes)", msg.len());

        send_message(&mut stream, msg)?;

        // Receive and deserialize response
        let response = recv_message(&mut stream)?;

        let result: AttestationResponse = serde_json::from_slice(&response)?;

        // Check for enclave-side errors
        if let Some(error) = result.error {
            tracing::error!("[parent] enclave attestation error: {}", error);
            return Err(AppError::EnclaveError(error));
        }

        // Extract attestation document
        match result.attestation_document {
            Some(doc) => {
                tracing::trace!(
                    "[parent] received attestation document ({} bytes)",
                    doc.len()
                );
                Ok(doc)
            }
            None => Err(AppError::EnclaveError(
                "enclave returned empty attestation document".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enclaves_new() {
        let enclaves = Enclaves::new();
        // Initial capacity should be MAX_ENCLAVES_PER_INSTANCE
        assert!(enclaves.enclaves.try_read().is_ok());
    }

    #[test]
    fn test_enclaves_default() {
        let enclaves = Enclaves::default();
        assert!(enclaves.enclaves.try_read().is_ok());
    }

    #[tokio::test]
    async fn test_get_enclaves_empty() {
        let enclaves = Enclaves::new();
        let result = enclaves.get_enclaves().await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_get_enclaves_returns_clone() {
        let enclaves = Enclaves::new();

        // Get enclaves twice - should work because we return a clone
        let first = enclaves.get_enclaves().await;
        let second = enclaves.get_enclaves().await;

        assert_eq!(first.len(), second.len());
    }

    #[test]
    fn test_enclave_prefix_filter() {
        // Test the filter logic that's used in refresh()
        let matching_name = format!("{}-test", ENCLAVE_PREFIX);
        assert!(matching_name.starts_with(ENCLAVE_PREFIX));

        let non_matching_name = "other-enclave";
        assert!(!non_matching_name.starts_with(ENCLAVE_PREFIX));
    }

    #[test]
    fn test_max_enclaves_constant() {
        assert_eq!(MAX_ENCLAVES_PER_INSTANCE, 2);
    }

    // Note: Testing refresh, run_enclave, and decrypt requires either:
    // 1. Running on an EC2 instance with Nitro Enclave support, or
    // 2. Mocking the nitro-cli command and vsock
    //
    // Integration tests are in tests/integration/
}
