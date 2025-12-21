// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

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

pub struct Enclaves {
    enclaves: RwLock<Vec<EnclaveDescribeInfo>>,
}

impl Default for Enclaves {
    fn default() -> Self {
        Self::new()
    }
}

impl Enclaves {
    pub fn new() -> Self {
        Self {
            enclaves: RwLock::new(Vec::with_capacity(constants::MAX_ENCLAVES_PER_INSTANCE)),
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_enclaves(&self) -> Vec<EnclaveDescribeInfo> {
        let enclaves = self.enclaves.read().await;
        enclaves.clone()
    }

    #[tracing::instrument(skip(self))]
    pub async fn refresh(&self, skip_run_enclaves: bool) -> Result<(), AppError> {
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

        let mut enclaves_writer = self.enclaves.write().await;
        enclaves_writer.clear();
        enclaves_writer.extend(enclaves.into_iter().filter(|e| {
            e.enclave_name
                .as_ref()
                .is_some_and(|name| name.starts_with(ENCLAVE_PREFIX))
        }));

        Ok(())
    }

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

    #[tracing::instrument(skip(self, payload))]
    pub fn decrypt(
        &self,
        cid: u32,
        port: u32,
        payload: EnclaveRequest,
    ) -> Result<EnclaveResponse, AppError> {
        let mut stream = VsockStream::connect(&VsockAddr::new(cid, port))?;

        tracing::debug!("[parent] connected to CID {} and port {}", cid, port);

        let msg = json!(payload).to_string();

        tracing::trace!("[parent] sending message ({} bytes)", msg.len());

        send_message(&mut stream, msg)?;

        let response = recv_message(&mut stream)?;

        let result: EnclaveResponse = serde_json::from_slice(&response)?;

        tracing::trace!(
            "[parent] received response with {} fields",
            result.fields.as_ref().map_or(0, |f| f.len())
        );

        Ok(result)
    }
}
