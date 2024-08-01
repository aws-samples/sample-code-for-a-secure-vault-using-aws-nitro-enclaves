// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use std::sync::Arc;

use crate::application::AppState;
use crate::errors::AppError;
use crate::models::{
    Credential, EnclaveDescribeInfo, EnclaveRequest, EnclaveResponse, EnclaveRunInfo,
    ParentRequest, ParentResponse,
};
use crate::{constants, imds};

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use rand::Rng;
use serde_json::json;

pub async fn health() -> impl IntoResponse {
    Json(json!({"status": "ok"}))
}

#[tracing::instrument(skip(state))]
pub async fn get_enclaves(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<EnclaveDescribeInfo>>, AppError> {
    let enclaves = state.enclaves.get_enclaves().await;

    Ok(Json(enclaves))
}

#[tracing::instrument(skip(state))]
pub async fn run_enclave(
    State(state): State<Arc<AppState>>,
) -> Result<Json<EnclaveRunInfo>, AppError> {
    let run_info = state.enclaves.run_enclave().await?;

    Ok(Json(run_info))
}

#[tracing::instrument(skip(state))]
pub async fn get_credentials(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Credential>, AppError> {
    let profile = state.options.role.clone();
    let credentials = imds::load_credentials(profile).await?;
    Ok(Json(credentials))
}

#[tracing::instrument(skip(state, request))]
pub async fn decrypt(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ParentRequest>,
) -> Result<Json<ParentResponse>, AppError> {
    let profile = state.options.role.clone();
    let credential = imds::load_credentials(profile).await?;

    let request = EnclaveRequest {
        credential,
        request,
    };

    let enclaves: Vec<EnclaveDescribeInfo> = state.enclaves.get_enclaves().await;
    if enclaves.is_empty() {
        return Err(AppError::EnclaveNotFound);
    }

    let mut rng = rand::thread_rng();
    let index: usize = rng.gen_range(0..enclaves.len());
    let cid: u32 = enclaves[index]
        .enclave_cid
        .try_into()
        .expect("Invalid enclave CID");

    tracing::debug!("[parent] sending decrypt request to CID: {:?}", cid);

    let response: EnclaveResponse =
        state
            .enclaves
            .decrypt(cid, constants::ENCLAVE_PORT, request)?;

    tracing::debug!("[parent] received response from CID: {:?}", cid);

    let response = ParentResponse {
        fields: response.fields.unwrap_or_default(),
        errors: response.errors,
    };

    Ok(Json(response))
}
