// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use std::sync::Arc;

use crate::application::AppState;
use crate::constants;
use crate::errors::AppError;
use crate::models::{
    Credential, EnclaveDescribeInfo, EnclaveRequest, EnclaveResponse, EnclaveRunInfo,
    ParentRequest, ParentResponse,
};

use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use serde_json::json;
use validator::Validate;

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
    let credentials = state.credentials.get_credentials().await?;
    Ok(Json(credentials))
}

#[tracing::instrument(skip(state, request))]
pub async fn decrypt(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ParentRequest>,
) -> Result<Json<ParentResponse>, AppError> {
    // Validate request
    request
        .validate()
        .map_err(|e| AppError::ValidationError(e.to_string()))?;

    let credential = state.credentials.get_credentials().await?;

    let request = EnclaveRequest {
        credential,
        request,
    };

    let enclaves: Vec<EnclaveDescribeInfo> = state.enclaves.get_enclaves().await;
    if enclaves.is_empty() {
        return Err(AppError::EnclaveNotFound);
    }

    let index = fastrand::usize(..enclaves.len());
    let cid: u32 = enclaves[index]
        .enclave_cid
        .try_into()
        .map_err(|_| AppError::InternalServerError)?;

    tracing::debug!("[parent] sending decrypt request to CID: {:?}", cid);

    let enclaves_ref = state.enclaves.clone();
    let port = constants::ENCLAVE_PORT;
    let response: EnclaveResponse =
        tokio::task::spawn_blocking(move || enclaves_ref.decrypt(cid, port, request))
            .await
            .map_err(|_| AppError::InternalServerError)??;

    tracing::debug!("[parent] received response from CID: {:?}", cid);

    let response = ParentResponse {
        fields: response.fields.unwrap_or_default(),
        errors: response.errors,
    };

    Ok(Json(response))
}
