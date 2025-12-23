// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

//! HTTP route handlers for the parent vault API.
//!
//! This module provides the following endpoints:
//!
//! | Method | Path | Handler | Description |
//! |--------|------|---------|-------------|
//! | GET | `/health` | [`health`] | Health check endpoint |
//! | GET | `/enclaves` | [`get_enclaves`] | List running enclaves |
//! | POST | `/decrypt` | [`decrypt`] | Decrypt vault fields |
//!
//! Additional endpoints (currently disabled):
//! - POST `/enclaves` - Launch a new enclave
//! - GET `/creds` - Get current IAM credentials

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

/// Health check endpoint.
///
/// Returns a simple JSON response indicating the service is running.
///
/// # Response
///
/// ```json
/// {"status": "ok"}
/// ```
pub async fn health() -> impl IntoResponse {
    Json(json!({"status": "ok"}))
}

/// Lists all running Nitro Enclaves.
///
/// Returns information about all enclaves that match the vault prefix.
///
/// # Response
///
/// A JSON array of [`EnclaveDescribeInfo`] objects.
#[tracing::instrument(skip(state))]
pub async fn get_enclaves(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<EnclaveDescribeInfo>>, AppError> {
    let enclaves = state.enclaves.get_enclaves().await;

    Ok(Json(enclaves))
}

/// Launches a new Nitro Enclave.
///
/// This endpoint is currently disabled in the router configuration.
///
/// # Response
///
/// Returns [`EnclaveRunInfo`] on success.
#[tracing::instrument(skip(state))]
pub async fn run_enclave(
    State(state): State<Arc<AppState>>,
) -> Result<Json<EnclaveRunInfo>, AppError> {
    let run_info = state.enclaves.run_enclave().await?;

    Ok(Json(run_info))
}

/// Returns the current IAM credentials.
///
/// This endpoint is currently disabled in the router configuration.
///
/// # Response
///
/// Returns [`Credential`] on success.
#[tracing::instrument(skip(state))]
pub async fn get_credentials(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Credential>, AppError> {
    let credentials = state.credentials.get_credentials().await?;
    Ok(Json(credentials))
}

/// Decrypts vault fields using a Nitro Enclave.
///
/// This is the main endpoint for decrypting PII/PHI data stored in the vault.
/// The request is validated, then forwarded to an available enclave over vsock.
///
/// # Request Flow
///
/// 1. Validate the incoming [`ParentRequest`]
/// 2. Check for available enclaves
/// 3. Fetch IAM credentials from the cache (or IMDS if expired)
/// 4. Select a random available enclave for load balancing
/// 5. Send the request to the enclave over vsock
/// 6. Return the decrypted response
///
/// # Errors
///
/// - [`AppError::ValidationError`] - Request validation failed
/// - [`AppError::EnclaveNotFound`] - No enclaves available
/// - [`AppError::InternalServerError`] - Credential or enclave communication failure
#[tracing::instrument(skip(state, request))]
pub async fn decrypt(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ParentRequest>,
) -> Result<Json<ParentResponse>, AppError> {
    // 1. Validate incoming request against size limits and format rules
    tracing::debug!(
        "[parent] validating decrypt request for vault_id: {}",
        request.vault_id
    );
    request.validate().map_err(|e| {
        tracing::error!("[parent] validation failed: {}", e);
        AppError::ValidationError(e.to_string())
    })?;

    // 2. Get available enclaves early to fail fast if none are available
    let enclaves: Vec<EnclaveDescribeInfo> = state.enclaves.get_enclaves().await;
    if enclaves.is_empty() {
        return Err(AppError::EnclaveNotFound);
    }

    // 3. Fetch (or use cached) IAM credentials from IMDS
    tracing::debug!("[parent] fetching credentials from cache");
    let credential = state.credentials.get_credentials().await.map_err(|e| {
        tracing::error!("[parent] failed to get credentials: {:?}", e);
        e
    })?;
    tracing::debug!("[parent] credentials retrieved successfully");

    let request = EnclaveRequest {
        credential,
        request,
    };

    // 4. Select a random enclave for load balancing
    let index = fastrand::usize(..enclaves.len());
    let enclave = enclaves.get(index).ok_or(AppError::EnclaveNotFound)?;
    let cid: u32 = enclave
        .enclave_cid
        .try_into()
        .map_err(|_| AppError::InternalServerError)?;

    tracing::debug!("[parent] sending decrypt request to CID: {:?}", cid);

    // 5. Send request to enclave via vsock (blocking operation)
    // spawn_blocking is used because vsock I/O is synchronous
    let enclaves_ref = state.enclaves.clone();
    let port = constants::ENCLAVE_PORT;
    let response: EnclaveResponse =
        tokio::task::spawn_blocking(move || enclaves_ref.decrypt(cid, port, request))
            .await
            .map_err(|e| {
                tracing::error!("[parent] spawn_blocking task failed: {:?}", e);
                AppError::InternalServerError
            })?
            .map_err(|e| {
                tracing::error!("[parent] enclave decrypt failed: {:?}", e);
                e
            })?;

    tracing::debug!("[parent] received response from CID: {:?}", cid);

    // 6. Transform enclave response to parent response format
    let response = ParentResponse {
        fields: response.fields.unwrap_or_default(),
        errors: response.errors,
    };

    Ok(Json(response))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::StatusCode;

    // Unit tests for route handlers (testing handler functions directly)
    // Integration tests using TestServer are in tests/http_integration.rs

    #[tokio::test]
    async fn test_health_returns_ok() {
        let response = health().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");
    }

    #[tokio::test]
    async fn test_health_response_structure() {
        let response = health().await.into_response();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Should have exactly one key
        assert_eq!(json.as_object().unwrap().len(), 1);
        assert!(json.get("status").is_some());
    }
}
