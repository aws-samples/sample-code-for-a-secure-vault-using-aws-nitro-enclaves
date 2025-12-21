// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use aws_credential_types::provider::error::CredentialsError;
use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum AppError {
    #[error("error running command: {0:?} {1}")]
    RunError(Option<i32>, String),
    #[error("error executing command")]
    ExecError,
    #[error("enclave not found")]
    EnclaveNotFound,
    #[error("unable to decrypt")]
    DecryptError,
    #[error("internal server error")]
    InternalServerError,
    #[error("validation error: {0}")]
    ValidationError(String),
    #[error("configuration error: {0}")]
    ConfigError(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::RunError(_, _) => (StatusCode::INTERNAL_SERVER_ERROR, "Run error".to_string()),
            Self::ExecError => (StatusCode::INTERNAL_SERVER_ERROR, "Exec error".to_string()),
            Self::EnclaveNotFound => (StatusCode::NOT_FOUND, "No enclaves found".to_string()),
            Self::DecryptError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to decrypt values".to_string(),
            ),
            Self::InternalServerError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error".to_string(),
            ),
            Self::ValidationError(msg) => (StatusCode::BAD_REQUEST, msg),
            Self::ConfigError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        let body = Json(json!({"code": status.as_u16(), "message": message}));

        (status, body).into_response()
    }
}

impl From<serde_json::Error> for AppError {
    fn from(_source: serde_json::Error) -> Self {
        tracing::error!("{:?}", _source);
        AppError::InternalServerError
    }
}

impl From<anyhow::Error> for AppError {
    fn from(_source: anyhow::Error) -> Self {
        tracing::error!("{:?}", _source);
        AppError::InternalServerError
    }
}

impl From<std::io::Error> for AppError {
    fn from(_source: std::io::Error) -> Self {
        tracing::error!("{:?}", _source);
        AppError::InternalServerError
    }
}

impl From<CredentialsError> for AppError {
    fn from(_source: CredentialsError) -> Self {
        tracing::error!("{:?}", _source);
        AppError::InternalServerError
    }
}
