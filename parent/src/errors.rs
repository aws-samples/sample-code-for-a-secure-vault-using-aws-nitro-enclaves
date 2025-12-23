// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

//! Application error types and HTTP response mapping.
//!
//! This module defines [`AppError`], the central error type for the parent vault.
//! Each error variant maps to an appropriate HTTP status code and JSON response body.

use aws_credential_types::provider::error::CredentialsError;
use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// Application error type with HTTP response mapping.
///
/// Each variant corresponds to a specific error condition and maps to an
/// appropriate HTTP status code when converted to a response.
///
/// # HTTP Status Code Mapping
///
/// | Variant | Status Code |
/// |---------|-------------|
/// | `RunError` | 500 Internal Server Error |
/// | `ExecError` | 500 Internal Server Error |
/// | `EnclaveNotFound` | 404 Not Found |
/// | `DecryptError` | 500 Internal Server Error |
/// | `InternalServerError` | 500 Internal Server Error |
/// | `ValidationError` | 400 Bad Request |
/// | `ConfigError` | 500 Internal Server Error |
#[derive(thiserror::Error, Debug, PartialEq, Clone)]
pub enum AppError {
    /// Error returned when a subprocess (e.g., `nitro-cli`) fails.
    ///
    /// Contains the optional exit code and stderr output.
    #[error("error running command: {0:?} {1}")]
    RunError(Option<i32>, String),

    /// Error returned when a subprocess cannot be executed at all.
    #[error("error executing command")]
    ExecError,

    /// Error returned when no running enclaves are available to process a request.
    #[error("enclave not found")]
    EnclaveNotFound,

    /// Error returned when the enclave fails to decrypt the requested data.
    #[error("unable to decrypt")]
    DecryptError,

    /// Generic internal server error for unexpected failures.
    #[error("internal server error")]
    InternalServerError,

    /// Error returned when request validation fails.
    ///
    /// The message contains details about what validation failed.
    #[error("validation error: {0}")]
    ValidationError(String),

    /// Error returned when application configuration is invalid.
    #[error("configuration error: {0}")]
    ConfigError(String),
}

/// Converts an [`AppError`] into an HTTP response.
///
/// The response body is JSON with the structure:
/// ```json
/// {"code": <status_code>, "message": "<error_message>"}
/// ```
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
            Self::ValidationError(msg) => {
                let message = if msg.is_empty() {
                    "Validation error".to_string()
                } else {
                    msg
                };
                (StatusCode::BAD_REQUEST, message)
            }
            Self::ConfigError(msg) => {
                let message = if msg.is_empty() {
                    "Configuration error".to_string()
                } else {
                    msg
                };
                (StatusCode::INTERNAL_SERVER_ERROR, message)
            }
        };

        let body = Json(json!({"code": status.as_u16(), "message": message}));

        (status, body).into_response()
    }
}

/// Converts JSON parsing errors to [`AppError::InternalServerError`].
impl From<serde_json::Error> for AppError {
    fn from(_source: serde_json::Error) -> Self {
        tracing::error!("{:?}", _source);
        AppError::InternalServerError
    }
}

/// Converts generic errors to [`AppError::InternalServerError`].
impl From<anyhow::Error> for AppError {
    fn from(_source: anyhow::Error) -> Self {
        tracing::error!("{:?}", _source);
        AppError::InternalServerError
    }
}

/// Converts I/O errors to [`AppError::InternalServerError`].
impl From<std::io::Error> for AppError {
    fn from(_source: std::io::Error) -> Self {
        tracing::error!("{:?}", _source);
        AppError::InternalServerError
    }
}

/// Converts AWS credential errors to [`AppError::InternalServerError`].
impl From<CredentialsError> for AppError {
    fn from(_source: CredentialsError) -> Self {
        tracing::error!("{:?}", _source);
        AppError::InternalServerError
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use proptest::prelude::*;

    /// Helper to extract status code from an AppError response.
    fn get_status(error: AppError) -> StatusCode {
        error.into_response().status()
    }

    /// Helper to extract response body as JSON.
    async fn get_body_json(error: AppError) -> serde_json::Value {
        let response = error.into_response();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    /// Strategy to generate arbitrary AppError variants.
    fn arb_app_error() -> impl Strategy<Value = AppError> {
        prop_oneof![
            (any::<Option<i32>>(), any::<String>())
                .prop_map(|(code, msg)| AppError::RunError(code, msg)),
            Just(AppError::ExecError),
            Just(AppError::EnclaveNotFound),
            Just(AppError::DecryptError),
            Just(AppError::InternalServerError),
            any::<String>().prop_map(AppError::ValidationError),
            any::<String>().prop_map(AppError::ConfigError),
        ]
    }

    proptest! {
        /// **Property 1: Error Response Structure Consistency**
        /// **Validates: Requirements 8.1, 8.2**
        ///
        /// *For any* AppError variant, when converted to an HTTP response,
        /// the response body SHALL contain both a `code` field (matching the
        /// HTTP status code) and a `message` field (containing a non-empty string).
        #[test]
        fn prop_error_response_structure_consistency(error in arb_app_error()) {
            // Get the expected status code before consuming the error
            let expected_status = match &error {
                AppError::RunError(_, _) => StatusCode::INTERNAL_SERVER_ERROR,
                AppError::ExecError => StatusCode::INTERNAL_SERVER_ERROR,
                AppError::EnclaveNotFound => StatusCode::NOT_FOUND,
                AppError::DecryptError => StatusCode::INTERNAL_SERVER_ERROR,
                AppError::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
                AppError::ValidationError(_) => StatusCode::BAD_REQUEST,
                AppError::ConfigError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            };

            // Convert error to response
            let response = error.into_response();
            let status = response.status();

            // Verify status code matches expected
            prop_assert_eq!(status, expected_status);

            // Extract body synchronously using tokio runtime
            let body_bytes = tokio_test::block_on(async {
                to_bytes(response.into_body(), usize::MAX).await.unwrap()
            });

            // Parse body as JSON
            let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

            // Verify `code` field exists and matches HTTP status code
            prop_assert!(body.get("code").is_some(), "Response body must contain 'code' field");
            let code = body["code"].as_u64().unwrap();
            prop_assert_eq!(code, expected_status.as_u16() as u64);

            // Verify `message` field exists and is a non-empty string
            prop_assert!(body.get("message").is_some(), "Response body must contain 'message' field");
            let message = body["message"].as_str().unwrap();
            prop_assert!(!message.is_empty(), "Message field must be non-empty");
        }
    }

    #[test]
    fn test_run_error_status_code() {
        let err = AppError::RunError(Some(1), "command failed".to_string());
        assert_eq!(get_status(err), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_exec_error_status_code() {
        assert_eq!(
            get_status(AppError::ExecError),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn test_enclave_not_found_status_code() {
        assert_eq!(get_status(AppError::EnclaveNotFound), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_decrypt_error_status_code() {
        assert_eq!(
            get_status(AppError::DecryptError),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn test_internal_server_error_status_code() {
        assert_eq!(
            get_status(AppError::InternalServerError),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn test_validation_error_status_code() {
        let err = AppError::ValidationError("invalid input".to_string());
        assert_eq!(get_status(err), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_config_error_status_code() {
        let err = AppError::ConfigError("bad config".to_string());
        assert_eq!(get_status(err), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_validation_error_body_contains_message() {
        let err = AppError::ValidationError("field is required".to_string());
        let body = get_body_json(err).await;
        assert_eq!(body["code"], 400);
        assert_eq!(body["message"], "field is required");
    }

    /// Test that ValidationError with empty message falls back to default message.
    /// **Validates: Requirements 8.3**
    #[tokio::test]
    async fn test_validation_error_empty_message_fallback() {
        let err = AppError::ValidationError(String::new());
        let body = get_body_json(err).await;
        assert_eq!(body["code"], 400);
        assert_eq!(body["message"], "Validation error");
    }

    #[tokio::test]
    async fn test_enclave_not_found_body() {
        let body = get_body_json(AppError::EnclaveNotFound).await;
        assert_eq!(body["code"], 404);
        assert_eq!(body["message"], "No enclaves found");
    }

    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let app_err: AppError = io_err.into();
        assert_eq!(app_err, AppError::InternalServerError);
    }

    #[test]
    fn test_from_anyhow_error() {
        let anyhow_err = anyhow::anyhow!("something went wrong");
        let app_err: AppError = anyhow_err.into();
        assert_eq!(app_err, AppError::InternalServerError);
    }

    #[test]
    fn test_app_error_equality() {
        assert_eq!(AppError::ExecError, AppError::ExecError);
        assert_ne!(AppError::ExecError, AppError::EnclaveNotFound);
        assert_eq!(
            AppError::ValidationError("msg".to_string()),
            AppError::ValidationError("msg".to_string())
        );
    }

    #[test]
    fn test_app_error_display() {
        let err = AppError::RunError(Some(1), "failed".to_string());
        assert_eq!(format!("{}", err), "error running command: Some(1) failed");

        let err = AppError::EnclaveNotFound;
        assert_eq!(format!("{}", err), "enclave not found");

        let err = AppError::ValidationError("bad input".to_string());
        assert_eq!(format!("{}", err), "validation error: bad input");
    }
}
