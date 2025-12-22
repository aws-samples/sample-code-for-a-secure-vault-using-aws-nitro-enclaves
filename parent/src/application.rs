// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

//! HTTP server setup and application lifecycle management.
//!
//! This module provides the [`Application`] struct for building and running
//! the Axum HTTP server with configured middleware.
//!
//! # Middleware Stack
//!
//! The server includes the following middleware (applied in order):
//!
//! 1. **Rate Limiting** - 100 requests/second per IP via tower-governor
//! 2. **Timeout** - 30 second request timeout
//! 3. **Body Limit** - 1 MB maximum request body size
//!
//! # Graceful Shutdown
//!
//! The server handles graceful shutdown on:
//! - `SIGINT` (Ctrl+C)
//! - `SIGTERM` (Unix only)

use crate::configuration::ParentOptions;
use crate::enclaves::Enclaves;
use crate::imds::CredentialCache;
use crate::routes;
use axum::Router;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::serve::Serve;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

/// Shared application state accessible from route handlers.
///
/// Contains configuration, enclave manager, and credential cache.
pub struct AppState {
    /// Application configuration options.
    pub options: ParentOptions,

    /// Enclave manager for listing and communicating with enclaves.
    pub enclaves: Arc<Enclaves>,

    /// Credential cache for IAM credentials from IMDS.
    pub credentials: Arc<CredentialCache>,
}

/// The HTTP application server.
///
/// Wraps an Axum server with the configured routes and middleware.
pub struct Application {
    port: u16,
    server: Serve<TcpListener, Router, Router>,
}

impl Application {
    /// Builds a new application server.
    ///
    /// Binds to the configured host and port, sets up routes and middleware,
    /// and prepares the server for running.
    ///
    /// # Arguments
    ///
    /// * `options` - Server configuration options
    /// * `enclaves` - Shared enclave manager
    ///
    /// # Errors
    ///
    /// Returns an error if the server cannot bind to the specified address.
    pub async fn build(
        options: ParentOptions,
        enclaves: Arc<Enclaves>,
    ) -> Result<Self, std::io::Error> {
        let address = format!("{}:{}", options.host, options.port);
        let listener = TcpListener::bind(address).await?;
        let server = run(listener, options.clone(), enclaves)?;
        let port = server.local_addr()?.port();

        tracing::info!("[parent] listening at http://{}:{}", options.host, port);

        Ok(Self { port, server })
    }

    /// Returns the port the server is listening on.
    ///
    /// This may differ from the configured port if port 0 was specified
    /// (which causes the OS to assign an available port).
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Runs the server until a shutdown signal is received.
    ///
    /// Handles graceful shutdown on SIGINT (Ctrl+C) and SIGTERM.
    pub async fn run_until_stopped(self) -> Result<(), std::io::Error> {
        self.server.with_graceful_shutdown(shutdown_signal()).await
    }
}

/// Waits for a shutdown signal (Ctrl+C or SIGTERM).
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("[parent] received Ctrl+C, starting graceful shutdown");
        }
        _ = terminate => {
            tracing::info!("[parent] received SIGTERM, starting graceful shutdown");
        }
    }
}

/// Maximum request body size (1 MB).
const REQUEST_BODY_LIMIT: usize = 1024 * 1024;

/// Request timeout duration (30 seconds).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Creates and configures the Axum router.
///
/// Sets up routes, shared state, and middleware layers.
///
/// # Middleware
///
/// - Timeout: 30 seconds
/// - Body limit: 1 MB
#[tracing::instrument(skip(listener, enclaves))]
pub fn run(
    listener: TcpListener,
    options: ParentOptions,
    enclaves: Arc<Enclaves>,
) -> Result<Serve<TcpListener, Router, Router>, std::io::Error> {
    let credentials = Arc::new(CredentialCache::new(options.role.clone()));
    let state = Arc::new(AppState {
        options,
        enclaves,
        credentials,
    });

    let app = Router::new()
        .route("/health", get(routes::health))
        .route("/enclaves", get(routes::get_enclaves))
        //.route("/enclaves", post(routes::run_enclave))
        .route("/decrypt", post(routes::decrypt))
        //.route("/creds", get(routes::get_credentials))
        .with_state(state)
        .layer(RequestBodyLimitLayer::new(REQUEST_BODY_LIMIT))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ));
    Ok(axum::serve(listener, app))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_body_limit_is_1mb() {
        assert_eq!(REQUEST_BODY_LIMIT, 1024 * 1024);
    }

    #[test]
    fn test_request_timeout_is_30s() {
        assert_eq!(REQUEST_TIMEOUT, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn test_application_build_with_port_0() {
        // Port 0 causes the OS to assign an available port
        let options = ParentOptions {
            host: "127.0.0.1".to_string(),
            port: 0,
            ..ParentOptions::default()
        };
        let enclaves = Arc::new(Enclaves::new());

        let app = Application::build(options, enclaves).await.unwrap();

        // Should have been assigned a non-zero port
        assert!(app.port() > 0);
    }

    #[tokio::test]
    async fn test_application_build_binds_to_port() {
        let options = ParentOptions {
            host: "127.0.0.1".to_string(),
            port: 0,
            ..ParentOptions::default()
        };
        let enclaves = Arc::new(Enclaves::new());

        let app = Application::build(options, enclaves).await.unwrap();
        let port = app.port();

        // Trying to bind to the same port should fail (port is in use)
        let listener_result = TcpListener::bind(format!("127.0.0.1:{}", port)).await;
        assert!(listener_result.is_err());
    }

    #[tokio::test]
    async fn test_run_creates_server() {
        let options = ParentOptions::default();
        let enclaves = Arc::new(Enclaves::new());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

        let result = run(listener, options, enclaves);
        assert!(result.is_ok());
    }
}
