// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use crate::configuration::ParentOptions;
use crate::enclaves::Enclaves;
use crate::imds::CredentialCache;
use crate::routes;
use axum::Router;
use axum::routing::{get, post};
use axum::serve::Serve;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

pub struct AppState {
    pub options: ParentOptions,
    pub enclaves: Arc<Enclaves>,
    pub credentials: Arc<CredentialCache>,
}

pub struct Application {
    port: u16,
    server: Serve<TcpListener, Router, Router>,
}

impl Application {
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

    pub fn port(&self) -> u16 {
        self.port
    }

    pub async fn run_until_stopped(self) -> Result<(), std::io::Error> {
        self.server.with_graceful_shutdown(shutdown_signal()).await
    }
}

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

// Request body limit: 1 MB
const REQUEST_BODY_LIMIT: usize = 1024 * 1024;
// Request timeout: 30 seconds
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

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

    // Rate limiting: 100 requests per second per IP
    let governor_config = GovernorConfigBuilder::default()
        .per_second(100)
        .burst_size(100)
        .finish()
        .expect("valid governor config");

    let app = Router::new()
        .route("/health", get(routes::health))
        .route("/enclaves", get(routes::get_enclaves))
        //.route("/enclaves", post(routes::run_enclave))
        .route("/decrypt", post(routes::decrypt))
        //.route("/creds", get(routes::get_credentials))
        .with_state(state)
        .layer(RequestBodyLimitLayer::new(REQUEST_BODY_LIMIT))
        .layer(TimeoutLayer::new(REQUEST_TIMEOUT))
        .layer(GovernorLayer::new(Arc::new(governor_config)));
    Ok(axum::serve(listener, app))
}
