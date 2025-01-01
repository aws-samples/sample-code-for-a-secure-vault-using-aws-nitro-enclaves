// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use crate::configuration::ParentOptions;
use crate::enclaves::Enclaves;
use crate::routes;
use axum::routing::{get, post};
use axum::serve::Serve;
use axum::Router;
use std::sync::Arc;
use tokio::net::TcpListener;

#[derive(Clone)]
pub struct AppState {
    pub options: ParentOptions,
    pub enclaves: Arc<Enclaves>,
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
        self.server.await
    }
}

#[tracing::instrument(skip(listener, enclaves))]
pub fn run(
    listener: TcpListener,
    options: ParentOptions,
    enclaves: Arc<Enclaves>,
) -> Result<Serve<TcpListener, Router, Router>, std::io::Error> {
    let state = Arc::new(AppState { options, enclaves });

    let app = Router::new()
        .route("/health", get(routes::health))
        .route("/enclaves", get(routes::get_enclaves))
        //.route("/enclaves", post(routes::run_enclave))
        .route("/decrypt", post(routes::decrypt))
        //.route("/creds", get(routes::get_credentials))
        .with_state(state);
    Ok(axum::serve(listener, app))
}
