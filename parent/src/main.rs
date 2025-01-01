// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use clap::Parser;
use parent_vault::configuration::ParentOptions;
use parent_vault::enclaves::Enclaves;
use parent_vault::{application::Application, constants};
use std::{io::Error, sync::Arc};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Error> {
    println!("[parent] init");

    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,tower_http=debug".into()),
        ))
        // this needs to be set to remove duplicated information in the log.
        .with_current_span(false)
        // this needs to be set to false, otherwise ANSI color codes will
        // show up in a confusing manner in CloudWatch logs.
        .with_ansi(false)
        // disabling time is handy because CloudWatch will add the ingestion time.
        .without_time()
        // remove the name of the function from every log entry
        .with_target(false)
        .init();

    // get configuration options from environment variables
    let options = ParentOptions::parse();

    tracing::info!("[parent] {:?}", &options);

    let enclaves = Arc::new(Enclaves::new());

    if !options.skip_refresh_enclaves {
        tracing::info!(
            "[parent] refreshing enclaves every {:#?}",
            constants::REFRESH_ENCLAVES_INTERVAL
        );
        let enclaves_mut = enclaves.clone();
        tokio::spawn(async move {
            loop {
                let _ = enclaves_mut.refresh(options.skip_run_enclaves).await;
                tracing::debug!(
                    "[parent] refreshed enclaves, sleeping for {:#?}",
                    constants::REFRESH_ENCLAVES_INTERVAL
                );
                tokio::time::sleep(constants::REFRESH_ENCLAVES_INTERVAL).await;
            }
        });
    } else {
        tracing::warn!("[parent] skipping refreshing enclaves");
    }

    let application = Application::build(options, enclaves).await.unwrap();

    application.run_until_stopped().await.map_err(Error::from)
}
