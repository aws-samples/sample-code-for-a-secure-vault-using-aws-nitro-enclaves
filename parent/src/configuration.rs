// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use clap::{ArgAction, Parser};

#[derive(Debug, Clone, Parser)]
#[command(author, version, about, long_about = None)]
pub struct ParentOptions {
    #[arg(long, default_value = "127.0.0.1", env("PARENT_HTTP_HOST"))]
    pub host: String,
    #[arg(long, default_value = "8080", env("PARENT_HTTP_PORT"))]
    pub port: u16,
    #[arg(long, default_value = "None", env("PARENT_ROLE_NAME"))]
    pub role: Option<String>,
    #[arg(long, default_value = "false", env("PARENT_SKIP_REFRESH_ENCLAVES"), action = ArgAction::SetTrue)]
    pub skip_refresh_enclaves: bool,
    #[arg(long, default_value = "false", env("PARENT_SKIP_RUN_ENCLAVES"), action = ArgAction::SetTrue)]
    pub skip_run_enclaves: bool,
}

impl Default for ParentOptions {
    fn default() -> Self {
        ParentOptions {
            host: "127.0.0.1".to_string(),
            port: 8080,
            role: None,
            skip_refresh_enclaves: true,
            skip_run_enclaves: true,
        }
    }
}
