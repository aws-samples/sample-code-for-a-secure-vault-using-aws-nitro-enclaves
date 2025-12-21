// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

//! Command-line argument parsing and configuration.
//!
//! This module defines [`ParentOptions`] which can be configured via command-line
//! arguments or environment variables.
//!
//! # Environment Variables
//!
//! | Variable | Description | Default |
//! |----------|-------------|---------|
//! | `PARENT_HTTP_HOST` | HTTP server listen address | `127.0.0.1` |
//! | `PARENT_HTTP_PORT` | HTTP server listen port | `8080` |
//! | `PARENT_ROLE_NAME` | IAM role name for credential assumption | None |
//! | `PARENT_SKIP_REFRESH_ENCLAVES` | Skip automatic enclave refresh | `false` |
//! | `PARENT_SKIP_RUN_ENCLAVES` | Skip launching new enclaves | `false` |

use clap::{ArgAction, Parser};

/// Configuration options for the parent vault application.
///
/// Options can be set via command-line arguments or environment variables.
/// Environment variables take the form `PARENT_*` (e.g., `PARENT_HTTP_PORT`).
///
/// # Example
///
/// ```bash
/// # Via command line
/// parent-vault --host 0.0.0.0 --port 9090 --role my-role
///
/// # Via environment variables
/// PARENT_HTTP_HOST=0.0.0.0 PARENT_HTTP_PORT=9090 parent-vault
/// ```
#[derive(Debug, Clone, Parser)]
#[command(author, version, about, long_about = None)]
pub struct ParentOptions {
    /// The address to bind the HTTP server to.
    ///
    /// Use `0.0.0.0` to listen on all interfaces.
    #[arg(long, default_value = "127.0.0.1", env("PARENT_HTTP_HOST"))]
    pub host: String,

    /// The port to bind the HTTP server to.
    #[arg(long, default_value = "8080", env("PARENT_HTTP_PORT"))]
    pub port: u16,

    /// Optional IAM role name for credential assumption.
    ///
    /// If not specified, the instance's default IAM role is used.
    #[arg(long, default_value = "None", env("PARENT_ROLE_NAME"))]
    pub role: Option<String>,

    /// Skip the background enclave refresh loop.
    ///
    /// When enabled, the parent will not periodically check enclave status
    /// or launch new enclaves.
    #[arg(long, default_value = "false", env("PARENT_SKIP_REFRESH_ENCLAVES"), action = ArgAction::SetTrue)]
    pub skip_refresh_enclaves: bool,

    /// Skip launching new enclaves during refresh.
    ///
    /// When enabled, the parent will describe existing enclaves but will
    /// not launch new ones if fewer than [`crate::constants::MAX_ENCLAVES_PER_INSTANCE`] are running.
    #[arg(long, default_value = "false", env("PARENT_SKIP_RUN_ENCLAVES"), action = ArgAction::SetTrue)]
    pub skip_run_enclaves: bool,
}

/// Default configuration suitable for local development and testing.
///
/// Note: Both `skip_refresh_enclaves` and `skip_run_enclaves` are `true`
/// in the default configuration to avoid requiring Nitro Enclave support
/// during development.
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_default_options() {
        let opts = ParentOptions::default();
        assert_eq!(opts.host, "127.0.0.1");
        assert_eq!(opts.port, 8080);
        assert!(opts.role.is_none());
        assert!(opts.skip_refresh_enclaves);
        assert!(opts.skip_run_enclaves);
    }

    #[test]
    fn test_parse_with_defaults() {
        let opts = ParentOptions::try_parse_from(["test"]).unwrap();
        assert_eq!(opts.host, "127.0.0.1");
        assert_eq!(opts.port, 8080);
    }

    #[test]
    fn test_parse_with_custom_host() {
        let opts = ParentOptions::try_parse_from(["test", "--host", "0.0.0.0"]).unwrap();
        assert_eq!(opts.host, "0.0.0.0");
    }

    #[test]
    fn test_parse_with_custom_port() {
        let opts = ParentOptions::try_parse_from(["test", "--port", "9090"]).unwrap();
        assert_eq!(opts.port, 9090);
    }

    #[test]
    fn test_parse_with_role() {
        let opts = ParentOptions::try_parse_from(["test", "--role", "my-iam-role"]).unwrap();
        assert_eq!(opts.role, Some("my-iam-role".to_string()));
    }

    #[test]
    fn test_parse_skip_refresh_flag() {
        let opts = ParentOptions::try_parse_from(["test", "--skip-refresh-enclaves"]).unwrap();
        assert!(opts.skip_refresh_enclaves);
    }

    #[test]
    fn test_parse_skip_run_flag() {
        let opts = ParentOptions::try_parse_from(["test", "--skip-run-enclaves"]).unwrap();
        assert!(opts.skip_run_enclaves);
    }

    #[test]
    fn test_parse_all_flags() {
        let opts = ParentOptions::try_parse_from([
            "test",
            "--host",
            "0.0.0.0",
            "--port",
            "3000",
            "--role",
            "vault-role",
            "--skip-refresh-enclaves",
            "--skip-run-enclaves",
        ])
        .unwrap();
        assert_eq!(opts.host, "0.0.0.0");
        assert_eq!(opts.port, 3000);
        assert_eq!(opts.role, Some("vault-role".to_string()));
        assert!(opts.skip_refresh_enclaves);
        assert!(opts.skip_run_enclaves);
    }

    #[test]
    fn test_invalid_port_fails() {
        let result = ParentOptions::try_parse_from(["test", "--port", "not-a-number"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_port_out_of_range_fails() {
        let result = ParentOptions::try_parse_from(["test", "--port", "99999"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_clone() {
        let opts = ParentOptions::default();
        let cloned = opts.clone();
        assert_eq!(cloned.host, opts.host);
        assert_eq!(cloned.port, opts.port);
    }

    #[test]
    fn test_debug() {
        let opts = ParentOptions::default();
        let debug = format!("{:?}", opts);
        assert!(debug.contains("ParentOptions"));
        assert!(debug.contains("127.0.0.1"));
        assert!(debug.contains("8080"));
    }
}
