// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

//! IAM credential caching from EC2 Instance Metadata Service (IMDS).
//!
//! This module provides [`CredentialCache`] which manages IAM credentials
//! for AWS service access. Credentials are fetched from IMDS and cached
//! with automatic refresh before expiry.
//!
//! # Caching Strategy
//!
//! - Credentials are cached after first fetch
//! - Cache is checked before every credential request
//! - Refresh is triggered when credentials are within
//!   [`CREDENTIAL_REFRESH_BUFFER`](crate::constants::CREDENTIAL_REFRESH_BUFFER) of expiry
//! - Thread-safe via [`RwLock`] with double-check locking pattern
//!
//! # IMDS Configuration
//!
//! - Endpoint: `http://169.254.169.254:80`
//! - Token TTL: 5 minutes (configurable via [`IMDS_TOKEN_TTL`](crate::constants::IMDS_TOKEN_TTL))
//! - Automatic retry on connection timeouts

use std::time::SystemTime;

use aws_config::imds::client::{Client, ImdsResponseRetryClassifier};
use aws_config::imds::credentials::ImdsCredentialsProvider;
use aws_credential_types::provider::ProvideCredentials;
use aws_smithy_runtime_api::client::retries::classifiers::SharedRetryClassifier;
use tokio::sync::RwLock;

use crate::constants;
use crate::errors::AppError;
use crate::models::Credential;

/// Cached credential with expiration time.
struct CachedCredential {
    /// The actual credential.
    credential: Credential,
    /// When the credential expires (None = never).
    expires_at: Option<SystemTime>,
}

/// Thread-safe cache for IAM credentials fetched from IMDS.
///
/// This cache automatically refreshes credentials before they expire,
/// ensuring uninterrupted access to AWS services.
///
/// # Thread Safety
///
/// Uses [`RwLock`] internally for concurrent read access with exclusive
/// write access during refresh. A double-check locking pattern prevents
/// redundant refreshes when multiple threads detect expiry simultaneously.
pub struct CredentialCache {
    /// Optional IAM role/profile name. If None, uses instance default.
    profile: Option<String>,
    /// The cached credential with RwLock for thread safety.
    cached: RwLock<Option<CachedCredential>>,
}

impl CredentialCache {
    /// Creates a new credential cache for the specified IAM role.
    ///
    /// # Arguments
    ///
    /// * `profile` - Optional IAM role name. If `None`, uses the instance's
    ///   default role.
    pub fn new(profile: Option<String>) -> Self {
        Self {
            profile,
            cached: RwLock::new(None),
        }
    }

    /// Returns cached credentials if valid, otherwise fetches fresh ones.
    ///
    /// Credentials are considered valid if they won't expire within the
    /// refresh buffer period (60 seconds by default).
    ///
    /// # Errors
    ///
    /// Returns `AppError::ConfigError` if IMDS client setup fails.
    /// Returns `AppError::InternalServerError` for credential fetch failures.
    pub async fn get_credentials(&self) -> Result<Credential, AppError> {
        // Fast path: check if cached credentials are still valid
        {
            let cache = self.cached.read().await;
            if let Some(ref cached) = *cache
                && self.is_valid(cached)
            {
                return Ok(cached.credential.clone());
            }
        }

        // Slow path: refresh credentials
        self.refresh().await
    }

    /// Checks if cached credentials are still valid.
    ///
    /// A credential is valid if:
    /// - It has no expiry time (permanent credentials), OR
    /// - Current time + refresh buffer < expiry time
    fn is_valid(&self, cached: &CachedCredential) -> bool {
        match cached.expires_at {
            Some(expires_at) => {
                let now = SystemTime::now();
                let buffer = constants::CREDENTIAL_REFRESH_BUFFER;
                // Valid if now + buffer < expires_at
                now.checked_add(buffer)
                    .map(|threshold| threshold < expires_at)
                    .unwrap_or(false)
            }
            None => true, // No expiry = always valid
        }
    }

    /// Refreshes credentials from IMDS.
    ///
    /// Uses double-check locking to prevent redundant refreshes when
    /// multiple threads detect expiry simultaneously.
    async fn refresh(&self) -> Result<Credential, AppError> {
        tracing::debug!("[parent] refreshing credentials from IMDS");
        let mut cache = self.cached.write().await;

        // Double-check after acquiring write lock (another thread may have refreshed)
        if let Some(ref cached) = *cache
            && self.is_valid(cached)
        {
            tracing::debug!("[parent] credentials already refreshed by another thread");
            return Ok(cached.credential.clone());
        }

        // Fetch fresh credentials from IMDS
        let (credential, expires_at) = load_credentials_with_expiry(self.profile.clone())
            .await
            .map_err(|e| {
                tracing::error!("[parent] failed to load credentials from IMDS: {:?}", e);
                e
            })?;

        tracing::debug!(
            "[parent] refreshed IMDS credentials, expires_at: {:?}",
            expires_at
        );

        *cache = Some(CachedCredential {
            credential: credential.clone(),
            expires_at,
        });

        Ok(credential)
    }
}

/// Fetches credentials from IMDS and returns them with expiration time.
///
/// # Arguments
///
/// * `profile` - Optional IAM role name
///
/// # Returns
///
/// A tuple of (credential, optional expiry time).
async fn load_credentials_with_expiry(
    profile: Option<String>,
) -> Result<(Credential, Option<SystemTime>), AppError> {
    let client = Client::builder()
        .endpoint("http://169.254.169.254:80")
        .map_err(|e| AppError::ConfigError(e.to_string()))?
        .token_ttl(constants::IMDS_TOKEN_TTL)
        .retry_classifier(SharedRetryClassifier::new(
            ImdsResponseRetryClassifier::default().with_retry_connect_timeouts(true),
        ))
        .build();

    let imds = {
        let mut builder = ImdsCredentialsProvider::builder().imds_client(client);
        if let Some(profile) = profile {
            builder = builder.profile(profile);
        }
        builder.build()
    };

    let credentials = imds.provide_credentials().await?;
    let expires_at = credentials.expiry();

    Ok((credentials.into(), expires_at))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_credential_cache_new() {
        let cache = CredentialCache::new(None);
        assert!(cache.profile.is_none());
    }

    #[test]
    fn test_credential_cache_new_with_profile() {
        let cache = CredentialCache::new(Some("my-role".to_string()));
        assert_eq!(cache.profile, Some("my-role".to_string()));
    }

    #[tokio::test]
    async fn test_is_valid_no_expiry() {
        let cache = CredentialCache::new(None);
        let cached = CachedCredential {
            credential: Credential {
                access_key_id: "AKIA123".to_string(),
                secret_access_key: "secret".to_string(),
                session_token: "token".to_string(),
            },
            expires_at: None,
        };
        assert!(cache.is_valid(&cached));
    }

    #[tokio::test]
    async fn test_is_valid_far_future_expiry() {
        let cache = CredentialCache::new(None);
        let cached = CachedCredential {
            credential: Credential {
                access_key_id: "AKIA123".to_string(),
                secret_access_key: "secret".to_string(),
                session_token: "token".to_string(),
            },
            expires_at: Some(SystemTime::now() + Duration::from_secs(3600)), // 1 hour
        };
        assert!(cache.is_valid(&cached));
    }

    #[tokio::test]
    async fn test_is_valid_within_refresh_buffer() {
        let cache = CredentialCache::new(None);
        let cached = CachedCredential {
            credential: Credential {
                access_key_id: "AKIA123".to_string(),
                secret_access_key: "secret".to_string(),
                session_token: "token".to_string(),
            },
            // Expires in 30 seconds, but buffer is 60 seconds
            expires_at: Some(SystemTime::now() + Duration::from_secs(30)),
        };
        // Should be invalid because we're within the refresh buffer
        assert!(!cache.is_valid(&cached));
    }

    #[tokio::test]
    async fn test_is_valid_expired() {
        let cache = CredentialCache::new(None);
        let cached = CachedCredential {
            credential: Credential {
                access_key_id: "AKIA123".to_string(),
                secret_access_key: "secret".to_string(),
                session_token: "token".to_string(),
            },
            expires_at: Some(SystemTime::now() - Duration::from_secs(1)), // Already expired
        };
        assert!(!cache.is_valid(&cached));
    }

    #[tokio::test]
    async fn test_is_valid_just_outside_buffer() {
        let cache = CredentialCache::new(None);
        let cached = CachedCredential {
            credential: Credential {
                access_key_id: "AKIA123".to_string(),
                secret_access_key: "secret".to_string(),
                session_token: "token".to_string(),
            },
            // Expires in 120 seconds, buffer is 60 seconds, so should be valid
            expires_at: Some(SystemTime::now() + Duration::from_secs(120)),
        };
        assert!(cache.is_valid(&cached));
    }

    // Note: Testing get_credentials and refresh requires either:
    // 1. Running on an EC2 instance with IMDS available, or
    // 2. Using wiremock to mock the IMDS endpoint
    //
    // Integration tests with wiremock are in tests/integration/
}
