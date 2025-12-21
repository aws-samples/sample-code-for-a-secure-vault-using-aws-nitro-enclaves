// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use std::time::SystemTime;

use aws_config::imds::client::{Client, ImdsResponseRetryClassifier};
use aws_config::imds::credentials::ImdsCredentialsProvider;
use aws_credential_types::provider::ProvideCredentials;
use aws_smithy_runtime_api::client::retries::classifiers::SharedRetryClassifier;
use tokio::sync::RwLock;

use crate::constants;
use crate::errors::AppError;
use crate::models::Credential;

struct CachedCredential {
    credential: Credential,
    expires_at: Option<SystemTime>,
}

pub struct CredentialCache {
    profile: Option<String>,
    cached: RwLock<Option<CachedCredential>>,
}

impl CredentialCache {
    pub fn new(profile: Option<String>) -> Self {
        Self {
            profile,
            cached: RwLock::new(None),
        }
    }

    /// Returns cached credentials if valid, otherwise fetches fresh ones
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

    async fn refresh(&self) -> Result<Credential, AppError> {
        let mut cache = self.cached.write().await;

        // Double-check after acquiring write lock (another thread may have refreshed)
        if let Some(ref cached) = *cache
            && self.is_valid(cached)
        {
            return Ok(cached.credential.clone());
        }

        // Fetch fresh credentials from IMDS
        let (credential, expires_at) = load_credentials_with_expiry(self.profile.clone()).await?;

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

/// Fetches credentials from IMDS and returns them with expiration time
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
