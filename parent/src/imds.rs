// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use aws_config::imds::client::Client;
use aws_config::imds::credentials::ImdsCredentialsProvider;
use aws_credential_types::provider::ProvideCredentials;

use crate::constants;
use crate::errors::AppError;
use crate::models::Credential;

pub async fn load_credentials(profile: Option<String>) -> Result<Credential, AppError> {
    let client = Client::builder()
        .endpoint("http://169.254.169.254:80") // hardcode IMDS IPv4 address to avoid checking for credentials on the file system
        .expect("valid URL")
        .token_ttl(constants::IMDS_TOKEN_TTL)
        .build();

    let imds = {
        let mut builder = ImdsCredentialsProvider::builder().imds_client(client);
        if let Some(profile) = profile {
            builder = builder.profile(profile);
        }
        builder.build()
    };
    let credentials = imds.provide_credentials().await?;

    Ok(credentials.into())
}
