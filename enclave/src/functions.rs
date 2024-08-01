// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use aws_lc_rs::digest;
use base64::prelude::*;
use cel_interpreter::{extractors::This, FunctionContext, ResolveResult};
use chrono::{DateTime, FixedOffset, NaiveDate, NaiveTime, TimeZone, Utc};
use std::sync::Arc;

/// Default functions available:
/// https://github.com/clarkmcc/cel-rust/blob/master/interpreter/src/context.rs#L143

/// String Functions

pub fn is_empty(This(this): This<Arc<String>>) -> bool {
    this.is_empty()
}

pub fn to_lowercase(This(this): This<Arc<String>>) -> String {
    this.to_lowercase()
}

pub fn to_uppercase(This(this): This<Arc<String>>) -> String {
    this.to_uppercase()
}

/// Hash Functions

pub fn hmac_sha256(This(this): This<Arc<String>>) -> String {
    let digest = digest::digest(&digest::SHA256, this.as_bytes());
    hex::encode(digest.as_ref())
}

pub fn hmac_sha384(This(this): This<Arc<String>>) -> String {
    let digest = digest::digest(&digest::SHA384, this.as_bytes());
    hex::encode(digest.as_ref())
}

pub fn hmac_sha512(This(this): This<Arc<String>>) -> String {
    let digest = digest::digest(&digest::SHA512, this.as_bytes());
    hex::encode(digest.as_ref())
}

/// Hex Functions

pub fn hex_encode(This(this): This<Arc<String>>) -> String {
    hex::encode(this.as_bytes())
}

pub fn hex_decode(ftx: &FunctionContext, This(this): This<Arc<String>>) -> ResolveResult {
    match hex::decode(this.as_bytes()) {
        Ok(val) => match String::from_utf8(val) {
            Ok(result) => Ok(result.into()),
            Err(e) => ftx.error(e.to_string()).into(),
        },
        Err(e) => ftx.error(e.to_string()).into(),
    }
}

/// Base64 Functions

pub fn base64_encode(This(this): This<Arc<String>>) -> String {
    BASE64_STANDARD.encode(this.as_bytes())
}

pub fn base64_decode(ftx: &FunctionContext, This(this): This<Arc<String>>) -> ResolveResult {
    match BASE64_STANDARD.decode(this.as_str()) {
        Ok(val) => match String::from_utf8(val) {
            Ok(result) => Ok(result.into()),
            Err(e) => ftx.error(e.to_string()).into(),
        },
        Err(e) => ftx.error(e.to_string()).into(),
    }
}

/// Datetime Functions

pub fn date(ftx: &FunctionContext, This(this): This<Arc<String>>) -> ResolveResult {
    match NaiveDate::parse_from_str(&this, "%Y-%m-%d") {
        Ok(date) => {
            let tz_offset = FixedOffset::east_opt(0).unwrap();
            let datetime = date.and_time(NaiveTime::default());
            let dt_with_tz: DateTime<FixedOffset> =
                tz_offset.from_local_datetime(&datetime).unwrap();
            Ok(dt_with_tz.into())
        }
        Err(e) => ftx.error(e.to_string()).into(),
    }
}

pub fn today_utc() -> DateTime<FixedOffset> {
    let now_utc = Utc::now();
    let tz_offset = FixedOffset::east_opt(0).unwrap();
    let date = now_utc.date_naive();
    let datetime = date.and_time(NaiveTime::default());
    tz_offset.from_local_datetime(&datetime).unwrap()
}

pub fn age(This(this): This<DateTime<FixedOffset>>) -> ResolveResult {
    let now_local = Utc::now().with_timezone(this.offset());

    match now_local.years_since(this) {
        Some(years) => Ok(u64::from(years).into()),
        None => Ok(0.into()),
    }
}
