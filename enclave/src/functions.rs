// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

use aws_lc_rs::digest;
use cel_interpreter::{FunctionContext, ResolveResult, extractors::This};
use chrono::{DateTime, FixedOffset, NaiveDate, NaiveTime, TimeZone, Utc};
use data_encoding::{BASE64, HEXLOWER};
use std::sync::Arc;

// Default functions available:
// https://github.com/clarkmcc/cel-rust/blob/master/interpreter/src/context.rs#L169

// String Functions

pub fn is_empty(This(this): This<Arc<String>>) -> bool {
    this.is_empty()
}

pub fn to_lowercase(This(this): This<Arc<String>>) -> String {
    this.to_lowercase()
}

pub fn to_uppercase(This(this): This<Arc<String>>) -> String {
    this.to_uppercase()
}

// Hash Functions

pub fn sha256_hash(This(this): This<Arc<String>>) -> String {
    let digest = digest::digest(&digest::SHA256, this.as_bytes());
    HEXLOWER.encode(digest.as_ref())
}

pub fn sha384_hash(This(this): This<Arc<String>>) -> String {
    let digest = digest::digest(&digest::SHA384, this.as_bytes());
    HEXLOWER.encode(digest.as_ref())
}

pub fn sha512_hash(This(this): This<Arc<String>>) -> String {
    let digest = digest::digest(&digest::SHA512, this.as_bytes());
    HEXLOWER.encode(digest.as_ref())
}

// Hex Functions

pub fn hex_encode(This(this): This<Arc<String>>) -> String {
    HEXLOWER.encode(this.as_bytes())
}

pub fn hex_decode(ftx: &FunctionContext, This(this): This<Arc<String>>) -> ResolveResult {
    match HEXLOWER.decode(this.as_bytes()) {
        Ok(val) => match String::from_utf8(val) {
            Ok(result) => Ok(result.into()),
            Err(e) => ftx.error(e.to_string()).into(),
        },
        Err(e) => ftx.error(e.to_string()).into(),
    }
}

// Base64 Functions

pub fn base64_encode(This(this): This<Arc<String>>) -> String {
    BASE64.encode(this.as_bytes())
}

pub fn base64_decode(ftx: &FunctionContext, This(this): This<Arc<String>>) -> ResolveResult {
    match BASE64.decode(this.as_bytes()) {
        Ok(val) => match String::from_utf8(val) {
            Ok(result) => Ok(result.into()),
            Err(e) => ftx.error(e.to_string()).into(),
        },
        Err(e) => ftx.error(e.to_string()).into(),
    }
}

// Datetime Functions

/// UTC timezone offset (0 seconds from UTC)
/// This is a compile-time constant that is always valid.
const UTC_OFFSET: i32 = 0;

pub fn date(ftx: &FunctionContext, This(this): This<Arc<String>>) -> ResolveResult {
    match NaiveDate::parse_from_str(&this, "%Y-%m-%d") {
        Ok(date) => {
            // UTC offset of 0 is always valid, but we handle the theoretical None case
            let tz_offset = match FixedOffset::east_opt(UTC_OFFSET) {
                Some(offset) => offset,
                None => return ftx.error("failed to create UTC timezone offset").into(),
            };
            let datetime = date.and_time(NaiveTime::default());
            let dt_with_tz: DateTime<FixedOffset> = match tz_offset.from_local_datetime(&datetime) {
                chrono::LocalResult::Single(dt) => dt,
                chrono::LocalResult::Ambiguous(dt, _) => dt,
                chrono::LocalResult::None => {
                    return ftx.error("failed to convert datetime to timezone").into();
                }
            };
            Ok(dt_with_tz.into())
        }
        Err(e) => ftx.error(e.to_string()).into(),
    }
}

pub fn today_utc() -> DateTime<FixedOffset> {
    let now_utc = Utc::now();
    // UTC offset of 0 is always valid - use expect only in this case since
    // it's a compile-time constant and failure would indicate a bug in chrono
    #[allow(clippy::expect_used)]
    let tz_offset = FixedOffset::east_opt(UTC_OFFSET).expect("UTC offset 0 should always be valid");
    let date = now_utc.date_naive();
    let datetime = date.and_time(NaiveTime::default());
    // from_local_datetime with UTC offset should always succeed
    #[allow(clippy::expect_used)]
    tz_offset
        .from_local_datetime(&datetime)
        .single()
        .expect("UTC datetime conversion should always succeed")
}

pub fn age(This(this): This<DateTime<FixedOffset>>) -> ResolveResult {
    let now_local = Utc::now().with_timezone(this.offset());

    match now_local.years_since(this) {
        Some(years) => Ok(u64::from(years).into()),
        None => Ok(0.into()),
    }
}
