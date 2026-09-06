// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::redact::{RedactionError, RedactionErrorCode};

pub(super) fn require_timestamp(value: &str, field: &'static str) -> Result<(), RedactionError> {
    if is_supported_timestamp(value) {
        return Ok(());
    }
    Err(RedactionError::new(
        RedactionErrorCode::ArtifactInputInvalid,
        "sharing_timestamp_validate",
        format!("{field} must be epoch:<seconds>, unix:<seconds>, or whole-second UTC YYYY-MM-DDTHH:MM:SSZ"),
    ))
}

pub(super) fn optional_timestamp(
    value: Option<&str>,
    field: &'static str,
) -> Result<(), RedactionError> {
    if let Some(value) = value {
        require_timestamp(value, field)?;
    }
    Ok(())
}

pub(super) fn is_supported_timestamp(value: &str) -> bool {
    if let Some(seconds) = value
        .strip_prefix("epoch:")
        .or_else(|| value.strip_prefix("unix:"))
    {
        return seconds.parse::<u64>().is_ok();
    }
    is_utc_rfc3339(value)
}

fn is_utc_rfc3339(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return false;
    }
    let Some(year) = decimal(value, 0, 4) else {
        return false;
    };
    let Some(month) = decimal(value, 5, 7) else {
        return false;
    };
    let Some(day) = decimal(value, 8, 10) else {
        return false;
    };
    let Some(hour) = decimal(value, 11, 13) else {
        return false;
    };
    let Some(minute) = decimal(value, 14, 16) else {
        return false;
    };
    let Some(second) = decimal(value, 17, 19) else {
        return false;
    };
    (1..=12).contains(&month)
        && day >= 1
        && day <= days_in_month(year, month)
        && hour <= 23
        && minute <= 59
        && second <= 59
}

fn decimal(value: &str, start: usize, end: usize) -> Option<u32> {
    let component = value.get(start..end)?;
    if !component.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    component.parse().ok()
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if year.is_multiple_of(400) || (year.is_multiple_of(4) && !year.is_multiple_of(100)) => {
            29
        }
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}
