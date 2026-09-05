// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::artifacts::envelope_v1::{ArtifactEnvelopeV1, RedactionEnvelopeV1};
use crate::redact::profile_v1::BuiltInRedactionProfileV1;
use crate::redact::{RedactionError, RedactionErrorCode};

pub(crate) fn apply_auxiliary_redaction_metadata_v1(
    envelope: &mut ArtifactEnvelopeV1,
    profile: BuiltInRedactionProfileV1,
    redacted_at: &str,
) -> Result<(), RedactionError> {
    sanitize_sharing_provenance(envelope, profile, "auxiliary_provenance_validate")?;
    if profile.applies_auditor_redactions() && envelope.provenance.command_name.is_some() {
        envelope.provenance.command_name =
            Some(format!("redacted:{}:command_name", profile.as_str()));
    }
    finalize_redaction_metadata(envelope, profile, redacted_at);
    Ok(())
}

pub(crate) fn apply_redaction_metadata_v1(
    envelope: &mut ArtifactEnvelopeV1,
    profile: BuiltInRedactionProfileV1,
    redacted_at: &str,
) -> Result<(), RedactionError> {
    sanitize_sharing_provenance(envelope, profile, "provenance_validate")?;
    // Core command names are validated vocabulary, not free-form auxiliary provenance.
    finalize_redaction_metadata(envelope, profile, redacted_at);
    Ok(())
}

fn sanitize_sharing_provenance(
    envelope: &mut ArtifactEnvelopeV1,
    profile: BuiltInRedactionProfileV1,
    checkpoint: &'static str,
) -> Result<(), RedactionError> {
    if profile.applies_auditor_redactions() {
        if !is_supported_timestamp(&envelope.provenance.collected_at) {
            return Err(RedactionError::new(
                RedactionErrorCode::ArtifactInputInvalid,
                checkpoint,
                "artifact provenance collected_at must be epoch:<seconds>, unix:<seconds>, or whole-second UTC YYYY-MM-DDTHH:MM:SSZ",
            ));
        }
        if let Some(version) = envelope.provenance.fitctl_version.as_deref() {
            if version.trim().is_empty() {
                return Err(RedactionError::new(
                    RedactionErrorCode::ArtifactInputInvalid,
                    checkpoint,
                    "artifact provenance fitctl_version must be nonblank when present",
                ));
            }
            if !is_stable_public_version(version) {
                envelope.provenance.fitctl_version =
                    Some(format!("redacted:{}:fitctl_version", profile.as_str()));
            }
        }
    }
    Ok(())
}

fn finalize_redaction_metadata(
    envelope: &mut ArtifactEnvelopeV1,
    profile: BuiltInRedactionProfileV1,
    redacted_at: &str,
) {
    if profile.applies_fleet_redactions() {
        envelope.provenance.correlation_id = Some(envelope.artifact_id.clone());
    }
    if profile.applies_auditor_redactions() {
        envelope.provenance.source = profile.provenance_source_placeholder();
        envelope.provenance.fitctl_vcs_revision = None;
        envelope.provenance.fitctl_vcs_describe = None;
        envelope.provenance.fitctl_build_dirty = None;
    }
    envelope.redaction = Some(RedactionEnvelopeV1 {
        profile_id: profile.as_str().to_string(),
        redacted_at: redacted_at.to_string(),
    });
    envelope.signatures.clear();
}

fn is_stable_public_version(value: &str) -> bool {
    let components = value.split('.').collect::<Vec<_>>();
    components.len() == 3
        && components.iter().all(|component| {
            !component.is_empty()
                && component.bytes().all(|byte| byte.is_ascii_digit())
                && (component.len() == 1 || !component.starts_with('0'))
        })
}

fn is_supported_timestamp(value: &str) -> bool {
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
