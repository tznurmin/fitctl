// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::artifacts::envelope_v1::{ArtifactEnvelopeV1, RedactionEnvelopeV1};
use crate::redact::profile_v1::BuiltInRedactionProfileV1;
use crate::redact::timestamps_v1::{is_supported_timestamp, require_timestamp};
use crate::redact::{RedactionError, RedactionErrorCode};

pub(crate) fn apply_auxiliary_redaction_metadata_v1(
    envelope: &mut ArtifactEnvelopeV1,
    profile: BuiltInRedactionProfileV1,
    redacted_at: &str,
) -> Result<(), RedactionError> {
    sanitize_sharing_provenance(envelope, profile, "auxiliary_provenance_validate")?;
    if profile.applies_auditor_redactions() {
        require_timestamp(redacted_at, "redacted_at")?;
    }
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
    if profile.applies_auditor_redactions() {
        require_timestamp(redacted_at, "redacted_at")?;
    }
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
