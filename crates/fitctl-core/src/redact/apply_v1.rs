// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Redaction application across supported artifact families.

use std::path::Path;

use crate::artifacts::record_v1::{load_artifact_record_from_path, ArtifactRecordV1};
use crate::artifacts::validation_report_v1::ValidationReportV1;
use crate::artifacts::validation_v1::validate_validation_report;
use crate::redact::bundles_v1::{redact_config_bundle_artifact, redact_decision_bundle_artifact};
use crate::redact::contract_artifact_v1::redact_contract_artifact;
use crate::redact::extension_sections_v1::redact_extension_diagnostics_v1;
use crate::redact::profile_v1::BuiltInRedactionProfileV1;
use crate::redact::provenance_v1::apply_redaction_metadata_v1;
use crate::redact::runtime_artifacts_v1::{
    redact_state_artifact, redact_thermal_evidence_artifact,
};
use crate::redact::service_profile_artifact_v1::redact_service_profile_artifact;
use crate::redact::survey_artifact_v1::redact_survey_artifact;
use crate::redact::validation_report_v1::apply_validation_report_profile_v1;
use crate::redact::{RedactionError, RedactionErrorCode};

#[derive(Debug, Clone, PartialEq)]
pub struct RedactionRequestV1 {
    pub artifact: ArtifactRecordV1,
    pub profile: BuiltInRedactionProfileV1,
    pub redacted_at: String,
}

/// Load a typed artifact record for redaction.
pub fn load_artifact_record_for_redaction(path: &Path) -> Result<ArtifactRecordV1, RedactionError> {
    load_artifact_record_from_path(path).map_err(|error| {
        RedactionError::new(
            RedactionErrorCode::ArtifactInputInvalid,
            "artifact_load",
            error.message,
        )
    })
}

/// Apply one built-in redaction profile and emit a validated redacted artifact.
pub fn redact_artifact_v1(request: RedactionRequestV1) -> Result<ArtifactRecordV1, RedactionError> {
    if request.redacted_at.trim().is_empty() {
        return Err(RedactionError::new(
            RedactionErrorCode::RedactionApplyFailed,
            "redaction_apply",
            "redaction timestamp must be populated",
        ));
    }

    preflight_input(&request.artifact)?;
    if request.profile.applies_auditor_redactions() {
        crate::redact::observation_times_v1::core_times(&request.artifact)?;
    }

    match request.artifact {
        ArtifactRecordV1::Survey(artifact) => {
            redact_survey_artifact(artifact, request.profile, &request.redacted_at)
                .map(ArtifactRecordV1::Survey)
        }
        ArtifactRecordV1::Contract(artifact) => {
            redact_contract_artifact(artifact, request.profile, &request.redacted_at)
                .map(ArtifactRecordV1::Contract)
        }
        ArtifactRecordV1::ServiceProfile(artifact) => {
            redact_service_profile_artifact(artifact, request.profile, &request.redacted_at)
                .map(ArtifactRecordV1::ServiceProfile)
        }
        ArtifactRecordV1::State(artifact) => {
            redact_state_artifact(artifact, request.profile, &request.redacted_at)
                .map(ArtifactRecordV1::State)
        }
        ArtifactRecordV1::ThermalEvidence(artifact) => {
            redact_thermal_evidence_artifact(artifact, request.profile, &request.redacted_at)
                .map(ArtifactRecordV1::ThermalEvidence)
        }
        ArtifactRecordV1::ValidationReport(artifact) => {
            redact_validation_report_artifact(artifact, request.profile, &request.redacted_at)
                .map(ArtifactRecordV1::ValidationReport)
        }
        ArtifactRecordV1::ConfigBundle(artifact) => {
            redact_config_bundle_artifact(artifact, request.profile, &request.redacted_at)
                .map(ArtifactRecordV1::ConfigBundle)
        }
        ArtifactRecordV1::DecisionBundle(artifact) => {
            redact_decision_bundle_artifact(artifact, request.profile, &request.redacted_at)
                .map(ArtifactRecordV1::DecisionBundle)
        }
    }
}

fn preflight_input(artifact: &ArtifactRecordV1) -> Result<(), RedactionError> {
    let envelope = match artifact {
        ArtifactRecordV1::Survey(artifact) => &artifact.envelope,
        ArtifactRecordV1::Contract(artifact) => &artifact.envelope,
        ArtifactRecordV1::ServiceProfile(artifact) => &artifact.envelope,
        ArtifactRecordV1::State(artifact) => &artifact.envelope,
        ArtifactRecordV1::ThermalEvidence(artifact) => &artifact.envelope,
        ArtifactRecordV1::ValidationReport(artifact) => &artifact.envelope,
        ArtifactRecordV1::ConfigBundle(artifact) => &artifact.envelope,
        ArtifactRecordV1::DecisionBundle(artifact) => &artifact.envelope,
    };

    if envelope.redaction.is_some() {
        return Err(RedactionError::new(
            RedactionErrorCode::RedactionInputAlreadyRedacted,
            "redaction_preflight",
            "input artifact already carries redaction provenance",
        ));
    }

    Ok(())
}

pub(crate) fn redact_validation_report_artifact(
    mut artifact: ValidationReportV1,
    profile: BuiltInRedactionProfileV1,
    redacted_at: &str,
) -> Result<ValidationReportV1, RedactionError> {
    apply_validation_report_profile_v1(&mut artifact, profile);
    redact_extension_diagnostics_v1(&mut artifact.report.extension_diagnostics, profile)?;

    apply_redaction_metadata_v1(&mut artifact.envelope, profile, redacted_at)?;
    validate_validation_report(&artifact).map_err(|error| {
        RedactionError::new(
            RedactionErrorCode::RedactionOutputInvalid,
            "redaction_emit",
            error.message,
        )
    })?;

    Ok(artifact)
}
