// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Profile-specific redaction for standalone auxiliary reports.

use std::collections::BTreeMap;

use crate::artifacts::batch_classification_report_v1::BatchClassificationReportV1;
use crate::artifacts::recommendation_report_v1::RecommendationReportV1;
use crate::artifacts::validation_v1::{
    validate_batch_classification_report, validate_recommendation_report,
};
use crate::redact::profile_v1::BuiltInRedactionProfileV1;
use crate::redact::provenance_v1::apply_auxiliary_redaction_metadata_v1;
use crate::redact::{RedactionError, RedactionErrorCode};

pub(crate) fn redact_recommendation_report_artifact_v1(
    mut artifact: RecommendationReportV1,
    profile: BuiltInRedactionProfileV1,
    redacted_at: &str,
) -> Result<RecommendationReportV1, RedactionError> {
    validate_recommendation_report(&artifact).map_err(map_input_error)?;
    if profile.applies_auditor_redactions() {
        crate::redact::observation_times_v1::recommendation_time(&artifact)?;
    }
    apply_recommendation_report_profile_v1(&mut artifact, profile);
    apply_auxiliary_redaction_metadata_v1(&mut artifact.envelope, profile, redacted_at)?;
    validate_recommendation_report(&artifact).map_err(map_output_error)?;
    Ok(artifact)
}

pub(crate) fn apply_recommendation_report_profile_v1(
    artifact: &mut RecommendationReportV1,
    profile: BuiltInRedactionProfileV1,
) {
    if profile.applies_fleet_redactions() {
        artifact.envelope.artifact_id = profile.artifact_id_placeholder("recommendation-report");
        artifact.recommendation_basis.validation_report_artifact_id =
            profile.artifact_id_placeholder("validation-report");
        if artifact.recommendation_basis.state_artifact_id.is_some() {
            artifact.recommendation_basis.state_artifact_id =
                Some(profile.artifact_id_placeholder("state"));
        }
    }

    if profile.applies_auditor_redactions() {
        artifact.recommendation_basis.recommendation_engine_id =
            placeholder(profile, "recommendation_engine");
        artifact.recommendation_basis.recommendation_engine_version =
            placeholder(profile, "recommendation_engine_version");
        artifact.recommendation_basis.recommendation_pack_id =
            placeholder(profile, "recommendation_pack");
        artifact.recommendation_basis.recommendation_pack_version =
            placeholder(profile, "recommendation_pack_version");
        replace_optional(
            &mut artifact.report.recommendation_class,
            profile,
            "recommendation_class",
        );
        replace_optional(
            &mut artifact.report.expected_operating_mode,
            profile,
            "expected_operating_mode",
        );
        replace_optional(
            &mut artifact.report.processing_time_band,
            profile,
            "processing_time_band",
        );
        replace_optional(
            &mut artifact.report.throughput_band,
            profile,
            "throughput_band",
        );
        for (index, reason_id) in artifact.report.advisory_reason_ids.iter_mut().enumerate() {
            *reason_id = indexed_placeholder(profile, "advisory_reason", index);
        }
        artifact.report.summary = placeholder(profile, "recommendation_summary");
    }
}

pub(crate) fn redact_batch_classification_report_artifact_v1(
    mut artifact: BatchClassificationReportV1,
    profile: BuiltInRedactionProfileV1,
    redacted_at: &str,
) -> Result<BatchClassificationReportV1, RedactionError> {
    validate_batch_classification_report(&artifact).map_err(map_input_error)?;
    if profile.applies_auditor_redactions() {
        crate::redact::observation_times_v1::batch_times(&artifact)?;
    }

    let contract_ids = build_id_map(
        artifact
            .classification_basis
            .ordered_contracts
            .iter()
            .map(|value| value.artifact_id.as_str()),
        profile,
        "contract",
        profile.applies_fleet_redactions(),
    );
    let profile_ids = build_id_map(
        artifact
            .classification_basis
            .ordered_service_profiles
            .iter()
            .map(|value| value.artifact_id.as_str()),
        profile,
        "service_profile",
        profile.applies_auditor_redactions(),
    );

    if profile.applies_fleet_redactions() {
        artifact.envelope.artifact_id =
            profile.artifact_id_placeholder("batch-classification-report");
    }
    redact_batch_basis(&mut artifact, profile, &contract_ids, &profile_ids)?;
    redact_batch_rows(&mut artifact, profile, &contract_ids, &profile_ids)?;
    redact_batch_summaries(&mut artifact, &contract_ids, &profile_ids)?;

    apply_auxiliary_redaction_metadata_v1(&mut artifact.envelope, profile, redacted_at)?;
    validate_batch_classification_report(&artifact).map_err(map_output_error)?;
    Ok(artifact)
}

fn redact_batch_basis(
    artifact: &mut BatchClassificationReportV1,
    profile: BuiltInRedactionProfileV1,
    contract_ids: &BTreeMap<String, String>,
    profile_ids: &BTreeMap<String, String>,
) -> Result<(), RedactionError> {
    if profile.applies_auditor_redactions() {
        artifact.classification_basis.validation_engine_id =
            placeholder(profile, "validation_engine");
        artifact.classification_basis.validation_engine_version =
            placeholder(profile, "validation_engine_version");
    }
    for (index, contract) in artifact
        .classification_basis
        .ordered_contracts
        .iter_mut()
        .enumerate()
    {
        contract.artifact_id = mapped_id(contract_ids, &contract.artifact_id)?;
        if contract.host_alias.is_some() && profile.applies_fleet_redactions() {
            contract.host_alias = Some(indexed_placeholder(profile, "host", index));
        }
        if profile.applies_auditor_redactions() {
            replace_optional_indexed(&mut contract.display_name, profile, "contract_label", index);
            replace_optional_indexed(
                &mut contract.short_display_name,
                profile,
                "contract_short_label",
                index,
            );
        }
        if let Some(state) = contract.matched_state.as_mut() {
            if profile.applies_fleet_redactions() {
                state.artifact_id = indexed_placeholder(profile, "state", index);
            }
        }
    }

    for (index, service_profile) in artifact
        .classification_basis
        .ordered_service_profiles
        .iter_mut()
        .enumerate()
    {
        service_profile.artifact_id = mapped_id(profile_ids, &service_profile.artifact_id)?;
        if profile.applies_auditor_redactions() {
            replace_optional_indexed(
                &mut service_profile.display_name,
                profile,
                "service_profile_label",
                index,
            );
            replace_optional_indexed(
                &mut service_profile.short_display_name,
                profile,
                "service_profile_short_label",
                index,
            );
        }
    }
    Ok(())
}

fn redact_batch_rows(
    artifact: &mut BatchClassificationReportV1,
    profile: BuiltInRedactionProfileV1,
    contract_ids: &BTreeMap<String, String>,
    profile_ids: &BTreeMap<String, String>,
) -> Result<(), RedactionError> {
    for (index, row) in artifact.report.rows.iter_mut().enumerate() {
        if profile.applies_fleet_redactions() {
            row.row_id = indexed_placeholder(profile, "row", index);
        }
        row.contract_artifact_id = mapped_id(contract_ids, &row.contract_artifact_id)?;
        row.service_profile_artifact_id = mapped_id(profile_ids, &row.service_profile_artifact_id)?;
        if profile.applies_auditor_redactions() {
            if row.selected_degradation_tier.is_some() {
                row.selected_degradation_tier =
                    Some(indexed_placeholder(profile, "degradation_tier", index));
            }
            row.summary = indexed_placeholder(profile, "row_summary", index);
        }
    }
    Ok(())
}

fn redact_batch_summaries(
    artifact: &mut BatchClassificationReportV1,
    contract_ids: &BTreeMap<String, String>,
    profile_ids: &BTreeMap<String, String>,
) -> Result<(), RedactionError> {
    for summary in &mut artifact.report.contract_summaries {
        summary.contract_artifact_id = mapped_id(contract_ids, &summary.contract_artifact_id)?;
        map_ids(&mut summary.fit_profile_ids, profile_ids)?;
        map_ids(&mut summary.degraded_profile_ids, profile_ids)?;
        map_ids(&mut summary.unfit_profile_ids, profile_ids)?;
        map_ids(&mut summary.indeterminate_profile_ids, profile_ids)?;
    }
    for summary in &mut artifact.report.service_profile_summaries {
        summary.service_profile_artifact_id =
            mapped_id(profile_ids, &summary.service_profile_artifact_id)?;
        map_ids(&mut summary.fit_contract_ids, contract_ids)?;
        map_ids(&mut summary.degraded_contract_ids, contract_ids)?;
        map_ids(&mut summary.unfit_contract_ids, contract_ids)?;
        map_ids(&mut summary.indeterminate_contract_ids, contract_ids)?;
    }
    Ok(())
}

fn build_id_map<'a>(
    values: impl Iterator<Item = &'a str>,
    profile: BuiltInRedactionProfileV1,
    kind: &str,
    redact: bool,
) -> BTreeMap<String, String> {
    values
        .enumerate()
        .map(|(index, value)| {
            let replacement = if redact {
                indexed_placeholder(profile, kind, index)
            } else {
                value.to_string()
            };
            (value.to_string(), replacement)
        })
        .collect()
}

fn map_ids(
    values: &mut [String],
    replacements: &BTreeMap<String, String>,
) -> Result<(), RedactionError> {
    for value in values {
        *value = mapped_id(replacements, value)?;
    }
    Ok(())
}

fn mapped_id(
    replacements: &BTreeMap<String, String>,
    value: &str,
) -> Result<String, RedactionError> {
    replacements.get(value).cloned().ok_or_else(|| {
        RedactionError::new(
            RedactionErrorCode::RedactionApplyFailed,
            "redaction_apply",
            format!("batch report reference {value} has no declared replacement"),
        )
    })
}

fn replace_optional(value: &mut Option<String>, profile: BuiltInRedactionProfileV1, kind: &str) {
    if value.is_some() {
        *value = Some(placeholder(profile, kind));
    }
}

fn replace_optional_indexed(
    value: &mut Option<String>,
    profile: BuiltInRedactionProfileV1,
    kind: &str,
    index: usize,
) {
    if value.is_some() {
        *value = Some(indexed_placeholder(profile, kind, index));
    }
}

fn placeholder(profile: BuiltInRedactionProfileV1, kind: &str) -> String {
    format!("redacted:{}:{kind}", profile.as_str())
}

fn indexed_placeholder(profile: BuiltInRedactionProfileV1, kind: &str, index: usize) -> String {
    format!("redacted:{}:{kind}:{index:08}", profile.as_str())
}

fn map_input_error(
    error: crate::artifacts::validation_v1::ArtifactValidationError,
) -> RedactionError {
    RedactionError::new(
        RedactionErrorCode::ArtifactInputInvalid,
        "redaction_apply",
        error.message,
    )
}

fn map_output_error(
    error: crate::artifacts::validation_v1::ArtifactValidationError,
) -> RedactionError {
    RedactionError::new(
        RedactionErrorCode::RedactionOutputInvalid,
        "redaction_emit",
        error.message,
    )
}
