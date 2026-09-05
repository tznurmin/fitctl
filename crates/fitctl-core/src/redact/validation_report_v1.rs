// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Recursive built-in profile treatment for validation-report fields.

use std::collections::BTreeMap;

use crate::artifacts::validation_report_v1::ValidationReportV1;
use crate::redact::path_resources_v1::{deterministic_identifier_map, mapped_identifier};
use crate::redact::profile_v1::BuiltInRedactionProfileV1;

pub(crate) fn apply_validation_report_profile_v1(
    artifact: &mut ValidationReportV1,
    profile: BuiltInRedactionProfileV1,
) {
    if profile.applies_fleet_redactions() {
        artifact.envelope.artifact_id = profile.artifact_id_placeholder("validation-report");
        artifact.validation_basis.contract_artifact_id =
            profile.artifact_id_placeholder("contract");
        artifact.validation_basis.service_profile_artifact_id =
            profile.artifact_id_placeholder("service-profile");
        if let Some(state_artifact_id) = artifact.validation_basis.state_artifact_id.as_mut() {
            *state_artifact_id = profile.artifact_id_placeholder("state");
        }
    }
    if profile.applies_auditor_redactions() {
        artifact.validation_basis.validation_engine_id =
            profile.indexed_placeholder("validation_engine", 0);
        artifact.validation_basis.validation_engine_version =
            profile.indexed_placeholder("validation_engine_version", 0);
        let path_ids = deterministic_identifier_map(
            artifact
                .report
                .path_diagnostics
                .iter()
                .flat_map(|diagnostic| diagnostic.path_ids.iter().map(String::as_str)),
            profile,
            "path_id",
        );
        for (index, thermal_id) in artifact
            .validation_basis
            .thermal_evidence_artifact_ids
            .iter_mut()
            .enumerate()
        {
            *thermal_id = profile.indexed_placeholder("thermal_evidence", index);
        }
        for (index, diagnostic) in artifact.report.path_diagnostics.iter_mut().enumerate() {
            diagnostic.diagnostic_id = profile.indexed_placeholder("path_diagnostic", index);
            diagnostic.requirement_key = profile.indexed_placeholder("path_requirement", index);
            diagnostic.check_id = profile.indexed_placeholder("path_check", index);
            for path_id in &mut diagnostic.path_ids {
                *path_id = mapped_identifier(path_id, &path_ids);
            }
            let value_placeholder = format!("{}:{index}", profile.storage_identity_placeholder());
            replace_map(
                &mut diagnostic.expected,
                profile,
                "path_expected",
                &value_placeholder,
            );
            replace_map(
                &mut diagnostic.observed,
                profile,
                "path_observed",
                &value_placeholder,
            );
            replace_indexed(&mut diagnostic.evidence_refs, profile, "path_evidence_ref");
        }
    }
    if !profile.applies_external_redactions() {
        return;
    }

    replace_indexed(
        &mut artifact.report.matched_requirements,
        profile,
        "matched_requirement",
    );
    replace_indexed(
        &mut artifact.report.failed_requirements,
        profile,
        "failed_requirement",
    );
    replace_all(
        &mut artifact.report.evidence_refs,
        &profile.evidence_ref_placeholder(),
    );
    replace_all(
        &mut artifact.report.policy_refs,
        &profile.policy_ref_placeholder(),
    );
    replace_indexed(
        &mut artifact.report.assurance_mismatches,
        profile,
        "assurance_mismatch",
    );
    if artifact.report.selected_degradation_tier.is_some() {
        artifact.report.selected_degradation_tier =
            Some(profile.indexed_placeholder("degradation_tier", 0));
    }
    replace_indexed(&mut artifact.report.warnings, profile, "warning");
    artifact.report.summary = profile.indexed_placeholder("validation_summary", 0);

    for (index, diagnostic) in artifact.report.path_diagnostics.iter_mut().enumerate() {
        diagnostic.reason_code = profile.indexed_placeholder("path_reason", index);
    }
    for (index, explanation) in artifact.report.explanations.iter_mut().enumerate() {
        explanation.explanation_id = profile.indexed_placeholder("explanation", index);
        explanation.summary = profile.indexed_placeholder("explanation_summary", index);
        replace_indexed(
            &mut explanation.related_requirements,
            profile,
            "explanation_requirement",
        );
        replace_indexed(
            &mut explanation.evidence_refs,
            profile,
            "explanation_evidence_ref",
        );
        replace_indexed(
            &mut explanation.policy_refs,
            profile,
            "explanation_policy_ref",
        );
    }
    for (index, hint) in artifact.report.remediation_hints.iter_mut().enumerate() {
        hint.hint_id = profile.indexed_placeholder("remediation_hint", index);
        hint.summary = profile.indexed_placeholder("remediation_summary", index);
        for (action_index, action) in hint.actions.iter_mut().enumerate() {
            action.action_id = profile.indexed_placeholder("remediation_action", action_index);
            action.summary =
                profile.indexed_placeholder("remediation_action_summary", action_index);
        }
    }
}

fn replace_indexed(values: &mut [String], profile: BuiltInRedactionProfileV1, class: &str) {
    for (index, value) in values.iter_mut().enumerate() {
        *value = profile.indexed_placeholder(class, index);
    }
}

fn replace_all(values: &mut [String], replacement: &str) {
    for value in values {
        *value = replacement.to_string();
    }
}

fn replace_map(
    values: &mut BTreeMap<String, String>,
    profile: BuiltInRedactionProfileV1,
    class: &str,
    value_placeholder: &str,
) {
    *values = std::mem::take(values)
        .into_iter()
        .enumerate()
        .map(|(index, (key, _))| {
            let key = if is_public_path_diagnostic_key(&key) {
                key
            } else {
                profile.indexed_placeholder(&format!("{class}_key"), index)
            };
            (key, value_placeholder.to_string())
        })
        .collect();
}

fn is_public_path_diagnostic_key(key: &str) -> bool {
    matches!(
        key,
        "relationship_id"
            | "missing_path_id"
            | "must_not_share"
            | "left"
            | "right"
            | "pair_id"
            | "observed"
            | "required"
    )
}
