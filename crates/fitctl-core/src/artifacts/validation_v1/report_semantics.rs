// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Validation-report semantics that sit above pure schema-shape checks.

use super::*;

pub(super) fn validate_validation_report_semantics(
    report: &ValidationReportPayloadV1,
) -> Result<(), ArtifactValidationError> {
    match report.verdict {
        ValidationVerdictV1::Fit => {
            if report.primary_reason_code != ValidationReasonCodeV1::RequirementsSatisfied {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "fit validation reports must use requirements_satisfied as the primary reason code",
                ));
            }
            if report.selected_degradation_tier.is_some() {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "fit validation reports must not declare a degradation tier",
                ));
            }
        }
        ValidationVerdictV1::FitWithDegradation => {
            if report.primary_reason_code != ValidationReasonCodeV1::DegradationPathRequired {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "fit_with_degradation reports must use degradation_path_required as the primary reason code",
                ));
            }
            if report.selected_degradation_tier.is_none() {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "fit_with_degradation reports must declare the selected degradation tier",
                ));
            }
        }
        ValidationVerdictV1::Unfit | ValidationVerdictV1::Indeterminate => {
            if report.selected_degradation_tier.is_some() {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "non-degraded validation reports must not declare a degradation tier",
                ));
            }
            if report.primary_reason_code == ValidationReasonCodeV1::RequirementsSatisfied
                || report.primary_reason_code == ValidationReasonCodeV1::DegradationPathRequired
            {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "non-fit reports must not use success-path primary reason codes",
                ));
            }
        }
    }

    if !validation_reason_code_matches_verdict(report.verdict, report.primary_reason_code) {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "validation report primary reason code must match the selected verdict class",
        ));
    }

    Ok(())
}

pub(super) fn validate_batch_row_semantics(
    verdict: ValidationVerdictV1,
    primary_reason_code: ValidationReasonCodeV1,
    selected_degradation_tier: Option<&str>,
) -> Result<(), ArtifactValidationError> {
    match verdict {
        ValidationVerdictV1::Fit => {
            if primary_reason_code != ValidationReasonCodeV1::RequirementsSatisfied
                || selected_degradation_tier.is_some()
            {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "fit batch-classification rows must use requirements_satisfied and omit degradation tier",
                ));
            }
        }
        ValidationVerdictV1::FitWithDegradation => {
            if primary_reason_code != ValidationReasonCodeV1::DegradationPathRequired
                || selected_degradation_tier.is_none()
            {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "fit_with_degradation batch-classification rows must use degradation_path_required and retain degradation tier",
                ));
            }
        }
        ValidationVerdictV1::Unfit | ValidationVerdictV1::Indeterminate => {
            if selected_degradation_tier.is_some()
                || matches!(
                    primary_reason_code,
                    ValidationReasonCodeV1::RequirementsSatisfied
                        | ValidationReasonCodeV1::DegradationPathRequired
                )
            {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "non-fit batch-classification rows must not retain success-path reason codes or degradation tiers",
                ));
            }
        }
    }

    if !validation_reason_code_matches_verdict(verdict, primary_reason_code) {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "batch-classification rows must keep verdict and primary reason code aligned",
        ));
    }

    Ok(())
}

pub(super) fn validation_reason_code_matches_verdict(
    verdict: ValidationVerdictV1,
    primary_reason_code: ValidationReasonCodeV1,
) -> bool {
    match verdict {
        ValidationVerdictV1::Fit => {
            primary_reason_code == ValidationReasonCodeV1::RequirementsSatisfied
        }
        ValidationVerdictV1::FitWithDegradation => {
            primary_reason_code == ValidationReasonCodeV1::DegradationPathRequired
        }
        ValidationVerdictV1::Unfit => matches!(
            primary_reason_code,
            ValidationReasonCodeV1::RequirementUnsatisfied
                | ValidationReasonCodeV1::CapabilityUnknown
                | ValidationReasonCodeV1::AssuranceSourceNotAccepted
                | ValidationReasonCodeV1::AssuranceDerivationStageNotAccepted
                | ValidationReasonCodeV1::PolicyNotAdmissible
                | ValidationReasonCodeV1::NetworkMismatch
                | ValidationReasonCodeV1::TopologyMismatch
                | ValidationReasonCodeV1::CapabilityDegraded
                | ValidationReasonCodeV1::DegradationPathUnavailable
        ),
        ValidationVerdictV1::Indeterminate => matches!(
            primary_reason_code,
            ValidationReasonCodeV1::StateMissing
                | ValidationReasonCodeV1::StateStale
                | ValidationReasonCodeV1::AssurancePredicateUnresolved
                | ValidationReasonCodeV1::EvidenceIncomplete
                | ValidationReasonCodeV1::ValidationBlocked
                | ValidationReasonCodeV1::NetworkMismatch
                | ValidationReasonCodeV1::TopologyMismatch
        ),
    }
}

pub(super) fn validate_sorted_unique_refs<'a>(
    refs: impl Iterator<Item = (&'a str, &'a str)>,
    label: &str,
) -> Result<(), ArtifactValidationError> {
    let refs = refs.collect::<Vec<_>>();
    if refs
        .iter()
        .any(|(artifact_id, semantic_hash)| is_blank(artifact_id) || is_blank(semantic_hash))
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            format!("{label} must not contain blank ids or semantic hashes"),
        ));
    }
    let mut sorted = refs.clone();
    sorted.sort();
    if refs != sorted {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            format!("{label} must be deterministically sorted"),
        ));
    }
    let deduped = refs.iter().copied().collect::<BTreeSet<_>>();
    if deduped.len() != refs.len() {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            format!("{label} must be unique"),
        ));
    }
    Ok(())
}

pub(super) fn validate_sorted_unique_summary_lists<'a>(
    summaries: impl Iterator<Item = (&'a str, [&'a Vec<String>; 4])>,
    allowed_primary_ids: &BTreeSet<&str>,
    allowed_secondary_ids: &BTreeSet<&str>,
    primary_is_contract: bool,
) -> Result<(), ArtifactValidationError> {
    let summaries = summaries.collect::<Vec<_>>();
    let mut primary_ids = Vec::new();

    for (primary_id, groups) in &summaries {
        if is_blank(primary_id) || !allowed_primary_ids.contains(primary_id) {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "batch classification summaries must reference declared ids",
            ));
        }
        primary_ids.push(*primary_id);
        let mut seen = BTreeSet::new();
        for group in groups {
            let mut sorted = (*group).clone();
            sorted.sort();
            if sorted != **group {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "batch classification summary lists must be deterministically sorted",
                ));
            }
            for value in *group {
                if is_blank(value) || !allowed_secondary_ids.contains(value.as_str()) {
                    return Err(ArtifactValidationError::new(
                        ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                        "batch classification summaries must only reference declared ids",
                    ));
                }
                if !seen.insert(value.as_str()) {
                    return Err(ArtifactValidationError::new(
                        ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                        if primary_is_contract {
                            "batch classification contract summaries must not duplicate service-profile ids"
                        } else {
                            "batch classification service-profile summaries must not duplicate contract ids"
                        },
                    ));
                }
            }
        }
    }

    let mut sorted_primary_ids = primary_ids.clone();
    sorted_primary_ids.sort();
    if primary_ids != sorted_primary_ids {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "batch classification summaries must be deterministically sorted by primary id",
        ));
    }
    let deduped = primary_ids.iter().copied().collect::<BTreeSet<_>>();
    if deduped.len() != primary_ids.len() {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "batch classification summaries must be unique by primary id",
        ));
    }

    Ok(())
}

pub(super) fn validate_validation_explanations(
    report: &ValidationReportPayloadV1,
) -> Result<(), ArtifactValidationError> {
    let mut explanation_ids = report
        .explanations
        .iter()
        .map(|entry| entry.explanation_id.clone())
        .collect::<Vec<_>>();
    let explanation_ids_sorted = {
        let mut value = explanation_ids.clone();
        value.sort();
        value
    };
    if explanation_ids != explanation_ids_sorted {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "validation explanations must be deterministically sorted by explanation_id",
        ));
    }
    explanation_ids.dedup();
    if explanation_ids.len() != report.explanations.len() {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "validation explanations must have unique explanation_id values",
        ));
    }

    for explanation in &report.explanations {
        validate_validation_explanation(explanation, report.primary_reason_code)?;
    }

    Ok(())
}

pub(super) fn validate_validation_explanation(
    explanation: &ValidationExplanationV1,
    primary_reason_code: ValidationReasonCodeV1,
) -> Result<(), ArtifactValidationError> {
    if explanation.reason_code != primary_reason_code
        || explanation
            .related_requirements
            .iter()
            .any(|value| is_blank(value))
        || explanation
            .evidence_refs
            .iter()
            .any(|value| is_blank(value))
        || explanation.policy_refs.iter().any(|value| is_blank(value))
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "validation explanations must be non-blank, primary-reason-coupled, and typed",
        ));
    }

    Ok(())
}

pub(super) fn validate_validation_remediation_hints(
    report: &ValidationReportPayloadV1,
) -> Result<(), ArtifactValidationError> {
    if matches!(report.verdict, ValidationVerdictV1::Fit) && !report.remediation_hints.is_empty() {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "fit validation reports must not emit remediation hints",
        ));
    }

    let mut hint_ids = report
        .remediation_hints
        .iter()
        .map(|entry| entry.hint_id.clone())
        .collect::<Vec<_>>();
    let hint_ids_sorted = {
        let mut value = hint_ids.clone();
        value.sort();
        value
    };
    if hint_ids != hint_ids_sorted {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "validation remediation hints must be deterministically sorted by hint_id",
        ));
    }
    hint_ids.dedup();
    if hint_ids.len() != report.remediation_hints.len() {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "validation remediation hints must have unique hint_id values",
        ));
    }

    for hint in &report.remediation_hints {
        validate_validation_remediation_hint(hint, report.primary_reason_code)?;
    }

    Ok(())
}

pub(super) fn validate_validation_remediation_hint(
    hint: &ValidationRemediationHintV1,
    primary_reason_code: ValidationReasonCodeV1,
) -> Result<(), ArtifactValidationError> {
    if hint.reason_code != primary_reason_code {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "validation remediation hints must be coupled to the primary reason code",
        ));
    }

    let mut action_ids = hint
        .actions
        .iter()
        .map(|action| action.action_id.clone())
        .collect::<Vec<_>>();
    let action_ids_sorted = {
        let mut value = action_ids.clone();
        value.sort();
        value
    };
    if action_ids != action_ids_sorted {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "validation remediation actions must be deterministically sorted by action_id",
        ));
    }
    action_ids.dedup();
    if action_ids.len() != hint.actions.len() {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "validation remediation actions must have unique action_id values",
        ));
    }

    for action in &hint.actions {
        validate_validation_remediation_action(action)?;
    }

    Ok(())
}

pub(super) fn validate_validation_remediation_action(
    action: &ValidationRemediationActionV1,
) -> Result<(), ArtifactValidationError> {
    if is_blank(&action.action_id) || is_blank(&action.summary) {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "validation remediation actions must use non-blank ids and summaries",
        ));
    }

    Ok(())
}
