// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::artifacts::validation_report_v1::ValidationReportPayloadV1;

use super::{ValidationModeV1, ValidationReasonCodeV1, ValidationRequestV1, ValidationVerdictV1};

pub(super) fn apply_missing_state_basis(
    mut report: ValidationReportPayloadV1,
    request: &ValidationRequestV1,
) -> ValidationReportPayloadV1 {
    if !matches!(
        request.mode,
        ValidationModeV1::StateAdvisory | ValidationModeV1::StateRequired
    ) || request.host_state.is_some()
        || !request.thermal_evidence.is_empty()
        || report.primary_reason_code == ValidationReasonCodeV1::StateMissing
    {
        return report;
    }

    // Static rejection is still useful evidence, but cannot stand in for an absent state basis.
    if !report.summary.is_empty() && !report.warnings.contains(&report.summary) {
        report.warnings.push(report.summary.clone());
    }
    report.verdict = ValidationVerdictV1::Indeterminate;
    report.primary_reason_code = ValidationReasonCodeV1::StateMissing;
    report.selected_degradation_tier = None;
    report.summary = "state-aware validation has no host-state evidence".to_string();
    report
}
