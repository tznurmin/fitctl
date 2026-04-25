// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common;
use crate::e2e;
use fitctl_core::artifacts::validation_report_v1::{
    ValidationReasonCodeV1, ValidationReportV1, ValidationVerdictV1,
};

fn deployment_allows(report: &ValidationReportV1) -> bool {
    matches!(
        report.report.verdict,
        ValidationVerdictV1::Fit | ValidationVerdictV1::FitWithDegradation
    )
}

fn validate_with_state(
    contract_path: &std::path::Path,
    state_path: &std::path::Path,
) -> ValidationReportV1 {
    let output = e2e::run_fitctl([
        "validate",
        "--contract",
        contract_path
            .to_str()
            .expect("contract path should be valid UTF-8"),
        "--profile",
        common::repo_service_profile_path("general_compute_stateful_thresholds.v2.json")
            .to_str()
            .expect("profile path should be valid UTF-8"),
        "--validation-mode",
        "state_required",
        "--state",
        state_path
            .to_str()
            .expect("state path should be valid UTF-8"),
        "--max-state-age",
        "1h",
        "--validated-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&output);
    e2e::decode_json_stdout(&output)
}

#[test]
fn state_required_gate_respects_freshness_and_drives_machine_decision() {
    let temp_dir = common::unique_temp_dir("integration-e2e-state-gate");
    let survey_path = e2e::emit_survey_fixture(&temp_dir, "linux-bare-metal-like-v1");
    let contract_path =
        e2e::derive_contract(&temp_dir, &survey_path, "general_compute_default.v1.json");
    let fresh_state = e2e::emit_state_fixture(&temp_dir, "linux-bare-metal-like-fresh-v1");
    let stale_state = e2e::emit_state_fixture(&temp_dir, "linux-bare-metal-like-stale-v1");
    let limited_state =
        e2e::emit_state_fixture(&temp_dir, "linux-bare-metal-like-cgroup-limited-v1");

    let fresh_report = validate_with_state(&contract_path, &fresh_state);
    assert_eq!(fresh_report.report.verdict, ValidationVerdictV1::Fit);
    assert_eq!(
        fresh_report.report.primary_reason_code,
        ValidationReasonCodeV1::RequirementsSatisfied
    );
    assert!(deployment_allows(&fresh_report));

    let stale_report = validate_with_state(&contract_path, &stale_state);
    assert_eq!(
        stale_report.report.verdict,
        ValidationVerdictV1::Indeterminate
    );
    assert_eq!(
        stale_report.report.primary_reason_code,
        ValidationReasonCodeV1::StateStale
    );
    assert!(!deployment_allows(&stale_report));

    let limited_report = validate_with_state(&contract_path, &limited_state);
    assert_eq!(limited_report.report.verdict, ValidationVerdictV1::Unfit);
    assert_eq!(
        limited_report.report.primary_reason_code,
        ValidationReasonCodeV1::RequirementUnsatisfied
    );
    assert!(!deployment_allows(&limited_report));
}
