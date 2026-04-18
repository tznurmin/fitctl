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

#[test]
fn contract_only_gate_drives_machine_decision() {
    let temp_dir = common::unique_temp_dir("integration-e2e-contract-gate");
    let survey_path = e2e::emit_survey_fixture(&temp_dir, "linux-bare-metal-like-v1");
    let contract_path =
        e2e::derive_contract(&temp_dir, &survey_path, "general_compute_default.v1.json");

    let output = e2e::run_fitctl([
        "validate",
        "--contract",
        contract_path
            .to_str()
            .expect("contract path should be valid UTF-8"),
        "--profile",
        common::repo_service_profile_path("general_compute_contract_only.v2.json")
            .to_str()
            .expect("profile path should be valid UTF-8"),
        "--validation-mode",
        "contract_only",
        "--validated-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&output);

    let report: ValidationReportV1 = e2e::decode_json_stdout(&output);
    assert_eq!(
        report.validation_basis.validation_mode.as_str(),
        "contract_only"
    );
    assert_eq!(report.report.verdict, ValidationVerdictV1::Fit);
    assert_eq!(
        report.report.primary_reason_code,
        ValidationReasonCodeV1::RequirementsSatisfied
    );
    assert!(deployment_allows(&report));
}
