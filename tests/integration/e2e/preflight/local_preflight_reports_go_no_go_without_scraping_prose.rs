// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common;
use crate::e2e;
use fitctl_core::artifacts::validation_report_v1::{ValidationReportV1, ValidationVerdictV1};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreflightDecision {
    Continue,
    Abort,
}

fn preflight_decision(report: &ValidationReportV1) -> PreflightDecision {
    match report.report.verdict {
        ValidationVerdictV1::Fit | ValidationVerdictV1::FitWithDegradation => {
            PreflightDecision::Continue
        }
        ValidationVerdictV1::Unfit | ValidationVerdictV1::Indeterminate => PreflightDecision::Abort,
    }
}

fn validate_contract_only(
    contract_path: &std::path::Path,
    profile_file_name: &str,
) -> ValidationReportV1 {
    let output = e2e::run_fitctl([
        "validate",
        "--contract",
        contract_path
            .to_str()
            .expect("contract path should be valid UTF-8"),
        "--profile",
        common::repo_service_profile_path(profile_file_name)
            .to_str()
            .expect("profile path should be valid UTF-8"),
        "--validation-mode",
        "contract_only",
        "--validated-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&output);
    e2e::decode_json_stdout(&output)
}

#[test]
fn local_preflight_reports_go_no_go_without_scraping_prose() {
    let temp_dir = common::unique_temp_dir("integration-e2e-preflight");
    let bare_survey = e2e::emit_survey_fixture(&temp_dir, "linux-bare-metal-like-v1");
    let gpu_survey = e2e::emit_survey_fixture(&temp_dir, "linux-gpu-workstation-like-v1");
    let bare_contract =
        e2e::derive_contract(&temp_dir, &bare_survey, "general_compute_default.v1.json");
    let gpu_contract = e2e::derive_contract(&temp_dir, &gpu_survey, "gpu_compute_default.v1.json");

    let continue_report =
        validate_contract_only(&bare_contract, "general_compute_contract_only.v2.json");
    let abort_report = validate_contract_only(
        &gpu_contract,
        "general_compute_no_gpu_contract_only.v2.json",
    );

    assert_eq!(
        preflight_decision(&continue_report),
        PreflightDecision::Continue
    );
    assert_eq!(continue_report.report.verdict, ValidationVerdictV1::Fit);

    assert_eq!(preflight_decision(&abort_report), PreflightDecision::Abort);
    assert_eq!(abort_report.report.verdict, ValidationVerdictV1::Unfit);
    assert!(!abort_report.report.summary.is_empty());
}
