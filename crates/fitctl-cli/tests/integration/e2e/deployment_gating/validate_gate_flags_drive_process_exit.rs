// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use crate::common;
use crate::e2e;
use fitctl_core::artifacts::validation_report_v1::{ValidationReportV1, ValidationVerdictV1};

fn prepared_general_contract(root: &Path) -> PathBuf {
    let survey_path = e2e::emit_survey_fixture(root, "linux-bare-metal-like-v1");
    e2e::derive_contract(root, &survey_path, "general_compute_default.v1.json")
}

fn status_code(output: &std::process::Output) -> i32 {
    output.status.code().expect("process should exit normally")
}

fn decode_validation_report(output: &std::process::Output) -> ValidationReportV1 {
    e2e::decode_json_stdout(output)
}

#[test]
fn validate_fail_on_unfit_accepts_fit() {
    let temp_dir = common::unique_temp_dir("validate-gate-fit");
    let contract_path = prepared_general_contract(&temp_dir);

    let output = e2e::run_fitctl([
        "validate",
        "--contract",
        contract_path
            .to_str()
            .expect("contract path should be UTF-8"),
        "--profile",
        common::repo_service_profile_path("general_compute_contract_only.v2.json")
            .to_str()
            .expect("profile path should be UTF-8"),
        "--validation-mode",
        "contract_only",
        "--validated-at",
        common::FIXED_TIMESTAMP,
        "--fail-on-unfit",
    ]);

    e2e::assert_success(&output);
    let report = decode_validation_report(&output);
    assert_eq!(report.report.verdict, ValidationVerdictV1::Fit);
}

#[test]
fn validate_fail_on_unfit_accepts_fit_with_degradation() {
    let temp_dir = common::unique_temp_dir("validate-gate-degraded");
    let contract_path = prepared_general_contract(&temp_dir);

    let output = e2e::run_fitctl([
        "validate",
        "--contract",
        contract_path
            .to_str()
            .expect("contract path should be UTF-8"),
        "--profile",
        common::repo_service_profile_path(
            "gpu_preferred_with_general_compute_fallback_contract_only.v2.json",
        )
        .to_str()
        .expect("profile path should be UTF-8"),
        "--validation-mode",
        "contract_only",
        "--validated-at",
        common::FIXED_TIMESTAMP,
        "--fail-on-unfit",
    ]);

    e2e::assert_success(&output);
    let report = decode_validation_report(&output);
    assert_eq!(
        report.report.verdict,
        ValidationVerdictV1::FitWithDegradation
    );
}

#[test]
fn validate_fail_on_unfit_rejects_unfit_but_keeps_stdout_json() {
    let temp_dir = common::unique_temp_dir("validate-gate-unfit");
    let contract_path = prepared_general_contract(&temp_dir);

    let output = e2e::run_fitctl([
        "validate",
        "--contract",
        contract_path
            .to_str()
            .expect("contract path should be UTF-8"),
        "--profile",
        common::repo_service_profile_path("gpu_required_contract_only.v2.json")
            .to_str()
            .expect("profile path should be UTF-8"),
        "--validation-mode",
        "contract_only",
        "--validated-at",
        common::FIXED_TIMESTAMP,
        "--fail-on-unfit",
    ]);

    assert_eq!(
        status_code(&output),
        i32::from(fitctl_core::EXIT_CODE_POLICY_REJECTION)
    );
    let report = decode_validation_report(&output);
    assert_eq!(report.report.verdict, ValidationVerdictV1::Unfit);
    assert!(String::from_utf8_lossy(&output.stderr).contains("--fail-on-unfit"));
}

#[test]
fn validate_require_fit_rejects_fit_with_degradation() {
    let temp_dir = common::unique_temp_dir("validate-gate-require-fit");
    let contract_path = prepared_general_contract(&temp_dir);

    let output = e2e::run_fitctl([
        "validate",
        "--contract",
        contract_path
            .to_str()
            .expect("contract path should be UTF-8"),
        "--profile",
        common::repo_service_profile_path(
            "gpu_preferred_with_general_compute_fallback_contract_only.v2.json",
        )
        .to_str()
        .expect("profile path should be UTF-8"),
        "--validation-mode",
        "contract_only",
        "--validated-at",
        common::FIXED_TIMESTAMP,
        "--require-fit",
    ]);

    assert_eq!(
        status_code(&output),
        i32::from(fitctl_core::EXIT_CODE_POLICY_REJECTION)
    );
    let report = decode_validation_report(&output);
    assert_eq!(
        report.report.verdict,
        ValidationVerdictV1::FitWithDegradation
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("--require-fit"));
}

#[test]
fn validate_fail_on_unfit_rejects_indeterminate() {
    let temp_dir = common::unique_temp_dir("validate-gate-indeterminate");
    let contract_path = prepared_general_contract(&temp_dir);
    let stale_state = e2e::emit_state_fixture(&temp_dir, "linux-bare-metal-like-stale-v1");

    let output = e2e::run_fitctl([
        "validate",
        "--contract",
        contract_path
            .to_str()
            .expect("contract path should be UTF-8"),
        "--profile",
        common::repo_service_profile_path("general_compute_stateful_thresholds.v2.json")
            .to_str()
            .expect("profile path should be UTF-8"),
        "--validation-mode",
        "state_required",
        "--state",
        stale_state.to_str().expect("state path should be UTF-8"),
        "--max-state-age",
        "1h",
        "--validated-at",
        common::FIXED_TIMESTAMP,
        "--fail-on-unfit",
    ]);

    assert_eq!(
        status_code(&output),
        i32::from(fitctl_core::EXIT_CODE_POLICY_REJECTION)
    );
    let report = decode_validation_report(&output);
    assert_eq!(report.report.verdict, ValidationVerdictV1::Indeterminate);
}

#[test]
fn validate_gate_flags_are_mutually_exclusive() {
    let output = e2e::run_fitctl(["validate", "--fail-on-unfit", "--require-fit"]);

    assert_eq!(
        status_code(&output),
        i32::from(fitctl_core::EXIT_CODE_USAGE_ERROR)
    );
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("choose either"));
}
