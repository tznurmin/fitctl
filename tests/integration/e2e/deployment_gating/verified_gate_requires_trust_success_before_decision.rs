// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common;
use crate::e2e;
use fitctl_core::artifacts::validation_report_v1::{ValidationReportV1, ValidationVerdictV1};
use fitctl_core::verify::VerificationReportV1;

fn trusted_gate_allows(
    verify_status: &std::process::ExitStatus,
    verify_report: &VerificationReportV1,
    validation_report: &ValidationReportV1,
) -> bool {
    verify_status.success()
        && verify_report.accepted_by_policy
        && matches!(
            validation_report.report.verdict,
            ValidationVerdictV1::Fit | ValidationVerdictV1::FitWithDegradation
        )
}

#[test]
fn verified_gate_requires_trust_success_before_decision() {
    let temp_dir = common::unique_temp_dir("integration-e2e-trusted-gate");
    let survey_path = e2e::emit_survey_fixture(&temp_dir, "linux-bare-metal-like-v1");
    let contract_path =
        e2e::derive_contract(&temp_dir, &survey_path, "general_compute_default.v1.json");

    let key_path = common::generate_ed25519_keypair(&temp_dir, "trusted-signer");
    let signed_contract_path = e2e::sign_artifact(&temp_dir, &contract_path, &key_path, "contract");

    let signed_contract: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&signed_contract_path).expect("signed contract should be readable"),
    )
    .expect("signed contract should decode");
    let key_id = signed_contract["envelope"]["signatures"][0]["key_id"]
        .as_str()
        .expect("signed contract key id should be present")
        .to_string();

    let trusted_policy = common::trust_policy_for_signer(&key_id);
    let rejecting_policy = fitctl_core::verify::TrustPolicyV1 {
        policy_id: "integration-rejecting-policy-v1".to_string(),
        trusted_signers: vec![],
        allow_self_signed: false,
        ..common::trust_policy_for_signer(&key_id)
    };

    let trusted_policy_path = temp_dir.join("trusted-policy.json");
    let rejecting_policy_path = temp_dir.join("rejecting-policy.json");
    common::write_json_file(&trusted_policy_path, &trusted_policy);
    common::write_json_file(&rejecting_policy_path, &rejecting_policy);

    let validation_output = e2e::run_fitctl([
        "validate",
        "--contract",
        signed_contract_path
            .to_str()
            .expect("signed contract path should be valid UTF-8"),
        "--profile",
        common::repo_service_profile_path("general_compute_contract_only.v1.json")
            .to_str()
            .expect("profile path should be valid UTF-8"),
        "--validation-mode",
        "contract_only",
        "--validated-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&validation_output);
    let validation_report: ValidationReportV1 = e2e::decode_json_stdout(&validation_output);
    assert_eq!(validation_report.report.verdict, ValidationVerdictV1::Fit);

    let trusted_verify_output = e2e::run_fitctl([
        "verify",
        "--input",
        signed_contract_path
            .to_str()
            .expect("signed contract path should be valid UTF-8"),
        "--policy",
        trusted_policy_path
            .to_str()
            .expect("trusted policy path should be valid UTF-8"),
    ]);
    let trusted_verify_report: VerificationReportV1 =
        e2e::decode_json_stdout(&trusted_verify_output);
    assert!(trusted_verify_output.status.success());
    assert!(trusted_verify_report.accepted_by_policy);
    assert!(trusted_gate_allows(
        &trusted_verify_output.status,
        &trusted_verify_report,
        &validation_report
    ));

    let rejecting_verify_output = e2e::run_fitctl([
        "verify",
        "--input",
        signed_contract_path
            .to_str()
            .expect("signed contract path should be valid UTF-8"),
        "--policy",
        rejecting_policy_path
            .to_str()
            .expect("rejecting policy path should be valid UTF-8"),
    ]);
    let rejecting_verify_report: VerificationReportV1 =
        e2e::decode_json_stdout(&rejecting_verify_output);
    assert_eq!(rejecting_verify_output.status.code(), Some(1));
    assert!(!rejecting_verify_report.accepted_by_policy);
    assert!(!trusted_gate_allows(
        &rejecting_verify_output.status,
        &rejecting_verify_report,
        &validation_report
    ));
}
