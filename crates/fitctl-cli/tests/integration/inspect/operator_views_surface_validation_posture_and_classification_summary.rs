// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;
use std::process::Command;

use fitctl_core::artifacts::validation_report_v1::ValidationModeV1;
use fitctl_core::classify::{classify_batch_v1, BatchClassificationRequestV1};

use crate::cli;
use crate::common;

fn inspect_output(path: &Path) -> String {
    let output = Command::new(cli::fitctl_bin())
        .args([
            "inspect",
            "--input",
            path.to_str().expect("artifact path should be valid UTF-8"),
        ])
        .output()
        .expect("fitctl inspect should execute");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("inspect output should be UTF-8")
}

#[test]
fn validation_inspect_surfaces_operator_posture() {
    let temp_dir = common::unique_temp_dir("integration-inspect-operator-validation");

    let fit_report = common::validate_with_profile(
        common::derive_contract_from_fixture("linux-bare-metal-like-v1"),
        common::load_service_profile_file("general_compute_contract_only.v2.json"),
        None,
        ValidationModeV1::ContractOnly,
        None,
    );
    let fit_path = temp_dir.join("fit.validation.json");
    common::write_json_file(&fit_path, &fit_report);

    let stale_report = common::validate_with_profile(
        common::derive_contract_from_fixture("linux-bare-metal-like-v1"),
        common::load_service_profile_file("general_compute_stateful_thresholds.v2.json"),
        Some(common::collect_state_fixture(
            "linux-bare-metal-like-stale-v1",
        )),
        ValidationModeV1::StateRequired,
        Some(600),
    );
    let stale_path = temp_dir.join("stale.validation.json");
    common::write_json_file(&stale_path, &stale_report);

    let fit_summary = inspect_output(&fit_path);
    assert!(fit_summary.contains("Operator posture: proceed"));

    let stale_summary = inspect_output(&stale_path);
    assert!(stale_summary.contains("Operator posture: hold_for_evidence"));
    assert!(stale_summary.contains("State freshness: stale at validation"));
}

#[test]
fn batch_classification_inspect_surfaces_operator_counts_and_row_summaries() {
    let temp_dir = common::unique_temp_dir("integration-inspect-operator-classify");
    let report_path = temp_dir.join("batch-classification-report.json");
    let report = classify_batch_v1(BatchClassificationRequestV1 {
        contracts: vec![
            common::derive_contract_from_fixture("linux-bare-metal-like-v1"),
            common::derive_contract_from_fixture("linux-network-mixed-like-v1"),
            common::derive_contract_from_fixture_with_policy(
                "linux-gpu-dual-numa-like-v1",
                "gpu_compute_default.v1.json",
            ),
        ],
        service_profiles: vec![
            common::load_service_profile_file("general_compute_contract_only.v2.json"),
            common::load_service_profile_file("general_compute_no_gpu_contract_only.v2.json"),
            common::load_service_profile_file("gpu_required_contract_only.v2.json"),
        ],
        host_states: vec![],
        validation_mode: ValidationModeV1::ContractOnly,
        max_state_age_seconds: None,
        validated_at: common::FIXED_TIMESTAMP.to_string(),
    })
    .expect("batch classification should succeed");
    common::write_json_file(&report_path, &report);

    let summary = inspect_output(&report_path);

    assert!(summary.contains(
        "Operator posture counts: proceed 6; proceed_with_degradation 0; stop 3; hold_for_evidence 0"
    ));
    assert!(summary.contains(
        "Primary reason tally: capability_unknown=2, requirement_unsatisfied=1, requirements_satisfied=6"
    ));
    assert!(summary.contains(
        "contract-linux-bare-metal-like-v1-general-compute-default-v1 -> service-profile-general-compute-contract-only-v1: fit (requirements_satisfied)"
    ));
    assert!(summary.contains(
        "contract-linux-gpu-dual-numa-like-v1-gpu-compute-default-v1 -> service-profile-general-compute-no-gpu-contract-only-v1: unfit (requirement_unsatisfied)"
    ));
}
