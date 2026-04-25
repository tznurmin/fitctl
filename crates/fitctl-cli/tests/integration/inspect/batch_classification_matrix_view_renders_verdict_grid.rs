// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common;
use crate::e2e;

#[test]
fn batch_classification_matrix_view_renders_verdict_grid() {
    let temp_dir = common::unique_temp_dir("integration-inspect-matrix");
    let bare_survey = e2e::emit_survey_fixture(&temp_dir, "linux-bare-metal-like-v1");
    let network_survey = e2e::emit_survey_fixture(&temp_dir, "linux-network-mixed-like-v1");
    let gpu_survey = e2e::emit_survey_fixture(&temp_dir, "linux-gpu-dual-numa-like-v1");
    let bare_contract =
        e2e::derive_contract(&temp_dir, &bare_survey, "general_compute_default.v1.json");
    let network_contract = e2e::derive_contract(
        &temp_dir,
        &network_survey,
        "general_compute_default.v1.json",
    );
    let gpu_contract = e2e::derive_contract(&temp_dir, &gpu_survey, "gpu_compute_default.v1.json");

    let classify_output = e2e::run_fitctl([
        "classify",
        "--contract",
        bare_contract
            .to_str()
            .expect("bare contract path should be valid UTF-8"),
        "--contract",
        network_contract
            .to_str()
            .expect("network contract path should be valid UTF-8"),
        "--contract",
        gpu_contract
            .to_str()
            .expect("gpu contract path should be valid UTF-8"),
        "--profile",
        common::repo_service_profile_path("general_compute_contract_only.v2.json")
            .to_str()
            .expect("general profile path should be valid UTF-8"),
        "--profile",
        common::repo_service_profile_path("general_compute_no_gpu_contract_only.v2.json")
            .to_str()
            .expect("no-gpu profile path should be valid UTF-8"),
        "--profile",
        common::repo_service_profile_path("gpu_required_contract_only.v2.json")
            .to_str()
            .expect("gpu profile path should be valid UTF-8"),
        "--validated-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&classify_output);

    let report_path = temp_dir.join("batch.classification.json");
    e2e::write_stdout(&report_path, &classify_output);

    let inspect_output = e2e::run_fitctl([
        "inspect",
        "--input",
        report_path
            .to_str()
            .expect("report path should be valid UTF-8"),
        "--view",
        "matrix",
    ]);
    e2e::assert_success(&inspect_output);

    let matrix = String::from_utf8(inspect_output.stdout).expect("inspect output should be UTF-8");
    assert!(matrix.contains("Matrix"));
    assert!(matrix.contains("Verdict matrix:"));
    assert!(matrix.contains("Each row checks one Profile against one Host under one Contract."));
    assert!(matrix.contains("Profile = workload need; Host = candidate machine; Contract = host claim under policy; Verdict = fit result."));
    assert!(matrix.contains("Host"));
    assert!(matrix.contains("Contract"));
    assert!(matrix.contains("Profile"));
    assert!(matrix.contains("Verdict"));
    assert!(matrix.contains("cpu-host-01"));
    assert!(matrix.contains("network-mixed-01"));
    assert!(matrix.contains("gpu-numa-01"));
    assert!(matrix.contains("General compute default"));
    assert!(matrix.contains("GPU compute default"));
    assert!(matrix.contains("General compute"));
    assert!(matrix.contains("CPU only"));
    assert!(matrix.contains("GPU required"));
    assert!(matrix.lines().any(|line| {
        line.contains("General compute")
            && line.contains("gpu-numa-01")
            && line.contains("GPU compute default")
    }));
    assert!(matrix.lines().any(|line| {
        line.contains("CPU only")
            && line.contains("gpu-numa-01")
            && line.contains("GPU compute default")
            && line.contains("unfit")
    }));
    assert!(matrix.lines().any(|line| {
        line.contains("GPU required")
            && line.contains("cpu-host-01")
            && line.contains("General compute default")
            && line.contains("unfit")
    }));
    assert!(matrix.contains("unfit"));
    assert!(matrix.contains("fit"));
}
