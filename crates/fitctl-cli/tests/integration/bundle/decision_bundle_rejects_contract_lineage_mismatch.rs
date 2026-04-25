// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{common, e2e};

#[test]
fn decision_bundle_rejects_contract_lineage_mismatch() {
    let root = common::unique_temp_dir("decision-bundle-mismatch");
    let contract_a_root = root.join("contract-a");
    let contract_b_root = root.join("contract-b");
    std::fs::create_dir_all(&contract_a_root).expect("contract-a dir should exist");
    std::fs::create_dir_all(&contract_b_root).expect("contract-b dir should exist");

    let survey_a_path = e2e::emit_survey_fixture(&contract_a_root, "linux-bare-metal-like-v1");
    let contract_a_path = e2e::derive_contract(
        &contract_a_root,
        &survey_a_path,
        "general_compute_default.v1.json",
    );
    let survey_b_path = e2e::emit_survey_fixture(&contract_b_root, "linux-arm-sbc-like-v1");
    let contract_b_path = e2e::derive_contract(
        &contract_b_root,
        &survey_b_path,
        "general_compute_default.v1.json",
    );

    let validation_output = e2e::run_fitctl([
        "validate",
        "--contract",
        contract_a_path
            .to_str()
            .expect("contract path should be UTF-8"),
        "--profile",
        common::repo_service_profile_path("general_compute_contract_only.v2.json")
            .to_str()
            .expect("service-profile path should be UTF-8"),
        "--validated-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&validation_output);
    let validation_path = root.join("validation-report.json");
    e2e::write_stdout(&validation_path, &validation_output);

    let bundle_output = e2e::run_fitctl([
        "bundle",
        "--validation-report",
        validation_path
            .to_str()
            .expect("validation path should be UTF-8"),
        "--contract",
        contract_b_path
            .to_str()
            .expect("contract path should be UTF-8"),
        "--bundled-at",
        common::FIXED_TIMESTAMP,
    ]);
    assert!(
        !bundle_output.status.success(),
        "unexpected success: {}",
        String::from_utf8_lossy(&bundle_output.stdout)
    );

    let stderr = String::from_utf8_lossy(&bundle_output.stderr);
    assert!(stderr.contains(
        "decision bundle embedded contract must match the validation basis contract lineage"
    ));
}
