// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

use crate::common;
use crate::e2e;

#[test]
fn validate_convenience_chain_matches_explicit_contract_flow() {
    let root = common::unique_temp_dir("validation-convenience");
    let survey_path = e2e::emit_survey_fixture(&root, "linux-bare-metal-like-v1");
    let contract_path =
        e2e::derive_contract(&root, &survey_path, "general_compute_default.v1.json");
    let profile_path = common::repo_service_profile_path("general_compute_contract_only.v2.json");
    let policy_path = common::repo_policy_file_path("general_compute_default.v1.json");

    let explicit = e2e::run_fitctl([
        "validate",
        "--contract",
        contract_path
            .to_str()
            .expect("contract path should be UTF-8"),
        "--profile",
        profile_path.to_str().expect("profile path should be UTF-8"),
        "--validated-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&explicit);

    let convenience = e2e::run_fitctl([
        "validate",
        "--survey",
        survey_path.to_str().expect("survey path should be UTF-8"),
        "--policy",
        policy_path.to_str().expect("policy path should be UTF-8"),
        "--profile",
        profile_path.to_str().expect("profile path should be UTF-8"),
        "--validated-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&convenience);

    let explicit_json: Value = e2e::decode_json_stdout(&explicit);
    let convenience_json: Value = e2e::decode_json_stdout(&convenience);

    assert_eq!(explicit_json["report"], convenience_json["report"]);
    assert_eq!(
        explicit_json["validation_basis"],
        convenience_json["validation_basis"]
    );
}

#[test]
fn validate_convenience_chain_rejects_mixed_input_sets() {
    let root = common::unique_temp_dir("validation-convenience-mixed");
    let survey_path = e2e::emit_survey_fixture(&root, "linux-bare-metal-like-v1");
    let contract_path =
        e2e::derive_contract(&root, &survey_path, "general_compute_default.v1.json");
    let policy_path = common::repo_policy_file_path("general_compute_default.v1.json");
    let profile_path = common::repo_service_profile_path("general_compute_contract_only.v2.json");

    let output = e2e::run_fitctl([
        "validate",
        "--contract",
        contract_path
            .to_str()
            .expect("contract path should be UTF-8"),
        "--survey",
        survey_path.to_str().expect("survey path should be UTF-8"),
        "--policy",
        policy_path.to_str().expect("policy path should be UTF-8"),
        "--profile",
        profile_path.to_str().expect("profile path should be UTF-8"),
    ]);

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("choose either --contract or --survey")
    );
}
