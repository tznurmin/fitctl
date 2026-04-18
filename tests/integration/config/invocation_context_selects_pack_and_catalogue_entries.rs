// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

use crate::common;
use crate::e2e;

#[test]
fn invocation_context_selects_pack_and_catalogue_entries_for_contract_and_validate() {
    let root = common::unique_temp_dir("invocation-pack-selection");
    let survey_path = e2e::emit_survey_fixture(&root, "linux-bare-metal-like-v1");
    let state_path = e2e::emit_state_fixture(&root, "linux-bare-metal-like-fresh-v1");
    let explicit_contract_path =
        e2e::derive_contract(&root, &survey_path, "general_compute_default.v1.json");

    let explicit_validation = e2e::run_fitctl([
        "validate",
        "--contract",
        explicit_contract_path
            .to_str()
            .expect("contract path should be UTF-8"),
        "--profile",
        common::repo_service_profile_path("general_compute_stateful_thresholds.v2.json")
            .to_str()
            .expect("profile path should be UTF-8"),
        "--validation-mode",
        "state_required",
        "--state",
        state_path.to_str().expect("state path should be UTF-8"),
        "--max-state-age",
        "600",
        "--validated-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&explicit_validation);

    let invocation_contract = e2e::run_fitctl([
        "contract",
        "--survey",
        survey_path.to_str().expect("survey path should be UTF-8"),
        "--policy-pack",
        common::repo_policy_pack_path("general_compute_default_pack.v1.json")
            .to_str()
            .expect("policy-pack path should be UTF-8"),
        "--invocation-context",
        common::repo_invocation_context_path("general_compute_pack_state_required.v1.json")
            .to_str()
            .expect("invocation path should be UTF-8"),
        "--derived-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&invocation_contract);

    let invocation_validation = e2e::run_fitctl([
        "validate",
        "--survey",
        survey_path.to_str().expect("survey path should be UTF-8"),
        "--policy-pack",
        common::repo_policy_pack_path("general_compute_default_pack.v1.json")
            .to_str()
            .expect("policy-pack path should be UTF-8"),
        "--service-profile-catalogue",
        common::repo_service_profile_catalogue_path("general_compute.v1.json")
            .to_str()
            .expect("catalogue path should be UTF-8"),
        "--invocation-context",
        common::repo_invocation_context_path("general_compute_pack_state_required.v1.json")
            .to_str()
            .expect("invocation path should be UTF-8"),
        "--state",
        state_path.to_str().expect("state path should be UTF-8"),
        "--validated-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&invocation_validation);

    let explicit_contract_json: Value = serde_json::from_slice(
        &std::fs::read(&explicit_contract_path).expect("explicit contract should be readable"),
    )
    .expect("explicit contract should decode");
    let invocation_contract_json: Value = e2e::decode_json_stdout(&invocation_contract);
    assert_eq!(explicit_contract_json, invocation_contract_json);

    let explicit_validation_json: Value = e2e::decode_json_stdout(&explicit_validation);
    let invocation_validation_json: Value = e2e::decode_json_stdout(&invocation_validation);
    assert_eq!(
        explicit_validation_json["report"],
        invocation_validation_json["report"]
    );
    assert_eq!(
        explicit_validation_json["validation_basis"],
        invocation_validation_json["validation_basis"]
    );
}
