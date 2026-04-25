// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

use crate::common;
use crate::e2e;

#[test]
fn classify_accepts_invocation_context_selected_single_catalogue_profile() {
    let root = common::unique_temp_dir("catalogue-profile-classify");
    let survey_path = e2e::emit_survey_fixture(&root, "linux-bare-metal-like-v1");
    let contract_path =
        e2e::derive_contract(&root, &survey_path, "general_compute_default.v1.json");

    let explicit = e2e::run_fitctl([
        "classify",
        "--contract",
        contract_path
            .to_str()
            .expect("contract path should be UTF-8"),
        "--service-profile-catalogue",
        common::repo_service_profile_catalogue_path("general_compute.v1.json")
            .to_str()
            .expect("catalogue path should be UTF-8"),
        "--profile-id",
        "general_compute_stateful_thresholds_v1",
        "--validated-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&explicit);

    let invocation = e2e::run_fitctl([
        "classify",
        "--contract",
        contract_path
            .to_str()
            .expect("contract path should be UTF-8"),
        "--service-profile-catalogue",
        common::repo_service_profile_catalogue_path("general_compute.v1.json")
            .to_str()
            .expect("catalogue path should be UTF-8"),
        "--invocation-context",
        common::repo_invocation_context_path("general_compute_pack_state_required.v1.json")
            .to_str()
            .expect("invocation path should be UTF-8"),
        "--validated-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&invocation);

    let explicit_json: Value = e2e::decode_json_stdout(&explicit);
    let invocation_json: Value = e2e::decode_json_stdout(&invocation);
    assert_eq!(explicit_json, invocation_json);
}
