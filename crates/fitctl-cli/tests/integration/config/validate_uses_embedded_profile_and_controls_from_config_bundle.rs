// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

use crate::common;
use crate::e2e;

#[test]
fn config_bundle_validate_reuses_embedded_profile_and_controls() {
    let root = common::unique_temp_dir("validate-from-config-bundle");
    let survey_path = e2e::emit_survey_fixture(&root, "linux-bare-metal-like-v1");
    let state_path = e2e::emit_state_fixture(&root, "linux-bare-metal-like-fresh-v1");
    let contract_path =
        e2e::derive_contract(&root, &survey_path, "general_compute_default.v1.json");

    let explicit = e2e::run_fitctl([
        "validate",
        "--contract",
        contract_path
            .to_str()
            .expect("contract path should be valid UTF-8"),
        "--profile",
        common::repo_service_profile_path("general_compute_stateful_thresholds.v2.json")
            .to_str()
            .expect("profile path should be valid UTF-8"),
        "--validation-mode",
        "state_required",
        "--state",
        state_path
            .to_str()
            .expect("state path should be valid UTF-8"),
        "--max-state-age",
        "600",
        "--validated-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&explicit);

    let bundle_output = e2e::run_fitctl([
        "bundle-config",
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
        "--bundled-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&bundle_output);
    let bundle_path = root.join("general-compute.validate.config-bundle.json");
    e2e::write_stdout(&bundle_path, &bundle_output);

    let bundled = e2e::run_fitctl([
        "validate",
        "--contract",
        contract_path
            .to_str()
            .expect("contract path should be valid UTF-8"),
        "--config-bundle",
        bundle_path
            .to_str()
            .expect("bundle path should be valid UTF-8"),
        "--state",
        state_path
            .to_str()
            .expect("state path should be valid UTF-8"),
        "--validated-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&bundled);

    let explicit_json: Value = e2e::decode_json_stdout(&explicit);
    let bundled_json: Value = e2e::decode_json_stdout(&bundled);
    assert_eq!(explicit_json["report"], bundled_json["report"]);
    assert_eq!(
        explicit_json["validation_basis"],
        bundled_json["validation_basis"]
    );
}
