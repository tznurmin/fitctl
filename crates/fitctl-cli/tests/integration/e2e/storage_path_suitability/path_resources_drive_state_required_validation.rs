// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

use crate::{common, e2e};

#[test]
fn path_resources_drive_state_required_validation() {
    let root = common::unique_temp_dir("path-resources-validation");
    let survey_path = e2e::emit_survey_fixture(&root, "linux-gpu-workstation-like-v1");
    let contract_path =
        e2e::derive_contract(&root, &survey_path, "general_compute_default.v1.json");

    let state_output = e2e::run_fitctl([
        "state",
        "--fixture",
        "linux-gpu-workstation-like-path-resources-fit-v1",
    ]);
    e2e::assert_success(&state_output);
    let state_path = root.join("gpu.path-state.json");
    e2e::write_stdout(&state_path, &state_output);

    let inspect_output = e2e::run_fitctl([
        "inspect",
        "--input",
        state_path.to_str().expect("state path should be UTF-8"),
    ]);
    e2e::assert_success(&inspect_output);
    let inspect_text =
        String::from_utf8(inspect_output.stdout).expect("inspect output should be UTF-8");
    assert!(inspect_text.contains("Paths"));
    assert!(inspect_text.contains("Path model-cache"));
    assert!(inspect_text.contains("Path output"));

    let validation_output = e2e::run_fitctl([
        "validate",
        "--contract",
        contract_path
            .to_str()
            .expect("contract path should be UTF-8"),
        "--profile",
        common::repo_service_profile_path("local_image_generation_storage_state_required.v2.json")
            .to_str()
            .expect("profile path should be UTF-8"),
        "--state",
        state_path.to_str().expect("state path should be UTF-8"),
        "--validation-mode",
        "state_required",
        "--validated-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&validation_output);
    let validation: Value = e2e::decode_json_stdout(&validation_output);
    assert_eq!(validation["report"]["verdict"], "fit");
    assert!(validation["report"]["matched_requirements"]
        .as_array()
        .expect("matched requirements should be an array")
        .iter()
        .any(|value| value == "core_requirements.required_paths[model-cache]"));
}

#[test]
fn insufficient_path_space_is_unfit() {
    let root = common::unique_temp_dir("path-resources-unfit");
    let survey_path = e2e::emit_survey_fixture(&root, "linux-gpu-workstation-like-v1");
    let contract_path =
        e2e::derive_contract(&root, &survey_path, "general_compute_default.v1.json");
    let state_path =
        e2e::emit_state_fixture(&root, "linux-gpu-workstation-like-path-resources-fit-v1");

    let mut profile: Value = serde_json::from_str(
        &std::fs::read_to_string(common::repo_service_profile_path(
            "local_image_generation_storage_state_required.v2.json",
        ))
        .expect("profile should read"),
    )
    .expect("profile should decode");
    profile["profile"]["core_requirements"]["required_paths"][1]["min_available_bytes"] =
        serde_json::json!(1_099_511_627_776_u64);
    let profile_path = root.join("too-much-output-space.profile.json");
    std::fs::write(
        &profile_path,
        serde_json::to_vec_pretty(&profile).expect("profile should encode"),
    )
    .expect("profile should write");

    let validation_output = e2e::run_fitctl([
        "validate",
        "--contract",
        contract_path
            .to_str()
            .expect("contract path should be UTF-8"),
        "--profile",
        profile_path.to_str().expect("profile path should be UTF-8"),
        "--state",
        state_path.to_str().expect("state path should be UTF-8"),
        "--validation-mode",
        "state_required",
        "--validated-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&validation_output);
    let validation: Value = e2e::decode_json_stdout(&validation_output);
    assert_eq!(validation["report"]["verdict"], "unfit");
    assert_eq!(
        validation["report"]["primary_reason_code"],
        "requirement_unsatisfied"
    );
    assert!(validation["report"]["failed_requirements"]
        .as_array()
        .expect("failed requirements should be an array")
        .iter()
        .any(|value| value == "core_requirements.required_paths[output]"));
}
