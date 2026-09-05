// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;
use std::path::{Path, PathBuf};

use crate::{common, e2e};

fn emit_live_survey(root: &Path) -> PathBuf {
    let output = e2e::run_fitctl(["survey"]);
    e2e::assert_success(&output);
    let path = root.join("live.survey.json");
    e2e::write_stdout(&path, &output);
    path
}

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

#[test]
fn validate_live_state_writes_state_and_validation_outputs_before_gate_exit() {
    let root = common::unique_temp_dir("path-admission-output-retention");
    let checked_path = root.join("checked");
    std::fs::create_dir_all(&checked_path).expect("checked path should be created");
    let survey_path = emit_live_survey(&root);
    let contract_path =
        e2e::derive_contract(&root, &survey_path, "general_compute_default.v1.json");

    let mut profile: Value = serde_json::from_str(
        &std::fs::read_to_string(common::repo_service_profile_path(
            "general_compute_no_gpu_contract_only.v2.json",
        ))
        .expect("profile should read"),
    )
    .expect("profile should decode");
    profile["profile"]["core_requirements"]["required_paths"] = serde_json::json!([
        {
            "path_id": "scratch",
            "min_available_bytes": u64::MAX
        }
    ]);
    let profile_path = root.join("impossible-path-space.profile.json");
    std::fs::write(
        &profile_path,
        serde_json::to_vec_pretty(&profile).expect("profile should encode"),
    )
    .expect("profile should write");

    let state_out = root.join("live-state.json");
    let validation_out = root.join("validation.json");
    let output = e2e::run_fitctl([
        "validate",
        "--contract",
        contract_path
            .to_str()
            .expect("contract path should be UTF-8"),
        "--profile",
        profile_path.to_str().expect("profile path should be UTF-8"),
        "--live-state",
        "--path-check",
        &format!(
            "scratch={}",
            checked_path.to_str().expect("checked path should be UTF-8")
        ),
        "--validation-mode",
        "state_required",
        "--state-out",
        state_out.to_str().expect("state-out path should be UTF-8"),
        "--validation-out",
        validation_out
            .to_str()
            .expect("validation-out path should be UTF-8"),
        "--fail-on-unfit",
    ]);
    assert!(
        !output.status.success(),
        "non-fit validation should make --fail-on-unfit exit nonzero"
    );
    assert!(
        state_out.is_file(),
        "state artifact should be retained before gate exit"
    );
    assert!(
        validation_out.is_file(),
        "validation artifact should be retained before gate exit"
    );

    let stdout_validation: Value = e2e::decode_json_stdout(&output);
    let file_validation: Value = serde_json::from_slice(
        &std::fs::read(&validation_out).expect("validation file should read"),
    )
    .expect("validation file should decode");
    let state: Value =
        serde_json::from_slice(&std::fs::read(&state_out).expect("state file should read"))
            .expect("state file should decode");
    assert_eq!(stdout_validation, file_validation);
    assert_eq!(state["envelope"]["schema_id"], "host-state.v2");
    assert!(
        matches!(
            file_validation["report"]["verdict"].as_str(),
            Some("unfit" | "indeterminate")
        ),
        "the impossible path-space requirement must never be accepted"
    );
}

#[test]
fn validate_rejects_state_out_without_live_state() {
    let root = common::unique_temp_dir("path-admission-state-out-invalid");
    let survey_path = e2e::emit_survey_fixture(&root, "linux-gpu-workstation-like-v1");
    let contract_path =
        e2e::derive_contract(&root, &survey_path, "general_compute_default.v1.json");
    let state_path =
        e2e::emit_state_fixture(&root, "linux-gpu-workstation-like-path-resources-fit-v1");
    let state_out = root.join("should-not-exist.json");

    let output = e2e::run_fitctl([
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
        "--state-out",
        state_out.to_str().expect("state-out path should be UTF-8"),
    ]);
    assert!(!output.status.success());
    assert!(
        !state_out.exists(),
        "--state-out without --live-state must not write a partial artifact"
    );
}

#[test]
fn state_pair_probe_records_pair_capabilities() {
    let root = common::unique_temp_dir("path-admission-pair-probe");
    let cache = root.join("cache");
    let workspace = root.join("workspace");
    std::fs::create_dir_all(&cache).expect("cache path should be created");
    std::fs::create_dir_all(&workspace).expect("workspace path should be created");

    let output = e2e::run_fitctl([
        "state",
        "--live",
        "--path-check",
        &format!(
            "cache={}",
            cache.to_str().expect("cache path should be UTF-8")
        ),
        "--path-check",
        &format!(
            "workspace={}",
            workspace.to_str().expect("workspace path should be UTF-8")
        ),
        "--probe-path-link-pair",
        "cache:workspace",
    ]);
    e2e::assert_success(&output);
    let state: Value = e2e::decode_json_stdout(&output);
    let link_pairs = state["state"]["core_state"]["path_resources"]["link_pairs"]
        .as_array()
        .expect("link pairs should be emitted");
    assert!(link_pairs.iter().any(|pair| {
        pair["pair_id"] == "cache-to-workspace"
            && pair["from_path_id"] == "cache"
            && pair["to_path_id"] == "workspace"
            && pair["hardlink_supported"]["state"] == "observed"
    }));
}

#[test]
fn state_rejects_pair_probe_for_unknown_path_id() {
    let root = common::unique_temp_dir("path-admission-pair-probe-invalid");
    let cache = root.join("cache");
    std::fs::create_dir_all(&cache).expect("cache path should be created");

    let output = e2e::run_fitctl([
        "state",
        "--live",
        "--path-check",
        &format!(
            "cache={}",
            cache.to_str().expect("cache path should be UTF-8")
        ),
        "--probe-path-link-pair",
        "cache:workspace",
    ]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--probe-path-link-pair"));
    assert!(stderr.contains("workspace"));
}

#[test]
fn state_rejects_health_probe_for_unknown_path_id() {
    let root = common::unique_temp_dir("path-health-probe-invalid");
    let cache = root.join("cache");
    std::fs::create_dir_all(&cache).expect("cache path should be created");

    let output = e2e::run_fitctl([
        "state",
        "--live",
        "--path-check",
        &format!(
            "cache={}",
            cache.to_str().expect("cache path should be UTF-8")
        ),
        "--probe-path-health",
        "workspace",
    ]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--probe-path-health"));
    assert!(stderr.contains("workspace"));
}

#[test]
fn state_health_probe_records_health_section() {
    let root = common::unique_temp_dir("path-health-probe-state");
    let cache = root.join("cache");
    std::fs::create_dir_all(&cache).expect("cache path should be created");

    let output = e2e::run_fitctl([
        "state",
        "--live",
        "--path-check",
        &format!(
            "cache={}",
            cache.to_str().expect("cache path should be UTF-8")
        ),
        "--probe-path-health",
        "cache",
    ]);
    e2e::assert_success(&output);
    let state: Value = e2e::decode_json_stdout(&output);
    let path = &state["state"]["core_state"]["path_resources"]["paths"][0];
    assert_eq!(path["path_id"], "cache");
    assert!(path.get("storage_health").is_some());
    assert!(path["storage_health"].get("health_state").is_some());
    assert!(path["storage_health"].get("probe_method").is_some());
}

#[test]
fn validate_live_state_records_health_section_when_requested() {
    let root = common::unique_temp_dir("path-health-probe-validate");
    let checked_path = root.join("checked");
    std::fs::create_dir_all(&checked_path).expect("checked path should be created");
    let survey_path = emit_live_survey(&root);
    let contract_path =
        e2e::derive_contract(&root, &survey_path, "general_compute_default.v1.json");
    let state_out = root.join("state-with-health.json");

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
        "--live-state",
        "--path-check",
        &format!(
            "scratch={}",
            checked_path.to_str().expect("checked path should be UTF-8")
        ),
        "--probe-path-health",
        "scratch",
        "--validation-mode",
        "state_required",
        "--state-out",
        state_out.to_str().expect("state-out path should be UTF-8"),
    ]);
    e2e::assert_success(&output);
    let state: Value =
        serde_json::from_slice(&std::fs::read(&state_out).expect("state file should read"))
            .expect("state file should decode");
    assert!(state["state"]["core_state"]["path_resources"]["paths"][0]
        .get("storage_health")
        .is_some());
}

#[test]
fn inspect_state_renders_storage_health_summary() {
    let root = common::unique_temp_dir("path-health-probe-inspect");
    let cache = root.join("cache");
    std::fs::create_dir_all(&cache).expect("cache path should be created");

    let state_output = e2e::run_fitctl([
        "state",
        "--live",
        "--path-check",
        &format!(
            "cache={}",
            cache.to_str().expect("cache path should be UTF-8")
        ),
        "--probe-path-health",
        "cache",
    ]);
    e2e::assert_success(&state_output);
    let state_path = root.join("state.json");
    e2e::write_stdout(&state_path, &state_output);

    let inspect_output = e2e::run_fitctl([
        "inspect",
        "--input",
        state_path.to_str().expect("state path should be UTF-8"),
    ]);
    e2e::assert_success(&inspect_output);
    let inspect_text =
        String::from_utf8(inspect_output.stdout).expect("inspect output should be UTF-8");
    assert!(inspect_text.contains("Storage health"));
}
