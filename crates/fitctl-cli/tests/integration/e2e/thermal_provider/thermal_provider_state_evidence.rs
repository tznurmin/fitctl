// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

use crate::{common, e2e};

#[test]
fn state_thermal_provider_config_records_thermal_resources() {
    let root = common::unique_temp_dir("thermal-state");
    let config_path = write_lm_sensors_provider_config(&root);

    let output = e2e::run_fitctl([
        "state",
        "--live",
        "--thermal-provider-config",
        config_path.to_str().expect("config path should be UTF-8"),
    ]);
    e2e::assert_success(&output);
    let state: Value = e2e::decode_json_stdout(&output);
    let thermal = &state["state"]["core_state"]["thermal_resources"];

    assert_eq!(thermal["providers"][0]["provider_id"], "lm-sensors-fixture");
    assert_eq!(thermal["providers"][0]["outcome"], "success");
    assert!(thermal["readings"]
        .as_array()
        .expect("readings array")
        .iter()
        .any(|reading| reading["sensor_role"] == "nvme"
            && reading["temperature_millidegrees_celsius"] == 43_500));
}

#[test]
fn validate_live_state_records_thermal_resources_when_requested() {
    let root = common::unique_temp_dir("thermal-validate");
    let config_path = write_lm_sensors_provider_config(&root);
    let survey_output = e2e::run_fitctl(["survey"]);
    e2e::assert_success(&survey_output);
    let survey_path = root.join("live.survey.json");
    e2e::write_stdout(&survey_path, &survey_output);
    let contract_path =
        e2e::derive_contract(&root, &survey_path, "general_compute_default.v1.json");
    let state_out = root.join("thermal.state.json");

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
        "--thermal-provider-config",
        config_path.to_str().expect("config path should be UTF-8"),
        "--validation-mode",
        "state_required",
        "--state-out",
        state_out.to_str().expect("state-out path should be UTF-8"),
    ]);
    e2e::assert_success(&output);

    let state: Value =
        serde_json::from_slice(&fs::read(&state_out).expect("state file should read"))
            .expect("state file should decode");
    assert!(state["state"]["core_state"]
        .get("thermal_resources")
        .is_some());
}

#[test]
fn inspect_state_renders_thermal_summary() {
    let root = common::unique_temp_dir("thermal-inspect");
    let config_path = write_lm_sensors_provider_config(&root);
    let state_output = e2e::run_fitctl([
        "state",
        "--live",
        "--thermal-provider-config",
        config_path.to_str().expect("config path should be UTF-8"),
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
    let text = String::from_utf8(inspect_output.stdout).expect("inspect output should be UTF-8");
    assert!(text.contains("Thermal"));
    assert!(text.contains("lm-sensors-fixture"));
}

#[test]
fn state_rejects_invalid_thermal_provider_config() {
    let root = common::unique_temp_dir("thermal-invalid-config");
    let config_path = root.join("thermal-provider.json");
    fs::write(
        &config_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_id": "fitctl.thermal-provider-config.v1",
            "schema_version": 1,
            "providers": [
                {
                    "provider_id": "bad-shell",
                    "provider_kind": "lm_sensors_json",
                    "command": ["/bin/sh", "-c", "echo unsafe"],
                    "evidence_target": {
                        "target_kind": "current_host",
                        "collection_path": "local_process"
                    }
                }
            ]
        }))
        .expect("config should encode"),
    )
    .expect("config should write");

    let output = e2e::run_fitctl([
        "state",
        "--live",
        "--thermal-provider-config",
        config_path.to_str().expect("config path should be UTF-8"),
    ]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("thermal provider"));
    assert!(stderr.contains("shell"));
}

#[test]
fn state_collect_thermal_records_builtin_provider_outcomes() {
    let output = e2e::run_fitctl(["state", "--live", "--collect", "thermal"]);
    e2e::assert_success(&output);
    let state: Value = e2e::decode_json_stdout(&output);
    let providers = state["state"]["core_state"]["thermal_resources"]["providers"]
        .as_array()
        .expect("thermal providers should be present");

    assert!(providers
        .iter()
        .any(|provider| provider["provider_id"] == "local-lm-sensors"));
    assert!(providers
        .iter()
        .any(|provider| provider["provider_id"] == "local-nvidia-smi-thermal"));
}

#[test]
fn state_collect_rejects_unknown_feature() {
    let output = e2e::run_fitctl(["state", "--live", "--collect", "made-up-feature"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown --collect feature"));
}

#[test]
fn state_collect_memory_reliability_emits_section() {
    let output = e2e::run_fitctl(["state", "--live", "--collect", "memory-reliability"]);
    e2e::assert_success(&output);
    let state: Value = e2e::decode_json_stdout(&output);
    let memory = &state["state"]["core_state"]["memory_reliability"];

    assert!(memory.is_object());
    assert_eq!(memory["providers"][0]["provider_id"], "local-edac-sysfs");
}

#[test]
fn state_collect_gpu_reliability_emits_section() {
    let output = e2e::run_fitctl(["state", "--live", "--collect", "gpu-reliability"]);
    e2e::assert_success(&output);
    let state: Value = e2e::decode_json_stdout(&output);
    let gpu = &state["state"]["core_state"]["gpu_reliability"];

    assert!(gpu.is_object());
    assert_eq!(
        gpu["providers"][0]["provider_id"],
        "local-nvidia-smi-reliability"
    );
}

fn write_lm_sensors_provider_config(root: &Path) -> PathBuf {
    let provider_script = common::fixture_command::write(
        &common::repo_root(),
        root,
        "emit-lm-sensors-json",
        "cat <<'JSON'\n{\"nvme-pci-0100\":{\"Composite\":{\"temp1_input\":43.5}}}\nJSON\n",
        0o755,
    )
    .expect("create provider fixture");

    let config_path = root.join("thermal-provider.json");
    fs::write(
        &config_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_id": "fitctl.thermal-provider-config.v1",
            "schema_version": 1,
            "providers": [
                {
                    "provider_id": "lm-sensors-fixture",
                    "provider_kind": "lm_sensors_json",
                    "command": [provider_script.to_str().expect("script path should be UTF-8")],
                    "timeout_seconds": 5,
                    "evidence_target": {
                        "target_kind": "current_host",
                        "collection_path": "local_process"
                    }
                }
            ]
        }))
        .expect("config should encode"),
    )
    .expect("config should write");
    config_path
}
