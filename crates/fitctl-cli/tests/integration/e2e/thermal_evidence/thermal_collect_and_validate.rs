// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::{common, e2e};

#[test]
fn thermal_collect_emits_target_bound_artifact() {
    let root = common::unique_temp_dir("thermal-evidence-collect");
    let config_path = write_ipmi_provider_config(&root);

    let output = e2e::run_fitctl([
        "thermal",
        "collect",
        "--thermal-provider-config",
        config_path.to_str().expect("config path should be UTF-8"),
    ]);
    e2e::assert_success(&output);
    let artifact: Value = e2e::decode_json_stdout(&output);

    assert_eq!(
        artifact["envelope"]["schema_id"],
        "fitctl.thermal-evidence.v1"
    );
    assert_eq!(
        artifact["thermal_evidence"]["providers"][0]["evidence_target"]["host_id"],
        "host.gpu-host-01"
    );
    assert_eq!(
        artifact["thermal_evidence"]["readings"][0]["sensor_alias"],
        "target_inlet"
    );
}

#[test]
fn thermal_collect_require_target_host_id_accepts_matching_provider() {
    let root = common::unique_temp_dir("thermal-evidence-require-target-match");
    let config_path = write_ipmi_provider_config(&root);

    let output = e2e::run_fitctl([
        "thermal",
        "collect",
        "--thermal-provider-config",
        config_path.to_str().expect("config path should be UTF-8"),
        "--require-target-host-id",
        "host.gpu-host-01",
    ]);
    e2e::assert_success(&output);
    let artifact: Value = e2e::decode_json_stdout(&output);

    assert_eq!(
        artifact["thermal_evidence"]["providers"][0]["evidence_target"]["host_id"],
        "host.gpu-host-01"
    );
}

#[test]
fn thermal_collect_require_target_host_id_rejects_wrong_host_id() {
    let root = common::unique_temp_dir("thermal-evidence-require-target-wrong");
    let config_path = write_ipmi_provider_config(&root);

    let output = e2e::run_fitctl([
        "thermal",
        "collect",
        "--thermal-provider-config",
        config_path.to_str().expect("config path should be UTF-8"),
        "--require-target-host-id",
        "host.other",
    ]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("does not match required target host"));
}

#[test]
fn thermal_collect_require_target_host_id_rejects_current_host_provider() {
    let root = common::unique_temp_dir("thermal-evidence-require-target-current");
    let config_path = write_current_host_provider_config(&root);

    let output = e2e::run_fitctl([
        "thermal",
        "collect",
        "--thermal-provider-config",
        config_path.to_str().expect("config path should be UTF-8"),
        "--require-target-host-id",
        "host.gpu-host-01",
    ]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("does not declare evidence_target.host_id"));
}

#[test]
fn validate_accepts_thermal_evidence_without_host_state() {
    let root = common::unique_temp_dir("thermal-evidence-validate");
    let config_path = write_ipmi_provider_config(&root);
    let thermal_output = e2e::run_fitctl([
        "thermal",
        "collect",
        "--thermal-provider-config",
        config_path.to_str().expect("config path should be UTF-8"),
    ]);
    e2e::assert_success(&thermal_output);
    let thermal_artifact: Value = e2e::decode_json_stdout(&thermal_output);
    let expected_artifact_id = thermal_artifact["envelope"]["artifact_id"]
        .as_str()
        .expect("thermal evidence artifact id")
        .to_string();
    let thermal_evidence_path = root.join("thermal-evidence.json");
    e2e::write_stdout(&thermal_evidence_path, &thermal_output);

    let survey_path = e2e::emit_survey_fixture(&root, "linux-gpu-workstation-like-v1");
    let contract_path =
        e2e::derive_contract(&root, &survey_path, "general_compute_default.v1.json");
    let profile_path = write_thermal_profile(&root);

    let output = e2e::run_fitctl([
        "validate",
        "--contract",
        contract_path
            .to_str()
            .expect("contract path should be UTF-8"),
        "--profile",
        profile_path.to_str().expect("profile path should be UTF-8"),
        "--thermal-evidence",
        thermal_evidence_path
            .to_str()
            .expect("thermal evidence path should be UTF-8"),
        "--validation-mode",
        "state_required",
        "--validated-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&output);
    let report: Value = e2e::decode_json_stdout(&output);

    assert_eq!(report["report"]["verdict"], "fit");
    assert_eq!(
        report["validation_basis"]["thermal_evidence_artifact_ids"][0],
        expected_artifact_id
    );
    let matched_requirements = report["report"]["matched_requirements"]
        .as_array()
        .expect("matched requirements should be an array");
    assert!(matched_requirements.iter().any(|requirement| {
        requirement == "core_requirements.required_thermal_sensors[inlet-safe]"
    }));
}

#[test]
fn thermal_profile_init_accepts_standalone_thermal_evidence() {
    let root = common::unique_temp_dir("thermal-profile-init-evidence");
    let thermal_evidence_path = collect_thermal_evidence_to_file(&root);

    let output = e2e::run_fitctl([
        "thermal",
        "profile",
        "init",
        "--thermal-evidence",
        thermal_evidence_path
            .to_str()
            .expect("thermal evidence path should be UTF-8"),
        "--profile-id",
        "thermal_safe_v1",
        "--margin-mc",
        "2000",
    ]);
    e2e::assert_success(&output);
    let profile: Value = e2e::decode_json_stdout(&output);

    assert_eq!(profile["envelope"]["schema_id"], "service-profile.v2");
    assert_eq!(profile["profile"]["profile_id"], "thermal_safe_v1");
    assert_eq!(
        profile["envelope"]["provenance"]["source"],
        "thermal_evidence:thermal_profile_init_v1"
    );
    let requirements = profile["profile"]["core_requirements"]["required_thermal_sensors"]
        .as_array()
        .expect("thermal requirements should be an array");
    assert_eq!(requirements.len(), 1);
    let requirement = &requirements[0];
    assert_eq!(requirement["provider_id"], "site-bmc-thermal");
    assert_eq!(requirement["sensor_alias"], "target_inlet");
    assert_eq!(requirement["sensor_role"], "inlet");
    assert_eq!(requirement["max_temperature_millidegrees_celsius"], 43_000);
    assert_eq!(requirement["require_provider_success"], true);

    let encoded = serde_json::to_string(&profile).expect("profile should encode");
    assert!(!encoded.contains("collector_host"));
    assert!(!encoded.contains("evidence_target"));
    assert!(!encoded.contains("Inlet Temp"));
}

#[test]
fn thermal_profile_init_rejects_state_and_thermal_evidence_together() {
    let root = common::unique_temp_dir("thermal-profile-init-source-conflict");
    let thermal_evidence_path = collect_thermal_evidence_to_file(&root);
    let state_path = e2e::emit_state_fixture(&root, "linux-gpu-workstation-like-fresh-v1");

    let output = e2e::run_fitctl([
        "thermal",
        "profile",
        "init",
        "--state",
        state_path.to_str().expect("state path should be UTF-8"),
        "--thermal-evidence",
        thermal_evidence_path
            .to_str()
            .expect("thermal evidence path should be UTF-8"),
    ]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("requires exactly one of --state or --thermal-evidence"));
}

#[test]
fn thermal_profile_init_requires_one_source_input() {
    let output = e2e::run_fitctl([
        "thermal",
        "profile",
        "init",
        "--profile-id",
        "missing_source",
    ]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("requires exactly one of --state or --thermal-evidence"));
}

#[test]
fn thermal_profile_init_rejects_wrong_schema_thermal_evidence() {
    let root = common::unique_temp_dir("thermal-profile-init-wrong-schema");
    let wrong_schema_path = root.join("wrong-schema.json");
    common::write_json_file(
        &wrong_schema_path,
        &serde_json::json!({
            "envelope": {
                "schema_id": "service-profile.v2",
                "schema_version": 2,
                "artifact_id": "not-thermal-evidence",
                "provenance": {
                    "source": "test",
                    "collected_at": common::FIXED_TIMESTAMP
                },
                "redaction": null,
                "signatures": []
            },
            "profile": {}
        }),
    );

    let output = e2e::run_fitctl([
        "thermal",
        "profile",
        "init",
        "--thermal-evidence",
        wrong_schema_path
            .to_str()
            .expect("wrong schema path should be UTF-8"),
    ]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("thermal evidence"));
}

#[test]
fn thermal_profile_help_mentions_thermal_evidence_input() {
    let output = e2e::run_fitctl(["thermal", "profile", "init", "--help"]);
    e2e::assert_success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--thermal-evidence <thermal-evidence.json>"));
}

fn collect_thermal_evidence_to_file(root: &Path) -> PathBuf {
    let config_path = write_ipmi_provider_config(root);
    let thermal_output = e2e::run_fitctl([
        "thermal",
        "collect",
        "--thermal-provider-config",
        config_path.to_str().expect("config path should be UTF-8"),
    ]);
    e2e::assert_success(&thermal_output);
    let thermal_evidence_path = root.join("thermal-evidence.json");
    e2e::write_stdout(&thermal_evidence_path, &thermal_output);
    thermal_evidence_path
}

fn write_ipmi_provider_config(root: &Path) -> PathBuf {
    let provider_script = root.join("emit-ipmi-sensors");
    fs::write(
        &provider_script,
        "#!/bin/sh\ncat <<'EOF'\nInlet Temp | 41.000 | degrees C | ok | na | na | na | na | na | na\nEOF\n",
    )
    .expect("provider script should write");
    let mut permissions = fs::metadata(&provider_script)
        .expect("provider script metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider_script, permissions).expect("provider script should chmod");

    let config_path = root.join("thermal-provider.json");
    common::write_json_file(
        &config_path,
        &serde_json::json!({
            "schema_id": "fitctl.thermal-provider-config.v1",
            "schema_version": 1,
            "providers": [
                {
                    "provider_id": "site-bmc-thermal",
                    "provider_kind": "ipmitool_sensor",
                    "command": [provider_script.to_str().expect("script path should be UTF-8")],
                    "evidence_target": {
                        "target_kind": "host_id",
                        "host_id": "host.gpu-host-01",
                        "collection_path": "out_of_band_bmc"
                    },
                    "sensor_mappings": [
                        {
                            "raw_label": "Inlet Temp",
                            "sensor_role": "inlet",
                            "sensor_alias": "target_inlet"
                        }
                    ]
                }
            ]
        }),
    );
    config_path
}

fn write_current_host_provider_config(root: &Path) -> PathBuf {
    let provider_script = root.join("emit-local-sensors");
    fs::write(
        &provider_script,
        "#!/bin/sh\ncat <<'EOF'\nInlet Temp | 41.000 | degrees C | ok | na | na | na | na | na | na\nEOF\n",
    )
    .expect("provider script should write");
    let mut permissions = fs::metadata(&provider_script)
        .expect("provider script metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider_script, permissions).expect("provider script should chmod");

    let config_path = root.join("thermal-current-host-provider.json");
    common::write_json_file(
        &config_path,
        &serde_json::json!({
            "schema_id": "fitctl.thermal-provider-config.v1",
            "schema_version": 1,
            "providers": [
                {
                    "provider_id": "local-thermal",
                    "provider_kind": "ipmitool_sensor",
                    "command": [provider_script.to_str().expect("script path should be UTF-8")],
                    "evidence_target": {
                        "target_kind": "current_host",
                        "collection_path": "local_process"
                    }
                }
            ]
        }),
    );
    config_path
}

fn write_thermal_profile(root: &Path) -> PathBuf {
    let profile = fs::read(common::repo_service_profile_path(
        "general_compute_contract_only.v2.json",
    ))
    .expect("profile should read");
    let mut value: Value = serde_json::from_slice(&profile).expect("profile should decode");
    value["profile"]["core_requirements"]["required_thermal_sensors"] = serde_json::json!([
        {
            "requirement_id": "inlet-safe",
            "provider_id": "site-bmc-thermal",
            "sensor_alias": "target_inlet",
            "max_temperature_millidegrees_celsius": 45000,
            "require_provider_success": true
        }
    ]);
    let profile_path = root.join("thermal.profile.json");
    common::write_json_file(&profile_path, &value);
    profile_path
}
