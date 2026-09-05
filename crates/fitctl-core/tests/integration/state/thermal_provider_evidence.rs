// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common;
use fitctl_core::artifacts::record_v1::ArtifactRecordV1;
use fitctl_core::artifacts::semantic_hash_v1::semantic_hash_hex_for_state;
use fitctl_core::artifacts::state_v1::{
    HostStateThermalCollectorHostV1, HostStateThermalEvidenceTargetV1, ThermalCollectionPathV1,
    ThermalEvidenceTargetKindV1, ThermalProviderKindV1, ThermalProviderOutcomeV1,
    ThermalReadingStatusV1, ThermalSensorRoleV1,
};
use fitctl_core::artifacts::validation_v1::validate_host_state;
use fitctl_core::redact::{redact_artifact_v1, BuiltInRedactionProfileV1, RedactionRequestV1};
use fitctl_core::state::thermal_v1::{
    collect_thermal_resources_v1, load_thermal_provider_config_entries_from_paths_v1,
    parse_ipmitool_sensor_output_v1, parse_lm_sensors_json_output_v1,
    parse_nvidia_smi_query_output_v1, ThermalProviderConfigEntryV1,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

#[test]
fn thermal_provider_config_rejects_unknown_schema_and_shell_command() {
    let root = common::unique_temp_dir("thermal-provider-config");
    let bad_schema = root.join("bad-schema.json");
    common::write_json_file(
        &bad_schema,
        &serde_json::json!({
            "schema_id": "fitctl.thermal-provider-config.v2",
            "schema_version": 1,
            "providers": []
        }),
    );
    let error =
        load_thermal_provider_config_entries_from_paths_v1(std::slice::from_ref(&bad_schema))
            .expect_err("unknown schema should fail");
    assert!(error.message.contains("unsupported schema_id"));

    let shell_command = root.join("shell-command.json");
    common::write_json_file(
        &shell_command,
        &serde_json::json!({
            "schema_id": "fitctl.thermal-provider-config.v1",
            "schema_version": 1,
            "providers": [
                {
                    "provider_id": "bad-shell",
                    "provider_kind": "lm_sensors_json",
                    "command": ["/bin/sh", "-c", "sensors -j"],
                    "evidence_target": {
                        "target_kind": "current_host",
                        "collection_path": "local_process"
                    }
                }
            ]
        }),
    );
    let error =
        load_thermal_provider_config_entries_from_paths_v1(std::slice::from_ref(&shell_command))
            .expect_err("shell command should fail");
    assert!(error.message.contains("shell"));
}

#[test]
fn lm_sensors_json_parser_extracts_board_and_nvme_temperatures() {
    let readings = parse_lm_sensors_json_output_v1(
        "lm-sensors-fixture",
        r#"{
          "nvme-pci-0100": {
            "Composite": {
              "temp1_input": 43.5
            }
          },
          "acpitz-acpi-0": {
            "temp1": {
              "temp1_input": 27.0
            }
          }
        }"#,
        common::FIXED_TIMESTAMP,
        current_host_target(),
    )
    .expect("lm-sensors output should parse");

    assert!(readings.iter().any(|reading| {
        reading.provider_id == "lm-sensors-fixture"
            && reading.sensor_role == ThermalSensorRoleV1::Nvme
            && reading.temperature_millidegrees_celsius == 43_500
            && reading.status == ThermalReadingStatusV1::Ok
    }));
    assert!(readings
        .iter()
        .any(|reading| reading.sensor_role == ThermalSensorRoleV1::Board));
}

#[test]
fn nvidia_smi_query_parser_extracts_gpu_temperature() {
    let readings = parse_nvidia_smi_query_output_v1(
        "nvidia-smi-fixture",
        "GPU-1111, NVIDIA GeForce RTX 3090, 54\n",
        common::FIXED_TIMESTAMP,
        current_host_target(),
    )
    .expect("nvidia-smi output should parse");

    assert_eq!(readings.len(), 1);
    assert_eq!(readings[0].sensor_role, ThermalSensorRoleV1::Gpu);
    assert_eq!(readings[0].raw_label, "NVIDIA GeForce RTX 3090");
    assert_eq!(readings[0].temperature_millidegrees_celsius, 54_000);
}

#[test]
fn ipmitool_sensor_parser_extracts_bmc_temperature_rows() {
    let readings = parse_ipmitool_sensor_output_v1(
        "ipmi-fixture",
        "\
Inlet Temp       | 27.000     | degrees C  | ok    | na        | na        | na        | na        | na        | na\n\
Fan1             | 4000.000   | RPM        | ok    | na        | na        | na        | na        | na        | na\n\
System Board Temp| 33.000     | degrees C  | ok    | na        | na        | na        | na        | na        | na\n",
        common::FIXED_TIMESTAMP,
        host_id_target("host.compute-01"),
    )
    .expect("ipmitool output should parse");

    assert_eq!(readings.len(), 2);
    assert!(readings
        .iter()
        .any(|reading| reading.sensor_role == ThermalSensorRoleV1::Inlet));
    assert!(readings.iter().any(|reading| {
        reading.sensor_role == ThermalSensorRoleV1::Board
            && reading.evidence_target.target_kind == ThermalEvidenceTargetKindV1::HostId
            && reading.evidence_target.host_id.as_deref() == Some("host.compute-01")
    }));
}

#[test]
fn ipmitool_sensor_parser_ignores_unavailable_temperature_rows() {
    let readings = parse_ipmitool_sensor_output_v1(
        "ipmi-fixture",
        "\
Inlet Temp       | na         | degrees C  | na    | na        | na        | na        | na        | na        | na\n\
Outlet Temp      | N/A        | degrees C  | na    | na        | na        | na        | na        | na        | na\n\
System Board Temp| 33.000     | degrees C  | ok    | na        | na        | na        | na        | na        | na\n",
        common::FIXED_TIMESTAMP,
        host_id_target("host.compute-01"),
    )
    .expect("unavailable ipmitool temperature rows should not make output malformed");

    assert_eq!(readings.len(), 1);
    assert_eq!(readings[0].raw_label, "System Board Temp");
    assert_eq!(readings[0].temperature_millidegrees_celsius, 33_000);
}

#[test]
fn ipmitool_provider_with_only_unavailable_temperature_rows_is_partial() {
    let root = common::unique_temp_dir("thermal-ipmi-na");
    let provider_script = write_executable_script(
        &root,
        "ipmi-na",
        "cat <<'EOF'\nInlet Temp | na | degrees C | na | na | na | na | na | na | na\nEOF\n",
        0o755,
    );
    let provider = thermal_provider_with_kind(
        "ipmi-na",
        ThermalProviderKindV1::IpmitoolSensor,
        provider_script.to_str().expect("UTF-8 path"),
    );

    let resources = collect_thermal_resources_v1(
        &[provider],
        common::FIXED_TIMESTAMP,
        HostStateThermalCollectorHostV1 {
            host_alias: Some("collector-host".to_string()),
            local_stable_id: Some("collector-id".to_string()),
        },
    )
    .expect("thermal resources should be emitted for configured providers");

    assert!(resources.readings.is_empty());
    assert_provider_outcome(
        &resources.providers,
        "ipmi-na",
        ThermalProviderOutcomeV1::Partial,
    );
}

#[test]
fn thermal_provider_config_maps_raw_labels_to_roles_and_aliases() {
    let root = common::unique_temp_dir("thermal-provider-mapping");
    let provider_script = write_executable_script(
        &root,
        "ipmi-mapped",
        "cat <<'EOF'\nVR_P1_TEMP | 47.000 | degrees C | ok | na | na | na | na | na | na\nEOF\n",
        0o755,
    );
    let provider_config = root.join("thermal-provider.json");
    common::write_json_file(
        &provider_config,
        &serde_json::json!({
            "schema_id": "fitctl.thermal-provider-config.v1",
            "schema_version": 1,
            "providers": [
                {
                    "provider_id": "site-bmc-sensors",
                    "provider_kind": "ipmitool_sensor",
                    "command": [provider_script.to_str().expect("UTF-8 path")],
                    "evidence_target": {
                        "target_kind": "host_id",
                        "host_id": "host.compute-01",
                        "collection_path": "out_of_band_bmc"
                    },
                    "sensor_mappings": [
                        {
                            "raw_label": "VR_P1_TEMP",
                            "sensor_role": "vrm",
                            "sensor_alias": "cpu_vr_1"
                        }
                    ]
                }
            ]
        }),
    );
    let providers =
        load_thermal_provider_config_entries_from_paths_v1(std::slice::from_ref(&provider_config))
            .expect("provider config should decode");

    let resources = collect_thermal_resources_v1(
        &providers,
        common::FIXED_TIMESTAMP,
        HostStateThermalCollectorHostV1::default(),
    )
    .expect("thermal resources should be collected");

    assert_eq!(resources.readings.len(), 1);
    assert_eq!(resources.readings[0].raw_label, "VR_P1_TEMP");
    assert_eq!(resources.readings[0].sensor_role, ThermalSensorRoleV1::Vrm);
    assert_eq!(
        resources.readings[0].sensor_alias.as_deref(),
        Some("cpu_vr_1")
    );
}

#[test]
fn thermal_provider_config_rejects_duplicate_sensor_mappings() {
    let root = common::unique_temp_dir("thermal-provider-mapping-invalid");
    let provider_config = root.join("thermal-provider.json");
    common::write_json_file(
        &provider_config,
        &serde_json::json!({
            "schema_id": "fitctl.thermal-provider-config.v1",
            "schema_version": 1,
            "providers": [
                {
                    "provider_id": "site-bmc-sensors",
                    "provider_kind": "ipmitool_sensor",
                    "command": ["/run/current-system/sw/bin/printf", "unused"],
                    "evidence_target": {
                        "target_kind": "host_id",
                        "host_id": "host.compute-01",
                        "collection_path": "out_of_band_bmc"
                    },
                    "sensor_mappings": [
                        {
                            "raw_label": "VR_P1_TEMP",
                            "sensor_role": "vrm",
                            "sensor_alias": "duplicate"
                        },
                        {
                            "raw_label": "VR_P1_TEMP",
                            "sensor_role": "board",
                            "sensor_alias": "duplicate2"
                        }
                    ]
                }
            ]
        }),
    );

    let error =
        load_thermal_provider_config_entries_from_paths_v1(std::slice::from_ref(&provider_config))
            .expect_err("duplicate raw labels should be rejected");
    assert!(error.message.contains("duplicated"));
}

#[test]
fn thermal_provider_failures_emit_provider_outcomes() {
    let root = common::unique_temp_dir("thermal-provider-failures");
    let command_failed = write_executable_script(&root, "command-failed", "exit 9\n", 0o755);
    let malformed = write_executable_script(&root, "malformed", "printf 'not json'\n", 0o755);
    let partial = write_executable_script(&root, "partial", "printf '{}'\n", 0o755);
    let permission_denied =
        write_executable_script(&root, "permission-denied", "printf '{}'\n", 0o644);

    let providers = vec![
        thermal_provider("unavailable", "/definitely/missing/fitctl-thermal-provider"),
        thermal_provider(
            "permission-denied",
            permission_denied.to_str().expect("UTF-8 path"),
        ),
        thermal_provider(
            "command-failed",
            command_failed.to_str().expect("UTF-8 path"),
        ),
        thermal_provider("malformed", malformed.to_str().expect("UTF-8 path")),
        thermal_provider("partial", partial.to_str().expect("UTF-8 path")),
    ];

    let resources = collect_thermal_resources_v1(
        &providers,
        common::FIXED_TIMESTAMP,
        HostStateThermalCollectorHostV1 {
            host_alias: Some("collector-host".to_string()),
            local_stable_id: Some("collector-id".to_string()),
        },
    )
    .expect("thermal resources should be emitted for configured providers");

    assert_provider_outcome(
        &resources.providers,
        "unavailable",
        ThermalProviderOutcomeV1::Unavailable,
    );
    assert_provider_outcome(
        &resources.providers,
        "permission-denied",
        ThermalProviderOutcomeV1::PermissionDenied,
    );
    assert_provider_outcome(
        &resources.providers,
        "command-failed",
        ThermalProviderOutcomeV1::CommandFailed,
    );
    assert_provider_outcome(
        &resources.providers,
        "malformed",
        ThermalProviderOutcomeV1::Malformed,
    );
    assert_provider_outcome(
        &resources.providers,
        "partial",
        ThermalProviderOutcomeV1::Partial,
    );
}

#[test]
fn thermal_provider_command_failure_diagnostics_include_status_and_bounded_output() {
    let root = common::unique_temp_dir("thermal-provider-command-diagnostics");
    let command_failed = write_executable_script(
        &root,
        "command-failed",
        "printf 'partial stdout\\nsecond line\\n'\nprintf 'permission denied by wrapper\\nretry later\\n' >&2\nexit 9\n",
        0o755,
    );

    let providers = vec![thermal_provider(
        "command-failed",
        command_failed.to_str().expect("UTF-8 path"),
    )];

    let resources = collect_thermal_resources_v1(
        &providers,
        common::FIXED_TIMESTAMP,
        HostStateThermalCollectorHostV1 {
            host_alias: Some("collector-host".to_string()),
            local_stable_id: Some("collector-id".to_string()),
        },
    )
    .expect("thermal resources should be emitted for configured providers");

    let provider = resources
        .providers
        .iter()
        .find(|provider| provider.provider_id == "command-failed")
        .expect("command-failed provider should be present");

    assert_eq!(provider.outcome, ThermalProviderOutcomeV1::CommandFailed);
    assert_eq!(
        provider.error_code.as_deref(),
        Some("thermal_provider_command_failed")
    );
    let diagnostics = provider
        .diagnostics
        .as_deref()
        .expect("command failure should emit diagnostics");
    assert!(
        diagnostics.contains("exit status: 9"),
        "diagnostics should contain exit status: {diagnostics}"
    );
    assert!(
        diagnostics.contains("stderr: permission denied by wrapper retry later"),
        "diagnostics should contain normalized stderr excerpt: {diagnostics}"
    );
    assert!(
        diagnostics.contains("stdout: partial stdout second line"),
        "diagnostics should contain normalized stdout excerpt: {diagnostics}"
    );
    assert!(
        !diagnostics.contains(command_failed.to_str().expect("UTF-8 path")),
        "diagnostics must not retain provider command path: {diagnostics}"
    );
    assert!(resources.readings.is_empty());
}

#[test]
fn thermal_provider_command_failure_diagnostics_are_bounded() {
    let root = common::unique_temp_dir("thermal-provider-command-diagnostics-bound");
    let long_stderr = "bounded-diagnostic-".repeat(80);
    let command_failed = write_executable_script(
        &root,
        "command-failed-long",
        &format!("printf '{long_stderr}' >&2\nexit 9\n"),
        0o755,
    );

    let providers = vec![thermal_provider(
        "command-failed-long",
        command_failed.to_str().expect("UTF-8 path"),
    )];

    let resources = collect_thermal_resources_v1(
        &providers,
        common::FIXED_TIMESTAMP,
        HostStateThermalCollectorHostV1 {
            host_alias: Some("collector-host".to_string()),
            local_stable_id: Some("collector-id".to_string()),
        },
    )
    .expect("thermal resources should be emitted for configured providers");

    let diagnostics = resources.providers[0]
        .diagnostics
        .as_deref()
        .expect("command failure should emit diagnostics");
    assert!(
        diagnostics.len() <= 240,
        "diagnostics should stay bounded: {} bytes",
        diagnostics.len()
    );
    assert!(
        diagnostics.contains("stderr: bounded-diagnostic-"),
        "diagnostics should preserve a useful stderr prefix: {diagnostics}"
    );
}

#[test]
fn conformance_host_state_with_thermal_resources_is_valid() {
    let path =
        common::repo_root().join("fixtures/conformance/valid/host-state.thermal-resources.v2.json");
    let state: fitctl_core::artifacts::state_v1::HostStateV1 =
        serde_json::from_slice(&fs::read(path).expect("thermal conformance fixture should read"))
            .expect("thermal conformance fixture should decode");

    validate_host_state(&state).expect("thermal conformance fixture should validate");
}

#[test]
fn out_of_band_thermal_evidence_preserves_collector_and_target_identity() {
    let state = state_with_thermal_reading(41_000, common::FIXED_TIMESTAMP);
    let thermal = state
        .state
        .core_state
        .thermal_resources
        .expect("thermal resources should decode");

    assert_eq!(
        thermal.collector_host.host_alias.as_deref(),
        Some("collector-host")
    );
    assert_eq!(
        thermal.providers[0].evidence_target.host_id.as_deref(),
        Some("host.compute-01")
    );
    assert_eq!(
        thermal.readings[0].evidence_target.host_id.as_deref(),
        Some("host.compute-01")
    );
}

#[test]
fn thermal_resources_contribute_to_state_semantic_hash() {
    let left = state_with_thermal_reading(41_000, common::FIXED_TIMESTAMP);
    let right = state_with_thermal_reading(42_000, common::FIXED_TIMESTAMP);

    assert_ne!(
        semantic_hash_hex_for_state(&left).expect("left semantic hash"),
        semantic_hash_hex_for_state(&right).expect("right semantic hash")
    );
}

#[test]
fn thermal_observed_at_does_not_change_state_semantic_hash() {
    let left = state_with_thermal_reading(41_000, "2026-06-16T12:00:00Z");
    let right = state_with_thermal_reading(41_000, "2026-06-16T12:01:00Z");

    assert_eq!(
        semantic_hash_hex_for_state(&left).expect("left semantic hash"),
        semantic_hash_hex_for_state(&right).expect("right semantic hash")
    );
}

#[test]
fn thermal_provider_diagnostics_do_not_change_state_semantic_hash() {
    let left = state_with_thermal_provider_diagnostic("first provider stderr");
    let right = state_with_thermal_provider_diagnostic("different provider stderr");

    assert_eq!(
        semantic_hash_hex_for_state(&left).expect("left semantic hash"),
        semantic_hash_hex_for_state(&right).expect("right semantic hash")
    );
}

#[test]
fn external_profile_redacts_thermal_provider_identifiers() {
    let state = state_with_thermal_reading(41_000, common::FIXED_TIMESTAMP);
    let artifact = redact_artifact_v1(RedactionRequestV1 {
        artifact: ArtifactRecordV1::State(state),
        profile: BuiltInRedactionProfileV1::External,
        redacted_at: common::FIXED_TIMESTAMP.to_string(),
    })
    .expect("external state redaction should succeed");

    let ArtifactRecordV1::State(redacted) = artifact else {
        panic!("expected state artifact");
    };

    let rendered = serde_json::to_string(&redacted).expect("redacted state should encode");
    assert!(!rendered.contains("site-bmc-thermal"));
    assert!(!rendered.contains("Inlet Temp"));
    assert!(!rendered.contains("target_inlet"));
    assert!(!rendered.contains("collector-host"));
    assert!(rendered.contains("redacted:external:thermal_provider:0"));
    assert!(rendered.contains("redacted:external:thermal_sensor:0"));
}

#[test]
fn external_profile_redacts_thermal_provider_diagnostics() {
    let state = state_with_thermal_provider_diagnostic("permission denied by wrapper");
    let artifact = redact_artifact_v1(RedactionRequestV1 {
        artifact: ArtifactRecordV1::State(state),
        profile: BuiltInRedactionProfileV1::External,
        redacted_at: common::FIXED_TIMESTAMP.to_string(),
    })
    .expect("external state redaction should succeed");

    let ArtifactRecordV1::State(redacted) = artifact else {
        panic!("expected state artifact");
    };

    let rendered = serde_json::to_string(&redacted).expect("redacted state should encode");
    assert!(!rendered.contains("permission denied by wrapper"));
    assert!(rendered.contains("redacted:thermal_provider_diagnostic"));
}

fn thermal_provider(provider_id: &str, command: &str) -> ThermalProviderConfigEntryV1 {
    thermal_provider_with_kind(provider_id, ThermalProviderKindV1::LmSensorsJson, command)
}

fn thermal_provider_with_kind(
    provider_id: &str,
    provider_kind: ThermalProviderKindV1,
    command: &str,
) -> ThermalProviderConfigEntryV1 {
    ThermalProviderConfigEntryV1 {
        provider_id: provider_id.to_string(),
        provider_kind,
        command: vec![command.to_string()],
        timeout_seconds: Some(5),
        evidence_target: current_host_target(),
        sensor_mappings: Vec::new(),
    }
}

fn assert_provider_outcome(
    providers: &[fitctl_core::artifacts::state_v1::HostStateThermalProviderV1],
    provider_id: &str,
    outcome: ThermalProviderOutcomeV1,
) {
    assert!(
        providers
            .iter()
            .any(|provider| provider.provider_id == provider_id && provider.outcome == outcome),
        "expected provider {provider_id} to have outcome {}",
        outcome.as_str()
    );
}

fn write_executable_script(root: &Path, name: &str, body: &str, mode: u32) -> std::path::PathBuf {
    let path = root.join(name);
    fs::write(&path, format!("#!/bin/sh\n{body}")).expect("provider script should write");
    let mut permissions = fs::metadata(&path)
        .expect("provider script metadata")
        .permissions();
    permissions.set_mode(mode);
    fs::set_permissions(&path, permissions).expect("provider script permissions should update");
    path
}

fn state_with_thermal_reading(
    temperature_millidegrees_celsius: i64,
    observed_at: &str,
) -> fitctl_core::artifacts::state_v1::HostStateV1 {
    let state = common::collect_state_fixture("linux-bare-metal-like-fresh-v1");
    let mut value = serde_json::to_value(&state).expect("state should encode");
    value["state"]["core_state"]["thermal_resources"] = serde_json::json!({
        "observed_at": observed_at,
        "collector_host": {
            "host_alias": "collector-host",
            "local_stable_id": "collector-stable-id"
        },
        "providers": [
            {
                "provider_id": "site-bmc-thermal",
                "provider_kind": "ipmitool_sensor",
                "outcome": "success",
                "evidence_target": {
                    "target_kind": "host_id",
                    "host_id": "host.compute-01",
                    "collection_path": "out_of_band_bmc"
                },
                "observed_at": observed_at
            }
        ],
        "readings": [
            {
                "sensor_id": "site-bmc-thermal:inlet-temp",
                "sensor_role": "inlet",
                "sensor_alias": "target_inlet",
                "provider_id": "site-bmc-thermal",
                "raw_label": "Inlet Temp",
                "temperature_millidegrees_celsius": temperature_millidegrees_celsius,
                "status": "ok",
                "observed_at": observed_at,
                "evidence_target": {
                    "target_kind": "host_id",
                    "host_id": "host.compute-01",
                    "collection_path": "out_of_band_bmc"
                },
                "source": "ipmitool_sensor"
            }
        ]
    });

    serde_json::from_value(value).expect("thermal state should decode")
}

fn state_with_thermal_provider_diagnostic(
    diagnostics: &str,
) -> fitctl_core::artifacts::state_v1::HostStateV1 {
    let state = common::collect_state_fixture("linux-bare-metal-like-fresh-v1");
    let mut value = serde_json::to_value(&state).expect("state should encode");
    value["state"]["core_state"]["thermal_resources"] = serde_json::json!({
        "observed_at": common::FIXED_TIMESTAMP,
        "collector_host": {
            "host_alias": "collector-host",
            "local_stable_id": "collector-stable-id"
        },
        "providers": [
            {
                "provider_id": "site-bmc-thermal",
                "provider_kind": "ipmitool_sensor",
                "outcome": "command_failed",
                "evidence_target": {
                    "target_kind": "host_id",
                    "host_id": "host.compute-01",
                    "collection_path": "out_of_band_bmc"
                },
                "observed_at": common::FIXED_TIMESTAMP,
                "error_code": "thermal_provider_command_failed",
                "diagnostics": diagnostics
            }
        ],
        "readings": []
    });

    serde_json::from_value(value).expect("thermal diagnostic state should decode")
}

fn current_host_target() -> HostStateThermalEvidenceTargetV1 {
    HostStateThermalEvidenceTargetV1 {
        target_kind: ThermalEvidenceTargetKindV1::CurrentHost,
        host_id: None,
        collection_path: ThermalCollectionPathV1::LocalProcess,
    }
}

fn host_id_target(host_id: &str) -> HostStateThermalEvidenceTargetV1 {
    HostStateThermalEvidenceTargetV1 {
        target_kind: ThermalEvidenceTargetKindV1::HostId,
        host_id: Some(host_id.to_string()),
        collection_path: ThermalCollectionPathV1::OutOfBandBmc,
    }
}
