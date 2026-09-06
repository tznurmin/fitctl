// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::hardware_sensor_support::Fixture;
use serde_json::{json, Value};
use std::fs;

const SAMPLE: &str = r#"{"psu":{"Adapter":"HID","vrm":{"temp1_input":45.5},"voltage":{"in0_input":12},"current":{"curr1_input":"invalid"},"fan":{"fan1_input":0,"fan1_fault":1}}}"#;

#[test]
pub(crate) fn hardware_sensor_cli_single_capture_idempotence_and_quantity_separation() {
    for features in [
        vec!["hardware-sensors", "thermal"],
        vec!["thermal", "hardware-sensors", "hardware-sensors"],
    ] {
        let f = Fixture::new();
        f.script(
            "sensors",
            &format!("echo sample >> \"$SENSOR_COUNT\"\nprintf '%s' '{SAMPLE}'"),
        );
        f.script("nvidia-smi", "printf 'GPU-fixture, Fixture, 40\\n'");
        let mut cmd = f.command();
        cmd.args(["state", "--live"]);
        for flag in features {
            cmd.args(["--collect", flag]);
        }
        let out = cmd.output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let state: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(
            fs::read_to_string(f.0.join("count"))
                .unwrap()
                .lines()
                .count(),
            1
        );
        let core = &state["state"]["core_state"];
        let thermals = core["thermal_resources"]["readings"].as_array().unwrap();
        assert_eq!(thermals.len(), 2);
        assert!(thermals
            .iter()
            .all(|r| r["temperature_millidegrees_celsius"].as_i64().unwrap() >= 40_000));
        let hardware = &core["hardware_sensor_resources"];
        assert_eq!(hardware["providers"][0]["outcome"], "partial");
        assert_eq!(hardware["readings"].as_array().unwrap().len(), 3);
        assert_eq!(
            hardware["observed_at"],
            core["thermal_resources"]["observed_at"]
        );
        assert_eq!(
            hardware["collector_host"],
            core["thermal_resources"]["collector_host"]
        );
        let state_file = f.0.join("state.json");
        fs::write(&state_file, &out.stdout).unwrap();
        let inspect = f
            .command()
            .args(["inspect", "--input", state_file.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            inspect.status.success(),
            "{}",
            String::from_utf8_lossy(&inspect.stderr)
        );
        let text = String::from_utf8(inspect.stdout).unwrap();
        assert!(
            text.contains("Hardware Sensors")
                && text.contains("12.000000 V")
                && text.contains("0.000000 RPM")
                && text.contains("Faulted")
        );
    }
}

#[test]
pub(crate) fn hardware_sensor_cli_unavailable_malformed_and_failed_capture() {
    for (body, outcome, reason) in [
        (None, "unavailable", "hardware_sensor_source_unavailable"),
        (
            Some("exit 7"),
            "command_failed",
            "hardware_sensor_command_failed",
        ),
        (
            Some("printf '{bad'"),
            "malformed",
            "hardware_sensor_json_malformed",
        ),
        (
            Some("printf '{\"chip\":{},\"chip\":{}}'"),
            "malformed",
            "hardware_sensor_duplicate_key",
        ),
    ] {
        let f = Fixture::new();
        if let Some(body) = body {
            f.script("sensors", body);
        }
        let out = f
            .command()
            .args(["state", "--live", "--collect", "hardware-sensors"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let state: Value = serde_json::from_slice(&out.stdout).unwrap();
        let sensors = &state["state"]["core_state"]["hardware_sensor_resources"];
        assert_eq!(sensors["providers"][0]["outcome"], outcome);
        assert_eq!(sensors["providers"][0]["reason_code"], reason);
        assert_eq!(sensors["readings"], json!([]));
    }
}

#[test]
pub(crate) fn hardware_sensor_cli_replay_rejects_live_feature_without_capture() {
    let f = Fixture::new();
    f.script("sensors", "echo bad >> \"$SENSOR_COUNT\"");
    let out = f
        .command()
        .args([
            "state",
            "--fixture",
            "linux-bare-metal-like-fresh-v1",
            "--collect",
            "hardware-sensors",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!f.0.join("count").exists());
    let invalid = f
        .command()
        .args(["state", "--live", "--collect", "hardware-sensor"])
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("unknown --collect feature"));
    assert!(!f.0.join("count").exists());
}

#[test]
pub(crate) fn hardware_sensor_cli_does_not_coalesce_different_provider_contexts() {
    let f = Fixture::new();
    f.script(
        "sensors",
        &format!("echo sample >> \"$SENSOR_COUNT\"\nprintf '%s' '{SAMPLE}'"),
    );
    let config = f.0.join("provider.json");
    fs::write(&config,json!({"schema_id":"fitctl.thermal-provider-config.v1","schema_version":1,"providers":[{
        "provider_id":"configured-sensors","provider_kind":"lm_sensors_json","command":["sensors","-j"],
        "evidence_target":{"target_kind":"current_host","collection_path":"local_process"}}]}).to_string()).unwrap();
    let out = f
        .command()
        .args([
            "state",
            "--live",
            "--collect",
            "hardware-sensors",
            "--thermal-provider-config",
            config.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        fs::read_to_string(f.0.join("count"))
            .unwrap()
            .lines()
            .count(),
        2
    );
}
