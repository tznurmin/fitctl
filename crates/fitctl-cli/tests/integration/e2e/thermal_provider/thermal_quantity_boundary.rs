// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{cli, common};
use serde_json::{json, Value};
use std::{fs, path::PathBuf, process::Command};

struct Root(PathBuf);
impl Drop for Root {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
pub(crate) fn lm_sensors_units_cli_quantity_roundtrip() {
    let root = Root(common::unique_temp_dir("thermal-quantity-boundary"));
    let provider = common::fixture_command::write(
        &common::repo_root(),
        &root.0,
        "sensors",
        concat!(
            "printf '%s' '",
            "{\"psu\":{\"vrm temp\":{\"temp1_input\":46.75},\"case temp\":{\"temp2_input\":45.5},",
            "\"voltage\":{\"in0_input\":12},\"current\":{\"curr1_input\":null},",
            "\"power\":{\"power1_input\":34},\"fan\":{\"fan1_input\":0}}}'\n"
        ),
        0o700,
    )
    .unwrap();
    let config = root.0.join("provider.json");
    fs::write(
        &config,
        json!({"schema_id":"fitctl.thermal-provider-config.v1","schema_version":1,
        "providers":[{"provider_id":"local-lm-sensors","provider_kind":"lm_sensors_json",
        "command":[provider.to_str().unwrap(),"-j"],"evidence_target":{"target_kind":"current_host",
        "collection_path":"local_process"}}]})
        .to_string(),
    )
    .unwrap();
    let mut ids = Vec::new();
    for args in [["state", "--live"], ["thermal", "collect"]] {
        let out = Command::new(cli::fitctl_bin())
            .args(args)
            .args(["--thermal-provider-config", config.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let artifact: Value = serde_json::from_slice(&out.stdout).unwrap();
        let readings = if args[0] == "state" {
            &artifact["state"]["core_state"]["thermal_resources"]["readings"]
        } else {
            &artifact["thermal_evidence"]["readings"]
        };
        let rows = readings.as_array().unwrap();
        assert_eq!(rows.len(), 2);
        let mut values: Vec<_> = rows
            .iter()
            .map(|r| r["temperature_millidegrees_celsius"].as_i64().unwrap())
            .collect();
        values.sort();
        assert_eq!(values, [45_500, 46_750]);
        let mut current: Vec<_> = rows
            .iter()
            .map(|r| r["sensor_id"].as_str().unwrap().to_owned())
            .collect();
        current.sort();
        ids.push(current);
        let saved = root.0.join("artifact.json");
        fs::write(&saved, &out.stdout).unwrap();
        let inspected = Command::new(cli::fitctl_bin())
            .args(["inspect", "--input"])
            .arg(saved)
            .output()
            .unwrap();
        assert!(inspected.status.success());
        let text = String::from_utf8(inspected.stdout).unwrap();
        assert!(!text.contains("curr1") && !text.contains("power1") && !text.contains("fan1"));
    }
    assert_eq!(ids[0], ids[1]);
    assert_eq!(
        ids[0],
        [
            "local-lm-sensors:psu-case-temp-temp2-input",
            "local-lm-sensors:psu-vrm-temp-temp1-input"
        ]
    );
}
