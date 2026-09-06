// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{common, e2e};
use serde_json::Value;
use std::{fs, path::PathBuf};

#[test]
fn hardware_sensor_input_cli_rejects_undeclared_provider_before_redaction() {
    let root = TestRoot(common::unique_temp_dir("hardware-sensor-input"));
    let path = root.0.join("input.json");
    let mut input: Value = serde_json::from_slice(
        &fs::read(
            common::repo_root()
                .join("fixtures/conformance/valid/host-state.hardware-sensors.v2.json"),
        )
        .unwrap(),
    )
    .unwrap();
    input["state"]["core_state"]["hardware_sensor_resources"]["readings"][0]["provider_id"] =
        "private-undeclared-provider".into();
    common::write_json_file(&path, &input);
    let before = fs::read(&path).unwrap();
    for profile in ["auditor", "external"] {
        let output = e2e::run_fitctl([
            "redact",
            "--profile",
            profile,
            "--input",
            path.to_str().unwrap(),
        ]);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("artifact_input_invalid"), "{stderr}");
        assert!(stderr.contains("artifact_load"), "{stderr}");
        assert!(!stderr.contains("private-undeclared-provider"));
        assert_eq!(fs::read(&path).unwrap(), before);
    }
}

struct TestRoot(PathBuf);
impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
