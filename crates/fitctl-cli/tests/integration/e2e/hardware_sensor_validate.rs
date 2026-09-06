// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{common, hardware_sensor_support::Fixture};
use serde_json::Value;
use std::fs;

#[test]
pub(crate) fn hardware_sensor_live_validation_retains_same_typed_evidence_without_new_admission_claims(
) {
    let f = Fixture::new();
    f.script("sensors", "echo sample >> \"$SENSOR_COUNT\"\nprintf '%s' '{\"chip\":{\"power\":{\"power1_input\":3}}}'");
    let survey = f.command().arg("survey").output().unwrap();
    assert!(
        survey.status.success(),
        "{}",
        String::from_utf8_lossy(&survey.stderr)
    );
    let survey_path = f.0.join("survey.json");
    fs::write(&survey_path, survey.stdout).unwrap();
    let contract = f
        .command()
        .args(["contract", "--survey"])
        .arg(survey_path)
        .arg("--policy")
        .arg(common::repo_policy_path())
        .output()
        .unwrap();
    assert!(
        contract.status.success(),
        "{}",
        String::from_utf8_lossy(&contract.stderr)
    );
    let contract_path = f.0.join("contract.json");
    fs::write(&contract_path, contract.stdout).unwrap();
    let state_path = f.0.join("state.json");
    let profile = common::repo_service_profile_path("general_compute_stateful_thresholds.v2.json");
    let output = f
        .command()
        .args(["validate", "--contract"])
        .arg(contract_path)
        .arg("--profile")
        .arg(profile)
        .args([
            "--validation-mode",
            "state_required",
            "--live-state",
            "--collect",
            "hardware-sensors",
            "--state-out",
        ])
        .arg(&state_path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(!report["report"]["matched_requirements"]
        .to_string()
        .contains("hardware_sensor"));
    let state: Value = serde_json::from_slice(&fs::read(state_path).unwrap()).unwrap();
    assert_eq!(
        state["state"]["core_state"]["hardware_sensor_resources"]["readings"][0]["value"],
        3_000_000
    );
    assert_eq!(
        fs::read_to_string(f.0.join("count"))
            .unwrap()
            .lines()
            .count(),
        1
    );
    for command in ["state", "validate"] {
        let help = f.command().args([command, "--help"]).output().unwrap();
        assert!(help.status.success());
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&help.stdout),
            String::from_utf8_lossy(&help.stderr)
        );
        assert!(text.contains("hardware-sensors"));
    }
}
