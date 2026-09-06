// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{common, e2e};
use fitctl_core::bundle::{assemble_decision_bundle_v1, DecisionBundleAssemblyRequestV1};
use fitctl_core::validate::ValidationModeV1;
use serde_json::Value;

const SENTINEL: &str = "audit-only-private-sensor-time-070";
use fitctl_core::redact::load_redactable_artifact_from_value;
use std::{fs, path::PathBuf};

#[test]
fn sharing_times_cli_rejects_whole_output_without_echo_or_input_mutation() {
    let root = TestRoot(common::unique_temp_dir("sharing-times"));
    let path = root.0.join("input.json");
    for input in inputs() {
        for paths in mutation_groups(&input) {
            let mut input = input.clone();
            for field in &paths {
                *input.pointer_mut(field).unwrap() = SENTINEL.into();
            }
            load_redactable_artifact_from_value(input.clone()).expect("ordinary input still loads");
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
                assert_eq!(output.status.code(), Some(2), "{paths:?}");
                assert!(output.stdout.is_empty(), "{paths:?}");
                let stderr = String::from_utf8_lossy(&output.stderr);
                assert!(stderr.contains("artifact_input_invalid"), "{stderr}");
                assert!(stderr.contains("sharing_timestamp_validate"), "{stderr}");
                assert!(!stderr.contains(SENTINEL));
                assert_eq!(fs::read(&path).unwrap(), before);
            }
        }
    }
}

fn inputs() -> Vec<Value> {
    let mut values: Vec<_> = [
        "host-state.hardware-sensors.v2.json",
        "host-state.thermal-resources.v2.json",
        "thermal-evidence.out-of-band-bmc.v1.json",
        "host-contract.local-stable-identity-v2.v2.json",
        "validation-report.cuda-runtime-allocatable-memory-fit.v2.json",
        "batch-classification-report.cuda-runtime-shortlist.v3.json",
    ]
    .into_iter()
    .map(|name| {
        serde_json::from_slice(
            &fs::read(
                common::repo_root()
                    .join("fixtures/conformance/valid")
                    .join(name),
            )
            .unwrap(),
        )
        .unwrap()
    })
    .collect();
    let contract = common::derive_contract_from_fixture("linux-bare-metal-like-v1");
    let state = common::collect_state_fixture("linux-bare-metal-like-fresh-v1");
    let validation_report = common::validate_with_profile(
        contract.clone(),
        common::load_service_profile_file("general_compute_stateful_thresholds.v2.json"),
        Some(state.clone()),
        ValidationModeV1::StateRequired,
        Some(600),
    );
    values.push(
        serde_json::to_value(
            assemble_decision_bundle_v1(DecisionBundleAssemblyRequestV1 {
                contract,
                state: Some(state),
                validation_report,
                config_bundle: None,
                resolved_config: None,
                verification_bundle: None,
                recommendation_report: None,
                bundled_at: common::FIXED_TIMESTAMP.into(),
                notes: None,
            })
            .unwrap(),
        )
        .unwrap(),
    );
    values
}

fn mutation_groups(value: &Value) -> Vec<Vec<String>> {
    if value.get("bundle").is_some() {
        // State observation time is outside its semantic hash, so this preserves valid lineage.
        return vec![vec![
            "/bundle/state/state/core_state/freshness/observed_at".into()
        ]];
    }
    let paths = time_paths(value, "");
    let hardware: Vec<_> = paths
        .iter()
        .filter(|path| path.contains("/hardware_sensor_resources/"))
        .cloned()
        .collect();
    let mut groups: Vec<_> = paths
        .into_iter()
        .filter(|path| !path.contains("/hardware_sensor_resources/"))
        .map(|path| vec![path])
        .collect();
    if !hardware.is_empty() {
        groups.push(hardware);
    }
    groups
}

fn time_paths(value: &Value, prefix: &str) -> Vec<String> {
    let mut paths = Vec::new();
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let path = format!("{prefix}/{key}");
                if matches!(
                    key.as_str(),
                    "observed_at" | "state_observed_at" | "derived_at" | "validated_at"
                ) && child.is_string()
                {
                    paths.push(path);
                } else {
                    paths.extend(time_paths(child, &path));
                }
            }
        }
        Value::Array(array) => {
            for (index, child) in array.iter().enumerate() {
                paths.extend(time_paths(child, &format!("{prefix}/{index}")));
            }
        }
        _ => {}
    }
    paths
}

struct TestRoot(PathBuf);
impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
