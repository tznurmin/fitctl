// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use std::{fs, path::PathBuf};

use fitctl_core::artifacts::record_v1::load_artifact_record_from_value;
use fitctl_core::bundle::{assemble_decision_bundle_v1, DecisionBundleAssemblyRequestV1};
use fitctl_core::validate::ValidationModeV1;
use serde_json::Value;

use crate::{common, e2e};

const SENTINEL: &str = "audit-only-sensitive-core-provenance-83";

#[test]
fn imported_core_provenance_cli_rejects_bad_timestamps_without_partial_output() {
    let root = TestRoot(common::unique_temp_dir("core-provenance-rejection"));
    for profile in ["auditor", "external"] {
        for mut input in core_inputs() {
            input["envelope"]["provenance"]["collected_at"] = SENTINEL.into();
            assert_rejected(&root, &input, profile);
        }
        for slot in ["contract", "state", "validation_report"] {
            let mut input = nested_input();
            input["bundle"][slot]["envelope"]["provenance"]["collected_at"] = SENTINEL.into();
            assert_rejected(&root, &input, profile);
        }
    }
}

#[test]
fn imported_core_provenance_cli_sanitizes_versions_in_complete_output() {
    let root = TestRoot(common::unique_temp_dir("core-provenance-sanitization"));
    for profile in ["auditor", "external"] {
        for mut input in core_inputs() {
            input["envelope"]["provenance"]["fitctl_version"] = format!("0.6.0-{SENTINEL}").into();
            let path = root.0.join("input.json");
            common::write_json_file(&path, &input);
            let output = e2e::run_fitctl([
                "redact",
                "--profile",
                profile,
                "--input",
                path.to_str().unwrap(),
            ]);
            e2e::assert_success(&output);
            assert!(!String::from_utf8_lossy(&output.stdout).contains(SENTINEL));
            let value: Value = e2e::decode_json_stdout(&output);
            assert_eq!(
                value["envelope"]["provenance"]["command_name"],
                input["envelope"]["provenance"]["command_name"]
            );
            load_artifact_record_from_value(value).expect("CLI emits a valid full artifact");
        }
    }
}

fn assert_rejected(root: &TestRoot, input: &Value, profile: &str) {
    load_artifact_record_from_value(input.clone())
        .expect("ordinary input remains structurally valid");
    let path = root.0.join("input.json");
    common::write_json_file(&path, input);
    let before = fs::read(&path).unwrap();
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
    assert!(stderr.contains("provenance_validate"), "{stderr}");
    assert!(!stderr.contains(SENTINEL));
    assert_eq!(fs::read(path).unwrap(), before);
}

fn core_inputs() -> Vec<Value> {
    [
        "host-survey.local-stable-identity-v2.v2.json",
        "host-contract.local-stable-identity-v2.v2.json",
        "host-state.thermal-resources.v2.json",
        "thermal-evidence.out-of-band-bmc.v1.json",
        "validation-report.cuda-runtime-allocatable-memory-fit.v2.json",
    ]
    .into_iter()
    .map(|name| {
        let path = common::repo_root()
            .join("fixtures/conformance/valid")
            .join(name);
        serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
    })
    .collect()
}

fn nested_input() -> Value {
    let contract = common::derive_contract_from_fixture("linux-bare-metal-like-v1");
    let state = common::collect_state_fixture("linux-bare-metal-like-fresh-v1");
    let validation_report = common::validate_with_profile(
        contract.clone(),
        common::load_service_profile_file("general_compute_stateful_thresholds.v2.json"),
        Some(state.clone()),
        ValidationModeV1::StateRequired,
        Some(600),
    );
    serde_json::to_value(
        assemble_decision_bundle_v1(DecisionBundleAssemblyRequestV1 {
            validation_report,
            contract,
            state: Some(state),
            resolved_config: None,
            config_bundle: None,
            verification_bundle: None,
            recommendation_report: None,
            bundled_at: common::FIXED_TIMESTAMP.to_string(),
            notes: None,
        })
        .expect("stateful fixture bundle should assemble"),
    )
    .unwrap()
}

struct TestRoot(PathBuf);

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
