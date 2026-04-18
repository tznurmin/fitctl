// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

use crate::{common, e2e};

#[test]
fn decision_bundle_accepts_config_bundle_handoff() {
    let root = common::unique_temp_dir("decision-bundle-config-bundle");
    let survey_path = e2e::emit_survey_fixture(&root, "linux-bare-metal-like-v1");
    let contract_path =
        e2e::derive_contract(&root, &survey_path, "general_compute_default.v1.json");
    let config_bundle_path = e2e::emit_config_bundle(
        &root,
        "general_compute_default.v1.json",
        Some("general_compute_contract_only.v2.json"),
    );

    let validation_output = e2e::run_fitctl([
        "validate",
        "--contract",
        contract_path
            .to_str()
            .expect("contract path should be UTF-8"),
        "--profile",
        common::repo_service_profile_path("general_compute_contract_only.v2.json")
            .to_str()
            .expect("service-profile path should be UTF-8"),
        "--validated-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&validation_output);
    let validation_path = root.join("validation-report.json");
    e2e::write_stdout(&validation_path, &validation_output);

    let bundle_output = e2e::run_fitctl([
        "bundle",
        "--validation-report",
        validation_path
            .to_str()
            .expect("validation path should be UTF-8"),
        "--contract",
        contract_path
            .to_str()
            .expect("contract path should be UTF-8"),
        "--config-bundle",
        config_bundle_path
            .to_str()
            .expect("config-bundle path should be UTF-8"),
        "--bundled-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&bundle_output);

    let bundle_json: Value = e2e::decode_json_stdout(&bundle_output);
    assert_eq!(
        bundle_json["envelope"]["schema_id"],
        "fitctl.decision-bundle.v2"
    );
    assert_eq!(
        bundle_json["bundle"]["config_bundle"]["envelope"]["schema_id"],
        "fitctl.config-bundle.v2"
    );
    assert!(bundle_json["bundle"]["resolved_config"].is_null());
    assert_eq!(
        bundle_json["bundle_basis"]["config_bundle_artifact_id"],
        bundle_json["bundle"]["config_bundle"]["envelope"]["artifact_id"]
    );
    assert_eq!(
        bundle_json["bundle"]["config_bundle"]["config_bundle"]["policy"]["policy_id"],
        "general_compute_default_v1"
    );
    assert_eq!(
        bundle_json["bundle"]["config_bundle"]["config_bundle"]["service_profile"]["profile"]
            ["profile_id"],
        "general_compute_contract_only_v1"
    );

    let bundle_path = root.join("decision-bundle.config-bundle.json");
    e2e::write_stdout(&bundle_path, &bundle_output);
    let inspect_output = e2e::run_fitctl([
        "inspect",
        "--input",
        bundle_path.to_str().expect("bundle path should be UTF-8"),
    ]);
    e2e::assert_success(&inspect_output);
    let inspect_text = String::from_utf8_lossy(&inspect_output.stdout);
    assert!(inspect_text.contains("fitctl.config-bundle.v2"));
    assert!(inspect_text.contains("Config bundle artifact id"));
    assert!(inspect_text.contains("Config policy id"));
    assert!(inspect_text.contains("general_compute_default_v1"));
    assert!(inspect_text.contains("Config service profile id"));
    assert!(inspect_text.contains("general_compute_contract_only_v1"));
}
