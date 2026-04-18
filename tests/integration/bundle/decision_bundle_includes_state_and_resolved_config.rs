// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

use crate::{common, e2e};

#[test]
fn decision_bundle_includes_state_and_resolved_config() {
    let root = common::unique_temp_dir("decision-bundle-stateful");
    let survey_path = e2e::emit_survey_fixture(&root, "linux-bare-metal-like-v1");
    let contract_path =
        e2e::derive_contract(&root, &survey_path, "general_compute_default.v1.json");
    let state_path = e2e::emit_state_fixture(&root, "linux-bare-metal-like-fresh-v1");

    let validation_output = e2e::run_fitctl([
        "validate",
        "--contract",
        contract_path
            .to_str()
            .expect("contract path should be UTF-8"),
        "--profile",
        common::repo_service_profile_path("general_compute_stateful_thresholds.v2.json")
            .to_str()
            .expect("service-profile path should be UTF-8"),
        "--validation-mode",
        "state_required",
        "--state",
        state_path.to_str().expect("state path should be UTF-8"),
        "--max-state-age",
        "10m",
        "--validated-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&validation_output);
    let validation_path = root.join("validation-report.state.json");
    e2e::write_stdout(&validation_path, &validation_output);

    let resolved_config_output = e2e::run_fitctl([
        "inspect-config",
        "--policy-pack",
        common::repo_policy_pack_path("general_compute_default_pack.v1.json")
            .to_str()
            .expect("policy-pack path should be UTF-8"),
        "--service-profile-catalogue",
        common::repo_service_profile_catalogue_path("general_compute.v1.json")
            .to_str()
            .expect("catalogue path should be UTF-8"),
        "--invocation-context",
        common::repo_invocation_context_path("general_compute_pack_state_required.v1.json")
            .to_str()
            .expect("invocation path should be UTF-8"),
    ]);
    e2e::assert_success(&resolved_config_output);
    let resolved_config_path = root.join("resolved-config.json");
    e2e::write_stdout(&resolved_config_path, &resolved_config_output);

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
        "--state",
        state_path.to_str().expect("state path should be UTF-8"),
        "--resolved-config",
        resolved_config_path
            .to_str()
            .expect("resolved-config path should be UTF-8"),
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
        bundle_json["bundle"]["state"]["envelope"]["schema_id"],
        "host-state.v2"
    );
    assert_eq!(
        bundle_json["bundle"]["resolved_config"]["schema_id"],
        "fitctl.resolved-config.v1"
    );
    assert_eq!(
        bundle_json["bundle"]["resolved_config"]["validation_mode"],
        "state_required"
    );
    assert_eq!(
        bundle_json["bundle"]["resolved_config"]["max_state_age_seconds"],
        600
    );

    let bundle_path = root.join("decision-bundle.state.json");
    e2e::write_stdout(&bundle_path, &bundle_output);
    let inspect_output = e2e::run_fitctl([
        "inspect",
        "--input",
        bundle_path.to_str().expect("bundle path should be UTF-8"),
    ]);
    e2e::assert_success(&inspect_output);
    let inspect_text = String::from_utf8_lossy(&inspect_output.stdout);
    assert!(inspect_text.contains("Resolved policy id"));
    assert!(inspect_text.contains("Resolved validation mode"));
    assert!(inspect_text.contains("state_required"));
    assert!(inspect_text.contains("State freshness"));
}
