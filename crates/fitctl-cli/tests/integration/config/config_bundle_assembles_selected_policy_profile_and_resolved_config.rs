// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

use crate::common;
use crate::e2e;

#[test]
fn config_bundle_assembles_selected_policy_profile_and_resolved_config() {
    let output = e2e::run_fitctl([
        "bundle-config",
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
        "--bundled-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&output);

    let bundle: Value = e2e::decode_json_stdout(&output);
    assert_eq!(bundle["envelope"]["schema_id"], "fitctl.config-bundle.v2");
    assert_eq!(
        bundle["config_bundle_basis"]["policy_id"],
        "general_compute_default_v1"
    );
    assert_eq!(
        bundle["config_bundle_basis"]["service_profile_id"],
        "general_compute_stateful_thresholds_v1"
    );
    assert_eq!(
        bundle["config_bundle"]["policy"]["policy_id"],
        "general_compute_default_v1"
    );
    assert_eq!(
        bundle["config_bundle"]["service_profile"]["profile"]["profile_id"],
        "general_compute_stateful_thresholds_v1"
    );
    assert_eq!(
        bundle["config_bundle"]["resolved_config"]["selected_policy_pack_id"],
        "general-compute-policy-pack-v1"
    );
    assert_eq!(
        bundle["config_bundle"]["resolved_config"]["selected_service_profile_catalogue_id"],
        "general-compute-service-profiles-v1"
    );
    assert_eq!(
        bundle["config_bundle"]["resolved_config"]["validation_mode"],
        "state_required"
    );
    assert_eq!(
        bundle["config_bundle"]["resolved_config"]["max_state_age_seconds"],
        600
    );
    assert!(
        bundle["config_bundle_basis"]["resolved_config_semantic_hash"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
}
