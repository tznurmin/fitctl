// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use serde_json::json;

use crate::common;
use crate::e2e;

#[test]
fn inspect_config_reports_selection_provenance_from_invocation_context() {
    let output = e2e::run_fitctl([
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
    e2e::assert_success(&output);

    let resolved: serde_json::Value = e2e::decode_json_stdout(&output);
    assert_eq!(resolved["schema_id"], "fitctl.resolved-config.v1");
    assert_eq!(resolved["policy_id"], "general_compute_default_v1");
    assert_eq!(
        resolved["selected_policy_pack_id"],
        "general-compute-policy-pack-v1"
    );
    assert_eq!(
        resolved["selected_policy_entry_id"],
        "general_compute_default_v1"
    );
    assert_eq!(
        resolved["selected_policy_entry_source"],
        "invocation_context"
    );
    assert_eq!(
        resolved["selected_service_profile_catalogue_id"],
        "general-compute-service-profiles-v1"
    );
    assert_eq!(
        resolved["selected_service_profile_entry_id"],
        "general_compute_stateful_thresholds_v1"
    );
    assert_eq!(
        resolved["selected_service_profile_entry_source"],
        "invocation_context"
    );
    assert_eq!(
        resolved["invocation_id"],
        "general-compute-pack-state-required-v1"
    );
    assert_eq!(resolved["validation_mode"], "state_required");
    assert_eq!(resolved["max_state_age_seconds"], json!(600));
}
