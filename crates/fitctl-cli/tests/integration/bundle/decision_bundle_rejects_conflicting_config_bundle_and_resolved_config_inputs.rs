// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{common, e2e};

#[test]
fn decision_bundle_rejects_conflicting_config_bundle_and_resolved_config_inputs() {
    let root = common::unique_temp_dir("decision-bundle-config-conflict");
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
        "--resolved-config",
        resolved_config_path
            .to_str()
            .expect("resolved-config path should be UTF-8"),
        "--config-bundle",
        config_bundle_path
            .to_str()
            .expect("config-bundle path should be UTF-8"),
        "--bundled-at",
        common::FIXED_TIMESTAMP,
    ]);

    assert!(
        !bundle_output.status.success(),
        "unexpected success: {}",
        String::from_utf8_lossy(&bundle_output.stdout)
    );
    let stderr = String::from_utf8_lossy(&bundle_output.stderr);
    assert!(stderr.contains("--config-bundle must not be combined with --resolved-config"));
}
