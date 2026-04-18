// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common;
use crate::e2e;

#[test]
fn config_bundle_consumer_rejects_conflicting_cli_config_inputs() {
    let root = common::unique_temp_dir("config-bundle-cli-conflict");
    let survey_path = e2e::emit_survey_fixture(&root, "linux-bare-metal-like-v1");
    let contract_path =
        e2e::derive_contract(&root, &survey_path, "general_compute_default.v1.json");

    let bundle_output = e2e::run_fitctl([
        "bundle-config",
        "--policy",
        common::repo_policy_file_path("general_compute_default.v1.json")
            .to_str()
            .expect("policy path should be UTF-8"),
        "--profile",
        common::repo_service_profile_path("general_compute_contract_only.v2.json")
            .to_str()
            .expect("profile path should be UTF-8"),
        "--bundled-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&bundle_output);
    let bundle_path = root.join("conflict.config-bundle.json");
    e2e::write_stdout(&bundle_path, &bundle_output);

    let contract_conflict = e2e::run_fitctl([
        "contract",
        "--survey",
        survey_path.to_str().expect("survey path should be UTF-8"),
        "--config-bundle",
        bundle_path.to_str().expect("bundle path should be UTF-8"),
        "--policy",
        common::repo_policy_file_path("general_compute_default.v1.json")
            .to_str()
            .expect("policy path should be UTF-8"),
    ]);
    assert!(!contract_conflict.status.success());
    assert!(String::from_utf8_lossy(&contract_conflict.stderr)
        .contains("--config-bundle must not be combined"));

    let validate_conflict = e2e::run_fitctl([
        "validate",
        "--contract",
        contract_path
            .to_str()
            .expect("contract path should be valid UTF-8"),
        "--config-bundle",
        bundle_path.to_str().expect("bundle path should be UTF-8"),
        "--profile",
        common::repo_service_profile_path("general_compute_contract_only.v2.json")
            .to_str()
            .expect("profile path should be valid UTF-8"),
        "--validated-at",
        common::FIXED_TIMESTAMP,
    ]);
    assert!(!validate_conflict.status.success());
    assert!(String::from_utf8_lossy(&validate_conflict.stderr)
        .contains("--config-bundle must not be combined"));
}
