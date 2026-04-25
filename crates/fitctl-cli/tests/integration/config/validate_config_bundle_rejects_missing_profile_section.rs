// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common;
use crate::e2e;

#[test]
fn config_bundle_validate_rejects_missing_profile_section() {
    let root = common::unique_temp_dir("config-bundle-missing-profile");
    let survey_path = e2e::emit_survey_fixture(&root, "linux-bare-metal-like-v1");
    let contract_path =
        e2e::derive_contract(&root, &survey_path, "general_compute_default.v1.json");

    let bundle_output = e2e::run_fitctl([
        "bundle-config",
        "--policy",
        common::repo_policy_file_path("general_compute_default.v1.json")
            .to_str()
            .expect("policy path should be UTF-8"),
        "--bundled-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&bundle_output);
    let bundle_path = root.join("missing-profile.config-bundle.json");
    e2e::write_stdout(&bundle_path, &bundle_output);

    let output = e2e::run_fitctl([
        "validate",
        "--contract",
        contract_path
            .to_str()
            .expect("contract path should be valid UTF-8"),
        "--config-bundle",
        bundle_path
            .to_str()
            .expect("bundle path should be valid UTF-8"),
        "--validated-at",
        common::FIXED_TIMESTAMP,
    ]);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("--config-bundle requires an embedded selected service profile"));
}
