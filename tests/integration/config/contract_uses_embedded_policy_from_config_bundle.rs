// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

use crate::common;
use crate::e2e;

#[test]
fn config_bundle_contract_reuses_embedded_policy() {
    let root = common::unique_temp_dir("contract-from-config-bundle");
    let survey_path = e2e::emit_survey_fixture(&root, "linux-bare-metal-like-v1");
    let explicit_contract_path =
        e2e::derive_contract(&root, &survey_path, "general_compute_default.v1.json");

    let bundle_output = e2e::run_fitctl([
        "bundle-config",
        "--policy-pack",
        common::repo_policy_pack_path("general_compute_default_pack.v1.json")
            .to_str()
            .expect("policy-pack path should be UTF-8"),
        "--policy-id",
        "general_compute_default_v1",
        "--bundled-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&bundle_output);
    let bundle_path = root.join("general-compute.config-bundle.json");
    e2e::write_stdout(&bundle_path, &bundle_output);

    let bundled_contract = e2e::run_fitctl([
        "contract",
        "--survey",
        survey_path.to_str().expect("survey path should be UTF-8"),
        "--config-bundle",
        bundle_path.to_str().expect("bundle path should be UTF-8"),
        "--derived-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&bundled_contract);

    let explicit_json: Value = serde_json::from_slice(
        &std::fs::read(&explicit_contract_path).expect("explicit contract should be readable"),
    )
    .expect("explicit contract should decode");
    let bundled_json: Value = e2e::decode_json_stdout(&bundled_contract);

    assert_eq!(explicit_json, bundled_json);
}
