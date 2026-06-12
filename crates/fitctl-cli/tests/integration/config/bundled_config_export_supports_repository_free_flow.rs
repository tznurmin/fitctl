// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

use crate::{common, e2e};

#[test]
fn bundled_config_export_supports_repository_free_flow() {
    let root = common::unique_temp_dir("bundled-config-export");
    let export_root = root.join("exported");

    let list_output = e2e::run_fitctl(["config", "list"]);
    e2e::assert_success(&list_output);
    let list_text = String::from_utf8(list_output.stdout).expect("list output should be UTF-8");
    assert!(list_text.contains("configs/policy/general_compute_default.v1.json"));
    assert!(list_text.contains("configs/service_profiles/general_compute_contract_only.v2.json"));
    assert!(list_text.contains("configs/extensions/fitctl_runtime_cuda.v1.json"));

    let export_output = e2e::run_fitctl([
        "config",
        "export",
        "--out-dir",
        export_root.to_str().expect("export path should be UTF-8"),
    ]);
    e2e::assert_success(&export_output);

    let policy_path = export_root.join("configs/policy/general_compute_default.v1.json");
    let profile_path =
        export_root.join("configs/service_profiles/general_compute_contract_only.v2.json");
    assert!(policy_path.exists());
    assert!(profile_path.exists());

    let survey_output = e2e::run_fitctl(["survey", "--fixture", "linux-bare-metal-like-v1"]);
    e2e::assert_success(&survey_output);
    let survey_path = root.join("host.survey.json");
    e2e::write_stdout(&survey_path, &survey_output);

    let contract_output = e2e::run_fitctl([
        "contract",
        "--survey",
        survey_path.to_str().expect("survey path should be UTF-8"),
        "--policy",
        policy_path.to_str().expect("policy path should be UTF-8"),
        "--derived-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&contract_output);
    let contract_path = root.join("host.contract.json");
    e2e::write_stdout(&contract_path, &contract_output);

    let validation_output = e2e::run_fitctl([
        "validate",
        "--contract",
        contract_path
            .to_str()
            .expect("contract path should be UTF-8"),
        "--profile",
        profile_path.to_str().expect("profile path should be UTF-8"),
        "--validated-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&validation_output);

    let validation: Value = e2e::decode_json_stdout(&validation_output);
    assert_eq!(validation["report"]["verdict"], "fit");
    assert_eq!(
        validation["report"]["primary_reason_code"],
        "requirements_satisfied"
    );
}
