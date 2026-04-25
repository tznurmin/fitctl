// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

use crate::{common, e2e};

#[test]
fn decision_bundle_contract_only_assembles_local_artifact() {
    let root = common::unique_temp_dir("decision-bundle-contract-only");
    let survey_path = e2e::emit_survey_fixture(&root, "linux-bare-metal-like-v1");
    let contract_path =
        e2e::derive_contract(&root, &survey_path, "general_compute_default.v1.json");

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
        bundle_json["bundle"]["validation_report"]["envelope"]["schema_id"],
        "validation-report.v2"
    );
    assert_eq!(
        bundle_json["bundle"]["contract"]["envelope"]["schema_id"],
        "host-contract.v2"
    );
    assert!(bundle_json["bundle"]["state"].is_null());
    assert!(bundle_json["bundle"]["resolved_config"].is_null());

    let bundle_path = root.join("decision-bundle.json");
    e2e::write_stdout(&bundle_path, &bundle_output);
    let inspect_output = e2e::run_fitctl([
        "inspect",
        "--input",
        bundle_path.to_str().expect("bundle path should be UTF-8"),
    ]);
    e2e::assert_success(&inspect_output);
    let inspect_text = String::from_utf8_lossy(&inspect_output.stdout);
    assert!(inspect_text.contains("Bundle scope"));
    assert!(inspect_text.contains("single local decision"));
    assert!(inspect_text.contains("Bundle contents"));
    assert!(inspect_text.contains("validation-report.v2, host-contract.v2"));
    assert!(inspect_text.contains("Lineage status"));
}
