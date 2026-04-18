// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

use crate::{common, e2e};

#[test]
fn bundle_artifacts_accept_builtin_redaction_profiles() {
    let root = common::unique_temp_dir("bundle-redaction");
    let survey_path = e2e::emit_survey_fixture(&root, "linux-bare-metal-like-v1");
    let contract_path =
        e2e::derive_contract(&root, &survey_path, "general_compute_default.v1.json");
    let config_bundle_path = e2e::emit_config_bundle(
        &root,
        "general_compute_default.v1.json",
        Some("general_compute_contract_only.v2.json"),
    );

    let config_redact_output = e2e::run_fitctl([
        "redact",
        "--profile",
        "fleet",
        "--input",
        config_bundle_path
            .to_str()
            .expect("config bundle path should be UTF-8"),
    ]);
    e2e::assert_success(&config_redact_output);
    let config_redacted_json: Value = e2e::decode_json_stdout(&config_redact_output);
    assert_eq!(
        config_redacted_json["envelope"]["schema_id"],
        "fitctl.config-bundle.v2"
    );
    assert_eq!(
        config_redacted_json["envelope"]["redaction"]["profile_id"],
        "fleet"
    );
    assert_eq!(
        config_redacted_json["envelope"]["artifact_id"],
        "config-bundle-redacted-fleet-v1"
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
            .expect("service profile path should be UTF-8"),
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
            .expect("config bundle path should be UTF-8"),
        "--bundled-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&bundle_output);
    let bundle_path = root.join("decision-bundle.json");
    e2e::write_stdout(&bundle_path, &bundle_output);

    let bundle_redact_output = e2e::run_fitctl([
        "redact",
        "--profile",
        "external",
        "--input",
        bundle_path
            .to_str()
            .expect("decision bundle path should be UTF-8"),
    ]);
    e2e::assert_success(&bundle_redact_output);
    let bundle_redacted_json: Value = e2e::decode_json_stdout(&bundle_redact_output);
    assert_eq!(
        bundle_redacted_json["envelope"]["schema_id"],
        "fitctl.decision-bundle.v2"
    );
    assert_eq!(
        bundle_redacted_json["envelope"]["redaction"]["profile_id"],
        "external"
    );
    assert_eq!(
        bundle_redacted_json["bundle"]["validation_report"]["envelope"]["redaction"]["profile_id"],
        "external"
    );
    assert_eq!(
        bundle_redacted_json["bundle"]["contract"]["envelope"]["redaction"]["profile_id"],
        "external"
    );
    assert_eq!(
        bundle_redacted_json["bundle"]["config_bundle"]["envelope"]["redaction"]["profile_id"],
        "external"
    );

    let redacted_bundle_path = root.join("decision-bundle.redacted.json");
    e2e::write_stdout(&redacted_bundle_path, &bundle_redact_output);
    let inspect_output = e2e::run_fitctl([
        "inspect",
        "--input",
        redacted_bundle_path
            .to_str()
            .expect("redacted bundle path should be UTF-8"),
    ]);
    e2e::assert_success(&inspect_output);
    let inspect_text = String::from_utf8_lossy(&inspect_output.stdout);
    assert!(inspect_text.contains("Bundle contents"));
    assert!(inspect_text.contains("fitctl.config-bundle.v2"));
    assert!(inspect_text.contains("Lineage status"));
}
