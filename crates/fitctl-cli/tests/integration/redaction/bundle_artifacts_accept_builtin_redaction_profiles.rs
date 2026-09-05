// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

use crate::{common, e2e};

const SOURCE_SENTINEL: &str = "nested-sensitive-source-prod-31";
const CORRELATION_SENTINEL: &str = "nested-sensitive-correlation-prod-31";
const VCS_SENTINEL: &str = "nested-sensitive-vcs-prod-31";
const RECOMMENDATION_SENTINEL: &str = "nested-sensitive-recommendation-prod-31";

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

    let recommendation_output = e2e::run_fitctl([
        "recommend",
        "--validation-report",
        validation_path
            .to_str()
            .expect("validation path should be UTF-8"),
        "--recommendation-pack",
        common::repo_recommendation_pack_path("general_compute_advisory.v1.json")
            .to_str()
            .expect("recommendation pack path should be UTF-8"),
        "--recommended-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&recommendation_output);
    let recommendation_path = root.join("recommendation-report.json");
    let mut recommendation_json: Value = e2e::decode_json_stdout(&recommendation_output);
    recommendation_json["recommendation_basis"]["recommendation_pack_id"] =
        Value::String(RECOMMENDATION_SENTINEL.to_string());
    recommendation_json["recommendation_basis"]["recommendation_pack_version"] =
        Value::String(format!("1.4.0-{RECOMMENDATION_SENTINEL}.7+private.19"));
    common::write_json_file(&recommendation_path, &recommendation_json);

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
        "--recommendation-report",
        recommendation_path
            .to_str()
            .expect("recommendation path should be UTF-8"),
        "--bundled-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&bundle_output);
    let bundle_path = root.join("decision-bundle.json");
    let mut bundle_json: Value = e2e::decode_json_stdout(&bundle_output);
    inject_provenance_sentinels(&mut bundle_json);
    common::write_json_file(&bundle_path, &bundle_json);

    let bundle_fleet_output = e2e::run_fitctl([
        "redact",
        "--profile",
        "fleet",
        "--input",
        bundle_path
            .to_str()
            .expect("decision bundle path should be UTF-8"),
    ]);
    e2e::assert_success(&bundle_fleet_output);
    let fleet_text = String::from_utf8_lossy(&bundle_fleet_output.stdout);
    assert!(!fleet_text.contains(CORRELATION_SENTINEL));
    assert!(fleet_text.contains(SOURCE_SENTINEL));
    assert!(fleet_text.contains(VCS_SENTINEL));

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
    let external_text = String::from_utf8_lossy(&bundle_redact_output.stdout);
    for sentinel in [
        SOURCE_SENTINEL,
        CORRELATION_SENTINEL,
        VCS_SENTINEL,
        RECOMMENDATION_SENTINEL,
    ] {
        assert!(!external_text.contains(sentinel));
    }
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
    let embedded_profile =
        &bundle_redacted_json["bundle"]["config_bundle"]["config_bundle"]["service_profile"];
    assert_eq!(
        bundle_redacted_json["bundle"]["validation_report"]["validation_basis"]
            ["service_profile_artifact_id"],
        embedded_profile["envelope"]["artifact_id"]
    );
    assert_eq!(
        bundle_redacted_json["bundle"]["config_bundle"]["config_bundle_basis"]
            ["service_profile_id"],
        embedded_profile["profile"]["profile_id"]
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

fn inject_provenance_sentinels(value: &mut Value) {
    match value {
        Value::Object(object) => {
            if object.contains_key("schema_id")
                && object.contains_key("artifact_id")
                && object.contains_key("provenance")
            {
                let schema_id = object
                    .get("schema_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let provenance = object
                    .get_mut("provenance")
                    .and_then(Value::as_object_mut)
                    .expect("artifact envelope provenance should be an object");
                provenance.insert(
                    "source".to_string(),
                    Value::String(SOURCE_SENTINEL.to_string()),
                );
                provenance.insert(
                    "correlation_id".to_string(),
                    Value::String(CORRELATION_SENTINEL.to_string()),
                );
                provenance.insert(
                    "fitctl_vcs_describe".to_string(),
                    Value::String(VCS_SENTINEL.to_string()),
                );
                if matches!(
                    schema_id.as_str(),
                    "service-profile.v2"
                        | "fitctl.config-bundle.v2"
                        | "fitctl.decision-bundle.v2"
                        | "fitctl.recommendation-report.v2"
                ) {
                    provenance.insert(
                        "fitctl_version".to_string(),
                        Value::String(format!("0.6.0-{SOURCE_SENTINEL}+private")),
                    );
                    provenance.insert(
                        "command_name".to_string(),
                        Value::String(SOURCE_SENTINEL.to_string()),
                    );
                }
            }
            for nested in object.values_mut() {
                inject_provenance_sentinels(nested);
            }
        }
        Value::Array(values) => {
            for nested in values {
                inject_provenance_sentinels(nested);
            }
        }
        _ => {}
    }
}
