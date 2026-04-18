// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

use crate::{common, e2e};

#[test]
fn decision_bundle_accepts_recommendation_report_handoff() {
    let root = common::unique_temp_dir("decision-bundle-recommendation-report");
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

    let recommendation_output = e2e::run_fitctl([
        "recommend",
        "--validation-report",
        validation_path
            .to_str()
            .expect("validation path should be UTF-8"),
        "--recommendation-pack",
        common::repo_recommendation_pack_path("general_compute_advisory.v1.json")
            .to_str()
            .expect("recommendation-pack path should be UTF-8"),
        "--recommended-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&recommendation_output);
    let recommendation_path = root.join("recommendation-report.json");
    e2e::write_stdout(&recommendation_path, &recommendation_output);

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
        "--recommendation-report",
        recommendation_path
            .to_str()
            .expect("recommendation path should be UTF-8"),
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
        bundle_json["bundle"]["recommendation_report"]["envelope"]["schema_id"],
        "fitctl.recommendation-report.v2"
    );
    assert_eq!(
        bundle_json["bundle_basis"]["recommendation_report_artifact_id"],
        bundle_json["bundle"]["recommendation_report"]["envelope"]["artifact_id"]
    );
    assert_eq!(
        bundle_json["bundle"]["recommendation_report"]["recommendation_basis"]
            ["recommendation_pack_id"],
        "general-compute-advisory-v1"
    );

    let bundle_path = root.join("decision-bundle.recommendation.json");
    e2e::write_stdout(&bundle_path, &bundle_output);
    let inspect_output = e2e::run_fitctl([
        "inspect",
        "--input",
        bundle_path.to_str().expect("bundle path should be UTF-8"),
    ]);
    e2e::assert_success(&inspect_output);
    let inspect_text = String::from_utf8_lossy(&inspect_output.stdout);
    assert!(inspect_text.contains("fitctl.recommendation-report.v2"));
    assert!(inspect_text.contains("Recommendation report artifact id"));
    assert!(inspect_text.contains("Recommendation pack"));
    assert!(inspect_text.contains("general-compute-advisory-v1"));
}
