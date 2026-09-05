// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use fitctl_core::artifacts::envelope_v1::{ArtifactEnvelopeV1, ArtifactProvenanceV1};
use fitctl_core::artifacts::recommendation_report_v1::{
    RecommendationBasisV1, RecommendationConfidenceV1, RecommendationFreshnessStateV1,
    RecommendationFreshnessV1, RecommendationReportPayloadV1, RecommendationReportV1,
};
use fitctl_core::artifacts::schema_ids_v1::RECOMMENDATION_REPORT_SCHEMA_ID;
use fitctl_core::classify::{classify_batch_v1, BatchClassificationRequestV1};
use fitctl_core::validate::{ValidationModeV1, ValidationVerdictV1};

use crate::{common, e2e};

const SENTINEL: &str = "sensitive-auxiliary-report-value-prod-17";
const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn standalone_recommendation_and_batch_reports_accept_redaction() {
    let root = common::unique_temp_dir("standalone-auxiliary-redaction");
    let recommendation_path = root.join("recommendation-report.json");
    common::write_json_file(&recommendation_path, &sample_recommendation_report());

    let recommendation_output = e2e::run_fitctl([
        "redact",
        "--profile",
        "external",
        "--input",
        recommendation_path
            .to_str()
            .expect("recommendation path should be UTF-8"),
    ]);
    e2e::assert_success(&recommendation_output);
    let recommendation_json: serde_json::Value = e2e::decode_json_stdout(&recommendation_output);
    assert_eq!(
        recommendation_json["envelope"]["schema_id"],
        RECOMMENDATION_REPORT_SCHEMA_ID
    );
    assert!(!String::from_utf8_lossy(&recommendation_output.stdout).contains(SENTINEL));

    let mut batch = classify_batch_v1(BatchClassificationRequestV1 {
        contracts: vec![common::derive_contract_from_fixture(
            "linux-bare-metal-like-v1",
        )],
        service_profiles: vec![common::load_service_profile_file(
            "general_compute_contract_only.v2.json",
        )],
        host_states: vec![],
        validation_mode: ValidationModeV1::ContractOnly,
        max_state_age_seconds: None,
        validated_at: common::FIXED_TIMESTAMP.to_string(),
    })
    .expect("batch report should build");
    batch.envelope.provenance.source = SENTINEL.to_string();
    batch.envelope.provenance.correlation_id = Some(SENTINEL.to_string());
    batch.envelope.provenance.fitctl_vcs_describe = Some(SENTINEL.to_string());
    batch.envelope.provenance.fitctl_version = Some(format!("0.6.0-{SENTINEL}+private"));
    batch.envelope.provenance.command_name = Some(SENTINEL.to_string());
    batch.classification_basis.ordered_contracts[0].host_alias = Some(SENTINEL.to_string());
    batch.classification_basis.ordered_contracts[0].display_name = Some(SENTINEL.to_string());
    batch.classification_basis.ordered_service_profiles[0].display_name =
        Some(SENTINEL.to_string());
    batch.report.rows[0].summary = SENTINEL.to_string();
    let batch_path = root.join("batch-report.json");
    common::write_json_file(&batch_path, &batch);

    let batch_output = e2e::run_fitctl([
        "redact",
        "--profile",
        "external",
        "--input",
        batch_path.to_str().expect("batch path should be UTF-8"),
    ]);
    e2e::assert_success(&batch_output);
    let batch_json: serde_json::Value = e2e::decode_json_stdout(&batch_output);
    assert_eq!(
        batch_json["envelope"]["schema_id"],
        batch.envelope.schema_id
    );
    assert!(!String::from_utf8_lossy(&batch_output.stdout).contains(SENTINEL));
}

#[test]
fn standalone_auxiliary_redaction_rejects_malformed_provenance_without_stdout() {
    let root = common::unique_temp_dir("standalone-auxiliary-invalid-provenance");
    let path = root.join("recommendation-report.json");
    let mut report = sample_recommendation_report();
    report.envelope.provenance.collected_at = SENTINEL.to_string();
    common::write_json_file(&path, &report);

    let output = e2e::run_fitctl([
        "redact",
        "--profile",
        "external",
        "--input",
        path.to_str().expect("recommendation path should be UTF-8"),
    ]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("collected_at"));
}

fn sample_recommendation_report() -> RecommendationReportV1 {
    RecommendationReportV1 {
        envelope: ArtifactEnvelopeV1 {
            schema_id: RECOMMENDATION_REPORT_SCHEMA_ID.to_string(),
            schema_version: 2,
            artifact_id: format!("recommendation-report-{SENTINEL}"),
            provenance: ArtifactProvenanceV1 {
                source: SENTINEL.to_string(),
                collected_at: common::FIXED_TIMESTAMP.to_string(),
                fitctl_version: Some(format!("0.6.0-{SENTINEL}+private")),
                fitctl_vcs_revision: Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()),
                fitctl_vcs_describe: Some(SENTINEL.to_string()),
                fitctl_build_dirty: Some(false),
                command_name: Some(SENTINEL.to_string()),
                correlation_id: Some(SENTINEL.to_string()),
            },
            redaction: None,
            signatures: vec![],
        },
        recommendation_basis: RecommendationBasisV1 {
            validation_report_artifact_id: format!("validation-{SENTINEL}"),
            validation_report_semantic_hash: HASH.to_string(),
            validation_verdict: ValidationVerdictV1::Fit,
            recommendation_pack_id: SENTINEL.to_string(),
            recommendation_pack_version: format!("1.4.0-{SENTINEL}.7+private.19"),
            recommendation_engine_id: "fitctl.recommendation.boundary.v1".to_string(),
            recommendation_engine_version: "1.0.0".to_string(),
            state_artifact_id: Some(format!("state-{SENTINEL}")),
            state_semantic_hash: Some(HASH.to_string()),
        },
        report: RecommendationReportPayloadV1 {
            recommendation_class: Some(SENTINEL.to_string()),
            expected_operating_mode: Some(SENTINEL.to_string()),
            processing_time_band: Some(SENTINEL.to_string()),
            throughput_band: Some(SENTINEL.to_string()),
            confidence: RecommendationConfidenceV1::High,
            freshness: RecommendationFreshnessV1 {
                observed_at: common::FIXED_TIMESTAMP.to_string(),
                freshness_state: RecommendationFreshnessStateV1::Fresh,
            },
            advisory_reason_ids: vec![SENTINEL.to_string()],
            summary: SENTINEL.to_string(),
        },
    }
}
