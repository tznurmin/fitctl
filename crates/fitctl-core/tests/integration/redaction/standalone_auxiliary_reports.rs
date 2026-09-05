// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use fitctl_core::artifacts::envelope_v1::{ArtifactEnvelopeV1, ArtifactProvenanceV1};
use fitctl_core::artifacts::recommendation_report_v1::{
    RecommendationBasisV1, RecommendationConfidenceV1, RecommendationFreshnessStateV1,
    RecommendationFreshnessV1, RecommendationReportPayloadV1, RecommendationReportV1,
};
use fitctl_core::artifacts::record_v1::load_artifact_record_from_value;
use fitctl_core::artifacts::schema_ids_v1::{
    LEGACY_BATCH_CLASSIFICATION_REPORT_SCHEMA_ID, RECOMMENDATION_REPORT_SCHEMA_ID,
};
use fitctl_core::artifacts::validation_v1::{
    validate_batch_classification_report, validate_recommendation_report,
};
use fitctl_core::classify::{classify_batch_v1, BatchClassificationRequestV1};
use fitctl_core::redact::{
    load_redactable_artifact_for_redaction, load_redactable_artifact_from_value,
    redact_supported_artifact_v1, BuiltInRedactionProfileV1, RedactableArtifactRequestV1,
    RedactableArtifactV1, RedactionErrorCode,
};
use fitctl_core::validate::{ValidationModeV1, ValidationVerdictV1};

use crate::common;

const SENTINEL: &str = "sensitive-auxiliary-value-prod-29";
const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn standalone_recommendation_redaction_is_typed_for_every_profile() {
    for profile in profiles() {
        let original = sample_recommendation_report();
        let redacted = redact_supported_artifact_v1(RedactableArtifactRequestV1 {
            artifact: RedactableArtifactV1::RecommendationReport(Box::new(original.clone())),
            profile,
            redacted_at: common::FIXED_TIMESTAMP.to_string(),
        })
        .expect("recommendation report should redact");
        let RedactableArtifactV1::RecommendationReport(redacted) = redacted else {
            panic!("recommendation input should retain its typed family");
        };
        validate_recommendation_report(&redacted).expect("redacted recommendation should validate");
        assert_eq!(redacted.envelope.schema_id, original.envelope.schema_id);
        assert_eq!(
            redacted.envelope.schema_version,
            original.envelope.schema_version
        );
        assert!(redacted.envelope.signatures.is_empty());
    }
}

#[test]
fn standalone_batch_redaction_supports_current_and_legacy_reports() {
    for legacy in [false, true] {
        let mut report = sensitive_batch_report();
        if legacy {
            report.envelope.schema_id = LEGACY_BATCH_CLASSIFICATION_REPORT_SCHEMA_ID.to_string();
        }
        let schema_id = report.envelope.schema_id.clone();
        let redacted = redact_supported_artifact_v1(RedactableArtifactRequestV1 {
            artifact: RedactableArtifactV1::BatchClassificationReport(Box::new(report)),
            profile: BuiltInRedactionProfileV1::External,
            redacted_at: common::FIXED_TIMESTAMP.to_string(),
        })
        .expect("batch report should redact");
        let RedactableArtifactV1::BatchClassificationReport(redacted) = redacted else {
            panic!("batch input should retain its typed family");
        };
        validate_batch_classification_report(&redacted).expect("redacted batch should validate");
        assert_eq!(redacted.envelope.schema_id, schema_id);
        assert!(!serde_json::to_string(&redacted)
            .expect("batch should encode")
            .contains(SENTINEL));
    }
}

#[test]
fn standalone_auxiliary_profile_sentinels_follow_the_profile_matrix() {
    let local = redact_recommendation(BuiltInRedactionProfileV1::Local);
    assert!(serde_json::to_string(&local)
        .expect("local report should encode")
        .contains(SENTINEL));

    let fleet = redact_recommendation(BuiltInRedactionProfileV1::Fleet);
    assert_eq!(fleet.envelope.provenance.source, SENTINEL);
    assert_eq!(
        fleet.envelope.provenance.correlation_id.as_deref(),
        Some(fleet.envelope.artifact_id.as_str())
    );

    for profile in [
        BuiltInRedactionProfileV1::Auditor,
        BuiltInRedactionProfileV1::External,
    ] {
        let redacted = redact_recommendation(profile);
        let encoded = serde_json::to_string(&redacted).expect("report should encode");
        assert!(!encoded.contains(SENTINEL));
        assert_eq!(
            redacted.envelope.provenance.source,
            format!("redacted:{}:source", profile.as_str())
        );
    }
}

#[test]
fn auxiliary_inputs_reject_unsupported_and_already_redacted_artifacts() {
    let recommendation = sample_recommendation_report();
    let raw = serde_json::to_value(&recommendation).expect("recommendation should encode");
    assert!(load_artifact_record_from_value(raw.clone()).is_err());
    assert!(matches!(
        load_redactable_artifact_from_value(raw),
        Ok(RedactableArtifactV1::RecommendationReport(_))
    ));

    let redacted = redact_recommendation(BuiltInRedactionProfileV1::External);
    let error = redact_supported_artifact_v1(RedactableArtifactRequestV1 {
        artifact: RedactableArtifactV1::RecommendationReport(Box::new(redacted)),
        profile: BuiltInRedactionProfileV1::External,
        redacted_at: common::FIXED_TIMESTAMP.to_string(),
    })
    .expect_err("already_redacted input should fail closed");
    assert_eq!(
        error.code,
        RedactionErrorCode::RedactionInputAlreadyRedacted
    );

    let unsupported = serde_json::json!({
        "envelope": { "schema_id": "fitctl.unsupported.v1" }
    });
    assert!(load_redactable_artifact_from_value(unsupported).is_err());
}

#[test]
fn redacted_auxiliary_conformance_cases_are_registered_and_typed() {
    let manifest_path = common::repo_root().join("fixtures/conformance/manifest.v1.json");
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&manifest_path).expect("conformance manifest should read"),
    )
    .expect("conformance manifest should decode");
    let cases = manifest["redaction_valid_cases"]
        .as_array()
        .expect("redaction_valid_cases should be an array");
    assert_eq!(cases.len(), 2);

    for case in cases {
        let relative = case["path"].as_str().expect("case path should be text");
        let artifact = load_redactable_artifact_for_redaction(&common::repo_root().join(relative))
            .expect("redacted conformance artifact should load");
        assert_eq!(
            artifact.envelope().schema_id,
            case["schema_id"]
                .as_str()
                .expect("case schema id should be text")
        );
        assert_eq!(
            artifact
                .envelope()
                .redaction
                .as_ref()
                .expect("fixture should be redacted")
                .profile_id,
            "external"
        );
    }
}

#[test]
fn external_auxiliary_fixtures_are_complete_redactor_golden_outputs() {
    let expected_recommendation: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            common::repo_root()
                .join("fixtures/conformance/valid/recommendation-report.external-redacted.v2.json"),
        )
        .expect("recommendation fixture should read"),
    )
    .expect("recommendation fixture should decode");
    let actual_recommendation =
        serde_json::to_value(redact_recommendation(BuiltInRedactionProfileV1::External))
            .expect("recommendation should encode");
    assert_eq!(actual_recommendation, expected_recommendation);

    let expected_batch: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(common::repo_root().join(
            "fixtures/conformance/valid/batch-classification-report.external-redacted.v3.json",
        ))
        .expect("batch fixture should read"),
    )
    .expect("batch fixture should decode");
    let redacted = redact_supported_artifact_v1(RedactableArtifactRequestV1 {
        artifact: RedactableArtifactV1::BatchClassificationReport(Box::new(
            sensitive_batch_report(),
        )),
        profile: BuiltInRedactionProfileV1::External,
        redacted_at: common::FIXED_TIMESTAMP.to_string(),
    })
    .expect("batch report should redact");
    let actual_batch = serde_json::to_value(redacted).expect("batch should encode");
    assert_eq!(actual_batch, expected_batch);
}

#[test]
fn malformed_imported_auxiliary_timestamp_fails_closed() {
    for timestamp in [
        SENTINEL,
        "2025-02-29T00:00:00Z",
        "2025-04-21T14:37:19+00:00",
        "unix:18446744073709551616",
    ] {
        let mut report = sample_recommendation_report();
        report.envelope.provenance.collected_at = timestamp.to_string();
        let error = redact_supported_artifact_v1(RedactableArtifactRequestV1 {
            artifact: RedactableArtifactV1::RecommendationReport(Box::new(report)),
            profile: BuiltInRedactionProfileV1::External,
            redacted_at: common::FIXED_TIMESTAMP.to_string(),
        })
        .expect_err("malformed auxiliary provenance must fail closed");
        assert_eq!(error.code, RedactionErrorCode::ArtifactInputInvalid);
        assert!(error.message.contains("collected_at"));
    }
}

#[test]
fn external_auxiliary_retains_only_stable_public_fitctl_versions() {
    let mut report = sample_recommendation_report();
    report.envelope.provenance.fitctl_version = Some("0.6.0".to_string());
    let redacted = redact_supported_artifact_v1(RedactableArtifactRequestV1 {
        artifact: RedactableArtifactV1::RecommendationReport(Box::new(report)),
        profile: BuiltInRedactionProfileV1::External,
        redacted_at: common::FIXED_TIMESTAMP.to_string(),
    })
    .expect("stable public version should be shareable");
    let RedactableArtifactV1::RecommendationReport(redacted) = redacted else {
        panic!("recommendation type should remain stable");
    };
    assert_eq!(
        redacted.envelope.provenance.fitctl_version.as_deref(),
        Some("0.6.0")
    );
    assert_eq!(
        redacted.envelope.provenance.command_name.as_deref(),
        Some("redacted:external:command_name")
    );
}

fn redact_recommendation(profile: BuiltInRedactionProfileV1) -> RecommendationReportV1 {
    let redacted = redact_supported_artifact_v1(RedactableArtifactRequestV1 {
        artifact: RedactableArtifactV1::RecommendationReport(Box::new(
            sample_recommendation_report(),
        )),
        profile,
        redacted_at: common::FIXED_TIMESTAMP.to_string(),
    })
    .expect("recommendation should redact");
    let RedactableArtifactV1::RecommendationReport(redacted) = redacted else {
        panic!("recommendation type should remain stable");
    };
    *redacted
}

fn sample_recommendation_report() -> RecommendationReportV1 {
    RecommendationReportV1 {
        envelope: ArtifactEnvelopeV1 {
            schema_id: RECOMMENDATION_REPORT_SCHEMA_ID.to_string(),
            schema_version: 2,
            artifact_id: format!("recommendation-{SENTINEL}"),
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
            recommendation_engine_id: format!("{SENTINEL}-recommendation-engine"),
            recommendation_engine_version: format!("{SENTINEL}-engine-version"),
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

fn sensitive_batch_report(
) -> fitctl_core::artifacts::batch_classification_report_v1::BatchClassificationReportV1 {
    let mut report = classify_batch_v1(BatchClassificationRequestV1 {
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
    .expect("batch fixture should build");

    report.envelope.artifact_id = SENTINEL.to_string();
    report.envelope.provenance.source = SENTINEL.to_string();
    report.envelope.provenance.correlation_id = Some(SENTINEL.to_string());
    report.envelope.provenance.fitctl_vcs_describe = Some(SENTINEL.to_string());
    report.envelope.provenance.fitctl_version = Some(format!("0.6.0-{SENTINEL}+private"));
    report.envelope.provenance.command_name = Some(SENTINEL.to_string());
    report.envelope.artifact_id = SENTINEL.to_string();
    report.classification_basis.validation_engine_id = format!("{SENTINEL}-validation-engine");
    report.classification_basis.validation_engine_version = format!("{SENTINEL}-engine-version");
    report.classification_basis.ordered_contracts[0].host_alias = Some(SENTINEL.to_string());
    report.classification_basis.ordered_contracts[0].display_name = Some(SENTINEL.to_string());
    report.classification_basis.ordered_service_profiles[0].display_name =
        Some(SENTINEL.to_string());
    report.report.rows[0].row_id = SENTINEL.to_string();
    report.report.rows[0].summary = SENTINEL.to_string();
    report.classification_basis.ordered_contracts[0].semantic_hash = HASH.to_string();
    report.report.rows[0].contract_semantic_hash = HASH.to_string();
    let profile_hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    report.classification_basis.ordered_service_profiles[0].semantic_hash =
        profile_hash.to_string();
    report.report.rows[0].service_profile_semantic_hash = profile_hash.to_string();
    report
}

fn profiles() -> [BuiltInRedactionProfileV1; 4] {
    [
        BuiltInRedactionProfileV1::Local,
        BuiltInRedactionProfileV1::Fleet,
        BuiltInRedactionProfileV1::Auditor,
        BuiltInRedactionProfileV1::External,
    ]
}
