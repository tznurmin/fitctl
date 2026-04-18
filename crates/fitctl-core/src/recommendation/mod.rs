// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Advisory recommendation-report loading and validation.
//!
//! Recommendations stay outside the core fit verdict. This module handles the typed report surface
//! without promoting advisory output into contract or validation semantics.

use std::fs;
use std::path::Path;

use serde_json::{Map, Value};

use crate::artifacts::envelope_v1::{local_artifact_provenance_v1, ArtifactEnvelopeV1};
use crate::artifacts::recommendation_report_v1::{
    RecommendationBasisV1, RecommendationConfidenceV1, RecommendationFreshnessStateV1,
    RecommendationFreshnessV1, RecommendationReportPayloadV1, RecommendationReportV1,
};
use crate::artifacts::schema_ids_v1::{
    RECOMMENDATION_REPORT_SCHEMA_ID, TOP_LEVEL_ARTIFACT_SCHEMA_VERSION,
};
use crate::artifacts::semantic_hash_v1::semantic_hash_hex_for_validation_report;
use crate::artifacts::state_v1::FreshnessStateV1;
use crate::artifacts::validation_v1::{
    validate_recommendation_report, ArtifactValidationErrorCode,
};
use crate::config::RecommendationPackV1;
use crate::validate::{ValidationReportV1, ValidationVerdictV1};

pub const RECOMMENDATION_ERROR_MODEL_ID: &str = "fitctl.recommendation.v1";
pub const RECOMMENDATION_ERROR_MODEL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecommendationErrorCode {
    RecommendationInputInvalid,
    RecommendationSchemaUnsupported,
    RecommendationArtifactInvalid,
    RecommendationExecutionFailed,
}

impl RecommendationErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RecommendationInputInvalid => "recommendation_input_invalid",
            Self::RecommendationSchemaUnsupported => "recommendation_schema_unsupported",
            Self::RecommendationArtifactInvalid => "recommendation_artifact_invalid",
            Self::RecommendationExecutionFailed => "recommendation_execution_failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecommendationError {
    pub code: RecommendationErrorCode,
    pub checkpoint_id: &'static str,
    pub message: String,
    pub error_model_id: &'static str,
    pub error_model_version: u32,
}

impl RecommendationError {
    fn new(
        code: RecommendationErrorCode,
        checkpoint_id: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            checkpoint_id,
            message: message.into(),
            error_model_id: RECOMMENDATION_ERROR_MODEL_ID,
            error_model_version: RECOMMENDATION_ERROR_MODEL_VERSION,
        }
    }
}

impl std::fmt::Display for RecommendationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} [{} at {}]",
            self.message,
            self.code.as_str(),
            self.checkpoint_id
        )
    }
}

impl std::error::Error for RecommendationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecommendationRequestV1 {
    pub validation_report: ValidationReportV1,
    pub recommendation_pack: RecommendationPackV1,
    pub recommended_at: String,
}

pub fn evaluate_recommendation_v1(
    request: RecommendationRequestV1,
) -> Result<RecommendationReportV1, RecommendationError> {
    if request.recommended_at.trim().is_empty() {
        return Err(RecommendationError::new(
            RecommendationErrorCode::RecommendationInputInvalid,
            "recommendation_evaluate",
            "recommendation evaluation requires a non-blank recommended-at timestamp",
        ));
    }
    if request.recommendation_pack.output_schema_id != RECOMMENDATION_REPORT_SCHEMA_ID {
        return Err(RecommendationError::new(
            RecommendationErrorCode::RecommendationInputInvalid,
            "recommendation_evaluate",
            "recommendation pack output_schema_id must target fitctl.recommendation-report.v2",
        ));
    }

    let validation_report_semantic_hash =
        semantic_hash_hex_for_validation_report(&request.validation_report).map_err(|error| {
            RecommendationError::new(
                RecommendationErrorCode::RecommendationExecutionFailed,
                "recommendation_evaluate",
                error.message,
            )
        })?;

    let freshness = build_freshness(&request.validation_report, &request.recommended_at);
    let payload = build_recommendation_payload(
        request.validation_report.report.verdict,
        request
            .validation_report
            .report
            .primary_reason_code
            .as_str(),
        request
            .validation_report
            .report
            .selected_degradation_tier
            .as_deref(),
        freshness,
    );

    let report = RecommendationReportV1 {
        envelope: ArtifactEnvelopeV1 {
            schema_id: RECOMMENDATION_REPORT_SCHEMA_ID.to_string(),
            schema_version: TOP_LEVEL_ARTIFACT_SCHEMA_VERSION,
            artifact_id: format!(
                "recommendation-{}-{}",
                request.validation_report.envelope.artifact_id, request.recommendation_pack.pack_id
            ),
            provenance: local_artifact_provenance_v1(
                "recommendation_pack",
                request.recommended_at,
                "recommend",
                format!(
                    "validation:{};pack:{}",
                    request.validation_report.envelope.artifact_id,
                    request.recommendation_pack.pack_id
                ),
            ),
            redaction: None,
            signatures: vec![],
        },
        recommendation_basis: RecommendationBasisV1 {
            validation_report_artifact_id: request.validation_report.envelope.artifact_id,
            validation_report_semantic_hash,
            validation_verdict: request.validation_report.report.verdict,
            recommendation_pack_id: request.recommendation_pack.pack_id,
            recommendation_pack_version: request.recommendation_pack.pack_version,
            recommendation_engine_id: "fitctl.recommendation.v1".to_string(),
            recommendation_engine_version: "1".to_string(),
            state_artifact_id: request.validation_report.validation_basis.state_artifact_id,
            state_semantic_hash: request
                .validation_report
                .validation_basis
                .state_semantic_hash,
        },
        report: payload,
    };

    validate_recommendation_report(&report).map_err(|error| {
        let code = match error.code {
            ArtifactValidationErrorCode::ArtifactSchemaIdInvalid
            | ArtifactValidationErrorCode::ArtifactSchemaVersionInvalid => {
                RecommendationErrorCode::RecommendationSchemaUnsupported
            }
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt
            | ArtifactValidationErrorCode::ContractBasisInvalid => {
                RecommendationErrorCode::RecommendationArtifactInvalid
            }
        };
        RecommendationError::new(code, "recommendation_report_emit", error.message)
    })?;

    Ok(report)
}

pub fn load_recommendation_report_from_path(
    path: &Path,
) -> Result<RecommendationReportV1, RecommendationError> {
    let text = fs::read_to_string(path).map_err(|error| {
        RecommendationError::new(
            RecommendationErrorCode::RecommendationInputInvalid,
            "recommendation_report_load",
            format!(
                "failed to read recommendation report {}: {error}",
                path.display()
            ),
        )
    })?;

    let raw: Value = serde_json::from_str(&text).map_err(|error| {
        RecommendationError::new(
            RecommendationErrorCode::RecommendationInputInvalid,
            "recommendation_report_load",
            format!(
                "failed to decode recommendation report {}: {error}",
                path.display()
            ),
        )
    })?;
    load_recommendation_report_from_value(raw)
}

pub fn load_recommendation_report_from_value(
    raw: Value,
) -> Result<RecommendationReportV1, RecommendationError> {
    validate_recommendation_report_json(&raw)?;

    let report: RecommendationReportV1 = serde_json::from_value(raw).map_err(|error| {
        RecommendationError::new(
            RecommendationErrorCode::RecommendationInputInvalid,
            "recommendation_report_load",
            format!("failed to decode typed recommendation report input: {error}"),
        )
    })?;

    validate_recommendation_report(&report).map_err(|error| {
        let code = match error.code {
            ArtifactValidationErrorCode::ArtifactSchemaIdInvalid
            | ArtifactValidationErrorCode::ArtifactSchemaVersionInvalid => {
                RecommendationErrorCode::RecommendationSchemaUnsupported
            }
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt
            | ArtifactValidationErrorCode::ContractBasisInvalid => {
                RecommendationErrorCode::RecommendationArtifactInvalid
            }
        };
        RecommendationError::new(code, "recommendation_report_validate", error.message)
    })?;

    Ok(report)
}

fn validate_recommendation_report_json(raw: &Value) -> Result<(), RecommendationError> {
    let root = raw.as_object().ok_or_else(|| {
        RecommendationError::new(
            RecommendationErrorCode::RecommendationInputInvalid,
            "recommendation_report_load",
            "recommendation report must decode to a JSON object",
        )
    })?;

    reject_unknown_keys(root, &["envelope", "recommendation_basis", "report"])?;
    reject_explicit_nulls(
        root,
        &["envelope", "recommendation_basis", "report"],
        "recommendation report field",
    )?;

    let envelope = require_object(root, "envelope", "recommendation report envelope")?;
    reject_unknown_keys(
        envelope,
        &[
            "schema_id",
            "schema_version",
            "artifact_id",
            "provenance",
            "redaction",
            "signatures",
        ],
    )?;
    reject_explicit_nulls(
        envelope,
        &[
            "schema_id",
            "schema_version",
            "artifact_id",
            "provenance",
            "signatures",
        ],
        "recommendation report envelope field",
    )?;

    let provenance = require_object(envelope, "provenance", "recommendation report provenance")?;
    reject_unknown_keys(
        provenance,
        &[
            "source",
            "collected_at",
            "fitctl_version",
            "command_name",
            "correlation_id",
        ],
    )?;
    reject_explicit_nulls(
        provenance,
        &["source", "collected_at"],
        "recommendation report provenance field",
    )?;

    let basis = require_object(root, "recommendation_basis", "recommendation report basis")?;
    reject_explicit_nulls(
        basis,
        &[
            "validation_report_artifact_id",
            "validation_report_semantic_hash",
            "validation_verdict",
            "recommendation_pack_id",
            "recommendation_pack_version",
            "recommendation_engine_id",
            "recommendation_engine_version",
        ],
        "recommendation basis field",
    )?;

    let report = require_object(root, "report", "recommendation report payload")?;
    reject_explicit_nulls(
        report,
        &["confidence", "freshness", "summary"],
        "recommendation report field",
    )?;

    Ok(())
}

fn require_object<'a>(
    value: &'a Map<String, Value>,
    key: &'static str,
    label: &'static str,
) -> Result<&'a Map<String, Value>, RecommendationError> {
    value.get(key).and_then(Value::as_object).ok_or_else(|| {
        RecommendationError::new(
            RecommendationErrorCode::RecommendationInputInvalid,
            "recommendation_report_load",
            format!("{label} must be a non-null object"),
        )
    })
}

fn reject_unknown_keys(
    map: &Map<String, Value>,
    allowed_keys: &[&str],
) -> Result<(), RecommendationError> {
    if let Some(key) = map.keys().find(|key| !allowed_keys.contains(&key.as_str())) {
        return Err(RecommendationError::new(
            RecommendationErrorCode::RecommendationInputInvalid,
            "recommendation_report_load",
            format!("recommendation report contains unsupported field {key}"),
        ));
    }

    Ok(())
}

fn reject_explicit_nulls(
    map: &Map<String, Value>,
    keys: &[&str],
    label: &'static str,
) -> Result<(), RecommendationError> {
    if let Some(key) = keys
        .iter()
        .find(|key| map.get(**key).is_some_and(Value::is_null))
    {
        return Err(RecommendationError::new(
            RecommendationErrorCode::RecommendationInputInvalid,
            "recommendation_report_load",
            format!("{label} {key} must not be null"),
        ));
    }

    Ok(())
}

pub fn recommendation_report_schema_id() -> &'static str {
    RECOMMENDATION_REPORT_SCHEMA_ID
}

fn build_freshness(
    validation_report: &ValidationReportV1,
    recommended_at: &str,
) -> RecommendationFreshnessV1 {
    let observed_at = validation_report
        .validation_basis
        .state_observed_at
        .clone()
        .unwrap_or_else(|| validation_report.envelope.provenance.collected_at.clone());
    let freshness_state = validation_report
        .validation_basis
        .state_freshness_state
        .map(map_freshness_state)
        .unwrap_or(RecommendationFreshnessStateV1::Fresh);

    RecommendationFreshnessV1 {
        observed_at: if observed_at.trim().is_empty() {
            recommended_at.to_string()
        } else {
            observed_at
        },
        freshness_state,
    }
}

fn map_freshness_state(state: FreshnessStateV1) -> RecommendationFreshnessStateV1 {
    match state {
        FreshnessStateV1::Fresh => RecommendationFreshnessStateV1::Fresh,
        FreshnessStateV1::Stale => RecommendationFreshnessStateV1::Stale,
    }
}

fn build_recommendation_payload(
    verdict: ValidationVerdictV1,
    primary_reason_code: &str,
    selected_degradation_tier: Option<&str>,
    freshness: RecommendationFreshnessV1,
) -> RecommendationReportPayloadV1 {
    match verdict {
        ValidationVerdictV1::Fit => RecommendationReportPayloadV1 {
            recommendation_class: Some("recommended".to_string()),
            expected_operating_mode: Some("preferred".to_string()),
            processing_time_band: None,
            throughput_band: None,
            confidence: RecommendationConfidenceV1::High,
            freshness,
            advisory_reason_ids: vec!["validation/fit".to_string()],
            summary: "validation fits the host; the advisory pack recommends this target"
                .to_string(),
        },
        ValidationVerdictV1::FitWithDegradation => {
            let mut advisory_reason_ids = vec![
                "validation/fit_with_degradation".to_string(),
                format!("reason/{primary_reason_code}"),
            ];
            if let Some(tier) = selected_degradation_tier {
                advisory_reason_ids.push(format!("degradation/{tier}"));
            }
            RecommendationReportPayloadV1 {
                recommendation_class: Some("recommended_with_caveats".to_string()),
                expected_operating_mode: Some("degraded".to_string()),
                processing_time_band: None,
                throughput_band: None,
                confidence: RecommendationConfidenceV1::Medium,
                freshness,
                advisory_reason_ids,
                summary:
                    "validation fits only through a degradation path; the advisory pack recommends caution"
                        .to_string(),
            }
        }
        ValidationVerdictV1::Unfit => RecommendationReportPayloadV1 {
            recommendation_class: Some("not_recommended".to_string()),
            expected_operating_mode: None,
            processing_time_band: None,
            throughput_band: None,
            confidence: RecommendationConfidenceV1::High,
            freshness,
            advisory_reason_ids: vec![
                "validation/unfit".to_string(),
                format!("reason/{primary_reason_code}"),
            ],
            summary: "validation does not fit the host; the advisory pack does not recommend this target"
                .to_string(),
        },
        ValidationVerdictV1::Indeterminate => RecommendationReportPayloadV1 {
            recommendation_class: Some("insufficient_evidence".to_string()),
            expected_operating_mode: None,
            processing_time_band: None,
            throughput_band: None,
            confidence: RecommendationConfidenceV1::Low,
            freshness,
            advisory_reason_ids: vec![
                "validation/indeterminate".to_string(),
                format!("reason/{primary_reason_code}"),
            ],
            summary: "validation stayed indeterminate; the advisory pack cannot make a confident recommendation"
                .to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::envelope_v1::{ArtifactEnvelopeV1, ArtifactProvenanceV1};
    use crate::artifacts::validation_report_v1::{
        ValidationBasisV1, ValidationModeV1, ValidationReasonCodeV1, ValidationReportPayloadV1,
    };

    fn sample_pack() -> RecommendationPackV1 {
        RecommendationPackV1 {
            schema_id: "fitctl.recommendation-pack.v1".to_string(),
            schema_version: 1,
            pack_id: "general-compute-advisory-v1".to_string(),
            pack_version: "1.0.0".to_string(),
            summary: "test pack".to_string(),
            output_schema_id: RECOMMENDATION_REPORT_SCHEMA_ID.to_string(),
            supported_extension_namespaces: vec![],
        }
    }

    fn sample_validation_report(verdict: ValidationVerdictV1) -> ValidationReportV1 {
        let primary_reason_code = match verdict {
            ValidationVerdictV1::Fit => ValidationReasonCodeV1::RequirementsSatisfied,
            ValidationVerdictV1::FitWithDegradation => {
                ValidationReasonCodeV1::DegradationPathRequired
            }
            ValidationVerdictV1::Unfit => ValidationReasonCodeV1::RequirementUnsatisfied,
            ValidationVerdictV1::Indeterminate => ValidationReasonCodeV1::ValidationBlocked,
        };

        ValidationReportV1 {
            envelope: ArtifactEnvelopeV1 {
                schema_id: "validation-report.v2".to_string(),
                schema_version: TOP_LEVEL_ARTIFACT_SCHEMA_VERSION,
                artifact_id: "validation-report-general-compute-v1".to_string(),
                provenance: ArtifactProvenanceV1 {
                    source: "validate".to_string(),
                    collected_at: "2025-04-21T14:37:19Z".to_string(),
                    fitctl_version: Some("0.2.0".to_string()),
                    command_name: Some("validate".to_string()),
                    correlation_id: Some("test-validation".to_string()),
                },
                redaction: None,
                signatures: vec![],
            },
            validation_basis: ValidationBasisV1 {
                validation_mode: ValidationModeV1::ContractOnly,
                contract_artifact_id: "contract-a".to_string(),
                service_profile_artifact_id: "profile-a".to_string(),
                contract_semantic_hash:
                    "963155a0a0680abf1b43fa6d2b21161146865a5bc74694a0582010c024b9576f".to_string(),
                service_profile_semantic_hash:
                    "863155a0a0680abf1b43fa6d2b21161146865a5bc74694a0582010c024b9576f".to_string(),
                state_artifact_id: None,
                state_semantic_hash: None,
                state_observed_at: None,
                state_freshness_state: None,
                max_state_age_seconds: None,
                validation_engine_id: "fitctl.validate.v1".to_string(),
                validation_engine_version: "1".to_string(),
            },
            report: ValidationReportPayloadV1 {
                verdict,
                primary_reason_code,
                matched_requirements: vec![],
                failed_requirements: vec![],
                evidence_refs: vec![],
                policy_refs: vec![],
                assurance_mismatches: vec![],
                selected_degradation_tier: if verdict == ValidationVerdictV1::FitWithDegradation {
                    Some("general_compute".to_string())
                } else {
                    None
                },
                warnings: vec![],
                explanations: vec![],
                remediation_hints: vec![],
                summary: "validation summary".to_string(),
            },
        }
    }

    #[test]
    fn evaluation_keeps_validation_verdict_separate_from_recommendation_class() {
        let report = evaluate_recommendation_v1(RecommendationRequestV1 {
            validation_report: sample_validation_report(ValidationVerdictV1::FitWithDegradation),
            recommendation_pack: sample_pack(),
            recommended_at: "2025-04-21T14:37:19Z".to_string(),
        })
        .expect("recommendation should evaluate");

        assert_eq!(
            report.recommendation_basis.validation_verdict,
            ValidationVerdictV1::FitWithDegradation
        );
        assert_eq!(
            report.report.recommendation_class.as_deref(),
            Some("recommended_with_caveats")
        );
    }
}
