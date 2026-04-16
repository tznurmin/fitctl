// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Schema for advisory recommendation reports layered on top of validation results.

use serde::{Deserialize, Serialize};

use crate::artifacts::envelope_v1::ArtifactEnvelopeV1;
use crate::artifacts::validation_report_v1::ValidationVerdictV1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecommendationReportV1 {
    pub envelope: ArtifactEnvelopeV1,
    pub recommendation_basis: RecommendationBasisV1,
    pub report: RecommendationReportPayloadV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecommendationBasisV1 {
    pub validation_report_artifact_id: String,
    pub validation_report_semantic_hash: String,
    pub validation_verdict: ValidationVerdictV1,
    pub recommendation_pack_id: String,
    pub recommendation_pack_version: String,
    pub recommendation_engine_id: String,
    pub recommendation_engine_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_artifact_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_semantic_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecommendationReportPayloadV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommendation_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_operating_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub processing_time_band: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub throughput_band: Option<String>,
    pub confidence: RecommendationConfidenceV1,
    pub freshness: RecommendationFreshnessV1,
    #[serde(default)]
    pub advisory_reason_ids: Vec<String>,
    pub summary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationConfidenceV1 {
    Low,
    Medium,
    High,
}

impl RecommendationConfidenceV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecommendationFreshnessV1 {
    pub observed_at: String,
    pub freshness_state: RecommendationFreshnessStateV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationFreshnessStateV1 {
    Fresh,
    Stale,
    Unknown,
}

impl RecommendationFreshnessStateV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Stale => "stale",
            Self::Unknown => "unknown",
        }
    }
}
