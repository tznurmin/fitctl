// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Schema for batch classification reports built from many contract/profile pairs.

use serde::{Deserialize, Serialize};

use crate::artifacts::envelope_v1::ArtifactEnvelopeV1;
use crate::artifacts::validation_report_v1::{
    ValidationModeV1, ValidationReasonCodeV1, ValidationVerdictV1,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchClassificationReportV1 {
    pub envelope: ArtifactEnvelopeV1,
    pub classification_basis: BatchClassificationBasisV1,
    pub report: BatchClassificationReportPayloadV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchClassificationBasisV1 {
    pub validation_mode: ValidationModeV1,
    pub validated_at: String,
    pub validation_engine_id: String,
    pub validation_engine_version: String,
    pub ordered_contracts: Vec<BatchClassificationContractRefV1>,
    pub ordered_service_profiles: Vec<BatchClassificationServiceProfileRefV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchClassificationContractRefV1 {
    pub artifact_id: String,
    pub semantic_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchClassificationServiceProfileRefV1 {
    pub artifact_id: String,
    pub semantic_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchClassificationReportPayloadV1 {
    pub rows: Vec<BatchClassificationRowV1>,
    #[serde(default)]
    pub contract_summaries: Vec<BatchClassificationContractSummaryV1>,
    #[serde(default)]
    pub service_profile_summaries: Vec<BatchClassificationServiceProfileSummaryV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchClassificationRowV1 {
    pub row_id: String,
    pub contract_artifact_id: String,
    pub contract_semantic_hash: String,
    pub service_profile_artifact_id: String,
    pub service_profile_semantic_hash: String,
    pub verdict: ValidationVerdictV1,
    pub primary_reason_code: ValidationReasonCodeV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_degradation_tier: Option<String>,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchClassificationContractSummaryV1 {
    pub contract_artifact_id: String,
    #[serde(default)]
    pub fit_profile_ids: Vec<String>,
    #[serde(default)]
    pub degraded_profile_ids: Vec<String>,
    #[serde(default)]
    pub unfit_profile_ids: Vec<String>,
    #[serde(default)]
    pub indeterminate_profile_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchClassificationServiceProfileSummaryV1 {
    pub service_profile_artifact_id: String,
    #[serde(default)]
    pub fit_contract_ids: Vec<String>,
    #[serde(default)]
    pub degraded_contract_ids: Vec<String>,
    #[serde(default)]
    pub unfit_contract_ids: Vec<String>,
    #[serde(default)]
    pub indeterminate_contract_ids: Vec<String>,
}
