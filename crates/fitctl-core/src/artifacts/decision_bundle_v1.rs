// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Decision-bundle artifact for one local validated gating result.

use serde::{Deserialize, Serialize};

use crate::artifacts::config_bundle_v1::ConfigBundleV1;
use crate::artifacts::contract_v1::HostContractV1;
use crate::artifacts::envelope_v1::ArtifactEnvelopeV1;
use crate::artifacts::recommendation_report_v1::RecommendationReportV1;
use crate::artifacts::state_v1::HostStateV1;
use crate::artifacts::validation_report_v1::ValidationReportV1;
use crate::config::ResolvedConfigV1;
use crate::verify::VerificationBundleV1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Local wrapper-facing bundle around one validated decision and the canonical artifacts it uses.
pub struct DecisionBundleV1 {
    pub envelope: ArtifactEnvelopeV1,
    pub bundle_basis: DecisionBundleBasisV1,
    pub bundle: DecisionBundlePayloadV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Frozen artifact identities for the embedded decision inputs.
pub struct DecisionBundleBasisV1 {
    pub validation_report_artifact_id: String,
    pub validation_report_semantic_hash: String,
    pub contract_artifact_id: String,
    pub contract_semantic_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_artifact_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_semantic_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_bundle_artifact_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_bundle_semantic_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_bundle_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommendation_report_artifact_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommendation_report_semantic_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Embedded canonical artifacts carried together for one local gating result.
pub struct DecisionBundlePayloadV1 {
    pub validation_report: ValidationReportV1,
    pub contract: HostContractV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<HostStateV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_config: Option<ResolvedConfigV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_bundle: Option<ConfigBundleV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_bundle: Option<VerificationBundleV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommendation_report: Option<RecommendationReportV1>,
}
