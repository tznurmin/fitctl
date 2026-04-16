// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Schema for host survey artifacts and their raw observed evidence payload.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::artifacts::envelope_v1::ArtifactEnvelopeV1;
use crate::artifacts::metadata_v1::{ClaimMetadataV1, CollectorMetadataV1, IdentitySummaryV1};
use crate::survey::{ExecutionContextV1, SurveyObservationsV1};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// Top-level survey artifact.
///
/// The envelope carries provenance and signatures, while the payload stays open to extension
/// evidence without changing the core artifact shell.
pub struct HostSurveyV1 {
    pub envelope: ArtifactEnvelopeV1,
    pub survey: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Raw observed host evidence before policy interprets it into a host promise.
pub struct HostSurveyPayloadV1 {
    pub collection_mode: String,
    pub snapshot_id: String,
    pub host_alias: String,
    pub source_ref: String,
    pub core_evidence: HostSurveyCoreEvidenceV1,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extension_evidence: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Core survey content understood by the base system.
///
/// Extension evidence lives alongside this structure but remains outside the stable core schema.
pub struct HostSurveyCoreEvidenceV1 {
    pub execution_context: ExecutionContextV1,
    pub collectors: Vec<CollectorMetadataV1>,
    #[serde(default)]
    pub section_metadata: SurveySectionMetadataV1,
    #[serde(default)]
    pub identity_summary: IdentitySummaryV1,
    pub observations: SurveyObservationsV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
/// Per-section provenance and assurance metadata aligned with the major survey groups.
pub struct SurveySectionMetadataV1 {
    #[serde(default)]
    pub execution_context: ClaimMetadataV1,
    #[serde(default)]
    pub hostname: ClaimMetadataV1,
    #[serde(default)]
    pub cpu: ClaimMetadataV1,
    #[serde(default)]
    pub memory: ClaimMetadataV1,
    #[serde(default)]
    pub storage: ClaimMetadataV1,
    #[serde(default)]
    pub network: ClaimMetadataV1,
    #[serde(default)]
    pub accelerators: ClaimMetadataV1,
    #[serde(default)]
    pub topology: ClaimMetadataV1,
}

pub fn decode_host_survey_payload(
    payload: &Value,
) -> Result<HostSurveyPayloadV1, serde_json::Error> {
    serde_json::from_value(payload.clone())
}

pub fn encode_host_survey_payload(
    payload: &HostSurveyPayloadV1,
) -> Result<Value, serde_json::Error> {
    serde_json::to_value(payload)
}
