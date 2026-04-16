// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Top-level host-contract artifact envelope and basis metadata.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::artifacts::envelope_v1::ArtifactEnvelopeV1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostContractV1 {
    pub envelope: ArtifactEnvelopeV1,
    pub contract_basis: ContractBasisV1,
    pub contract: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractBasisV1 {
    pub core_semantic_basis: ContractSemanticBasisV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_basis: Option<ContractExtensionBasisV1>,
    pub derivation_provenance: DerivationProvenanceV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractSemanticBasisV1 {
    pub source_survey_semantic_hash: String,
    pub policy_semantic_hash: String,
    pub derivation_engine_id: String,
    pub derivation_engine_version: String,
    pub contract_schema_version: u32,
    pub selected_policy_layers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractExtensionBasisV1 {
    pub enabled_extension_namespaces: Vec<String>,
    pub extension_semantic_hashes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationProvenanceV1 {
    pub derived_at: String,
    pub notes: Option<String>,
}
