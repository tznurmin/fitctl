// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Shared metadata enums and structs reused across survey, contract, state, and validation.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Identifies one collector implementation that contributed evidence.
pub struct CollectorMetadataV1 {
    pub collector_id: String,
    pub collector_version: String,
    pub source_family: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
/// How strongly a claim was established.
pub enum AssuranceSourceV1 {
    #[default]
    SelfObserved,
    ImportedAuxiliary,
    LocallyVerified,
    HardwareAttested,
}

impl AssuranceSourceV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SelfObserved => "self_observed",
            Self::ImportedAuxiliary => "imported_auxiliary",
            Self::LocallyVerified => "locally_verified",
            Self::HardwareAttested => "hardware_attested",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
/// Which pipeline phase produced the claim.
pub enum DerivationStageV1 {
    #[default]
    Observed,
    Normalized,
    Derived,
    PolicyAsserted,
    ValidationResult,
}

impl DerivationStageV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Normalized => "normalized",
            Self::Derived => "derived",
            Self::PolicyAsserted => "policy_asserted",
            Self::ValidationResult => "validation_result",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
/// Per-claim provenance shared across survey, contract, state, and validation outputs.
pub struct ClaimMetadataV1 {
    #[serde(default)]
    pub assurance_source: AssuranceSourceV1,
    #[serde(default)]
    pub derivation_stage: DerivationStageV1,
    #[serde(default)]
    pub source_collectors: Vec<String>,
    #[serde(default)]
    pub evidence_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_rule_id: Option<String>,
    #[serde(default)]
    pub trust_evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum IdentityClassV1 {
    #[default]
    LocalStable,
    ExportPseudonym,
}

impl IdentityClassV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalStable => "local_stable",
            Self::ExportPseudonym => "export_pseudonym",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
/// Identity material carried through survey and contract outputs.
///
/// These values help correlate local artifacts, but human views may shorten or redact them.
pub struct IdentitySummaryV1 {
    #[serde(default)]
    pub identity_class: IdentityClassV1,
    #[serde(default)]
    pub local_stable_id: String,
    #[serde(default)]
    pub composition_digest: String,
    #[serde(default)]
    pub provenance_fingerprint: String,
}
