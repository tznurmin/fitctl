// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Schema for validation reports emitted when a service profile is checked against a contract.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::artifacts::envelope_v1::ArtifactEnvelopeV1;
use crate::artifacts::state_v1::FreshnessStateV1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Top-level decision artifact emitted by validation.
pub struct ValidationReportV1 {
    pub envelope: ArtifactEnvelopeV1,
    pub validation_basis: ValidationBasisV1,
    pub report: ValidationReportPayloadV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Frozen input identity for one validation decision.
///
/// This lets later readers tell which contract, profile, and optional state snapshot produced the
/// report without replaying the whole pipeline.
pub struct ValidationBasisV1 {
    pub validation_mode: ValidationModeV1,
    pub contract_artifact_id: String,
    pub service_profile_artifact_id: String,
    pub contract_semantic_hash: String,
    pub service_profile_semantic_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_artifact_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_semantic_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Freshness timestamp from the state artifact so validation reports can explain stale-state
    /// decisions without requiring the original host-state artifact to be opened separately.
    pub state_observed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Raw freshness flag captured by the state artifact before any max-state-age window is
    /// applied during validation.
    pub state_freshness_state: Option<FreshnessStateV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Optional freshness window that was applied when deciding whether the provided host-state
    /// was still current enough to use.
    pub max_state_age_seconds: Option<u64>,
    pub validation_engine_id: String,
    pub validation_engine_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Machine-readable decision body.
///
/// The payload records the outcome and the evidence needed to explain it, not a full execution
/// trace of every internal check.
pub struct ValidationReportPayloadV1 {
    pub verdict: ValidationVerdictV1,
    pub primary_reason_code: ValidationReasonCodeV1,
    #[serde(default)]
    pub matched_requirements: Vec<String>,
    #[serde(default)]
    pub failed_requirements: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub policy_refs: Vec<String>,
    #[serde(default)]
    pub assurance_mismatches: Vec<String>,
    pub selected_degradation_tier: Option<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extension_diagnostics: BTreeMap<String, Value>,
    #[serde(default)]
    pub explanations: Vec<ValidationExplanationV1>,
    #[serde(default)]
    pub remediation_hints: Vec<ValidationRemediationHintV1>,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Human-readable explanation attached to one reason code.
pub struct ValidationExplanationV1 {
    pub explanation_id: String,
    pub reason_code: ValidationReasonCodeV1,
    pub summary: String,
    #[serde(default)]
    pub related_requirements: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub policy_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Operator-facing next step tied to one reason code.
pub struct ValidationRemediationHintV1 {
    pub hint_id: String,
    pub reason_code: ValidationReasonCodeV1,
    pub summary: String,
    #[serde(default)]
    pub actions: Vec<ValidationRemediationActionV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Small action item nested under a remediation hint.
pub struct ValidationRemediationActionV1 {
    pub action_id: String,
    pub summary: String,
}

impl Default for ValidationReportPayloadV1 {
    fn default() -> Self {
        Self {
            verdict: ValidationVerdictV1::Indeterminate,
            primary_reason_code: ValidationReasonCodeV1::ValidationBlocked,
            matched_requirements: vec![],
            failed_requirements: vec![],
            evidence_refs: vec![],
            policy_refs: vec![],
            assurance_mismatches: vec![],
            selected_degradation_tier: None,
            warnings: vec![],
            extension_diagnostics: BTreeMap::new(),
            explanations: vec![],
            remediation_hints: vec![],
            summary: String::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Validation mode controls how much live state may influence the decision.
pub enum ValidationModeV1 {
    ContractOnly,
    StateAdvisory,
    StateRequired,
    StateAware,
}

impl ValidationModeV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractOnly => "contract_only",
            Self::StateAdvisory => "state_advisory",
            Self::StateRequired => "state_required",
            Self::StateAware => "state_aware",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Verdict is the outcome class; reason codes explain why that outcome was reached.
pub enum ValidationVerdictV1 {
    Fit,
    FitWithDegradation,
    Unfit,
    Indeterminate,
}

impl ValidationVerdictV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fit => "fit",
            Self::FitWithDegradation => "fit_with_degradation",
            Self::Unfit => "unfit",
            Self::Indeterminate => "indeterminate",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Primary reason taxonomy used for machine decisions and inspect summaries.
pub enum ValidationReasonCodeV1 {
    RequirementsSatisfied,
    RequirementUnsatisfied,
    CapabilityUnknown,
    StateMissing,
    StateStale,
    AssurancePredicateUnresolved,
    AssuranceSourceNotAccepted,
    AssuranceDerivationStageNotAccepted,
    PolicyNotAdmissible,
    NetworkMismatch,
    TopologyMismatch,
    CapabilityDegraded,
    DegradationPathRequired,
    DegradationPathUnavailable,
    EvidenceIncomplete,
    ValidationBlocked,
}

impl ValidationReasonCodeV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RequirementsSatisfied => "requirements_satisfied",
            Self::RequirementUnsatisfied => "requirement_unsatisfied",
            Self::CapabilityUnknown => "capability_unknown",
            Self::StateMissing => "state_missing",
            Self::StateStale => "state_stale",
            Self::AssurancePredicateUnresolved => "assurance_predicate_unresolved",
            Self::AssuranceSourceNotAccepted => "assurance_source_not_accepted",
            Self::AssuranceDerivationStageNotAccepted => "assurance_derivation_stage_not_accepted",
            Self::PolicyNotAdmissible => "policy_not_admissible",
            Self::NetworkMismatch => "network_mismatch",
            Self::TopologyMismatch => "topology_mismatch",
            Self::CapabilityDegraded => "capability_degraded",
            Self::DegradationPathRequired => "degradation_path_required",
            Self::DegradationPathUnavailable => "degradation_path_unavailable",
            Self::EvidenceIncomplete => "evidence_incomplete",
            Self::ValidationBlocked => "validation_blocked",
        }
    }
}
