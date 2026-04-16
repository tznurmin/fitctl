// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Schema for workload requirements consumed by validation.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::artifacts::envelope_v1::ArtifactEnvelopeV1;
use crate::artifacts::metadata_v1::{AssuranceSourceV1, DerivationStageV1};
use crate::survey::NetworkInterfaceKindV1;
use crate::survey::VisibilityScopeV1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// Top-level workload requirement artifact.
pub struct ServiceProfileV1 {
    pub envelope: ArtifactEnvelopeV1,
    pub profile: ServiceProfilePayloadV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Workload demand definition.
///
/// Profiles describe what a service needs from a host contract; they do not derive those
/// capabilities from host evidence themselves.
pub struct ServiceProfilePayloadV1 {
    pub profile_id: String,
    pub core_requirements: ServiceRequirementsV1,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extension_requirements: BTreeMap<String, Value>,
    pub preferences: ServicePreferencesV1,
    pub exclusions: ServiceExclusionsV1,
    #[serde(default)]
    pub degradation_ladder: Vec<DegradationTierV1>,
    #[serde(default)]
    pub assurance_predicates: Vec<AssurancePredicateV1>,
    #[serde(default)]
    pub assurance_requirements: Vec<ExplicitAssuranceRequirementV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Hard requirements that validation must satisfy before preferences or fallbacks are considered.
pub struct ServiceRequirementsV1 {
    pub primary_capability_class: String,
    pub allowed_visibility_scopes: Vec<VisibilityScopeV1>,
    pub min_allocatable_cpu_logical_cores: Option<u32>,
    pub min_allocatable_memory_bytes: Option<u64>,
    #[serde(default)]
    pub min_non_loopback_interfaces: Option<u32>,
    #[serde(default)]
    pub min_network_link_speed_mbps: Option<u64>,
    #[serde(default)]
    pub required_network_interface_kinds: Vec<NetworkInterfaceKindV1>,
    #[serde(default)]
    pub min_numa_nodes: Option<u32>,
    #[serde(default)]
    pub max_numa_nodes: Option<u32>,
    #[serde(default)]
    pub min_cpu_packages: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
/// Soft guidance kept separate from hard requirements so fit semantics stay conservative.
pub struct ServicePreferencesV1 {
    pub preferred_visibility_scope: Option<VisibilityScopeV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
/// Explicit things the workload must not run on even if positive requirements are met.
pub struct ServiceExclusionsV1 {
    #[serde(default)]
    pub forbidden_capability_classes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Ordered fallback tier accepted when the primary capability class is unavailable.
pub struct DegradationTierV1 {
    pub tier_id: String,
    pub acceptable_capability_class: String,
    pub rationale: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Compact shortcuts for common assurance expectations.
pub enum AssurancePredicateV1 {
    LocallyVerifiedRequired,
    HardwareAttestedRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Fine-grained assurance rule for one target when the built-in predicates are too coarse.
pub struct ExplicitAssuranceRequirementV1 {
    pub target: String,
    pub accepted_assurance_sources: Vec<AssuranceSourceV1>,
    pub accepted_derivation_stages: Vec<DerivationStageV1>,
    #[serde(default)]
    pub allow_policy_asserted: bool,
    #[serde(default)]
    pub allow_mixed_sources: bool,
    #[serde(default)]
    pub allow_stale_evidence: bool,
}
