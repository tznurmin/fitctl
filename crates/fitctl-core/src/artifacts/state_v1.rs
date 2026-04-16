// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Schema for host runtime-state artifacts and their core resource and operability sections.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::artifacts::envelope_v1::ArtifactEnvelopeV1;
use crate::artifacts::metadata_v1::{ClaimMetadataV1, CollectorMetadataV1};
use crate::survey::{
    deserialize_observation_limitation_reason_opt_v1, ObservationLimitationReasonV1,
    ObservationStateV1,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Top-level runtime-state artifact.
///
/// Unlike survey and contract artifacts, state artifacts are expected to change as the host is
/// loaded, constrained, or otherwise evolves over time.
pub struct HostStateV1 {
    pub envelope: ArtifactEnvelopeV1,
    pub state: HostStatePayloadV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Operational snapshot consumed by state-aware validation.
pub struct HostStatePayloadV1 {
    pub collection_mode: StateCollectionModeV1,
    pub snapshot_id: String,
    pub host_alias: String,
    pub source_ref: String,
    pub core_state: HostStateCoreV1,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extension_state: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Core runtime view of freshness, allocatable resources, execution ceilings, and degraded classes.
pub struct HostStateCoreV1 {
    pub collectors: Vec<CollectorMetadataV1>,
    #[serde(default)]
    pub section_metadata: StateSectionMetadataV1,
    pub freshness: StateFreshnessV1,
    pub resources: HostRuntimeResourcesV1,
    #[serde(default)]
    pub boundaries: HostStateExecutionBoundariesV1,
    #[serde(default)]
    pub topology: HostStateTopologyV1,
    #[serde(default)]
    pub operability: HostStateOperabilityV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateCollectionModeV1 {
    Live,
    Replay,
}

impl StateCollectionModeV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Replay => "replay",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Freshness marker for runtime state.
///
/// The timestamp matters for full artifact validation, while semantic identity keeps only the
/// freshness state itself.
pub struct StateFreshnessV1 {
    pub observed_at: String,
    pub freshness_state: FreshnessStateV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessStateV1 {
    Fresh,
    Stale,
}

impl FreshnessStateV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Stale => "stale",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Current allocatable and used resource view rather than static hardware inventory.
pub struct HostRuntimeResourcesV1 {
    pub allocatable_cpu_logical_cores: StateFieldV1<u32>,
    pub memory_total_bytes: StateFieldV1<u64>,
    pub allocatable_memory_bytes: StateFieldV1<u64>,
    pub memory_used_excluding_cache_bytes: StateFieldV1<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
/// Per-section provenance for runtime values.
pub struct StateSectionMetadataV1 {
    #[serde(default)]
    pub resources: ClaimMetadataV1,
    #[serde(default)]
    pub boundaries: ClaimMetadataV1,
    #[serde(default)]
    pub topology: ClaimMetadataV1,
    #[serde(default)]
    pub operability: ClaimMetadataV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
/// Runtime ceilings imposed by cgroups or similar execution boundaries.
pub struct HostStateExecutionBoundariesV1 {
    #[serde(default)]
    pub cgroup_version: StateFieldV1<String>,
    #[serde(default)]
    pub cpuset_cpu_logical_cores: StateFieldV1<u32>,
    #[serde(default)]
    pub cpu_quota_logical_cores: StateFieldV1<u32>,
    #[serde(default)]
    pub memory_limit_bytes: StateFieldV1<u64>,
    #[serde(default)]
    pub memory_current_bytes: StateFieldV1<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct HostStateTopologyV1 {
    #[serde(default)]
    pub visible_numa_nodes: StateFieldV1<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct HostStateOperabilityV1 {
    #[serde(default)]
    pub degraded_capability_classes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Wrapper for one runtime value that keeps missing, partial, and unknown states explicit.
pub struct StateFieldV1<T> {
    pub state: ObservationStateV1,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_observation_limitation_reason_opt_v1"
    )]
    pub limitation_reason: Option<ObservationLimitationReasonV1>,
    pub value: Option<T>,
}

impl<T> Default for StateFieldV1<T> {
    fn default() -> Self {
        Self {
            state: ObservationStateV1::Unknown,
            limitation_reason: None,
            value: None,
        }
    }
}
