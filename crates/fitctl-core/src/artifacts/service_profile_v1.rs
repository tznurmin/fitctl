// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Schema for workload requirements consumed by validation.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::artifacts::envelope_v1::ArtifactEnvelopeV1;
use crate::artifacts::metadata_v1::{AssuranceSourceV1, DerivationStageV1};
use crate::artifacts::state_v1::{
    StateStorageDurabilityClassV1, StateStorageHealthStateV1, StateStorageMediaClassV1,
    ThermalSensorRoleV1,
};
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short_display_name: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_allocatable_cpu_logical_cores: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_allocatable_memory_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_non_loopback_interfaces: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_network_link_speed_mbps: Option<u64>,
    #[serde(default)]
    pub required_network_interface_kinds: Vec<NetworkInterfaceKindV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_numa_nodes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_numa_nodes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_cpu_packages: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_policy_scoped_accelerators: Option<u32>,
    #[serde(default)]
    pub require_accelerator_locality_known: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_accelerator_numa_nodes: Option<u32>,
    #[serde(default)]
    pub required_paths: Vec<ServicePathRequirementV1>,
    #[serde(default)]
    pub path_relationships: Vec<ServicePathRelationshipRequirementV1>,
    #[serde(default)]
    pub required_path_link_pairs: Vec<ServicePathLinkPairRequirementV1>,
    #[serde(default)]
    pub required_thermal_sensors: Vec<ServiceThermalRequirementV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_memory_reliability: Option<ServiceMemoryReliabilityRequirementV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_gpu_reliability: Option<ServiceGpuReliabilityRequirementV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Runtime path capacity required by a workload.
pub struct ServicePathRequirementV1 {
    pub path_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_available_bytes: Option<u64>,
    #[serde(default)]
    pub accepted_media_classes: Vec<StateStorageMediaClassV1>,
    #[serde(default)]
    pub accepted_durability_classes: Vec<StateStorageDurabilityClassV1>,
    #[serde(default)]
    pub required_filesystem_types: Vec<String>,
    #[serde(default)]
    pub accepted_filesystem_uuids: Vec<String>,
    #[serde(default)]
    pub accepted_partition_uuids: Vec<String>,
    #[serde(default)]
    pub accepted_persistent_device_links: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_hardlink: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_reflink: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_symlink: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_copy: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_health: Option<ServicePathStorageHealthRequirementV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
/// Optional storage-health requirements for the device backing one required path.
pub struct ServicePathStorageHealthRequirementV1 {
    #[serde(default)]
    pub accepted_health_states: Vec<StateStorageHealthStateV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_temperature_celsius: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_percentage_used: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_available_spare_percent: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Relationship requirements between two runtime path resources.
pub struct ServicePathRelationshipRequirementV1 {
    pub relationship_id: String,
    pub left_path_id: String,
    pub right_path_id: String,
    pub must_not_share: Vec<ServicePathRelationshipIdentityV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServicePathRelationshipIdentityV1 {
    FilesystemUuid,
    PartitionUuid,
    MountDeviceMajorMinor,
    ContainingMountPoint,
}

impl ServicePathRelationshipIdentityV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FilesystemUuid => "filesystem_uuid",
            Self::PartitionUuid => "partition_uuid",
            Self::MountDeviceMajorMinor => "mount_device_major_minor",
            Self::ContainingMountPoint => "containing_mount_point",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Link capability requirements between two runtime path resources.
pub struct ServicePathLinkPairRequirementV1 {
    pub pair_id: String,
    pub from_path_id: String,
    pub to_path_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_hardlink: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_reflink: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_symlink: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_copy: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Runtime thermal evidence required by a workload.
pub struct ServiceThermalRequirementV1 {
    pub requirement_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensor_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensor_alias: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensor_role: Option<ThermalSensorRoleV1>,
    pub max_temperature_millidegrees_celsius: i64,
    #[serde(default = "default_require_thermal_provider_success")]
    pub require_provider_success: bool,
}

fn default_require_thermal_provider_success() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
/// Runtime memory-reliability evidence required by a workload.
pub struct ServiceMemoryReliabilityRequirementV1 {
    #[serde(default = "default_require_reliability_provider_success")]
    pub require_provider_success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_corrected_error_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_uncorrected_error_count: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
/// Runtime GPU-reliability evidence required by a workload.
pub struct ServiceGpuReliabilityRequirementV1 {
    #[serde(default = "default_require_reliability_provider_success")]
    pub require_provider_success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_ecc_mode_current: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_volatile_corrected_ecc_error_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_volatile_uncorrected_ecc_error_count: Option<u64>,
    #[serde(default)]
    pub require_no_retired_pages_pending: bool,
    #[serde(default)]
    pub require_no_row_remapper_pending: bool,
}

fn default_require_reliability_provider_success() -> bool {
    true
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
