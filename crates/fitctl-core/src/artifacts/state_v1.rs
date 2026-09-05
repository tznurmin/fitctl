// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Schema for host runtime-state artifacts and their core resource and operability sections.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::artifacts::envelope_v1::ArtifactEnvelopeV1;
use crate::artifacts::metadata_v1::{ClaimMetadataV1, CollectorMetadataV1};
use crate::artifacts::metadata_v1::{
    LocalStableAnchorFamilyV1, LocalStableAnchorSourceV1, LocalStableIdDegradedReasonV1,
    LocalStableStabilityClassV1,
};
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_identity: Option<StateLocalIdentityV1>,
    pub core_state: HostStateCoreV1,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extension_state: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Narrow local identity metadata used by host-state correlation.
///
/// State tracks only the local identity anchor used for correlation. Composition and provenance
/// digests remain survey/contract concepts.
pub struct StateLocalIdentityV1 {
    pub local_stable_id: String,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub local_stable_id_version: u32,
    pub local_stable_anchor_family: LocalStableAnchorFamilyV1,
    pub local_stable_anchor_source: LocalStableAnchorSourceV1,
    pub local_stable_stability_class: LocalStableStabilityClassV1,
    #[serde(default)]
    pub local_stable_id_degraded: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_stable_id_degraded_reason: Option<LocalStableIdDegradedReasonV1>,
}

fn is_zero_u32(value: &u32) -> bool {
    *value == 0
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
    pub path_resources: HostStatePathResourcesV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thermal_resources: Option<HostStateThermalResourcesV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_reliability: Option<HostStateMemoryReliabilityV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_reliability: Option<HostStateGpuReliabilityV1>,
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
/// Runtime filesystem capacity observed for explicit workload paths.
pub struct HostStatePathResourcesV1 {
    #[serde(default)]
    pub paths: Vec<HostStatePathResourceV1>,
    #[serde(default)]
    pub link_pairs: Vec<HostStatePathLinkPairV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Optional platform thermal evidence collected from configured providers.
pub struct HostStateThermalResourcesV1 {
    pub observed_at: String,
    pub collector_host: HostStateThermalCollectorHostV1,
    #[serde(default)]
    pub providers: Vec<HostStateThermalProviderV1>,
    #[serde(default)]
    pub readings: Vec<HostStateThermalReadingV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
/// Host context that collected provider output.
pub struct HostStateThermalCollectorHostV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_alias: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_stable_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// One configured thermal provider invocation and its typed outcome.
pub struct HostStateThermalProviderV1 {
    pub provider_id: String,
    pub provider_kind: ThermalProviderKindV1,
    pub outcome: ThermalProviderOutcomeV1,
    pub evidence_target: HostStateThermalEvidenceTargetV1,
    pub observed_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// One normalized thermal reading from a provider.
pub struct HostStateThermalReadingV1 {
    pub sensor_id: String,
    pub sensor_role: ThermalSensorRoleV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensor_alias: Option<String>,
    pub provider_id: String,
    pub raw_label: String,
    pub temperature_millidegrees_celsius: i64,
    pub status: ThermalReadingStatusV1,
    pub observed_at: String,
    pub evidence_target: HostStateThermalEvidenceTargetV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// The host or target that provider evidence describes.
pub struct HostStateThermalEvidenceTargetV1 {
    pub target_kind: ThermalEvidenceTargetKindV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    pub collection_path: ThermalCollectionPathV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThermalEvidenceTargetKindV1 {
    CurrentHost,
    HostId,
}

impl ThermalEvidenceTargetKindV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CurrentHost => "current_host",
            Self::HostId => "host_id",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThermalCollectionPathV1 {
    LocalProcess,
    OutOfBandBmc,
    Unknown,
}

impl ThermalCollectionPathV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalProcess => "local_process",
            Self::OutOfBandBmc => "out_of_band_bmc",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThermalProviderKindV1 {
    LmSensorsJson,
    NvidiaSmiQuery,
    IpmitoolSensor,
}

impl ThermalProviderKindV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LmSensorsJson => "lm_sensors_json",
            Self::NvidiaSmiQuery => "nvidia_smi_query",
            Self::IpmitoolSensor => "ipmitool_sensor",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThermalProviderOutcomeV1 {
    Success,
    Unavailable,
    PermissionDenied,
    CommandFailed,
    Malformed,
    Partial,
}

impl ThermalProviderOutcomeV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Unavailable => "unavailable",
            Self::PermissionDenied => "permission_denied",
            Self::CommandFailed => "command_failed",
            Self::Malformed => "malformed",
            Self::Partial => "partial",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThermalSensorRoleV1 {
    Cpu,
    Gpu,
    Board,
    NetworkChip,
    StorageDrive,
    Nvme,
    Ssd,
    Inlet,
    Exhaust,
    Vrm,
    Bmc,
    Unknown,
}

impl ThermalSensorRoleV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Gpu => "gpu",
            Self::Board => "board",
            Self::NetworkChip => "network_chip",
            Self::StorageDrive => "storage_drive",
            Self::Nvme => "nvme",
            Self::Ssd => "ssd",
            Self::Inlet => "inlet",
            Self::Exhaust => "exhaust",
            Self::Vrm => "vrm",
            Self::Bmc => "bmc",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThermalReadingStatusV1 {
    Ok,
    Warning,
    Critical,
    Unavailable,
    Unknown,
}

impl ThermalReadingStatusV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warning => "warning",
            Self::Critical => "critical",
            Self::Unavailable => "unavailable",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Optional local memory-reliability evidence from safe host interfaces such as EDAC sysfs.
pub struct HostStateMemoryReliabilityV1 {
    pub observed_at: String,
    #[serde(default)]
    pub providers: Vec<HostStateMemoryReliabilityProviderV1>,
    #[serde(default)]
    pub controller_count: StateFieldV1<u32>,
    #[serde(default)]
    pub dimm_count: StateFieldV1<u32>,
    #[serde(default)]
    pub corrected_error_count: StateFieldV1<u64>,
    #[serde(default)]
    pub uncorrected_error_count: StateFieldV1<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// One memory-reliability evidence provider and its collection outcome.
pub struct HostStateMemoryReliabilityProviderV1 {
    pub provider_id: String,
    pub provider_kind: MemoryReliabilityProviderKindV1,
    pub outcome: StateEvidenceProviderOutcomeV1,
    pub observed_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryReliabilityProviderKindV1 {
    EdacSysfs,
}

impl MemoryReliabilityProviderKindV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EdacSysfs => "edac_sysfs",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Optional local GPU reliability evidence from read-only provider output.
pub struct HostStateGpuReliabilityV1 {
    pub observed_at: String,
    #[serde(default)]
    pub providers: Vec<HostStateGpuReliabilityProviderV1>,
    #[serde(default)]
    pub devices: Vec<HostStateGpuReliabilityDeviceV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// One GPU-reliability evidence provider and its collection outcome.
pub struct HostStateGpuReliabilityProviderV1 {
    pub provider_id: String,
    pub provider_kind: GpuReliabilityProviderKindV1,
    pub outcome: StateEvidenceProviderOutcomeV1,
    pub observed_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GpuReliabilityProviderKindV1 {
    NvidiaSmiXml,
}

impl GpuReliabilityProviderKindV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NvidiaSmiXml => "nvidia_smi_xml",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Per-GPU reliability state. Fields remain unknown when a read-only provider cannot expose them.
pub struct HostStateGpuReliabilityDeviceV1 {
    #[serde(default)]
    pub gpu_uuid: StateFieldV1<String>,
    #[serde(default)]
    pub product_name: StateFieldV1<String>,
    #[serde(default)]
    pub ecc_mode_current: StateFieldV1<String>,
    #[serde(default)]
    pub volatile_corrected_ecc_error_count: StateFieldV1<u64>,
    #[serde(default)]
    pub volatile_uncorrected_ecc_error_count: StateFieldV1<u64>,
    #[serde(default)]
    pub retired_pages_pending: StateFieldV1<bool>,
    #[serde(default)]
    pub row_remapper_pending: StateFieldV1<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateEvidenceProviderOutcomeV1 {
    Success,
    Unavailable,
    PermissionDenied,
    CommandFailed,
    Malformed,
    Partial,
}

impl StateEvidenceProviderOutcomeV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Unavailable => "unavailable",
            Self::PermissionDenied => "permission_denied",
            Self::CommandFailed => "command_failed",
            Self::Malformed => "malformed",
            Self::Partial => "partial",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// One path checked for state-aware storage suitability.
pub struct HostStatePathResourceV1 {
    pub path_id: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_path: Option<String>,
    #[serde(default)]
    pub canonical_path: StateFieldV1<String>,
    #[serde(default)]
    pub containing_mount_point: StateFieldV1<String>,
    #[serde(default)]
    pub filesystem_type: StateFieldV1<String>,
    #[serde(default)]
    pub mount_source: StateFieldV1<String>,
    #[serde(default)]
    pub mount_options: StateFieldV1<Vec<String>>,
    #[serde(default)]
    pub mount_device_major_minor: StateFieldV1<String>,
    #[serde(default)]
    pub filesystem_uuid: StateFieldV1<String>,
    #[serde(default)]
    pub partition_uuid: StateFieldV1<String>,
    #[serde(default)]
    pub persistent_device_links: StateFieldV1<Vec<String>>,
    #[serde(default)]
    pub storage_identity_evidence: Vec<String>,
    #[serde(default)]
    pub media_class: StateFieldV1<StateStorageMediaClassV1>,
    #[serde(default)]
    pub media_class_confidence: StateFieldV1<StateStorageMediaClassConfidenceV1>,
    #[serde(default)]
    pub media_class_evidence: Vec<String>,
    #[serde(default)]
    pub durability_class: StateFieldV1<StateStorageDurabilityClassV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<String>,
    pub exists: StateFieldV1<bool>,
    pub filesystem_available_bytes: StateFieldV1<u64>,
    pub filesystem_total_bytes: StateFieldV1<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_capabilities: Option<HostStatePathLinkCapabilitiesV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_health: Option<HostStatePathStorageHealthV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateStorageMediaClassV1 {
    Tmpfs,
    Nvme,
    Ssd,
    Hdd,
    Network,
    Unknown,
}

impl StateStorageMediaClassV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tmpfs => "tmpfs",
            Self::Nvme => "nvme",
            Self::Ssd => "ssd",
            Self::Hdd => "hdd",
            Self::Network => "network",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateStorageMediaClassConfidenceV1 {
    High,
    Medium,
    Low,
    Unknown,
}

impl StateStorageMediaClassConfidenceV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateStorageDurabilityClassV1 {
    Ephemeral,
    Durable,
    Unknown,
}

impl StateStorageDurabilityClassV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ephemeral => "ephemeral",
            Self::Durable => "durable",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
/// Optional safe link capability probes for one checked path.
pub struct HostStatePathLinkCapabilitiesV1 {
    pub hardlink_supported: StateFieldV1<bool>,
    pub reflink_supported: StateFieldV1<bool>,
    pub symlink_supported: StateFieldV1<bool>,
    pub copy_possible: StateFieldV1<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Optional best-effort health evidence for the storage backing one checked path.
pub struct HostStatePathStorageHealthV1 {
    pub health_state: StateFieldV1<StateStorageHealthStateV1>,
    pub temperature_celsius: StateFieldV1<i64>,
    pub percentage_used: StateFieldV1<u32>,
    pub available_spare_percent: StateFieldV1<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Coarse health state when a safe source reports one directly.
pub enum StateStorageHealthStateV1 {
    Ok,
    Warning,
    Critical,
    Unknown,
}

impl StateStorageHealthStateV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warning => "warning",
            Self::Critical => "critical",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Optional safe link capability probes between two checked paths.
pub struct HostStatePathLinkPairV1 {
    pub pair_id: String,
    pub from_path_id: String,
    pub to_path_id: String,
    pub same_filesystem: StateFieldV1<bool>,
    pub hardlink_supported: StateFieldV1<bool>,
    pub reflink_supported: StateFieldV1<bool>,
    pub symlink_supported: StateFieldV1<bool>,
    pub copy_possible: StateFieldV1<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
/// Per-section provenance for runtime values.
pub struct StateSectionMetadataV1 {
    #[serde(default)]
    pub resources: ClaimMetadataV1,
    #[serde(default)]
    pub path_resources: ClaimMetadataV1,
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
    pub available_cgroup_controllers: StateFieldV1<Vec<String>>,
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
