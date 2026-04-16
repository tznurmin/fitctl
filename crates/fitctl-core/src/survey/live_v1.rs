// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Live Linux survey collectors and conservative source-family fallbacks.
//!
//! This module gathers raw host evidence from local Linux interfaces. When platforms do not expose
//! the same source families, the collector ladder prefers explicit markers first and falls back
//! conservatively instead of inventing stronger claims.

use std::collections::BTreeMap;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

mod accelerators;
mod cpu;
mod network;

use self::accelerators::*;
use self::cpu::*;
use self::network::*;

use crate::survey::execution_context_v1::{
    deserialize_observation_limitation_reason_opt_v1, ExecutionContextV1,
    ObservationLimitationReasonV1, ObservationStateV1, PrivilegeLevelV1, VisibilityScopeV1,
};
use crate::survey::{LiveSystemProbeV1, SurveyError, SurveyErrorCode};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Wrapper around one observed survey value.
///
/// This keeps missing, partial, and unknown states explicit instead of collapsing them into a
/// plain optional value.
pub struct SurveyFieldV1<T> {
    pub state: ObservationStateV1,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_observation_limitation_reason_opt_v1"
    )]
    pub limitation_reason: Option<ObservationLimitationReasonV1>,
    pub value: Option<T>,
}

impl<T> Default for SurveyFieldV1<T> {
    fn default() -> Self {
        Self {
            state: ObservationStateV1::Unknown,
            limitation_reason: None,
            value: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
/// Explains whether cache sizes represent one visible instance or an aggregate total.
pub enum CpuCacheSummaryBasisV1 {
    #[serde(rename = "representative_instance_sizes")]
    #[default]
    RepresentativeInstanceSizes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Records how the CPU model string was obtained so fallback-derived labels stay honest.
pub enum CpuModelBasisV1 {
    DirectCpuModel,
    ArmPartLookup,
    CpuinfoLabelFallback,
}

impl CpuModelBasisV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DirectCpuModel => "direct_cpu_model",
            Self::ArmPartLookup => "arm_part_lookup",
            Self::CpuinfoLabelFallback => "cpuinfo_label_fallback",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Representative cache sizes from the source family used by the collector.
pub struct CpuCacheSummaryV1 {
    #[serde(default)]
    pub summary_basis: CpuCacheSummaryBasisV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub l1_data_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub l1_instruction_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub l2_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub l3_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// CPU inventory gathered from host-visible sources.
///
/// The section may still be partial even when the CPU itself is clearly observed.
pub struct CpuDetailsV1 {
    pub architecture: String,
    pub logical_cores: u32,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_basis: Option<CpuModelBasisV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub physical_cores: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threads_per_core: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub feature_flags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_summary: Option<CpuCacheSummaryV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryDetailsV1 {
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Coarse storage class used for structural summaries rather than detailed device modelling.
pub enum StorageBlockDeviceClassV1 {
    SolidState,
    Rotational,
    Loop,
    Ram,
    Optical,
    Other,
}

impl StorageBlockDeviceClassV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SolidState => "solid_state",
            Self::Rotational => "rotational",
            Self::Loop => "loop",
            Self::Ram => "ram",
            Self::Optical => "optical",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageBlockDeviceV1 {
    pub name: String,
    pub class: StorageBlockDeviceClassV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removable: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Simplified mount role used for inspect summaries and contract promotion.
pub enum StorageMountRoleV1 {
    Root,
    Boot,
    Home,
    Var,
    Runtime,
    Temp,
    Data,
    Other,
}

impl StorageMountRoleV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Boot => "boot",
            Self::Home => "home",
            Self::Var => "var",
            Self::Runtime => "runtime",
            Self::Temp => "temp",
            Self::Data => "data",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageMountV1 {
    pub path: String,
    pub filesystem_type: String,
    pub role: StorageMountRoleV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageDetailsV1 {
    pub block_devices: Vec<String>,
    pub mounts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub block_device_details: Vec<StorageBlockDeviceV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mount_details: Vec<StorageMountV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceleratorKindV1 {
    Gpu,
    Npu,
    Fpga,
    Other,
}

impl AcceleratorKindV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gpu => "gpu",
            Self::Npu => "npu",
            Self::Fpga => "fpga",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Where the accelerator inventory entry came from.
pub enum AcceleratorDiscoverySourceV1 {
    #[default]
    Pci,
    DrmPlatform,
}

impl AcceleratorDiscoverySourceV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pci => "pci",
            Self::DrmPlatform => "drm_platform",
        }
    }
}

fn accelerator_discovery_source_is_default(value: &AcceleratorDiscoverySourceV1) -> bool {
    *value == AcceleratorDiscoverySourceV1::Pci
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Near-static operability signal.
///
/// This is intentionally weaker than runtime readiness and is safe to promote into contracts.
pub enum StaticOperabilityV1 {
    Operable,
    NotOperable,
    Indeterminate,
}

impl StaticOperabilityV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Operable => "operable",
            Self::NotOperable => "not_operable",
            Self::Indeterminate => "indeterminate",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Survey-side static operability summary for one accelerator set.
pub struct AcceleratorOperabilityV1 {
    pub static_operability: StaticOperabilityV1,
    pub driver_bound_devices: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub visible_device_nodes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceleratorDeviceV1 {
    pub kind: AcceleratorKindV1,
    #[serde(
        default,
        skip_serializing_if = "accelerator_discovery_source_is_default"
    )]
    pub discovery_source: AcceleratorDiscoverySourceV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pci_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceleratorDetailsV1 {
    pub devices: Vec<AcceleratorDeviceV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operability: Option<AcceleratorOperabilityV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Network classification keeps physical kind separate from virtuality so real NICs, bridges,
/// tunnels, and veth pairs do not collapse into one bucket.
pub enum NetworkInterfaceKindV1 {
    Loopback,
    Ethernet,
    Wireless,
    Bridge,
    Tunnel,
    Veth,
    Other,
}

impl NetworkInterfaceKindV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Ethernet => "ethernet",
            Self::Wireless => "wireless",
            Self::Bridge => "bridge",
            Self::Tunnel => "tunnel",
            Self::Veth => "veth",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Whether an interface appears to be backed by real hardware or by a virtual network layer.
pub enum NetworkInterfaceVirtualityV1 {
    Physical,
    Virtual,
    #[default]
    Indeterminate,
}

impl NetworkInterfaceVirtualityV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Physical => "physical",
            Self::Virtual => "virtual",
            Self::Indeterminate => "indeterminate",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkLinkStateV1 {
    Up,
    Down,
    Dormant,
    Unknown,
}

impl NetworkLinkStateV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Down => "down",
            Self::Dormant => "dormant",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkCarrierStateV1 {
    Up,
    Down,
    #[default]
    Unknown,
}

impl NetworkCarrierStateV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Down => "down",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkDuplexV1 {
    Full,
    Half,
    #[default]
    Unknown,
}

impl NetworkDuplexV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Half => "half",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// One interface-level snapshot used to build the higher-level network summaries.
pub struct NetworkInterfaceV1 {
    pub name: String,
    pub interface_kind: NetworkInterfaceKindV1,
    #[serde(default)]
    pub interface_virtuality: NetworkInterfaceVirtualityV1,
    pub link_state: NetworkLinkStateV1,
    #[serde(default)]
    pub carrier_state: NetworkCarrierStateV1,
    #[serde(default)]
    pub duplex: NetworkDuplexV1,
    #[serde(default)]
    pub mtu: Option<u32>,
    #[serde(default)]
    pub speed_mbps: Option<u64>,
    #[serde(default)]
    pub mac_address: Option<String>,
    #[serde(default)]
    pub addresses: Vec<NetworkAddressV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
/// Coarse addressability view kept separate from the raw address list.
pub struct NetworkAddressabilitySummaryV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub non_loopback_address_families: Option<Vec<IpAddressFamilyV1>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_route_families: Option<Vec<IpAddressFamilyV1>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Full survey-side network inventory before contract derivation compresses it into summaries.
pub struct NetworkDetailsV1 {
    pub interfaces: Vec<String>,
    #[serde(default)]
    pub interface_details: Vec<NetworkInterfaceV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addressability_summary: Option<NetworkAddressabilitySummaryV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpAddressFamilyV1 {
    Ipv4,
    Ipv6,
}

impl IpAddressFamilyV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkAddressV1 {
    pub family: IpAddressFamilyV1,
    pub address: String,
    pub prefix_len: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyDetailsV1 {
    pub numa_nodes: u32,
    pub cpu_packages: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurveyObservationsV1 {
    pub hostname: SurveyFieldV1<String>,
    pub cpu: SurveyFieldV1<CpuDetailsV1>,
    pub memory: SurveyFieldV1<MemoryDetailsV1>,
    pub storage: SurveyFieldV1<StorageDetailsV1>,
    pub network: SurveyFieldV1<NetworkDetailsV1>,
    #[serde(default)]
    pub accelerators: SurveyFieldV1<AcceleratorDetailsV1>,
    #[serde(default)]
    pub topology: SurveyFieldV1<TopologyDetailsV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotSourceKindV1 {
    Live,
    Replay { corpus_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Full raw snapshot gathered by the live collectors before normalisation into a survey artifact.
pub struct CollectedHostSnapshotV1 {
    pub source_kind: SnapshotSourceKindV1,
    pub provenance_source: String,
    pub snapshot_id: String,
    pub collected_at: String,
    pub host_alias: String,
    pub execution_context: ExecutionContextV1,
    pub collectors: Vec<String>,
    pub observations: SurveyObservationsV1,
}

pub struct LocalLiveProbeV1;

pub struct NoopLiveProbeV1;

struct NetworkCollectionV1 {
    field: SurveyFieldV1<NetworkDetailsV1>,
    collectors: Vec<String>,
}

impl LiveSystemProbeV1 for NoopLiveProbeV1 {
    fn collect_snapshot(&self) -> Result<CollectedHostSnapshotV1, SurveyError> {
        Err(SurveyError::new(
            SurveyErrorCode::CollectorSourceUnavailable,
            "survey_source_probe",
            "no live probe is configured",
        ))
    }
}

impl LiveSystemProbeV1 for LocalLiveProbeV1 {
    fn collect_snapshot(&self) -> Result<CollectedHostSnapshotV1, SurveyError> {
        // Collect raw host evidence first and leave the typed artifact assembly to the
        // normalization layer. That keeps live probing and schema shaping decoupled.
        let execution_context = detect_execution_context();
        let hostname = read_hostname();
        let host_alias = hostname
            .value
            .clone()
            .unwrap_or_else(|| "localhost".to_string());
        let network_collection = read_network();
        let mut collectors = vec![
            "procfs".to_string(),
            "cpuinfo_flags".to_string(),
            "sysfs".to_string(),
            "sysfs_cpu_topology".to_string(),
            "sysfs_cpu_cache".to_string(),
            "cgroupfs".to_string(),
            "mountinfo".to_string(),
            "block_and_filesystem".to_string(),
            "pci_accelerators".to_string(),
            "pci_driver_binding".to_string(),
            "drm_class".to_string(),
            "drm_platform_graphics".to_string(),
            "devfs_accelerator_nodes".to_string(),
        ];
        collectors.extend(network_collection.collectors);

        Ok(CollectedHostSnapshotV1 {
            source_kind: SnapshotSourceKindV1::Live,
            provenance_source: "live:linux_core_v1".to_string(),
            snapshot_id: host_alias.clone(),
            collected_at: current_epoch_marker(),
            host_alias,
            execution_context,
            collectors,
            observations: SurveyObservationsV1 {
                hostname,
                cpu: read_cpu(),
                memory: read_memory(),
                storage: read_storage(),
                network: network_collection.field,
                accelerators: read_accelerators(),
                topology: read_topology(),
            },
        })
    }
}

fn detect_execution_context() -> ExecutionContextV1 {
    // Gather all low-level platform hints first, then resolve the execution context in one place.
    // That keeps the fallback ladder explicit and testable.
    let cgroup_text = fs::read_to_string("/proc/1/cgroup")
        .or_else(|_| fs::read_to_string("/proc/self/cgroup"))
        .unwrap_or_default();
    let dmi_product_name = read_trimmed("/sys/class/dmi/id/product_name");
    let device_tree_model = read_trimmed_lossy("/sys/firmware/devicetree/base/model")
        .or_else(|| read_trimmed_lossy("/proc/device-tree/model"));
    let (visibility_scope, container_runtime, mut notes) = infer_execution_context(
        &cgroup_text,
        dmi_product_name.as_deref(),
        device_tree_model.as_deref(),
        Path::new("/.dockerenv").exists(),
    );

    if cgroup_text.is_empty() {
        notes.push("cgroup evidence unavailable".to_string());
    }

    ExecutionContextV1 {
        visibility_scope,
        privilege_level: detect_privilege_level(),
        container_runtime,
        notes,
    }
}

fn detect_container_runtime(cgroup_text: &str) -> Option<String> {
    if cgroup_text.contains("docker") || Path::new("/.dockerenv").exists() {
        Some("docker".to_string())
    } else if cgroup_text.contains("kubepods") {
        Some("kubernetes".to_string())
    } else if cgroup_text.contains("containerd") {
        Some("containerd".to_string())
    } else if cgroup_text.contains("podman") {
        Some("podman".to_string())
    } else {
        None
    }
}

fn infer_execution_context(
    cgroup_text: &str,
    dmi_product_name: Option<&str>,
    device_tree_model: Option<&str>,
    has_dockerenv: bool,
) -> (VisibilityScopeV1, Option<String>, Vec<String>) {
    // Resolve from the strongest platform markers downward: explicit container evidence wins,
    // then virtual-machine markers, then bare-metal platform hints, and only then unknown.
    if has_dockerenv {
        return (
            VisibilityScopeV1::ContainerRestricted,
            Some("docker".to_string()),
            vec!["container marker file detected".to_string()],
        );
    }

    if contains_any(cgroup_text, &["docker", "kubepods", "containerd", "podman"]) {
        return (
            VisibilityScopeV1::ContainerRestricted,
            detect_container_runtime(cgroup_text),
            vec!["cgroup runtime marker detected".to_string()],
        );
    }

    if let Some(product_name) = dmi_product_name {
        if looks_like_vm(product_name) {
            return (
                VisibilityScopeV1::VmLike,
                None,
                vec!["virtual-machine product name detected".to_string()],
            );
        }

        return (VisibilityScopeV1::BareMetalLike, None, Vec::new());
    }

    if device_tree_model.is_some() {
        return (
            VisibilityScopeV1::BareMetalLike,
            None,
            vec!["device-tree platform model detected".to_string()],
        );
    }

    (
        VisibilityScopeV1::Unknown,
        None,
        vec!["execution context inferred conservatively".to_string()],
    )
}

fn looks_like_vm(product_name: &str) -> bool {
    contains_any(
        product_name,
        &[
            "kvm",
            "qemu",
            "virtualbox",
            "vmware",
            "virtual machine",
            "hyper-v",
        ],
    )
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    let haystack = haystack.to_ascii_lowercase();
    needles
        .iter()
        .any(|needle| haystack.contains(&needle.to_ascii_lowercase()))
}

fn detect_privilege_level() -> PrivilegeLevelV1 {
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            let uid = rest.split_whitespace().next().unwrap_or_default();
            return if uid == "0" {
                PrivilegeLevelV1::Full
            } else {
                PrivilegeLevelV1::Limited
            };
        }
    }

    PrivilegeLevelV1::Limited
}

fn read_hostname() -> SurveyFieldV1<String> {
    match read_trimmed("/proc/sys/kernel/hostname").or_else(|| read_trimmed("/etc/hostname")) {
        Some(hostname) if !hostname.is_empty() => observed(hostname),
        _ => unknown(),
    }
}

fn read_memory() -> SurveyFieldV1<MemoryDetailsV1> {
    let meminfo = match fs::read_to_string("/proc/meminfo") {
        Ok(text) => text,
        Err(_) => return unknown(),
    };

    let total_bytes = meminfo.lines().find_map(|line| {
        let value = line.strip_prefix("MemTotal:")?.trim();
        let kib = value.split_whitespace().next()?.parse::<u64>().ok()?;
        Some(kib * 1024)
    });

    match total_bytes {
        Some(total_bytes) if total_bytes > 0 => observed(MemoryDetailsV1 { total_bytes }),
        _ => unknown(),
    }
}

fn read_storage() -> SurveyFieldV1<StorageDetailsV1> {
    // Storage remains Ring-1 inventory evidence here: block-device classes, mounts, and
    // filesystem types. Capacity, performance, and health belong to later layers.
    let mount_details = fs::read_to_string("/proc/self/mountinfo")
        .ok()
        .map(parse_mount_details)
        .unwrap_or_default();
    let block_device_details = fs::read_dir("/sys/block")
        .ok()
        .map(read_block_device_details)
        .unwrap_or_default();
    let mounts = mount_details
        .iter()
        .map(|detail| detail.path.clone())
        .collect::<Vec<_>>();
    let block_devices = block_device_details
        .iter()
        .map(|detail| detail.name.clone())
        .collect::<Vec<_>>();

    if mounts.is_empty() && block_devices.is_empty() {
        return unknown();
    }

    let state = if mounts.is_empty() || block_devices.is_empty() {
        ObservationStateV1::PartiallyObserved
    } else {
        ObservationStateV1::Observed
    };

    let mut details = StorageDetailsV1 {
        block_devices,
        mounts,
        block_device_details,
        mount_details,
    };
    details.block_devices.sort();
    details.block_devices.dedup();
    details.mounts.sort();
    details.mounts.dedup();
    details
        .block_device_details
        .sort_by(|left, right| left.name.cmp(&right.name));
    details
        .mount_details
        .sort_by(|left, right| left.path.cmp(&right.path));

    let limitation_reason = matches!(state, ObservationStateV1::PartiallyObserved)
        .then_some(ObservationLimitationReasonV1::CollectorLimitation);

    SurveyFieldV1 {
        state,
        limitation_reason,
        value: Some(details),
    }
}

fn read_topology() -> SurveyFieldV1<TopologyDetailsV1> {
    // Topology falls back conservatively when only one side is visible. That keeps common
    // single-node, single-package hosts useful without presenting missing counters as strong fact.
    let numa_nodes = read_numa_node_count();
    let cpu_packages = read_cpu_package_count();

    match (numa_nodes, cpu_packages) {
        (Some(numa_nodes), Some(cpu_packages)) if numa_nodes > 0 && cpu_packages > 0 => {
            observed(TopologyDetailsV1 {
                numa_nodes,
                cpu_packages,
            })
        }
        (Some(numa_nodes), None) if numa_nodes > 0 => SurveyFieldV1 {
            state: ObservationStateV1::PartiallyObserved,
            limitation_reason: Some(ObservationLimitationReasonV1::CollectorLimitation),
            value: Some(TopologyDetailsV1 {
                numa_nodes,
                cpu_packages: 1,
            }),
        },
        (None, Some(cpu_packages)) if cpu_packages > 0 => SurveyFieldV1 {
            state: ObservationStateV1::PartiallyObserved,
            limitation_reason: Some(ObservationLimitationReasonV1::CollectorLimitation),
            value: Some(TopologyDetailsV1 {
                numa_nodes: 1,
                cpu_packages,
            }),
        },
        _ => unknown(),
    }
}

fn read_numa_node_count() -> Option<u32> {
    let mut count = fs::read_dir("/sys/devices/system/node")
        .ok()?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.starts_with("node"))
        .count() as u32;

    if count == 0 {
        count = read_trimmed("/sys/devices/system/node/online")
            .and_then(parse_cpu_range_count)
            .unwrap_or(0);
    }

    (count > 0).then_some(count)
}

fn read_cpu_package_count() -> Option<u32> {
    let entries = fs::read_dir("/sys/devices/system/cpu").ok()?;
    let mut package_ids = std::collections::BTreeSet::new();

    for entry in entries.filter_map(|entry| entry.ok()) {
        let name = entry.file_name().into_string().ok()?;
        if !name.starts_with("cpu")
            || !name[3..]
                .chars()
                .all(|character| character.is_ascii_digit())
        {
            continue;
        }
        let package_path = entry.path().join("topology/physical_package_id");
        if let Some(package_id) = read_trimmed(package_path.to_str()?) {
            package_ids.insert(package_id);
        }
    }

    if package_ids.is_empty() {
        Some(1)
    } else {
        Some(u32::try_from(package_ids.len()).ok()?)
    }
}

fn parse_cpu_range_count(value: String) -> Option<u32> {
    let mut count = 0_u32;
    for segment in value.split(',') {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        if let Some((start, end)) = segment.split_once('-') {
            let start = start.parse::<u32>().ok()?;
            let end = end.parse::<u32>().ok()?;
            count = count.checked_add(end.checked_sub(start)?.checked_add(1)?)?;
        } else {
            let _ = segment.parse::<u32>().ok()?;
            count = count.checked_add(1)?;
        }
    }

    (count > 0).then_some(count)
}

fn read_block_device_details(entries: fs::ReadDir) -> Vec<StorageBlockDeviceV1> {
    // Device names are the stable join key for the storage baseline, so sort and dedup before the
    // survey artifact is emitted.
    let mut devices = entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .map(|name| StorageBlockDeviceV1 {
            removable: read_storage_bool(format!("/sys/block/{name}/removable")),
            class: classify_block_device(&name),
            name,
        })
        .collect::<Vec<_>>();
    devices.sort_by(|left, right| left.name.cmp(&right.name));
    devices.dedup_by(|left, right| left.name == right.name);
    devices
}

fn classify_block_device(name: &str) -> StorageBlockDeviceClassV1 {
    if name.starts_with("loop") {
        return StorageBlockDeviceClassV1::Loop;
    }
    if name.starts_with("ram") || name.starts_with("zram") {
        return StorageBlockDeviceClassV1::Ram;
    }
    if name.starts_with("sr") {
        return StorageBlockDeviceClassV1::Optical;
    }
    if name.starts_with("nvme") || name.starts_with("mmcblk") {
        return StorageBlockDeviceClassV1::SolidState;
    }

    match read_storage_bool(format!("/sys/block/{name}/queue/rotational")) {
        Some(true) => StorageBlockDeviceClassV1::Rotational,
        Some(false) => StorageBlockDeviceClassV1::SolidState,
        None => StorageBlockDeviceClassV1::Other,
    }
}

fn read_storage_bool(path: String) -> Option<bool> {
    match read_trimmed(&path) {
        Some(value) if value == "0" => Some(false),
        Some(value) if value == "1" => Some(true),
        _ => None,
    }
}

fn parse_mount_details(mountinfo: String) -> Vec<StorageMountV1> {
    // Keep only the fields needed by the baseline storage model: mount path, filesystem type, and
    // a coarse role classification derived from the path.
    let mut mounts = Vec::new();

    for line in mountinfo.lines() {
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        let left_parts = left.split_whitespace().collect::<Vec<_>>();
        let right_parts = right.split_whitespace().collect::<Vec<_>>();
        if left_parts.len() < 5 || right_parts.is_empty() {
            continue;
        }

        let path = left_parts[4].to_string();
        mounts.push(StorageMountV1 {
            filesystem_type: right_parts[0].to_string(),
            role: classify_storage_mount_role(&path),
            path,
        });
    }

    mounts.sort_by(|left, right| left.path.cmp(&right.path));
    mounts.dedup_by(|left, right| left.path == right.path);
    mounts
}

fn classify_storage_mount_role(path: &str) -> StorageMountRoleV1 {
    if path == "/" {
        StorageMountRoleV1::Root
    } else if path == "/boot" || path == "/boot/efi" || path.starts_with("/boot/") {
        StorageMountRoleV1::Boot
    } else if path == "/home" || path.starts_with("/home/") {
        StorageMountRoleV1::Home
    } else if path == "/var" || path.starts_with("/var/") {
        StorageMountRoleV1::Var
    } else if path == "/run" || path.starts_with("/run/") {
        StorageMountRoleV1::Runtime
    } else if path == "/tmp" || path.starts_with("/tmp/") {
        StorageMountRoleV1::Temp
    } else if path == "/mnt"
        || path.starts_with("/mnt/")
        || path == "/media"
        || path.starts_with("/media/")
        || path == "/srv"
        || path.starts_with("/srv/")
        || path == "/data"
        || path.starts_with("/data/")
        || path == "/opt"
        || path.starts_with("/opt/")
    {
        StorageMountRoleV1::Data
    } else {
        StorageMountRoleV1::Other
    }
}

fn read_trimmed(path: &str) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn read_trimmed_lossy(path: &str) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    let trimmed = text.split('\0').next().unwrap_or_default().trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn current_epoch_marker() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("unix:{seconds}")
}

fn observed<T>(value: T) -> SurveyFieldV1<T> {
    SurveyFieldV1 {
        state: ObservationStateV1::Observed,
        limitation_reason: None,
        value: Some(value),
    }
}

fn unknown<T>() -> SurveyFieldV1<T> {
    SurveyFieldV1 {
        state: ObservationStateV1::Unknown,
        limitation_reason: None,
        value: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_cpu_model_uses_arm_implementer_and_part_fallback() {
        let cpuinfo = r#"processor   : 0
Features    : fp asimd evtstrm crc32 cpuid
CPU implementer : 0x41
CPU architecture: 8
CPU variant : 0x0
CPU part    : 0xd08
CPU revision    : 3

Model       : Raspberry Pi 4 Model B Rev 1.4
"#;

        assert_eq!(
            read_cpu_model(cpuinfo),
            Some(("Arm Cortex-A72".to_string(), CpuModelBasisV1::ArmPartLookup))
        );
    }

    #[test]
    fn test_read_cpu_model_falls_back_to_board_model_when_needed() {
        let cpuinfo = r#"processor   : 0
Features    : fp asimd

Model       : Example ARM SBC
"#;

        assert_eq!(
            read_cpu_model(cpuinfo),
            Some((
                "Example ARM SBC".to_string(),
                CpuModelBasisV1::CpuinfoLabelFallback
            ))
        );
    }

    #[test]
    fn test_read_cpu_model_uses_direct_model_name_when_present() {
        let cpuinfo = r#"processor   : 0
model name  : Intel(R) Core(TM) i7-9700 CPU @ 3.00GHz
"#;

        assert_eq!(
            read_cpu_model(cpuinfo),
            Some((
                "Intel(R) Core(TM) i7-9700 CPU @ 3.00GHz".to_string(),
                CpuModelBasisV1::DirectCpuModel
            ))
        );
    }

    #[test]
    fn test_infer_execution_context_uses_device_tree_bare_metal_fallback() {
        let (scope, runtime, notes) =
            infer_execution_context("", None, Some("Raspberry Pi 4 Model B Rev 1.4"), false);

        assert_eq!(scope, VisibilityScopeV1::BareMetalLike);
        assert_eq!(runtime, None);
        assert!(notes.contains(&"device-tree platform model detected".to_string()));
    }

    #[test]
    fn test_infer_execution_context_remains_unknown_without_markers() {
        let (scope, runtime, notes) = infer_execution_context("", None, None, false);

        assert_eq!(scope, VisibilityScopeV1::Unknown);
        assert_eq!(runtime, None);
        assert!(notes.contains(&"execution context inferred conservatively".to_string()));
    }
}
