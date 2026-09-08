// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use std::ffi::CString;
use std::fs;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
#[cfg(test)]
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::artifacts::categorical_values_v1::{
    EDAC_SYSFS_NO_CONTROLLERS, EDAC_SYSFS_PARTIAL, EDAC_SYSFS_READ_FAILED, EDAC_SYSFS_UNAVAILABLE,
    NVIDIA_SMI_COMMAND_FAILED, NVIDIA_SMI_NO_DEVICES, NVIDIA_SMI_UNAVAILABLE,
    NVIDIA_SMI_XML_MALFORMED,
};
use crate::artifacts::state_v1::{
    FreshnessStateV1, GpuReliabilityProviderKindV1, HostRuntimeResourcesV1,
    HostStateExecutionBoundariesV1, HostStateGpuReliabilityDeviceV1,
    HostStateGpuReliabilityProviderV1, HostStateGpuReliabilityV1,
    HostStateMemoryReliabilityProviderV1, HostStateMemoryReliabilityV1, HostStateOperabilityV1,
    HostStatePathResourceV1, HostStatePathResourcesV1, HostStatePathStorageHealthV1,
    HostStateThermalCollectorHostV1, HostStateThermalResourcesV1, HostStateTopologyV1,
    MemoryReliabilityProviderKindV1, StateEvidenceProviderOutcomeV1, StateFieldV1,
    StateFreshnessV1, StateStorageDurabilityClassV1, StateStorageMediaClassConfidenceV1,
    StateStorageMediaClassV1,
};
use crate::identity::{select_live_linux_identity_input_v2, LocalStableIdentityInputV2};
use crate::state::thermal_v1::ThermalProviderConfigEntryV1;
use crate::state::{LiveStateProbeV1, StateError, StateErrorCode};
use crate::survey::{ObservationLimitationReasonV1, ObservationStateV1};

#[path = "path_link_probe_v1.rs"]
mod path_link_probe_v1;
use path_link_probe_v1::{probe_path_link_capabilities, probe_path_link_pair_capabilities};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotSourceKindV1 {
    Live,
    Replay { corpus_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectedHostStateSnapshotV1 {
    pub source_kind: SnapshotSourceKindV1,
    pub provenance_source: String,
    pub snapshot_id: String,
    pub collected_at: String,
    pub host_alias: String,
    pub local_stable_identity_input: Option<LocalStableIdentityInputV2>,
    pub collectors: Vec<String>,
    pub freshness: StateFreshnessV1,
    pub resources: HostRuntimeResourcesV1,
    pub path_resources: HostStatePathResourcesV1,
    pub thermal_resources: Option<HostStateThermalResourcesV1>,
    pub hardware_sensor_resources:
        Option<crate::artifacts::hardware_sensor_resources_v1::HardwareSensorResourcesV1>,
    pub memory_reliability: Option<HostStateMemoryReliabilityV1>,
    pub gpu_reliability: Option<HostStateGpuReliabilityV1>,
    pub boundaries: HostStateExecutionBoundariesV1,
    pub topology: HostStateTopologyV1,
    pub operability: HostStateOperabilityV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatePathCheckRequestV1 {
    pub path_id: String,
    pub path: PathBuf,
    pub probe_links: bool,
    pub probe_health: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatePathLinkPairProbeRequestV1 {
    pub from_path_id: String,
    pub to_path_id: String,
}

#[derive(Debug, Clone, Default)]
pub struct LocalLiveStateProbeV1 {
    path_checks: Vec<StatePathCheckRequestV1>,
    path_link_pair_probes: Vec<StatePathLinkPairProbeRequestV1>,
    thermal_provider_configs: Vec<ThermalProviderConfigEntryV1>,
    collect_memory_reliability: bool,
    collect_gpu_reliability: bool,
    collect_hardware_sensors: bool,
}

impl LocalLiveStateProbeV1 {
    pub fn new(path_checks: Vec<StatePathCheckRequestV1>) -> Self {
        Self {
            path_checks,
            path_link_pair_probes: Vec::new(),
            thermal_provider_configs: Vec::new(),
            collect_memory_reliability: false,
            collect_gpu_reliability: false,
            collect_hardware_sensors: false,
        }
    }

    pub fn new_with_path_link_pairs(
        path_checks: Vec<StatePathCheckRequestV1>,
        path_link_pair_probes: Vec<StatePathLinkPairProbeRequestV1>,
    ) -> Self {
        Self {
            path_checks,
            path_link_pair_probes,
            thermal_provider_configs: Vec::new(),
            collect_memory_reliability: false,
            collect_gpu_reliability: false,
            collect_hardware_sensors: false,
        }
    }

    pub fn new_with_path_link_pairs_and_thermal_providers(
        path_checks: Vec<StatePathCheckRequestV1>,
        path_link_pair_probes: Vec<StatePathLinkPairProbeRequestV1>,
        thermal_provider_configs: Vec<ThermalProviderConfigEntryV1>,
    ) -> Self {
        Self {
            path_checks,
            path_link_pair_probes,
            thermal_provider_configs,
            collect_memory_reliability: false,
            collect_gpu_reliability: false,
            collect_hardware_sensors: false,
        }
    }

    pub fn with_memory_reliability_collection(mut self, enabled: bool) -> Self {
        self.collect_memory_reliability = enabled;
        self
    }

    pub fn with_gpu_reliability_collection(mut self, enabled: bool) -> Self {
        self.collect_gpu_reliability = enabled;
        self
    }

    pub fn with_hardware_sensor_collection(mut self, enabled: bool) -> Self {
        self.collect_hardware_sensors = enabled;
        self
    }
}

pub struct NoopLiveStateProbeV1;

impl LiveStateProbeV1 for NoopLiveStateProbeV1 {
    fn collect_snapshot(&self) -> Result<CollectedHostStateSnapshotV1, StateError> {
        Err(StateError::new(
            StateErrorCode::StateSourceUnavailable,
            "state_source_probe",
            "no live state probe is configured",
        ))
    }
}

impl LiveStateProbeV1 for LocalLiveStateProbeV1 {
    fn collect_snapshot(&self) -> Result<CollectedHostStateSnapshotV1, StateError> {
        let collected_at = current_epoch_marker();
        let host_alias = read_hostname().unwrap_or_else(|| "localhost".to_string());
        let live_identity = select_live_linux_identity_input_v2(
            read_trimmed("/etc/machine-id").as_deref(),
            read_trimmed("/var/lib/dbus/machine-id").as_deref(),
            read_trimmed("/sys/class/dmi/id/product_uuid").as_deref(),
            read_kernel_hostname_for_identity_v2().as_deref(),
        );
        let meminfo = read_meminfo_counters();
        let boundaries = read_execution_boundaries();

        // Runtime resources are bounded by both what the process can currently see and what cgroup
        // limits declare, so downstream validation reasons about deployable headroom rather than
        // raw host totals alone.
        let process_visible_cpu_logical_cores = std::thread::available_parallelism()
            .ok()
            .and_then(|value| u32::try_from(value.get()).ok())
            .filter(|value| *value > 0)
            .unwrap_or_default();
        let allocatable_cpu_logical_cores = observed_or_unknown(bound_cpu_capacity(
            process_visible_cpu_logical_cores,
            boundary_value(&boundaries.cpuset_cpu_logical_cores),
            boundary_value(&boundaries.cpu_quota_logical_cores),
        ));
        let memory_total_bytes = meminfo
            .as_ref()
            .and_then(|counters| positive_u64_field(counters.total_bytes))
            .map(observed)
            .unwrap_or_else(unknown);
        let host_available_bytes = meminfo
            .as_ref()
            .and_then(|counters| positive_u64_field(counters.available_bytes));
        let bounded_available_bytes = bound_allocatable_memory_bytes(
            host_available_bytes,
            boundary_value(&boundaries.memory_limit_bytes),
            non_negative_boundary_value(&boundaries.memory_current_bytes),
        );
        let allocatable_memory_bytes = meminfo
            .as_ref()
            .and(bounded_available_bytes)
            .map(observed)
            .unwrap_or_else(unknown);
        let memory_used_excluding_cache_bytes = meminfo
            .as_ref()
            .and_then(MeminfoCountersV1::used_excluding_cache_bytes)
            .filter(|value| *value > 0)
            .map(observed)
            .unwrap_or_else(unknown);

        let path_resources = collect_path_resources(&self.path_checks, &self.path_link_pair_probes);
        let (thermal_resources, hardware_sensor_resources) =
            super::local_sensor_capture_v1::collect(
                &self.thermal_provider_configs,
                self.collect_hardware_sensors,
                &collected_at,
                thermal_collector_host(&host_alias, Some(&live_identity.input)),
            );
        let memory_reliability = self
            .collect_memory_reliability
            .then(|| collect_memory_reliability(&collected_at));
        let gpu_reliability = self
            .collect_gpu_reliability
            .then(|| collect_gpu_reliability(&collected_at));
        let mut collectors = vec![
            "runtime_cpu_capacity".to_string(),
            "procfs_meminfo".to_string(),
            "cgroupfs_cpuset".to_string(),
            "cgroupfs_cpu_quota".to_string(),
            "cgroupfs_memory_boundary".to_string(),
            "sysfs_topology".to_string(),
        ];
        if !path_resources.paths.is_empty() {
            collectors.push("statvfs_path_capacity".to_string());
            collectors.push("mountinfo_path_storage".to_string());
            collectors.push("sysfs_block_media".to_string());
        }
        if path_resources
            .paths
            .iter()
            .any(|path| path.link_capabilities.is_some())
            || !path_resources.link_pairs.is_empty()
        {
            collectors.push("path_link_probe".to_string());
        }
        if path_resources
            .paths
            .iter()
            .any(|path| path.storage_health.is_some())
        {
            collectors.push("path_storage_health_probe".to_string());
        }
        if thermal_resources.is_some() {
            collectors.push("thermal_provider".to_string());
        }
        if hardware_sensor_resources.is_some() {
            collectors.push("hardware_sensor_provider".to_owned());
        }
        if memory_reliability.is_some() {
            collectors.push("edac_memory_reliability".to_string());
        }
        if gpu_reliability.is_some() {
            collectors.push("nvidia_smi_gpu_reliability".to_string());
        }

        Ok(CollectedHostStateSnapshotV1 {
            source_kind: SnapshotSourceKindV1::Live,
            provenance_source: "live:linux_runtime_v1".to_string(),
            snapshot_id: host_alias.clone(),
            collected_at: collected_at.clone(),
            host_alias,
            local_stable_identity_input: Some(live_identity.input),
            collectors,
            freshness: StateFreshnessV1 {
                observed_at: collected_at,
                freshness_state: FreshnessStateV1::Fresh,
            },
            resources: HostRuntimeResourcesV1 {
                allocatable_cpu_logical_cores,
                memory_total_bytes,
                allocatable_memory_bytes,
                memory_used_excluding_cache_bytes,
            },
            path_resources,
            thermal_resources,
            hardware_sensor_resources,
            memory_reliability,
            gpu_reliability,
            boundaries,
            topology: HostStateTopologyV1 {
                visible_numa_nodes: read_visible_numa_nodes(),
            },
            operability: HostStateOperabilityV1 {
                degraded_capability_classes: Vec::new(),
            },
        })
    }
}

fn thermal_collector_host(
    host_alias: &str,
    identity: Option<&LocalStableIdentityInputV2>,
) -> HostStateThermalCollectorHostV1 {
    HostStateThermalCollectorHostV1 {
        host_alias: Some(host_alias.to_string()),
        local_stable_id: identity
            .map(LocalStableIdentityInputV2::derive_state_local_identity)
            .map(|identity| identity.local_stable_id),
    }
}

fn collect_memory_reliability(observed_at: &str) -> HostStateMemoryReliabilityV1 {
    collect_memory_reliability_from_edac_root(Path::new("/sys/devices/system/edac/mc"), observed_at)
}

fn collect_memory_reliability_from_edac_root(
    edac_root: &Path,
    observed_at: &str,
) -> HostStateMemoryReliabilityV1 {
    let mut result = HostStateMemoryReliabilityV1 {
        observed_at: observed_at.to_string(),
        providers: vec![HostStateMemoryReliabilityProviderV1 {
            provider_id: "local-edac-sysfs".to_string(),
            provider_kind: MemoryReliabilityProviderKindV1::EdacSysfs,
            outcome: StateEvidenceProviderOutcomeV1::Unavailable,
            observed_at: observed_at.to_string(),
            source: Some(edac_root.to_string_lossy().to_string()),
            error_code: Some(EDAC_SYSFS_UNAVAILABLE.to_string()),
            diagnostics: Some("EDAC sysfs root is not available".to_string()),
        }],
        controller_count: unknown(),
        dimm_count: unknown(),
        corrected_error_count: unknown(),
        uncorrected_error_count: unknown(),
    };

    if !edac_root.exists() {
        return result;
    }
    let entries = match fs::read_dir(edac_root) {
        Ok(entries) => entries,
        Err(error) => {
            let outcome = if error.kind() == std::io::ErrorKind::PermissionDenied {
                StateEvidenceProviderOutcomeV1::PermissionDenied
            } else {
                StateEvidenceProviderOutcomeV1::CommandFailed
            };
            result.providers[0].outcome = outcome;
            result.providers[0].error_code = Some(EDAC_SYSFS_READ_FAILED.to_string());
            result.providers[0].diagnostics = Some(format!("failed to read EDAC sysfs: {error}"));
            return result;
        }
    };

    let mut controllers = entries
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("mc"))
        })
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    controllers.sort();
    if controllers.is_empty() {
        result.providers[0].outcome = StateEvidenceProviderOutcomeV1::Partial;
        result.providers[0].error_code = Some(EDAC_SYSFS_NO_CONTROLLERS.to_string());
        result.providers[0].diagnostics =
            Some("EDAC sysfs root contained no memory controllers".to_string());
        result.controller_count = observed(0);
        result.dimm_count = observed(0);
        result.corrected_error_count = observed(0);
        result.uncorrected_error_count = observed(0);
        return result;
    }

    let mut dimm_count = 0_u32;
    let mut corrected = 0_u64;
    let mut uncorrected = 0_u64;
    let mut malformed = false;
    for controller in &controllers {
        dimm_count = dimm_count.saturating_add(count_controller_dimms(controller));
        match read_edac_counter(controller.join("ce_count")) {
            Some(value) => corrected = corrected.saturating_add(value),
            None => malformed = true,
        }
        match read_edac_counter(controller.join("ue_count")) {
            Some(value) => uncorrected = uncorrected.saturating_add(value),
            None => malformed = true,
        }
    }

    result.providers[0].outcome = if malformed {
        StateEvidenceProviderOutcomeV1::Partial
    } else {
        StateEvidenceProviderOutcomeV1::Success
    };
    result.providers[0].error_code = malformed.then(|| EDAC_SYSFS_PARTIAL.to_string());
    result.providers[0].diagnostics =
        malformed.then(|| "one or more EDAC counters were missing or malformed".to_string());
    result.controller_count = observed(u32::try_from(controllers.len()).unwrap_or(u32::MAX));
    result.dimm_count = observed(dimm_count);
    result.corrected_error_count = observed(corrected);
    result.uncorrected_error_count = observed(uncorrected);
    result
}

fn count_controller_dimms(controller: &Path) -> u32 {
    fs::read_dir(controller)
        .ok()
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| name.starts_with("dimm"))
                })
                .count()
        })
        .and_then(|count| u32::try_from(count).ok())
        .unwrap_or_default()
}

fn read_edac_counter(path: PathBuf) -> Option<u64> {
    read_trimmed(path.to_str()?)?.parse::<u64>().ok()
}

fn collect_gpu_reliability(observed_at: &str) -> HostStateGpuReliabilityV1 {
    match Command::new("nvidia-smi").args(["-q", "-x"]).output() {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8_lossy(&output.stdout);
            match parse_nvidia_smi_reliability_xml(&text) {
                Some(devices) if !devices.is_empty() => HostStateGpuReliabilityV1 {
                    observed_at: observed_at.to_string(),
                    providers: vec![gpu_reliability_provider(
                        StateEvidenceProviderOutcomeV1::Success,
                        observed_at,
                        None,
                        None,
                    )],
                    devices,
                },
                Some(_) => HostStateGpuReliabilityV1 {
                    observed_at: observed_at.to_string(),
                    providers: vec![gpu_reliability_provider(
                        StateEvidenceProviderOutcomeV1::Partial,
                        observed_at,
                        Some(NVIDIA_SMI_NO_DEVICES),
                        Some("nvidia-smi XML contained no GPU entries"),
                    )],
                    devices: Vec::new(),
                },
                None => HostStateGpuReliabilityV1 {
                    observed_at: observed_at.to_string(),
                    providers: vec![gpu_reliability_provider(
                        StateEvidenceProviderOutcomeV1::Malformed,
                        observed_at,
                        Some(NVIDIA_SMI_XML_MALFORMED),
                        Some("nvidia-smi XML output could not be parsed for GPU reliability"),
                    )],
                    devices: Vec::new(),
                },
            }
        }
        Ok(output) => HostStateGpuReliabilityV1 {
            observed_at: observed_at.to_string(),
            providers: vec![gpu_reliability_provider(
                StateEvidenceProviderOutcomeV1::CommandFailed,
                observed_at,
                Some(NVIDIA_SMI_COMMAND_FAILED),
                Some(&format!("nvidia-smi -q -x exited with {}", output.status)),
            )],
            devices: Vec::new(),
        },
        Err(error) => {
            let outcome = if error.kind() == std::io::ErrorKind::NotFound {
                StateEvidenceProviderOutcomeV1::Unavailable
            } else if error.kind() == std::io::ErrorKind::PermissionDenied {
                StateEvidenceProviderOutcomeV1::PermissionDenied
            } else {
                StateEvidenceProviderOutcomeV1::CommandFailed
            };
            HostStateGpuReliabilityV1 {
                observed_at: observed_at.to_string(),
                providers: vec![gpu_reliability_provider(
                    outcome,
                    observed_at,
                    Some(NVIDIA_SMI_UNAVAILABLE),
                    Some(&format!("failed to run nvidia-smi -q -x: {error}")),
                )],
                devices: Vec::new(),
            }
        }
    }
}

fn gpu_reliability_provider(
    outcome: StateEvidenceProviderOutcomeV1,
    observed_at: &str,
    error_code: Option<&str>,
    diagnostics: Option<&str>,
) -> HostStateGpuReliabilityProviderV1 {
    HostStateGpuReliabilityProviderV1 {
        provider_id: "local-nvidia-smi-reliability".to_string(),
        provider_kind: GpuReliabilityProviderKindV1::NvidiaSmiXml,
        outcome,
        observed_at: observed_at.to_string(),
        error_code: error_code.map(ToOwned::to_owned),
        diagnostics: diagnostics.map(|value| value.chars().take(240).collect()),
    }
}

fn parse_nvidia_smi_reliability_xml(text: &str) -> Option<Vec<HostStateGpuReliabilityDeviceV1>> {
    if !text.contains("<nvidia_smi_log") && !text.contains("<gpu") {
        return None;
    }
    let mut devices = Vec::new();
    let mut rest = text;
    while let Some(gpu_start) = find_gpu_element_start(rest) {
        let gpu_element = &rest[gpu_start..];
        let open_end = gpu_element.find('>')?;
        let after_open = &gpu_element[open_end + 1..];
        let (gpu_body, tail) = after_open.split_once("</gpu>")?;
        devices.push(HostStateGpuReliabilityDeviceV1 {
            gpu_uuid: state_string_from_tag(gpu_body, &["uuid"]),
            product_name: state_string_from_tag(gpu_body, &["product_name"]),
            ecc_mode_current: state_string_from_tag(gpu_body, &["current_ecc"]),
            volatile_corrected_ecc_error_count: state_u64_from_tag(
                gpu_body,
                &[
                    "volatile_corrected_ecc_error_count",
                    "volatile_corrected",
                    "single_bit_ecc_errors",
                ],
            ),
            volatile_uncorrected_ecc_error_count: state_u64_from_tag(
                gpu_body,
                &[
                    "volatile_uncorrected_ecc_error_count",
                    "volatile_uncorrected",
                    "double_bit_ecc_errors",
                ],
            ),
            retired_pages_pending: state_bool_from_tag(gpu_body, &["pending_retirement"]),
            row_remapper_pending: state_bool_from_tag(gpu_body, &["remapping_pending"]),
        });
        rest = tail;
    }
    Some(devices)
}

fn find_gpu_element_start(text: &str) -> Option<usize> {
    ["<gpu ", "<gpu>"]
        .iter()
        .filter_map(|needle| text.find(needle))
        .min()
}

fn state_string_from_tag(text: &str, tags: &[&str]) -> StateFieldV1<String> {
    tags.iter()
        .find_map(|tag| xml_tag_text(text, tag))
        .filter(|value| !value.eq_ignore_ascii_case("n/a"))
        .map(observed)
        .unwrap_or_else(unknown)
}

fn state_u64_from_tag(text: &str, tags: &[&str]) -> StateFieldV1<u64> {
    tags.iter()
        .find_map(|tag| xml_tag_text(text, tag))
        .and_then(|value| value.parse::<u64>().ok())
        .map(observed)
        .unwrap_or_else(unknown)
}

fn state_bool_from_tag(text: &str, tags: &[&str]) -> StateFieldV1<bool> {
    tags.iter()
        .find_map(|tag| xml_tag_text(text, tag))
        .and_then(|value| match value.to_ascii_lowercase().as_str() {
            "yes" | "true" | "1" | "pending" => Some(true),
            "no" | "false" | "0" | "none" => Some(false),
            _ => None,
        })
        .map(observed)
        .unwrap_or_else(unknown)
}

fn xml_tag_text(text: &str, tag: &str) -> Option<String> {
    let start = format!("<{tag}>");
    let end = format!("</{tag}>");
    let (_, rest) = text.split_once(&start)?;
    let (value, _) = rest.split_once(&end)?;
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn collect_path_resources(
    requests: &[StatePathCheckRequestV1],
    pair_requests: &[StatePathLinkPairProbeRequestV1],
) -> HostStatePathResourcesV1 {
    let mounts = read_mountinfo();
    let observed_at = current_epoch_marker();
    let mut paths = requests
        .iter()
        .map(|request| collect_path_resource(request, &mounts, &observed_at))
        .collect::<Vec<_>>();
    paths.sort_by(|left, right| left.path_id.cmp(&right.path_id));
    let mut link_pairs = pair_requests
        .iter()
        .filter_map(|request| {
            let from_path = requests
                .iter()
                .find(|candidate| candidate.path_id == request.from_path_id)?;
            let to_path = requests
                .iter()
                .find(|candidate| candidate.path_id == request.to_path_id)?;
            Some(probe_path_link_pair_capabilities(
                &request.from_path_id,
                &from_path.path,
                &request.to_path_id,
                &to_path.path,
                &observed_at,
            ))
        })
        .collect::<Vec<_>>();
    link_pairs.sort_by(|left, right| left.pair_id.cmp(&right.pair_id));
    HostStatePathResourcesV1 { paths, link_pairs }
}

fn collect_path_resource(
    request: &StatePathCheckRequestV1,
    mounts: &[MountInfoV1],
    observed_at: &str,
) -> HostStatePathResourceV1 {
    let exists = request.path.exists();
    let (available, total) = statvfs_bytes(&request.path).unwrap_or((unknown(), unknown()));
    let canonical_path = canonical_path_field(&request.path);
    let mount_lookup_path = canonical_path
        .value
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(|| request.path.clone());
    let mount = find_containing_mount(&mount_lookup_path, mounts);
    let (media_class, media_class_confidence, media_class_evidence, durability_class) =
        classify_path_media(mount);
    let storage_identity = resolve_path_storage_identity(mount);
    let link_capabilities = request
        .probe_links
        .then(|| probe_path_link_capabilities(&request.path, observed_at));
    let storage_health = request
        .probe_health
        .then(|| probe_path_storage_health(mount, observed_at));

    HostStatePathResourceV1 {
        path_id: request.path_id.clone(),
        path: request.path.to_string_lossy().to_string(),
        requested_path: Some(request.path.to_string_lossy().to_string()),
        canonical_path,
        containing_mount_point: mount
            .map(|entry| observed(entry.mount_point.to_string_lossy().to_string()))
            .unwrap_or_else(unknown),
        filesystem_type: mount
            .map(|entry| observed(entry.filesystem_type.clone()))
            .unwrap_or_else(unknown),
        mount_source: mount
            .map(|entry| observed(entry.mount_source.clone()))
            .unwrap_or_else(unknown),
        mount_options: mount
            .map(|entry| observed(entry.mount_options.clone()))
            .unwrap_or_else(unknown),
        mount_device_major_minor: storage_identity.mount_device_major_minor,
        filesystem_uuid: storage_identity.filesystem_uuid,
        partition_uuid: storage_identity.partition_uuid,
        persistent_device_links: storage_identity.persistent_device_links,
        storage_identity_evidence: storage_identity.storage_identity_evidence,
        media_class: observed(media_class),
        media_class_confidence: observed(media_class_confidence),
        media_class_evidence,
        durability_class: observed(durability_class),
        observed_at: Some(observed_at.to_string()),
        exists: observed(exists),
        filesystem_available_bytes: available,
        filesystem_total_bytes: total,
        link_capabilities,
        storage_health,
    }
}

fn canonical_path_field(path: &Path) -> StateFieldV1<String> {
    match fs::canonicalize(path) {
        Ok(value) => observed(value.to_string_lossy().to_string()),
        Err(_) => unknown(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MountInfoV1 {
    device_major_minor: String,
    mount_point: PathBuf,
    filesystem_type: String,
    mount_source: String,
    mount_options: Vec<String>,
}

fn read_mountinfo() -> Vec<MountInfoV1> {
    let Ok(text) = fs::read_to_string("/proc/self/mountinfo") else {
        return Vec::new();
    };

    text.lines().filter_map(parse_mountinfo_line).collect()
}

fn parse_mountinfo_line(line: &str) -> Option<MountInfoV1> {
    let (left, right) = line.split_once(" - ")?;
    let mut left_fields = left.split_whitespace();
    let _mount_id = left_fields.next()?;
    let _parent_id = left_fields.next()?;
    let device_major_minor = left_fields.next()?.to_string();
    let _root = left_fields.next()?;
    let mount_point = decode_mountinfo_field(left_fields.next()?);
    let mount_options = left_fields
        .next()
        .map(|value| {
            value
                .split(',')
                .filter(|entry| !entry.trim().is_empty())
                .map(decode_mountinfo_field)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let mut right_fields = right.split_whitespace();
    let filesystem_type = right_fields.next()?.to_string();
    let mount_source = right_fields
        .next()
        .map(decode_mountinfo_field)
        .unwrap_or_else(|| "unknown".to_string());

    Some(MountInfoV1 {
        device_major_minor,
        mount_point: PathBuf::from(mount_point),
        filesystem_type,
        mount_source,
        mount_options,
    })
}

fn decode_mountinfo_field(value: &str) -> String {
    let mut decoded = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(character) = chars.next() {
        if character == '\\' {
            let octal = [chars.next(), chars.next(), chars.next()];
            if let [Some(a), Some(b), Some(c)] = octal {
                let candidate = [a, b, c].iter().collect::<String>();
                if let Ok(byte) = u8::from_str_radix(&candidate, 8) {
                    decoded.push(byte as char);
                    continue;
                }
                decoded.push('\\');
                decoded.push_str(&candidate);
                continue;
            }
            decoded.push('\\');
            for item in octal.into_iter().flatten() {
                decoded.push(item);
            }
        } else {
            decoded.push(character);
        }
    }
    decoded
}

fn find_containing_mount<'a>(path: &Path, mounts: &'a [MountInfoV1]) -> Option<&'a MountInfoV1> {
    mounts
        .iter()
        .filter(|entry| path.starts_with(&entry.mount_point))
        .max_by_key(|entry| entry.mount_point.as_os_str().len())
}

fn classify_path_media(
    mount: Option<&MountInfoV1>,
) -> (
    StateStorageMediaClassV1,
    StateStorageMediaClassConfidenceV1,
    Vec<String>,
    StateStorageDurabilityClassV1,
) {
    let Some(mount) = mount else {
        return (
            StateStorageMediaClassV1::Unknown,
            StateStorageMediaClassConfidenceV1::Unknown,
            vec!["mountinfo unavailable".to_string()],
            StateStorageDurabilityClassV1::Unknown,
        );
    };

    let fs_type = mount.filesystem_type.as_str();
    if matches!(fs_type, "tmpfs" | "ramfs" | "devtmpfs") {
        return (
            StateStorageMediaClassV1::Tmpfs,
            StateStorageMediaClassConfidenceV1::High,
            vec![format!("filesystem_type={fs_type}")],
            StateStorageDurabilityClassV1::Ephemeral,
        );
    }

    if matches!(
        fs_type,
        "nfs" | "nfs4" | "cifs" | "smb3" | "smbfs" | "fuse.sshfs" | "sshfs" | "9p"
    ) {
        return (
            StateStorageMediaClassV1::Network,
            StateStorageMediaClassConfidenceV1::High,
            vec![format!("filesystem_type={fs_type}")],
            StateStorageDurabilityClassV1::Durable,
        );
    }

    if let Some((class, confidence, mut evidence)) =
        classify_block_device_media(&mount.mount_source)
    {
        evidence.push(format!("filesystem_type={fs_type}"));
        return (
            class,
            confidence,
            evidence,
            StateStorageDurabilityClassV1::Durable,
        );
    }

    (
        StateStorageMediaClassV1::Unknown,
        StateStorageMediaClassConfidenceV1::Unknown,
        vec![
            format!("filesystem_type={fs_type}"),
            format!("mount_source={}", mount.mount_source),
        ],
        StateStorageDurabilityClassV1::Unknown,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PathStorageIdentityEvidenceV1 {
    mount_device_major_minor: StateFieldV1<String>,
    filesystem_uuid: StateFieldV1<String>,
    partition_uuid: StateFieldV1<String>,
    persistent_device_links: StateFieldV1<Vec<String>>,
    storage_identity_evidence: Vec<String>,
}

fn resolve_path_storage_identity(mount: Option<&MountInfoV1>) -> PathStorageIdentityEvidenceV1 {
    let Some(mount) = mount else {
        return PathStorageIdentityEvidenceV1 {
            mount_device_major_minor: unknown(),
            filesystem_uuid: unknown(),
            partition_uuid: unknown(),
            persistent_device_links: unknown(),
            storage_identity_evidence: vec!["mountinfo unavailable".to_string()],
        };
    };

    let dev_disk_root = Path::new("/dev/disk");
    let filesystem_uuid_links =
        find_matching_device_links(dev_disk_root, "by-uuid", &mount.mount_source);
    let partition_uuid_links =
        find_matching_device_links(dev_disk_root, "by-partuuid", &mount.mount_source);
    let persistent_device_links =
        find_matching_device_links(dev_disk_root, "by-id", &mount.mount_source);

    let filesystem_uuid = device_link_basename_field(&filesystem_uuid_links);
    let partition_uuid = device_link_basename_field(&partition_uuid_links);
    let persistent_device_links = if persistent_device_links.is_empty() {
        unknown()
    } else {
        observed(
            persistent_device_links
                .into_iter()
                .map(|path| path.to_string_lossy().to_string())
                .collect::<Vec<_>>(),
        )
    };

    let mut storage_identity_evidence = vec![format!(
        "mount_device_major_minor={}",
        mount.device_major_minor
    )];
    if let Some(value) = filesystem_uuid.value.as_ref() {
        storage_identity_evidence.push(format!("filesystem_uuid={value}"));
    }
    if let Some(value) = partition_uuid.value.as_ref() {
        storage_identity_evidence.push(format!("partition_uuid={value}"));
    }
    if let Some(values) = persistent_device_links.value.as_ref() {
        for value in values {
            storage_identity_evidence.push(format!("persistent_device_link={value}"));
        }
    }
    if filesystem_uuid.value.is_none()
        && partition_uuid.value.is_none()
        && persistent_device_links.value.is_none()
    {
        storage_identity_evidence.push(format!(
            "no_persistent_device_links_for_mount_source={}",
            mount.mount_source
        ));
    }
    storage_identity_evidence.sort();
    storage_identity_evidence.dedup();

    PathStorageIdentityEvidenceV1 {
        mount_device_major_minor: observed(mount.device_major_minor.clone()),
        filesystem_uuid,
        partition_uuid,
        persistent_device_links,
        storage_identity_evidence,
    }
}

fn device_link_basename_field(paths: &[PathBuf]) -> StateFieldV1<String> {
    paths
        .first()
        .and_then(|path| path.file_name())
        .map(|value| observed(value.to_string_lossy().to_string()))
        .unwrap_or_else(unknown)
}

fn find_matching_device_links(
    dev_disk_root: &Path,
    category: &str,
    mount_source: &str,
) -> Vec<PathBuf> {
    let Some(source_canonical) = canonical_device_path(mount_source) else {
        return Vec::new();
    };
    find_matching_device_links_for_canonical_source(
        &dev_disk_root.join(category),
        &source_canonical,
    )
}

fn canonical_device_path(raw: &str) -> Option<PathBuf> {
    let path = Path::new(raw);
    if !path.starts_with("/dev") {
        return None;
    }
    fs::canonicalize(path).ok()
}

fn find_matching_device_links_for_canonical_source(
    link_root: &Path,
    source_canonical: &Path,
) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(link_root) else {
        return Vec::new();
    };

    let mut matches = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            fs::canonicalize(path)
                .map(|candidate| candidate == source_canonical)
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    matches.sort();
    matches.dedup();
    matches
}

fn classify_block_device_media(
    mount_source: &str,
) -> Option<(
    StateStorageMediaClassV1,
    StateStorageMediaClassConfidenceV1,
    Vec<String>,
)> {
    let source_path = Path::new(mount_source);
    if !source_path.starts_with("/dev") {
        return None;
    }

    let canonical = fs::canonicalize(source_path).unwrap_or_else(|_| source_path.to_path_buf());
    let device_name = canonical.file_name()?.to_string_lossy().to_string();
    let base_device = base_block_device_name(&device_name);
    let rotational_path = Path::new("/sys/class/block")
        .join(&base_device)
        .join("queue/rotational");

    if base_device.starts_with("nvme") {
        return Some((
            StateStorageMediaClassV1::Nvme,
            StateStorageMediaClassConfidenceV1::High,
            vec![format!("block_device={base_device}")],
        ));
    }

    if let Some(rotational) = read_trimmed(rotational_path.to_str().unwrap_or_default()) {
        match rotational.as_str() {
            "0" => {
                return Some((
                    StateStorageMediaClassV1::Ssd,
                    StateStorageMediaClassConfidenceV1::High,
                    vec![
                        format!("block_device={base_device}"),
                        "rotational=0".to_string(),
                    ],
                ));
            }
            "1" => {
                return Some((
                    StateStorageMediaClassV1::Hdd,
                    StateStorageMediaClassConfidenceV1::High,
                    vec![
                        format!("block_device={base_device}"),
                        "rotational=1".to_string(),
                    ],
                ));
            }
            _ => {}
        }
    }

    None
}

fn base_block_device_name(device_name: &str) -> String {
    if device_name.starts_with("dm-") || device_name.starts_with("md") {
        return device_name.to_string();
    }

    if let Some((base, _partition)) = device_name.rsplit_once('p') {
        if base.starts_with("nvme") {
            return base.to_string();
        }
    }

    device_name
        .trim_end_matches(|character: char| character.is_ascii_digit())
        .to_string()
}

fn probe_path_storage_health(
    mount: Option<&MountInfoV1>,
    observed_at: &str,
) -> HostStatePathStorageHealthV1 {
    let mut result = HostStatePathStorageHealthV1 {
        health_state: unknown(),
        temperature_celsius: unknown(),
        percentage_used: unknown(),
        available_spare_percent: unknown(),
        source: None,
        probe_method: Some("safe-sysfs-storage-health".to_string()),
        probe_error: None,
        observed_at: Some(observed_at.to_string()),
    };

    let Some(mount) = mount else {
        result.probe_error = Some("no containing mount was observed for checked path".to_string());
        return result;
    };
    let Some(device_name) = mount_source_block_device_name(&mount.mount_source) else {
        result.source = Some(format!("mount_source:{}", mount.mount_source));
        result.probe_error = Some("mount source is not a local block device".to_string());
        return result;
    };

    let base_device = base_block_device_name(&device_name);
    let sysfs_device_root = Path::new("/sys/class/block").join(&base_device);
    result.source = Some(format!("sysfs:{}", sysfs_device_root.display()));

    if let Some(temperature) = read_block_temperature_celsius(&sysfs_device_root) {
        result.temperature_celsius = observed(temperature);
    }
    if result.temperature_celsius.value.is_none() {
        result.probe_error = Some("no safe storage health source for path".to_string());
    }

    result
}

fn mount_source_block_device_name(mount_source: &str) -> Option<String> {
    let canonical = canonical_device_path(mount_source)?;
    canonical
        .file_name()
        .map(|value| value.to_string_lossy().to_string())
}

fn read_block_temperature_celsius(sysfs_device_root: &Path) -> Option<i64> {
    let hwmon_root = sysfs_device_root.join("device/hwmon");
    let entries = fs::read_dir(hwmon_root).ok()?;
    for entry in entries.filter_map(Result::ok) {
        let Ok(files) = fs::read_dir(entry.path()) else {
            continue;
        };
        let mut temperature_files = files
            .filter_map(Result::ok)
            .map(|file| file.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("temp") && name.ends_with("_input"))
            })
            .collect::<Vec<_>>();
        temperature_files.sort();
        for path in temperature_files {
            let Some(raw) = read_trimmed(path.to_str().unwrap_or_default()) else {
                continue;
            };
            let Ok(millidegrees) = raw.parse::<i64>() else {
                continue;
            };
            return Some(millidegrees / 1000);
        }
    }
    None
}

fn statvfs_bytes(path: &std::path::Path) -> Option<(StateFieldV1<u64>, StateFieldV1<u64>)> {
    let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stats = MaybeUninit::<libc::statvfs>::uninit();
    let result = unsafe { libc::statvfs(c_path.as_ptr(), stats.as_mut_ptr()) };
    if result != 0 {
        return None;
    }
    let stats = unsafe { stats.assume_init() };
    let fragment_size = stats.f_frsize.max(1);
    let available = (stats.f_bavail as u128).checked_mul(fragment_size as u128)?;
    let total = (stats.f_blocks as u128).checked_mul(fragment_size as u128)?;
    Some((
        observed(u64::try_from(available).ok()?),
        observed(u64::try_from(total).ok()?),
    ))
}

fn read_execution_boundaries() -> HostStateExecutionBoundariesV1 {
    // The baseline models cgroup v2 explicitly. Older or absent controller layouts degrade to
    // unknown so state-aware validation does not infer limits it cannot justify.
    let cgroup_root = std::path::Path::new("/sys/fs/cgroup");
    if !cgroup_root.exists() {
        return HostStateExecutionBoundariesV1::default();
    }

    let cgroup_version = if cgroup_root.join("cgroup.controllers").exists() {
        observed("v2".to_string())
    } else {
        unknown()
    };

    HostStateExecutionBoundariesV1 {
        cgroup_version: cgroup_version.clone(),
        available_cgroup_controllers: if boundary_value(&cgroup_version).as_deref() == Some("v2") {
            read_cgroup_controllers(cgroup_root)
        } else {
            unknown()
        },
        cpuset_cpu_logical_cores: if boundary_value(&cgroup_version).as_deref() == Some("v2") {
            read_cpuset_cpu_count(cgroup_root)
        } else {
            unknown()
        },
        cpu_quota_logical_cores: if boundary_value(&cgroup_version).as_deref() == Some("v2") {
            read_cpu_quota_logical_cores(cgroup_root)
        } else {
            unknown()
        },
        memory_limit_bytes: if boundary_value(&cgroup_version).as_deref() == Some("v2") {
            read_memory_limit_bytes(cgroup_root)
        } else {
            unknown()
        },
        memory_current_bytes: if boundary_value(&cgroup_version).as_deref() == Some("v2") {
            read_memory_current_bytes(cgroup_root)
        } else {
            unknown()
        },
    }
}

fn read_cgroup_controllers(cgroup_root: &std::path::Path) -> StateFieldV1<Vec<String>> {
    let mut controllers = read_trimmed(
        cgroup_root
            .join("cgroup.controllers")
            .to_str()
            .unwrap_or_default(),
    )
    .map(|value| {
        value
            .split_whitespace()
            .map(str::to_string)
            .filter(|entry| !entry.trim().is_empty())
            .collect::<Vec<_>>()
    })
    .unwrap_or_default();
    controllers.sort();
    controllers.dedup();
    if controllers.is_empty() {
        unknown()
    } else {
        observed(controllers)
    }
}

fn read_cpuset_cpu_count(cgroup_root: &std::path::Path) -> StateFieldV1<u32> {
    let primary = cgroup_root.join("cpuset.cpus.effective");
    let fallback = cgroup_root.join("cpuset.cpus");
    let value = read_trimmed(primary.to_str().unwrap_or_default())
        .or_else(|| read_trimmed(fallback.to_str().unwrap_or_default()))
        .and_then(parse_cpu_range_count);
    observed_or_unknown(value)
}

fn read_cpu_quota_logical_cores(cgroup_root: &std::path::Path) -> StateFieldV1<u32> {
    let Some(value) = read_trimmed(cgroup_root.join("cpu.max").to_str().unwrap_or_default()) else {
        return unknown();
    };
    let Some((quota, period)) = value.split_once(' ') else {
        return unknown();
    };
    if quota == "max" {
        return unknown();
    }
    let Some(quota) = quota.parse::<u64>().ok() else {
        return unknown();
    };
    let Some(period) = period.parse::<u64>().ok() else {
        return unknown();
    };
    if quota == 0 || period == 0 {
        return unknown();
    }

    let logical_cores = quota.saturating_add(period.saturating_sub(1)) / period;
    observed_or_unknown(u32::try_from(logical_cores).ok().filter(|value| *value > 0))
}

fn read_memory_limit_bytes(cgroup_root: &std::path::Path) -> StateFieldV1<u64> {
    match read_trimmed(cgroup_root.join("memory.max").to_str().unwrap_or_default()).as_deref() {
        Some("max") | None => unknown(),
        Some(value) => observed_or_unknown(value.parse::<u64>().ok().filter(|value| *value > 0)),
    }
}

fn read_memory_current_bytes(cgroup_root: &std::path::Path) -> StateFieldV1<u64> {
    observed_or_unknown(
        read_trimmed(
            cgroup_root
                .join("memory.current")
                .to_str()
                .unwrap_or_default(),
        )
        .and_then(|value| value.parse::<u64>().ok()),
    )
}

fn bound_cpu_capacity(
    process_visible: u32,
    cpuset: Option<u32>,
    quota: Option<u32>,
) -> Option<u32> {
    // Capacity is the tightest bound we can observe across scheduler visibility, cpuset, and
    // quota. Any missing source simply drops out of the minimum.
    let mut candidates = Vec::new();
    if process_visible > 0 {
        candidates.push(process_visible);
    }
    if let Some(cpuset) = cpuset.filter(|value| *value > 0) {
        candidates.push(cpuset);
    }
    if let Some(quota) = quota.filter(|value| *value > 0) {
        candidates.push(quota);
    }
    candidates.into_iter().min()
}

fn bound_allocatable_memory_bytes(
    host_available: Option<u64>,
    memory_limit: Option<u64>,
    memory_current: Option<u64>,
) -> Option<u64> {
    // Prefer the smaller of host-available memory and cgroup headroom so allocatable memory
    // reflects the deployment boundary rather than optimistic host totals.
    let host_available = host_available?;
    if let (Some(memory_limit), Some(memory_current)) = (memory_limit, memory_current) {
        if memory_current > memory_limit {
            return None;
        }
        let boundary_headroom = memory_limit.saturating_sub(memory_current);
        return Some(host_available.min(boundary_headroom));
    }

    Some(host_available)
}

fn read_hostname() -> Option<String> {
    let text = fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
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

fn read_kernel_hostname_for_identity_v2() -> Option<String> {
    read_trimmed("/proc/sys/kernel/hostname")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MeminfoCountersV1 {
    total_bytes: u64,
    free_bytes: u64,
    available_bytes: u64,
    buffers_bytes: u64,
    cached_bytes: u64,
    reclaimable_slab_bytes: u64,
    shared_memory_bytes: u64,
}

impl MeminfoCountersV1 {
    fn used_excluding_cache_bytes(&self) -> Option<u64> {
        if self.total_bytes == 0 {
            return None;
        }

        let reclaimable_bytes = self
            .free_bytes
            .saturating_add(self.buffers_bytes)
            .saturating_add(self.cached_bytes)
            .saturating_add(self.reclaimable_slab_bytes);
        let base_used = self.total_bytes.saturating_sub(reclaimable_bytes);
        let used = base_used.saturating_add(self.shared_memory_bytes);

        (used <= self.total_bytes).then_some(used)
    }
}

fn read_meminfo_counters() -> Option<MeminfoCountersV1> {
    // Require the full counter set so the derived runtime memory figures come from one coherent
    // procfs snapshot instead of mixing counters from different reads.
    let text = fs::read_to_string("/proc/meminfo").ok()?;
    Some(MeminfoCountersV1 {
        total_bytes: read_meminfo_counter_bytes(&text, "MemTotal")?,
        free_bytes: read_meminfo_counter_bytes(&text, "MemFree")?,
        available_bytes: read_meminfo_counter_bytes(&text, "MemAvailable")?,
        buffers_bytes: read_meminfo_counter_bytes(&text, "Buffers")?,
        cached_bytes: read_meminfo_counter_bytes(&text, "Cached")?,
        reclaimable_slab_bytes: read_meminfo_counter_bytes(&text, "SReclaimable")?,
        shared_memory_bytes: read_meminfo_counter_bytes(&text, "Shmem")?,
    })
}

fn read_meminfo_counter_bytes(text: &str, field_name: &str) -> Option<u64> {
    for line in text.lines() {
        let line = line.trim();
        let prefix = format!("{field_name}:");
        if !line.starts_with(&prefix) {
            continue;
        }

        let mut parts = line.split_whitespace();
        let _ = parts.next();
        let kib = parts.next()?.parse::<u64>().ok()?;
        return Some(kib.saturating_mul(1024));
    }

    None
}

fn positive_u64_field(value: u64) -> Option<u64> {
    (value > 0).then_some(value)
}

fn boundary_value<T: Clone>(field: &StateFieldV1<T>) -> Option<T> {
    match (&field.state, &field.value) {
        (ObservationStateV1::Observed, Some(value))
        | (ObservationStateV1::PartiallyObserved, Some(value)) => Some(value.clone()),
        _ => None,
    }
}

fn non_negative_boundary_value(field: &StateFieldV1<u64>) -> Option<u64> {
    match (&field.state, &field.value) {
        (ObservationStateV1::Observed, Some(value))
        | (ObservationStateV1::PartiallyObserved, Some(value)) => Some(*value),
        _ => None,
    }
}

fn read_visible_numa_nodes() -> StateFieldV1<u32> {
    let count = fs::read_dir("/sys/devices/system/node")
        .ok()
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .filter_map(|entry| entry.file_name().into_string().ok())
                .filter(|name| name.starts_with("node"))
                .count() as u32
        })
        .unwrap_or_default();

    if count > 0 {
        observed(count)
    } else {
        unknown()
    }
}

fn current_epoch_marker() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("unix:{seconds}")
}

fn observed<T>(value: T) -> StateFieldV1<T> {
    StateFieldV1 {
        state: ObservationStateV1::Observed,
        limitation_reason: None,
        value: Some(value),
    }
}

fn observed_or_unknown<T>(value: Option<T>) -> StateFieldV1<T> {
    value.map(observed).unwrap_or_else(unknown)
}

fn unknown<T>() -> StateFieldV1<T> {
    StateFieldV1 {
        state: ObservationStateV1::Unknown,
        limitation_reason: None,
        value: None,
    }
}

#[allow(dead_code)]
fn unknown_with_reason<T>(reason: ObservationLimitationReasonV1) -> StateFieldV1<T> {
    StateFieldV1 {
        state: ObservationStateV1::Unknown,
        limitation_reason: Some(reason),
        value: None,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_device_links_are_sorted_and_resolved_by_canonical_target() {
        let root = std::env::temp_dir().join(format!(
            "fitctl-device-link-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let device_root = root.join("dev");
        let by_uuid = device_root.join("disk/by-uuid");
        fs::create_dir_all(&by_uuid).expect("fake by-uuid root should be created");
        let device = device_root.join("nvme0n1p1");
        fs::write(&device, b"fake device target").expect("fake device should be created");
        let canonical = fs::canonicalize(&device).expect("fake device should canonicalize");

        let first = by_uuid.join("11111111-2222-3333-4444-555555555555");
        let second = by_uuid.join("22222222-2222-3333-4444-555555555555");
        symlink(&device, &second).expect("second fake UUID link should be created");
        symlink(&device, &first).expect("first fake UUID link should be created");
        symlink(device_root.join("missing"), by_uuid.join("stale-link"))
            .expect("stale fake UUID link should be created");

        let matches = find_matching_device_links_for_canonical_source(&by_uuid, &canonical);
        assert_eq!(matches, vec![first, second]);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn memory_reliability_edac_sysfs_sums_controller_counters() {
        let root = std::env::temp_dir().join(format!(
            "fitctl-edac-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let mc0 = root.join("mc0");
        let mc1 = root.join("mc1");
        fs::create_dir_all(mc0.join("dimm0")).expect("fake dimm should create");
        fs::create_dir_all(mc1.join("dimm0")).expect("fake dimm should create");
        fs::create_dir_all(mc1.join("dimm1")).expect("fake dimm should create");
        fs::write(mc0.join("ce_count"), "2\n").expect("ce should write");
        fs::write(mc0.join("ue_count"), "0\n").expect("ue should write");
        fs::write(mc1.join("ce_count"), "5\n").expect("ce should write");
        fs::write(mc1.join("ue_count"), "1\n").expect("ue should write");

        let evidence = collect_memory_reliability_from_edac_root(&root, "unix:1");
        assert_eq!(
            evidence.providers[0].outcome,
            StateEvidenceProviderOutcomeV1::Success
        );
        assert_eq!(evidence.controller_count.value, Some(2));
        assert_eq!(evidence.dimm_count.value, Some(3));
        assert_eq!(evidence.corrected_error_count.value, Some(7));
        assert_eq!(evidence.uncorrected_error_count.value, Some(1));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn memory_reliability_edac_absent_is_unavailable() {
        let root = std::env::temp_dir().join(format!(
            "fitctl-edac-missing-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let evidence = collect_memory_reliability_from_edac_root(&root, "unix:1");
        assert_eq!(
            evidence.providers[0].outcome,
            StateEvidenceProviderOutcomeV1::Unavailable
        );
        assert_eq!(
            evidence.providers[0].error_code.as_deref(),
            Some("edac_sysfs_unavailable")
        );
    }

    #[test]
    fn gpu_reliability_parser_extracts_ecc_and_remapper_fields() {
        let xml = r#"
<nvidia_smi_log>
  <gpu id="00000000:01:00.0">
    <product_name>NVIDIA Test GPU</product_name>
    <gpu_operation_mode>
      <current_gom>N/A</current_gom>
      <pending_gom>N/A</pending_gom>
    </gpu_operation_mode>
    <uuid>GPU-test-uuid</uuid>
    <ecc_mode><current_ecc>Enabled</current_ecc></ecc_mode>
    <volatile_corrected_ecc_error_count>3</volatile_corrected_ecc_error_count>
    <volatile_uncorrected_ecc_error_count>1</volatile_uncorrected_ecc_error_count>
    <retired_pages><pending_retirement>No</pending_retirement></retired_pages>
    <row_remapper><remapping_pending>Yes</remapping_pending></row_remapper>
  </gpu>
</nvidia_smi_log>
"#;
        let devices = parse_nvidia_smi_reliability_xml(xml).expect("XML should parse");
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].gpu_uuid.value.as_deref(), Some("GPU-test-uuid"));
        assert_eq!(
            devices[0].product_name.value.as_deref(),
            Some("NVIDIA Test GPU")
        );
        assert_eq!(
            devices[0].ecc_mode_current.value.as_deref(),
            Some("Enabled")
        );
        assert_eq!(devices[0].volatile_corrected_ecc_error_count.value, Some(3));
        assert_eq!(
            devices[0].volatile_uncorrected_ecc_error_count.value,
            Some(1)
        );
        assert_eq!(devices[0].retired_pages_pending.value, Some(false));
        assert_eq!(devices[0].row_remapper_pending.value, Some(true));
    }
}
