// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::artifacts::state_v1::{
    FreshnessStateV1, HostRuntimeResourcesV1, HostStateExecutionBoundariesV1,
    HostStateOperabilityV1, HostStateTopologyV1, StateFieldV1, StateFreshnessV1,
};
use crate::identity::{select_live_linux_identity_input_v2, LocalStableIdentityInputV2};
use crate::state::{LiveStateProbeV1, StateError, StateErrorCode};
use crate::survey::{ObservationLimitationReasonV1, ObservationStateV1};

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
    pub boundaries: HostStateExecutionBoundariesV1,
    pub topology: HostStateTopologyV1,
    pub operability: HostStateOperabilityV1,
}

pub struct LocalLiveStateProbeV1;

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

        Ok(CollectedHostStateSnapshotV1 {
            source_kind: SnapshotSourceKindV1::Live,
            provenance_source: "live:linux_runtime_v1".to_string(),
            snapshot_id: host_alias.clone(),
            collected_at: collected_at.clone(),
            host_alias,
            local_stable_identity_input: Some(live_identity.input),
            collectors: vec![
                "runtime_cpu_capacity".to_string(),
                "procfs_meminfo".to_string(),
                "cgroupfs_cpuset".to_string(),
                "cgroupfs_cpu_quota".to_string(),
                "cgroupfs_memory_boundary".to_string(),
                "sysfs_topology".to_string(),
            ],
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
