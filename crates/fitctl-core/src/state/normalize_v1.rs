// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Normalize collected runtime-state snapshots into host-state.v2 artifacts.

use crate::artifacts::envelope_v1::{local_artifact_provenance_v1, ArtifactEnvelopeV1};
use crate::artifacts::metadata_v1::{
    AssuranceSourceV1, ClaimMetadataV1, CollectorMetadataV1, DerivationStageV1,
};
use crate::artifacts::schema_ids_v1::{HOST_STATE_SCHEMA_ID, TOP_LEVEL_ARTIFACT_SCHEMA_VERSION};
use crate::artifacts::state_v1::{
    HostStateCoreV1, HostStatePayloadV1, HostStateV1, StateCollectionModeV1, StateFieldV1,
    StateSectionMetadataV1,
};
use crate::artifacts::validation_v1::validate_host_state;
use crate::state::live_v1::{CollectedHostStateSnapshotV1, SnapshotSourceKindV1};
use crate::state::{StateError, StateErrorCode};
use crate::survey::{validate_observation_field_coherence_v1, ObservationStateV1};

pub(crate) fn build_host_state_from_snapshot(
    mut snapshot: CollectedHostStateSnapshotV1,
) -> Result<HostStateV1, StateError> {
    if snapshot.collectors.is_empty()
        || snapshot
            .collectors
            .iter()
            .any(|collector| collector.trim().is_empty())
    {
        return Err(StateError::new(
            StateErrorCode::StatePayloadMalformed,
            "state_parse",
            "state snapshot must contain at least one non-blank collector id",
        ));
    }

    validate_field(
        &snapshot.resources.allocatable_cpu_logical_cores,
        "allocatable_cpu_logical_cores",
        |value| *value > 0,
    )?;
    validate_field(
        &snapshot.resources.memory_total_bytes,
        "memory_total_bytes",
        |value| *value > 0,
    )?;
    validate_field(
        &snapshot.resources.allocatable_memory_bytes,
        "allocatable_memory_bytes",
        |value| *value > 0,
    )?;
    validate_field(
        &snapshot.resources.memory_used_excluding_cache_bytes,
        "memory_used_excluding_cache_bytes",
        |value| *value > 0,
    )?;
    validate_memory_accounting(&snapshot.resources)?;
    validate_path_resources(&snapshot.path_resources)?;
    validate_thermal_resources(snapshot.thermal_resources.as_ref())?;
    validate_memory_reliability(snapshot.memory_reliability.as_ref())?;
    validate_gpu_reliability(snapshot.gpu_reliability.as_ref())?;

    canonicalise_snapshot(&mut snapshot);

    let artifact_id = format!("state-{}", sanitize_identifier(&snapshot.snapshot_id));
    let payload = HostStatePayloadV1 {
        collection_mode: source_kind_label(&snapshot.source_kind),
        snapshot_id: snapshot.snapshot_id.clone(),
        host_alias: snapshot.host_alias.clone(),
        source_ref: snapshot.provenance_source.clone(),
        local_identity: snapshot
            .local_stable_identity_input
            .as_ref()
            .map(|identity| identity.derive_state_local_identity()),
        core_state: HostStateCoreV1 {
            collectors: typed_collectors_from_snapshot(&snapshot.collectors),
            section_metadata: StateSectionMetadataV1 {
                resources: ClaimMetadataV1 {
                    assurance_source: AssuranceSourceV1::SelfObserved,
                    derivation_stage: DerivationStageV1::Normalized,
                    source_collectors: snapshot.collectors.clone(),
                    evidence_paths: vec!["$.state.core_state.resources".to_string()],
                    policy_rule_id: None,
                    trust_evidence_refs: Vec::new(),
                },
                path_resources: ClaimMetadataV1 {
                    assurance_source: AssuranceSourceV1::SelfObserved,
                    derivation_stage: DerivationStageV1::Normalized,
                    source_collectors: snapshot.collectors.clone(),
                    evidence_paths: vec!["$.state.core_state.path_resources".to_string()],
                    policy_rule_id: None,
                    trust_evidence_refs: Vec::new(),
                },
                boundaries: ClaimMetadataV1 {
                    assurance_source: AssuranceSourceV1::SelfObserved,
                    derivation_stage: DerivationStageV1::Normalized,
                    source_collectors: snapshot.collectors.clone(),
                    evidence_paths: vec!["$.state.core_state.boundaries".to_string()],
                    policy_rule_id: None,
                    trust_evidence_refs: Vec::new(),
                },
                topology: ClaimMetadataV1 {
                    assurance_source: AssuranceSourceV1::SelfObserved,
                    derivation_stage: DerivationStageV1::Normalized,
                    source_collectors: snapshot.collectors.clone(),
                    evidence_paths: vec!["$.state.core_state.topology".to_string()],
                    policy_rule_id: None,
                    trust_evidence_refs: Vec::new(),
                },
                operability: ClaimMetadataV1 {
                    assurance_source: AssuranceSourceV1::SelfObserved,
                    derivation_stage: DerivationStageV1::Normalized,
                    source_collectors: snapshot.collectors.clone(),
                    evidence_paths: vec!["$.state.core_state.operability".to_string()],
                    policy_rule_id: None,
                    trust_evidence_refs: Vec::new(),
                },
            },
            freshness: snapshot.freshness.clone(),
            resources: snapshot.resources.clone(),
            path_resources: snapshot.path_resources.clone(),
            thermal_resources: snapshot.thermal_resources.clone(),
            hardware_sensor_resources: snapshot.hardware_sensor_resources.clone(),
            memory_reliability: snapshot.memory_reliability.clone(),
            gpu_reliability: snapshot.gpu_reliability.clone(),
            boundaries: snapshot.boundaries.clone(),
            topology: snapshot.topology.clone(),
            operability: snapshot.operability.clone(),
        },
        extension_state: Default::default(),
    };

    let state = serde_json::from_value(serde_json::to_value(payload).map_err(|error| {
        StateError::new(
            StateErrorCode::StateNormalizationFailed,
            "state_emit",
            format!("failed to encode normalized host-state payload: {error}"),
        )
    })?)
    .map_err(|error| {
        StateError::new(
            StateErrorCode::StateNormalizationFailed,
            "state_emit",
            format!("failed to decode normalized host-state payload: {error}"),
        )
    })?;

    let artifact = HostStateV1 {
        envelope: ArtifactEnvelopeV1 {
            schema_id: HOST_STATE_SCHEMA_ID.to_string(),
            schema_version: TOP_LEVEL_ARTIFACT_SCHEMA_VERSION,
            artifact_id: artifact_id.clone(),
            provenance: local_artifact_provenance_v1(
                snapshot.provenance_source,
                snapshot.collected_at,
                "state",
                artifact_id,
            ),
            redaction: None,
            signatures: vec![],
        },
        state,
    };

    validate_host_state(&artifact).map_err(|error| {
        StateError::new(
            StateErrorCode::HostStateArtifactInvalid,
            "state_emit",
            error.message,
        )
    })?;

    Ok(artifact)
}

fn validate_memory_reliability(
    memory_reliability: Option<&crate::state::HostStateMemoryReliabilityV1>,
) -> Result<(), StateError> {
    let Some(memory_reliability) = memory_reliability else {
        return Ok(());
    };
    if memory_reliability.observed_at.trim().is_empty() || memory_reliability.providers.is_empty() {
        return Err(StateError::new(
            StateErrorCode::StateNormalizationFailed,
            "memory_reliability_emit",
            "memory reliability evidence must include observed_at and provider outcomes",
        ));
    }
    let mut provider_ids = std::collections::BTreeSet::new();
    for provider in &memory_reliability.providers {
        if provider.provider_id.trim().is_empty()
            || provider.observed_at.trim().is_empty()
            || !provider_ids.insert(provider.provider_id.clone())
        {
            return Err(StateError::new(
                StateErrorCode::StateNormalizationFailed,
                "memory_reliability_emit",
                "memory reliability provider ids must be unique and metadata must be non-blank",
            ));
        }
        for value in [
            provider.source.as_ref(),
            provider.error_code.as_ref(),
            provider.diagnostics.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if value.trim().is_empty() {
                return Err(StateError::new(
                    StateErrorCode::StateNormalizationFailed,
                    "memory_reliability_emit",
                    "memory reliability provider optional strings must be non-blank",
                ));
            }
        }
    }
    validate_field(
        &memory_reliability.controller_count,
        "memory_reliability.controller_count",
        |_| true,
    )?;
    validate_field(
        &memory_reliability.dimm_count,
        "memory_reliability.dimm_count",
        |_| true,
    )?;
    validate_field(
        &memory_reliability.corrected_error_count,
        "memory_reliability.corrected_error_count",
        |_| true,
    )?;
    validate_field(
        &memory_reliability.uncorrected_error_count,
        "memory_reliability.uncorrected_error_count",
        |_| true,
    )?;
    Ok(())
}

fn validate_gpu_reliability(
    gpu_reliability: Option<&crate::state::HostStateGpuReliabilityV1>,
) -> Result<(), StateError> {
    let Some(gpu_reliability) = gpu_reliability else {
        return Ok(());
    };
    if gpu_reliability.observed_at.trim().is_empty() || gpu_reliability.providers.is_empty() {
        return Err(StateError::new(
            StateErrorCode::StateNormalizationFailed,
            "gpu_reliability_emit",
            "GPU reliability evidence must include observed_at and provider outcomes",
        ));
    }
    let mut provider_ids = std::collections::BTreeSet::new();
    for provider in &gpu_reliability.providers {
        if provider.provider_id.trim().is_empty()
            || provider.observed_at.trim().is_empty()
            || !provider_ids.insert(provider.provider_id.clone())
        {
            return Err(StateError::new(
                StateErrorCode::StateNormalizationFailed,
                "gpu_reliability_emit",
                "GPU reliability provider ids must be unique and metadata must be non-blank",
            ));
        }
        for value in [provider.error_code.as_ref(), provider.diagnostics.as_ref()]
            .into_iter()
            .flatten()
        {
            if value.trim().is_empty() {
                return Err(StateError::new(
                    StateErrorCode::StateNormalizationFailed,
                    "gpu_reliability_emit",
                    "GPU reliability provider optional strings must be non-blank",
                ));
            }
        }
    }
    for device in &gpu_reliability.devices {
        validate_field(&device.gpu_uuid, "gpu_reliability.gpu_uuid", |value| {
            !value.trim().is_empty()
        })?;
        validate_field(
            &device.product_name,
            "gpu_reliability.product_name",
            |value| !value.trim().is_empty(),
        )?;
        validate_field(
            &device.ecc_mode_current,
            "gpu_reliability.ecc_mode_current",
            |value| !value.trim().is_empty(),
        )?;
        validate_field(
            &device.volatile_corrected_ecc_error_count,
            "gpu_reliability.volatile_corrected_ecc_error_count",
            |_| true,
        )?;
        validate_field(
            &device.volatile_uncorrected_ecc_error_count,
            "gpu_reliability.volatile_uncorrected_ecc_error_count",
            |_| true,
        )?;
        validate_field(
            &device.retired_pages_pending,
            "gpu_reliability.retired_pages_pending",
            |_| true,
        )?;
        validate_field(
            &device.row_remapper_pending,
            "gpu_reliability.row_remapper_pending",
            |_| true,
        )?;
    }
    Ok(())
}

fn validate_thermal_resources(
    thermal_resources: Option<&crate::state::HostStateThermalResourcesV1>,
) -> Result<(), StateError> {
    let Some(thermal_resources) = thermal_resources else {
        return Ok(());
    };
    if thermal_resources.observed_at.trim().is_empty()
        || thermal_resources.providers.is_empty()
        || thermal_resources
            .collector_host
            .host_alias
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        || thermal_resources
            .collector_host
            .local_stable_id
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
    {
        return Err(StateError::new(
            StateErrorCode::StateNormalizationFailed,
            "thermal_provider_emit",
            "thermal resources must include observed_at, provider outcomes, and non-blank collector host metadata",
        ));
    }
    let mut provider_ids = std::collections::BTreeSet::new();
    for provider in &thermal_resources.providers {
        if provider.provider_id.trim().is_empty()
            || !provider_ids.insert(provider.provider_id.clone())
        {
            return Err(StateError::new(
                StateErrorCode::StateNormalizationFailed,
                "thermal_provider_emit",
                "thermal provider ids must be non-blank and unique",
            ));
        }
        validate_thermal_target(&provider.evidence_target)?;
        for value in [
            provider.error_code.as_ref(),
            provider.diagnostics.as_ref(),
            Some(&provider.observed_at),
        ]
        .into_iter()
        .flatten()
        {
            if value.trim().is_empty() {
                return Err(StateError::new(
                    StateErrorCode::StateNormalizationFailed,
                    "thermal_provider_emit",
                    "thermal provider metadata must be non-blank when present",
                ));
            }
        }
    }
    let mut sensor_ids = std::collections::BTreeSet::new();
    for reading in &thermal_resources.readings {
        if reading.sensor_id.trim().is_empty()
            || reading.provider_id.trim().is_empty()
            || reading.raw_label.trim().is_empty()
            || reading.observed_at.trim().is_empty()
            || !sensor_ids.insert(reading.sensor_id.clone())
            || !provider_ids.contains(&reading.provider_id)
        {
            return Err(StateError::new(
                StateErrorCode::StateNormalizationFailed,
                "thermal_provider_emit",
                "thermal readings must include unique sensor ids and known provider ids",
            ));
        }
        validate_thermal_target(&reading.evidence_target)?;
        if reading
            .source
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(StateError::new(
                StateErrorCode::StateNormalizationFailed,
                "thermal_provider_emit",
                "thermal reading source must be non-blank when present",
            ));
        }
        if reading
            .sensor_alias
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(StateError::new(
                StateErrorCode::StateNormalizationFailed,
                "thermal_provider_emit",
                "thermal reading alias must be non-blank when present",
            ));
        }
    }
    Ok(())
}

fn validate_thermal_target(
    target: &crate::state::HostStateThermalEvidenceTargetV1,
) -> Result<(), StateError> {
    match target.target_kind {
        crate::state::ThermalEvidenceTargetKindV1::CurrentHost => {
            if target.host_id.is_some() {
                return Err(StateError::new(
                    StateErrorCode::StateNormalizationFailed,
                    "thermal_provider_emit",
                    "current_host thermal target must not include host_id",
                ));
            }
        }
        crate::state::ThermalEvidenceTargetKindV1::HostId => {
            if target
                .host_id
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
            {
                return Err(StateError::new(
                    StateErrorCode::StateNormalizationFailed,
                    "thermal_provider_emit",
                    "host_id thermal target requires non-blank host_id",
                ));
            }
        }
    }
    Ok(())
}

fn validate_field<T>(
    field: &StateFieldV1<T>,
    field_name: &str,
    validate_value: impl FnOnce(&T) -> bool,
) -> Result<(), StateError> {
    validate_observation_field_coherence_v1(
        &field.state,
        field.limitation_reason.as_ref(),
        field.value.as_ref(),
        validate_value,
    )
    .map_err(|message| {
        StateError::new(
            StateErrorCode::StateNormalizationFailed,
            "state_emit",
            format!("state field {field_name} {message}"),
        )
    })
}

fn canonicalise_snapshot(snapshot: &mut CollectedHostStateSnapshotV1) {
    snapshot.collectors.sort();
    snapshot.collectors.dedup();
}

fn validate_memory_accounting(
    resources: &crate::state::HostRuntimeResourcesV1,
) -> Result<(), StateError> {
    let total = scalar_value(&resources.memory_total_bytes);
    let allocatable = scalar_value(&resources.allocatable_memory_bytes);
    let used = scalar_value(&resources.memory_used_excluding_cache_bytes);

    if let (Some(total), Some(allocatable)) = (total, allocatable) {
        if allocatable > total {
            return Err(StateError::new(
                StateErrorCode::StateNormalizationFailed,
                "state_emit",
                "allocatable memory must not exceed total memory",
            ));
        }
    }

    if let (Some(total), Some(used)) = (total, used) {
        if used > total {
            return Err(StateError::new(
                StateErrorCode::StateNormalizationFailed,
                "state_emit",
                "used-excluding-cache memory must not exceed total memory",
            ));
        }
    }

    Ok(())
}

fn validate_path_resources(
    path_resources: &crate::state::HostStatePathResourcesV1,
) -> Result<(), StateError> {
    let mut path_ids = std::collections::BTreeSet::new();
    for path in &path_resources.paths {
        if path.path_id.trim().is_empty() || path.path.trim().is_empty() {
            return Err(StateError::new(
                StateErrorCode::StateNormalizationFailed,
                "state_emit",
                "path resource entries must include non-blank path_id and path",
            ));
        }
        if !path_ids.insert(path.path_id.clone()) {
            return Err(StateError::new(
                StateErrorCode::StateNormalizationFailed,
                "state_emit",
                format!("path resource id {} is duplicated", path.path_id),
            ));
        }
        validate_field(&path.exists, "path_resources.exists", |_| true)?;
        validate_field(
            &path.mount_device_major_minor,
            "path_resources.mount_device_major_minor",
            |value| !value.trim().is_empty(),
        )?;
        validate_field(
            &path.filesystem_uuid,
            "path_resources.filesystem_uuid",
            |value| !value.trim().is_empty(),
        )?;
        validate_field(
            &path.partition_uuid,
            "path_resources.partition_uuid",
            |value| !value.trim().is_empty(),
        )?;
        validate_field(
            &path.persistent_device_links,
            "path_resources.persistent_device_links",
            |value| value.iter().all(|entry| !entry.trim().is_empty()),
        )?;
        validate_field(
            &path.filesystem_available_bytes,
            "path_resources.filesystem_available_bytes",
            |_| true,
        )?;
        validate_field(
            &path.filesystem_total_bytes,
            "path_resources.filesystem_total_bytes",
            |value| *value > 0,
        )?;
        if let (Some(available), Some(total)) = (
            scalar_value(&path.filesystem_available_bytes),
            scalar_value(&path.filesystem_total_bytes),
        ) {
            if available > total {
                return Err(StateError::new(
                    StateErrorCode::StateNormalizationFailed,
                    "state_emit",
                    format!(
                        "path resource {} available bytes must not exceed total bytes",
                        path.path_id
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn scalar_value<T: Copy>(field: &StateFieldV1<T>) -> Option<T> {
    match (&field.state, &field.value) {
        (ObservationStateV1::Observed, Some(value))
        | (ObservationStateV1::PartiallyObserved, Some(value)) => Some(*value),
        _ => None,
    }
}

fn source_kind_label(source_kind: &SnapshotSourceKindV1) -> StateCollectionModeV1 {
    match source_kind {
        SnapshotSourceKindV1::Live => StateCollectionModeV1::Live,
        SnapshotSourceKindV1::Replay { .. } => StateCollectionModeV1::Replay,
    }
}

fn sanitize_identifier(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len());

    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            sanitized.push(character.to_ascii_lowercase());
        } else {
            sanitized.push('-');
        }
    }

    sanitized.trim_matches('-').to_string()
}

fn typed_collectors_from_snapshot(collectors: &[String]) -> Vec<CollectorMetadataV1> {
    collectors
        .iter()
        .map(|collector_id| CollectorMetadataV1 {
            collector_id: collector_id.clone(),
            collector_version: "1".to_string(),
            source_family: state_source_family_for_collector(collector_id).to_string(),
        })
        .collect()
}

fn state_source_family_for_collector(collector_id: &str) -> &'static str {
    match collector_id {
        "std::available_parallelism" | "runtime_cpu_capacity" => "rust_std",
        "procfs_meminfo" => "procfs",
        "cgroupfs_cpuset" | "cgroupfs_cpu_quota" | "cgroupfs_memory_boundary" => "cgroupfs",
        "statvfs_path_capacity" => "statvfs",
        "mountinfo_path_storage" => "mountinfo",
        "sysfs_block_media" => "sysfs",
        "path_link_probe" => "filesystem_probe",
        "path_storage_health_probe" => "storage_health_probe",
        "thermal_provider" => "thermal_provider",
        "hardware_sensor_provider" => "hardware_sensor_provider",
        "edac_memory_reliability" => "edac_memory_reliability",
        "nvidia_smi_gpu_reliability" => "nvidia_smi_gpu_reliability",
        "sysfs_topology" => "sysfs",
        _ => "unknown",
    }
}
