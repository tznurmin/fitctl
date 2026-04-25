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
        "sysfs_topology" => "sysfs",
        _ => "unknown",
    }
}
