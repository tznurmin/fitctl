// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Redaction for host-state and standalone thermal evidence artifacts.

use crate::artifacts::state_v1::{HostStateV1, StateFieldV1};
use crate::artifacts::thermal_evidence_v1::ThermalEvidenceV1;
use crate::artifacts::validation_v1::{validate_host_state, validate_thermal_evidence};
use crate::redact::core_metadata_v1::redact_claim_metadata_v1;
use crate::redact::extension_sections_v1::redact_extension_state_v1;
use crate::redact::path_resources_v1::redact_state_path_resources_v1;
use crate::redact::profile_v1::BuiltInRedactionProfileV1;
use crate::redact::provenance_v1::apply_redaction_metadata_v1;
use crate::redact::{RedactionError, RedactionErrorCode};

pub(crate) fn redact_state_artifact(
    mut artifact: HostStateV1,
    profile: BuiltInRedactionProfileV1,
    redacted_at: &str,
) -> Result<HostStateV1, RedactionError> {
    if profile.applies_fleet_redactions() {
        let host_placeholder = profile.host_placeholder();
        artifact.envelope.artifact_id = profile.artifact_id_placeholder("state");
        artifact.state.snapshot_id = host_placeholder.clone();
        artifact.state.host_alias = host_placeholder;
        if let Some(local_identity) = artifact.state.local_identity.as_mut() {
            local_identity.local_stable_id = profile.local_stable_identity_placeholder();
        }
    }
    if profile.applies_auditor_redactions() {
        artifact.state.local_identity = None;
        artifact.state.source_ref = profile.source_ref_placeholder();
        let metadata = &mut artifact.state.core_state.section_metadata;
        redact_claim_metadata_v1(&mut metadata.resources, profile, "state_resources");
        redact_claim_metadata_v1(
            &mut metadata.path_resources,
            profile,
            "state_path_resources",
        );
        redact_claim_metadata_v1(&mut metadata.boundaries, profile, "state_boundaries");
        redact_claim_metadata_v1(&mut metadata.topology, profile, "state_topology");
        redact_claim_metadata_v1(&mut metadata.operability, profile, "state_operability");
        redact_state_path_resources_v1(&mut artifact.state.core_state.path_resources, profile);
        for (index, class) in artifact
            .state
            .core_state
            .operability
            .degraded_capability_classes
            .iter_mut()
            .enumerate()
        {
            *class = profile.indexed_placeholder("degraded_capability_class", index);
        }
        if let Some(thermal_resources) = artifact.state.core_state.thermal_resources.as_mut() {
            redact_thermal_resources(thermal_resources, profile);
        }
        if let Some(memory_reliability) = artifact.state.core_state.memory_reliability.as_mut() {
            redact_memory_reliability(memory_reliability, profile);
        }
        if let Some(gpu_reliability) = artifact.state.core_state.gpu_reliability.as_mut() {
            redact_gpu_reliability(gpu_reliability, profile);
        }
    }
    redact_extension_state_v1(&mut artifact.state.extension_state, profile)?;

    apply_redaction_metadata_v1(&mut artifact.envelope, profile, redacted_at)?;
    validate_host_state(&artifact).map_err(output_error)?;
    Ok(artifact)
}

fn redact_memory_reliability(
    memory_reliability: &mut crate::artifacts::state_v1::HostStateMemoryReliabilityV1,
    profile: BuiltInRedactionProfileV1,
) {
    for (index, provider) in memory_reliability.providers.iter_mut().enumerate() {
        provider.provider_id = indexed_placeholder(&profile.thermal_provider_placeholder(), index);
        if provider.source.is_some() {
            provider.source = Some("redacted:memory_reliability_source".to_string());
        }
        if provider.diagnostics.is_some() {
            provider.diagnostics = Some("redacted:memory_reliability_diagnostic".to_string());
        }
    }
}

fn redact_gpu_reliability(
    gpu_reliability: &mut crate::artifacts::state_v1::HostStateGpuReliabilityV1,
    profile: BuiltInRedactionProfileV1,
) {
    for (index, provider) in gpu_reliability.providers.iter_mut().enumerate() {
        provider.provider_id = indexed_placeholder(&profile.thermal_provider_placeholder(), index);
        if provider.diagnostics.is_some() {
            provider.diagnostics = Some("redacted:gpu_reliability_diagnostic".to_string());
        }
    }
    for (index, device) in gpu_reliability.devices.iter_mut().enumerate() {
        replace_observed_string(
            &mut device.gpu_uuid,
            &indexed_placeholder(&profile.storage_identity_placeholder(), index),
        );
    }
}

fn redact_thermal_resources(
    thermal: &mut crate::artifacts::state_v1::HostStateThermalResourcesV1,
    profile: BuiltInRedactionProfileV1,
) {
    if thermal.collector_host.host_alias.is_some() {
        thermal.collector_host.host_alias = Some(profile.host_placeholder());
    }
    if thermal.collector_host.local_stable_id.is_some() {
        thermal.collector_host.local_stable_id = Some(profile.local_stable_identity_placeholder());
    }
    let provider_ids = thermal
        .providers
        .iter()
        .map(|provider| provider.provider_id.clone())
        .collect::<Vec<_>>();
    for (index, provider) in thermal.providers.iter_mut().enumerate() {
        provider.provider_id = indexed_placeholder(&profile.thermal_provider_placeholder(), index);
        if provider.diagnostics.is_some() {
            provider.diagnostics = Some("redacted:thermal_provider_diagnostic".to_string());
        }
        if let Some(host_id) = provider.evidence_target.host_id.as_mut() {
            *host_id = profile.host_placeholder();
        }
    }
    for (index, reading) in thermal.readings.iter_mut().enumerate() {
        reading.sensor_id = indexed_placeholder(&profile.thermal_sensor_placeholder(), index);
        reading.provider_id = indexed_placeholder(
            &profile.thermal_provider_placeholder(),
            provider_index(&provider_ids, &reading.provider_id),
        );
        reading.raw_label = indexed_placeholder(&profile.thermal_sensor_placeholder(), index);
        if reading.sensor_alias.is_some() {
            reading.sensor_alias = Some(indexed_placeholder(
                &profile.thermal_sensor_placeholder(),
                index,
            ));
        }
        if reading.source.is_some() {
            reading.source = Some("redacted:thermal_source".to_string());
        }
        if let Some(host_id) = reading.evidence_target.host_id.as_mut() {
            *host_id = profile.host_placeholder();
        }
    }
}

pub(crate) fn redact_thermal_evidence_artifact(
    mut artifact: ThermalEvidenceV1,
    profile: BuiltInRedactionProfileV1,
    redacted_at: &str,
) -> Result<ThermalEvidenceV1, RedactionError> {
    if profile.applies_fleet_redactions() {
        artifact.envelope.artifact_id = profile.artifact_id_placeholder("thermal-evidence");
    }
    if profile.applies_auditor_redactions() {
        redact_thermal_resources(&mut artifact.thermal_evidence, profile);
    }
    apply_redaction_metadata_v1(&mut artifact.envelope, profile, redacted_at)?;
    validate_thermal_evidence(&artifact).map_err(output_error)?;
    Ok(artifact)
}

fn provider_index(provider_ids: &[String], provider_id: &str) -> usize {
    provider_ids
        .iter()
        .position(|candidate| candidate == provider_id)
        .unwrap_or_default()
}

fn replace_observed_string(field: &mut StateFieldV1<String>, replacement: &str) {
    if field.value.is_some() {
        field.value = Some(replacement.to_string());
    }
}

fn indexed_placeholder(base: &str, index: usize) -> String {
    format!("{base}:{index}")
}

fn output_error(error: crate::artifacts::validation_v1::ArtifactValidationError) -> RedactionError {
    RedactionError::new(
        RedactionErrorCode::RedactionOutputInvalid,
        "redaction_emit",
        error.message,
    )
}
