// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Typed host-survey sharing views.

use crate::artifacts::survey_v1::{
    decode_host_survey_payload, encode_host_survey_payload, HostSurveyPayloadV1, HostSurveyV1,
    SurveySectionMetadataV1,
};
use crate::artifacts::validation_v1::validate_host_survey;
use crate::redact::core_metadata_v1::{
    redact_accelerator_operability_v1, redact_claim_metadata_v1, redact_identity_summary_v1,
};
use crate::redact::extension_sections_v1::redact_extension_evidence_v1;
use crate::redact::profile_v1::BuiltInRedactionProfileV1;
use crate::redact::provenance_v1::apply_redaction_metadata_v1;
use crate::redact::{RedactionError, RedactionErrorCode};
use crate::survey::SurveyFieldV1;

pub(crate) fn redact_survey_artifact(
    mut artifact: HostSurveyV1,
    profile: BuiltInRedactionProfileV1,
    redacted_at: &str,
) -> Result<HostSurveyV1, RedactionError> {
    let mut payload: HostSurveyPayloadV1 =
        decode_host_survey_payload(&artifact.survey).map_err(|error| {
            RedactionError::new(
                RedactionErrorCode::ArtifactInputInvalid,
                "redaction_apply",
                format!("failed to decode host-survey payload for redaction: {error}"),
            )
        })?;

    if profile.applies_fleet_redactions() {
        let host_placeholder = profile.host_placeholder();
        payload.snapshot_id = host_placeholder.clone();
        payload.host_alias = host_placeholder.clone();
        replace_string_field(
            &mut payload.core_evidence.observations.hostname,
            &host_placeholder,
        );
        artifact.envelope.artifact_id = profile.artifact_id_placeholder("survey");
    }

    if profile.applies_auditor_redactions() {
        payload.source_ref = profile.source_ref_placeholder();
        redact_survey_section_metadata(&mut payload.core_evidence.section_metadata, profile);
        redact_identity_summary_v1(&mut payload.core_evidence.identity_summary, profile);
        if payload
            .core_evidence
            .execution_context
            .container_runtime
            .is_some()
        {
            payload.core_evidence.execution_context.container_runtime =
                Some(profile.indexed_placeholder("container_runtime", 0));
        }
        for (index, note) in payload
            .core_evidence
            .execution_context
            .notes
            .iter_mut()
            .enumerate()
        {
            *note = profile.indexed_placeholder("execution_note", index);
        }
        redact_storage_and_network(&mut payload, profile);
        if let Some(accelerators) = payload
            .core_evidence
            .observations
            .accelerators
            .value
            .as_mut()
        {
            for device in &mut accelerators.devices {
                device.pci_address = None;
            }
            if let Some(operability) = accelerators.operability.as_mut() {
                redact_accelerator_operability_v1(operability, profile);
            }
        }
    }

    if profile.applies_external_redactions() {
        if let Some(cpu) = payload.core_evidence.observations.cpu.value.as_mut() {
            cpu.model = profile.cpu_model_placeholder();
        }
    }
    redact_extension_evidence_v1(&mut payload.extension_evidence, profile)?;

    artifact.survey = encode_host_survey_payload(&payload).map_err(|error| {
        RedactionError::new(
            RedactionErrorCode::RedactionApplyFailed,
            "redaction_apply",
            format!("failed to encode redacted host-survey payload: {error}"),
        )
    })?;
    apply_redaction_metadata_v1(&mut artifact.envelope, profile, redacted_at)?;
    validate_host_survey(&artifact).map_err(output_error)?;
    Ok(artifact)
}

fn redact_survey_section_metadata(
    metadata: &mut SurveySectionMetadataV1,
    profile: BuiltInRedactionProfileV1,
) {
    redact_claim_metadata_v1(
        &mut metadata.execution_context,
        profile,
        "execution_context",
    );
    redact_claim_metadata_v1(&mut metadata.hostname, profile, "hostname");
    redact_claim_metadata_v1(&mut metadata.cpu, profile, "cpu");
    redact_claim_metadata_v1(&mut metadata.memory, profile, "memory");
    redact_claim_metadata_v1(&mut metadata.storage, profile, "storage");
    redact_claim_metadata_v1(&mut metadata.network, profile, "network");
    redact_claim_metadata_v1(&mut metadata.accelerators, profile, "accelerators");
    redact_claim_metadata_v1(&mut metadata.topology, profile, "topology");
}

fn redact_storage_and_network(
    payload: &mut HostSurveyPayloadV1,
    profile: BuiltInRedactionProfileV1,
) {
    if let Some(storage) = payload.core_evidence.observations.storage.value.as_mut() {
        replace_each_string(
            &mut storage.block_devices,
            &profile.block_device_placeholder(),
        );
        replace_each_string(&mut storage.mounts, &profile.mount_path_placeholder());
        for (index, detail) in storage.block_device_details.iter_mut().enumerate() {
            detail.name = format!("{}:{index}", profile.block_device_placeholder());
        }
        for (index, detail) in storage.mount_details.iter_mut().enumerate() {
            detail.path = format!("{}:{index}", profile.mount_path_placeholder());
        }
    }
    if let Some(network) = payload.core_evidence.observations.network.value.as_mut() {
        replace_each_string(
            &mut network.interfaces,
            &profile.network_interface_placeholder(),
        );
        for (index, detail) in network.interface_details.iter_mut().enumerate() {
            detail.name = format!("{}:{index}", profile.network_interface_placeholder());
            detail.mac_address = None;
            detail.addresses.clear();
        }
    }
}

fn replace_string_field(field: &mut SurveyFieldV1<String>, replacement: &str) {
    if let Some(value) = field.value.as_mut() {
        *value = replacement.to_string();
    }
}

fn replace_each_string(values: &mut [String], base: &str) {
    for (index, value) in values.iter_mut().enumerate() {
        *value = format!("{base}:{index}");
    }
}

fn output_error(error: crate::artifacts::validation_v1::ArtifactValidationError) -> RedactionError {
    RedactionError::new(
        RedactionErrorCode::RedactionOutputInvalid,
        "redaction_emit",
        error.message,
    )
}
