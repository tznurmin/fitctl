// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Redaction application across supported artifact families.

use std::path::Path;

use crate::artifacts::contract_v1::HostContractV1;
use crate::artifacts::envelope_v1::{ArtifactEnvelopeV1, RedactionEnvelopeV1};
use crate::artifacts::record_v1::{load_artifact_record_from_path, ArtifactRecordV1};
use crate::artifacts::service_profile_v1::ServiceProfileV1;
use crate::artifacts::state_v1::HostStateV1;
use crate::artifacts::survey_v1::{
    decode_host_survey_payload, encode_host_survey_payload, HostSurveyPayloadV1, HostSurveyV1,
};
use crate::artifacts::validation_report_v1::ValidationReportV1;
use crate::artifacts::validation_v1::{
    validate_host_contract, validate_host_state, validate_host_survey, validate_service_profile,
    validate_validation_report,
};
use crate::extensions::{
    decode_node_runtime_evidence_from_value, decode_python_runtime_evidence_from_value,
    redact_node_runtime_evidence_export_v1, redact_python_runtime_evidence_export_v1,
    NODE_RUNTIME_NAMESPACE, PYTHON_RUNTIME_NAMESPACE,
};
use crate::redact::profile_v1::BuiltInRedactionProfileV1;
use crate::redact::{RedactionError, RedactionErrorCode};
use crate::survey::SurveyFieldV1;

#[derive(Debug, Clone, PartialEq)]
pub struct RedactionRequestV1 {
    pub artifact: ArtifactRecordV1,
    pub profile: BuiltInRedactionProfileV1,
    pub redacted_at: String,
}

/// Load a typed artifact record for redaction.
pub fn load_artifact_record_for_redaction(path: &Path) -> Result<ArtifactRecordV1, RedactionError> {
    load_artifact_record_from_path(path).map_err(|error| {
        RedactionError::new(
            RedactionErrorCode::ArtifactInputInvalid,
            "artifact_load",
            error.message,
        )
    })
}

/// Apply one built-in redaction profile and emit a validated redacted artifact.
pub fn redact_artifact_v1(request: RedactionRequestV1) -> Result<ArtifactRecordV1, RedactionError> {
    if request.redacted_at.trim().is_empty() {
        return Err(RedactionError::new(
            RedactionErrorCode::RedactionApplyFailed,
            "redaction_apply",
            "redaction timestamp must be populated",
        ));
    }

    preflight_input(&request.artifact)?;

    match request.artifact {
        ArtifactRecordV1::Survey(artifact) => {
            redact_survey_artifact(artifact, request.profile, &request.redacted_at)
                .map(ArtifactRecordV1::Survey)
        }
        ArtifactRecordV1::Contract(artifact) => {
            redact_contract_artifact(artifact, request.profile, &request.redacted_at)
                .map(ArtifactRecordV1::Contract)
        }
        ArtifactRecordV1::ServiceProfile(artifact) => {
            redact_service_profile_artifact(artifact, request.profile, &request.redacted_at)
                .map(ArtifactRecordV1::ServiceProfile)
        }
        ArtifactRecordV1::State(artifact) => {
            redact_state_artifact(artifact, request.profile, &request.redacted_at)
                .map(ArtifactRecordV1::State)
        }
        ArtifactRecordV1::ValidationReport(artifact) => {
            redact_validation_report_artifact(artifact, request.profile, &request.redacted_at)
                .map(ArtifactRecordV1::ValidationReport)
        }
    }
}

fn preflight_input(artifact: &ArtifactRecordV1) -> Result<(), RedactionError> {
    let envelope = match artifact {
        ArtifactRecordV1::Survey(artifact) => &artifact.envelope,
        ArtifactRecordV1::Contract(artifact) => &artifact.envelope,
        ArtifactRecordV1::ServiceProfile(artifact) => &artifact.envelope,
        ArtifactRecordV1::State(artifact) => &artifact.envelope,
        ArtifactRecordV1::ValidationReport(artifact) => &artifact.envelope,
    };

    if envelope.redaction.is_some() {
        return Err(RedactionError::new(
            RedactionErrorCode::RedactionInputAlreadyRedacted,
            "redaction_preflight",
            "input artifact already carries redaction provenance",
        ));
    }

    Ok(())
}

fn redact_survey_artifact(
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
        payload.core_evidence.identity_summary.local_stable_id =
            profile.local_stable_identity_placeholder();
        payload
            .core_evidence
            .identity_summary
            .provenance_fingerprint = profile.provenance_fingerprint_placeholder();
        if let Some(storage) = payload.core_evidence.observations.storage.value.as_mut() {
            replace_each_string_with_indexed_placeholder(
                &mut storage.block_devices,
                &profile.block_device_placeholder(),
            );
            replace_each_string_with_indexed_placeholder(
                &mut storage.mounts,
                &profile.mount_path_placeholder(),
            );
            for (index, detail) in storage.block_device_details.iter_mut().enumerate() {
                detail.name = indexed_placeholder(&profile.block_device_placeholder(), index);
            }
            for (index, detail) in storage.mount_details.iter_mut().enumerate() {
                detail.path = indexed_placeholder(&profile.mount_path_placeholder(), index);
            }
        }
        if let Some(network) = payload.core_evidence.observations.network.value.as_mut() {
            replace_each_string_with_indexed_placeholder(
                &mut network.interfaces,
                &profile.network_interface_placeholder(),
            );
            for (index, detail) in network.interface_details.iter_mut().enumerate() {
                detail.name = indexed_placeholder(&profile.network_interface_placeholder(), index);
                detail.mac_address = None;
                detail.addresses.clear();
            }
        }
    }

    if profile.applies_external_redactions() {
        if let Some(cpu) = payload.core_evidence.observations.cpu.value.as_mut() {
            cpu.model = profile.cpu_model_placeholder();
        }
    }
    if let Some(value) = payload.extension_evidence.get_mut(PYTHON_RUNTIME_NAMESPACE) {
        let mut evidence = decode_python_runtime_evidence_from_value(value).map_err(|error| {
            RedactionError::new(
                RedactionErrorCode::ArtifactInputInvalid,
                "redaction_apply",
                error.message,
            )
        })?;
        redact_python_runtime_evidence_export_v1(&mut evidence, profile);
        *value = serde_json::to_value(evidence).map_err(|error| {
            RedactionError::new(
                RedactionErrorCode::RedactionApplyFailed,
                "redaction_apply",
                format!("failed to encode redacted Python runtime extension evidence: {error}"),
            )
        })?;
    }
    if let Some(value) = payload.extension_evidence.get_mut(NODE_RUNTIME_NAMESPACE) {
        let mut evidence = decode_node_runtime_evidence_from_value(value).map_err(|error| {
            RedactionError::new(
                RedactionErrorCode::ArtifactInputInvalid,
                "redaction_apply",
                error.message,
            )
        })?;
        redact_node_runtime_evidence_export_v1(&mut evidence, profile);
        *value = serde_json::to_value(evidence).map_err(|error| {
            RedactionError::new(
                RedactionErrorCode::RedactionApplyFailed,
                "redaction_apply",
                format!("failed to encode redacted Node runtime extension evidence: {error}"),
            )
        })?;
    }

    artifact.survey = encode_host_survey_payload(&payload).map_err(|error| {
        RedactionError::new(
            RedactionErrorCode::RedactionApplyFailed,
            "redaction_apply",
            format!("failed to encode redacted host-survey payload: {error}"),
        )
    })?;
    apply_redaction_metadata(&mut artifact.envelope, profile, redacted_at);
    validate_host_survey(&artifact).map_err(|error| {
        RedactionError::new(
            RedactionErrorCode::RedactionOutputInvalid,
            "redaction_emit",
            error.message,
        )
    })?;

    Ok(artifact)
}

fn redact_contract_artifact(
    mut artifact: HostContractV1,
    profile: BuiltInRedactionProfileV1,
    redacted_at: &str,
) -> Result<HostContractV1, RedactionError> {
    let mut payload: crate::contract::HostContractPayloadV1 =
        serde_json::from_value(artifact.contract.clone()).map_err(|error| {
            RedactionError::new(
                RedactionErrorCode::ArtifactInputInvalid,
                "redaction_apply",
                format!("failed to decode host-contract payload for redaction: {error}"),
            )
        })?;

    if profile.applies_fleet_redactions() {
        artifact.envelope.artifact_id = profile.artifact_id_placeholder("contract");
    }
    if profile.applies_external_redactions() {
        replace_each_string(
            &mut artifact
                .contract_basis
                .core_semantic_basis
                .selected_policy_layers,
            &profile.policy_layer_placeholder(),
        );
    }
    if profile.applies_auditor_redactions() {
        payload.core_contract.identity_summary.local_stable_id =
            profile.local_stable_identity_placeholder();
        payload
            .core_contract
            .identity_summary
            .provenance_fingerprint = profile.provenance_fingerprint_placeholder();
    }

    artifact.contract = serde_json::to_value(payload).map_err(|error| {
        RedactionError::new(
            RedactionErrorCode::RedactionApplyFailed,
            "redaction_apply",
            format!("failed to encode redacted host-contract payload: {error}"),
        )
    })?;

    apply_redaction_metadata(&mut artifact.envelope, profile, redacted_at);
    validate_host_contract(&artifact).map_err(|error| {
        RedactionError::new(
            RedactionErrorCode::RedactionOutputInvalid,
            "redaction_emit",
            error.message,
        )
    })?;

    Ok(artifact)
}

fn redact_service_profile_artifact(
    mut artifact: ServiceProfileV1,
    profile: BuiltInRedactionProfileV1,
    redacted_at: &str,
) -> Result<ServiceProfileV1, RedactionError> {
    apply_redaction_metadata(&mut artifact.envelope, profile, redacted_at);
    validate_service_profile(&artifact).map_err(|error| {
        RedactionError::new(
            RedactionErrorCode::RedactionOutputInvalid,
            "redaction_emit",
            error.message,
        )
    })?;

    Ok(artifact)
}

fn redact_state_artifact(
    mut artifact: HostStateV1,
    profile: BuiltInRedactionProfileV1,
    redacted_at: &str,
) -> Result<HostStateV1, RedactionError> {
    if profile.applies_fleet_redactions() {
        let host_placeholder = profile.host_placeholder();
        artifact.envelope.artifact_id = profile.artifact_id_placeholder("state");
        artifact.state.snapshot_id = host_placeholder.clone();
        artifact.state.host_alias = host_placeholder;
    }
    if profile.applies_auditor_redactions() {
        artifact.state.source_ref = profile.source_ref_placeholder();
    }

    apply_redaction_metadata(&mut artifact.envelope, profile, redacted_at);
    validate_host_state(&artifact).map_err(|error| {
        RedactionError::new(
            RedactionErrorCode::RedactionOutputInvalid,
            "redaction_emit",
            error.message,
        )
    })?;

    Ok(artifact)
}

fn redact_validation_report_artifact(
    mut artifact: ValidationReportV1,
    profile: BuiltInRedactionProfileV1,
    redacted_at: &str,
) -> Result<ValidationReportV1, RedactionError> {
    if profile.applies_fleet_redactions() {
        artifact.envelope.artifact_id = profile.artifact_id_placeholder("validation-report");
        artifact.validation_basis.contract_artifact_id =
            profile.artifact_id_placeholder("contract");
        if let Some(state_artifact_id) = artifact.validation_basis.state_artifact_id.as_mut() {
            *state_artifact_id = profile.artifact_id_placeholder("state");
        }
    }
    if profile.applies_external_redactions() {
        replace_each_string(
            &mut artifact.report.policy_refs,
            &profile.policy_ref_placeholder(),
        );
        replace_each_string(
            &mut artifact.report.evidence_refs,
            &profile.evidence_ref_placeholder(),
        );
    }

    apply_redaction_metadata(&mut artifact.envelope, profile, redacted_at);
    validate_validation_report(&artifact).map_err(|error| {
        RedactionError::new(
            RedactionErrorCode::RedactionOutputInvalid,
            "redaction_emit",
            error.message,
        )
    })?;

    Ok(artifact)
}

fn apply_redaction_metadata(
    envelope: &mut ArtifactEnvelopeV1,
    profile: BuiltInRedactionProfileV1,
    redacted_at: &str,
) {
    envelope.redaction = Some(RedactionEnvelopeV1 {
        profile_id: profile.as_str().to_string(),
        redacted_at: redacted_at.to_string(),
    });
    envelope.signatures.clear();
}

fn replace_string_field(field: &mut SurveyFieldV1<String>, replacement: &str) {
    if let Some(value) = field.value.as_mut() {
        *value = replacement.to_string();
    }
}

fn replace_each_string(values: &mut [String], replacement: &str) {
    for value in values {
        *value = replacement.to_string();
    }
}

fn replace_each_string_with_indexed_placeholder(values: &mut [String], replacement: &str) {
    for (index, value) in values.iter_mut().enumerate() {
        *value = indexed_placeholder(replacement, index);
    }
}

fn indexed_placeholder(base: &str, index: usize) -> String {
    format!("{base}:{index}")
}
