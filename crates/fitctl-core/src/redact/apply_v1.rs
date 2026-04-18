// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Redaction application across supported artifact families.

use std::path::Path;

use crate::artifacts::config_bundle_v1::ConfigBundleV1;
use crate::artifacts::contract_v1::HostContractV1;
use crate::artifacts::decision_bundle_v1::DecisionBundleV1;
use crate::artifacts::envelope_v1::{ArtifactEnvelopeV1, RedactionEnvelopeV1};
use crate::artifacts::recommendation_report_v1::RecommendationReportV1;
use crate::artifacts::record_v1::{load_artifact_record_from_path, ArtifactRecordV1};
use crate::artifacts::semantic_hash_v1::{
    semantic_hash_hex_for_config_bundle, semantic_hash_hex_for_contract,
    semantic_hash_hex_for_recommendation_report, semantic_hash_hex_for_state,
    semantic_hash_hex_for_validation_report,
};
use crate::artifacts::service_profile_v1::ServiceProfileV1;
use crate::artifacts::state_v1::HostStateV1;
use crate::artifacts::survey_v1::{
    decode_host_survey_payload, encode_host_survey_payload, HostSurveyPayloadV1, HostSurveyV1,
};
use crate::artifacts::validation_report_v1::ValidationReportV1;
use crate::artifacts::validation_v1::{
    validate_config_bundle, validate_decision_bundle, validate_host_contract, validate_host_state,
    validate_host_survey, validate_recommendation_report, validate_service_profile,
    validate_validation_report,
};
use crate::extensions::{
    decode_cuda_runtime_evidence_from_value, decode_node_runtime_evidence_from_value,
    decode_python_runtime_evidence_from_value, redact_cuda_runtime_evidence_export_v1,
    redact_node_runtime_evidence_export_v1, redact_python_runtime_evidence_export_v1,
    CUDA_RUNTIME_NAMESPACE, NODE_RUNTIME_NAMESPACE, PYTHON_RUNTIME_NAMESPACE,
};
use crate::redact::profile_v1::BuiltInRedactionProfileV1;
use crate::redact::{RedactionError, RedactionErrorCode};
use crate::survey::SurveyFieldV1;
use crate::verify::{validate_verification_bundle_v1, VerificationBundleV1};

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
        ArtifactRecordV1::ConfigBundle(artifact) => {
            redact_config_bundle_artifact(artifact, request.profile, &request.redacted_at)
                .map(ArtifactRecordV1::ConfigBundle)
        }
        ArtifactRecordV1::DecisionBundle(artifact) => {
            redact_decision_bundle_artifact(artifact, request.profile, &request.redacted_at)
                .map(ArtifactRecordV1::DecisionBundle)
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
        ArtifactRecordV1::ConfigBundle(artifact) => &artifact.envelope,
        ArtifactRecordV1::DecisionBundle(artifact) => &artifact.envelope,
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
    if let Some(value) = payload.extension_evidence.get_mut(CUDA_RUNTIME_NAMESPACE) {
        let mut evidence = decode_cuda_runtime_evidence_from_value(value).map_err(|error| {
            RedactionError::new(
                RedactionErrorCode::ArtifactInputInvalid,
                "redaction_apply",
                error.message,
            )
        })?;
        redact_cuda_runtime_evidence_export_v1(&mut evidence, profile);
        *value = serde_json::to_value(evidence).map_err(|error| {
            RedactionError::new(
                RedactionErrorCode::RedactionApplyFailed,
                "redaction_apply",
                format!("failed to encode redacted CUDA runtime extension evidence: {error}"),
            )
        })?;
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
        let host_placeholder = profile.host_placeholder();
        artifact.envelope.artifact_id = profile.artifact_id_placeholder("contract");
        artifact.host_alias = Some(host_placeholder.clone());
        artifact.display_name = artifact
            .short_display_name
            .as_ref()
            .map(|label| format!("{host_placeholder} / {label}"));
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

fn redact_config_bundle_artifact(
    mut artifact: ConfigBundleV1,
    profile: BuiltInRedactionProfileV1,
    redacted_at: &str,
) -> Result<ConfigBundleV1, RedactionError> {
    validate_config_bundle(&artifact).map_err(map_redaction_input_validation_error)?;

    if let Some(service_profile) = artifact.config_bundle.service_profile.take() {
        artifact.config_bundle.service_profile = Some(redact_service_profile_artifact(
            service_profile,
            profile,
            redacted_at,
        )?);
    }

    if profile.applies_fleet_redactions() {
        artifact.envelope.artifact_id = profile.artifact_id_placeholder("config-bundle");
    }

    apply_redaction_metadata(&mut artifact.envelope, profile, redacted_at);
    validate_config_bundle(&artifact).map_err(map_redaction_output_validation_error)?;

    Ok(artifact)
}

fn redact_decision_bundle_artifact(
    mut artifact: DecisionBundleV1,
    profile: BuiltInRedactionProfileV1,
    redacted_at: &str,
) -> Result<DecisionBundleV1, RedactionError> {
    validate_decision_bundle(&artifact).map_err(map_redaction_input_validation_error)?;

    artifact.bundle.contract =
        redact_contract_artifact(artifact.bundle.contract, profile, redacted_at)?;
    artifact.bundle.validation_report = redact_embedded_validation_report_artifact(
        artifact.bundle.validation_report,
        &artifact.bundle.contract,
        artifact.bundle.state.as_ref(),
        profile,
        redacted_at,
    )?;
    artifact.bundle.state = match artifact.bundle.state.take() {
        Some(state) => Some(redact_state_artifact(state, profile, redacted_at)?),
        None => None,
    };
    artifact.bundle.validation_report = retarget_validation_report_lineage(
        artifact.bundle.validation_report,
        &artifact.bundle.contract,
        artifact.bundle.state.as_ref(),
    )?;

    artifact.bundle.config_bundle = match artifact.bundle.config_bundle.take() {
        Some(config_bundle) => Some(redact_config_bundle_artifact(
            config_bundle,
            profile,
            redacted_at,
        )?),
        None => None,
    };
    artifact.bundle.verification_bundle = match artifact.bundle.verification_bundle.take() {
        Some(verification_bundle) => Some(redact_embedded_verification_bundle(
            verification_bundle,
            &artifact.bundle.contract,
            profile,
        )?),
        None => None,
    };
    artifact.bundle.recommendation_report = match artifact.bundle.recommendation_report.take() {
        Some(recommendation_report) => Some(redact_embedded_recommendation_report_artifact(
            recommendation_report,
            &artifact.bundle.validation_report,
            artifact.bundle.state.as_ref(),
            profile,
            redacted_at,
        )?),
        None => None,
    };

    artifact.bundle_basis.validation_report_artifact_id = artifact
        .bundle
        .validation_report
        .envelope
        .artifact_id
        .clone();
    artifact.bundle_basis.validation_report_semantic_hash =
        semantic_hash_hex_for_validation_report(&artifact.bundle.validation_report)
            .map_err(map_redaction_artifact_projection_error)?;
    artifact.bundle_basis.contract_artifact_id =
        artifact.bundle.contract.envelope.artifact_id.clone();
    artifact.bundle_basis.contract_semantic_hash =
        semantic_hash_hex_for_contract(&artifact.bundle.contract)
            .map_err(map_redaction_artifact_projection_error)?;
    artifact.bundle_basis.state_artifact_id = artifact
        .bundle
        .state
        .as_ref()
        .map(|state| state.envelope.artifact_id.clone());
    artifact.bundle_basis.state_semantic_hash = match artifact.bundle.state.as_ref() {
        Some(state) => Some(
            semantic_hash_hex_for_state(state).map_err(map_redaction_artifact_projection_error)?,
        ),
        None => None,
    };
    artifact.bundle_basis.config_bundle_artifact_id = artifact
        .bundle
        .config_bundle
        .as_ref()
        .map(|bundle| bundle.envelope.artifact_id.clone());
    artifact.bundle_basis.config_bundle_semantic_hash = match artifact.bundle.config_bundle.as_ref()
    {
        Some(bundle) => Some(
            semantic_hash_hex_for_config_bundle(bundle)
                .map_err(map_redaction_artifact_projection_error)?,
        ),
        None => None,
    };
    artifact.bundle_basis.verification_bundle_id = artifact
        .bundle
        .verification_bundle
        .as_ref()
        .map(|bundle| bundle.bundle_id.clone());
    artifact.bundle_basis.recommendation_report_artifact_id = artifact
        .bundle
        .recommendation_report
        .as_ref()
        .map(|report| report.envelope.artifact_id.clone());
    artifact.bundle_basis.recommendation_report_semantic_hash =
        match artifact.bundle.recommendation_report.as_ref() {
            Some(report) => Some(
                semantic_hash_hex_for_recommendation_report(report)
                    .map_err(map_redaction_artifact_projection_error)?,
            ),
            None => None,
        };

    if profile.applies_fleet_redactions() {
        artifact.envelope.artifact_id = profile.artifact_id_placeholder("decision-bundle");
    }

    apply_redaction_metadata(&mut artifact.envelope, profile, redacted_at);
    validate_decision_bundle(&artifact).map_err(map_redaction_output_validation_error)?;

    Ok(artifact)
}

fn redact_embedded_validation_report_artifact(
    artifact: ValidationReportV1,
    contract: &HostContractV1,
    state: Option<&HostStateV1>,
    profile: BuiltInRedactionProfileV1,
    redacted_at: &str,
) -> Result<ValidationReportV1, RedactionError> {
    let redacted = redact_validation_report_artifact(artifact, profile, redacted_at)?;
    retarget_validation_report_lineage(redacted, contract, state)
}

fn retarget_validation_report_lineage(
    mut artifact: ValidationReportV1,
    contract: &HostContractV1,
    state: Option<&HostStateV1>,
) -> Result<ValidationReportV1, RedactionError> {
    artifact.validation_basis.contract_artifact_id = contract.envelope.artifact_id.clone();
    artifact.validation_basis.contract_semantic_hash = semantic_hash_hex_for_contract(contract)
        .map_err(map_redaction_artifact_projection_error)?;

    match state {
        Some(state) => {
            artifact.validation_basis.state_artifact_id = Some(state.envelope.artifact_id.clone());
            artifact.validation_basis.state_semantic_hash = Some(
                semantic_hash_hex_for_state(state)
                    .map_err(map_redaction_artifact_projection_error)?,
            );
        }
        None => {
            artifact.validation_basis.state_artifact_id = None;
            artifact.validation_basis.state_semantic_hash = None;
        }
    }

    validate_validation_report(&artifact).map_err(map_redaction_output_validation_error)?;
    Ok(artifact)
}

fn redact_embedded_recommendation_report_artifact(
    mut artifact: RecommendationReportV1,
    validation_report: &ValidationReportV1,
    state: Option<&HostStateV1>,
    profile: BuiltInRedactionProfileV1,
    redacted_at: &str,
) -> Result<RecommendationReportV1, RedactionError> {
    if profile.applies_fleet_redactions() {
        artifact.envelope.artifact_id = profile.artifact_id_placeholder("recommendation-report");
    }

    artifact.recommendation_basis.validation_report_artifact_id =
        validation_report.envelope.artifact_id.clone();
    artifact
        .recommendation_basis
        .validation_report_semantic_hash =
        semantic_hash_hex_for_validation_report(validation_report)
            .map_err(map_redaction_artifact_projection_error)?;
    artifact.recommendation_basis.validation_verdict = validation_report.report.verdict;

    match state {
        Some(state) => {
            artifact.recommendation_basis.state_artifact_id =
                Some(state.envelope.artifact_id.clone());
            artifact.recommendation_basis.state_semantic_hash = Some(
                semantic_hash_hex_for_state(state)
                    .map_err(map_redaction_artifact_projection_error)?,
            );
        }
        None => {
            artifact.recommendation_basis.state_artifact_id = None;
            artifact.recommendation_basis.state_semantic_hash = None;
        }
    }

    apply_redaction_metadata(&mut artifact.envelope, profile, redacted_at);
    validate_recommendation_report(&artifact).map_err(map_redaction_output_validation_error)?;

    Ok(artifact)
}

fn redact_embedded_verification_bundle(
    mut bundle: VerificationBundleV1,
    contract: &HostContractV1,
    profile: BuiltInRedactionProfileV1,
) -> Result<VerificationBundleV1, RedactionError> {
    if profile.applies_fleet_redactions() {
        bundle.bundle_id = profile.artifact_id_placeholder("verification-bundle");
    }

    let contract_semantic_hash = semantic_hash_hex_for_contract(contract)
        .map_err(map_redaction_artifact_projection_error)?;
    bundle.artifact_schema_id = contract.envelope.schema_id.clone();
    bundle.artifact_id = contract.envelope.artifact_id.clone();
    bundle.artifact_semantic_hash = contract_semantic_hash.clone();
    bundle.verification_report.artifact_schema_id = contract.envelope.schema_id.clone();
    bundle.verification_report.artifact_id = contract.envelope.artifact_id.clone();

    validate_verification_bundle_v1(&bundle).map_err(|error| {
        RedactionError::new(
            RedactionErrorCode::RedactionOutputInvalid,
            "redaction_emit",
            error.message,
        )
    })?;

    Ok(bundle)
}

fn map_redaction_input_validation_error(
    error: crate::artifacts::validation_v1::ArtifactValidationError,
) -> RedactionError {
    RedactionError::new(
        RedactionErrorCode::ArtifactInputInvalid,
        "redaction_apply",
        error.message,
    )
}

fn map_redaction_output_validation_error(
    error: crate::artifacts::validation_v1::ArtifactValidationError,
) -> RedactionError {
    RedactionError::new(
        RedactionErrorCode::RedactionOutputInvalid,
        "redaction_emit",
        error.message,
    )
}

fn map_redaction_artifact_projection_error(
    error: crate::artifacts::validation_v1::ArtifactValidationError,
) -> RedactionError {
    RedactionError::new(
        RedactionErrorCode::RedactionApplyFailed,
        "redaction_apply",
        error.message,
    )
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
