// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Typed host-contract sharing views.

use crate::artifacts::contract_v1::HostContractV1;
use crate::artifacts::validation_v1::validate_host_contract;
use crate::contract::HostContractPayloadV1;
use crate::redact::core_metadata_v1::{
    redact_accelerator_operability_v1, redact_claim_metadata_v1, redact_identity_summary_v1,
};
use crate::redact::extension_basis_v1::validate_contract_extension_basis_for_sharing_v1;
use crate::redact::extension_sections_v1::redact_extension_contract_v1;
use crate::redact::profile_v1::BuiltInRedactionProfileV1;
use crate::redact::provenance_v1::apply_redaction_metadata_v1;
use crate::redact::{RedactionError, RedactionErrorCode};

pub(crate) fn redact_contract_artifact(
    mut artifact: HostContractV1,
    profile: BuiltInRedactionProfileV1,
    redacted_at: &str,
) -> Result<HostContractV1, RedactionError> {
    let mut payload: HostContractPayloadV1 = serde_json::from_value(artifact.contract.clone())
        .map_err(|error| {
            RedactionError::new(
                RedactionErrorCode::ArtifactInputInvalid,
                "redaction_apply",
                format!("failed to decode host-contract payload for redaction: {error}"),
            )
        })?;

    validate_contract_extension_basis_for_sharing_v1(
        artifact.contract_basis.extension_basis.as_ref(),
        &payload.extension_contract,
        profile,
    )?;

    if profile.applies_fleet_redactions() {
        artifact.envelope.artifact_id = profile.artifact_id_placeholder("contract");
        artifact.host_alias = Some(profile.host_placeholder());
        replace_optional_label(&mut artifact.display_name, profile, "contract_display_name");
        replace_optional_label(
            &mut artifact.short_display_name,
            profile,
            "contract_short_display_name",
        );
    }

    if profile.applies_auditor_redactions() {
        let semantic_basis = &mut artifact.contract_basis.core_semantic_basis;
        semantic_basis.derivation_engine_id = profile.indexed_placeholder("derivation_engine", 0);
        semantic_basis.derivation_engine_version =
            profile.indexed_placeholder("derivation_engine_version", 0);
        replace_all(
            &mut semantic_basis.selected_policy_layers,
            &profile.policy_layer_placeholder(),
        );
        artifact.contract_basis.derivation_provenance.notes = None;
        redact_identity_summary_v1(&mut payload.core_contract.identity_summary, profile);
        redact_capability_classes(&mut payload, profile);
        if payload
            .core_contract
            .execution_constraints
            .container_runtime
            .is_some()
        {
            payload
                .core_contract
                .execution_constraints
                .container_runtime = Some(profile.indexed_placeholder("container_runtime", 0));
        }
        if let Some(operability) = payload
            .core_contract
            .accelerator_summary
            .operability
            .as_mut()
        {
            redact_accelerator_operability_v1(operability, profile);
        }
    }
    redact_extension_contract_v1(&mut payload.extension_contract, profile)?;

    artifact.contract = serde_json::to_value(payload).map_err(|error| {
        RedactionError::new(
            RedactionErrorCode::RedactionApplyFailed,
            "redaction_apply",
            format!("failed to encode redacted host-contract payload: {error}"),
        )
    })?;
    apply_redaction_metadata_v1(&mut artifact.envelope, profile, redacted_at)?;
    validate_host_contract(&artifact).map_err(output_error)?;
    Ok(artifact)
}

fn redact_capability_classes(
    payload: &mut HostContractPayloadV1,
    profile: BuiltInRedactionProfileV1,
) {
    payload.core_contract.capability_classes =
        std::mem::take(&mut payload.core_contract.capability_classes)
            .into_iter()
            .enumerate()
            .map(|(index, (_, mut claim))| {
                replace_indexed(&mut claim.rule_ids, profile, "capability_rule");
                replace_indexed(&mut claim.evidence_refs, profile, "capability_evidence");
                claim.summary = profile.indexed_placeholder("capability_summary", index);
                redact_claim_metadata_v1(&mut claim.claim_metadata, profile, "capability_claim");
                (
                    profile.indexed_placeholder("capability_class", index),
                    claim,
                )
            })
            .collect();
}

fn replace_optional_label(
    value: &mut Option<String>,
    profile: BuiltInRedactionProfileV1,
    class: &str,
) {
    if value.is_some() {
        *value = Some(profile.indexed_placeholder(class, 0));
    }
}

fn replace_indexed(values: &mut [String], profile: BuiltInRedactionProfileV1, class: &str) {
    for (index, value) in values.iter_mut().enumerate() {
        *value = profile.indexed_placeholder(class, index);
    }
}

fn replace_all(values: &mut [String], replacement: &str) {
    for value in values {
        *value = replacement.to_string();
    }
}

fn output_error(error: crate::artifacts::validation_v1::ArtifactValidationError) -> RedactionError {
    RedactionError::new(
        RedactionErrorCode::RedactionOutputInvalid,
        "redaction_emit",
        error.message,
    )
}
