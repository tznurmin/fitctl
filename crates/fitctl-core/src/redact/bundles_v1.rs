// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Redaction and lineage repair for configuration and decision bundles.

use crate::artifacts::config_bundle_v1::ConfigBundleV1;
use crate::artifacts::contract_v1::HostContractV1;
use crate::artifacts::decision_bundle_v1::DecisionBundleV1;
use crate::artifacts::recommendation_report_v1::RecommendationReportV1;
use crate::artifacts::semantic_hash_v1::{
    semantic_hash_hex_for_config_bundle, semantic_hash_hex_for_contract,
    semantic_hash_hex_for_recommendation_report, semantic_hash_hex_for_service_profile,
    semantic_hash_hex_for_state, semantic_hash_hex_for_validation_report,
};
use crate::artifacts::service_profile_v1::ServiceProfileV1;
use crate::artifacts::state_v1::HostStateV1;
use crate::artifacts::validation_report_v1::ValidationReportV1;
use crate::artifacts::validation_v1::{
    validate_config_bundle, validate_decision_bundle, validate_recommendation_report,
    validate_validation_report,
};
use crate::redact::apply_v1::redact_validation_report_artifact;
use crate::redact::auxiliary_reports_v1::apply_recommendation_report_profile_v1;
use crate::redact::config_bundle_lineage_v1::repair_config_bundle_service_profile_lineage;
use crate::redact::contract_artifact_v1::redact_contract_artifact;
use crate::redact::profile_v1::BuiltInRedactionProfileV1;
use crate::redact::provenance_v1::apply_auxiliary_redaction_metadata_v1;
use crate::redact::runtime_artifacts_v1::redact_state_artifact;
use crate::redact::service_profile_artifact_v1::redact_service_profile_artifact;
use crate::redact::{RedactionError, RedactionErrorCode};
use crate::verify::{validate_verification_bundle_v1, VerificationBundleV1};

pub(crate) fn redact_config_bundle_artifact(
    mut artifact: ConfigBundleV1,
    profile: BuiltInRedactionProfileV1,
    redacted_at: &str,
) -> Result<ConfigBundleV1, RedactionError> {
    validate_config_bundle(&artifact).map_err(map_input_validation_error)?;

    if let Some(service_profile) = artifact.config_bundle.service_profile.take() {
        artifact.config_bundle.service_profile = Some(redact_service_profile_artifact(
            service_profile,
            profile,
            redacted_at,
        )?);
    }
    repair_config_bundle_service_profile_lineage(&mut artifact)?;

    if profile.applies_fleet_redactions() {
        artifact.envelope.artifact_id = profile.artifact_id_placeholder("config-bundle");
    }

    apply_auxiliary_redaction_metadata_v1(&mut artifact.envelope, profile, redacted_at)?;
    validate_config_bundle(&artifact).map_err(map_output_validation_error)?;
    Ok(artifact)
}

pub(crate) fn redact_decision_bundle_artifact(
    mut artifact: DecisionBundleV1,
    profile: BuiltInRedactionProfileV1,
    redacted_at: &str,
) -> Result<DecisionBundleV1, RedactionError> {
    validate_decision_bundle(&artifact).map_err(map_input_validation_error)?;

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
    if let Some(service_profile) = artifact
        .bundle
        .config_bundle
        .as_ref()
        .and_then(|bundle| bundle.config_bundle.service_profile.as_ref())
    {
        retarget_validation_service_profile_lineage(
            &mut artifact.bundle.validation_report,
            service_profile,
        )?;
    }
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

    refresh_decision_bundle_basis(&mut artifact)?;
    if profile.applies_fleet_redactions() {
        artifact.envelope.artifact_id = profile.artifact_id_placeholder("decision-bundle");
    }
    apply_auxiliary_redaction_metadata_v1(&mut artifact.envelope, profile, redacted_at)?;
    validate_decision_bundle(&artifact).map_err(map_output_validation_error)?;
    Ok(artifact)
}

fn refresh_decision_bundle_basis(artifact: &mut DecisionBundleV1) -> Result<(), RedactionError> {
    artifact.bundle_basis.validation_report_artifact_id = artifact
        .bundle
        .validation_report
        .envelope
        .artifact_id
        .clone();
    artifact.bundle_basis.validation_report_semantic_hash =
        semantic_hash_hex_for_validation_report(&artifact.bundle.validation_report)
            .map_err(map_projection_error)?;
    artifact.bundle_basis.contract_artifact_id =
        artifact.bundle.contract.envelope.artifact_id.clone();
    artifact.bundle_basis.contract_semantic_hash =
        semantic_hash_hex_for_contract(&artifact.bundle.contract).map_err(map_projection_error)?;
    artifact.bundle_basis.state_artifact_id = artifact
        .bundle
        .state
        .as_ref()
        .map(|state| state.envelope.artifact_id.clone());
    artifact.bundle_basis.state_semantic_hash = artifact
        .bundle
        .state
        .as_ref()
        .map(semantic_hash_hex_for_state)
        .transpose()
        .map_err(map_projection_error)?;
    artifact.bundle_basis.config_bundle_artifact_id = artifact
        .bundle
        .config_bundle
        .as_ref()
        .map(|bundle| bundle.envelope.artifact_id.clone());
    artifact.bundle_basis.config_bundle_semantic_hash = artifact
        .bundle
        .config_bundle
        .as_ref()
        .map(semantic_hash_hex_for_config_bundle)
        .transpose()
        .map_err(map_projection_error)?;
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
    artifact.bundle_basis.recommendation_report_semantic_hash = artifact
        .bundle
        .recommendation_report
        .as_ref()
        .map(semantic_hash_hex_for_recommendation_report)
        .transpose()
        .map_err(map_projection_error)?;
    Ok(())
}

fn retarget_validation_service_profile_lineage(
    validation_report: &mut ValidationReportV1,
    service_profile: &ServiceProfileV1,
) -> Result<(), RedactionError> {
    validation_report
        .validation_basis
        .service_profile_artifact_id = service_profile.envelope.artifact_id.clone();
    validation_report
        .validation_basis
        .service_profile_semantic_hash =
        semantic_hash_hex_for_service_profile(service_profile).map_err(map_projection_error)?;
    validate_validation_report(validation_report).map_err(map_output_validation_error)
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
    artifact.validation_basis.contract_semantic_hash =
        semantic_hash_hex_for_contract(contract).map_err(map_projection_error)?;
    match state {
        Some(state) => {
            artifact.validation_basis.state_artifact_id = Some(state.envelope.artifact_id.clone());
            artifact.validation_basis.state_semantic_hash =
                Some(semantic_hash_hex_for_state(state).map_err(map_projection_error)?);
        }
        None => {
            artifact.validation_basis.state_artifact_id = None;
            artifact.validation_basis.state_semantic_hash = None;
        }
    }
    validate_validation_report(&artifact).map_err(map_output_validation_error)?;
    Ok(artifact)
}

fn redact_embedded_recommendation_report_artifact(
    mut artifact: RecommendationReportV1,
    validation_report: &ValidationReportV1,
    state: Option<&HostStateV1>,
    profile: BuiltInRedactionProfileV1,
    redacted_at: &str,
) -> Result<RecommendationReportV1, RedactionError> {
    apply_recommendation_report_profile_v1(&mut artifact, profile);
    artifact.recommendation_basis.validation_report_artifact_id =
        validation_report.envelope.artifact_id.clone();
    artifact
        .recommendation_basis
        .validation_report_semantic_hash =
        semantic_hash_hex_for_validation_report(validation_report).map_err(map_projection_error)?;
    artifact.recommendation_basis.validation_verdict = validation_report.report.verdict;
    match state {
        Some(state) => {
            artifact.recommendation_basis.state_artifact_id =
                Some(state.envelope.artifact_id.clone());
            artifact.recommendation_basis.state_semantic_hash =
                Some(semantic_hash_hex_for_state(state).map_err(map_projection_error)?);
        }
        None => {
            artifact.recommendation_basis.state_artifact_id = None;
            artifact.recommendation_basis.state_semantic_hash = None;
        }
    }
    apply_auxiliary_redaction_metadata_v1(&mut artifact.envelope, profile, redacted_at)?;
    validate_recommendation_report(&artifact).map_err(map_output_validation_error)?;
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
    let contract_semantic_hash =
        semantic_hash_hex_for_contract(contract).map_err(map_projection_error)?;
    bundle.artifact_schema_id = contract.envelope.schema_id.clone();
    bundle.artifact_id = contract.envelope.artifact_id.clone();
    bundle.artifact_semantic_hash = contract_semantic_hash;
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

fn map_input_validation_error(
    error: crate::artifacts::validation_v1::ArtifactValidationError,
) -> RedactionError {
    RedactionError::new(
        RedactionErrorCode::ArtifactInputInvalid,
        "redaction_apply",
        error.message,
    )
}

fn map_output_validation_error(
    error: crate::artifacts::validation_v1::ArtifactValidationError,
) -> RedactionError {
    RedactionError::new(
        RedactionErrorCode::RedactionOutputInvalid,
        "redaction_emit",
        error.message,
    )
}

fn map_projection_error(
    error: crate::artifacts::validation_v1::ArtifactValidationError,
) -> RedactionError {
    RedactionError::new(
        RedactionErrorCode::RedactionApplyFailed,
        "redaction_apply",
        error.message,
    )
}
