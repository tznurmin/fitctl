// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Local decision-bundle assembly over existing canonical artifacts.
//!
//! This module keeps the bundle narrow: one validation result plus the canonical artifacts needed
//! to explain it, without widening into rollout or scheduler semantics.

use crate::artifacts::config_bundle_v1::ConfigBundleV1;
use crate::artifacts::decision_bundle_v1::{
    DecisionBundleBasisV1, DecisionBundlePayloadV1, DecisionBundleV1,
};
use crate::artifacts::envelope_v1::{local_artifact_provenance_v1, LOCAL_FITCTL_VERSION_V1};
use crate::artifacts::recommendation_report_v1::RecommendationReportV1;
use crate::artifacts::schema_ids_v1::{
    DECISION_BUNDLE_SCHEMA_ID, TOP_LEVEL_ARTIFACT_SCHEMA_VERSION,
};
use crate::artifacts::validation_v1::validate_decision_bundle;
use crate::config::{load_resolved_config_from_path, ResolvedConfigV1};
use crate::config_bundle::load_config_bundle_from_path_v1;
use crate::recommendation::load_recommendation_report_from_path;
use crate::validate::{
    load_contract_artifact_for_validation, load_host_state_artifact_for_validation,
    load_validation_report_from_path,
};
use crate::verify::{load_verification_bundle_from_path, VerificationBundleV1};
use crate::{
    artifacts::record_v1::ArtifactRecordV1,
    artifacts::semantic_hash_v1::{
        semantic_hash_hex_for_config_bundle, semantic_hash_hex_for_contract,
        semantic_hash_hex_for_decision_bundle, semantic_hash_hex_for_recommendation_report,
        semantic_hash_hex_for_state, semantic_hash_hex_for_validation_report,
    },
};
use std::path::Path;

pub const BUNDLE_ERROR_MODEL_ID: &str = "fitctl.bundle.v1";
pub const BUNDLE_ERROR_MODEL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleErrorCode {
    BundleInputInvalid,
    BundleLineageMismatch,
    BundleEmitInvalid,
}

impl BundleErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BundleInputInvalid => "bundle_input_invalid",
            Self::BundleLineageMismatch => "bundle_lineage_mismatch",
            Self::BundleEmitInvalid => "bundle_emit_invalid",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleError {
    pub code: BundleErrorCode,
    pub checkpoint_id: &'static str,
    pub message: String,
    pub error_model_id: &'static str,
    pub error_model_version: u32,
}

impl BundleError {
    pub fn new(
        code: BundleErrorCode,
        checkpoint_id: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            checkpoint_id,
            message: message.into(),
            error_model_id: BUNDLE_ERROR_MODEL_ID,
            error_model_version: BUNDLE_ERROR_MODEL_VERSION,
        }
    }
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} [{} at {}]",
            self.message,
            self.code.as_str(),
            self.checkpoint_id
        )
    }
}

impl std::error::Error for BundleError {}

#[derive(Debug, Clone, PartialEq)]
pub struct DecisionBundleAssemblyRequestV1 {
    pub validation_report: crate::artifacts::validation_report_v1::ValidationReportV1,
    pub contract: crate::artifacts::contract_v1::HostContractV1,
    pub state: Option<crate::artifacts::state_v1::HostStateV1>,
    pub resolved_config: Option<ResolvedConfigV1>,
    pub config_bundle: Option<ConfigBundleV1>,
    pub verification_bundle: Option<VerificationBundleV1>,
    pub recommendation_report: Option<RecommendationReportV1>,
    pub bundled_at: String,
    pub notes: Option<String>,
}

/// Load and validate the canonical bundle inputs from disk for one local assembly run.
#[allow(clippy::too_many_arguments)]
pub fn load_decision_bundle_inputs_from_paths_v1(
    validation_report_path: &Path,
    contract_path: &Path,
    state_path: Option<&Path>,
    resolved_config_path: Option<&Path>,
    config_bundle_path: Option<&Path>,
    verification_bundle_path: Option<&Path>,
    recommendation_report_path: Option<&Path>,
    bundled_at: String,
    notes: Option<String>,
) -> Result<DecisionBundleAssemblyRequestV1, BundleError> {
    let validation_report =
        load_validation_report_from_path(validation_report_path).map_err(|error| {
            BundleError::new(
                BundleErrorCode::BundleInputInvalid,
                "bundle_load",
                error.message,
            )
        })?;
    let contract = load_contract_artifact_for_validation(contract_path).map_err(|error| {
        BundleError::new(
            BundleErrorCode::BundleInputInvalid,
            "bundle_load",
            error.message,
        )
    })?;
    let state = match state_path {
        Some(path) => Some(
            load_host_state_artifact_for_validation(path).map_err(|error| {
                BundleError::new(
                    BundleErrorCode::BundleInputInvalid,
                    "bundle_load",
                    error.message,
                )
            })?,
        ),
        None => None,
    };
    let resolved_config = match resolved_config_path {
        Some(path) => Some(load_resolved_config_from_path(path).map_err(|error| {
            BundleError::new(
                BundleErrorCode::BundleInputInvalid,
                "bundle_load",
                error.message,
            )
        })?),
        None => None,
    };
    let config_bundle = match config_bundle_path {
        Some(path) => Some(load_config_bundle_from_path_v1(path).map_err(|error| {
            BundleError::new(
                BundleErrorCode::BundleInputInvalid,
                "bundle_load",
                error.message,
            )
        })?),
        None => None,
    };
    let verification_bundle = match verification_bundle_path {
        Some(path) => Some(load_verification_bundle_from_path(path).map_err(|error| {
            BundleError::new(
                BundleErrorCode::BundleInputInvalid,
                "bundle_load",
                error.message,
            )
        })?),
        None => None,
    };
    let recommendation_report = match recommendation_report_path {
        Some(path) => Some(load_recommendation_report_from_path(path).map_err(|error| {
            BundleError::new(
                BundleErrorCode::BundleInputInvalid,
                "bundle_load",
                error.message,
            )
        })?),
        None => None,
    };

    Ok(DecisionBundleAssemblyRequestV1 {
        validation_report,
        contract,
        state,
        resolved_config,
        config_bundle,
        verification_bundle,
        recommendation_report,
        bundled_at,
        notes,
    })
}

/// Assemble one local bundle and validate that the embedded artifact lineage stays aligned.
pub fn assemble_decision_bundle_v1(
    request: DecisionBundleAssemblyRequestV1,
) -> Result<DecisionBundleV1, BundleError> {
    if request.bundled_at.trim().is_empty() {
        return Err(BundleError::new(
            BundleErrorCode::BundleInputInvalid,
            "bundle_assemble",
            "bundle timestamp must be populated",
        ));
    }
    if request.resolved_config.is_some() && request.config_bundle.is_some() {
        return Err(BundleError::new(
            BundleErrorCode::BundleInputInvalid,
            "bundle_assemble",
            "decision bundle must not carry both raw resolved config and config bundle",
        ));
    }

    let validation_report_semantic_hash =
        semantic_hash_hex_for_validation_report(&request.validation_report).map_err(|error| {
            BundleError::new(
                BundleErrorCode::BundleInputInvalid,
                "bundle_assemble",
                error.message,
            )
        })?;
    let contract_semantic_hash =
        semantic_hash_hex_for_contract(&request.contract).map_err(|error| {
            BundleError::new(
                BundleErrorCode::BundleInputInvalid,
                "bundle_assemble",
                error.message,
            )
        })?;
    let state_semantic_hash = match request.state.as_ref() {
        Some(state) => Some(semantic_hash_hex_for_state(state).map_err(|error| {
            BundleError::new(
                BundleErrorCode::BundleInputInvalid,
                "bundle_assemble",
                error.message,
            )
        })?),
        None => None,
    };
    let config_bundle_semantic_hash = match request.config_bundle.as_ref() {
        Some(bundle) => Some(
            semantic_hash_hex_for_config_bundle(bundle).map_err(|error| {
                BundleError::new(
                    BundleErrorCode::BundleInputInvalid,
                    "bundle_assemble",
                    error.message,
                )
            })?,
        ),
        None => None,
    };
    let recommendation_report_semantic_hash = match request.recommendation_report.as_ref() {
        Some(report) => Some(semantic_hash_hex_for_recommendation_report(report).map_err(
            |error| {
                BundleError::new(
                    BundleErrorCode::BundleInputInvalid,
                    "bundle_assemble",
                    error.message,
                )
            },
        )?),
        None => None,
    };

    let artifact_id = format!(
        "decision-bundle-{}",
        request.validation_report.envelope.artifact_id
    );
    let bundle = DecisionBundleV1 {
        envelope: crate::artifacts::envelope_v1::ArtifactEnvelopeV1 {
            schema_id: DECISION_BUNDLE_SCHEMA_ID.to_string(),
            schema_version: TOP_LEVEL_ARTIFACT_SCHEMA_VERSION,
            artifact_id: artifact_id.clone(),
            provenance: local_artifact_provenance_v1(
                "bundle:single_decision",
                request.bundled_at,
                "bundle",
                artifact_id,
            ),
            redaction: None,
            signatures: vec![],
        },
        bundle_basis: DecisionBundleBasisV1 {
            validation_report_artifact_id: request.validation_report.envelope.artifact_id.clone(),
            validation_report_semantic_hash,
            contract_artifact_id: request.contract.envelope.artifact_id.clone(),
            contract_semantic_hash,
            state_artifact_id: request
                .state
                .as_ref()
                .map(|artifact| artifact.envelope.artifact_id.clone()),
            state_semantic_hash,
            config_bundle_artifact_id: request
                .config_bundle
                .as_ref()
                .map(|artifact| artifact.envelope.artifact_id.clone()),
            config_bundle_semantic_hash,
            verification_bundle_id: request
                .verification_bundle
                .as_ref()
                .map(|bundle| bundle.bundle_id.clone()),
            recommendation_report_artifact_id: request
                .recommendation_report
                .as_ref()
                .map(|report| report.envelope.artifact_id.clone()),
            recommendation_report_semantic_hash,
        },
        bundle: DecisionBundlePayloadV1 {
            validation_report: request.validation_report,
            contract: request.contract,
            state: request.state,
            resolved_config: request.resolved_config,
            config_bundle: request.config_bundle,
            verification_bundle: request.verification_bundle,
            recommendation_report: request.recommendation_report,
        },
    };

    validate_decision_bundle(&bundle).map_err(|error| {
        let code = match error.code {
            crate::artifacts::validation_v1::ArtifactValidationErrorCode::ArtifactPayloadCorrupt => {
                BundleErrorCode::BundleLineageMismatch
            }
            crate::artifacts::validation_v1::ArtifactValidationErrorCode::ArtifactSchemaIdInvalid
            | crate::artifacts::validation_v1::ArtifactValidationErrorCode::ArtifactSchemaVersionInvalid
            | crate::artifacts::validation_v1::ArtifactValidationErrorCode::ContractBasisInvalid => {
                BundleErrorCode::BundleEmitInvalid
            }
        };
        BundleError::new(code, "bundle_validate", error.message)
    })?;

    semantic_hash_hex_for_decision_bundle(&bundle).map_err(|error| {
        BundleError::new(
            BundleErrorCode::BundleEmitInvalid,
            "bundle_emit",
            error.message,
        )
    })?;

    Ok(bundle)
}

/// Convert the new bundle artifact into a generic artifact record for signing, diffing, and inspect.
pub fn bundle_record_v1(bundle: DecisionBundleV1) -> ArtifactRecordV1 {
    ArtifactRecordV1::DecisionBundle(bundle)
}

pub fn fitctl_version_v1() -> &'static str {
    LOCAL_FITCTL_VERSION_V1
}
