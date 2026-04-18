// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Tagged artifact-record wrapper used for loading and handling supported top-level artifacts.

use std::fs;
use std::path::Path;

use serde_json::Value;

use crate::artifacts::config_bundle_v1::ConfigBundleV1;
use crate::artifacts::contract_v1::HostContractV1;
use crate::artifacts::decision_bundle_v1::DecisionBundleV1;
use crate::artifacts::envelope_v1::ArtifactEnvelopeV1;
use crate::artifacts::schema_ids_v1::{
    CONFIG_BUNDLE_SCHEMA_ID, DECISION_BUNDLE_SCHEMA_ID, HOST_CONTRACT_SCHEMA_ID,
    HOST_STATE_SCHEMA_ID, HOST_SURVEY_SCHEMA_ID, SERVICE_PROFILE_SCHEMA_ID,
    VALIDATION_REPORT_SCHEMA_ID,
};
use crate::artifacts::semantic_hash_v1::{
    semantic_bytes_for_config_bundle, semantic_bytes_for_contract,
    semantic_bytes_for_decision_bundle, semantic_bytes_for_service_profile,
    semantic_bytes_for_state, semantic_bytes_for_survey, semantic_bytes_for_validation_report,
    semantic_content_json_for_config_bundle, semantic_content_json_for_contract,
    semantic_content_json_for_decision_bundle, semantic_content_json_for_service_profile,
    semantic_content_json_for_state, semantic_content_json_for_survey,
    semantic_content_json_for_validation_report, semantic_hash_hex_for_config_bundle,
    semantic_hash_hex_for_contract, semantic_hash_hex_for_decision_bundle,
    semantic_hash_hex_for_service_profile, semantic_hash_hex_for_state,
    semantic_hash_hex_for_survey, semantic_hash_hex_for_validation_report,
};
use crate::artifacts::service_profile_v1::ServiceProfileV1;
use crate::artifacts::state_v1::HostStateV1;
use crate::artifacts::survey_v1::HostSurveyV1;
use crate::artifacts::validation_report_v1::ValidationReportV1;
use crate::artifacts::validation_v1::{
    validate_config_bundle, validate_decision_bundle, validate_host_contract, validate_host_state,
    validate_host_survey, validate_service_profile, validate_validation_report,
    ArtifactValidationErrorCode,
};
pub const ARTIFACT_RECORD_ERROR_MODEL_ID: &str = "fitctl.artifact_record.v1";
pub const ARTIFACT_RECORD_ERROR_MODEL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactRecordErrorCode {
    ArtifactReadInvalid,
    ArtifactDecodeInvalid,
    ArtifactSchemaUnsupported,
    ArtifactLoadInvalid,
}

impl ArtifactRecordErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ArtifactReadInvalid => "artifact_read_invalid",
            Self::ArtifactDecodeInvalid => "artifact_decode_invalid",
            Self::ArtifactSchemaUnsupported => "artifact_schema_unsupported",
            Self::ArtifactLoadInvalid => "artifact_load_invalid",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactRecordError {
    pub code: ArtifactRecordErrorCode,
    pub checkpoint_id: &'static str,
    pub message: String,
    pub error_model_id: &'static str,
    pub error_model_version: u32,
}

impl ArtifactRecordError {
    fn new(
        code: ArtifactRecordErrorCode,
        checkpoint_id: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            checkpoint_id,
            message: message.into(),
            error_model_id: ARTIFACT_RECORD_ERROR_MODEL_ID,
            error_model_version: ARTIFACT_RECORD_ERROR_MODEL_VERSION,
        }
    }
}

impl std::fmt::Display for ArtifactRecordError {
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

impl std::error::Error for ArtifactRecordError {}

#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum ArtifactRecordV1 {
    Survey(HostSurveyV1),
    Contract(HostContractV1),
    ServiceProfile(ServiceProfileV1),
    State(HostStateV1),
    ValidationReport(ValidationReportV1),
    ConfigBundle(ConfigBundleV1),
    DecisionBundle(DecisionBundleV1),
}

impl ArtifactRecordV1 {
    pub fn envelope(&self) -> &ArtifactEnvelopeV1 {
        match self {
            Self::Survey(artifact) => &artifact.envelope,
            Self::Contract(artifact) => &artifact.envelope,
            Self::ServiceProfile(artifact) => &artifact.envelope,
            Self::State(artifact) => &artifact.envelope,
            Self::ValidationReport(artifact) => &artifact.envelope,
            Self::ConfigBundle(artifact) => &artifact.envelope,
            Self::DecisionBundle(artifact) => &artifact.envelope,
        }
    }

    pub fn envelope_mut(&mut self) -> &mut ArtifactEnvelopeV1 {
        match self {
            Self::Survey(artifact) => &mut artifact.envelope,
            Self::Contract(artifact) => &mut artifact.envelope,
            Self::ServiceProfile(artifact) => &mut artifact.envelope,
            Self::State(artifact) => &mut artifact.envelope,
            Self::ValidationReport(artifact) => &mut artifact.envelope,
            Self::ConfigBundle(artifact) => &mut artifact.envelope,
            Self::DecisionBundle(artifact) => &mut artifact.envelope,
        }
    }

    pub fn schema_id(&self) -> &str {
        &self.envelope().schema_id
    }

    pub fn artifact_id(&self) -> &str {
        &self.envelope().artifact_id
    }

    pub fn semantic_hash_hex(&self) -> Result<String, ArtifactRecordError> {
        match self {
            Self::Survey(artifact) => semantic_hash_hex_for_survey(artifact),
            Self::Contract(artifact) => semantic_hash_hex_for_contract(artifact),
            Self::ServiceProfile(artifact) => semantic_hash_hex_for_service_profile(artifact),
            Self::State(artifact) => semantic_hash_hex_for_state(artifact),
            Self::ValidationReport(artifact) => semantic_hash_hex_for_validation_report(artifact),
            Self::ConfigBundle(artifact) => semantic_hash_hex_for_config_bundle(artifact),
            Self::DecisionBundle(artifact) => semantic_hash_hex_for_decision_bundle(artifact),
        }
        .map_err(|error| {
            ArtifactRecordError::new(
                ArtifactRecordErrorCode::ArtifactLoadInvalid,
                "artifact_projection",
                error.message,
            )
        })
    }

    pub fn semantic_bytes(&self) -> Result<Vec<u8>, ArtifactRecordError> {
        match self {
            Self::Survey(artifact) => semantic_bytes_for_survey(artifact),
            Self::Contract(artifact) => semantic_bytes_for_contract(artifact),
            Self::ServiceProfile(artifact) => semantic_bytes_for_service_profile(artifact),
            Self::State(artifact) => semantic_bytes_for_state(artifact),
            Self::ValidationReport(artifact) => semantic_bytes_for_validation_report(artifact),
            Self::ConfigBundle(artifact) => semantic_bytes_for_config_bundle(artifact),
            Self::DecisionBundle(artifact) => semantic_bytes_for_decision_bundle(artifact),
        }
        .map_err(|error| {
            ArtifactRecordError::new(
                ArtifactRecordErrorCode::ArtifactLoadInvalid,
                "artifact_projection",
                error.message,
            )
        })
    }

    pub fn semantic_cbor_bytes(&self) -> Result<Vec<u8>, ArtifactRecordError> {
        self.semantic_bytes()
    }

    pub fn semantic_content_json(&self) -> Result<Value, ArtifactRecordError> {
        match self {
            Self::Survey(artifact) => semantic_content_json_for_survey(artifact),
            Self::Contract(artifact) => semantic_content_json_for_contract(artifact),
            Self::ServiceProfile(artifact) => semantic_content_json_for_service_profile(artifact),
            Self::State(artifact) => semantic_content_json_for_state(artifact),
            Self::ValidationReport(artifact) => {
                semantic_content_json_for_validation_report(artifact)
            }
            Self::ConfigBundle(artifact) => semantic_content_json_for_config_bundle(artifact),
            Self::DecisionBundle(artifact) => semantic_content_json_for_decision_bundle(artifact),
        }
        .map_err(|error| {
            ArtifactRecordError::new(
                ArtifactRecordErrorCode::ArtifactLoadInvalid,
                "artifact_projection",
                error.message,
            )
        })
    }

    pub fn semantic_projection_json(&self) -> Result<Value, ArtifactRecordError> {
        self.semantic_content_json()
    }

    pub fn full_artifact_json(&self) -> Result<Value, ArtifactRecordError> {
        serde_json::to_value(self).map_err(|error| {
            ArtifactRecordError::new(
                ArtifactRecordErrorCode::ArtifactDecodeInvalid,
                "artifact_encode",
                format!("failed to encode artifact as JSON value: {error}"),
            )
        })
    }

    pub fn json_value(&self) -> Result<Value, ArtifactRecordError> {
        self.full_artifact_json()
    }
}

impl serde::Serialize for ArtifactRecordV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Survey(artifact) => artifact.serialize(serializer),
            Self::Contract(artifact) => artifact.serialize(serializer),
            Self::ServiceProfile(artifact) => artifact.serialize(serializer),
            Self::State(artifact) => artifact.serialize(serializer),
            Self::ValidationReport(artifact) => artifact.serialize(serializer),
            Self::ConfigBundle(artifact) => artifact.serialize(serializer),
            Self::DecisionBundle(artifact) => artifact.serialize(serializer),
        }
    }
}

/// Load a typed artifact record from disk and fail closed on unsupported schema ids.
pub fn load_artifact_record_from_path(
    path: &Path,
) -> Result<ArtifactRecordV1, ArtifactRecordError> {
    let text = fs::read_to_string(path).map_err(|error| {
        ArtifactRecordError::new(
            ArtifactRecordErrorCode::ArtifactReadInvalid,
            "artifact_load",
            format!("failed to read artifact {}: {error}", path.display()),
        )
    })?;
    let raw: Value = serde_json::from_str(&text).map_err(|error| {
        ArtifactRecordError::new(
            ArtifactRecordErrorCode::ArtifactDecodeInvalid,
            "artifact_load",
            format!("failed to decode artifact {}: {error}", path.display()),
        )
    })?;

    let schema_id = raw
        .get("envelope")
        .and_then(|value| value.get("schema_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ArtifactRecordError::new(
                ArtifactRecordErrorCode::ArtifactDecodeInvalid,
                "artifact_load",
                format!(
                    "artifact {} must include envelope.schema_id",
                    path.display()
                ),
            )
        })?
        .to_string();

    load_artifact_record_from_value_with_schema_id(raw, &schema_id)
}

/// Load a typed artifact record from an already-decoded JSON value.
pub fn load_artifact_record_from_value(
    raw: Value,
) -> Result<ArtifactRecordV1, ArtifactRecordError> {
    let schema_id = raw
        .get("envelope")
        .and_then(|value| value.get("schema_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ArtifactRecordError::new(
                ArtifactRecordErrorCode::ArtifactDecodeInvalid,
                "artifact_load",
                "artifact input must include envelope.schema_id",
            )
        })?
        .to_string();

    load_artifact_record_from_value_with_schema_id(raw, &schema_id)
}

fn load_artifact_record_from_value_with_schema_id(
    raw: Value,
    schema_id: &str,
) -> Result<ArtifactRecordV1, ArtifactRecordError> {
    fn map_validation_error(
        error: crate::artifacts::validation_v1::ArtifactValidationError,
    ) -> ArtifactRecordError {
        let code = match error.code {
            ArtifactValidationErrorCode::ArtifactSchemaIdInvalid
            | ArtifactValidationErrorCode::ArtifactSchemaVersionInvalid => {
                ArtifactRecordErrorCode::ArtifactSchemaUnsupported
            }
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt
            | ArtifactValidationErrorCode::ContractBasisInvalid => {
                ArtifactRecordErrorCode::ArtifactLoadInvalid
            }
        };

        ArtifactRecordError::new(code, "artifact_load", error.message)
    }

    match schema_id {
        HOST_SURVEY_SCHEMA_ID => {
            let artifact: HostSurveyV1 = serde_json::from_value(raw).map_err(|error| {
                ArtifactRecordError::new(
                    ArtifactRecordErrorCode::ArtifactDecodeInvalid,
                    "artifact_load",
                    format!("failed to decode host-survey.v2 artifact: {error}"),
                )
            })?;
            validate_host_survey(&artifact).map_err(map_validation_error)?;
            Ok(ArtifactRecordV1::Survey(artifact))
        }
        HOST_CONTRACT_SCHEMA_ID => {
            let artifact: HostContractV1 = serde_json::from_value(raw).map_err(|error| {
                ArtifactRecordError::new(
                    ArtifactRecordErrorCode::ArtifactDecodeInvalid,
                    "artifact_load",
                    format!("failed to decode host-contract.v2 artifact: {error}"),
                )
            })?;
            validate_host_contract(&artifact).map_err(map_validation_error)?;
            Ok(ArtifactRecordV1::Contract(artifact))
        }
        SERVICE_PROFILE_SCHEMA_ID => {
            let artifact: ServiceProfileV1 = serde_json::from_value(raw).map_err(|error| {
                ArtifactRecordError::new(
                    ArtifactRecordErrorCode::ArtifactDecodeInvalid,
                    "artifact_load",
                    format!("failed to decode service-profile.v2 artifact: {error}"),
                )
            })?;
            validate_service_profile(&artifact).map_err(map_validation_error)?;
            Ok(ArtifactRecordV1::ServiceProfile(artifact))
        }
        HOST_STATE_SCHEMA_ID => {
            let artifact: HostStateV1 = serde_json::from_value(raw).map_err(|error| {
                ArtifactRecordError::new(
                    ArtifactRecordErrorCode::ArtifactDecodeInvalid,
                    "artifact_load",
                    format!("failed to decode host-state.v2 artifact: {error}"),
                )
            })?;
            validate_host_state(&artifact).map_err(map_validation_error)?;
            Ok(ArtifactRecordV1::State(artifact))
        }
        VALIDATION_REPORT_SCHEMA_ID => {
            let artifact: ValidationReportV1 = serde_json::from_value(raw).map_err(|error| {
                ArtifactRecordError::new(
                    ArtifactRecordErrorCode::ArtifactDecodeInvalid,
                    "artifact_load",
                    format!("failed to decode validation-report.v2 artifact: {error}"),
                )
            })?;
            validate_validation_report(&artifact).map_err(map_validation_error)?;
            Ok(ArtifactRecordV1::ValidationReport(artifact))
        }
        CONFIG_BUNDLE_SCHEMA_ID => {
            let artifact: ConfigBundleV1 = serde_json::from_value(raw).map_err(|error| {
                ArtifactRecordError::new(
                    ArtifactRecordErrorCode::ArtifactDecodeInvalid,
                    "artifact_load",
                    format!("failed to decode fitctl.config-bundle.v2 artifact: {error}"),
                )
            })?;
            validate_config_bundle(&artifact).map_err(map_validation_error)?;
            Ok(ArtifactRecordV1::ConfigBundle(artifact))
        }
        DECISION_BUNDLE_SCHEMA_ID => {
            let artifact: DecisionBundleV1 = serde_json::from_value(raw).map_err(|error| {
                ArtifactRecordError::new(
                    ArtifactRecordErrorCode::ArtifactDecodeInvalid,
                    "artifact_load",
                    format!("failed to decode fitctl.decision-bundle.v2 artifact: {error}"),
                )
            })?;
            validate_decision_bundle(&artifact).map_err(map_validation_error)?;
            Ok(ArtifactRecordV1::DecisionBundle(artifact))
        }
        unsupported => Err(ArtifactRecordError::new(
            ArtifactRecordErrorCode::ArtifactSchemaUnsupported,
            "artifact_load",
            format!("artifact schema id {unsupported} is not supported by the diff surface"),
        )),
    }
}
