// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Advisory recommendation-report loading and validation.
//!
//! Recommendations stay outside the core fit verdict. This module handles the typed report surface
//! without promoting advisory output into contract or validation semantics.

use std::fs;
use std::path::Path;

use serde_json::{Map, Value};

use crate::artifacts::recommendation_report_v1::RecommendationReportV1;
use crate::artifacts::schema_ids_v1::RECOMMENDATION_REPORT_SCHEMA_ID;
use crate::artifacts::validation_v1::{
    validate_recommendation_report, ArtifactValidationErrorCode,
};

pub const RECOMMENDATION_ERROR_MODEL_ID: &str = "fitctl.recommendation.v1";
pub const RECOMMENDATION_ERROR_MODEL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecommendationErrorCode {
    RecommendationInputInvalid,
    RecommendationSchemaUnsupported,
    RecommendationArtifactInvalid,
}

impl RecommendationErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RecommendationInputInvalid => "recommendation_input_invalid",
            Self::RecommendationSchemaUnsupported => "recommendation_schema_unsupported",
            Self::RecommendationArtifactInvalid => "recommendation_artifact_invalid",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecommendationError {
    pub code: RecommendationErrorCode,
    pub checkpoint_id: &'static str,
    pub message: String,
    pub error_model_id: &'static str,
    pub error_model_version: u32,
}

impl RecommendationError {
    fn new(
        code: RecommendationErrorCode,
        checkpoint_id: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            checkpoint_id,
            message: message.into(),
            error_model_id: RECOMMENDATION_ERROR_MODEL_ID,
            error_model_version: RECOMMENDATION_ERROR_MODEL_VERSION,
        }
    }
}

impl std::fmt::Display for RecommendationError {
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

impl std::error::Error for RecommendationError {}

pub fn load_recommendation_report_from_path(
    path: &Path,
) -> Result<RecommendationReportV1, RecommendationError> {
    let text = fs::read_to_string(path).map_err(|error| {
        RecommendationError::new(
            RecommendationErrorCode::RecommendationInputInvalid,
            "recommendation_report_load",
            format!(
                "failed to read recommendation report {}: {error}",
                path.display()
            ),
        )
    })?;

    let raw: Value = serde_json::from_str(&text).map_err(|error| {
        RecommendationError::new(
            RecommendationErrorCode::RecommendationInputInvalid,
            "recommendation_report_load",
            format!(
                "failed to decode recommendation report {}: {error}",
                path.display()
            ),
        )
    })?;
    load_recommendation_report_from_value(raw)
}

pub fn load_recommendation_report_from_value(
    raw: Value,
) -> Result<RecommendationReportV1, RecommendationError> {
    validate_recommendation_report_json(&raw)?;

    let report: RecommendationReportV1 = serde_json::from_value(raw).map_err(|error| {
        RecommendationError::new(
            RecommendationErrorCode::RecommendationInputInvalid,
            "recommendation_report_load",
            format!("failed to decode typed recommendation report input: {error}"),
        )
    })?;

    validate_recommendation_report(&report).map_err(|error| {
        let code = match error.code {
            ArtifactValidationErrorCode::ArtifactSchemaIdInvalid
            | ArtifactValidationErrorCode::ArtifactSchemaVersionInvalid => {
                RecommendationErrorCode::RecommendationSchemaUnsupported
            }
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt
            | ArtifactValidationErrorCode::ContractBasisInvalid => {
                RecommendationErrorCode::RecommendationArtifactInvalid
            }
        };
        RecommendationError::new(code, "recommendation_report_validate", error.message)
    })?;

    Ok(report)
}

fn validate_recommendation_report_json(raw: &Value) -> Result<(), RecommendationError> {
    let root = raw.as_object().ok_or_else(|| {
        RecommendationError::new(
            RecommendationErrorCode::RecommendationInputInvalid,
            "recommendation_report_load",
            "recommendation report must decode to a JSON object",
        )
    })?;

    reject_unknown_keys(root, &["envelope", "recommendation_basis", "report"])?;
    reject_explicit_nulls(
        root,
        &["envelope", "recommendation_basis", "report"],
        "recommendation report field",
    )?;

    let envelope = require_object(root, "envelope", "recommendation report envelope")?;
    reject_unknown_keys(
        envelope,
        &[
            "schema_id",
            "schema_version",
            "artifact_id",
            "provenance",
            "redaction",
            "signatures",
        ],
    )?;
    reject_explicit_nulls(
        envelope,
        &[
            "schema_id",
            "schema_version",
            "artifact_id",
            "provenance",
            "signatures",
        ],
        "recommendation report envelope field",
    )?;

    let provenance = require_object(envelope, "provenance", "recommendation report provenance")?;
    reject_unknown_keys(
        provenance,
        &[
            "source",
            "collected_at",
            "tool_version",
            "command_name",
            "correlation_id",
        ],
    )?;
    reject_explicit_nulls(
        provenance,
        &["source", "collected_at"],
        "recommendation report provenance field",
    )?;

    let basis = require_object(root, "recommendation_basis", "recommendation report basis")?;
    reject_explicit_nulls(
        basis,
        &[
            "validation_report_artifact_id",
            "validation_report_semantic_hash",
            "validation_verdict",
            "recommendation_pack_id",
            "recommendation_pack_version",
            "recommendation_engine_id",
            "recommendation_engine_version",
        ],
        "recommendation basis field",
    )?;

    let report = require_object(root, "report", "recommendation report payload")?;
    reject_explicit_nulls(
        report,
        &["confidence", "freshness", "summary"],
        "recommendation report field",
    )?;

    Ok(())
}

fn require_object<'a>(
    value: &'a Map<String, Value>,
    key: &'static str,
    label: &'static str,
) -> Result<&'a Map<String, Value>, RecommendationError> {
    value.get(key).and_then(Value::as_object).ok_or_else(|| {
        RecommendationError::new(
            RecommendationErrorCode::RecommendationInputInvalid,
            "recommendation_report_load",
            format!("{label} must be a non-null object"),
        )
    })
}

fn reject_unknown_keys(
    map: &Map<String, Value>,
    allowed_keys: &[&str],
) -> Result<(), RecommendationError> {
    if let Some(key) = map.keys().find(|key| !allowed_keys.contains(&key.as_str())) {
        return Err(RecommendationError::new(
            RecommendationErrorCode::RecommendationInputInvalid,
            "recommendation_report_load",
            format!("recommendation report contains unsupported field {key}"),
        ));
    }

    Ok(())
}

fn reject_explicit_nulls(
    map: &Map<String, Value>,
    keys: &[&str],
    label: &'static str,
) -> Result<(), RecommendationError> {
    if let Some(key) = keys
        .iter()
        .find(|key| map.get(**key).is_some_and(Value::is_null))
    {
        return Err(RecommendationError::new(
            RecommendationErrorCode::RecommendationInputInvalid,
            "recommendation_report_load",
            format!("{label} {key} must not be null"),
        ));
    }

    Ok(())
}

pub fn recommendation_report_schema_id() -> &'static str {
    RECOMMENDATION_REPORT_SCHEMA_ID
}
