// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Redaction-only typed dispatch for core and standalone auxiliary artifacts.

use std::fs;
use std::path::Path;

use serde::Serialize;
use serde_json::Value;

use crate::artifacts::batch_classification_report_v1::BatchClassificationReportV1;
use crate::artifacts::envelope_v1::ArtifactEnvelopeV1;
use crate::artifacts::recommendation_report_v1::RecommendationReportV1;
use crate::artifacts::record_v1::{load_artifact_record_from_value, ArtifactRecordV1};
use crate::artifacts::schema_ids_v1::{
    is_supported_batch_classification_report_schema_id, RECOMMENDATION_REPORT_SCHEMA_ID,
};
use crate::classify::load_batch_classification_report_from_value;
use crate::recommendation::load_recommendation_report_from_value;
use crate::redact::apply_v1::{redact_artifact_v1, RedactionRequestV1};
use crate::redact::auxiliary_reports_v1::{
    redact_batch_classification_report_artifact_v1, redact_recommendation_report_artifact_v1,
};
use crate::redact::{BuiltInRedactionProfileV1, RedactionError, RedactionErrorCode};

#[derive(Debug, Clone, PartialEq)]
pub enum RedactableArtifactV1 {
    Core(Box<ArtifactRecordV1>),
    RecommendationReport(Box<RecommendationReportV1>),
    BatchClassificationReport(Box<BatchClassificationReportV1>),
}

impl RedactableArtifactV1 {
    pub fn envelope(&self) -> &ArtifactEnvelopeV1 {
        match self {
            Self::Core(artifact) => artifact.envelope(),
            Self::RecommendationReport(artifact) => &artifact.envelope,
            Self::BatchClassificationReport(artifact) => &artifact.envelope,
        }
    }
}

impl Serialize for RedactableArtifactV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Core(artifact) => artifact.serialize(serializer),
            Self::RecommendationReport(artifact) => artifact.serialize(serializer),
            Self::BatchClassificationReport(artifact) => artifact.serialize(serializer),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RedactableArtifactRequestV1 {
    pub artifact: RedactableArtifactV1,
    pub profile: BuiltInRedactionProfileV1,
    pub redacted_at: String,
}

pub fn load_redactable_artifact_for_redaction(
    path: &Path,
) -> Result<RedactableArtifactV1, RedactionError> {
    let text = fs::read_to_string(path).map_err(|error| {
        RedactionError::new(
            RedactionErrorCode::ArtifactInputInvalid,
            "artifact_load",
            format!("failed to read artifact {}: {error}", path.display()),
        )
    })?;
    let raw: Value = serde_json::from_str(&text).map_err(|error| {
        RedactionError::new(
            RedactionErrorCode::ArtifactInputInvalid,
            "artifact_load",
            format!("failed to decode artifact {}: {error}", path.display()),
        )
    })?;
    load_redactable_artifact_from_value(raw)
}

pub fn load_redactable_artifact_from_value(
    raw: Value,
) -> Result<RedactableArtifactV1, RedactionError> {
    let schema_id = raw
        .get("envelope")
        .and_then(|value| value.get("schema_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            RedactionError::new(
                RedactionErrorCode::ArtifactInputInvalid,
                "artifact_load",
                "artifact input must include envelope.schema_id",
            )
        })?
        .to_string();

    if schema_id == RECOMMENDATION_REPORT_SCHEMA_ID {
        return load_recommendation_report_from_value(raw)
            .map(Box::new)
            .map(RedactableArtifactV1::RecommendationReport)
            .map_err(|error| input_error(error.message));
    }
    if is_supported_batch_classification_report_schema_id(&schema_id) {
        return load_batch_classification_report_from_value(raw)
            .map(Box::new)
            .map(RedactableArtifactV1::BatchClassificationReport)
            .map_err(|error| input_error(error.message));
    }

    load_artifact_record_from_value(raw)
        .map(Box::new)
        .map(RedactableArtifactV1::Core)
        .map_err(|error| input_error(error.message))
}

pub fn redact_supported_artifact_v1(
    request: RedactableArtifactRequestV1,
) -> Result<RedactableArtifactV1, RedactionError> {
    if request.redacted_at.trim().is_empty() {
        return Err(RedactionError::new(
            RedactionErrorCode::RedactionApplyFailed,
            "redaction_apply",
            "redaction timestamp must be populated",
        ));
    }
    if request.artifact.envelope().redaction.is_some() {
        return Err(RedactionError::new(
            RedactionErrorCode::RedactionInputAlreadyRedacted,
            "redaction_preflight",
            "input artifact already carries redaction provenance",
        ));
    }

    match request.artifact {
        RedactableArtifactV1::Core(artifact) => redact_artifact_v1(RedactionRequestV1 {
            artifact: *artifact,
            profile: request.profile,
            redacted_at: request.redacted_at,
        })
        .map(Box::new)
        .map(RedactableArtifactV1::Core),
        RedactableArtifactV1::RecommendationReport(artifact) => {
            redact_recommendation_report_artifact_v1(
                *artifact,
                request.profile,
                &request.redacted_at,
            )
            .map(Box::new)
            .map(RedactableArtifactV1::RecommendationReport)
        }
        RedactableArtifactV1::BatchClassificationReport(artifact) => {
            redact_batch_classification_report_artifact_v1(
                *artifact,
                request.profile,
                &request.redacted_at,
            )
            .map(Box::new)
            .map(RedactableArtifactV1::BatchClassificationReport)
        }
    }
}

fn input_error(message: impl Into<String>) -> RedactionError {
    RedactionError::new(
        RedactionErrorCode::ArtifactInputInvalid,
        "artifact_load",
        message,
    )
}
