// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Semantic diffing between supported artifacts after schema-aware loading.

use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::artifacts::record_v1::{
    load_artifact_record_from_path, ArtifactRecordError, ArtifactRecordV1,
};
use crate::artifacts::schema_ids_v1::{
    HOST_CONTRACT_SCHEMA_ID, HOST_STATE_SCHEMA_ID, HOST_SURVEY_SCHEMA_ID,
    SERVICE_PROFILE_SCHEMA_ID, VALIDATION_REPORT_SCHEMA_ID,
};
use crate::diff::{DiffError, DiffErrorCode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftClassV1 {
    EvidenceDrift,
    ContractDrift,
    StateDrift,
    ServiceProfileDrift,
    ValidationReportDrift,
    SchemaMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticRelationV1 {
    SemanticallyIdentical,
    NonSemanticOnlyDifference,
    SemanticallyDifferent,
    SchemaMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticChangeKindV1 {
    Additive,
    Subtractive,
    Changed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticChangeV1 {
    pub path: String,
    pub change_kind: SemanticChangeKindV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left_value: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub right_value: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticDiffReportV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub drift_class: DriftClassV1,
    pub semantic_relation: SemanticRelationV1,
    pub left_schema_id: String,
    pub right_schema_id: String,
    pub left_artifact_id: String,
    pub right_artifact_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left_semantic_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub right_semantic_hash: Option<String>,
    pub non_semantic_differences_ignored: bool,
    #[serde(default)]
    pub changes: Vec<SemanticChangeV1>,
}

pub fn load_artifact_record_for_diff(path: &Path) -> Result<ArtifactRecordV1, DiffError> {
    load_artifact_record_from_path(path).map_err(map_artifact_record_error)
}

pub fn diff_artifact_records_v1(
    left: &ArtifactRecordV1,
    right: &ArtifactRecordV1,
) -> Result<SemanticDiffReportV1, DiffError> {
    let left_schema_id = left.schema_id().to_string();
    let right_schema_id = right.schema_id().to_string();

    if left_schema_id != right_schema_id {
        return Ok(SemanticDiffReportV1 {
            schema_id: "fitctl.diff.report.v1".to_string(),
            schema_version: 1,
            drift_class: DriftClassV1::SchemaMismatch,
            semantic_relation: SemanticRelationV1::SchemaMismatch,
            left_schema_id,
            right_schema_id,
            left_artifact_id: left.artifact_id().to_string(),
            right_artifact_id: right.artifact_id().to_string(),
            left_semantic_hash: None,
            right_semantic_hash: None,
            non_semantic_differences_ignored: false,
            changes: vec![],
        });
    }

    let left_semantic_hash = left
        .semantic_hash_hex()
        .map_err(map_artifact_record_error)?;
    let right_semantic_hash = right
        .semantic_hash_hex()
        .map_err(map_artifact_record_error)?;
    let left_projection = left
        .semantic_projection_json()
        .map_err(map_artifact_record_error)?;
    let right_projection = right
        .semantic_projection_json()
        .map_err(map_artifact_record_error)?;
    let left_raw = left.json_value().map_err(map_artifact_record_error)?;
    let right_raw = right.json_value().map_err(map_artifact_record_error)?;

    let left_normalized_raw = normalize_json_value(&left_raw);
    let right_normalized_raw = normalize_json_value(&right_raw);
    let non_semantic_differences_ignored =
        left_semantic_hash == right_semantic_hash && left_normalized_raw != right_normalized_raw;

    let semantic_relation = if left_semantic_hash == right_semantic_hash {
        if non_semantic_differences_ignored {
            SemanticRelationV1::NonSemanticOnlyDifference
        } else {
            SemanticRelationV1::SemanticallyIdentical
        }
    } else {
        SemanticRelationV1::SemanticallyDifferent
    };

    let mut changes = Vec::new();
    if semantic_relation == SemanticRelationV1::SemanticallyDifferent {
        diff_json_values("$", &left_projection, &right_projection, &mut changes);
        changes.sort_by(|left, right| left.path.cmp(&right.path));
    }

    Ok(SemanticDiffReportV1 {
        schema_id: "fitctl.diff.report.v1".to_string(),
        schema_version: 1,
        drift_class: drift_class_for_schema_id(&left_schema_id),
        semantic_relation,
        left_schema_id,
        right_schema_id,
        left_artifact_id: left.artifact_id().to_string(),
        right_artifact_id: right.artifact_id().to_string(),
        left_semantic_hash: Some(left_semantic_hash),
        right_semantic_hash: Some(right_semantic_hash),
        non_semantic_differences_ignored,
        changes,
    })
}

fn drift_class_for_schema_id(schema_id: &str) -> DriftClassV1 {
    match schema_id {
        HOST_SURVEY_SCHEMA_ID => DriftClassV1::EvidenceDrift,
        HOST_CONTRACT_SCHEMA_ID => DriftClassV1::ContractDrift,
        HOST_STATE_SCHEMA_ID => DriftClassV1::StateDrift,
        SERVICE_PROFILE_SCHEMA_ID => DriftClassV1::ServiceProfileDrift,
        VALIDATION_REPORT_SCHEMA_ID => DriftClassV1::ValidationReportDrift,
        _ => DriftClassV1::SchemaMismatch,
    }
}

fn diff_json_values(path: &str, left: &Value, right: &Value, changes: &mut Vec<SemanticChangeV1>) {
    if left == right {
        return;
    }

    match (left, right) {
        (Value::Object(left_map), Value::Object(right_map)) => {
            let keys: BTreeSet<&str> = left_map
                .keys()
                .map(String::as_str)
                .chain(right_map.keys().map(String::as_str))
                .collect();

            for key in keys {
                let child_path = format!("{path}.{key}");
                match (left_map.get(key), right_map.get(key)) {
                    (Some(left_value), Some(right_value)) => {
                        diff_json_values(&child_path, left_value, right_value, changes)
                    }
                    (Some(left_value), None) => changes.push(SemanticChangeV1 {
                        path: child_path,
                        change_kind: SemanticChangeKindV1::Subtractive,
                        left_value: Some(left_value.clone()),
                        right_value: None,
                    }),
                    (None, Some(right_value)) => changes.push(SemanticChangeV1 {
                        path: child_path,
                        change_kind: SemanticChangeKindV1::Additive,
                        left_value: None,
                        right_value: Some(right_value.clone()),
                    }),
                    (None, None) => {}
                }
            }
        }
        _ => changes.push(SemanticChangeV1 {
            path: path.to_string(),
            change_kind: SemanticChangeKindV1::Changed,
            left_value: Some(left.clone()),
            right_value: Some(right.clone()),
        }),
    }
}

fn normalize_json_value(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(normalize_json_value).collect()),
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut normalized = Map::new();
            for key in keys {
                normalized.insert(key.clone(), normalize_json_value(&map[key]));
            }
            Value::Object(normalized)
        }
        _ => value.clone(),
    }
}

fn map_artifact_record_error(error: ArtifactRecordError) -> DiffError {
    let code = match error.code {
        crate::artifacts::record_v1::ArtifactRecordErrorCode::ArtifactReadInvalid
        | crate::artifacts::record_v1::ArtifactRecordErrorCode::ArtifactDecodeInvalid
        | crate::artifacts::record_v1::ArtifactRecordErrorCode::ArtifactSchemaUnsupported
        | crate::artifacts::record_v1::ArtifactRecordErrorCode::ArtifactLoadInvalid => {
            DiffErrorCode::ArtifactLoadInvalid
        }
    };

    DiffError::new(code, "diff_load", error.message)
}
