// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Semantic drift classification for typed artifacts.
//!
//! The diff surface compares semantic content rather than presentation details so operators can
//! tell whether a change is materially meaningful.

use serde::{Deserialize, Serialize};

pub mod semantic_v1;

pub use semantic_v1::{
    diff_artifact_records_v1, load_artifact_record_for_diff, DriftClassV1, SemanticChangeKindV1,
    SemanticChangeV1, SemanticDiffReportV1, SemanticRelationV1,
};

pub const DIFF_ERROR_MODEL_ID: &str = "fitctl.diff.v1";
pub const DIFF_ERROR_MODEL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffErrorCode {
    ArtifactLoadInvalid,
    DiffInputInvalid,
    SemanticProjectionInvalid,
}

impl DiffErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ArtifactLoadInvalid => "artifact_load_invalid",
            Self::DiffInputInvalid => "diff_input_invalid",
            Self::SemanticProjectionInvalid => "semantic_projection_invalid",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffError {
    pub code: DiffErrorCode,
    pub checkpoint_id: &'static str,
    pub message: String,
    pub error_model_id: &'static str,
    pub error_model_version: u32,
}

impl DiffError {
    pub(crate) fn new(
        code: DiffErrorCode,
        checkpoint_id: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            checkpoint_id,
            message: message.into(),
            error_model_id: DIFF_ERROR_MODEL_ID,
            error_model_version: DIFF_ERROR_MODEL_VERSION,
        }
    }
}

impl std::fmt::Display for DiffError {
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

impl std::error::Error for DiffError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactDriftViewV1 {
    pub drift_class: DriftClassV1,
    pub semantic_relation: SemanticRelationV1,
    pub left_artifact_id: String,
    pub right_artifact_id: String,
    pub changed_path_count: usize,
    pub changed_paths: Vec<String>,
    pub non_semantic_differences_ignored: bool,
}

pub fn compact_drift_view_v1(report: &SemanticDiffReportV1) -> CompactDriftViewV1 {
    CompactDriftViewV1 {
        drift_class: report.drift_class,
        semantic_relation: report.semantic_relation,
        left_artifact_id: report.left_artifact_id.clone(),
        right_artifact_id: report.right_artifact_id.clone(),
        changed_path_count: report.changes.len(),
        changed_paths: report
            .changes
            .iter()
            .map(|change| change.path.clone())
            .collect(),
        non_semantic_differences_ignored: report.non_semantic_differences_ignored,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::semantic_v1::{DriftClassV1, SemanticDiffReportV1, SemanticRelationV1};

    #[test]
    fn compact_drift_view_preserves_changed_paths_and_counts() {
        let report = SemanticDiffReportV1 {
            schema_id: "fitctl.diff.report.v1".to_string(),
            schema_version: 1,
            drift_class: DriftClassV1::ContractDrift,
            semantic_relation: SemanticRelationV1::SemanticallyDifferent,
            left_schema_id: "fitctl.host-contract.v2".to_string(),
            right_schema_id: "fitctl.host-contract.v2".to_string(),
            left_artifact_id: "left".to_string(),
            right_artifact_id: "right".to_string(),
            left_semantic_hash: Some("a".to_string()),
            right_semantic_hash: Some("b".to_string()),
            non_semantic_differences_ignored: false,
            changes: vec![
                SemanticChangeV1 {
                    path: "$.contract.capability".to_string(),
                    change_kind: SemanticChangeKindV1::Changed,
                    left_value: None,
                    right_value: None,
                },
                SemanticChangeV1 {
                    path: "$.contract.constraints".to_string(),
                    change_kind: SemanticChangeKindV1::Additive,
                    left_value: None,
                    right_value: None,
                },
            ],
        };

        let view = compact_drift_view_v1(&report);
        assert_eq!(view.drift_class, DriftClassV1::ContractDrift);
        assert_eq!(view.changed_path_count, 2);
        assert_eq!(
            view.changed_paths,
            vec![
                "$.contract.capability".to_string(),
                "$.contract.constraints".to_string()
            ]
        );
    }
}
