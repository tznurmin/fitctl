// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Semantic drift classification for typed artifacts.
//!
//! The diff surface compares semantic content rather than presentation details so operators can
//! tell whether a change is materially meaningful.

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
