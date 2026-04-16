// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Profile-driven artifact redaction.
//!
//! Redaction removes or replaces sensitive fields while preserving the typed artifact structure
//! needed for sharing and downstream tooling.

pub mod apply_v1;
pub mod profile_v1;

pub use apply_v1::{load_artifact_record_for_redaction, redact_artifact_v1, RedactionRequestV1};
pub use profile_v1::{parse_builtin_redaction_profile_v1, BuiltInRedactionProfileV1};

pub const REDACTION_ERROR_MODEL_ID: &str = "fitctl.redaction.v1";
pub const REDACTION_ERROR_MODEL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionErrorCode {
    ArtifactInputInvalid,
    RedactionProfileInvalid,
    RedactionInputAlreadyRedacted,
    RedactionApplyFailed,
    RedactionOutputInvalid,
}

impl RedactionErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ArtifactInputInvalid => "artifact_input_invalid",
            Self::RedactionProfileInvalid => "redaction_profile_invalid",
            Self::RedactionInputAlreadyRedacted => "redaction_input_already_redacted",
            Self::RedactionApplyFailed => "redaction_apply_failed",
            Self::RedactionOutputInvalid => "redaction_output_invalid",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionError {
    pub code: RedactionErrorCode,
    pub checkpoint_id: &'static str,
    pub message: String,
    pub error_model_id: &'static str,
    pub error_model_version: u32,
}

impl RedactionError {
    pub(crate) fn new(
        code: RedactionErrorCode,
        checkpoint_id: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            checkpoint_id,
            message: message.into(),
            error_model_id: REDACTION_ERROR_MODEL_ID,
            error_model_version: REDACTION_ERROR_MODEL_VERSION,
        }
    }
}

impl std::fmt::Display for RedactionError {
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

impl std::error::Error for RedactionError {}
