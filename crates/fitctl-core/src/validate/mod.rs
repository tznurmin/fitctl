// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Validation over contracts, service profiles, and optional runtime state.
//!
//! Validation answers "does this workload fit this host promise?" rather than recomputing host
//! capabilities from raw survey evidence on every call.

pub mod contract_only_v1;
pub mod reason_codes_v1;

pub use crate::artifacts::validation_report_v1::{
    ValidationModeV1, ValidationReasonCodeV1, ValidationReportV1, ValidationVerdictV1,
};
pub use contract_only_v1::{
    load_contract_artifact_for_validation, load_host_state_artifact_for_validation,
    load_service_profile_artifact_for_validation, load_validation_report_from_path,
    validate_request_v1, ValidationRequestV1,
};
pub use reason_codes_v1::{VALIDATION_REASON_CODES_V1, VALIDATION_VERDICTS_V1};

pub const VALIDATION_ERROR_MODEL_ID: &str = "fitctl.validate.v1";
pub const VALIDATION_ERROR_MODEL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationErrorCode {
    ValidationInputInvalid,
    ContractArtifactInvalid,
    ServiceProfileArtifactInvalid,
    StateArtifactInvalid,
    ValidationModeUnsupported,
    ValidationReportInvalid,
    ValidationExecutionFailed,
}

impl ValidationErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ValidationInputInvalid => "validation_input_invalid",
            Self::ContractArtifactInvalid => "contract_artifact_invalid",
            Self::ServiceProfileArtifactInvalid => "service_profile_artifact_invalid",
            Self::StateArtifactInvalid => "state_artifact_invalid",
            Self::ValidationModeUnsupported => "validation_mode_unsupported",
            Self::ValidationReportInvalid => "validation_report_invalid",
            Self::ValidationExecutionFailed => "validation_execution_failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    pub code: ValidationErrorCode,
    pub checkpoint_id: &'static str,
    pub message: String,
    pub error_model_id: &'static str,
    pub error_model_version: u32,
}

impl ValidationError {
    pub(crate) fn new(
        code: ValidationErrorCode,
        checkpoint_id: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            checkpoint_id,
            message: message.into(),
            error_model_id: VALIDATION_ERROR_MODEL_ID,
            error_model_version: VALIDATION_ERROR_MODEL_VERSION,
        }
    }
}

impl std::fmt::Display for ValidationError {
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

impl std::error::Error for ValidationError {}
