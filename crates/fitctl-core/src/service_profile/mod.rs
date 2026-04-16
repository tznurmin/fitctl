// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Service-profile schemas and loading.
//!
//! Service profiles describe workload requirements, degradation ladders, and explicit validation
//! constraints. They do not define what a host may promise.

pub mod schema_v1;

pub use schema_v1::load_service_profile_from_path;

pub const SERVICE_PROFILE_ERROR_MODEL_ID: &str = "fitctl.service_profile.v1";
pub const SERVICE_PROFILE_ERROR_MODEL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceProfileErrorCode {
    ServiceProfileDocumentInvalid,
    ServiceProfileSchemaUnsupported,
    ServiceProfileRequirementInvalid,
    DegradationLadderInvalid,
    AssurancePredicateInvalid,
    ServiceProfileArtifactInvalid,
}

impl ServiceProfileErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ServiceProfileDocumentInvalid => "service_profile_document_invalid",
            Self::ServiceProfileSchemaUnsupported => "service_profile_schema_unsupported",
            Self::ServiceProfileRequirementInvalid => "service_profile_requirement_invalid",
            Self::DegradationLadderInvalid => "degradation_ladder_invalid",
            Self::AssurancePredicateInvalid => "assurance_predicate_invalid",
            Self::ServiceProfileArtifactInvalid => "service_profile_artifact_invalid",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceProfileError {
    pub code: ServiceProfileErrorCode,
    pub checkpoint_id: &'static str,
    pub message: String,
    pub error_model_id: &'static str,
    pub error_model_version: u32,
}

impl ServiceProfileError {
    pub(crate) fn new(
        code: ServiceProfileErrorCode,
        checkpoint_id: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            checkpoint_id,
            message: message.into(),
            error_model_id: SERVICE_PROFILE_ERROR_MODEL_ID,
            error_model_version: SERVICE_PROFILE_ERROR_MODEL_VERSION,
        }
    }
}

impl std::fmt::Display for ServiceProfileError {
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

impl std::error::Error for ServiceProfileError {}
