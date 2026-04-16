// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Canonical schema ids for the supported top-level artifact families.

pub const HOST_SURVEY_SCHEMA_ID: &str = "host-survey.v1";
pub const HOST_CONTRACT_SCHEMA_ID: &str = "host-contract.v1";
pub const HOST_STATE_SCHEMA_ID: &str = "host-state.v1";
pub const SERVICE_PROFILE_SCHEMA_ID: &str = "service-profile.v1";
pub const VALIDATION_REPORT_SCHEMA_ID: &str = "validation-report.v1";
pub const RECOMMENDATION_REPORT_SCHEMA_ID: &str = "fitctl.recommendation-report.v1";
pub const BATCH_CLASSIFICATION_REPORT_SCHEMA_ID: &str = "fitctl.batch-classification-report.v1";

pub const CORE_TOP_LEVEL_SCHEMA_IDS: [&str; 5] = [
    HOST_SURVEY_SCHEMA_ID,
    HOST_CONTRACT_SCHEMA_ID,
    HOST_STATE_SCHEMA_ID,
    SERVICE_PROFILE_SCHEMA_ID,
    VALIDATION_REPORT_SCHEMA_ID,
];

pub fn is_supported_core_schema_id(schema_id: &str) -> bool {
    CORE_TOP_LEVEL_SCHEMA_IDS.contains(&schema_id)
}
