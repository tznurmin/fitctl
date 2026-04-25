// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Canonical schema ids for the supported top-level artifact families.

pub const TOP_LEVEL_ARTIFACT_SCHEMA_VERSION: u32 = 2;

pub const HOST_SURVEY_SCHEMA_ID: &str = "host-survey.v2";
pub const HOST_CONTRACT_SCHEMA_ID: &str = "host-contract.v2";
pub const HOST_STATE_SCHEMA_ID: &str = "host-state.v2";
pub const SERVICE_PROFILE_SCHEMA_ID: &str = "service-profile.v2";
pub const VALIDATION_REPORT_SCHEMA_ID: &str = "validation-report.v2";
pub const RECOMMENDATION_REPORT_SCHEMA_ID: &str = "fitctl.recommendation-report.v2";
pub const LEGACY_BATCH_CLASSIFICATION_REPORT_SCHEMA_ID: &str =
    "fitctl.batch-classification-report.v2";
pub const BATCH_CLASSIFICATION_REPORT_SCHEMA_ID: &str = "fitctl.batch-classification-report.v3";
pub const CONFIG_BUNDLE_SCHEMA_ID: &str = "fitctl.config-bundle.v2";
pub const DECISION_BUNDLE_SCHEMA_ID: &str = "fitctl.decision-bundle.v2";

pub const BATCH_CLASSIFICATION_REPORT_SCHEMA_IDS: [&str; 2] = [
    LEGACY_BATCH_CLASSIFICATION_REPORT_SCHEMA_ID,
    BATCH_CLASSIFICATION_REPORT_SCHEMA_ID,
];

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

pub fn is_supported_batch_classification_report_schema_id(schema_id: &str) -> bool {
    BATCH_CLASSIFICATION_REPORT_SCHEMA_IDS.contains(&schema_id)
}
