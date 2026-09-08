// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Typed configuration schemas and validated loading facade.

use serde::{Deserialize, Serialize};

use crate::artifacts::validation_report_v1::ValidationModeV1;

pub const CONFIG_ERROR_MODEL_ID: &str = "fitctl.config.v1";
pub const CONFIG_ERROR_MODEL_VERSION: u32 = 1;
pub const EXTENSION_PACK_SCHEMA_ID: &str = "fitctl.extension-pack.v1";
pub const RECOMMENDATION_PACK_SCHEMA_ID: &str = "fitctl.recommendation-pack.v1";
pub const INVOCATION_CONTEXT_SCHEMA_ID: &str = "fitctl.invocation-context.v1";
pub const RESOLVED_CONFIG_SCHEMA_ID: &str = "fitctl.resolved-config.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigErrorCode {
    ConfigInputInvalid,
    ConfigResolveConflict,
}

impl ConfigErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfigInputInvalid => "config_input_invalid",
            Self::ConfigResolveConflict => "config_resolve_conflict",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub code: ConfigErrorCode,
    pub checkpoint_id: &'static str,
    pub message: String,
    pub error_model_id: &'static str,
    pub error_model_version: u32,
}

impl ConfigError {
    pub fn new(
        code: ConfigErrorCode,
        checkpoint_id: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            checkpoint_id,
            message: message.into(),
            error_model_id: CONFIG_ERROR_MODEL_ID,
            error_model_version: CONFIG_ERROR_MODEL_VERSION,
        }
    }
}

impl std::fmt::Display for ConfigError {
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

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Required privilege level for the pack's collectors.
pub enum ExtensionPackPrivilegeV1 {
    Unprivileged,
    ElevatedVisibility,
    Root,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// How long emitted extension evidence can be treated as current.
pub enum ExtensionFreshnessModelV1 {
    StaticUntilRecollected,
    SnapshotBound,
    LiveStateBound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Whether extension failure blocks the namespace entirely or must stay explicit in output.
pub enum ExtensionFailureSemanticsV1 {
    FailClosed,
    PartialExplicit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Which phase of the artifact pipeline an extension section belongs to.
pub enum ExtensionSectionKindV1 {
    SurveyEvidence,
    ExtensionContract,
    ExtensionState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Declares one extension namespace and the sections it may emit.
pub struct ExtensionSectionSchemaV1 {
    pub section_kind: ExtensionSectionKindV1,
    pub schema_id: String,
    pub schema_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Extension-pack manifest for one namespace.
///
/// This declares what the namespace may emit and the collection/runtime expectations around it.
pub struct ExtensionPackV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub pack_id: String,
    pub namespace: String,
    pub namespace_owner: String,
    pub pack_version: String,
    pub collector_ids: Vec<String>,
    pub emitted_sections: Vec<ExtensionSectionSchemaV1>,
    pub required_privilege: ExtensionPackPrivilegeV1,
    pub freshness_model: ExtensionFreshnessModelV1,
    pub failure_semantics: ExtensionFailureSemanticsV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Advisory pack contract for recommendation output.
///
/// Recommendation packs stay outside the core validation verdict.
pub struct RecommendationPackV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub pack_id: String,
    pub pack_version: String,
    pub summary: String,
    pub output_schema_id: String,
    #[serde(default)]
    pub supported_extension_namespaces: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Where a pack or catalogue entry id came from in the final resolved run.
pub enum ConfigSelectionSourceV1 {
    Cli,
    InvocationContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Per-run opt-ins layered on top of policy and pack inputs.
pub struct InvocationContextV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub invocation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_policy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_service_profile_id: Option<String>,
    #[serde(default)]
    pub enabled_extension_namespaces: Vec<String>,
    #[serde(default)]
    pub selected_recommendation_pack_ids: Vec<String>,
    #[serde(default)]
    pub enabled_simulation_layer_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_mode: Option<ValidationModeV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_state_age_seconds: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisabledExtensionReasonV1 {
    PolicyDisallowed,
    InvocationNotEnabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Records why a namespace stayed disabled after configuration resolution.
pub struct DisabledExtensionNamespaceV1 {
    pub namespace: String,
    pub reason: DisabledExtensionReasonV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Frozen merged configuration view used by inspect-config and the CLI pipeline.
pub struct ResolvedConfigV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub policy_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_policy_pack_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_policy_entry_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_policy_entry_source: Option<ConfigSelectionSourceV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_policy_pack_lock_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_policy_pack_lock_signed: Option<bool>,
    pub selected_policy_layers: Vec<String>,
    pub policy_allowed_extension_namespaces: Vec<String>,
    pub configured_extension_pack_ids: Vec<String>,
    pub available_extension_namespaces: Vec<String>,
    pub enabled_extension_namespaces: Vec<String>,
    #[serde(default)]
    pub disabled_extension_namespaces: Vec<DisabledExtensionNamespaceV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_policy_id: Option<String>,
    pub available_recommendation_pack_ids: Vec<String>,
    pub selected_recommendation_pack_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invocation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_service_profile_catalogue_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_service_profile_entry_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_service_profile_entry_source: Option<ConfigSelectionSourceV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_mode: Option<ValidationModeV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_state_age_seconds: Option<u64>,
    #[serde(default)]
    pub enabled_simulation_layer_ids: Vec<String>,
}

pub use super::load_v1::{
    add_missing_built_in_extension_packs_v1, built_in_extension_pack_for_namespace_v1,
    load_extension_pack_from_path, load_extension_pack_from_value,
    load_invocation_context_from_path, load_invocation_context_from_value,
    load_recommendation_pack_from_path, load_resolved_config_from_path,
};
pub use super::semantic_hash_v1::{
    semantic_hash_hex_for_extension_pack, semantic_hash_hex_for_resolved_config,
};
pub use super::validation_v1::validate_resolved_config;
