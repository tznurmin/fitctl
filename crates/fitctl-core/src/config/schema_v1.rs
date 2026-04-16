// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Typed configuration-pack schemas and JSON loaders for extension, recommendation, and invocation documents.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::artifacts::validation_report_v1::ValidationModeV1;
use crate::recommendation::recommendation_report_schema_id;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Per-run opt-ins layered on top of policy and pack inputs.
pub struct InvocationContextV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub invocation_id: String,
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
    pub validation_mode: Option<ValidationModeV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_state_age_seconds: Option<u64>,
    #[serde(default)]
    pub enabled_simulation_layer_ids: Vec<String>,
}

pub fn load_extension_pack_from_path(path: &Path) -> Result<ExtensionPackV1, ConfigError> {
    let raw = load_json_value_from_path(path, "extension pack")?;
    validate_extension_pack_json(&raw)?;
    let pack: ExtensionPackV1 = serde_json::from_value(raw).map_err(|error| {
        ConfigError::new(
            ConfigErrorCode::ConfigInputInvalid,
            "config_load",
            format!(
                "failed to decode extension pack {}: {error}",
                path.display()
            ),
        )
    })?;
    validate_extension_pack(&pack)?;
    Ok(pack)
}

pub fn load_recommendation_pack_from_path(
    path: &Path,
) -> Result<RecommendationPackV1, ConfigError> {
    let raw = load_json_value_from_path(path, "recommendation pack")?;
    validate_recommendation_pack_json(&raw)?;
    let pack: RecommendationPackV1 = serde_json::from_value(raw).map_err(|error| {
        ConfigError::new(
            ConfigErrorCode::ConfigInputInvalid,
            "config_load",
            format!(
                "failed to decode recommendation pack {}: {error}",
                path.display()
            ),
        )
    })?;
    validate_recommendation_pack(&pack)?;
    Ok(pack)
}

pub fn load_invocation_context_from_path(path: &Path) -> Result<InvocationContextV1, ConfigError> {
    let raw = load_json_value_from_path(path, "invocation context")?;
    validate_invocation_context_json(&raw)?;
    let context: InvocationContextV1 = serde_json::from_value(raw).map_err(|error| {
        ConfigError::new(
            ConfigErrorCode::ConfigInputInvalid,
            "config_load",
            format!(
                "failed to decode invocation context {}: {error}",
                path.display()
            ),
        )
    })?;
    validate_invocation_context(&context)?;
    Ok(context)
}

fn load_json_value_from_path(path: &Path, label: &str) -> Result<Value, ConfigError> {
    let text = fs::read_to_string(path).map_err(|error| {
        ConfigError::new(
            ConfigErrorCode::ConfigInputInvalid,
            "config_load",
            format!("failed to read {label} {}: {error}", path.display()),
        )
    })?;
    serde_json::from_str(&text).map_err(|error| {
        ConfigError::new(
            ConfigErrorCode::ConfigInputInvalid,
            "config_load",
            format!("failed to decode {label} {}: {error}", path.display()),
        )
    })
}

fn validate_extension_pack_json(raw: &Value) -> Result<(), ConfigError> {
    let root = require_object(raw, "extension pack root")?;
    reject_unknown_keys(
        root,
        &[
            "schema_id",
            "schema_version",
            "pack_id",
            "namespace",
            "namespace_owner",
            "pack_version",
            "collector_ids",
            "emitted_sections",
            "required_privilege",
            "freshness_model",
            "failure_semantics",
        ],
        "extension pack contains unsupported field",
    )?;
    reject_explicit_nulls(
        root,
        &[
            "schema_id",
            "schema_version",
            "pack_id",
            "namespace",
            "namespace_owner",
            "pack_version",
            "collector_ids",
            "emitted_sections",
            "required_privilege",
            "freshness_model",
            "failure_semantics",
        ],
        "extension pack field",
    )?;

    let sections = root
        .get("emitted_sections")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ConfigError::new(
                ConfigErrorCode::ConfigInputInvalid,
                "config_validate",
                "extension pack emitted_sections must be an array",
            )
        })?;
    for (index, section) in sections.iter().enumerate() {
        let section = section.as_object().ok_or_else(|| {
            ConfigError::new(
                ConfigErrorCode::ConfigInputInvalid,
                "config_validate",
                format!("extension emitted section at index {index} must be an object"),
            )
        })?;
        reject_unknown_keys(
            section,
            &["section_kind", "schema_id", "schema_version"],
            "extension emitted section contains unsupported field",
        )?;
        reject_explicit_nulls(
            section,
            &["section_kind", "schema_id", "schema_version"],
            "extension emitted section field",
        )?;
    }
    Ok(())
}

fn validate_recommendation_pack_json(raw: &Value) -> Result<(), ConfigError> {
    let root = require_object(raw, "recommendation pack root")?;
    reject_unknown_keys(
        root,
        &[
            "schema_id",
            "schema_version",
            "pack_id",
            "pack_version",
            "summary",
            "output_schema_id",
            "supported_extension_namespaces",
        ],
        "recommendation pack contains unsupported field",
    )?;
    reject_explicit_nulls(
        root,
        &[
            "schema_id",
            "schema_version",
            "pack_id",
            "pack_version",
            "summary",
            "output_schema_id",
            "supported_extension_namespaces",
        ],
        "recommendation pack field",
    )?;
    Ok(())
}

fn validate_invocation_context_json(raw: &Value) -> Result<(), ConfigError> {
    let root = require_object(raw, "invocation context root")?;
    reject_unknown_keys(
        root,
        &[
            "schema_id",
            "schema_version",
            "invocation_id",
            "enabled_extension_namespaces",
            "selected_recommendation_pack_ids",
            "enabled_simulation_layer_ids",
            "validation_mode",
            "max_state_age_seconds",
        ],
        "invocation context contains unsupported field",
    )?;
    reject_explicit_nulls(
        root,
        &[
            "schema_id",
            "schema_version",
            "invocation_id",
            "enabled_extension_namespaces",
            "selected_recommendation_pack_ids",
            "enabled_simulation_layer_ids",
            "validation_mode",
            "max_state_age_seconds",
        ],
        "invocation context field",
    )?;
    Ok(())
}

fn validate_extension_pack(pack: &ExtensionPackV1) -> Result<(), ConfigError> {
    if pack.schema_id != EXTENSION_PACK_SCHEMA_ID || pack.schema_version != 1 {
        return Err(ConfigError::new(
            ConfigErrorCode::ConfigInputInvalid,
            "config_validate",
            "extension pack must declare the supported schema id and version",
        ));
    }
    if is_blank(&pack.pack_id)
        || is_blank(&pack.namespace)
        || is_blank(&pack.namespace_owner)
        || is_blank(&pack.pack_version)
        || pack.collector_ids.is_empty()
        || pack.emitted_sections.is_empty()
    {
        return Err(ConfigError::new(
            ConfigErrorCode::ConfigInputInvalid,
            "config_validate",
            "extension packs require non-empty ids, namespace, namespace_owner, collector_ids, and emitted_sections",
        ));
    }

    validate_unique_nonblank(
        &pack.collector_ids,
        "extension pack collector_ids must be non-empty and unique",
    )?;

    let mut seen_sections = BTreeSet::new();
    for section in &pack.emitted_sections {
        if is_blank(&section.schema_id) || section.schema_version == 0 {
            return Err(ConfigError::new(
                ConfigErrorCode::ConfigInputInvalid,
                "config_validate",
                "extension emitted sections require non-empty schema ids and positive schema versions",
            ));
        }
        let key = (
            section.section_kind,
            section.schema_id.clone(),
            section.schema_version,
        );
        if !seen_sections.insert(key) {
            return Err(ConfigError::new(
                ConfigErrorCode::ConfigInputInvalid,
                "config_validate",
                "extension emitted sections must be unique by kind and schema identity",
            ));
        }
    }

    Ok(())
}

/// Hash an extension-pack manifest on its canonical semantic content.
pub fn semantic_hash_hex_for_extension_pack(pack: &ExtensionPackV1) -> Result<String, ConfigError> {
    #[derive(Serialize)]
    struct ExtensionSectionProjection<'a> {
        section_kind: ExtensionSectionKindV1,
        schema_id: &'a str,
        schema_version: u32,
    }

    #[derive(Serialize)]
    struct ExtensionPackSemanticProjection<'a> {
        pack_id: &'a str,
        namespace: &'a str,
        namespace_owner: &'a str,
        pack_version: &'a str,
        collector_ids: Vec<&'a str>,
        emitted_sections: Vec<ExtensionSectionProjection<'a>>,
        required_privilege: ExtensionPackPrivilegeV1,
        freshness_model: ExtensionFreshnessModelV1,
        failure_semantics: ExtensionFailureSemanticsV1,
    }

    let mut collector_ids = pack
        .collector_ids
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    collector_ids.sort_unstable();

    let mut emitted_sections = pack
        .emitted_sections
        .iter()
        .map(|section| ExtensionSectionProjection {
            section_kind: section.section_kind,
            schema_id: section.schema_id.as_str(),
            schema_version: section.schema_version,
        })
        .collect::<Vec<_>>();
    emitted_sections.sort_by(|left, right| {
        left.section_kind
            .cmp(&right.section_kind)
            .then_with(|| left.schema_id.cmp(right.schema_id))
            .then_with(|| left.schema_version.cmp(&right.schema_version))
    });

    let bytes = serde_cbor::to_vec(&ExtensionPackSemanticProjection {
        pack_id: &pack.pack_id,
        namespace: &pack.namespace,
        namespace_owner: &pack.namespace_owner,
        pack_version: &pack.pack_version,
        collector_ids,
        emitted_sections,
        required_privilege: pack.required_privilege,
        freshness_model: pack.freshness_model,
        failure_semantics: pack.failure_semantics,
    })
    .map_err(|error| {
        ConfigError::new(
            ConfigErrorCode::ConfigInputInvalid,
            "config_validate",
            format!("failed to encode extension-pack semantic projection: {error}"),
        )
    })?;

    let digest = Sha256::digest(bytes);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn validate_recommendation_pack(pack: &RecommendationPackV1) -> Result<(), ConfigError> {
    if pack.schema_id != RECOMMENDATION_PACK_SCHEMA_ID || pack.schema_version != 1 {
        return Err(ConfigError::new(
            ConfigErrorCode::ConfigInputInvalid,
            "config_validate",
            "recommendation pack must declare the supported schema id and version",
        ));
    }
    if is_blank(&pack.pack_id)
        || is_blank(&pack.pack_version)
        || is_blank(&pack.summary)
        || is_blank(&pack.output_schema_id)
    {
        return Err(ConfigError::new(
            ConfigErrorCode::ConfigInputInvalid,
            "config_validate",
            "recommendation packs require non-empty ids, version, summary, and output_schema_id",
        ));
    }
    validate_unique_nonblank(
        &pack.supported_extension_namespaces,
        "recommendation pack supported_extension_namespaces must be non-empty and unique when present",
    )?;
    if pack.output_schema_id != recommendation_report_schema_id() {
        return Err(ConfigError::new(
            ConfigErrorCode::ConfigInputInvalid,
            "config_validate",
            "recommendation packs must target fitctl.recommendation-report.v1",
        ));
    }
    Ok(())
}

fn validate_invocation_context(context: &InvocationContextV1) -> Result<(), ConfigError> {
    if context.schema_id != INVOCATION_CONTEXT_SCHEMA_ID || context.schema_version != 1 {
        return Err(ConfigError::new(
            ConfigErrorCode::ConfigInputInvalid,
            "config_validate",
            "invocation context must declare the supported schema id and version",
        ));
    }
    if is_blank(&context.invocation_id) {
        return Err(ConfigError::new(
            ConfigErrorCode::ConfigInputInvalid,
            "config_validate",
            "invocation contexts require a non-empty invocation_id",
        ));
    }
    validate_unique_nonblank(
        &context.enabled_extension_namespaces,
        "invocation enabled_extension_namespaces must be non-empty and unique",
    )?;
    validate_unique_nonblank(
        &context.selected_recommendation_pack_ids,
        "invocation selected_recommendation_pack_ids must be non-empty and unique",
    )?;
    validate_unique_nonblank(
        &context.enabled_simulation_layer_ids,
        "invocation enabled_simulation_layer_ids must be non-empty and unique",
    )?;
    if matches!(context.validation_mode, Some(ValidationModeV1::StateAware)) {
        return Err(ConfigError::new(
            ConfigErrorCode::ConfigInputInvalid,
            "config_validate",
            "invocation context must use canonical validation modes rather than the legacy state_aware alias",
        ));
    }
    if context
        .max_state_age_seconds
        .is_some_and(|value| value == 0)
    {
        return Err(ConfigError::new(
            ConfigErrorCode::ConfigInputInvalid,
            "config_validate",
            "invocation context max_state_age_seconds must be positive when present",
        ));
    }
    Ok(())
}

fn require_object<'a>(
    value: &'a Value,
    label: &'static str,
) -> Result<&'a Map<String, Value>, ConfigError> {
    value.as_object().ok_or_else(|| {
        ConfigError::new(
            ConfigErrorCode::ConfigInputInvalid,
            "config_validate",
            format!("{label} must decode to an object"),
        )
    })
}

fn reject_unknown_keys(
    map: &Map<String, Value>,
    allowed_keys: &[&str],
    message_prefix: &str,
) -> Result<(), ConfigError> {
    if let Some(key) = map.keys().find(|key| !allowed_keys.contains(&key.as_str())) {
        return Err(ConfigError::new(
            ConfigErrorCode::ConfigInputInvalid,
            "config_validate",
            format!("{message_prefix}: {key}"),
        ));
    }
    Ok(())
}

fn reject_explicit_nulls(
    map: &Map<String, Value>,
    allowed_keys: &[&str],
    message_prefix: &str,
) -> Result<(), ConfigError> {
    for key in allowed_keys {
        if map.get(*key).is_some_and(Value::is_null) {
            return Err(ConfigError::new(
                ConfigErrorCode::ConfigInputInvalid,
                "config_validate",
                format!("{message_prefix} {key} must not be null"),
            ));
        }
    }
    Ok(())
}

fn validate_unique_nonblank(values: &[String], message: &str) -> Result<(), ConfigError> {
    let mut seen = BTreeSet::new();
    for value in values {
        if is_blank(value) || !seen.insert(value.clone()) {
            return Err(ConfigError::new(
                ConfigErrorCode::ConfigInputInvalid,
                "config_validate",
                message,
            ));
        }
    }
    Ok(())
}

fn is_blank(value: &str) -> bool {
    value.trim().is_empty()
}
