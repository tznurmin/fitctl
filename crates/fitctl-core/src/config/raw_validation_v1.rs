// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Raw JSON constraints shared by configuration ingress.

use super::schema_v1::{ConfigError, ConfigErrorCode};
use serde_json::{Map, Value};

pub(super) fn validate_extension_pack_json(raw: &Value) -> Result<(), ConfigError> {
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

pub(super) fn validate_recommendation_pack_json(raw: &Value) -> Result<(), ConfigError> {
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

pub(super) fn validate_invocation_context_json(raw: &Value) -> Result<(), ConfigError> {
    let root = require_object(raw, "invocation context root")?;
    reject_unknown_keys(
        root,
        &[
            "schema_id",
            "schema_version",
            "invocation_id",
            "selected_policy_id",
            "selected_service_profile_id",
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
            "selected_policy_id",
            "selected_service_profile_id",
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
