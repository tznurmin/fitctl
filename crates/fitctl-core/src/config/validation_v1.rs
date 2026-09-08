// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Existing semantic checks for typed configuration documents.

use super::schema_v1::{
    ConfigError, ConfigErrorCode, ExtensionPackV1, InvocationContextV1, RecommendationPackV1,
    ResolvedConfigV1, EXTENSION_PACK_SCHEMA_ID, INVOCATION_CONTEXT_SCHEMA_ID,
    RECOMMENDATION_PACK_SCHEMA_ID, RESOLVED_CONFIG_SCHEMA_ID,
};
use crate::artifacts::validation_report_v1::ValidationModeV1;
use crate::recommendation::recommendation_report_schema_id;
use std::collections::BTreeSet;

pub(super) fn validate_extension_pack(pack: &ExtensionPackV1) -> Result<(), ConfigError> {
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

pub(super) fn validate_recommendation_pack(pack: &RecommendationPackV1) -> Result<(), ConfigError> {
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
            "recommendation packs must target fitctl.recommendation-report.v2",
        ));
    }
    Ok(())
}

pub(super) fn validate_invocation_context(
    context: &InvocationContextV1,
) -> Result<(), ConfigError> {
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
    if context
        .selected_policy_id
        .as_ref()
        .is_some_and(|value| is_blank(value))
    {
        return Err(ConfigError::new(
            ConfigErrorCode::ConfigInputInvalid,
            "config_validate",
            "invocation context selected_policy_id must be non-empty when present",
        ));
    }
    if context
        .selected_service_profile_id
        .as_ref()
        .is_some_and(|value| is_blank(value))
    {
        return Err(ConfigError::new(
            ConfigErrorCode::ConfigInputInvalid,
            "config_validate",
            "invocation context selected_service_profile_id must be non-empty when present",
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

pub fn validate_resolved_config(resolved: &ResolvedConfigV1) -> Result<(), ConfigError> {
    if resolved.schema_id != RESOLVED_CONFIG_SCHEMA_ID || resolved.schema_version != 1 {
        return Err(ConfigError::new(
            ConfigErrorCode::ConfigInputInvalid,
            "config_validate",
            "resolved config must declare the supported schema id and version",
        ));
    }
    if is_blank(&resolved.policy_id) {
        return Err(ConfigError::new(
            ConfigErrorCode::ConfigInputInvalid,
            "config_validate",
            "resolved config policy_id must be populated",
        ));
    }
    validate_unique_nonblank(
        &resolved.selected_policy_layers,
        "resolved config selected_policy_layers must be non-empty and unique",
    )?;
    validate_unique_nonblank(
        &resolved.policy_allowed_extension_namespaces,
        "resolved config policy_allowed_extension_namespaces must be non-empty and unique when present",
    )?;
    validate_unique_nonblank(
        &resolved.configured_extension_pack_ids,
        "resolved config configured_extension_pack_ids must be non-empty and unique when present",
    )?;
    validate_unique_nonblank(
        &resolved.available_extension_namespaces,
        "resolved config available_extension_namespaces must be non-empty and unique when present",
    )?;
    validate_unique_nonblank(
        &resolved.enabled_extension_namespaces,
        "resolved config enabled_extension_namespaces must be non-empty and unique when present",
    )?;
    validate_unique_nonblank(
        &resolved.available_recommendation_pack_ids,
        "resolved config available_recommendation_pack_ids must be non-empty and unique when present",
    )?;
    validate_unique_nonblank(
        &resolved.selected_recommendation_pack_ids,
        "resolved config selected_recommendation_pack_ids must be non-empty and unique when present",
    )?;
    validate_unique_nonblank(
        &resolved.enabled_simulation_layer_ids,
        "resolved config enabled_simulation_layer_ids must be non-empty and unique when present",
    )?;

    if resolved
        .selected_policy_pack_id
        .as_ref()
        .is_some_and(|value| is_blank(value))
        || resolved
            .selected_policy_entry_id
            .as_ref()
            .is_some_and(|value| is_blank(value))
        || resolved
            .selected_policy_pack_lock_id
            .as_ref()
            .is_some_and(|value| is_blank(value))
        || resolved
            .trust_policy_id
            .as_ref()
            .is_some_and(|value| is_blank(value))
        || resolved
            .invocation_id
            .as_ref()
            .is_some_and(|value| is_blank(value))
        || resolved
            .selected_service_profile_catalogue_id
            .as_ref()
            .is_some_and(|value| is_blank(value))
        || resolved
            .selected_service_profile_entry_id
            .as_ref()
            .is_some_and(|value| is_blank(value))
    {
        return Err(ConfigError::new(
            ConfigErrorCode::ConfigInputInvalid,
            "config_validate",
            "resolved config optional identifiers must be non-empty when present",
        ));
    }
    if matches!(resolved.validation_mode, Some(ValidationModeV1::StateAware)) {
        return Err(ConfigError::new(
            ConfigErrorCode::ConfigInputInvalid,
            "config_validate",
            "resolved config must use canonical validation modes rather than the legacy state_aware alias",
        ));
    }
    if resolved
        .max_state_age_seconds
        .is_some_and(|value| value == 0)
    {
        return Err(ConfigError::new(
            ConfigErrorCode::ConfigInputInvalid,
            "config_validate",
            "resolved config max_state_age_seconds must be positive when present",
        ));
    }

    let mut disabled_namespaces = BTreeSet::new();
    for entry in &resolved.disabled_extension_namespaces {
        if is_blank(&entry.namespace) || !disabled_namespaces.insert(entry.namespace.clone()) {
            return Err(ConfigError::new(
                ConfigErrorCode::ConfigInputInvalid,
                "config_validate",
                "resolved config disabled_extension_namespaces must use non-empty unique namespaces",
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
