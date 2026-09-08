// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Validated configuration ingress without consumer-side decoding shortcuts.

use super::raw_validation_v1::{
    validate_extension_pack_json, validate_invocation_context_json,
    validate_recommendation_pack_json,
};
use super::schema_v1::{
    ConfigError, ConfigErrorCode, ExtensionPackV1, InvocationContextV1, RecommendationPackV1,
    ResolvedConfigV1,
};
use super::validation_v1::{
    validate_extension_pack, validate_invocation_context, validate_recommendation_pack,
    validate_resolved_config,
};
use serde_json::Value;
use std::fs;
use std::path::Path;

pub fn load_extension_pack_from_path(path: &Path) -> Result<ExtensionPackV1, ConfigError> {
    let raw = load_json_value_from_path(path, "extension pack")?;
    decode_extension_pack(raw, Some(path))
}

/// Validate a supplied extension pack with the same raw, typed and semantic checks as file ingress.
///
/// Performs no I/O. Explicit null fields retain their distinction from omission.
pub fn load_extension_pack_from_value(raw: Value) -> Result<ExtensionPackV1, ConfigError> {
    decode_extension_pack(raw, None)
}

fn decode_extension_pack(
    raw: Value,
    source_path: Option<&Path>,
) -> Result<ExtensionPackV1, ConfigError> {
    validate_extension_pack_json(&raw)?;
    let pack: ExtensionPackV1 = serde_json::from_value(raw).map_err(|error| {
        ConfigError::new(
            ConfigErrorCode::ConfigInputInvalid,
            "config_load",
            match source_path {
                Some(path) => format!(
                    "failed to decode extension pack {}: {error}",
                    path.display()
                ),
                None => format!("failed to decode extension pack: {error}"),
            },
        )
    })?;
    validate_extension_pack(&pack)?;
    Ok(pack)
}

pub fn built_in_extension_pack_for_namespace_v1(namespace: &str) -> Option<ExtensionPackV1> {
    let raw = match namespace {
        "fitctl.runtime.cuda" => include_str!("builtin/fitctl_runtime_cuda.v1.json"),
        "fitctl.runtime.python" => include_str!("builtin/fitctl_runtime_python.v1.json"),
        "fitctl.runtime.node" => include_str!("builtin/fitctl_runtime_node.v1.json"),
        _ => return None,
    };
    Some(decode_built_in_extension_pack_v1(raw))
}

fn decode_built_in_extension_pack_v1(raw: &str) -> ExtensionPackV1 {
    let pack: ExtensionPackV1 =
        serde_json::from_str(raw).expect("built-in extension pack manifest must decode");
    validate_extension_pack(&pack).expect("built-in extension pack manifest must validate");
    pack
}

pub fn add_missing_built_in_extension_packs_v1(
    extension_packs: &mut Vec<ExtensionPackV1>,
    requested_extension_namespaces: &[String],
) {
    for namespace in requested_extension_namespaces {
        if extension_packs
            .iter()
            .any(|pack| pack.namespace == *namespace)
        {
            continue;
        }
        if let Some(pack) = built_in_extension_pack_for_namespace_v1(namespace) {
            extension_packs.push(pack);
        }
    }
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
    decode_invocation_context(raw, Some(path))
}

/// Validate a supplied invocation context with the same raw, typed and semantic checks as file ingress.
///
/// Performs no I/O. Explicit null fields retain their distinction from omission.
pub fn load_invocation_context_from_value(raw: Value) -> Result<InvocationContextV1, ConfigError> {
    decode_invocation_context(raw, None)
}

fn decode_invocation_context(
    raw: Value,
    source_path: Option<&Path>,
) -> Result<InvocationContextV1, ConfigError> {
    validate_invocation_context_json(&raw)?;
    let context: InvocationContextV1 = serde_json::from_value(raw).map_err(|error| {
        ConfigError::new(
            ConfigErrorCode::ConfigInputInvalid,
            "config_load",
            match source_path {
                Some(path) => format!(
                    "failed to decode invocation context {}: {error}",
                    path.display()
                ),
                None => format!("failed to decode invocation context: {error}"),
            },
        )
    })?;
    validate_invocation_context(&context)?;
    Ok(context)
}

pub fn load_resolved_config_from_path(path: &Path) -> Result<ResolvedConfigV1, ConfigError> {
    let raw = load_json_value_from_path(path, "resolved config")?;
    let resolved: ResolvedConfigV1 = serde_json::from_value(raw).map_err(|error| {
        ConfigError::new(
            ConfigErrorCode::ConfigInputInvalid,
            "config_load",
            format!(
                "failed to decode resolved config {}: {error}",
                path.display()
            ),
        )
    })?;
    validate_resolved_config(&resolved)?;
    Ok(resolved)
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
