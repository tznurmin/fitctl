// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Typed policy-document schema, loaders, and fail-closed validation helpers.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::contract::{ContractDerivationError, ContractDerivationErrorCode};
use crate::survey::AcceleratorKindV1;

pub const POLICY_DOCUMENT_SCHEMA_ID: &str = "fitctl.policy.document.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Policy shapes what a surveyed host may promise.
///
/// The same survey can yield different contracts under different policies.
pub struct PolicyDocumentV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub policy_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short_display_name: Option<String>,
    pub layers: Vec<PolicyLayerV1>,
    #[serde(default)]
    pub extension_policy: PolicyExtensionPolicyV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// One precedence-ranked override layer inside a policy document.
pub struct PolicyLayerV1 {
    pub layer_id: String,
    pub kind: PolicyLayerKindV1,
    pub rules: PolicyRulesOverrideV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Higher-precedence kinds override lower ones when both set the same rule.
pub enum PolicyLayerKindV1 {
    BuiltInDefaults,
    Site,
    HostClass,
    HostLocal,
    ValidationSimulation,
}

impl PolicyLayerKindV1 {
    pub fn precedence_rank(self) -> u8 {
        match self {
            Self::BuiltInDefaults => 0,
            Self::Site => 1,
            Self::HostClass => 2,
            Self::HostLocal => 3,
            Self::ValidationSimulation => 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
/// Sparse override set.
///
/// Omitted fields intentionally inherit from lower-precedence layers.
pub struct PolicyRulesOverrideV1 {
    pub capability_class: Option<String>,
    pub min_cpu_logical_cores: Option<u32>,
    pub min_memory_bytes: Option<u64>,
    pub allow_container_restricted: Option<bool>,
    pub require_network_visibility: Option<bool>,
    pub required_accelerator_kind: Option<AcceleratorKindV1>,
    pub min_accelerator_devices: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
/// Namespace allowlist for extension-derived contract content.
pub struct PolicyExtensionPolicyV1 {
    #[serde(default)]
    pub allowed_extension_namespaces: Vec<String>,
}

pub fn load_policy_document_from_path(
    path: &Path,
) -> Result<PolicyDocumentV1, ContractDerivationError> {
    let text = fs::read_to_string(path).map_err(|error| {
        ContractDerivationError::new(
            ContractDerivationErrorCode::PolicyDocumentInvalid,
            "policy_load",
            format!("failed to read policy document {}: {error}", path.display()),
        )
    })?;

    let raw: Value = serde_json::from_str(&text).map_err(|error| {
        ContractDerivationError::new(
            ContractDerivationErrorCode::PolicyDocumentInvalid,
            "policy_load",
            format!(
                "failed to decode policy document {}: {error}",
                path.display()
            ),
        )
    })?;
    validate_policy_document_json(&raw)?;
    let policy: PolicyDocumentV1 = serde_json::from_value(raw).map_err(|error| {
        ContractDerivationError::new(
            ContractDerivationErrorCode::PolicyDocumentInvalid,
            "policy_load",
            format!(
                "failed to decode typed policy document {}: {error}",
                path.display()
            ),
        )
    })?;

    validate_policy_document(&policy)?;
    Ok(policy)
}

fn validate_policy_document_json(raw: &Value) -> Result<(), ContractDerivationError> {
    let root = raw.as_object().ok_or_else(|| {
        ContractDerivationError::new(
            ContractDerivationErrorCode::PolicyDocumentInvalid,
            "policy_load",
            "policy document must decode to a JSON object",
        )
    })?;

    reject_unknown_keys(
        root,
        &[
            "schema_id",
            "schema_version",
            "policy_id",
            "display_name",
            "short_display_name",
            "layers",
            "extension_policy",
        ],
        "policy document contains unsupported top-level field",
    )?;
    reject_explicit_nulls(
        root,
        &[
            "schema_id",
            "schema_version",
            "policy_id",
            "display_name",
            "short_display_name",
            "layers",
            "extension_policy",
        ],
        "policy document field",
    )?;

    if let Some(layers) = root.get("layers") {
        let layers = layers.as_array().ok_or_else(|| {
            ContractDerivationError::new(
                ContractDerivationErrorCode::PolicyDocumentInvalid,
                "policy_load",
                "policy document layers must be an array",
            )
        })?;

        for (index, layer) in layers.iter().enumerate() {
            let layer = layer.as_object().ok_or_else(|| {
                ContractDerivationError::new(
                    ContractDerivationErrorCode::PolicyDocumentInvalid,
                    "policy_load",
                    format!("policy layer at index {index} must be an object"),
                )
            })?;

            reject_unknown_keys(
                layer,
                &["layer_id", "kind", "rules"],
                "policy layer contains unsupported field",
            )?;
            reject_explicit_nulls(layer, &["layer_id", "kind", "rules"], "policy layer field")?;

            if let Some(rules) = layer.get("rules") {
                let rules = rules.as_object().ok_or_else(|| {
                    ContractDerivationError::new(
                        ContractDerivationErrorCode::PolicyDocumentInvalid,
                        "policy_load",
                        format!("policy layer rules at index {index} must be an object"),
                    )
                })?;

                reject_unknown_keys(
                    rules,
                    &[
                        "capability_class",
                        "min_cpu_logical_cores",
                        "min_memory_bytes",
                        "allow_container_restricted",
                        "require_network_visibility",
                        "required_accelerator_kind",
                        "min_accelerator_devices",
                    ],
                    "policy layer rules contain unsupported field",
                )?;
                reject_explicit_nulls(
                    rules,
                    &[
                        "capability_class",
                        "min_cpu_logical_cores",
                        "min_memory_bytes",
                        "allow_container_restricted",
                        "require_network_visibility",
                        "required_accelerator_kind",
                        "min_accelerator_devices",
                    ],
                    "policy rule override",
                )?;
            }
        }
    }

    if let Some(extension_policy) = root.get("extension_policy") {
        let extension_policy = extension_policy.as_object().ok_or_else(|| {
            ContractDerivationError::new(
                ContractDerivationErrorCode::PolicyDocumentInvalid,
                "policy_load",
                "policy document extension_policy must be an object",
            )
        })?;
        reject_unknown_keys(
            extension_policy,
            &["allowed_extension_namespaces"],
            "policy extension_policy contains unsupported field",
        )?;
        reject_explicit_nulls(
            extension_policy,
            &["allowed_extension_namespaces"],
            "policy extension_policy field",
        )?;
    }

    Ok(())
}

pub(crate) fn validate_policy_document(
    policy: &PolicyDocumentV1,
) -> Result<(), ContractDerivationError> {
    if policy.schema_id != POLICY_DOCUMENT_SCHEMA_ID
        || policy.schema_version != 1
        || policy.policy_id.trim().is_empty()
        || policy
            .display_name
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        || policy
            .short_display_name
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        || policy.layers.is_empty()
    {
        return Err(ContractDerivationError::new(
            ContractDerivationErrorCode::PolicyDocumentInvalid,
            "policy_load",
            "policy document must declare the supported schema, non-blank optional labels, and at least one layer",
        ));
    }

    let mut layer_ids = BTreeSet::new();
    for layer in &policy.layers {
        if layer.layer_id.trim().is_empty() || !layer_ids.insert(layer.layer_id.clone()) {
            return Err(ContractDerivationError::new(
                ContractDerivationErrorCode::PolicyDocumentInvalid,
                "policy_load",
                "policy layer ids must be non-empty and unique",
            ));
        }

        if matches!(
            layer.rules.capability_class.as_deref(),
            Some(value) if value.trim().is_empty()
        ) {
            return Err(ContractDerivationError::new(
                ContractDerivationErrorCode::PolicyDocumentInvalid,
                "policy_load",
                "policy rule capability_class overrides must be non-empty when present",
            ));
        }

        if layer.rules.capability_class.is_none()
            && layer.rules.min_cpu_logical_cores.is_none()
            && layer.rules.min_memory_bytes.is_none()
            && layer.rules.allow_container_restricted.is_none()
            && layer.rules.require_network_visibility.is_none()
            && layer.rules.required_accelerator_kind.is_none()
            && layer.rules.min_accelerator_devices.is_none()
        {
            return Err(ContractDerivationError::new(
                ContractDerivationErrorCode::PolicyDocumentInvalid,
                "policy_load",
                "each policy layer must override at least one rule",
            ));
        }

        if layer.rules.min_accelerator_devices == Some(0) {
            return Err(ContractDerivationError::new(
                ContractDerivationErrorCode::PolicyDocumentInvalid,
                "policy_load",
                "policy min_accelerator_devices must stay positive when present",
            ));
        }
    }

    let mut allowed_extension_namespaces = BTreeSet::new();
    for namespace in &policy.extension_policy.allowed_extension_namespaces {
        if namespace.trim().is_empty() || !allowed_extension_namespaces.insert(namespace.clone()) {
            return Err(ContractDerivationError::new(
                ContractDerivationErrorCode::PolicyDocumentInvalid,
                "policy_load",
                "policy extension allowed_extension_namespaces must be non-empty and unique",
            ));
        }
    }

    Ok(())
}

fn reject_unknown_keys(
    map: &Map<String, Value>,
    allowed_keys: &[&str],
    message_prefix: &str,
) -> Result<(), ContractDerivationError> {
    if let Some(key) = map.keys().find(|key| !allowed_keys.contains(&key.as_str())) {
        return Err(ContractDerivationError::new(
            ContractDerivationErrorCode::PolicyDocumentInvalid,
            "policy_load",
            format!("{message_prefix}: {key}"),
        ));
    }

    Ok(())
}

fn reject_explicit_nulls(
    map: &Map<String, Value>,
    fields: &[&str],
    message_prefix: &str,
) -> Result<(), ContractDerivationError> {
    if let Some(field) = fields
        .iter()
        .find(|field| matches!(map.get(**field), Some(Value::Null)))
    {
        return Err(ContractDerivationError::new(
            ContractDerivationErrorCode::PolicyDocumentInvalid,
            "policy_load",
            format!("{message_prefix} '{field}' must not be null"),
        ));
    }

    Ok(())
}
