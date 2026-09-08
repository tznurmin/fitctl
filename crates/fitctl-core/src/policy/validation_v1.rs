// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Shared raw-input and semantic validation for policy documents.

use super::schema_v1::{PolicyDocumentV1, POLICY_DOCUMENT_SCHEMA_ID};
use crate::contract::{ContractDerivationError, ContractDerivationErrorCode};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

pub(super) fn validate_policy_document_json(raw: &Value) -> Result<(), ContractDerivationError> {
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
                        "required_accelerator_vendor",
                        "required_accelerator_integration",
                        "min_accelerator_devices",
                        "policy_scoped_accelerator_inventory_mode",
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
                        "required_accelerator_vendor",
                        "required_accelerator_integration",
                        "min_accelerator_devices",
                        "policy_scoped_accelerator_inventory_mode",
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
            && layer.rules.required_accelerator_vendor.is_none()
            && layer.rules.required_accelerator_integration.is_none()
            && layer.rules.min_accelerator_devices.is_none()
            && layer
                .rules
                .policy_scoped_accelerator_inventory_mode
                .is_none()
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
        if layer
            .rules
            .required_accelerator_vendor
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(ContractDerivationError::new(
                ContractDerivationErrorCode::PolicyDocumentInvalid,
                "policy_scope_validate",
                "policy required_accelerator_vendor must stay non-blank when present",
            ));
        }
        if (layer.rules.required_accelerator_vendor.is_some()
            || layer.rules.required_accelerator_integration.is_some())
            && layer.rules.required_accelerator_kind.is_none()
        {
            return Err(ContractDerivationError::new(
                ContractDerivationErrorCode::PolicyDocumentInvalid,
                "policy_scope_validate",
                "policy accelerator vendor or integration filters require required_accelerator_kind in this version",
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
