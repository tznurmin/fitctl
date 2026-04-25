// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Policy-layer merging and precedence resolution.

use std::collections::BTreeSet;

use crate::contract::{ContractDerivationError, ContractDerivationErrorCode};
use crate::policy::schema_v1::{
    validate_policy_document, PolicyDocumentV1, PolicyLayerKindV1, PolicyRulesOverrideV1,
    PolicyScopedAcceleratorInventoryModeV1,
};
use crate::survey::{AcceleratorIntegrationV1, AcceleratorKindV1};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePolicyV1 {
    pub policy_id: String,
    pub selected_policy_layers: Vec<String>,
    pub capability_class: String,
    pub min_cpu_logical_cores: u32,
    pub min_memory_bytes: u64,
    pub allow_container_restricted: bool,
    pub require_network_visibility: bool,
    pub required_accelerator_kind: Option<AcceleratorKindV1>,
    pub required_accelerator_vendor: Option<String>,
    pub required_accelerator_integration: Option<AcceleratorIntegrationV1>,
    pub min_accelerator_devices: Option<u32>,
    pub policy_scoped_accelerator_inventory_mode: Option<PolicyScopedAcceleratorInventoryModeV1>,
}

#[derive(Default)]
struct LayeredRuleAccumV1 {
    capability_class: Option<String>,
    min_cpu_logical_cores: Option<u32>,
    min_memory_bytes: Option<u64>,
    allow_container_restricted: Option<bool>,
    require_network_visibility: Option<bool>,
    required_accelerator_kind: Option<AcceleratorKindV1>,
    required_accelerator_vendor: Option<String>,
    required_accelerator_integration: Option<AcceleratorIntegrationV1>,
    min_accelerator_devices: Option<u32>,
    policy_scoped_accelerator_inventory_mode: Option<PolicyScopedAcceleratorInventoryModeV1>,
}

pub fn merge_policy_document_v1(
    policy: &PolicyDocumentV1,
) -> Result<EffectivePolicyV1, ContractDerivationError> {
    validate_policy_document(policy)?;

    let mut layers = policy.layers.clone();
    layers.sort_by_key(|layer| (layer.kind.precedence_rank(), layer.layer_id.clone()));

    let mut seen_semantic_kinds = BTreeSet::new();
    for layer in &layers {
        if layer.kind != PolicyLayerKindV1::ValidationSimulation
            && !seen_semantic_kinds.insert(layer.kind)
        {
            return Err(ContractDerivationError::new(
                ContractDerivationErrorCode::PolicyLayerConflict,
                "policy_layer_merge",
                "policy document contains conflicting layers at the same precedence kind",
            ));
        }
    }

    let mut layered = LayeredRuleAccumV1::default();
    let mut selected_policy_layers = Vec::new();

    for layer in &layers {
        if layer.kind == PolicyLayerKindV1::ValidationSimulation {
            continue;
        }

        selected_policy_layers.push(layer.layer_id.clone());
        apply_rules(&layer.rules, &mut layered);
    }

    let capability_class = layered.capability_class.ok_or_else(|| {
        ContractDerivationError::new(
            ContractDerivationErrorCode::PolicyDocumentInvalid,
            "policy_layer_merge",
            "effective policy is missing capability_class after layering",
        )
    })?;
    let min_cpu_logical_cores = layered.min_cpu_logical_cores.ok_or_else(|| {
        ContractDerivationError::new(
            ContractDerivationErrorCode::PolicyDocumentInvalid,
            "policy_layer_merge",
            "effective policy is missing min_cpu_logical_cores after layering",
        )
    })?;
    let min_memory_bytes = layered.min_memory_bytes.ok_or_else(|| {
        ContractDerivationError::new(
            ContractDerivationErrorCode::PolicyDocumentInvalid,
            "policy_layer_merge",
            "effective policy is missing min_memory_bytes after layering",
        )
    })?;
    let allow_container_restricted = layered.allow_container_restricted.ok_or_else(|| {
        ContractDerivationError::new(
            ContractDerivationErrorCode::PolicyDocumentInvalid,
            "policy_layer_merge",
            "effective policy is missing allow_container_restricted after layering",
        )
    })?;
    let require_network_visibility = layered.require_network_visibility.ok_or_else(|| {
        ContractDerivationError::new(
            ContractDerivationErrorCode::PolicyDocumentInvalid,
            "policy_layer_merge",
            "effective policy is missing require_network_visibility after layering",
        )
    })?;

    if selected_policy_layers.is_empty() {
        return Err(ContractDerivationError::new(
            ContractDerivationErrorCode::PolicyDocumentInvalid,
            "policy_layer_merge",
            "effective policy must retain at least one semantic layer",
        ));
    }

    if layered.policy_scoped_accelerator_inventory_mode.is_some()
        && layered.required_accelerator_kind.is_none()
    {
        return Err(ContractDerivationError::new(
            ContractDerivationErrorCode::PolicyDocumentInvalid,
            "accelerator_scope_mode_validate",
            "policy_scoped_accelerator_inventory_mode requires required_accelerator_kind in this version",
        ));
    }

    Ok(EffectivePolicyV1 {
        policy_id: policy.policy_id.clone(),
        selected_policy_layers,
        capability_class,
        min_cpu_logical_cores,
        min_memory_bytes,
        allow_container_restricted,
        require_network_visibility,
        required_accelerator_kind: layered.required_accelerator_kind,
        required_accelerator_vendor: layered.required_accelerator_vendor,
        required_accelerator_integration: layered.required_accelerator_integration,
        min_accelerator_devices: layered.min_accelerator_devices,
        policy_scoped_accelerator_inventory_mode: layered.policy_scoped_accelerator_inventory_mode,
    })
}

fn apply_rules(rules: &PolicyRulesOverrideV1, layered: &mut LayeredRuleAccumV1) {
    if let Some(value) = &rules.capability_class {
        layered.capability_class = Some(value.clone());
    }
    if let Some(value) = rules.min_cpu_logical_cores {
        layered.min_cpu_logical_cores = Some(value);
    }
    if let Some(value) = rules.min_memory_bytes {
        layered.min_memory_bytes = Some(value);
    }
    if let Some(value) = rules.allow_container_restricted {
        layered.allow_container_restricted = Some(value);
    }
    if let Some(value) = rules.require_network_visibility {
        layered.require_network_visibility = Some(value);
    }
    if let Some(value) = rules.required_accelerator_kind {
        layered.required_accelerator_kind = Some(value);
    }
    if let Some(value) = &rules.required_accelerator_vendor {
        layered.required_accelerator_vendor = Some(value.clone());
    }
    if let Some(value) = rules.required_accelerator_integration {
        layered.required_accelerator_integration = Some(value);
    }
    if let Some(value) = rules.min_accelerator_devices {
        layered.min_accelerator_devices = Some(value);
    }
    if let Some(value) = rules.policy_scoped_accelerator_inventory_mode {
        layered.policy_scoped_accelerator_inventory_mode = Some(value);
    }
}
