// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use crate::artifacts::contract_v1::ContractExtensionBasisV1;
use crate::config::schema_v1::{
    semantic_hash_hex_for_extension_pack, ConfigError, ConfigErrorCode,
    DisabledExtensionNamespaceV1, DisabledExtensionReasonV1, ExtensionPackV1, InvocationContextV1,
    RecommendationPackV1, ResolvedConfigV1, RESOLVED_CONFIG_SCHEMA_ID,
};
use crate::policy::{merge_policy_document_v1, PolicyDocumentV1, PolicyLayerKindV1};
use crate::verify::TrustPolicyV1;

#[derive(Debug, Clone)]
pub struct ResolveConfigurationRequestV1 {
    pub policy: PolicyDocumentV1,
    pub trust_policy: Option<TrustPolicyV1>,
    pub extension_packs: Vec<ExtensionPackV1>,
    pub recommendation_packs: Vec<RecommendationPackV1>,
    pub invocation_context: Option<InvocationContextV1>,
}

/// Resolve policy, packs, and invocation choices into one conflict-checked runtime view.
///
/// Policy merging happens first, then invocation requests are checked against the merged policy
/// and configured packs. Later phases can consume the resolved config without re-deciding whether a
/// namespace or pack was admissible.
pub fn resolve_configuration_v1(
    request: ResolveConfigurationRequestV1,
) -> Result<ResolvedConfigV1, ConfigError> {
    let effective_policy = merge_policy_document_v1(&request.policy).map_err(|error| {
        ConfigError::new(
            ConfigErrorCode::ConfigInputInvalid,
            "config_resolve",
            error.message,
        )
    })?;

    let policy_allowed_extension_namespaces = request
        .policy
        .extension_policy
        .allowed_extension_namespaces
        .clone();
    let allowed_set: BTreeSet<_> = policy_allowed_extension_namespaces
        .iter()
        .cloned()
        .collect();

    let mut extension_packs_by_namespace = BTreeMap::new();
    let mut configured_extension_pack_ids = Vec::new();
    let mut seen_extension_pack_ids = BTreeSet::new();
    for pack in request.extension_packs {
        if !seen_extension_pack_ids.insert(pack.pack_id.clone()) {
            return Err(ConfigError::new(
                ConfigErrorCode::ConfigResolveConflict,
                "config_resolve",
                format!(
                    "extension pack id {} is declared more than once",
                    pack.pack_id
                ),
            ));
        }
        if extension_packs_by_namespace
            .insert(pack.namespace.clone(), pack.clone())
            .is_some()
        {
            return Err(ConfigError::new(
                ConfigErrorCode::ConfigResolveConflict,
                "config_resolve",
                format!(
                    "extension namespace {} is declared by more than one manifest",
                    pack.namespace
                ),
            ));
        }
        configured_extension_pack_ids.push(pack.pack_id);
    }
    configured_extension_pack_ids.sort();

    let mut recommendation_packs_by_id = BTreeMap::new();
    for pack in request.recommendation_packs {
        if recommendation_packs_by_id
            .insert(pack.pack_id.clone(), pack)
            .is_some()
        {
            return Err(ConfigError::new(
                ConfigErrorCode::ConfigResolveConflict,
                "config_resolve",
                "recommendation pack ids must be unique",
            ));
        }
    }

    let invocation = request.invocation_context;
    let requested_extension_namespaces: BTreeSet<String> = invocation
        .as_ref()
        .map(|context| {
            context
                .enabled_extension_namespaces
                .iter()
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    let requested_recommendation_pack_ids: BTreeSet<String> = invocation
        .as_ref()
        .map(|context| {
            context
                .selected_recommendation_pack_ids
                .iter()
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    let enabled_simulation_layer_ids: BTreeSet<String> = invocation
        .as_ref()
        .map(|context| {
            context
                .enabled_simulation_layer_ids
                .iter()
                .cloned()
                .collect()
        })
        .unwrap_or_default();

    for namespace in &requested_extension_namespaces {
        if !extension_packs_by_namespace.contains_key(namespace) {
            return Err(ConfigError::new(
                ConfigErrorCode::ConfigResolveConflict,
                "config_resolve",
                format!(
                    "invocation requests extension namespace {namespace} but no matching extension pack is configured"
                ),
            ));
        }
        if !allowed_set.contains(namespace) {
            return Err(ConfigError::new(
                ConfigErrorCode::ConfigResolveConflict,
                "config_resolve",
                format!(
                    "invocation requests extension namespace {namespace} but policy does not allow it"
                ),
            ));
        }
    }

    for pack_id in &requested_recommendation_pack_ids {
        if !recommendation_packs_by_id.contains_key(pack_id) {
            return Err(ConfigError::new(
                ConfigErrorCode::ConfigResolveConflict,
                "config_resolve",
                format!(
                    "invocation requests recommendation pack {pack_id} but no matching recommendation pack is configured"
                ),
            ));
        }
    }

    let mut simulation_layers_by_id = BTreeMap::new();
    for layer in &request.policy.layers {
        simulation_layers_by_id.insert(layer.layer_id.clone(), layer.kind);
    }
    for layer_id in &enabled_simulation_layer_ids {
        let Some(kind) = simulation_layers_by_id.get(layer_id) else {
            return Err(ConfigError::new(
                ConfigErrorCode::ConfigResolveConflict,
                "config_resolve",
                format!(
                    "invocation requests simulation layer {layer_id} but no matching policy layer exists"
                ),
            ));
        };
        if *kind != PolicyLayerKindV1::ValidationSimulation {
            return Err(ConfigError::new(
                ConfigErrorCode::ConfigResolveConflict,
                "config_resolve",
                format!("invocation layer {layer_id} is not a validation_simulation layer"),
            ));
        }
    }

    let mut available_extension_namespaces: Vec<String> =
        extension_packs_by_namespace.keys().cloned().collect();
    available_extension_namespaces.sort();
    let mut enabled_extension_namespaces = Vec::new();
    let mut disabled_extension_namespaces = Vec::new();

    for namespace in &available_extension_namespaces {
        if !allowed_set.contains(namespace) {
            disabled_extension_namespaces.push(DisabledExtensionNamespaceV1 {
                namespace: namespace.clone(),
                reason: DisabledExtensionReasonV1::PolicyDisallowed,
            });
        } else if requested_extension_namespaces.contains(namespace) {
            enabled_extension_namespaces.push(namespace.clone());
        } else {
            disabled_extension_namespaces.push(DisabledExtensionNamespaceV1 {
                namespace: namespace.clone(),
                reason: DisabledExtensionReasonV1::InvocationNotEnabled,
            });
        }
    }

    let mut available_recommendation_pack_ids: Vec<String> =
        recommendation_packs_by_id.keys().cloned().collect();
    available_recommendation_pack_ids.sort();
    let mut selected_recommendation_pack_ids: Vec<String> =
        requested_recommendation_pack_ids.into_iter().collect();
    selected_recommendation_pack_ids.sort();

    let mut policy_allowed_extension_namespaces = policy_allowed_extension_namespaces;
    policy_allowed_extension_namespaces.sort();

    let mut enabled_simulation_layer_ids: Vec<String> =
        enabled_simulation_layer_ids.into_iter().collect();
    enabled_simulation_layer_ids.sort();

    Ok(ResolvedConfigV1 {
        schema_id: RESOLVED_CONFIG_SCHEMA_ID.to_string(),
        schema_version: 1,
        policy_id: effective_policy.policy_id,
        selected_policy_pack_id: None,
        selected_policy_entry_id: None,
        selected_policy_pack_lock_id: None,
        selected_policy_pack_lock_signed: None,
        selected_policy_layers: effective_policy.selected_policy_layers,
        policy_allowed_extension_namespaces,
        configured_extension_pack_ids,
        available_extension_namespaces,
        enabled_extension_namespaces,
        disabled_extension_namespaces,
        trust_policy_id: request.trust_policy.map(|policy| policy.policy_id),
        available_recommendation_pack_ids,
        selected_recommendation_pack_ids,
        invocation_id: invocation
            .as_ref()
            .map(|context| context.invocation_id.clone()),
        selected_service_profile_catalogue_id: None,
        selected_service_profile_entry_id: None,
        validation_mode: invocation
            .as_ref()
            .and_then(|context| context.validation_mode),
        max_state_age_seconds: invocation.and_then(|context| context.max_state_age_seconds),
        enabled_simulation_layer_ids,
    })
}

/// Build the contract-side extension basis for namespaces that survived config resolution.
///
/// The basis records semantic hashes for enabled extension packs so derived contracts can prove
/// exactly which extension manifests informed their capability claims.
pub fn build_extension_basis_v1(
    resolved: &ResolvedConfigV1,
    extension_packs: &[ExtensionPackV1],
) -> Result<Option<ContractExtensionBasisV1>, ConfigError> {
    if resolved.enabled_extension_namespaces.is_empty() {
        return Ok(None);
    }

    let packs_by_namespace = extension_packs
        .iter()
        .map(|pack| (pack.namespace.as_str(), pack))
        .collect::<BTreeMap<_, _>>();
    let mut extension_semantic_hashes = BTreeMap::new();

    for namespace in &resolved.enabled_extension_namespaces {
        let Some(pack) = packs_by_namespace.get(namespace.as_str()) else {
            return Err(ConfigError::new(
                ConfigErrorCode::ConfigResolveConflict,
                "config_resolve",
                format!(
                    "enabled extension namespace {namespace} has no matching configured manifest"
                ),
            ));
        };
        extension_semantic_hashes.insert(
            namespace.clone(),
            semantic_hash_hex_for_extension_pack(pack)?,
        );
    }

    Ok(Some(ContractExtensionBasisV1 {
        enabled_extension_namespaces: resolved.enabled_extension_namespaces.clone(),
        extension_semantic_hashes,
    }))
}
