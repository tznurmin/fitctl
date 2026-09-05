// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Resolve extension activation before contract payload derivation begins.

use fitctl_core::artifacts::config_bundle_v1::ConfigBundleV1;
use fitctl_core::artifacts::contract_v1::ContractExtensionBasisV1;
use fitctl_core::config::{
    add_missing_built_in_extension_packs_v1, build_extension_basis_v1, resolve_configuration_v1,
    ExtensionPackV1, InvocationContextV1, ResolveConfigurationRequestV1,
};
use fitctl_core::policy::PolicyDocumentV1;

pub(super) fn resolve_contract_extension_basis_v1(
    config_bundle: Option<&ConfigBundleV1>,
    policy: PolicyDocumentV1,
    mut extension_packs: Vec<ExtensionPackV1>,
    invocation_context: Option<&InvocationContextV1>,
    mut direct_namespaces: Vec<String>,
) -> Result<Option<ContractExtensionBasisV1>, String> {
    if let Some(bundle) = config_bundle {
        if !bundle
            .config_bundle
            .resolved_config
            .configured_extension_pack_ids
            .is_empty()
            || !bundle
                .config_bundle
                .resolved_config
                .enabled_extension_namespaces
                .is_empty()
        {
            return Err(
                "config bundle extension selections are not supported in the first config-bundle contract flow"
                    .to_string(),
            );
        }
        return Ok(None);
    }

    if extension_packs.is_empty() && invocation_context.is_none() && direct_namespaces.is_empty() {
        return Ok(None);
    }

    let mut requested_namespaces = invocation_context
        .map(|context| context.enabled_extension_namespaces.clone())
        .unwrap_or_default();
    requested_namespaces.append(&mut direct_namespaces);
    requested_namespaces.sort();
    requested_namespaces.dedup();
    if requested_namespaces
        .iter()
        .any(|namespace| namespace.trim().is_empty())
    {
        return Err("enabled extension namespaces must be non-empty".to_string());
    }
    add_missing_built_in_extension_packs_v1(&mut extension_packs, &requested_namespaces);

    let resolved = resolve_configuration_v1(ResolveConfigurationRequestV1 {
        policy,
        trust_policy: None,
        extension_packs: extension_packs.clone(),
        recommendation_packs: vec![],
        invocation_context: Some(InvocationContextV1 {
            schema_id: "fitctl.invocation-context.v1".to_string(),
            schema_version: 1,
            invocation_id: invocation_context
                .map(|context| context.invocation_id.clone())
                .unwrap_or_else(|| "contract-extension-activation-v1".to_string()),
            selected_policy_id: None,
            selected_service_profile_id: None,
            enabled_extension_namespaces: requested_namespaces,
            selected_recommendation_pack_ids: vec![],
            enabled_simulation_layer_ids: vec![],
            validation_mode: None,
            max_state_age_seconds: None,
        }),
        selected_policy_pack_id: None,
        selected_policy_entry_id: None,
        selected_policy_entry_source: None,
        selected_policy_pack_lock_id: None,
        selected_policy_pack_lock_signed: None,
        selected_service_profile_catalogue_id: None,
        selected_service_profile_entry_id: None,
        selected_service_profile_entry_source: None,
    })
    .map_err(|error| error.to_string())?;

    build_extension_basis_v1(&resolved, &extension_packs).map_err(|error| error.to_string())
}
