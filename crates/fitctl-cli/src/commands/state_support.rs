// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Shared CLI helpers for host-state collection and extension activation.

use std::path::{Path, PathBuf};

use fitctl_core::artifacts::state_v1::HostStateV1;
use fitctl_core::config::{
    load_extension_pack_from_path, resolve_cuda_environment_from_catalogue_path,
    ExtensionSectionKindV1,
};
use fitctl_core::extensions::{
    apply_cuda_runtime_extension_to_state_with_selection_v1,
    load_cuda_selected_environment_input_from_path, CudaSelectedEnvironmentRequestV1,
    CUDA_RUNTIME_NAMESPACE,
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StateExtensionSelectionV1 {
    requested_extension_namespaces: Vec<String>,
    cuda_selected_environment: Option<CudaSelectedEnvironmentRequestV1>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CudaSelectedEnvironmentCliInputV1 {
    pub catalogue_path: Option<PathBuf>,
    pub environment_id: Option<String>,
    pub replay_input_path: Option<PathBuf>,
}

impl StateExtensionSelectionV1 {
    pub fn is_empty(&self) -> bool {
        self.requested_extension_namespaces.is_empty() && self.cuda_selected_environment.is_none()
    }
}

pub fn prepare_state_extension_selection_v1(
    collection_is_live: bool,
    invocation_enabled_extension_namespaces: &[String],
    extension_pack_paths: &[PathBuf],
    enabled_extension_namespaces: &[String],
    cuda_selected_environment_input: &CudaSelectedEnvironmentCliInputV1,
) -> Result<StateExtensionSelectionV1, String> {
    let mut extension_packs = Vec::new();
    for path in extension_pack_paths {
        let pack = load_extension_pack_from_path(path).map_err(|error| error.to_string())?;
        extension_packs.push(pack);
    }

    let mut requested_extension_namespaces = invocation_enabled_extension_namespaces.to_vec();
    requested_extension_namespaces.extend(enabled_extension_namespaces.iter().cloned());
    requested_extension_namespaces.sort();
    requested_extension_namespaces.dedup();

    if requested_extension_namespaces
        .iter()
        .any(|namespace| namespace.trim().is_empty())
    {
        return Err("enabled extension namespaces must be non-empty".to_string());
    }
    if !requested_extension_namespaces.is_empty() && extension_packs.is_empty() {
        return Err("--enable-extension requires at least one --extension-pack".to_string());
    }
    for namespace in &requested_extension_namespaces {
        let Some(pack) = extension_packs
            .iter()
            .find(|pack| &pack.namespace == namespace)
        else {
            return Err(format!(
                "extension namespace {namespace} was enabled but no matching extension pack is configured"
            ));
        };
        if !pack
            .emitted_sections
            .iter()
            .any(|section| section.section_kind == ExtensionSectionKindV1::ExtensionState)
        {
            return Err(format!(
                "extension namespace {namespace} is enabled but its extension pack does not declare extension_state output"
            ));
        }
        if namespace != CUDA_RUNTIME_NAMESPACE {
            return Err(format!(
                "extension namespace {namespace} is enabled but no state collector is implemented for it"
            ));
        }
    }

    let cuda_selected_environment = resolve_cuda_selected_environment_request_v1(
        collection_is_live,
        &requested_extension_namespaces,
        cuda_selected_environment_input,
    )?;

    Ok(StateExtensionSelectionV1 {
        requested_extension_namespaces,
        cuda_selected_environment,
    })
}

pub fn resolve_cuda_selected_environment_request_v1(
    collection_is_live: bool,
    requested_extension_namespaces: &[String],
    input: &CudaSelectedEnvironmentCliInputV1,
) -> Result<Option<CudaSelectedEnvironmentRequestV1>, String> {
    let any_selection_flag = input.catalogue_path.is_some()
        || input.environment_id.is_some()
        || input.replay_input_path.is_some();
    if !any_selection_flag {
        return Ok(None);
    }
    if !requested_extension_namespaces
        .iter()
        .any(|namespace| namespace == CUDA_RUNTIME_NAMESPACE)
    {
        return Err(
            "CUDA selected-environment flags require --enable-extension fitctl.runtime.cuda"
                .to_string(),
        );
    }

    if collection_is_live {
        if input.replay_input_path.is_some() {
            return Err(
                "--cuda-selected-environment-input is only supported with replay collection"
                    .to_string(),
            );
        }
        let Some(catalogue_path) = input.catalogue_path.as_ref() else {
            return Err(
                "live CUDA selected-environment collection requires --cuda-environment-catalogue"
                    .to_string(),
            );
        };
        let Some(environment_id) = input.environment_id.as_deref() else {
            return Err(
                "live CUDA selected-environment collection requires --cuda-environment-id"
                    .to_string(),
            );
        };
        let (_, entry) =
            resolve_cuda_environment_from_catalogue_path(catalogue_path, environment_id)
                .map_err(|error| error.to_string())?;
        return Ok(Some(CudaSelectedEnvironmentRequestV1::CatalogueEntry(
            entry,
        )));
    }

    if input.catalogue_path.is_some() || input.environment_id.is_some() {
        return Err(
            "replay CUDA selected-environment collection only supports --cuda-selected-environment-input"
                .to_string(),
        );
    }
    let Some(replay_input_path) = input.replay_input_path.as_ref() else {
        return Err(
            "replay CUDA selected-environment collection requires --cuda-selected-environment-input"
                .to_string(),
        );
    };
    let input = load_cuda_selected_environment_input_from_path(replay_input_path)
        .map_err(|error| error.to_string())?;
    Ok(Some(CudaSelectedEnvironmentRequestV1::ReplayInput(input)))
}

pub fn apply_state_extension_selection_v1(
    mut state: HostStateV1,
    selection: &StateExtensionSelectionV1,
    replay_extensions_root: Option<&Path>,
) -> Result<HostStateV1, String> {
    for namespace in &selection.requested_extension_namespaces {
        state = match namespace.as_str() {
            CUDA_RUNTIME_NAMESPACE => apply_cuda_runtime_extension_to_state_with_selection_v1(
                state,
                replay_extensions_root
                    .map(|root| root.join("cuda_runtime_state"))
                    .as_deref(),
                selection.cuda_selected_environment.as_ref(),
            )
            .map_err(|error| error.to_string())?,
            _ => unreachable!("validated before extension application"),
        };
    }

    Ok(state)
}

pub fn default_state_replay_extensions_root_v1(replay_fixtures_root: &Path) -> PathBuf {
    replay_fixtures_root
        .parent()
        .map(|root| root.join("extensions"))
        .unwrap_or_else(|| PathBuf::from("fixtures/extensions"))
}
