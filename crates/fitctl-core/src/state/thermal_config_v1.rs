// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Config loading and validation for opt-in thermal providers.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::artifacts::state_v1::{
    HostStateThermalEvidenceTargetV1, ThermalEvidenceTargetKindV1, ThermalProviderKindV1,
    ThermalSensorRoleV1,
};
use crate::state::{StateError, StateErrorCode};

const THERMAL_PROVIDER_CONFIG_SCHEMA_ID: &str = "fitctl.thermal-provider-config.v1";
const THERMAL_PROVIDER_CONFIG_SCHEMA_VERSION: u32 = 1;
pub(super) const DEFAULT_PROVIDER_TIMEOUT_SECONDS: u64 = 5;
const MAX_PROVIDER_TIMEOUT_SECONDS: u64 = 60;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ThermalProviderConfigDocumentV1 {
    schema_id: String,
    schema_version: u32,
    #[serde(default)]
    providers: Vec<ThermalProviderConfigEntryV1>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThermalProviderConfigEntryV1 {
    pub provider_id: String,
    pub provider_kind: ThermalProviderKindV1,
    pub command: Vec<String>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    pub evidence_target: HostStateThermalEvidenceTargetV1,
    #[serde(default)]
    pub sensor_mappings: Vec<ThermalSensorMappingConfigV1>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThermalSensorMappingConfigV1 {
    pub raw_label: String,
    pub sensor_role: ThermalSensorRoleV1,
    #[serde(default)]
    pub sensor_alias: Option<String>,
}

pub fn load_thermal_provider_config_entries_from_paths_v1(
    paths: &[PathBuf],
) -> Result<Vec<ThermalProviderConfigEntryV1>, StateError> {
    let mut entries = Vec::new();
    for path in paths {
        entries.extend(load_thermal_provider_config_entries_from_path_v1(path)?);
    }
    Ok(entries)
}

fn load_thermal_provider_config_entries_from_path_v1(
    path: &Path,
) -> Result<Vec<ThermalProviderConfigEntryV1>, StateError> {
    let text = std::fs::read_to_string(path).map_err(|error| {
        StateError::new(
            StateErrorCode::StatePayloadMalformed,
            "thermal_provider_config_load",
            format!(
                "failed to read thermal provider config {}: {error}",
                path.display()
            ),
        )
    })?;
    let document: ThermalProviderConfigDocumentV1 =
        serde_json::from_str(&text).map_err(|error| {
            StateError::new(
                StateErrorCode::StatePayloadMalformed,
                "thermal_provider_config_load",
                format!(
                    "failed to decode thermal provider config {}: {error}",
                    path.display()
                ),
            )
        })?;
    if document.schema_id != THERMAL_PROVIDER_CONFIG_SCHEMA_ID {
        return Err(StateError::new(
            StateErrorCode::StatePayloadMalformed,
            "thermal_provider_config_validate",
            format!(
                "thermal provider config {} has unsupported schema_id {}",
                path.display(),
                document.schema_id
            ),
        ));
    }
    if document.schema_version != THERMAL_PROVIDER_CONFIG_SCHEMA_VERSION {
        return Err(StateError::new(
            StateErrorCode::StatePayloadMalformed,
            "thermal_provider_config_validate",
            format!(
                "thermal provider config {} has unsupported schema_version {}",
                path.display(),
                document.schema_version
            ),
        ));
    }
    if document.providers.is_empty() {
        return Err(StateError::new(
            StateErrorCode::StatePayloadMalformed,
            "thermal_provider_config_validate",
            format!(
                "thermal provider config {} must include providers",
                path.display()
            ),
        ));
    }
    let mut provider_ids = std::collections::BTreeSet::new();
    for provider in &document.providers {
        validate_provider_config_entry(provider, &mut provider_ids)?;
    }
    Ok(document.providers)
}

fn validate_provider_config_entry(
    provider: &ThermalProviderConfigEntryV1,
    provider_ids: &mut std::collections::BTreeSet<String>,
) -> Result<(), StateError> {
    if provider.provider_id.trim().is_empty() || provider.provider_id.contains(char::is_whitespace)
    {
        return Err(StateError::new(
            StateErrorCode::StatePayloadMalformed,
            "thermal_provider_config_validate",
            "thermal provider id must be non-empty and contain no whitespace",
        ));
    }
    if !provider_ids.insert(provider.provider_id.clone()) {
        return Err(StateError::new(
            StateErrorCode::StatePayloadMalformed,
            "thermal_provider_config_validate",
            format!("thermal provider id {} is duplicated", provider.provider_id),
        ));
    }
    if provider.command.is_empty() || provider.command.iter().any(|entry| entry.trim().is_empty()) {
        return Err(StateError::new(
            StateErrorCode::StatePayloadMalformed,
            "thermal_provider_config_validate",
            format!(
                "thermal provider {} command must be a non-empty argv array",
                provider.provider_id
            ),
        ));
    }
    if uses_known_shell_command_form(&provider.command) {
        return Err(StateError::new(
            StateErrorCode::StatePayloadMalformed,
            "thermal_provider_config_validate",
            format!(
                "thermal provider {} command uses unsupported shell -c form",
                provider.provider_id
            ),
        ));
    }
    let timeout = provider
        .timeout_seconds
        .unwrap_or(DEFAULT_PROVIDER_TIMEOUT_SECONDS);
    if timeout == 0 || timeout > MAX_PROVIDER_TIMEOUT_SECONDS {
        return Err(StateError::new(
            StateErrorCode::StatePayloadMalformed,
            "thermal_provider_config_validate",
            format!(
                "thermal provider {} timeout_seconds must be 1..={}",
                provider.provider_id, MAX_PROVIDER_TIMEOUT_SECONDS
            ),
        ));
    }
    validate_evidence_target(&provider.provider_id, &provider.evidence_target)?;
    validate_sensor_mappings(provider)?;
    Ok(())
}

fn validate_sensor_mappings(provider: &ThermalProviderConfigEntryV1) -> Result<(), StateError> {
    let mut raw_labels = std::collections::BTreeSet::new();
    let mut aliases = std::collections::BTreeSet::new();
    for mapping in &provider.sensor_mappings {
        if mapping.raw_label.trim().is_empty() {
            return Err(StateError::new(
                StateErrorCode::StatePayloadMalformed,
                "thermal_provider_config_validate",
                format!(
                    "thermal provider {} sensor mapping raw_label must be non-blank",
                    provider.provider_id
                ),
            ));
        }
        if !raw_labels.insert(mapping.raw_label.clone()) {
            return Err(StateError::new(
                StateErrorCode::StatePayloadMalformed,
                "thermal_provider_config_validate",
                format!(
                    "thermal provider {} sensor mapping raw_label {} is duplicated",
                    provider.provider_id, mapping.raw_label
                ),
            ));
        }
        if let Some(alias) = mapping.sensor_alias.as_ref() {
            if alias.trim().is_empty() || alias.contains(char::is_whitespace) {
                return Err(StateError::new(
                    StateErrorCode::StatePayloadMalformed,
                    "thermal_provider_config_validate",
                    format!(
                        "thermal provider {} sensor alias must be non-empty and contain no whitespace",
                        provider.provider_id
                    ),
                ));
            }
            if !aliases.insert(alias.clone()) {
                return Err(StateError::new(
                    StateErrorCode::StatePayloadMalformed,
                    "thermal_provider_config_validate",
                    format!(
                        "thermal provider {} sensor alias {} is duplicated",
                        provider.provider_id, alias
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn uses_known_shell_command_form(command: &[String]) -> bool {
    let Some(program) = command.first() else {
        return false;
    };
    let shell_name = Path::new(program)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(program);
    matches!(shell_name, "sh" | "bash" | "dash" | "zsh" | "fish")
        && command.iter().any(|value| value == "-c")
}

fn validate_evidence_target(
    provider_id: &str,
    target: &HostStateThermalEvidenceTargetV1,
) -> Result<(), StateError> {
    match target.target_kind {
        ThermalEvidenceTargetKindV1::CurrentHost => {
            if target.host_id.is_some() {
                return Err(StateError::new(
                    StateErrorCode::StatePayloadMalformed,
                    "thermal_provider_config_validate",
                    format!(
                        "thermal provider {provider_id} current_host target must not set host_id"
                    ),
                ));
            }
        }
        ThermalEvidenceTargetKindV1::HostId => {
            if target
                .host_id
                .as_deref()
                .is_none_or(|value| value.trim().is_empty())
            {
                return Err(StateError::new(
                    StateErrorCode::StatePayloadMalformed,
                    "thermal_provider_config_validate",
                    format!(
                        "thermal provider {provider_id} host_id target requires non-blank host_id"
                    ),
                ));
            }
        }
    }
    Ok(())
}
