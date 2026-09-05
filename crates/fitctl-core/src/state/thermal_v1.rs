// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Thermal provider config, command execution, and output parsing.

#[path = "thermal_command_v1.rs"]
mod thermal_command_v1;
#[path = "thermal_config_v1.rs"]
mod thermal_config_v1;
#[path = "thermal_ipmitool_v1.rs"]
mod thermal_ipmitool_v1;
#[path = "thermal_lm_sensors_v1.rs"]
mod thermal_lm_sensors_v1;
#[path = "thermal_nvidia_smi_v1.rs"]
mod thermal_nvidia_smi_v1;

use std::process::Output;

use crate::artifacts::categorical_values_v1::{
    THERMAL_PROVIDER_COMMAND_FAILED, THERMAL_PROVIDER_NO_TEMPERATURE_READINGS,
    THERMAL_PROVIDER_OUTPUT_MALFORMED, THERMAL_PROVIDER_OUTPUT_TOO_LARGE,
};
use crate::artifacts::state_v1::{
    HostStateThermalCollectorHostV1, HostStateThermalEvidenceTargetV1, HostStateThermalProviderV1,
    HostStateThermalReadingV1, HostStateThermalResourcesV1, ThermalCollectionPathV1,
    ThermalEvidenceTargetKindV1, ThermalProviderKindV1, ThermalProviderOutcomeV1,
    ThermalReadingStatusV1, ThermalSensorRoleV1,
};

use thermal_command_v1::{run_provider_command, MAX_PROVIDER_OUTPUT_BYTES};
use thermal_config_v1::DEFAULT_PROVIDER_TIMEOUT_SECONDS;
pub use thermal_config_v1::{
    load_thermal_provider_config_entries_from_paths_v1, ThermalProviderConfigEntryV1,
    ThermalSensorMappingConfigV1,
};
pub use thermal_ipmitool_v1::parse_ipmitool_sensor_output_v1;
pub use thermal_lm_sensors_v1::parse_lm_sensors_json_output_v1;
pub use thermal_nvidia_smi_v1::parse_nvidia_smi_query_output_v1;

pub fn built_in_local_thermal_provider_entries_v1() -> Vec<ThermalProviderConfigEntryV1> {
    let evidence_target = HostStateThermalEvidenceTargetV1 {
        target_kind: ThermalEvidenceTargetKindV1::CurrentHost,
        host_id: None,
        collection_path: ThermalCollectionPathV1::LocalProcess,
    };
    vec![
        ThermalProviderConfigEntryV1 {
            provider_id: "local-lm-sensors".to_string(),
            provider_kind: ThermalProviderKindV1::LmSensorsJson,
            command: vec!["sensors".to_string(), "-j".to_string()],
            timeout_seconds: Some(DEFAULT_PROVIDER_TIMEOUT_SECONDS),
            evidence_target: evidence_target.clone(),
            sensor_mappings: Vec::new(),
        },
        ThermalProviderConfigEntryV1 {
            provider_id: "local-nvidia-smi-thermal".to_string(),
            provider_kind: ThermalProviderKindV1::NvidiaSmiQuery,
            command: vec![
                "nvidia-smi".to_string(),
                "--query-gpu=uuid,name,temperature.gpu".to_string(),
                "--format=csv,noheader,nounits".to_string(),
            ],
            timeout_seconds: Some(DEFAULT_PROVIDER_TIMEOUT_SECONDS),
            evidence_target,
            sensor_mappings: Vec::new(),
        },
    ]
}

pub fn collect_thermal_resources_v1(
    providers: &[ThermalProviderConfigEntryV1],
    observed_at: &str,
    collector_host: HostStateThermalCollectorHostV1,
) -> Option<HostStateThermalResourcesV1> {
    if providers.is_empty() {
        return None;
    }

    let mut provider_entries = Vec::with_capacity(providers.len());
    let mut readings = Vec::new();
    for provider in providers {
        let (provider_entry, provider_readings) = collect_provider(provider, observed_at);
        provider_entries.push(provider_entry);
        readings.extend(provider_readings);
    }

    Some(HostStateThermalResourcesV1 {
        observed_at: observed_at.to_string(),
        collector_host,
        providers: provider_entries,
        readings,
    })
}

fn collect_provider(
    provider: &ThermalProviderConfigEntryV1,
    observed_at: &str,
) -> (HostStateThermalProviderV1, Vec<HostStateThermalReadingV1>) {
    match run_provider_command(provider) {
        Ok(output) => {
            if !output.status.success() {
                let diagnostics = provider_command_failed_diagnostics(&output);
                return (
                    provider_outcome(
                        provider,
                        ThermalProviderOutcomeV1::CommandFailed,
                        observed_at,
                        Some(THERMAL_PROVIDER_COMMAND_FAILED),
                        Some(diagnostics.as_str()),
                    ),
                    Vec::new(),
                );
            }
            if output.stdout.len() > MAX_PROVIDER_OUTPUT_BYTES {
                return (
                    provider_outcome(
                        provider,
                        ThermalProviderOutcomeV1::Malformed,
                        observed_at,
                        Some(THERMAL_PROVIDER_OUTPUT_TOO_LARGE),
                        Some("provider stdout exceeded bounded output size"),
                    ),
                    Vec::new(),
                );
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            match parse_provider_output(provider, &stdout, observed_at) {
                Ok(readings) if readings.is_empty() => (
                    provider_outcome(
                        provider,
                        ThermalProviderOutcomeV1::Partial,
                        observed_at,
                        Some(THERMAL_PROVIDER_NO_TEMPERATURE_READINGS),
                        Some("provider output contained no temperature readings"),
                    ),
                    Vec::new(),
                ),
                Ok(mut readings) => {
                    apply_sensor_mappings(provider, &mut readings);
                    (
                        provider_outcome(
                            provider,
                            ThermalProviderOutcomeV1::Success,
                            observed_at,
                            None,
                            None,
                        ),
                        readings,
                    )
                }
                Err(error) => (
                    provider_outcome(
                        provider,
                        ThermalProviderOutcomeV1::Malformed,
                        observed_at,
                        Some(THERMAL_PROVIDER_OUTPUT_MALFORMED),
                        Some(error.message.as_str()),
                    ),
                    Vec::new(),
                ),
            }
        }
        Err(error) => (
            provider_outcome(
                provider,
                error.outcome,
                observed_at,
                Some(error.error_code),
                Some(error.diagnostics.as_str()),
            ),
            Vec::new(),
        ),
    }
}

fn apply_sensor_mappings(
    provider: &ThermalProviderConfigEntryV1,
    readings: &mut [HostStateThermalReadingV1],
) {
    if provider.sensor_mappings.is_empty() {
        return;
    }
    for reading in readings {
        let Some(mapping) = provider
            .sensor_mappings
            .iter()
            .find(|mapping| mapping.raw_label == reading.raw_label)
        else {
            continue;
        };
        reading.sensor_role = mapping.sensor_role;
        reading.sensor_alias = mapping.sensor_alias.clone();
    }
}

fn provider_outcome(
    provider: &ThermalProviderConfigEntryV1,
    outcome: ThermalProviderOutcomeV1,
    observed_at: &str,
    error_code: Option<&str>,
    diagnostics: Option<&str>,
) -> HostStateThermalProviderV1 {
    HostStateThermalProviderV1 {
        provider_id: provider.provider_id.clone(),
        provider_kind: provider.provider_kind,
        outcome,
        evidence_target: provider.evidence_target.clone(),
        observed_at: observed_at.to_string(),
        error_code: error_code.map(ToOwned::to_owned),
        diagnostics: diagnostics.map(|value| bounded_diagnostic(value, 240)),
    }
}

fn bounded_diagnostic(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

fn provider_command_failed_diagnostics(output: &Output) -> String {
    let mut parts = vec![format!("provider command exited with {}", output.status)];
    if let Some(stderr) = bounded_output_excerpt(&output.stderr, 120) {
        parts.push(format!("stderr: {stderr}"));
    }
    if let Some(stdout) = bounded_output_excerpt(&output.stdout, 120) {
        parts.push(format!("stdout: {stdout}"));
    }
    parts.join("; ")
}

fn bounded_output_excerpt(bytes: &[u8], max_chars: usize) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    let normalized = text
        .chars()
        .map(|character| {
            if character.is_control() && character != '\n' && character != '\t' {
                ' '
            } else {
                character
            }
        })
        .collect::<String>();
    let compact = normalized.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.is_empty() {
        return None;
    }
    Some(compact.chars().take(max_chars).collect())
}

fn parse_provider_output(
    provider: &ThermalProviderConfigEntryV1,
    output: &str,
    observed_at: &str,
) -> Result<Vec<HostStateThermalReadingV1>, ThermalParseErrorV1> {
    match provider.provider_kind {
        ThermalProviderKindV1::LmSensorsJson => parse_lm_sensors_json_output_v1(
            &provider.provider_id,
            output,
            observed_at,
            provider.evidence_target.clone(),
        ),
        ThermalProviderKindV1::NvidiaSmiQuery => parse_nvidia_smi_query_output_v1(
            &provider.provider_id,
            output,
            observed_at,
            provider.evidence_target.clone(),
        ),
        ThermalProviderKindV1::IpmitoolSensor => parse_ipmitool_sensor_output_v1(
            &provider.provider_id,
            output,
            observed_at,
            provider.evidence_target.clone(),
        ),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThermalParseErrorV1 {
    pub message: String,
}

impl ThermalParseErrorV1 {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

pub(super) fn number_to_millidegrees(value: &serde_json::Value) -> Option<i64> {
    value.as_f64().map(|value| (value * 1000.0).round() as i64)
}

pub(super) struct ThermalReadingInputV1<'a> {
    pub provider_id: &'a str,
    pub sensor_key: &'a str,
    pub role: ThermalSensorRoleV1,
    pub raw_label: &'a str,
    pub temperature_millidegrees_celsius: i64,
    pub status: ThermalReadingStatusV1,
    pub observed_at: &'a str,
    pub evidence_target: HostStateThermalEvidenceTargetV1,
    pub source: Option<&'a str>,
}

pub(super) fn thermal_reading(input: ThermalReadingInputV1<'_>) -> HostStateThermalReadingV1 {
    HostStateThermalReadingV1 {
        sensor_id: format!(
            "{}:{}",
            input.provider_id,
            sanitize_id_part(input.sensor_key)
        ),
        sensor_role: input.role,
        sensor_alias: None,
        provider_id: input.provider_id.to_string(),
        raw_label: input.raw_label.to_string(),
        temperature_millidegrees_celsius: input.temperature_millidegrees_celsius,
        status: input.status,
        observed_at: input.observed_at.to_string(),
        evidence_target: input.evidence_target,
        source: input.source.map(ToOwned::to_owned),
    }
}

pub(super) fn infer_sensor_role(text: &str) -> ThermalSensorRoleV1 {
    let lowered = text.to_ascii_lowercase();
    if lowered.contains("nvme") {
        ThermalSensorRoleV1::Nvme
    } else if lowered.contains("ssd") {
        ThermalSensorRoleV1::Ssd
    } else if lowered.contains("gpu") || lowered.contains("nvidia") {
        ThermalSensorRoleV1::Gpu
    } else if lowered.contains("cpu") || lowered.contains("coretemp") || lowered.contains("k10temp")
    {
        ThermalSensorRoleV1::Cpu
    } else if lowered.contains("inlet") {
        ThermalSensorRoleV1::Inlet
    } else if lowered.contains("exhaust") {
        ThermalSensorRoleV1::Exhaust
    } else if lowered.contains("vrm") {
        ThermalSensorRoleV1::Vrm
    } else if lowered.contains("bmc") || lowered.contains("ipmi") {
        ThermalSensorRoleV1::Bmc
    } else if lowered.contains("network") || lowered.contains("broadcom") {
        ThermalSensorRoleV1::NetworkChip
    } else if lowered.contains("board")
        || lowered.contains("acpi")
        || lowered.contains("system")
        || lowered.contains("chipset")
    {
        ThermalSensorRoleV1::Board
    } else {
        ThermalSensorRoleV1::Unknown
    }
}

pub(super) fn thermal_status_from_text(text: &str) -> ThermalReadingStatusV1 {
    let lowered = text.to_ascii_lowercase();
    if lowered.contains("critical") || lowered.contains("cr") {
        ThermalReadingStatusV1::Critical
    } else if lowered.contains("warn") || lowered.contains("nc") {
        ThermalReadingStatusV1::Warning
    } else if lowered.contains("ok") {
        ThermalReadingStatusV1::Ok
    } else {
        ThermalReadingStatusV1::Unknown
    }
}

fn sanitize_id_part(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            out.push(character.to_ascii_lowercase());
        } else {
            out.push('-');
        }
    }
    out.trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_local_thermal_provider_entries_are_stable() {
        let providers = built_in_local_thermal_provider_entries_v1();
        assert_eq!(providers.len(), 2);

        assert_eq!(providers[0].provider_id, "local-lm-sensors");
        assert_eq!(
            providers[0].provider_kind,
            ThermalProviderKindV1::LmSensorsJson
        );
        assert_eq!(providers[0].command, vec!["sensors", "-j"]);
        assert_eq!(
            providers[0].evidence_target.target_kind,
            ThermalEvidenceTargetKindV1::CurrentHost
        );
        assert_eq!(
            providers[0].evidence_target.collection_path,
            ThermalCollectionPathV1::LocalProcess
        );

        assert_eq!(providers[1].provider_id, "local-nvidia-smi-thermal");
        assert_eq!(
            providers[1].provider_kind,
            ThermalProviderKindV1::NvidiaSmiQuery
        );
        assert_eq!(providers[1].command[0], "nvidia-smi");
        assert!(providers[1]
            .command
            .iter()
            .any(|arg| arg == "--query-gpu=uuid,name,temperature.gpu"));
        assert_eq!(
            providers[1].evidence_target.target_kind,
            ThermalEvidenceTargetKindV1::CurrentHost
        );
    }
}
