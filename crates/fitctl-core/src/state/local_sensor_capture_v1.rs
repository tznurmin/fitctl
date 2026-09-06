// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Invocation-owned capture shared only with the identical built-in local thermal provider.

use super::hardware_sensors_v1::parse_hardware_sensors_json_v1;
use super::thermal_v1::thermal_command_v1::{run_provider_command, ProviderFailure};
use super::thermal_v1::{
    built_in_local_thermal_provider_entries_v1, collect_thermal_with_capture_v1,
    ThermalProviderConfigEntryV1,
};
use crate::artifacts::hardware_sensor_resources_v1::*;
use crate::artifacts::state_v1::{
    HostStateThermalCollectorHostV1, HostStateThermalResourcesV1, StateEvidenceProviderOutcomeV1,
    ThermalProviderOutcomeV1,
};

pub(super) fn collect(
    thermal: &[ThermalProviderConfigEntryV1],
    hardware: bool,
    observed_at: &str,
    collector_host: HostStateThermalCollectorHostV1,
) -> (
    Option<HostStateThermalResourcesV1>,
    Option<HardwareSensorResourcesV1>,
) {
    let builtin = built_in_local_thermal_provider_entries_v1().remove(0);
    let capture = hardware.then(|| {
        if cfg!(target_os = "linux") {
            run_provider_command(&builtin)
        } else {
            Err(ProviderFailure {
                outcome: ThermalProviderOutcomeV1::Unavailable,
                error_code: "thermal_provider_unavailable",
                diagnostics: "hardware sensors require Linux".to_owned(),
            })
        }
    });
    let thermal_resources =
        collect_thermal_with_capture_v1(thermal, observed_at, collector_host.clone(), |p| {
            if matches_builtin(p, &builtin) {
                if let Some(result) = &capture {
                    return result.clone();
                }
            }
            run_provider_command(p)
        });
    let hardware_resources = capture.map(|result| {
        use HardwareSensorReasonV1::*;
        let failure = match result {
            Ok(output) if !output.status.success() => (
                StateEvidenceProviderOutcomeV1::CommandFailed,
                HardwareSensorCommandFailed,
            ),
            Ok(output) => {
                let decoded = std::str::from_utf8(&output.stdout)
                    .map_err(|_| HardwareSensorJsonMalformed)
                    .and_then(|text| {
                        parse_hardware_sensors_json_v1(
                            text,
                            &builtin.provider_id,
                            observed_at,
                            collector_host.clone(),
                            builtin.evidence_target.clone(),
                        )
                        .map_err(|e| e.reason_code)
                    });
                match decoded {
                    Ok(resources) => return resources,
                    Err(reason) => (StateEvidenceProviderOutcomeV1::Malformed, reason),
                }
            }
            Err(e) => match e.outcome {
                ThermalProviderOutcomeV1::Unavailable => (
                    StateEvidenceProviderOutcomeV1::Unavailable,
                    HardwareSensorSourceUnavailable,
                ),
                ThermalProviderOutcomeV1::PermissionDenied => (
                    StateEvidenceProviderOutcomeV1::PermissionDenied,
                    HardwareSensorPermissionDenied,
                ),
                _ => (
                    StateEvidenceProviderOutcomeV1::CommandFailed,
                    match e.error_code {
                        "thermal_provider_command_timeout" => HardwareSensorTimeout,
                        "thermal_provider_output_too_large" => HardwareSensorOutputLimit,
                        _ => HardwareSensorCommandFailed,
                    },
                ),
            },
        };
        HardwareSensorResourcesV1 {
            observed_at: observed_at.to_owned(),
            collector_host,
            providers: vec![HardwareSensorProviderV1 {
                provider_id: builtin.provider_id,
                provider_kind: HardwareSensorProviderKindV1::LmSensorsJson,
                outcome: failure.0,
                evidence_target: builtin.evidence_target,
                observed_at: observed_at.to_owned(),
                reason_code: Some(failure.1),
                diagnostics: None,
            }],
            readings: vec![],
        }
    });
    (thermal_resources, hardware_resources)
}

fn matches_builtin(p: &ThermalProviderConfigEntryV1, b: &ThermalProviderConfigEntryV1) -> bool {
    p.provider_id == b.provider_id
        && p.provider_kind == b.provider_kind
        && p.command == b.command
        && p.timeout_seconds == b.timeout_seconds
        && p.evidence_target == b.evidence_target
        && p.sensor_mappings.is_empty()
}
