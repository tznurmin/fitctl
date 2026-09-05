// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Parser for structured `nvidia-smi` temperature query output.

use crate::artifacts::state_v1::{
    HostStateThermalEvidenceTargetV1, HostStateThermalReadingV1, ThermalReadingStatusV1,
    ThermalSensorRoleV1,
};
use crate::state::thermal_v1::{thermal_reading, ThermalParseErrorV1, ThermalReadingInputV1};

pub fn parse_nvidia_smi_query_output_v1(
    provider_id: &str,
    output: &str,
    observed_at: &str,
    evidence_target: HostStateThermalEvidenceTargetV1,
) -> Result<Vec<HostStateThermalReadingV1>, ThermalParseErrorV1> {
    let mut readings = Vec::new();
    for line in output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let parts = line.split(',').map(str::trim).collect::<Vec<_>>();
        if parts.len() < 3 {
            return Err(ThermalParseErrorV1::new(
                "nvidia-smi query row must contain uuid, name, temperature",
            ));
        }
        let temperature = parts[2].parse::<i64>().map_err(|error| {
            ThermalParseErrorV1::new(format!("nvidia-smi temperature is malformed: {error}"))
        })?;
        readings.push(thermal_reading(ThermalReadingInputV1 {
            provider_id,
            sensor_key: parts[0],
            role: ThermalSensorRoleV1::Gpu,
            raw_label: parts[1],
            temperature_millidegrees_celsius: temperature * 1000,
            status: ThermalReadingStatusV1::Ok,
            observed_at,
            evidence_target: evidence_target.clone(),
            source: Some("nvidia_smi_query"),
        }));
    }
    Ok(readings)
}
