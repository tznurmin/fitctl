// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Parser for `ipmitool sensor` thermal provider output.

use crate::artifacts::state_v1::{
    HostStateThermalEvidenceTargetV1, HostStateThermalReadingV1, ThermalReadingStatusV1,
};
use crate::state::thermal_v1::{
    infer_sensor_role, thermal_reading, thermal_status_from_text, ThermalParseErrorV1,
    ThermalReadingInputV1,
};

pub fn parse_ipmitool_sensor_output_v1(
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
        let parts = line.split('|').map(str::trim).collect::<Vec<_>>();
        if parts.len() < 3 {
            continue;
        }
        let units = parts[2].to_ascii_lowercase();
        if !(units.contains("degrees c") || units == "c" || units.contains("celsius")) {
            continue;
        }
        if is_unavailable_temperature_value(parts[1]) {
            continue;
        }
        let temperature = parts[1].parse::<f64>().map_err(|error| {
            ThermalParseErrorV1::new(format!("ipmitool temperature is malformed: {error}"))
        })?;
        let status = parts
            .get(3)
            .map(|value| thermal_status_from_text(value))
            .unwrap_or(ThermalReadingStatusV1::Unknown);
        readings.push(thermal_reading(ThermalReadingInputV1 {
            provider_id,
            sensor_key: parts[0],
            role: infer_sensor_role(parts[0]),
            raw_label: parts[0],
            temperature_millidegrees_celsius: (temperature * 1000.0).round() as i64,
            status,
            observed_at,
            evidence_target: evidence_target.clone(),
            source: Some("ipmitool_sensor"),
        }));
    }
    Ok(readings)
}

fn is_unavailable_temperature_value(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "na" | "n/a" | "unavailable" | "not available" | "disabled" | "no reading"
    )
}
