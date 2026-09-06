// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Parser for `sensors -j` style thermal provider output.

use crate::artifacts::state_v1::{HostStateThermalEvidenceTargetV1, HostStateThermalReadingV1};
use crate::state::thermal_v1::{
    infer_sensor_role, number_to_millidegrees, thermal_reading, ThermalParseErrorV1,
    ThermalReadingInputV1,
};

pub fn parse_lm_sensors_json_output_v1(
    provider_id: &str,
    output: &str,
    observed_at: &str,
    evidence_target: HostStateThermalEvidenceTargetV1,
) -> Result<Vec<HostStateThermalReadingV1>, ThermalParseErrorV1> {
    let value: serde_json::Value = serde_json::from_str(output).map_err(|error| {
        ThermalParseErrorV1::new(format!("lm-sensors JSON is malformed: {error}"))
    })?;
    let object = value
        .as_object()
        .ok_or_else(|| ThermalParseErrorV1::new("lm-sensors JSON root must be an object"))?;
    let mut readings = Vec::new();
    for (chip, chip_value) in object {
        let Some(features) = chip_value.as_object() else {
            continue;
        };
        for (feature, feature_value) in features {
            let Some(fields) = feature_value.as_object() else {
                continue;
            };
            for (field, field_value) in fields {
                if !is_temperature_input(field) {
                    continue;
                }
                let Some(value) = number_to_millidegrees(field_value) else {
                    return Err(ThermalParseErrorV1::new(
                        "lm-sensors temperature value must be numeric",
                    ));
                };
                let role = infer_sensor_role(&format!("{chip} {feature}"));
                readings.push(thermal_reading(ThermalReadingInputV1 {
                    provider_id,
                    sensor_key: &format!("{chip}:{feature}:{field}"),
                    role,
                    raw_label: feature,
                    temperature_millidegrees_celsius: value,
                    status: crate::artifacts::state_v1::ThermalReadingStatusV1::Ok,
                    observed_at,
                    evidence_target: evidence_target.clone(),
                    source: Some(chip),
                }));
            }
        }
    }
    Ok(readings)
}

fn is_temperature_input(field: &str) -> bool {
    let Some(index) = field
        .strip_prefix("temp")
        .and_then(|s| s.strip_suffix("_input"))
    else {
        return false;
    };
    // libsensors exposes several quantities as *_input; only tempN carries Celsius.
    matches!(index.as_bytes().first(), Some(b'1'..=b'9'))
        && index.bytes().all(|byte| byte.is_ascii_digit())
}
