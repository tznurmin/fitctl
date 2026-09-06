// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use fitctl_core::artifacts::state_v1::{
    HostStateThermalEvidenceTargetV1, ThermalCollectionPathV1, ThermalEvidenceTargetKindV1,
};
use fitctl_core::state::thermal_v1::parse_lm_sensors_json_output_v1;

fn parse(
    value: serde_json::Value,
) -> Result<
    Vec<fitctl_core::artifacts::state_v1::HostStateThermalReadingV1>,
    fitctl_core::state::thermal_v1::ThermalParseErrorV1,
> {
    parse_lm_sensors_json_output_v1(
        "local-lm-sensors",
        &value.to_string(),
        "2026-09-05T00:00:00Z",
        HostStateThermalEvidenceTargetV1 {
            target_kind: ThermalEvidenceTargetKindV1::CurrentHost,
            host_id: None,
            collection_path: ThermalCollectionPathV1::LocalProcess,
        },
    )
}

#[test]
pub(crate) fn lm_sensors_units_mixed_quantities_remain_temperature_only() {
    let readings = parse(serde_json::json!({"corsairpsu-hid": {
        "vrm temp": {"temp1_input": 46.75}, "case temp": {"temp2_input": 45.5},
        "curr +12v": {"curr2_input": 3}, "power +12v": {"power2_input": 34},
        "v_in": {"in0_input": 230}, "psu fan": {"fan1_input": 0},
        "energy": {"energy1_input": 100}, "humidity": {"humidity1_input": 50}
    }}))
    .unwrap();
    assert_eq!(readings.len(), 2);
    assert!(readings.iter().all(|r| r.sensor_id.contains("-temp")));
    assert!(readings
        .iter()
        .any(|r| r.temperature_millidegrees_celsius == 45_500));
}

#[test]
pub(crate) fn lm_sensors_units_channel_grammar_is_exact() {
    for ignored in [
        "temp0_input",
        "temp01_input",
        "temp_input",
        "temp-1_input",
        "atemp1_input",
        "temp١_input",
        "power1_input",
    ] {
        assert!(
            parse(serde_json::json!({"chip":{"label":{ignored:"not a number"}}}))
                .unwrap()
                .is_empty(),
            "{ignored}"
        );
    }
    for (field, value) in [("temp1_input", 0), ("temp12_input", -3)] {
        let readings = parse(serde_json::json!({"chip":{"label":{field:value}}})).unwrap();
        assert_eq!(readings.len(), 1);
        assert_eq!(readings[0].temperature_millidegrees_celsius, value * 1000);
    }
}

#[test]
pub(crate) fn lm_sensors_units_value_failure_is_quantity_local() {
    let input =
        serde_json::json!({"chip":{"temp":{"temp1_input":42},"current":{"curr1_input":null}}});
    assert_eq!(parse(input).unwrap().len(), 1);
    assert!(parse(serde_json::json!({"chip":{"temp":{"temp1_input":null}}})).is_err());
}
