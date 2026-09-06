// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use fitctl_core::artifacts::hardware_sensor_resources_v1::*;
use fitctl_core::artifacts::hardware_sensor_validation_v1::validate_hardware_sensor_resources_v1;
use fitctl_core::artifacts::state_v1::*;
use fitctl_core::state::hardware_sensors_v1::parse_hardware_sensors_json_v1;
use serde_json::{json, Value};

pub(super) fn parse(
    text: &str,
) -> Result<HardwareSensorResourcesV1, fitctl_core::state::hardware_sensors_v1::SensorError> {
    parse_hardware_sensors_json_v1(
        text,
        "fixture-provider",
        "2026-09-05T00:00:00Z",
        HostStateThermalCollectorHostV1 {
            host_alias: Some("fixture-host".into()),
            local_stable_id: None,
        },
        HostStateThermalEvidenceTargetV1 {
            target_kind: ThermalEvidenceTargetKindV1::CurrentHost,
            host_id: None,
            collection_path: ThermalCollectionPathV1::LocalProcess,
        },
    )
}
fn project(fields: Value) -> HardwareSensorResourcesV1 {
    let result = parse(&json!({"chip":{"label":fields}}).to_string()).unwrap();
    validate_hardware_sensor_resources_v1(&result).unwrap();
    result
}

#[test]
pub(crate) fn hardware_sensor_quantity_matrix() {
    use HardwareSensorQuantityV1::*;
    use HardwareSensorUnitV1::*;
    for (key, value, q, u, scaled) in [
        ("in0_input", -12.25, Voltage, Microvolts, -12_250_000),
        ("curr1_input", -1.125, Current, Microamperes, -1_125_000),
        ("power1_input", -3.5, Power, Microwatts, -3_500_000),
        ("power1_average", 2.75, Power, Microwatts, 2_750_000),
        ("fan1_input", 0., FanSpeed, MillirevolutionsPerMinute, 0),
        ("energy1_input", 123., Energy, Microjoules, 123_000_000),
        (
            "humidity1_input",
            100.,
            RelativeHumidity,
            Millipercent,
            100_000,
        ),
    ] {
        let resources = project(json!({key:value}));
        assert_eq!(
            resources.providers[0].outcome,
            StateEvidenceProviderOutcomeV1::Success
        );
        let r = &resources.readings[0];
        assert_eq!((r.quantity, r.unit, r.value), (q, u, Some(scaled)), "{key}");
    }
    for (v, want) in [(0.0000005, 1), (-0.0000005, -1), (0., 0)] {
        assert_eq!(
            project(json!({"in1_input":v})).readings[0].value,
            Some(want)
        );
    }
}

#[test]
pub(crate) fn hardware_sensor_rejects_invalid_values_without_erasing_siblings() {
    for invalid in [
        json!(null),
        json!(true),
        json!("12"),
        json!([]),
        json!(1e100),
    ] {
        let resources = project(json!({"in0_input":invalid,"curr1_input":0}));
        assert_eq!(
            resources.providers[0].outcome,
            StateEvidenceProviderOutcomeV1::Partial
        );
        let bad = resources
            .readings
            .iter()
            .find(|r| r.channel_id == "in0_input")
            .unwrap();
        assert_eq!(bad.value, None);
        assert_eq!(bad.value_state, HardwareSensorValueStateV1::Malformed);
    }
    for (key, v) in [
        ("fan1_input", -0.000001),
        ("energy1_input", -1.),
        ("humidity1_input", 100.00001),
    ] {
        let r = project(json!({key:v}));
        assert_eq!(
            r.readings[0].reason_code,
            Some(HardwareSensorReasonV1::HardwareSensorValueOutOfRange)
        );
    }
}

#[test]
pub(crate) fn hardware_sensor_alarm_fault_and_limit_matrix() {
    let r = project(
        json!({"fan1_input":0,"fan1_min":100,"fan1_max":5000,"fan1_fault":1,"fan1_alarm":0}),
    );
    assert_eq!(
        r.providers[0].outcome,
        StateEvidenceProviderOutcomeV1::Partial
    );
    assert_eq!(r.readings[0].value, Some(0));
    assert_eq!(
        r.readings[0].value_state,
        HardwareSensorValueStateV1::Faulted
    );
    assert_eq!(r.readings[0].limits.len(), 2);
    assert!(r.readings[0]
        .flags
        .iter()
        .any(|f| f.kind == HardwareSensorFlagKindV1::Alarm
            && f.state == HardwareSensorFlagStateV1::Clear));
    let r = project(json!({"in0_input":12,"in0_crit":10,"in0_max_alarm":1}));
    assert_eq!(
        r.providers[0].outcome,
        StateEvidenceProviderOutcomeV1::Success
    );
    assert_eq!(
        r.readings[0].flags.len(),
        1,
        "do not synthesize an alarm from a limit"
    );
    for flag in [json!(true), json!("1"), json!(null), json!(2), json!(-1)] {
        let r = project(json!({"in0_input":12,"in0_alarm":flag}));
        assert_eq!(r.readings[0].value, Some(12_000_000));
        assert_eq!(
            r.readings[0].flags[0].state,
            HardwareSensorFlagStateV1::Malformed
        );
        assert_eq!(
            r.providers[0].outcome,
            StateEvidenceProviderOutcomeV1::Partial
        );
    }
    let r = project(json!({"in0_min":1}));
    assert_eq!(
        r.readings[0].value_state,
        HardwareSensorValueStateV1::Unavailable
    );
    assert_eq!(r.readings[0].value, None);
}

#[test]
pub(crate) fn hardware_sensor_exact_grammar_and_average_identity() {
    let r = project(
        json!({"temp1_input":45,"in01_input":12,"fan0_input":0,"curr01_input":0,"power1_cap":12,"pwm1":34,"in1_enable":1,"power1_input_highest":200}),
    );
    assert!(r.readings.is_empty());
    assert_eq!(
        r.providers[0].reason_code,
        Some(HardwareSensorReasonV1::HardwareSensorNoSupportedReadings)
    );
    let r = project(
        json!({"power1_input":3,"power1_average":2,"power1_average_max":8,"power1_max":9,"power1_cap_alarm":0}),
    );
    assert_eq!(r.readings.len(), 2);
    assert_ne!(r.readings[0].sensor_id, r.readings[1].sensor_id);
    assert!(r
        .readings
        .iter()
        .all(|r| r.limits.len() == 1 && r.flags.len() == 1));
}

#[test]
pub(crate) fn hardware_sensor_duplicate_structure_and_bounds() {
    for text in [
        r#"{"chip":{"a":{"in0_input":1,"in0_input":2}}}"#,
        r#"{"chip":{},"chip":{}}"#,
    ] {
        assert_eq!(
            parse(text).unwrap_err().reason_code,
            HardwareSensorReasonV1::HardwareSensorDuplicateKey
        );
    }
    for text in ["[]", "null", r#"{"chip":42}"#, r#"{"chip":{"feature":42}}"#] {
        assert!(parse(text).is_err());
    }
    assert!(parse(&json!({"x".repeat(1025):{}}).to_string()).is_err());
    assert!(parse(&json!({"x".repeat(1024):{}}).to_string()).is_ok());
    let at_limit: serde_json::Map<_, _> = (1..=4096)
        .map(|i| (format!("in{i}_input"), json!(1)))
        .collect();
    let accepted = parse(&json!({"chip":{"label":at_limit}}).to_string()).unwrap();
    assert_eq!(accepted.readings.len(), 4096);
    validate_hardware_sensor_resources_v1(&accepted).unwrap();
    let fields: serde_json::Map<_, _> = (1..=4097)
        .map(|i| (format!("in{i}_input"), json!(1)))
        .collect();
    assert_eq!(
        parse(&json!({"chip":{"label":fields}}).to_string())
            .unwrap_err()
            .reason_code,
        HardwareSensorReasonV1::HardwareSensorStructureLimit
    );
    assert_eq!(
        parse(&" ".repeat(1_048_577)).unwrap_err().reason_code,
        HardwareSensorReasonV1::HardwareSensorOutputLimit
    );
    assert!(parse(&format!("{{}}{}", " ".repeat(1_048_574))).is_ok());
    assert!(parse(r#"{"chip":{"a":{"in0_input":1},"b":{"in0_input":2}}}"#).is_err());
}

#[test]
pub(crate) fn hardware_sensor_typed_artifacts_fail_closed() {
    let valid = project(json!({"in0_input":12}));
    for mutate in [0, 1, 2, 3, 4, 5, 6] {
        let mut s = valid.clone();
        match mutate {
            0 => s.readings[0].unit = HardwareSensorUnitV1::Microamperes,
            1 => s.readings[0].provider_id = "unknown".into(),
            2 => s.readings.push(s.readings[0].clone()),
            3 => s.readings[0].value = None,
            4 => {
                s.readings[0].reason_code =
                    Some(HardwareSensorReasonV1::HardwareSensorValueUnavailable)
            }
            5 => s.readings[0].observed_at = "wrong-time".into(),
            _ => s.providers[0].outcome = StateEvidenceProviderOutcomeV1::Unavailable,
        }
        assert!(
            validate_hardware_sensor_resources_v1(&s).is_err(),
            "mutation {mutate}"
        );
    }
    for key in ["quantity", "unit", "value_state", "measurement_kind"] {
        let mut json = serde_json::to_value(&valid).unwrap();
        json["readings"][0][key] = json!("unknown");
        assert!(serde_json::from_value::<HardwareSensorResourcesV1>(json).is_err());
    }
}
