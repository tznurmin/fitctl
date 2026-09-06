// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::hardware_sensor_quantities::parse;
use fitctl_core::artifacts::hardware_sensor_resources_v1::*;
use fitctl_core::artifacts::hardware_sensor_validation_v1::validate_hardware_sensor_resources_v1;
use fitctl_core::artifacts::state_v1::StateEvidenceProviderOutcomeV1;
use serde_json::{json, Value};

#[test]
pub(crate) fn hardware_sensor_provider_outcome_cannot_contradict_evidence() {
    let partial = parse(r#"{"chip":{"volts":{"in0_min":10}}}"#).unwrap();
    let mut inconsistent = partial.clone();
    inconsistent.providers[0].reason_code = Some(HardwareSensorReasonV1::HardwareSensorTimeout);
    assert!(validate_hardware_sensor_resources_v1(&inconsistent).is_err());
    let mut malformed = partial.clone();
    malformed.providers[0].outcome = StateEvidenceProviderOutcomeV1::Malformed;
    assert!(validate_hardware_sensor_resources_v1(&malformed).is_err());
    let mut empty = partial;
    empty.readings.clear();
    assert!(validate_hardware_sensor_resources_v1(&empty).is_err());
}

#[test]
pub(crate) fn hardware_sensor_wire_fields_are_required_even_for_null_values() {
    let resources = parse(r#"{"chip":{"volts":{"in0_min":10}}}"#).unwrap();
    let valid = serde_json::to_value(resources).unwrap();
    assert!(valid["readings"][0]["value"].is_null());
    for key in [
        "sensor_id",
        "value",
        "limits",
        "flags",
        "evidence_target",
        "raw_label",
    ] {
        let mut bad = valid.clone();
        bad["readings"][0].as_object_mut().unwrap().remove(key);
        assert!(
            serde_json::from_value::<HardwareSensorResourcesV1>(bad).is_err(),
            "{key}"
        );
    }
    let mut bad = valid.clone();
    bad["readings"][0]["limits"][0]
        .as_object_mut()
        .unwrap()
        .remove("value");
    assert!(serde_json::from_value::<HardwareSensorResourcesV1>(bad).is_err());
    for path in ["", "/providers/0", "/readings/0", "/readings/0/limits/0"] {
        let mut bad = valid.clone();
        bad.pointer_mut(path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unexpected".into(), json!(0));
        assert!(
            serde_json::from_value::<HardwareSensorResourcesV1>(bad).is_err(),
            "{path}"
        );
    }
    for key in ["observed_at", "collector_host", "providers", "readings"] {
        let mut bad = valid.clone();
        bad[key] = Value::Null;
        assert!(
            serde_json::from_value::<HardwareSensorResourcesV1>(bad).is_err(),
            "{key}"
        );
    }
}

#[test]
pub(crate) fn hardware_sensor_auxiliary_evidence_is_partial_not_wholly_malformed() {
    let s = parse(r#"{"chip":{"power":{"power1_input":"bad","power1_max":20}}}"#).unwrap();
    assert_eq!(
        s.providers[0].outcome,
        StateEvidenceProviderOutcomeV1::Partial
    );
    validate_hardware_sensor_resources_v1(&s).unwrap();
    let average = parse(r#"{"chip":{"power":{"power1_average":20,"power1_alarm":0}}}"#).unwrap();
    assert_eq!(
        average.readings.len(),
        1,
        "an average with a channel flag must not invent an input"
    );
    assert_eq!(
        average.providers[0].outcome,
        StateEvidenceProviderOutcomeV1::Success
    );
}

#[test]
pub(crate) fn hardware_sensor_rejects_alternative_json_layout() {
    let error = parse(r#"{"chip":{"in0":{"input":{"value":12,"unit":"V","quantity":"voltage"}}}}"#)
        .unwrap_err();
    assert_eq!(
        error.reason_code,
        HardwareSensorReasonV1::HardwareSensorJsonMalformed
    );
}
