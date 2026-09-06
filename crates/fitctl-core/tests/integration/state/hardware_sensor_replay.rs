// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common;
use fitctl_core::artifacts::{
    record_v1::ArtifactRecordV1, state_v1::HostStateV1, validation_v1::validate_host_state,
};
use fitctl_core::redact::{redact_artifact_v1, BuiltInRedactionProfileV1, RedactionRequestV1};
use serde_json::Value;
use std::fs;

#[test]
pub(crate) fn hardware_sensor_replay_preserves_supplied_time_and_never_needs_live_probe() {
    // NoopLiveStateProbeV1 returns an error if accidentally selected by the replay engine.
    let state = common::collect_state_fixture("linux-hardware-sensors-v1");
    let sensors = state
        .state
        .core_state
        .hardware_sensor_resources
        .as_ref()
        .unwrap();
    assert_eq!(sensors.observed_at, "2026-09-05T00:00:00Z");
    assert_eq!(sensors.readings.len(), 7);
    assert_eq!(sensors.providers[0].provider_id, "local-lm-sensors");
    validate_host_state(&state).unwrap();
}

#[test]
pub(crate) fn hardware_sensor_conformance_valid_partial_invalid_and_redacted() {
    let root = common::repo_root();
    let corpus: Value = serde_json::from_slice(
        &fs::read(root.join("fixtures/conformance/manifest.v1.json")).unwrap(),
    )
    .unwrap();
    let mut seen = 0;
    for case in corpus["valid_cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| {
            c["case_id"]
                .as_str()
                .unwrap()
                .starts_with("state_hardware_sensor")
        })
    {
        let state: HostStateV1 =
            serde_json::from_slice(&fs::read(root.join(case["path"].as_str().unwrap())).unwrap())
                .unwrap();
        validate_host_state(&state).unwrap();
        assert_eq!(
            state
                .state
                .core_state
                .hardware_sensor_resources
                .as_ref()
                .unwrap()
                .readings
                .len(),
            7
        );
        let external = redact_artifact_v1(RedactionRequestV1 {
            artifact: ArtifactRecordV1::State(state),
            profile: BuiltInRedactionProfileV1::External,
            redacted_at: common::FIXED_TIMESTAMP.into(),
        })
        .unwrap();
        let json = serde_json::to_value(external).unwrap();
        assert!(!json.to_string().contains("fixture-psu"));
        seen += 1;
    }
    assert_eq!(seen, 2);
    let invalid: HostStateV1 = serde_json::from_slice(
        &fs::read(
            root.join("fixtures/conformance/invalid/hardware-sensor-quantity-unit-mismatch.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let error = validate_host_state(&invalid).unwrap_err();
    assert_eq!(error.error_model_id, "fitctl.hardware_sensor_evidence.v1");
    assert!(error
        .message
        .contains("hardware_sensor_quantity_unit_mismatch"));
}
