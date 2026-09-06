// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common;
use fitctl_core::artifacts::{
    hardware_sensor_resources_v1::*,
    record_v1::{load_artifact_record_from_value, ArtifactRecordV1},
    state_v1::{HostStateV1, ThermalEvidenceTargetKindV1},
    validation_v1::validate_host_state,
};
use fitctl_core::redact::{
    redact_artifact_v1, BuiltInRedactionProfileV1, RedactionErrorCode, RedactionRequestV1,
};
use std::{fs, panic::catch_unwind};

const SHARING: [BuiltInRedactionProfileV1; 2] = [
    BuiltInRedactionProfileV1::Auditor,
    BuiltInRedactionProfileV1::External,
];
const PRIVATE_ID: &str = "private-undeclared-provider";

fn fixture() -> HostStateV1 {
    let state = serde_json::from_slice(
        &fs::read(
            common::repo_root()
                .join("fixtures/conformance/valid/host-state.hardware-sensors.v2.json"),
        )
        .unwrap(),
    )
    .unwrap();
    validate_host_state(&state).unwrap();
    state
}

fn request(state: HostStateV1, profile: BuiltInRedactionProfileV1) -> RedactionRequestV1 {
    RedactionRequestV1 {
        artifact: ArtifactRecordV1::State(state),
        profile,
        redacted_at: common::FIXED_TIMESTAMP.into(),
    }
}

#[test]
fn hardware_sensor_input_direct_api_rejects_invalid_sections_without_panicking() {
    for mutation in [
        "undeclared_provider",
        "empty_providers",
        "duplicate_provider",
        "duplicate_sensor",
        "target_mismatch",
        "unit_mismatch",
    ] {
        let mut state = fixture();
        let sensors = state
            .state
            .core_state
            .hardware_sensor_resources
            .as_mut()
            .unwrap();
        match mutation {
            "undeclared_provider" => sensors.readings[0].provider_id = PRIVATE_ID.into(),
            "empty_providers" => sensors.providers.clear(),
            "duplicate_provider" => sensors.providers.push(sensors.providers[0].clone()),
            "duplicate_sensor" => {
                sensors.readings[1].sensor_id = sensors.readings[0].sensor_id.clone()
            }
            "target_mismatch" => {
                sensors.readings[0].evidence_target.target_kind =
                    ThermalEvidenceTargetKindV1::HostId;
                sensors.readings[0].evidence_target.host_id = Some(PRIVATE_ID.into());
            }
            "unit_mismatch" => sensors.readings[0].unit = HardwareSensorUnitV1::Microjoules,
            _ => unreachable!(),
        }
        let before = serde_json::to_value(&state).unwrap();
        assert!(
            load_artifact_record_from_value(before.clone()).is_err(),
            "{mutation}"
        );
        for profile in SHARING {
            let result = catch_unwind(|| redact_artifact_v1(request(state.clone(), profile)))
                .unwrap_or_else(|_| panic!("redaction panicked for {mutation} / {profile:?}"));
            let error = result
                .err()
                .unwrap_or_else(|| panic!("accepted {mutation}"));
            assert_eq!(
                error.code,
                RedactionErrorCode::ArtifactInputInvalid,
                "{mutation}"
            );
            assert_eq!(error.checkpoint_id, "redaction_preflight", "{mutation}");
            assert_eq!(error.error_model_id, "fitctl.redaction.v1");
            assert_eq!(error.error_model_version, 1);
            assert!(error.message.contains("hardware_sensor_"));
            assert!(!error.message.contains(PRIVATE_ID));
            assert_eq!(serde_json::to_value(&state).unwrap(), before);
        }
    }
}

#[test]
fn hardware_sensor_input_valid_multiple_providers_preserve_measurements_and_links() {
    let mut state = fixture();
    let sensors = state
        .state
        .core_state
        .hardware_sensor_resources
        .as_mut()
        .unwrap();
    let voltage = sensors
        .readings
        .iter_mut()
        .find(|r| r.quantity == HardwareSensorQuantityV1::Voltage)
        .unwrap();
    voltage.limits.push(HardwareSensorLimitV1 {
        kind: HardwareSensorLimitKindV1::Max,
        source: HardwareSensorLimitSourceV1::ProviderReported,
        quantity: voltage.quantity,
        unit: voltage.unit,
        value: Some(13_000_000),
        value_state: HardwareSensorValueStateV1::Observed,
        reason_code: None,
    });
    voltage.flags.push(HardwareSensorFlagV1 {
        kind: HardwareSensorFlagKindV1::Alarm,
        state: HardwareSensorFlagStateV1::Asserted,
        reason_code: None,
    });
    let mut provider = sensors.providers[0].clone();
    provider.provider_id = "private-second-provider".into();
    provider.evidence_target.target_kind = ThermalEvidenceTargetKindV1::HostId;
    provider.evidence_target.host_id = Some("private-second-target".into());
    let readings: Vec<_> = sensors
        .readings
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let mut r = r.clone();
            r.sensor_id = format!("private-second-sensor-{i}");
            r.provider_id = provider.provider_id.clone();
            r.evidence_target = provider.evidence_target.clone();
            r
        })
        .collect();
    sensors.providers.push(provider);
    sensors.readings.extend(readings);
    validate_host_state(&state).unwrap();
    let original = state
        .state
        .core_state
        .hardware_sensor_resources
        .as_ref()
        .unwrap();
    let before = serde_json::to_value(&state).unwrap();
    for profile in SHARING {
        let output = redact_artifact_v1(request(state.clone(), profile)).unwrap();
        let ArtifactRecordV1::State(output) = output else {
            panic!("state expected")
        };
        validate_host_state(&output).unwrap();
        let out = output.state.core_state.hardware_sensor_resources.unwrap();
        assert_eq!(out.providers.len(), original.providers.len());
        assert_eq!(out.readings.len(), original.readings.len());
        assert_eq!(out.observed_at, original.observed_at);
        for (input, output) in original.readings.iter().zip(&out.readings) {
            let provider_index = original
                .providers
                .iter()
                .position(|p| p.provider_id == input.provider_id)
                .unwrap();
            assert_eq!(
                output.provider_id,
                out.providers[provider_index].provider_id
            );
            assert_eq!(
                output.evidence_target,
                out.providers[provider_index].evidence_target
            );
            let mut restored = output.clone();
            restored.sensor_id = input.sensor_id.clone();
            restored.provider_id = input.provider_id.clone();
            restored.chip_id = input.chip_id.clone();
            restored.raw_label = input.raw_label.clone();
            restored.evidence_target = input.evidence_target.clone();
            assert_eq!(&restored, input);
        }
        assert!(!serde_json::to_string(&out).unwrap().contains("private-"));
        assert_eq!(serde_json::to_value(&state).unwrap(), before);
    }
}

#[test]
fn hardware_sensor_input_preserves_existing_preflight_precedence() {
    for profile in SHARING {
        let mut malformed = fixture();
        let sensors = malformed
            .state
            .core_state
            .hardware_sensor_resources
            .as_mut()
            .unwrap();
        sensors.readings[0].provider_id = PRIVATE_ID.into();
        sensors.observed_at = "private-not-a-timestamp".into();
        let error = redact_artifact_v1(request(malformed, profile))
            .err()
            .unwrap();
        assert_eq!(error.checkpoint_id, "sharing_timestamp_validate");

        let ArtifactRecordV1::State(mut already) =
            redact_artifact_v1(request(fixture(), profile)).unwrap()
        else {
            panic!("state expected")
        };
        already
            .state
            .core_state
            .hardware_sensor_resources
            .as_mut()
            .unwrap()
            .readings[0]
            .provider_id = PRIVATE_ID.into();
        let error = redact_artifact_v1(request(already, profile)).err().unwrap();
        assert_eq!(
            error.code,
            RedactionErrorCode::RedactionInputAlreadyRedacted
        );
        assert_eq!(error.checkpoint_id, "redaction_preflight");
    }
}
