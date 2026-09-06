// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{common, hardware_sensor_quantities::parse};
use fitctl_core::artifacts::hardware_sensor_resources_v1::*;
use fitctl_core::artifacts::{
    record_v1::ArtifactRecordV1, semantic_hash_v1::semantic_hash_hex_for_state,
    validation_v1::validate_host_state,
};
use fitctl_core::redact::{redact_artifact_v1, BuiltInRedactionProfileV1, RedactionRequestV1};

fn state() -> fitctl_core::artifacts::state_v1::HostStateV1 {
    let mut s = common::collect_state_fixture("linux-bare-metal-like-fresh-v1");
    s.state.core_state.hardware_sensor_resources = Some(
        parse(r#"{"sensitive-chip":{"sensitive-label":{"in0_input":12,"curr1_input":3}}}"#)
            .unwrap(),
    );
    s
}

#[test]
pub(crate) fn hardware_sensor_complete_sensitive_metadata_is_redacted() {
    let mut original = state();
    let s = original
        .state
        .core_state
        .hardware_sensor_resources
        .as_mut()
        .unwrap();
    s.collector_host.host_alias = Some("private-collector".into());
    s.collector_host.local_stable_id = Some("private-anchor".into());
    let target = fitctl_core::artifacts::state_v1::HostStateThermalEvidenceTargetV1 {
        target_kind: fitctl_core::artifacts::state_v1::ThermalEvidenceTargetKindV1::HostId,
        host_id: Some("private-target".into()),
        collection_path: fitctl_core::artifacts::state_v1::ThermalCollectionPathV1::LocalProcess,
    };
    s.providers[0].provider_id = "private-provider".into();
    s.providers[0].diagnostics = Some("private-diagnostic".into());
    s.providers[0].evidence_target = target.clone();
    for (i, r) in s.readings.iter_mut().enumerate() {
        r.provider_id = "private-provider".into();
        r.chip_id = "private-chip".into();
        r.sensor_id = format!("private-sensor-{i}");
        r.raw_label = "private-label".into();
        r.evidence_target = target.clone();
    }
    validate_host_state(&original).unwrap();
    for profile in [
        BuiltInRedactionProfileV1::Auditor,
        BuiltInRedactionProfileV1::External,
    ] {
        let redacted = redact_artifact_v1(RedactionRequestV1 {
            artifact: ArtifactRecordV1::State(original.clone()),
            profile,
            redacted_at: common::FIXED_TIMESTAMP.into(),
        })
        .unwrap();
        let text = serde_json::to_string(&redacted).unwrap();
        assert!(!text.contains("private-"), "{text}");
        let ArtifactRecordV1::State(s) = redacted else {
            panic!("state")
        };
        validate_host_state(&s).unwrap();
    }
}

#[test]
pub(crate) fn hardware_sensor_hash_diff_and_legacy_roundtrip() {
    let original = state();
    let h = semantic_hash_hex_for_state(&original).unwrap();
    let mut volatile = original.clone();
    let sensors = volatile
        .state
        .core_state
        .hardware_sensor_resources
        .as_mut()
        .unwrap();
    sensors.observed_at = "2026-09-05T01:00:00Z".into();
    for p in &mut sensors.providers {
        p.observed_at = sensors.observed_at.clone();
        p.diagnostics = Some("display-only".into());
    }
    for r in &mut sensors.readings {
        r.observed_at = sensors.observed_at.clone();
        r.raw_label = "renamed".into();
    }
    sensors.readings.reverse();
    assert_eq!(h, semantic_hash_hex_for_state(&volatile).unwrap());
    let mut changed = original.clone();
    changed
        .state
        .core_state
        .hardware_sensor_resources
        .as_mut()
        .unwrap()
        .readings[0]
        .value = Some(0);
    assert_ne!(h, semantic_hash_hex_for_state(&changed).unwrap());
    let diff = fitctl_core::diff::diff_artifact_records_v1(
        &ArtifactRecordV1::State(original),
        &ArtifactRecordV1::State(changed),
    )
    .unwrap();
    assert!(diff
        .changes
        .iter()
        .any(|c| c.path.contains("hardware_sensor_resources")));
    let old = common::collect_state_fixture("linux-bare-metal-like-fresh-v1");
    assert!(old.state.core_state.hardware_sensor_resources.is_none());
    let bytes = serde_json::to_string(&old).unwrap();
    assert!(!bytes.contains("hardware_sensor_resources"));
    let decoded = serde_json::from_str(&bytes).unwrap();
    assert_eq!(
        semantic_hash_hex_for_state(&old).unwrap(),
        semantic_hash_hex_for_state(&decoded).unwrap()
    );
}

#[test]
pub(crate) fn hardware_sensor_redaction_preserves_numbers_not_private_labels() {
    for profile in [
        BuiltInRedactionProfileV1::Local,
        BuiltInRedactionProfileV1::Fleet,
        BuiltInRedactionProfileV1::Auditor,
        BuiltInRedactionProfileV1::External,
    ] {
        let original = state();
        let redacted = redact_artifact_v1(RedactionRequestV1 {
            artifact: ArtifactRecordV1::State(original.clone()),
            profile,
            redacted_at: common::FIXED_TIMESTAMP.into(),
        })
        .unwrap();
        let ArtifactRecordV1::State(redacted) = redacted else {
            panic!("state")
        };
        validate_host_state(&redacted).unwrap();
        assert_eq!(
            redacted
                .state
                .core_state
                .hardware_sensor_resources
                .as_ref()
                .unwrap()
                .readings
                .iter()
                .map(|r| r.value)
                .collect::<Vec<_>>(),
            original
                .state
                .core_state
                .hardware_sensor_resources
                .as_ref()
                .unwrap()
                .readings
                .iter()
                .map(|r| r.value)
                .collect::<Vec<_>>()
        );
        let text = serde_json::to_string(&redacted).unwrap();
        assert_eq!(
            text.contains("sensitive-"),
            matches!(
                profile,
                BuiltInRedactionProfileV1::Local | BuiltInRedactionProfileV1::Fleet
            )
        );
    }
}

#[test]
pub(crate) fn hardware_sensor_signature_detects_numeric_mutation_and_clears_on_redaction() {
    let root = common::unique_temp_dir("hardware-sensor-signature");
    let key = common::generate_ed25519_keypair(&root, "signer");
    let signed = common::sign_artifact(ArtifactRecordV1::State(state()), &key);
    fitctl_core::sign::verify_artifact_signatures_v1(&signed).unwrap();
    let redacted = redact_artifact_v1(RedactionRequestV1 {
        artifact: signed.clone(),
        profile: BuiltInRedactionProfileV1::External,
        redacted_at: common::FIXED_TIMESTAMP.into(),
    })
    .unwrap();
    let ArtifactRecordV1::State(redacted) = redacted else {
        panic!("state")
    };
    assert!(redacted.envelope.signatures.is_empty());
    let ArtifactRecordV1::State(mut changed) = signed else {
        panic!("state")
    };
    changed
        .state
        .core_state
        .hardware_sensor_resources
        .as_mut()
        .unwrap()
        .readings[0]
        .value = Some(0);
    assert!(
        fitctl_core::sign::verify_artifact_signatures_v1(&ArtifactRecordV1::State(changed))
            .is_err()
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
pub(crate) fn hardware_sensor_invalid_artifact_cannot_hash_or_inspect() {
    let mut s = state();
    s.state
        .core_state
        .hardware_sensor_resources
        .as_mut()
        .unwrap()
        .readings[0]
        .unit = HardwareSensorUnitV1::Microjoules;
    assert!(semantic_hash_hex_for_state(&s).is_err());
    assert!(
        fitctl_core::inspect::load_artifact_record_for_inspect_from_value(
            serde_json::to_value(s).unwrap()
        )
        .is_err()
    );
}
