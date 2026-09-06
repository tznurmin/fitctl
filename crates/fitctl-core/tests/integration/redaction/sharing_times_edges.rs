// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{common, sharing_time_fixtures as fixtures};
use fitctl_core::artifacts::record_v1::{load_artifact_record_from_value, ArtifactRecordV1};
use fitctl_core::redact::{
    load_redactable_artifact_from_value, redact_artifact_v1, redact_supported_artifact_v1,
    BuiltInRedactionProfileV1, RedactableArtifactRequestV1, RedactionErrorCode, RedactionRequestV1,
};
use serde_json::Value;

const SHARING: [BuiltInRedactionProfileV1; 2] = [
    BuiltInRedactionProfileV1::Auditor,
    BuiltInRedactionProfileV1::External,
];

#[test]
fn sharing_times_valid_nested_and_auxiliary_times_survive_complete_output() {
    for input in fixtures::inputs() {
        let paths = fixtures::time_paths(&input, "");
        assert!(!paths.is_empty());
        for profile in SHARING {
            let output = redact_supported_artifact_v1(RedactableArtifactRequestV1 {
                artifact: load_redactable_artifact_from_value(input.clone()).unwrap(),
                profile,
                redacted_at: common::FIXED_TIMESTAMP.into(),
            })
            .unwrap();
            let output = serde_json::to_value(output).unwrap();
            for path in &paths {
                assert_eq!(input.pointer(path), output.pointer(path), "{path}");
            }
            load_redactable_artifact_from_value(output).unwrap();
        }
    }
}

#[test]
fn sharing_times_direct_core_api_checks_each_hardware_time_before_emit() {
    let input = fixtures::rich_state();
    load_artifact_record_from_value(input.clone()).unwrap();
    for path in fixtures::time_paths(&input, "")
        .into_iter()
        .filter(|path| path.contains("/hardware_sensor_resources/"))
    {
        let mut bad = input.clone();
        fixtures::replace(&mut bad, std::slice::from_ref(&path), fixtures::SENTINEL);
        // Direct typed callers can bypass the loading validator's equality checks.
        let state: fitctl_core::artifacts::state_v1::HostStateV1 =
            serde_json::from_value(bad).unwrap();
        for profile in SHARING {
            let error = redact_artifact_v1(RedactionRequestV1 {
                artifact: ArtifactRecordV1::State(state.clone()),
                profile,
                redacted_at: common::FIXED_TIMESTAMP.into(),
            })
            .err()
            .unwrap_or_else(|| panic!("unchecked {path}"));
            assert_eq!(error.code, RedactionErrorCode::ArtifactInputInvalid);
            assert_eq!(error.checkpoint_id, "sharing_timestamp_validate");
            assert!(!error.message.contains(fixtures::SENTINEL));
        }
    }
}

#[test]
fn sharing_times_verification_timestamps_remain_invalid_at_ordinary_loading() {
    let input = fixtures::bundle();
    for path in [
        "/bundle/verification_bundle/produced_at",
        "/bundle/verification_bundle/verification_report/verified_at",
    ] {
        let mut bad = input.clone();
        *bad.pointer_mut(path).unwrap() = fixtures::SENTINEL.into();
        assert!(
            load_artifact_record_from_value(bad.clone()).is_err(),
            "{path}"
        );
        for profile in SHARING {
            let bundle = serde_json::from_value(bad.clone()).unwrap();
            let error = redact_artifact_v1(RedactionRequestV1 {
                artifact: ArtifactRecordV1::DecisionBundle(bundle),
                profile,
                redacted_at: common::FIXED_TIMESTAMP.into(),
            })
            .err()
            .unwrap_or_else(|| panic!("direct typed verification timestamp must also reject"));
            assert_eq!(error.checkpoint_id, "sharing_timestamp_validate");
            assert!(!error.message.contains(fixtures::SENTINEL));
        }
    }
}

#[test]
fn sharing_times_no_new_relationship_and_absent_sections_are_required() {
    let mut input = fixtures::rich_state();
    // Independently observed sensor sections may have different valid times from freshness.
    input["state"]["core_state"]["freshness"]["observed_at"] = "unix:1".into();
    for section in ["memory_reliability", "gpu_reliability", "thermal_resources"] {
        input["state"]["core_state"]
            .as_object_mut()
            .unwrap()
            .remove(section);
    }
    for profile in SHARING {
        let output = redact_supported_artifact_v1(RedactableArtifactRequestV1 {
            artifact: load_redactable_artifact_from_value(input.clone()).unwrap(),
            profile,
            redacted_at: common::FIXED_TIMESTAMP.into(),
        })
        .unwrap();
        let output: Value = serde_json::to_value(output).unwrap();
        assert_eq!(
            output["state"]["core_state"]["freshness"]["observed_at"],
            "unix:1"
        );
        assert!(output["state"]["core_state"]["memory_reliability"].is_null());
    }
}
