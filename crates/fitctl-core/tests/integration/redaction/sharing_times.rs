// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{common, sharing_time_fixtures as fixtures};
use fitctl_core::redact::{
    load_redactable_artifact_from_value, redact_supported_artifact_v1, BuiltInRedactionProfileV1,
    RedactableArtifactRequestV1, RedactionError, RedactionErrorCode,
};
use serde_json::Value;

const SHARING: [BuiltInRedactionProfileV1; 2] = [
    BuiltInRedactionProfileV1::Auditor,
    BuiltInRedactionProfileV1::External,
];

fn redact(
    input: Value,
    profile: BuiltInRedactionProfileV1,
    at: &str,
) -> Result<Value, RedactionError> {
    let artifact =
        load_redactable_artifact_from_value(input).expect("ordinary input must remain valid");
    redact_supported_artifact_v1(RedactableArtifactRequestV1 {
        artifact,
        profile,
        redacted_at: at.into(),
    })
    .map(|artifact| serde_json::to_value(artifact).unwrap())
}

#[test]
fn sharing_times_reject_every_retained_timestamp_family_without_echoing() {
    for input in fixtures::inputs() {
        for paths in fixtures::mutation_groups(&input) {
            let mut bad = input.clone();
            fixtures::replace(&mut bad, &paths, fixtures::SENTINEL);
            for profile in SHARING {
                let error = redact(bad.clone(), profile, common::FIXED_TIMESTAMP)
                    .err()
                    .unwrap_or_else(|| panic!("sharing must reject {paths:?}"));
                assert_eq!(
                    error.code,
                    RedactionErrorCode::ArtifactInputInvalid,
                    "{paths:?}"
                );
                assert_eq!(
                    error.checkpoint_id, "sharing_timestamp_validate",
                    "{paths:?}"
                );
                assert!(!error.message.contains(fixtures::SENTINEL));
            }
        }
    }
}

#[test]
fn sharing_times_supported_grammar_preserves_complete_output_and_numeric_facts() {
    let input = fixtures::rich_state();
    let paths = fixtures::time_paths(&input, "");
    for at in [
        "epoch:0",
        "unix:1788566117",
        "unix:18446744073709551615",
        "2024-02-29T23:59:59Z",
    ] {
        let mut input = input.clone();
        fixtures::replace(&mut input, &paths, at);
        for profile in SHARING {
            let output = redact(input.clone(), profile, at).unwrap();
            for path in &paths {
                assert_eq!(output.pointer(path).unwrap(), at, "{path}");
            }
            assert_eq!(output["envelope"]["redaction"]["redacted_at"], at);
            let field = "state";
            let original = &input[field]["core_state"]["hardware_sensor_resources"]["readings"];
            let redacted = &output[field]["core_state"]["hardware_sensor_resources"]["readings"];
            for (before, after) in original
                .as_array()
                .unwrap()
                .iter()
                .zip(redacted.as_array().unwrap())
            {
                for key in ["value", "quantity", "unit", "observed_at"] {
                    assert_eq!(before[key], after[key]);
                }
            }
            load_redactable_artifact_from_value(output).unwrap();
        }
    }
}

#[test]
fn sharing_times_bad_grammar_and_supplied_redaction_time_fail_closed() {
    let input = fixtures::rich_state();
    let paths = fixtures::time_paths(&input, "");
    for at in [
        fixtures::SENTINEL,
        "unix:18446744073709551616",
        "2025-02-29T12:00:00Z",
        "2025-04-21T24:00:00Z",
        "2025-04-21T14:37:19+00:00",
        "2025-04-21T14:37:19.123Z",
        " unix:1",
    ] {
        let mut bad = input.clone();
        fixtures::replace(&mut bad, &paths, at);
        for profile in SHARING {
            for result in [
                redact(bad.clone(), profile, common::FIXED_TIMESTAMP),
                redact(input.clone(), profile, at),
            ] {
                let error = result
                    .err()
                    .unwrap_or_else(|| panic!("invalid sharing time must fail"));
                assert_eq!(error.code, RedactionErrorCode::ArtifactInputInvalid);
                assert_eq!(error.checkpoint_id, "sharing_timestamp_validate");
                assert!(!error.message.contains(at));
            }
        }
    }
}

#[test]
fn sharing_times_local_fleet_and_optional_absence_remain_compatible() {
    for input in fixtures::inputs() {
        for paths in fixtures::mutation_groups(&input) {
            let mut input = input.clone();
            fixtures::replace(&mut input, &paths, fixtures::SENTINEL);
            for profile in [
                BuiltInRedactionProfileV1::Local,
                BuiltInRedactionProfileV1::Fleet,
            ] {
                let output = redact(input.clone(), profile, fixtures::SENTINEL).unwrap();
                for path in &paths {
                    assert_eq!(output.pointer(path).unwrap(), fixtures::SENTINEL);
                }
            }
        }
    }
    let mut input = fixtures::rich_state();
    input["state"]["core_state"]["path_resources"]["paths"][0]["storage_health"]["observed_at"] =
        Value::Null;
    for profile in SHARING {
        let output = redact(input.clone(), profile, common::FIXED_TIMESTAMP).unwrap();
        assert!(
            output["state"]["core_state"]["path_resources"]["paths"][0]["storage_health"]
                ["observed_at"]
                .is_null()
        );
    }
}
