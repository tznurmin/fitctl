// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use fitctl_core::artifacts::record_v1::{load_artifact_record_from_value, ArtifactRecordV1};
use fitctl_core::redact::{
    redact_artifact_v1, BuiltInRedactionProfileV1, RedactionErrorCode, RedactionRequestV1,
};

use crate::common;

const SENTINEL: &str = "audit-only-sensitive-build-83";
const COLLECTION_LABEL: &str = "audit-only-sensitive-collection-label-83";

#[test]
fn imported_core_versions_are_sanitized_in_complete_sharing_output() {
    for profile in sharing_profiles() {
        for original in core_artifacts() {
            for version in [
                format!("0.6.0-{SENTINEL}"),
                format!("0.6.0+{SENTINEL}"),
                "v0.6.0".to_string(),
                "00.6.0".to_string(),
            ] {
                let mut input = original.clone();
                input.envelope_mut().provenance.fitctl_version = Some(version);
                let input = round_trip(input);
                let command = input.envelope().provenance.command_name.clone();
                let collected_at = input.envelope().provenance.collected_at.clone();
                let output = redact(input, profile);
                let expected = format!("redacted:{}:fitctl_version", profile.as_str());
                assert_eq!(
                    output.envelope().provenance.fitctl_version.as_deref(),
                    Some(expected.as_str()),
                    "{}",
                    output.schema_id()
                );
                assert_eq!(output.envelope().provenance.command_name, command);
                assert_eq!(output.envelope().provenance.collected_at, collected_at);
                assert!(!serde_json::to_string(&output).unwrap().contains(SENTINEL));
                assert!(output.envelope().signatures.is_empty());
                round_trip(output);
            }
        }
    }
}

#[test]
fn imported_core_malformed_timestamps_fail_at_the_sharing_boundary() {
    for profile in sharing_profiles() {
        for original in core_artifacts() {
            for timestamp in [
                COLLECTION_LABEL,
                "unix:18446744073709551616",
                "epoch:-1",
                "2025-02-29T00:00:00Z",
                "2025-04-31T00:00:00Z",
                "2025-04-21T24:00:00Z",
                "2025-04-21T14:60:00Z",
                "2025-04-21T14:37:60Z",
                "2025-04-21T14:37:19.1Z",
                "2025-04-21T14:37:19+00:00",
            ] {
                let mut input = original.clone();
                input.envelope_mut().provenance.collected_at = timestamp.to_string();
                let error = redact_artifact_v1(RedactionRequestV1 {
                    artifact: round_trip(input),
                    profile,
                    redacted_at: common::FIXED_TIMESTAMP.to_string(),
                })
                .expect_err("structurally valid imported timestamp must not be shareable");
                assert_eq!(error.code, RedactionErrorCode::ArtifactInputInvalid);
                assert_eq!(error.checkpoint_id, "provenance_validate");
                assert!(error.message.contains("collected_at"));
                assert!(!error.message.contains(COLLECTION_LABEL));
            }
        }
    }
}

#[test]
fn imported_core_supported_timestamps_and_release_versions_are_preserved() {
    for profile in sharing_profiles() {
        for original in core_artifacts() {
            for timestamp in [
                "epoch:0",
                "unix:1788566117",
                "unix:18446744073709551615",
                "2024-02-29T23:59:59Z",
                common::FIXED_TIMESTAMP,
            ] {
                for version in ["0.6.0", "0.2.1", "12.30.40"] {
                    let mut input = original.clone();
                    input.envelope_mut().provenance.collected_at = timestamp.to_string();
                    input.envelope_mut().provenance.fitctl_version = Some(version.to_string());
                    let output = redact(round_trip(input), profile);
                    assert_eq!(output.envelope().provenance.collected_at, timestamp);
                    assert_eq!(
                        output.envelope().provenance.fitctl_version.as_deref(),
                        Some(version)
                    );
                    round_trip(output);
                }
            }
        }
    }
}

#[test]
fn imported_core_local_and_fleet_keep_existing_provenance_compatibility() {
    for profile in [
        BuiltInRedactionProfileV1::Local,
        BuiltInRedactionProfileV1::Fleet,
    ] {
        for mut input in core_artifacts() {
            input.envelope_mut().provenance.collected_at = COLLECTION_LABEL.to_string();
            input.envelope_mut().provenance.fitctl_version = Some(SENTINEL.to_string());
            let output = redact(round_trip(input), profile);
            assert_eq!(output.envelope().provenance.collected_at, COLLECTION_LABEL);
            assert_eq!(
                output.envelope().provenance.fitctl_version.as_deref(),
                Some(SENTINEL)
            );
            round_trip(output);
        }
    }
}

#[test]
fn imported_core_missing_provenance_and_unknown_commands_remain_invalid() {
    for original in core_artifacts() {
        for version in [None, Some("".to_string()), Some(" \n".to_string())] {
            let mut input = original.clone();
            input.envelope_mut().provenance.fitctl_version = version;
            assert!(
                load_artifact_record_from_value(serde_json::to_value(&input).unwrap()).is_err()
            );
            for profile in sharing_profiles() {
                assert!(redact_artifact_v1(RedactionRequestV1 {
                    artifact: input.clone(),
                    profile,
                    redacted_at: common::FIXED_TIMESTAMP.to_string(),
                })
                .is_err());
            }
        }
        let mut input = original.clone();
        input.envelope_mut().provenance.command_name = Some(SENTINEL.to_string());
        assert!(load_artifact_record_from_value(serde_json::to_value(input).unwrap()).is_err());
        let mut input = original;
        input.envelope_mut().provenance.collected_at = " ".to_string();
        assert!(load_artifact_record_from_value(serde_json::to_value(input).unwrap()).is_err());
    }
}

#[test]
fn imported_core_provenance_mutations_do_not_redefine_semantic_identity() {
    for mut input in core_artifacts() {
        let original_hash = input.semantic_hash_hex().unwrap();
        input.envelope_mut().provenance.collected_at = COLLECTION_LABEL.to_string();
        input.envelope_mut().provenance.fitctl_version = Some(SENTINEL.to_string());
        assert_eq!(
            round_trip(input).semantic_hash_hex().unwrap(),
            original_hash
        );
    }
}

#[test]
fn imported_core_sanitized_outputs_still_reject_reredaction() {
    for profile in sharing_profiles() {
        for input in core_artifacts() {
            let error = redact_artifact_v1(RedactionRequestV1 {
                artifact: redact(input, profile),
                profile,
                redacted_at: common::FIXED_TIMESTAMP.to_string(),
            })
            .expect_err("redaction provenance cannot be overwritten");
            assert_eq!(
                error.code,
                RedactionErrorCode::RedactionInputAlreadyRedacted
            );
        }
    }
}

fn core_artifacts() -> Vec<ArtifactRecordV1> {
    [
        "host-survey.local-stable-identity-v2.v2.json",
        "host-contract.local-stable-identity-v2.v2.json",
        "host-state.thermal-resources.v2.json",
        "thermal-evidence.out-of-band-bmc.v1.json",
        "validation-report.cuda-runtime-allocatable-memory-fit.v2.json",
    ]
    .into_iter()
    .map(|name| {
        let path = common::repo_root()
            .join("fixtures/conformance/valid")
            .join(name);
        let raw = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        load_artifact_record_from_value(raw).expect("conformance input should validate")
    })
    .collect()
}

fn sharing_profiles() -> [BuiltInRedactionProfileV1; 2] {
    [
        BuiltInRedactionProfileV1::Auditor,
        BuiltInRedactionProfileV1::External,
    ]
}

fn round_trip(artifact: ArtifactRecordV1) -> ArtifactRecordV1 {
    load_artifact_record_from_value(serde_json::to_value(artifact).unwrap())
        .expect("complete artifact must remain valid")
}

fn redact(artifact: ArtifactRecordV1, profile: BuiltInRedactionProfileV1) -> ArtifactRecordV1 {
    redact_artifact_v1(RedactionRequestV1 {
        artifact,
        profile,
        redacted_at: common::FIXED_TIMESTAMP.to_string(),
    })
    .expect("artifact should redact")
}
