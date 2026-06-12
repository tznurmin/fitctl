// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common;
use fitctl_core::artifacts::record_v1::ArtifactRecordV1;
use fitctl_core::redact::{redact_artifact_v1, BuiltInRedactionProfileV1, RedactionRequestV1};

#[test]
fn external_profile_redacts_sensitive_fields() {
    let survey = common::collect_survey_fixture("linux-bare-metal-like-v1");
    let original_survey = survey.survey.clone();
    let artifact = redact_artifact_v1(RedactionRequestV1 {
        artifact: ArtifactRecordV1::Survey(survey),
        profile: BuiltInRedactionProfileV1::External,
        redacted_at: common::FIXED_TIMESTAMP.to_string(),
    })
    .expect("external survey redaction should succeed");

    let ArtifactRecordV1::Survey(redacted) = artifact else {
        panic!("expected survey artifact");
    };

    assert_eq!(redacted.envelope.artifact_id, "survey-redacted-external-v1");
    assert_eq!(redacted.survey["host_alias"], "redacted:external:host");
    assert_eq!(redacted.survey["snapshot_id"], "redacted:external:host");
    assert_eq!(
        redacted.survey["source_ref"],
        "redacted:external:source_ref"
    );
    assert_eq!(
        redacted.survey["core_evidence"]["observations"]["hostname"]["value"],
        "redacted:external:host"
    );
    assert_eq!(
        redacted.survey["core_evidence"]["observations"]["cpu"]["value"]["model"],
        "redacted:external:cpu_model"
    );
    assert_eq!(
        redacted.survey["core_evidence"]["observations"]["network"]["value"]["interfaces"]
            .as_array()
            .expect("interfaces should remain an array")
            .len(),
        original_survey["core_evidence"]["observations"]["network"]["value"]["interfaces"]
            .as_array()
            .expect("original interfaces should remain an array")
            .len()
    );
}

#[test]
fn external_profile_redacts_state_checked_paths() {
    let state = common::collect_state_fixture("linux-gpu-workstation-like-path-resources-fit-v1");
    let artifact = redact_artifact_v1(RedactionRequestV1 {
        artifact: ArtifactRecordV1::State(state),
        profile: BuiltInRedactionProfileV1::External,
        redacted_at: common::FIXED_TIMESTAMP.to_string(),
    })
    .expect("external state redaction should succeed");

    let ArtifactRecordV1::State(redacted) = artifact else {
        panic!("expected state artifact");
    };

    let rendered = serde_json::to_string(&redacted).expect("redacted state should encode");
    assert!(!rendered.contains("/var/lib/local-model-cache"));
    assert!(!rendered.contains("/var/tmp/image-output"));
    assert_eq!(
        redacted.state.core_state.path_resources.paths[0].path,
        "redacted:external:mount_path:0"
    );
    assert_eq!(
        redacted.state.core_state.path_resources.paths[1].path,
        "redacted:external:mount_path:1"
    );
}
