// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use fitctl_core::artifacts::record_v1::ArtifactRecordV1;
use fitctl_core::artifacts::validation_v1::validate_host_survey;
use fitctl_core::inspect::render_artifact_summary_v1;
use fitctl_core::survey::AcceleratorIntegrationV1;

use crate::common;

#[test]
fn accelerator_inventory_depth_surfaces_richer_details() {
    let survey = common::collect_survey_fixture("linux-arm-sbc-like-v1");
    validate_host_survey(&survey).expect("arm survey should validate");

    let payload = common::decode_survey_payload(&survey);
    let accelerators = payload
        .core_evidence
        .observations
        .accelerators
        .value
        .expect("accelerator details should be present");

    assert_eq!(accelerators.devices[0].family.as_deref(), Some("videocore"));
    assert_eq!(accelerators.devices[0].model.as_deref(), Some("v3d"));
    assert_eq!(
        accelerators.devices[0].integration,
        Some(AcceleratorIntegrationV1::Integrated)
    );

    let summary =
        render_artifact_summary_v1(&ArtifactRecordV1::Survey(survey)).expect("survey inspect");
    assert!(summary.contains("families videocore"));
    assert!(summary.contains("models v3d"));
    assert!(summary.contains("1 integrated"));
}
