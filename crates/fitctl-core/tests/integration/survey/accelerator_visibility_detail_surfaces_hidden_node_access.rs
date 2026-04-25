// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use fitctl_core::artifacts::record_v1::ArtifactRecordV1;
use fitctl_core::artifacts::validation_v1::validate_host_survey;
use fitctl_core::inspect::{render_artifact_summary_with_options_v1, InspectRenderOptionsV1};
use fitctl_core::survey::{StaticOperabilityV1, VisibilityScopeV1};

use crate::common;

#[test]
fn accelerator_visibility_detail_surfaces_hidden_node_access() {
    let survey = common::collect_survey_fixture("linux-gpu-container-restricted-like-v1");
    validate_host_survey(&survey).expect("restricted gpu survey should validate");

    let payload = common::decode_survey_payload(&survey);
    let accelerators = payload
        .core_evidence
        .observations
        .accelerators
        .value
        .expect("accelerator details should be present");
    let operability = accelerators
        .operability
        .as_ref()
        .expect("operability should be present");

    assert_eq!(
        payload.core_evidence.execution_context.visibility_scope,
        VisibilityScopeV1::ContainerRestricted
    );
    assert_eq!(
        operability.static_operability,
        StaticOperabilityV1::NotOperable
    );
    assert!(operability.visible_device_nodes.is_empty());
    assert!(operability.visible_render_nodes.is_empty());

    let summary = render_artifact_summary_with_options_v1(
        &ArtifactRecordV1::Survey(survey),
        InspectRenderOptionsV1 {
            verbose: true,
            ..InspectRenderOptionsV1::default()
        },
    )
    .expect("survey inspect");
    assert!(summary.contains("nodes <none>"));
    assert!(summary.contains("render nodes <none>"));
}
