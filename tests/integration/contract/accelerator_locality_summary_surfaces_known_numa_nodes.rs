// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use fitctl_core::artifacts::record_v1::ArtifactRecordV1;
use fitctl_core::artifacts::validation_v1::{validate_host_contract, validate_host_survey};
use fitctl_core::inspect::render_artifact_summary_v1;

use crate::common;

#[test]
fn accelerator_locality_summary_surfaces_known_numa_nodes() {
    let survey = common::collect_survey_fixture("linux-gpu-dual-numa-like-v1");
    validate_host_survey(&survey).expect("gpu dual-numa survey should validate");
    let survey_payload = common::decode_survey_payload(&survey);
    let accelerators = survey_payload
        .core_evidence
        .observations
        .accelerators
        .value
        .expect("accelerator details should be present");

    assert_eq!(accelerators.devices[0].numa_node, Some(0));
    assert_eq!(accelerators.devices[1].numa_node, Some(1));

    let contract = common::derive_contract_from_fixture_with_policy(
        "linux-gpu-dual-numa-like-v1",
        "gpu_compute_default.v1.json",
    );
    validate_host_contract(&contract).expect("gpu dual-numa contract should validate");
    let contract_payload = common::decode_contract_payload(&contract);

    assert_eq!(
        contract_payload
            .core_contract
            .accelerator_summary
            .accelerators_with_known_numa_node,
        Some(2)
    );
    assert_eq!(
        contract_payload
            .core_contract
            .accelerator_summary
            .accelerator_numa_nodes,
        vec![0, 1]
    );

    let contract_summary = render_artifact_summary_v1(&ArtifactRecordV1::Contract(contract))
        .expect("contract inspect");
    assert!(contract_summary.contains("locality 2/2 known; NUMA nodes 0, 1"));
}
