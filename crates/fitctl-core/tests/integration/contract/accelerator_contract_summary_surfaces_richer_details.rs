// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use fitctl_core::artifacts::record_v1::ArtifactRecordV1;
use fitctl_core::artifacts::validation_v1::validate_host_contract;
use fitctl_core::inspect::render_artifact_summary_v1;

use crate::common;

#[test]
fn accelerator_contract_summary_surfaces_richer_details() {
    let contract = common::derive_contract_from_fixture_with_policy(
        "linux-gpu-workstation-like-v1",
        "gpu_compute_default.v1.json",
    );
    validate_host_contract(&contract).expect("gpu contract should validate");

    let payload = common::decode_contract_payload(&contract);
    assert_eq!(
        payload.core_contract.accelerator_summary.families,
        vec!["nvidia_pci".to_string()]
    );
    assert_eq!(
        payload.core_contract.accelerator_summary.models,
        vec!["nvidia-gpu-2206".to_string(), "nvidia-gpu-2230".to_string()]
    );
    assert_eq!(
        payload
            .core_contract
            .accelerator_summary
            .accelerators_with_known_memory,
        Some(2)
    );
    assert_eq!(
        payload.core_contract.accelerator_summary.max_memory_bytes,
        Some(51_539_607_552)
    );

    let summary = render_artifact_summary_v1(&ArtifactRecordV1::Contract(contract))
        .expect("contract inspect");
    assert!(summary.contains("families nvidia_pci"));
    assert!(summary.contains("models nvidia-gpu-2206, nvidia-gpu-2230"));
    assert!(summary.contains("2 known-memory"));
    assert!(summary.contains("max memory 48.0 GiB"));
}
