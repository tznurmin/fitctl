// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common;
use fitctl_core::artifacts::record_v1::ArtifactRecordV1;
use fitctl_core::artifacts::semantic_hash_v1::semantic_hash_hex_for_state;

#[test]
fn replay_produces_stable_host_state_artifact() {
    let left = common::collect_state_fixture("linux-bare-metal-like-fresh-v1");
    let mut right = common::collect_state_fixture("linux-bare-metal-like-fresh-v1");
    right.state.core_state.freshness.observed_at = "2025-04-21T14:42:19Z".to_string();

    assert_ne!(left, right);
    assert_eq!(
        semantic_hash_hex_for_state(&left).expect("left semantic hash"),
        semantic_hash_hex_for_state(&right).expect("right semantic hash")
    );
    assert_eq!(
        ArtifactRecordV1::State(left)
            .semantic_bytes()
            .expect("left semantic bytes"),
        ArtifactRecordV1::State(right)
            .semantic_bytes()
            .expect("right semantic bytes")
    );
}

#[test]
fn path_resources_contribute_to_state_semantic_hash() {
    let left = common::collect_state_fixture("linux-gpu-workstation-like-path-resources-fit-v1");
    let mut right =
        common::collect_state_fixture("linux-gpu-workstation-like-path-resources-fit-v1");
    right.state.core_state.path_resources.paths[0]
        .filesystem_available_bytes
        .value = Some(1);

    assert_ne!(
        semantic_hash_hex_for_state(&left).expect("left semantic hash"),
        semantic_hash_hex_for_state(&right).expect("right semantic hash")
    );
}

#[test]
fn memory_reliability_contributes_to_state_semantic_hash() {
    let left = common::collect_state_fixture("linux-bare-metal-like-fresh-v1");
    let mut right = common::collect_state_fixture("linux-bare-metal-like-fresh-v1");
    let mut value = serde_json::to_value(&right).expect("state should encode");
    value["state"]["core_state"]["memory_reliability"] = serde_json::json!({
        "observed_at": common::FIXED_TIMESTAMP,
        "providers": [
            {
                "provider_id": "local-edac-sysfs",
                "provider_kind": "edac_sysfs",
                "outcome": "success",
                "observed_at": common::FIXED_TIMESTAMP,
                "source": "/sys/devices/system/edac/mc"
            }
        ],
        "controller_count": { "state": "observed", "value": 1 },
        "dimm_count": { "state": "observed", "value": 8 },
        "corrected_error_count": { "state": "observed", "value": 2 },
        "uncorrected_error_count": { "state": "observed", "value": 0 }
    });
    right = serde_json::from_value(value).expect("state should decode");

    assert_ne!(
        semantic_hash_hex_for_state(&left).expect("left semantic hash"),
        semantic_hash_hex_for_state(&right).expect("right semantic hash")
    );
}

#[test]
fn gpu_reliability_contributes_to_state_semantic_hash() {
    let left = common::collect_state_fixture("linux-gpu-workstation-like-fresh-v1");
    let mut right = common::collect_state_fixture("linux-gpu-workstation-like-fresh-v1");
    let mut value = serde_json::to_value(&right).expect("state should encode");
    value["state"]["core_state"]["gpu_reliability"] = serde_json::json!({
        "observed_at": common::FIXED_TIMESTAMP,
        "providers": [
            {
                "provider_id": "local-nvidia-smi-reliability",
                "provider_kind": "nvidia_smi_xml",
                "outcome": "success",
                "observed_at": common::FIXED_TIMESTAMP
            }
        ],
        "devices": [
            {
                "gpu_uuid": { "state": "observed", "value": "GPU-secret-uuid" },
                "product_name": { "state": "observed", "value": "NVIDIA Test GPU" },
                "ecc_mode_current": { "state": "observed", "value": "Enabled" },
                "volatile_corrected_ecc_error_count": { "state": "observed", "value": 1 },
                "volatile_uncorrected_ecc_error_count": { "state": "observed", "value": 0 },
                "retired_pages_pending": { "state": "observed", "value": false },
                "row_remapper_pending": { "state": "observed", "value": false }
            }
        ]
    });
    right = serde_json::from_value(value).expect("state should decode");

    assert_ne!(
        semantic_hash_hex_for_state(&left).expect("left semantic hash"),
        semantic_hash_hex_for_state(&right).expect("right semantic hash")
    );
}
