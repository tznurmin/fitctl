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
