// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use fitctl_core::artifacts::validation_v1::validate_host_state;
use fitctl_core::state::{
    LocalLiveStateProbeV1, StateEngineV1, StateModeV1, StatePathCheckRequestV1,
};
use fitctl_core::survey::ObservationStateV1;

use crate::common;

#[test]
fn live_path_check_records_storage_evidence() {
    let root = common::unique_temp_dir("path-storage-evidence");
    let state = StateEngineV1::new(LocalLiveStateProbeV1::new(vec![StatePathCheckRequestV1 {
        path_id: "scratch".to_string(),
        path: root.clone(),
        probe_links: false,
        probe_health: false,
    }]))
    .collect_host_state(StateModeV1::Live)
    .expect("live state should collect");

    validate_host_state(&state).expect("host state should validate");
    let path = &state.state.core_state.path_resources.paths[0];
    assert_eq!(path.path_id, "scratch");
    assert_eq!(path.exists.state, ObservationStateV1::Observed);
    assert_eq!(path.exists.value, Some(true));
    assert_eq!(path.canonical_path.state, ObservationStateV1::Observed);
    assert_eq!(
        path.canonical_path.value.as_deref(),
        Some(root.to_str().expect("temp path should be UTF-8"))
    );
    assert_eq!(
        path.containing_mount_point.state,
        ObservationStateV1::Observed
    );
    assert_eq!(path.filesystem_type.state, ObservationStateV1::Observed);
    assert_eq!(
        path.mount_device_major_minor.state,
        ObservationStateV1::Observed
    );
    assert!(!path.storage_identity_evidence.is_empty());
    assert_eq!(path.media_class.state, ObservationStateV1::Observed);
    assert!(path.observed_at.is_some());
    assert!(path.link_capabilities.is_none());
}

#[test]
fn link_capability_probe_is_explicit_and_typed() {
    let root = common::unique_temp_dir("path-link-probe");
    let state = StateEngineV1::new(LocalLiveStateProbeV1::new(vec![StatePathCheckRequestV1 {
        path_id: "scratch".to_string(),
        path: root,
        probe_links: true,
        probe_health: false,
    }]))
    .collect_host_state(StateModeV1::Live)
    .expect("live state should collect");

    let path = &state.state.core_state.path_resources.paths[0];
    let links = path
        .link_capabilities
        .as_ref()
        .expect("link capabilities should be present when requested");
    assert_eq!(links.copy_possible.state, ObservationStateV1::Observed);
    assert!(links.probe_method.is_some());
    assert!(links.probe_root.is_some());
    validate_host_state(&state).expect("host state with link probes should validate");
}
