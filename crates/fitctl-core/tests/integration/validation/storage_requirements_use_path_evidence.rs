// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use fitctl_core::artifacts::record_v1::ArtifactRecordV1;
use fitctl_core::artifacts::semantic_hash_v1::semantic_hash_hex_for_state;
use fitctl_core::artifacts::service_profile_v1::ServiceProfileV1;
use fitctl_core::artifacts::state_v1::{
    HostStatePathLinkCapabilitiesV1, StateFieldV1, StateStorageDurabilityClassV1,
    StateStorageMediaClassV1,
};
use fitctl_core::artifacts::validation_report_v1::{ValidationModeV1, ValidationVerdictV1};
use fitctl_core::artifacts::validation_v1::validate_host_state;
use fitctl_core::redact::{redact_artifact_v1, BuiltInRedactionProfileV1, RedactionRequestV1};
use fitctl_core::storage_profile::{init_storage_profile_v1, StorageProfileInitRequestV1};
use fitctl_core::survey::ObservationStateV1;

use crate::common;

#[test]
fn storage_media_and_filesystem_requirements_can_fit() {
    let contract = common::derive_contract_from_fixture("linux-gpu-workstation-like-v1");
    let state = path_state_with_storage_evidence();
    let profile =
        storage_profile_with_requirements(vec!["nvme"], vec!["durable"], vec!["ext4"], false);

    let report = common::validate_with_profile(
        contract,
        profile,
        Some(state),
        ValidationModeV1::StateRequired,
        None,
    );
    assert_eq!(report.report.verdict, ValidationVerdictV1::Fit);
    assert!(report
        .report
        .matched_requirements
        .contains(&"core_requirements.required_paths[model-cache]".to_string()));
}

#[test]
fn storage_media_mismatch_is_unfit() {
    let contract = common::derive_contract_from_fixture("linux-gpu-workstation-like-v1");
    let state = path_state_with_storage_evidence();
    let profile =
        storage_profile_with_requirements(vec!["tmpfs"], vec!["ephemeral"], vec!["ext4"], false);

    let report = common::validate_with_profile(
        contract,
        profile,
        Some(state),
        ValidationModeV1::StateRequired,
        None,
    );
    assert_eq!(report.report.verdict, ValidationVerdictV1::Unfit);
    assert!(report
        .report
        .failed_requirements
        .contains(&"core_requirements.required_paths[model-cache]".to_string()));
}

#[test]
fn storage_identity_requirements_can_fit() {
    let contract = common::derive_contract_from_fixture("linux-gpu-workstation-like-v1");
    let state = path_state_with_storage_evidence();
    let profile = storage_profile_with_identity_requirements(
        vec!["11111111-2222-3333-4444-555555555555"],
        vec!["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"],
    );

    let report = common::validate_with_profile(
        contract,
        profile,
        Some(state),
        ValidationModeV1::StateRequired,
        None,
    );
    assert_eq!(report.report.verdict, ValidationVerdictV1::Fit);
}

#[test]
fn persistent_device_link_requirements_can_fit() {
    let contract = common::derive_contract_from_fixture("linux-gpu-workstation-like-v1");
    let state = path_state_with_storage_evidence();
    let profile = storage_profile_with_persistent_device_links(vec!["/dev/disk/by-id/nvme-test"]);

    let report = common::validate_with_profile(
        contract,
        profile,
        Some(state),
        ValidationModeV1::StateRequired,
        None,
    );
    assert_eq!(report.report.verdict, ValidationVerdictV1::Fit);
}

#[test]
fn storage_profile_init_includes_observed_storage_identity() {
    let profile = init_storage_profile_v1(StorageProfileInitRequestV1 {
        state: path_state_with_storage_evidence(),
        profile_id: "generated-storage-profile-test-v1".to_string(),
        display_name: None,
        short_display_name: None,
        primary_capability_class: "general_compute".to_string(),
        min_available_bytes_by_path_id: BTreeMap::from([(
            "model-cache".to_string(),
            1_073_741_824,
        )]),
    })
    .expect("storage profile should initialize from observed path evidence");

    let path_requirement = &profile.profile.core_requirements.required_paths[0];
    assert_eq!(path_requirement.path_id, "model-cache");
    assert_eq!(path_requirement.min_available_bytes, Some(1_073_741_824));
    assert_eq!(
        path_requirement.accepted_filesystem_uuids,
        vec!["11111111-2222-3333-4444-555555555555".to_string()]
    );
    assert_eq!(
        path_requirement.accepted_partition_uuids,
        vec!["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".to_string()]
    );
    assert_eq!(
        path_requirement.accepted_persistent_device_links,
        vec!["/dev/disk/by-id/nvme-test".to_string()]
    );
    assert_eq!(path_requirement.required_filesystem_types, vec!["ext4"]);
    assert_eq!(
        path_requirement.accepted_media_classes,
        vec![StateStorageMediaClassV1::Nvme]
    );
}

#[test]
fn missing_persistent_device_link_evidence_is_indeterminate_when_required() {
    let contract = common::derive_contract_from_fixture("linux-gpu-workstation-like-v1");
    let mut state = path_state_with_storage_evidence();
    state.state.core_state.path_resources.paths[0].persistent_device_links =
        StateFieldV1::default();
    let profile = storage_profile_with_persistent_device_links(vec!["/dev/disk/by-id/nvme-test"]);

    let report = common::validate_with_profile(
        contract,
        profile,
        Some(state),
        ValidationModeV1::StateRequired,
        None,
    );
    assert_eq!(report.report.verdict, ValidationVerdictV1::Indeterminate);
    assert_eq!(
        report.report.primary_reason_code,
        fitctl_core::artifacts::validation_report_v1::ValidationReasonCodeV1::StateMissing
    );
}

#[test]
fn persistent_device_link_mismatch_is_unfit() {
    let contract = common::derive_contract_from_fixture("linux-gpu-workstation-like-v1");
    let state = path_state_with_storage_evidence();
    let profile = storage_profile_with_persistent_device_links(vec!["/dev/disk/by-id/nvme-other"]);

    let report = common::validate_with_profile(
        contract,
        profile,
        Some(state),
        ValidationModeV1::StateRequired,
        None,
    );
    assert_eq!(report.report.verdict, ValidationVerdictV1::Unfit);
    assert!(report
        .report
        .summary
        .contains("persistent device link is not accepted"));
    assert!(report
        .report
        .failed_requirements
        .contains(&"core_requirements.required_paths[model-cache]".to_string()));
}

#[test]
fn storage_identity_mismatch_is_unfit() {
    let contract = common::derive_contract_from_fixture("linux-gpu-workstation-like-v1");
    let state = path_state_with_storage_evidence();
    let profile = storage_profile_with_identity_requirements(
        vec!["99999999-2222-3333-4444-555555555555"],
        vec!["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"],
    );

    let report = common::validate_with_profile(
        contract,
        profile,
        Some(state),
        ValidationModeV1::StateRequired,
        None,
    );
    assert_eq!(report.report.verdict, ValidationVerdictV1::Unfit);
    assert!(report
        .report
        .summary
        .contains("filesystem UUID is not accepted"));
}

#[test]
fn missing_storage_identity_evidence_is_indeterminate_when_required() {
    let contract = common::derive_contract_from_fixture("linux-gpu-workstation-like-v1");
    let mut state = path_state_with_storage_evidence();
    let path = &mut state.state.core_state.path_resources.paths[0];
    path.filesystem_uuid = StateFieldV1::default();
    let profile = storage_profile_with_identity_requirements(
        vec!["11111111-2222-3333-4444-555555555555"],
        vec![],
    );

    let report = common::validate_with_profile(
        contract,
        profile,
        Some(state),
        ValidationModeV1::StateRequired,
        None,
    );
    assert_eq!(report.report.verdict, ValidationVerdictV1::Indeterminate);
    assert_eq!(
        report.report.primary_reason_code,
        fitctl_core::artifacts::validation_report_v1::ValidationReasonCodeV1::StateMissing
    );
}

#[test]
fn required_link_capability_without_probe_is_indeterminate() {
    let contract = common::derive_contract_from_fixture("linux-gpu-workstation-like-v1");
    let state = path_state_with_storage_evidence();
    let profile = storage_profile_with_requirements(vec!["nvme"], vec!["durable"], vec![], true);

    let report = common::validate_with_profile(
        contract,
        profile,
        Some(state),
        ValidationModeV1::StateRequired,
        None,
    );
    assert_eq!(report.report.verdict, ValidationVerdictV1::Indeterminate);
    assert!(report
        .report
        .summary
        .contains("required path link capability evidence is missing"));
}

#[test]
fn path_relationship_requires_distinct_filesystem_identity() {
    let contract = common::derive_contract_from_fixture("linux-gpu-workstation-like-v1");
    let state = state_with_two_paths_and_pair(true);
    let profile = storage_profile_with_relationship("filesystem_uuid");

    let fit_report = common::validate_with_profile(
        contract.clone(),
        profile.clone(),
        Some(state.clone()),
        ValidationModeV1::StateRequired,
        None,
    );
    assert_eq!(fit_report.report.verdict, ValidationVerdictV1::Fit);

    let mut shared_state = state;
    shared_state.state.core_state.path_resources.paths[1].filesystem_uuid =
        observed("11111111-2222-3333-4444-555555555555".to_string());
    let unfit_report = common::validate_with_profile(
        contract,
        profile,
        Some(shared_state),
        ValidationModeV1::StateRequired,
        None,
    );
    assert_eq!(unfit_report.report.verdict, ValidationVerdictV1::Unfit);
    assert!(unfit_report
        .report
        .failed_requirements
        .contains(&"core_requirements.path_relationships[model-cache-not-output]".to_string()));

    let json = serde_json::to_value(&unfit_report).expect("report should encode");
    let diagnostics = json["report"]["path_diagnostics"]
        .as_array()
        .expect("path diagnostics should be emitted");
    assert!(diagnostics.iter().any(|diagnostic| {
        diagnostic["diagnostic_id"] == "path_relationship:model-cache-not-output:filesystem_uuid"
            && diagnostic["status"] == "failed"
            && diagnostic["observed"]["left"] == "11111111-2222-3333-4444-555555555555"
            && diagnostic["observed"]["right"] == "11111111-2222-3333-4444-555555555555"
    }));
}

#[test]
fn required_path_link_pair_capability_uses_pair_probe_evidence() {
    let contract = common::derive_contract_from_fixture("linux-gpu-workstation-like-v1");
    let state = state_with_two_paths_and_pair(true);
    let profile = storage_profile_with_pair_requirement();

    let fit_report = common::validate_with_profile(
        contract.clone(),
        profile.clone(),
        Some(state),
        ValidationModeV1::StateRequired,
        None,
    );
    assert_eq!(fit_report.report.verdict, ValidationVerdictV1::Fit);

    let blocked_state = state_with_two_paths_and_pair(false);
    let unfit_report = common::validate_with_profile(
        contract,
        profile,
        Some(blocked_state),
        ValidationModeV1::StateRequired,
        None,
    );
    assert_eq!(unfit_report.report.verdict, ValidationVerdictV1::Unfit);
    assert!(unfit_report.report.failed_requirements.contains(
        &"core_requirements.required_path_link_pairs[model-cache-to-output]".to_string()
    ));
}

#[test]
fn path_link_pairs_contribute_to_state_semantic_hash() {
    let original = state_with_two_paths_and_pair(true);
    let original_hash =
        semantic_hash_hex_for_state(&original).expect("original state should hash semantically");
    let changed = state_with_two_paths_and_pair(false);
    let changed_hash =
        semantic_hash_hex_for_state(&changed).expect("changed state should hash semantically");
    assert_ne!(original_hash, changed_hash);
}

#[test]
fn storage_health_contributes_to_state_semantic_hash() {
    let original = state_with_storage_health(41);
    let original_hash =
        semantic_hash_hex_for_state(&original).expect("original state should hash semantically");
    let changed = state_with_storage_health(42);
    let changed_hash =
        semantic_hash_hex_for_state(&changed).expect("changed state should hash semantically");
    assert_ne!(original_hash, changed_hash);
}

#[test]
fn storage_health_unknown_when_device_health_unavailable() {
    let mut value =
        serde_json::to_value(path_state_with_storage_evidence()).expect("state should encode");
    value["state"]["core_state"]["path_resources"]["paths"][0]["storage_health"] = serde_json::json!({
        "health_state": unknown_json(),
        "temperature_celsius": unknown_json(),
        "percentage_used": unknown_json(),
        "available_spare_percent": unknown_json(),
        "source": "unknown",
        "probe_method": "sysfs_hwmon_best_effort",
        "probe_error": "no safe storage health source for path",
        "observed_at": common::FIXED_TIMESTAMP
    });
    let state: fitctl_core::artifacts::state_v1::HostStateV1 =
        serde_json::from_value(value).expect("state with unavailable health should decode");

    validate_host_state(&state).expect("unknown storage health evidence should be valid state");
    let health = state.state.core_state.path_resources.paths[0]
        .storage_health
        .as_ref()
        .expect("storage health should be present");
    assert_eq!(health.health_state.state, ObservationStateV1::Unknown);
    assert_eq!(
        health.temperature_celsius.state,
        ObservationStateV1::Unknown
    );
    assert_eq!(
        health.probe_error.as_deref(),
        Some("no safe storage health source for path")
    );
}

#[test]
fn path_storage_evidence_contributes_to_state_semantic_hash_and_redacts() {
    let original = path_state_with_storage_evidence();
    let original_hash =
        semantic_hash_hex_for_state(&original).expect("original state should hash semantically");
    let mut changed = original.clone();
    changed.state.core_state.path_resources.paths[0].media_class =
        observed(StateStorageMediaClassV1::Ssd);
    let changed_hash =
        semantic_hash_hex_for_state(&changed).expect("changed state should hash semantically");
    assert_ne!(original_hash, changed_hash);

    let artifact = redact_artifact_v1(RedactionRequestV1 {
        artifact: ArtifactRecordV1::State(original),
        profile: BuiltInRedactionProfileV1::External,
        redacted_at: common::FIXED_TIMESTAMP.to_string(),
    })
    .expect("state redaction should succeed");
    let ArtifactRecordV1::State(redacted) = artifact else {
        panic!("expected state artifact");
    };
    let rendered = serde_json::to_string(&redacted).expect("redacted state should encode");
    assert!(!rendered.contains("/var/lib/local-model-cache"));
    assert!(!rendered.contains("/dev/nvme0n1p1"));
    assert!(!rendered.contains("11111111-2222-3333-4444-555555555555"));
    assert!(!rendered.contains("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"));
    assert!(!rendered.contains("/dev/disk/by-id/nvme-test"));
    assert_eq!(
        redacted.state.core_state.path_resources.paths[0]
            .canonical_path
            .value
            .as_deref(),
        Some("redacted:external:mount_path:0")
    );
}

fn state_with_two_paths_and_pair(
    hardlink_supported: bool,
) -> fitctl_core::artifacts::state_v1::HostStateV1 {
    let mut state = path_state_with_storage_evidence();
    state.state.core_state.path_resources.paths.truncate(1);
    let mut output = state.state.core_state.path_resources.paths[0].clone();
    output.path_id = "output".to_string();
    output.path = "/var/tmp/image-output".to_string();
    output.requested_path = Some("/var/tmp/image-output".to_string());
    output.canonical_path = observed("/var/tmp/image-output".to_string());
    output.containing_mount_point = observed("/var/tmp".to_string());
    output.mount_source = observed("/dev/nvme1n1p1".to_string());
    output.mount_device_major_minor = observed("259:2".to_string());
    output.filesystem_uuid = observed("22222222-2222-3333-4444-555555555555".to_string());
    output.partition_uuid = observed("bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee".to_string());
    output.persistent_device_links = observed(vec!["/dev/disk/by-id/nvme-output".to_string()]);
    output.storage_identity_evidence = vec![
        "filesystem_uuid=22222222-2222-3333-4444-555555555555".to_string(),
        "partition_uuid=bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee".to_string(),
        "persistent_device_link=/dev/disk/by-id/nvme-output".to_string(),
    ];
    state.state.core_state.path_resources.paths.push(output);

    let mut value = serde_json::to_value(&state).expect("state should encode");
    value["state"]["core_state"]["path_resources"]["link_pairs"] = serde_json::json!([
        {
            "pair_id": "model-cache-to-output",
            "from_path_id": "model-cache",
            "to_path_id": "output",
            "same_filesystem": observed_json(false),
            "hardlink_supported": observed_json(hardlink_supported),
            "reflink_supported": observed_json(false),
            "symlink_supported": observed_json(true),
            "copy_possible": observed_json(true),
            "probe_method": "test-pair-probe",
            "observed_at": common::FIXED_TIMESTAMP
        }
    ]);
    serde_json::from_value(value).expect("state with pair evidence should decode")
}

fn path_state_with_storage_evidence() -> fitctl_core::artifacts::state_v1::HostStateV1 {
    let mut state =
        common::collect_state_fixture("linux-gpu-workstation-like-path-resources-fit-v1");
    let path = &mut state.state.core_state.path_resources.paths[0];
    path.requested_path = Some("/var/lib/local-model-cache".to_string());
    path.canonical_path = observed("/var/lib/local-model-cache".to_string());
    path.containing_mount_point = observed("/var".to_string());
    path.filesystem_type = observed("ext4".to_string());
    path.mount_source = observed("/dev/nvme0n1p1".to_string());
    path.mount_options = observed(vec!["rw".to_string(), "relatime".to_string()]);
    path.mount_device_major_minor = observed("259:1".to_string());
    path.filesystem_uuid = observed("11111111-2222-3333-4444-555555555555".to_string());
    path.partition_uuid = observed("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".to_string());
    path.persistent_device_links = observed(vec!["/dev/disk/by-id/nvme-test".to_string()]);
    path.storage_identity_evidence = vec![
        "filesystem_uuid=11111111-2222-3333-4444-555555555555".to_string(),
        "partition_uuid=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".to_string(),
        "persistent_device_link=/dev/disk/by-id/nvme-test".to_string(),
    ];
    path.media_class = observed(StateStorageMediaClassV1::Nvme);
    path.media_class_confidence =
        observed(fitctl_core::state::StateStorageMediaClassConfidenceV1::High);
    path.media_class_evidence = vec!["block_device=nvme0n1".to_string()];
    path.durability_class = observed(StateStorageDurabilityClassV1::Durable);
    path.observed_at = Some(common::FIXED_TIMESTAMP.to_string());
    state
}

fn storage_profile_with_relationship(identity: &str) -> ServiceProfileV1 {
    let profile = storage_profile_with_requirements(vec!["nvme"], vec!["durable"], vec![], false);
    let mut value = serde_json::to_value(&profile).expect("profile should encode");
    value["profile"]["core_requirements"]["path_relationships"] = serde_json::json!([
        {
            "relationship_id": "model-cache-not-output",
            "left_path_id": "model-cache",
            "right_path_id": "output",
            "must_not_share": [identity]
        }
    ]);
    serde_json::from_value(value).expect("profile with relationship should decode")
}

fn storage_profile_with_pair_requirement() -> ServiceProfileV1 {
    let profile = storage_profile_with_requirements(vec!["nvme"], vec!["durable"], vec![], false);
    let mut value = serde_json::to_value(&profile).expect("profile should encode");
    value["profile"]["core_requirements"]["required_path_link_pairs"] = serde_json::json!([
        {
            "pair_id": "model-cache-to-output",
            "from_path_id": "model-cache",
            "to_path_id": "output",
            "require_hardlink": true
        }
    ]);
    serde_json::from_value(value).expect("profile with pair requirement should decode")
}

fn storage_profile_with_identity_requirements(
    filesystem_uuids: Vec<&str>,
    partition_uuids: Vec<&str>,
) -> ServiceProfileV1 {
    let mut profile =
        storage_profile_with_requirements(vec!["nvme"], vec!["durable"], vec![], false);
    let path_requirement = &mut profile.profile.core_requirements.required_paths[0];
    path_requirement.accepted_filesystem_uuids = filesystem_uuids
        .into_iter()
        .map(std::string::ToString::to_string)
        .collect();
    path_requirement.accepted_partition_uuids = partition_uuids
        .into_iter()
        .map(std::string::ToString::to_string)
        .collect();
    profile
}

fn storage_profile_with_persistent_device_links(accepted_links: Vec<&str>) -> ServiceProfileV1 {
    let profile = storage_profile_with_requirements(vec!["nvme"], vec!["durable"], vec![], false);
    let mut value = serde_json::to_value(&profile).expect("profile should encode");
    value["profile"]["core_requirements"]["required_paths"][0]
        ["accepted_persistent_device_links"] = serde_json::json!(accepted_links);
    serde_json::from_value(value).expect("profile with persistent device links should decode")
}

fn state_with_storage_health(
    temperature_celsius: i64,
) -> fitctl_core::artifacts::state_v1::HostStateV1 {
    let state = path_state_with_storage_evidence();
    let mut value = serde_json::to_value(&state).expect("state should encode");
    value["state"]["core_state"]["path_resources"]["paths"][0]["storage_health"] = serde_json::json!({
        "health_state": observed_json("ok"),
        "temperature_celsius": observed_json(temperature_celsius),
        "percentage_used": observed_json(3),
        "available_spare_percent": observed_json(100),
        "source": "test-health-source:/dev/nvme0n1",
        "probe_method": "synthetic",
        "observed_at": common::FIXED_TIMESTAMP
    });
    serde_json::from_value(value).expect("state with storage health should decode")
}

fn storage_profile_with_requirements(
    media_classes: Vec<&str>,
    durability_classes: Vec<&str>,
    filesystem_types: Vec<&str>,
    require_link_probe: bool,
) -> ServiceProfileV1 {
    let mut profile: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(common::repo_service_profile_path(
            "local_image_generation_storage_state_required.v2.json",
        ))
        .expect("profile should read"),
    )
    .expect("profile should decode");
    let path_requirement = &mut profile["profile"]["core_requirements"]["required_paths"][0];
    path_requirement["accepted_media_classes"] = serde_json::json!(media_classes);
    path_requirement["accepted_durability_classes"] = serde_json::json!(durability_classes);
    path_requirement["required_filesystem_types"] = serde_json::json!(filesystem_types);
    if require_link_probe {
        path_requirement["require_hardlink"] = serde_json::json!(true);
    }
    serde_json::from_value(profile).expect("profile should decode")
}

fn observed<T>(value: T) -> StateFieldV1<T> {
    StateFieldV1 {
        state: ObservationStateV1::Observed,
        limitation_reason: None,
        value: Some(value),
    }
}

fn observed_json<T: serde::Serialize>(value: T) -> serde_json::Value {
    serde_json::json!({
        "state": "observed",
        "value": value
    })
}

fn unknown_json() -> serde_json::Value {
    serde_json::json!({
        "state": "unknown",
        "value": null
    })
}

#[allow(dead_code)]
fn observed_links() -> HostStatePathLinkCapabilitiesV1 {
    HostStatePathLinkCapabilitiesV1 {
        cleanup: None,
        hardlink_supported: observed(true),
        reflink_supported: observed(false),
        symlink_supported: observed(true),
        copy_possible: observed(true),
        probe_method: Some("test".to_string()),
        probe_error: None,
        probe_root: Some("/var/lib/local-model-cache/.probe".to_string()),
        observed_at: Some(common::FIXED_TIMESTAMP.to_string()),
    }
}
