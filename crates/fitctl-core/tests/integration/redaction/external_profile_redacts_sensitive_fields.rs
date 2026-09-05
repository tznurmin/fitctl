// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common;
use fitctl_core::artifacts::record_v1::ArtifactRecordV1;
use fitctl_core::artifacts::service_profile_v1::ServiceProfileV1;
use fitctl_core::artifacts::validation_report_v1::{
    ValidationModeV1, ValidationPathDiagnosticStatusV1, ValidationPathDiagnosticV1,
};
use fitctl_core::redact::{redact_artifact_v1, BuiltInRedactionProfileV1, RedactionRequestV1};
use std::collections::BTreeMap;

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

#[test]
fn external_profile_redacts_validation_path_diagnostics() {
    let mut report = common::validate_with_profile(
        common::derive_contract_from_fixture("linux-gpu-workstation-like-v1"),
        common::load_service_profile_file("general_compute_no_gpu_contract_only.v2.json"),
        None,
        ValidationModeV1::ContractOnly,
        None,
    );
    report
        .report
        .path_diagnostics
        .push(ValidationPathDiagnosticV1 {
            diagnostic_id: "path_relationship:model-cache-not-output:filesystem_uuid".to_string(),
            requirement_key: "core_requirements.path_relationships[model-cache-not-output]"
                .to_string(),
            path_ids: vec!["model-cache".to_string(), "output".to_string()],
            check_id: "filesystem_uuid".to_string(),
            status: ValidationPathDiagnosticStatusV1::Failed,
            reason_code: "path_relationship_not_separated".to_string(),
            expected: BTreeMap::from([(
                "must_not_share".to_string(),
                "filesystem_uuid".to_string(),
            )]),
            observed: BTreeMap::from([
                (
                    "left".to_string(),
                    "11111111-2222-3333-4444-555555555555".to_string(),
                ),
                (
                    "right".to_string(),
                    "11111111-2222-3333-4444-555555555555".to_string(),
                ),
            ]),
            evidence_refs: vec!["$.state.core_state.path_resources.paths[]".to_string()],
        });

    let artifact = redact_artifact_v1(RedactionRequestV1 {
        artifact: ArtifactRecordV1::ValidationReport(report),
        profile: BuiltInRedactionProfileV1::External,
        redacted_at: common::FIXED_TIMESTAMP.to_string(),
    })
    .expect("external validation-report redaction should succeed");

    let ArtifactRecordV1::ValidationReport(redacted) = artifact else {
        panic!("expected validation-report artifact");
    };

    let rendered = serde_json::to_string(&redacted).expect("redacted report should encode");
    assert!(!rendered.contains("11111111-2222-3333-4444-555555555555"));
    assert_eq!(
        redacted.report.path_diagnostics[0]
            .observed
            .get("left")
            .map(String::as_str),
        Some("redacted:external:storage_identity:0")
    );
    assert_eq!(
        redacted.report.path_diagnostics[0]
            .expected
            .get("must_not_share")
            .map(String::as_str),
        Some("redacted:external:storage_identity:0")
    );
}

#[test]
fn external_profile_redacts_service_profile_persistent_device_links() {
    let profile = service_profile_with_persistent_device_link_requirement();
    let artifact = redact_artifact_v1(RedactionRequestV1 {
        artifact: ArtifactRecordV1::ServiceProfile(profile),
        profile: BuiltInRedactionProfileV1::External,
        redacted_at: common::FIXED_TIMESTAMP.to_string(),
    })
    .expect("external service profile redaction should succeed");

    let ArtifactRecordV1::ServiceProfile(redacted) = artifact else {
        panic!("expected service-profile artifact");
    };

    let rendered = serde_json::to_string(&redacted).expect("redacted profile should encode");
    assert!(!rendered.contains("/dev/disk/by-id/nvme-sensitive-serial"));
    let redacted_json = serde_json::to_value(&redacted).expect("redacted profile should encode");
    assert_eq!(
        redacted_json["profile"]["core_requirements"]["required_paths"][0]
            ["accepted_persistent_device_links"][0],
        "redacted:external:storage_identity:0"
    );
}

#[test]
fn external_profile_redacts_storage_health_source_identity() {
    let mut state =
        common::collect_state_fixture("linux-gpu-workstation-like-path-resources-fit-v1");
    let mut value = serde_json::to_value(&state).expect("state should encode");
    value["state"]["core_state"]["path_resources"]["paths"][0]["storage_health"] = serde_json::json!({
        "health_state": { "state": "unknown", "value": null },
        "temperature_celsius": { "state": "unknown", "value": null },
        "percentage_used": { "state": "unknown", "value": null },
        "available_spare_percent": { "state": "unknown", "value": null },
        "source": "sysfs:/sys/class/block/nvme0n1/device/hwmon/hwmon0",
        "probe_method": "synthetic",
        "probe_error": "permission denied on /dev/nvme0",
        "observed_at": common::FIXED_TIMESTAMP
    });
    state = serde_json::from_value(value).expect("state with storage health should decode");

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
    assert!(!rendered.contains("nvme0n1"));
    assert!(!rendered.contains("/dev/nvme0"));
    assert!(rendered.contains("redacted:external:storage_health_source:0"));
    assert!(rendered.contains("redacted:probe_error"));
}

#[test]
fn external_profile_redacts_reliability_provider_diagnostics_and_gpu_uuid() {
    let mut state = common::collect_state_fixture("linux-gpu-workstation-like-fresh-v1");
    let mut value = serde_json::to_value(&state).expect("state should encode");
    value["state"]["core_state"]["memory_reliability"] = serde_json::json!({
        "observed_at": common::FIXED_TIMESTAMP,
        "providers": [
            {
                "provider_id": "local-edac-sysfs",
                "provider_kind": "edac_sysfs",
                "outcome": "partial",
                "observed_at": common::FIXED_TIMESTAMP,
                "source": "/sys/devices/system/edac/mc",
                "error_code": "edac_sysfs_partial",
                "diagnostics": "permission denied on /sys/devices/system/edac/mc/mc0"
            }
        ],
        "controller_count": { "state": "observed", "value": 1 },
        "dimm_count": { "state": "observed", "value": 8 },
        "corrected_error_count": { "state": "observed", "value": 2 },
        "uncorrected_error_count": { "state": "observed", "value": 0 }
    });
    value["state"]["core_state"]["gpu_reliability"] = serde_json::json!({
        "observed_at": common::FIXED_TIMESTAMP,
        "providers": [
            {
                "provider_id": "local-nvidia-smi-reliability",
                "provider_kind": "nvidia_smi_xml",
                "outcome": "success",
                "observed_at": common::FIXED_TIMESTAMP,
                "diagnostics": "NVIDIA raw diagnostic"
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
    state = serde_json::from_value(value).expect("state with reliability evidence should decode");

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
    assert!(!rendered.contains("/sys/devices/system/edac"));
    assert!(!rendered.contains("permission denied"));
    assert!(!rendered.contains("GPU-secret-uuid"));
    assert!(!rendered.contains("NVIDIA raw diagnostic"));
    assert!(rendered.contains("redacted:memory_reliability_source"));
    assert!(rendered.contains("redacted:external:storage_identity:0"));
}

fn service_profile_with_persistent_device_link_requirement() -> ServiceProfileV1 {
    let mut profile: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(common::repo_service_profile_path(
            "local_image_generation_storage_state_required.v2.json",
        ))
        .expect("profile should read"),
    )
    .expect("profile should decode");
    profile["profile"]["core_requirements"]["required_paths"][0]
        ["accepted_persistent_device_links"] =
        serde_json::json!(["/dev/disk/by-id/nvme-sensitive-serial"]);
    serde_json::from_value(profile).expect("profile with persistent link should decode")
}
