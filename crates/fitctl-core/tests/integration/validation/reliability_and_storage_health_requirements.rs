// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common;

use fitctl_core::artifacts::service_profile_v1::ServiceProfileV1;
use fitctl_core::artifacts::state_v1::HostStateV1;
use fitctl_core::artifacts::validation_report_v1::{
    ValidationModeV1, ValidationReasonCodeV1, ValidationVerdictV1,
};
use fitctl_core::artifacts::validation_v1::validate_service_profile;
use fitctl_core::service_profile::load_service_profile_from_path;

#[test]
fn storage_health_requirement_can_fit() {
    let report = validate(
        storage_health_profile(76, 90, 10),
        state_with_storage_health(41, 3, 100),
    );

    assert_eq!(report.report.verdict, ValidationVerdictV1::Fit);
    assert!(report
        .report
        .matched_requirements
        .contains(&"core_requirements.required_paths[model-cache].storage_health".to_string()));
}

#[test]
fn storage_health_requirement_missing_is_indeterminate() {
    let mut state = state_with_storage_health(41, 3, 100);
    state.state.core_state.path_resources.paths[0].storage_health = None;

    let report = validate(storage_health_profile(76, 90, 10), state);

    assert_eq!(report.report.verdict, ValidationVerdictV1::Indeterminate);
    assert_eq!(
        report.report.primary_reason_code,
        ValidationReasonCodeV1::StateMissing
    );
    assert!(report
        .report
        .failed_requirements
        .contains(&"core_requirements.required_paths[model-cache].storage_health".to_string()));
}

#[test]
fn storage_health_temperature_above_limit_is_unfit() {
    let report = validate(
        storage_health_profile(76, 90, 10),
        state_with_storage_health(77, 3, 100),
    );

    assert_eq!(report.report.verdict, ValidationVerdictV1::Unfit);
    assert_eq!(
        report.report.primary_reason_code,
        ValidationReasonCodeV1::RequirementUnsatisfied
    );
    assert!(report.report.summary.contains("storage health"));
}

#[test]
fn memory_reliability_requirement_can_fit() {
    let report = validate(
        memory_reliability_profile(0, 0),
        state_with_memory_reliability(0, 0, "success"),
    );

    assert_eq!(report.report.verdict, ValidationVerdictV1::Fit);
    assert!(report
        .report
        .matched_requirements
        .contains(&"core_requirements.required_memory_reliability".to_string()));
}

#[test]
fn memory_reliability_missing_is_indeterminate() {
    let report = validate(
        memory_reliability_profile(0, 0),
        common::collect_state_fixture("linux-gpu-workstation-like-fresh-v1"),
    );

    assert_eq!(report.report.verdict, ValidationVerdictV1::Indeterminate);
    assert_eq!(
        report.report.primary_reason_code,
        ValidationReasonCodeV1::StateMissing
    );
}

#[test]
fn memory_reliability_uncorrected_errors_are_unfit() {
    let report = validate(
        memory_reliability_profile(0, 0),
        state_with_memory_reliability(0, 1, "success"),
    );

    assert_eq!(report.report.verdict, ValidationVerdictV1::Unfit);
    assert_eq!(
        report.report.primary_reason_code,
        ValidationReasonCodeV1::RequirementUnsatisfied
    );
}

#[test]
fn gpu_reliability_requirement_can_fit() {
    let report = validate(
        gpu_reliability_profile(0, 0),
        state_with_gpu_reliability(0, 0, "success"),
    );

    assert_eq!(report.report.verdict, ValidationVerdictV1::Fit);
    assert!(report
        .report
        .matched_requirements
        .contains(&"core_requirements.required_gpu_reliability".to_string()));
}

#[test]
fn gpu_reliability_missing_is_indeterminate() {
    let report = validate(
        gpu_reliability_profile(0, 0),
        common::collect_state_fixture("linux-gpu-workstation-like-fresh-v1"),
    );

    assert_eq!(report.report.verdict, ValidationVerdictV1::Indeterminate);
    assert_eq!(
        report.report.primary_reason_code,
        ValidationReasonCodeV1::StateMissing
    );
}

#[test]
fn gpu_reliability_uncorrected_errors_are_unfit() {
    let report = validate(
        gpu_reliability_profile(0, 0),
        state_with_gpu_reliability(0, 1, "success"),
    );

    assert_eq!(report.report.verdict, ValidationVerdictV1::Unfit);
    assert_eq!(
        report.report.primary_reason_code,
        ValidationReasonCodeV1::RequirementUnsatisfied
    );
}

#[test]
fn service_profile_reliability_requirement_schema_rejects_invalid_values() {
    let profile = gpu_reliability_profile(0, 0);
    let mut value = serde_json::to_value(profile).expect("profile should encode");
    value["profile"]["core_requirements"]["required_gpu_reliability"]
        ["max_volatile_uncorrected_ecc_error_count"] = serde_json::json!(-1);
    let root = common::unique_temp_dir("reliability-invalid-profile");
    let path = common::write_temp_service_profile(&root, "profile.json", &value);

    let error = load_service_profile_from_path(&path).expect_err("invalid profile should fail");
    assert!(error.message.contains("required GPU reliability"));
}

#[test]
fn conformance_reliability_storage_health_profile_validates() {
    let path = common::repo_root()
        .join("fixtures/conformance/valid/service-profile.reliability-storage-health-requirements.v2.json");
    let profile = load_service_profile_from_path(&path)
        .expect("reliability storage-health conformance profile should load");

    validate_service_profile(&profile)
        .expect("reliability storage-health conformance profile should validate");
}

fn validate(
    profile: ServiceProfileV1,
    state: HostStateV1,
) -> fitctl_core::artifacts::validation_report_v1::ValidationReportV1 {
    common::validate_with_profile(
        common::derive_contract_from_fixture("linux-gpu-workstation-like-v1"),
        profile,
        Some(state),
        ValidationModeV1::StateRequired,
        None,
    )
}

fn storage_health_profile(
    max_temperature_celsius: i64,
    max_percentage_used: u32,
    min_available_spare_percent: u32,
) -> ServiceProfileV1 {
    let profile = common::load_service_profile_file("general_compute_contract_only.v2.json");
    let mut value = serde_json::to_value(profile).expect("profile should encode");
    value["profile"]["core_requirements"]["required_paths"] = serde_json::json!([
        {
            "path_id": "model-cache",
            "storage_health": {
                "accepted_health_states": ["ok"],
                "max_temperature_celsius": max_temperature_celsius,
                "max_percentage_used": max_percentage_used,
                "min_available_spare_percent": min_available_spare_percent
            }
        }
    ]);
    serde_json::from_value(value).expect("profile should decode")
}

fn memory_reliability_profile(max_corrected: u64, max_uncorrected: u64) -> ServiceProfileV1 {
    let profile = common::load_service_profile_file("general_compute_contract_only.v2.json");
    let mut value = serde_json::to_value(profile).expect("profile should encode");
    value["profile"]["core_requirements"]["required_memory_reliability"] = serde_json::json!({
        "require_provider_success": true,
        "max_corrected_error_count": max_corrected,
        "max_uncorrected_error_count": max_uncorrected
    });
    serde_json::from_value(value).expect("profile should decode")
}

fn gpu_reliability_profile(max_corrected: u64, max_uncorrected: u64) -> ServiceProfileV1 {
    let profile = common::load_service_profile_file("general_compute_contract_only.v2.json");
    let mut value = serde_json::to_value(profile).expect("profile should encode");
    value["profile"]["core_requirements"]["required_gpu_reliability"] = serde_json::json!({
        "require_provider_success": true,
        "require_ecc_mode_current": "Enabled",
        "max_volatile_corrected_ecc_error_count": max_corrected,
        "max_volatile_uncorrected_ecc_error_count": max_uncorrected,
        "require_no_retired_pages_pending": true,
        "require_no_row_remapper_pending": true
    });
    serde_json::from_value(value).expect("profile should decode")
}

fn state_with_storage_health(
    temperature_celsius: i64,
    percentage_used: u32,
    available_spare_percent: u32,
) -> HostStateV1 {
    let mut state =
        common::collect_state_fixture("linux-gpu-workstation-like-path-resources-fit-v1");
    state.state.core_state.path_resources.paths[0].path_id = "model-cache".to_string();
    let mut value = serde_json::to_value(state).expect("state should encode");
    value["state"]["core_state"]["path_resources"]["paths"][0]["storage_health"] = serde_json::json!({
        "health_state": observed_json("ok"),
        "temperature_celsius": observed_json(temperature_celsius),
        "percentage_used": observed_json(percentage_used),
        "available_spare_percent": observed_json(available_spare_percent),
        "source": "test-health-source:/dev/nvme0n1",
        "probe_method": "synthetic",
        "observed_at": common::FIXED_TIMESTAMP
    });
    serde_json::from_value(value).expect("state with storage health should decode")
}

fn state_with_memory_reliability(
    corrected_error_count: u64,
    uncorrected_error_count: u64,
    provider_outcome: &str,
) -> HostStateV1 {
    let mut value = serde_json::to_value(common::collect_state_fixture(
        "linux-gpu-workstation-like-fresh-v1",
    ))
    .expect("state should encode");
    value["state"]["core_state"]["memory_reliability"] = serde_json::json!({
        "observed_at": common::FIXED_TIMESTAMP,
        "providers": [
            {
                "provider_id": "local-edac",
                "provider_kind": "edac_sysfs",
                "outcome": provider_outcome,
                "observed_at": common::FIXED_TIMESTAMP,
                "source": "/sys/devices/system/edac/mc"
            }
        ],
        "controller_count": observed_json(1),
        "dimm_count": observed_json(8),
        "corrected_error_count": observed_json(corrected_error_count),
        "uncorrected_error_count": observed_json(uncorrected_error_count)
    });
    serde_json::from_value(value).expect("state with memory reliability should decode")
}

fn state_with_gpu_reliability(
    corrected_error_count: u64,
    uncorrected_error_count: u64,
    provider_outcome: &str,
) -> HostStateV1 {
    let mut value = serde_json::to_value(common::collect_state_fixture(
        "linux-gpu-workstation-like-fresh-v1",
    ))
    .expect("state should encode");
    value["state"]["core_state"]["gpu_reliability"] = serde_json::json!({
        "observed_at": common::FIXED_TIMESTAMP,
        "providers": [
            {
                "provider_id": "local-nvidia-smi-reliability",
                "provider_kind": "nvidia_smi_xml",
                "outcome": provider_outcome,
                "observed_at": common::FIXED_TIMESTAMP
            }
        ],
        "devices": [
            {
                "gpu_uuid": observed_json("GPU-test"),
                "product_name": observed_json("NVIDIA test GPU"),
                "ecc_mode_current": observed_json("Enabled"),
                "volatile_corrected_ecc_error_count": observed_json(corrected_error_count),
                "volatile_uncorrected_ecc_error_count": observed_json(uncorrected_error_count),
                "retired_pages_pending": observed_json(false),
                "row_remapper_pending": observed_json(false)
            }
        ]
    });
    serde_json::from_value(value).expect("state with GPU reliability should decode")
}

fn observed_json<T: serde::Serialize>(value: T) -> serde_json::Value {
    serde_json::json!({
        "state": "observed",
        "value": value
    })
}
