// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common;
use fitctl_core::artifacts::validation_report_v1::{
    ValidationModeV1, ValidationReasonCodeV1, ValidationVerdictV1,
};
use fitctl_core::artifacts::validation_v1::validate_service_profile;
use fitctl_core::thermal_profile::{
    init_thermal_profile_v1, ThermalProfileInitRequestV1, ThermalProfileInitSourceV1,
};

#[test]
fn thermal_requirement_by_alias_can_fit() {
    let contract = common::derive_contract_from_fixture("linux-gpu-workstation-like-v1");
    let state = state_with_thermal_reading(41_000, "success");
    let profile = thermal_profile("target_inlet", 45_000);

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
        .contains(&"core_requirements.required_thermal_sensors[inlet-safe]".to_string()));
}

#[test]
fn thermal_temperature_above_limit_is_unfit() {
    let contract = common::derive_contract_from_fixture("linux-gpu-workstation-like-v1");
    let state = state_with_thermal_reading(52_000, "success");
    let profile = thermal_profile("target_inlet", 45_000);

    let report = common::validate_with_profile(
        contract,
        profile,
        Some(state),
        ValidationModeV1::StateRequired,
        None,
    );

    assert_eq!(report.report.verdict, ValidationVerdictV1::Unfit);
    assert_eq!(
        report.report.primary_reason_code,
        ValidationReasonCodeV1::RequirementUnsatisfied
    );
    assert!(report
        .report
        .failed_requirements
        .contains(&"core_requirements.required_thermal_sensors[inlet-safe]".to_string()));
}

#[test]
fn missing_required_thermal_sensor_is_indeterminate() {
    let contract = common::derive_contract_from_fixture("linux-gpu-workstation-like-v1");
    let state = state_with_thermal_reading(41_000, "success");
    let profile = thermal_profile("missing_alias", 45_000);

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
        ValidationReasonCodeV1::EvidenceIncomplete
    );
}

#[test]
fn non_success_provider_blocks_required_thermal_evidence() {
    let contract = common::derive_contract_from_fixture("linux-gpu-workstation-like-v1");
    let state = state_with_thermal_reading(41_000, "partial");
    let profile = thermal_profile("target_inlet", 45_000);

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
        ValidationReasonCodeV1::EvidenceIncomplete
    );
}

#[test]
fn thermal_evidence_target_mismatch_is_indeterminate() {
    let contract = common::derive_contract_from_fixture("linux-gpu-workstation-like-v1");
    let state = state_with_thermal_reading_for_target(41_000, "success", "host.collector-01");
    let profile = thermal_profile("target_inlet", 45_000);

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
        ValidationReasonCodeV1::EvidenceIncomplete
    );
    assert!(report.report.summary.contains("target does not match"));
}

#[test]
fn contract_only_with_thermal_requirement_requires_state() {
    let contract = common::derive_contract_from_fixture("linux-gpu-workstation-like-v1");
    let profile = thermal_profile("target_inlet", 45_000);

    let report = common::validate_with_profile(
        contract,
        profile,
        None,
        ValidationModeV1::ContractOnly,
        None,
    );

    assert_eq!(report.report.verdict, ValidationVerdictV1::Indeterminate);
    assert_eq!(
        report.report.primary_reason_code,
        ValidationReasonCodeV1::StateMissing
    );
    assert!(report
        .report
        .failed_requirements
        .contains(&"core_requirements.required_thermal_sensors[inlet-safe]".to_string()));
}

#[test]
fn thermal_profile_init_generates_reviewable_requirements_from_state() {
    let state = state_with_thermal_reading(41_000, "success");

    let profile = init_thermal_profile_v1(ThermalProfileInitRequestV1 {
        source: ThermalProfileInitSourceV1::State(Box::new(state)),
        profile_id: "thermal_safe_v1".to_string(),
        display_name: Some("Thermal safe".to_string()),
        short_display_name: Some("Thermal".to_string()),
        primary_capability_class: "general_compute".to_string(),
        margin_millidegrees_celsius: 10_000,
    })
    .expect("thermal profile should initialize from state");

    validate_service_profile(&profile).expect("generated profile should validate");
    let encoded = serde_json::to_value(&profile).expect("generated profile should encode");
    let core_requirements = encoded["profile"]["core_requirements"]
        .as_object()
        .expect("core requirements should encode as an object");
    assert!(
        !core_requirements.contains_key("min_allocatable_cpu_logical_cores"),
        "generated profile should omit absent optional requirements instead of serializing null"
    );
    let requirement = &profile.profile.core_requirements.required_thermal_sensors[0];
    assert_eq!(requirement.requirement_id, "target-inlet");
    assert_eq!(requirement.provider_id.as_deref(), Some("site-bmc-thermal"));
    assert_eq!(requirement.sensor_alias.as_deref(), Some("target_inlet"));
    assert_eq!(requirement.max_temperature_millidegrees_celsius, 51_000);
    assert!(requirement.require_provider_success);
}

#[test]
fn conformance_thermal_state_and_profile_roundtrip_to_fit() {
    let contract = common::derive_contract_from_fixture("linux-gpu-workstation-like-v1");
    let state_path =
        common::repo_root().join("fixtures/conformance/valid/host-state.thermal-resources.v2.json");
    let profile_path = common::repo_root()
        .join("fixtures/conformance/valid/service-profile.thermal-requirements.v2.json");
    let mut state_value: serde_json::Value = serde_json::from_slice(
        &std::fs::read(state_path).expect("thermal state fixture should read"),
    )
    .expect("thermal state fixture should decode");
    state_value["state"]["host_alias"] = serde_json::json!("gpu-host-01");
    state_value["state"]["core_state"]["thermal_resources"]["providers"][0]["evidence_target"]
        ["host_id"] = serde_json::json!("host.gpu-host-01");
    state_value["state"]["core_state"]["thermal_resources"]["readings"][0]["evidence_target"]
        ["host_id"] = serde_json::json!("host.gpu-host-01");
    state_value["state"]["core_state"]["thermal_resources"]["readings"][1]["evidence_target"]
        ["host_id"] = serde_json::json!("host.gpu-host-01");
    let state = serde_json::from_value(state_value).expect("thermal state fixture should decode");
    let profile = serde_json::from_slice(
        &std::fs::read(profile_path).expect("thermal profile fixture should read"),
    )
    .expect("thermal profile fixture should decode");

    let report = common::validate_with_profile(
        contract,
        profile,
        Some(state),
        ValidationModeV1::StateRequired,
        None,
    );

    assert_eq!(report.report.verdict, ValidationVerdictV1::Fit);
    assert!(report.report.failed_requirements.is_empty());
    assert!(report
        .report
        .matched_requirements
        .contains(&"core_requirements.required_thermal_sensors[target-inlet]".to_string()));
}

fn thermal_profile(
    sensor_alias: &str,
    max_temperature_millidegrees_celsius: i64,
) -> fitctl_core::artifacts::service_profile_v1::ServiceProfileV1 {
    let profile = common::load_service_profile_file("general_compute_contract_only.v2.json");
    let mut value = serde_json::to_value(profile).expect("profile should encode");
    value["profile"]["core_requirements"]["required_thermal_sensors"] = serde_json::json!([
        {
            "requirement_id": "inlet-safe",
            "provider_id": "site-bmc-thermal",
            "sensor_alias": sensor_alias,
            "max_temperature_millidegrees_celsius": max_temperature_millidegrees_celsius,
            "require_provider_success": true
        }
    ]);
    serde_json::from_value(value).expect("thermal profile should decode")
}

fn state_with_thermal_reading(
    temperature_millidegrees_celsius: i64,
    provider_outcome: &str,
) -> fitctl_core::artifacts::state_v1::HostStateV1 {
    state_with_thermal_reading_for_target(
        temperature_millidegrees_celsius,
        provider_outcome,
        "host.gpu-host-01",
    )
}

fn state_with_thermal_reading_for_target(
    temperature_millidegrees_celsius: i64,
    provider_outcome: &str,
    target_host_id: &str,
) -> fitctl_core::artifacts::state_v1::HostStateV1 {
    let state = common::collect_state_fixture("linux-gpu-workstation-like-fresh-v1");
    let mut value = serde_json::to_value(state).expect("state should encode");
    value["state"]["core_state"]["thermal_resources"] = serde_json::json!({
        "observed_at": common::FIXED_TIMESTAMP,
        "collector_host": {
            "host_alias": "collector-host"
        },
        "providers": [
            {
                "provider_id": "site-bmc-thermal",
                "provider_kind": "ipmitool_sensor",
                "outcome": provider_outcome,
                "evidence_target": {
                    "target_kind": "host_id",
                    "host_id": target_host_id,
                    "collection_path": "out_of_band_bmc"
                },
                "observed_at": common::FIXED_TIMESTAMP
            }
        ],
        "readings": [
            {
                "sensor_id": "site-bmc-thermal:inlet-temp",
                "sensor_role": "inlet",
                "sensor_alias": "target_inlet",
                "provider_id": "site-bmc-thermal",
                "raw_label": "Inlet Temp",
                "temperature_millidegrees_celsius": temperature_millidegrees_celsius,
                "status": "ok",
                "observed_at": common::FIXED_TIMESTAMP,
                "evidence_target": {
                    "target_kind": "host_id",
                    "host_id": target_host_id,
                    "collection_path": "out_of_band_bmc"
                },
                "source": "ipmitool_sensor"
            }
        ]
    });
    serde_json::from_value(value).expect("thermal state should decode")
}
