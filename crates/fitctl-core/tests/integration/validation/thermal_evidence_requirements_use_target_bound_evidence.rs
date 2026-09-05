// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common;
use crate::target_bound_thermal_evidence::thermal_evidence_artifact;
use fitctl_core::artifacts::semantic_hash_v1::semantic_hash_hex_for_thermal_evidence;
use fitctl_core::artifacts::state_v1::ThermalProviderOutcomeV1;
use fitctl_core::artifacts::validation_report_v1::{
    ValidationModeV1, ValidationReasonCodeV1, ValidationVerdictV1,
};
use fitctl_core::validate::{validate_request_v1, ValidationRequestV1};

#[test]
fn target_bound_thermal_evidence_can_satisfy_target_contract() {
    let contract = common::derive_contract_from_fixture("linux-gpu-workstation-like-v1");
    let profile = thermal_profile("target_inlet", 45_000);
    let thermal_evidence =
        thermal_evidence_artifact(41_000, common::FIXED_TIMESTAMP, "host.gpu-host-01");

    let report = validate_request_v1(ValidationRequestV1 {
        contract,
        service_profile: profile,
        host_state: None,
        thermal_evidence: vec![thermal_evidence],
        mode: ValidationModeV1::StateRequired,
        validated_at: common::FIXED_TIMESTAMP.to_string(),
        notes: Some("integration-test".to_string()),
        max_state_age_seconds: None,
    })
    .expect("validation should emit");

    assert_eq!(report.report.verdict, ValidationVerdictV1::Fit);
    assert!(report
        .report
        .matched_requirements
        .contains(&"core_requirements.required_thermal_sensors[inlet-safe]".to_string()));
}

#[test]
fn validation_report_records_thermal_evidence_basis() {
    let contract = common::derive_contract_from_fixture("linux-gpu-workstation-like-v1");
    let profile = thermal_profile("target_inlet", 45_000);
    let thermal_evidence =
        thermal_evidence_artifact(41_000, common::FIXED_TIMESTAMP, "host.gpu-host-01");
    let expected_id = thermal_evidence.envelope.artifact_id.clone();
    let expected_hash =
        semantic_hash_hex_for_thermal_evidence(&thermal_evidence).expect("semantic hash");

    let report = validate_request_v1(ValidationRequestV1 {
        contract,
        service_profile: profile,
        host_state: None,
        thermal_evidence: vec![thermal_evidence],
        mode: ValidationModeV1::StateRequired,
        validated_at: common::FIXED_TIMESTAMP.to_string(),
        notes: Some("integration-test".to_string()),
        max_state_age_seconds: None,
    })
    .expect("validation should emit");

    assert_eq!(
        report.validation_basis.thermal_evidence_artifact_ids,
        vec![expected_id]
    );
    assert_eq!(
        report.validation_basis.thermal_evidence_semantic_hashes,
        vec![expected_hash]
    );
}

#[test]
fn thermal_evidence_target_mismatch_is_indeterminate() {
    let contract = common::derive_contract_from_fixture("linux-gpu-workstation-like-v1");
    let profile = thermal_profile("target_inlet", 45_000);
    let thermal_evidence =
        thermal_evidence_artifact(41_000, common::FIXED_TIMESTAMP, "host.collector-01");

    let report = validate_request_v1(ValidationRequestV1 {
        contract,
        service_profile: profile,
        host_state: None,
        thermal_evidence: vec![thermal_evidence],
        mode: ValidationModeV1::StateRequired,
        validated_at: common::FIXED_TIMESTAMP.to_string(),
        notes: Some("integration-test".to_string()),
        max_state_age_seconds: None,
    })
    .expect("validation should emit");

    assert_eq!(report.report.verdict, ValidationVerdictV1::Indeterminate);
    assert_eq!(
        report.report.primary_reason_code,
        ValidationReasonCodeV1::EvidenceIncomplete
    );
    assert!(report.report.summary.contains("target does not match"));
}

#[test]
fn partial_thermal_evidence_provider_is_indeterminate() {
    let contract = common::derive_contract_from_fixture("linux-gpu-workstation-like-v1");
    let profile = thermal_profile("target_inlet", 45_000);
    let mut thermal_evidence =
        thermal_evidence_artifact(41_000, common::FIXED_TIMESTAMP, "host.gpu-host-01");
    thermal_evidence.thermal_evidence.providers[0].outcome = ThermalProviderOutcomeV1::Partial;

    let report = validate_request_v1(ValidationRequestV1 {
        contract,
        service_profile: profile,
        host_state: None,
        thermal_evidence: vec![thermal_evidence],
        mode: ValidationModeV1::StateRequired,
        validated_at: common::FIXED_TIMESTAMP.to_string(),
        notes: Some("integration-test".to_string()),
        max_state_age_seconds: None,
    })
    .expect("validation should emit");

    assert_eq!(report.report.verdict, ValidationVerdictV1::Indeterminate);
    assert_eq!(
        report.report.primary_reason_code,
        ValidationReasonCodeV1::EvidenceIncomplete
    );
}

#[test]
fn target_bound_thermal_evidence_threshold_failure_is_unfit() {
    let contract = common::derive_contract_from_fixture("linux-gpu-workstation-like-v1");
    let profile = thermal_profile("target_inlet", 45_000);
    let thermal_evidence =
        thermal_evidence_artifact(52_000, common::FIXED_TIMESTAMP, "host.gpu-host-01");

    let report = validate_request_v1(ValidationRequestV1 {
        contract,
        service_profile: profile,
        host_state: None,
        thermal_evidence: vec![thermal_evidence],
        mode: ValidationModeV1::StateRequired,
        validated_at: common::FIXED_TIMESTAMP.to_string(),
        notes: Some("integration-test".to_string()),
        max_state_age_seconds: None,
    })
    .expect("validation should emit");

    assert_eq!(report.report.verdict, ValidationVerdictV1::Unfit);
    assert_eq!(
        report.report.primary_reason_code,
        ValidationReasonCodeV1::RequirementUnsatisfied
    );
}

#[test]
fn stale_thermal_evidence_is_indeterminate_when_freshness_is_required() {
    let contract = common::derive_contract_from_fixture("linux-gpu-workstation-like-v1");
    let profile = thermal_profile("target_inlet", 45_000);
    let thermal_evidence =
        thermal_evidence_artifact(41_000, "2025-04-21T14:00:00Z", "host.gpu-host-01");

    let report = validate_request_v1(ValidationRequestV1 {
        contract,
        service_profile: profile,
        host_state: None,
        thermal_evidence: vec![thermal_evidence],
        mode: ValidationModeV1::StateRequired,
        validated_at: common::FIXED_TIMESTAMP.to_string(),
        notes: Some("integration-test".to_string()),
        max_state_age_seconds: Some(60),
    })
    .expect("validation should emit");

    assert_eq!(report.report.verdict, ValidationVerdictV1::Indeterminate);
    assert_eq!(
        report.report.primary_reason_code,
        ValidationReasonCodeV1::StateStale
    );
}

#[test]
fn thermal_evidence_does_not_satisfy_non_thermal_runtime_requirements() {
    let contract = common::derive_contract_from_fixture("linux-gpu-workstation-like-v1");
    let mut profile_value =
        serde_json::to_value(thermal_profile("target_inlet", 45_000)).expect("profile encode");
    profile_value["profile"]["core_requirements"]["min_allocatable_cpu_logical_cores"] =
        serde_json::json!(1);
    let profile = serde_json::from_value(profile_value).expect("profile decode");
    let thermal_evidence =
        thermal_evidence_artifact(41_000, common::FIXED_TIMESTAMP, "host.gpu-host-01");

    let report = validate_request_v1(ValidationRequestV1 {
        contract,
        service_profile: profile,
        host_state: None,
        thermal_evidence: vec![thermal_evidence],
        mode: ValidationModeV1::StateRequired,
        validated_at: common::FIXED_TIMESTAMP.to_string(),
        notes: Some("integration-test".to_string()),
        max_state_age_seconds: None,
    })
    .expect("validation should emit");

    assert_eq!(report.report.verdict, ValidationVerdictV1::Indeterminate);
    assert_eq!(
        report.report.primary_reason_code,
        ValidationReasonCodeV1::StateMissing
    );
    assert!(report
        .report
        .failed_requirements
        .contains(&"core_requirements.min_allocatable_cpu_logical_cores".to_string()));
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
