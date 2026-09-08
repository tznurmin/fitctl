// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

#[path = "support/common.rs"]
mod common;

use fitctl_core::artifacts::semantic_hash_v1::semantic_hash_hex_for_batch_classification_report;
use fitctl_core::artifacts::state_v1::{FreshnessStateV1, HostStateV1, StateFieldV1};
use fitctl_core::artifacts::validation_v1::{
    validate_batch_classification_report, validate_validation_report,
};
use fitctl_core::classify::{classify_batch_v1, BatchClassificationRequestV1};
use fitctl_core::validate::{
    validate_request_v1, ValidationModeV1, ValidationReasonCodeV1, ValidationRequestV1,
    ValidationVerdictV1,
};

fn request(
    runtime: bool,
    state: Option<HostStateV1>,
    mode: ValidationModeV1,
) -> ValidationRequestV1 {
    ValidationRequestV1 {
        contract: common::derive_contract_from_fixture("linux-bare-metal-like-v1"),
        service_profile: common::load_service_profile_file(if runtime {
            "general_compute_stateful_thresholds.v2.json"
        } else {
            "general_compute_contract_only.v2.json"
        }),
        host_state: state,
        thermal_evidence: vec![],
        mode,
        validated_at: common::FIXED_TIMESTAMP.into(),
        notes: None,
        max_state_age_seconds: None,
    }
}

fn batch(request: &ValidationRequestV1) -> BatchClassificationRequestV1 {
    BatchClassificationRequestV1 {
        contracts: vec![request.contract.clone()],
        service_profiles: vec![request.service_profile.clone()],
        host_states: request.host_state.iter().cloned().collect(),
        validation_mode: request.mode,
        max_state_age_seconds: request.max_state_age_seconds,
        validated_at: request.validated_at.clone(),
    }
}

fn check_parity(
    request: ValidationRequestV1,
    verdict: ValidationVerdictV1,
    reason: ValidationReasonCodeV1,
) {
    let single = validate_request_v1(request.clone()).expect("valid inputs must emit a report");
    validate_validation_report(&single).unwrap();
    assert_eq!(single.report.verdict, verdict);
    assert_eq!(single.report.primary_reason_code, reason);
    assert_eq!(
        single.validation_basis.state_artifact_id.is_some(),
        request.host_state.is_some()
    );
    assert_eq!(
        single.validation_basis.state_semantic_hash.is_some(),
        request.host_state.is_some()
    );
    assert_eq!(
        single.validation_basis.state_observed_at.is_some(),
        request.host_state.is_some()
    );
    assert_eq!(
        single.validation_basis.state_freshness_state.is_some(),
        request.host_state.is_some()
    );
    let classified = classify_batch_v1(batch(&request)).expect("missing state is a row outcome");
    validate_batch_classification_report(&classified).unwrap();
    let row = &classified.report.rows[0];
    assert_eq!(row.verdict, verdict);
    assert_eq!(row.primary_reason_code, reason);
    assert_eq!(row.summary, single.report.summary);
    let repeated = classify_batch_v1(batch(&request)).unwrap();
    assert_eq!(
        serde_json::to_value(&classified).unwrap(),
        serde_json::to_value(&repeated).unwrap()
    );
    assert_eq!(
        semantic_hash_hex_for_batch_classification_report(&classified).unwrap(),
        semantic_hash_hex_for_batch_classification_report(&repeated).unwrap()
    );
}

#[test]
fn missing_static_state_is_a_valid_single_and_batch_outcome() {
    for mode in [
        ValidationModeV1::StateAdvisory,
        ValidationModeV1::StateRequired,
    ] {
        check_parity(
            request(false, None, mode),
            ValidationVerdictV1::Indeterminate,
            ValidationReasonCodeV1::StateMissing,
        );
    }
}

#[test]
fn missing_runtime_state_and_mixed_profiles_remain_rows() {
    for mode in [
        ValidationModeV1::StateAdvisory,
        ValidationModeV1::StateRequired,
    ] {
        let runtime = request(true, None, mode);
        check_parity(
            runtime.clone(),
            ValidationVerdictV1::Indeterminate,
            ValidationReasonCodeV1::StateMissing,
        );
        let mut input = batch(&runtime);
        input
            .service_profiles
            .push(request(false, None, mode).service_profile);
        let report = classify_batch_v1(input).expect("both missing-state rows must be retained");
        assert_eq!(report.report.rows.len(), 2);
        assert!(report
            .report
            .rows
            .iter()
            .all(|row| row.primary_reason_code == ValidationReasonCodeV1::StateMissing));
    }
}

#[test]
fn supplied_state_and_contract_only_controls_keep_their_decisions() {
    check_parity(
        request(false, None, ValidationModeV1::ContractOnly),
        ValidationVerdictV1::Fit,
        ValidationReasonCodeV1::RequirementsSatisfied,
    );
    for runtime in [false, true] {
        for mode in [
            ValidationModeV1::StateAdvisory,
            ValidationModeV1::StateRequired,
        ] {
            for quality in ["fresh", "stale", "unknown"] {
                let mut state = common::collect_state_fixture("linux-bare-metal-like-fresh-v1");
                let (verdict, reason) = if runtime && quality != "fresh" {
                    (
                        ValidationVerdictV1::Indeterminate,
                        if quality == "stale" {
                            ValidationReasonCodeV1::StateStale
                        } else {
                            ValidationReasonCodeV1::StateMissing
                        },
                    )
                } else {
                    (
                        ValidationVerdictV1::Fit,
                        ValidationReasonCodeV1::RequirementsSatisfied,
                    )
                };
                if quality == "stale" {
                    state.state.core_state.freshness.freshness_state = FreshnessStateV1::Stale;
                }
                if quality == "unknown" {
                    state
                        .state
                        .core_state
                        .resources
                        .allocatable_cpu_logical_cores = StateFieldV1::default();
                }
                check_parity(request(runtime, Some(state), mode), verdict, reason);
            }
        }
    }
}

#[test]
fn invalid_or_unmatched_states_are_not_synthesized_into_rows() {
    for kind in ["malformed", "unused", "contract_only"] {
        let mut state = common::collect_state_fixture("linux-bare-metal-like-fresh-v1");
        let mode = if kind == "contract_only" {
            ValidationModeV1::ContractOnly
        } else {
            ValidationModeV1::StateRequired
        };
        if kind == "malformed" {
            state.envelope.schema_version = 99;
        }
        if kind == "unused" {
            state.state.host_alias = "unmatched-host".into();
            state.state.local_identity = None;
        }
        let error = classify_batch_v1(batch(&request(false, Some(state), mode))).unwrap_err();
        assert_eq!(error.error_model_id, "fitctl.batch_classification.v2");
        let (code, checkpoint) = match kind {
            "malformed" => ("batch_execution_failed", "batch_state_select"),
            "unused" => ("batch_input_invalid", "batch_state_map"),
            _ => ("batch_input_invalid", "batch_request_validate"),
        };
        assert_eq!(error.code.as_str(), code, "{kind}: {error:?}");
        assert_eq!(error.checkpoint_id, checkpoint, "{kind}: {error:?}");
    }
}
