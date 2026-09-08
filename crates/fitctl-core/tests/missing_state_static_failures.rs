// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

#[path = "support/common.rs"]
mod common;

use fitctl_core::artifacts::semantic_hash_v1::semantic_hash_hex_for_batch_classification_report;
use fitctl_core::artifacts::service_profile_v1::AssurancePredicateV1;
use fitctl_core::artifacts::state_v1::FreshnessStateV1;
use fitctl_core::artifacts::thermal_evidence_v1::ThermalEvidenceV1;
use fitctl_core::artifacts::validation_v1::{
    validate_batch_classification_report, validate_validation_report,
};
use fitctl_core::classify::{classify_batch_v1, BatchClassificationRequestV1};
use fitctl_core::survey::VisibilityScopeV1;
use fitctl_core::validate::{
    validate_request_v1, ValidationModeV1 as Mode, ValidationReasonCodeV1 as Reason,
    ValidationReportV1, ValidationRequestV1, ValidationVerdictV1 as Verdict,
};

const CASES: [(&str, Verdict, Reason); 7] = [
    ("scope", Verdict::Unfit, Reason::RequirementUnsatisfied),
    (
        "unknown_scope",
        Verdict::Indeterminate,
        Reason::EvidenceIncomplete,
    ),
    ("capability", Verdict::Unfit, Reason::CapabilityUnknown),
    ("excluded", Verdict::Unfit, Reason::RequirementUnsatisfied),
    ("static_floor", Verdict::Unfit, Reason::TopologyMismatch),
    (
        "assurance",
        Verdict::Indeterminate,
        Reason::AssurancePredicateUnresolved,
    ),
    (
        "degraded",
        Verdict::FitWithDegradation,
        Reason::DegradationPathRequired,
    ),
];

fn input(case: &str, runtime: bool, mode: Mode) -> ValidationRequestV1 {
    let mut contract = common::derive_contract_from_fixture("linux-bare-metal-like-v1");
    let mut profile = common::load_service_profile_file(if case == "degraded" {
        "gpu_preferred_with_general_compute_fallback_contract_only.v2.json"
    } else {
        "general_compute_contract_only.v2.json"
    });
    match case {
        "scope" => {
            profile.profile.core_requirements.allowed_visibility_scopes =
                vec![VisibilityScopeV1::VmLike]
        }
        "unknown_scope" => {
            let mut payload = common::decode_contract_payload(&contract);
            payload.core_contract.execution_constraints.visibility_scope =
                VisibilityScopeV1::Unknown;
            contract.contract = serde_json::to_value(payload).unwrap();
        }
        "capability" => {
            profile.profile.core_requirements.primary_capability_class =
                "absent_fixture_capability".into()
        }
        "excluded" => {
            profile.profile.exclusions.forbidden_capability_classes = vec!["general_compute".into()]
        }
        "static_floor" => profile.profile.core_requirements.min_cpu_packages = Some(100),
        "assurance" => {
            profile.profile.assurance_predicates =
                vec![AssurancePredicateV1::LocallyVerifiedRequired]
        }
        "degraded" => {}
        _ => panic!("unknown fixture case"),
    }
    if runtime {
        profile
            .profile
            .core_requirements
            .min_allocatable_cpu_logical_cores = Some(1);
    }
    profile.envelope.artifact_id = format!("profile-{case}-{runtime}");
    profile.profile.profile_id = format!("profile-{case}-{runtime}");
    ValidationRequestV1 {
        contract,
        service_profile: profile,
        host_state: None,
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

fn single(request: ValidationRequestV1) -> ValidationReportV1 {
    let report = validate_request_v1(request).expect("valid input must emit a typed decision");
    validate_validation_report(&report).unwrap();
    report
}

fn thermal_evidence() -> ThermalEvidenceV1 {
    serde_json::from_str(include_str!(
        "../../../fixtures/conformance/valid/thermal-evidence.out-of-band-bmc.v1.json"
    ))
    .unwrap()
}

#[test]
fn early_static_results_without_evidence_are_valid_missing_state_decisions() {
    for (case, _, _) in CASES {
        let static_report = single(input(case, false, Mode::ContractOnly));
        for runtime in [false, true] {
            for mode in [Mode::StateAdvisory, Mode::StateRequired] {
                let request = input(case, runtime, mode);
                let report = single(request.clone());
                assert_eq!(report.report.verdict, Verdict::Indeterminate, "{case}");
                assert_eq!(
                    report.report.primary_reason_code,
                    Reason::StateMissing,
                    "{case}"
                );
                assert!(report.report.selected_degradation_tier.is_none());
                let basis = &report.validation_basis;
                assert!(basis.state_artifact_id.is_none());
                assert!(basis.state_semantic_hash.is_none());
                assert!(basis.state_observed_at.is_none());
                assert!(basis.state_freshness_state.is_none());
                assert!(basis.thermal_evidence_artifact_ids.is_empty());
                assert!(basis.thermal_evidence_semantic_hashes.is_empty());
                // Runtime missing-state diagnostics already have their own established shape.
                if !runtime || case != "degraded" {
                    assert_eq!(
                        report.report.matched_requirements,
                        static_report.report.matched_requirements
                    );
                    assert_eq!(
                        report.report.failed_requirements,
                        static_report.report.failed_requirements
                    );
                    assert_eq!(
                        report.report.evidence_refs,
                        static_report.report.evidence_refs
                    );
                    assert_eq!(report.report.policy_refs, static_report.report.policy_refs);
                    assert_eq!(
                        report.report.assurance_mismatches,
                        static_report.report.assurance_mismatches
                    );
                    assert!(report
                        .report
                        .warnings
                        .contains(&static_report.report.summary));
                }
                let classified =
                    classify_batch_v1(batch(&request)).expect("retain the missing-state row");
                validate_batch_classification_report(&classified).unwrap();
                assert_eq!(classified.report.rows.len(), 1);
                assert_eq!(classified.report.rows[0].verdict, report.report.verdict);
                assert_eq!(
                    classified.report.rows[0].primary_reason_code,
                    report.report.primary_reason_code
                );
                assert_eq!(classified.report.rows[0].summary, report.report.summary);
                let mut invalid = report.clone();
                invalid.report.primary_reason_code = Reason::RequirementUnsatisfied;
                assert!(validate_validation_report(&invalid).is_err());
            }
        }
    }
}

#[test]
fn supplied_state_and_contract_only_preserve_static_decisions() {
    for (case, verdict, reason) in CASES {
        let report = single(input(case, false, Mode::ContractOnly));
        assert_eq!(
            (report.report.verdict, report.report.primary_reason_code),
            (verdict, reason),
            "{case}"
        );
        for runtime in [false, true] {
            for mode in [Mode::StateAdvisory, Mode::StateRequired] {
                for stale in [false, true] {
                    let mut request = input(case, runtime, mode);
                    let mut state = common::collect_state_fixture("linux-bare-metal-like-fresh-v1");
                    if stale {
                        state.state.core_state.freshness.freshness_state = FreshnessStateV1::Stale;
                    }
                    request.host_state = Some(state);
                    let actual = single(request);
                    let expected = if case == "degraded" && runtime && stale {
                        (Verdict::Indeterminate, Reason::StateStale)
                    } else {
                        (verdict, reason)
                    };
                    assert_eq!(
                        (actual.report.verdict, actual.report.primary_reason_code),
                        expected,
                        "{case}"
                    );
                    assert!(actual.validation_basis.state_artifact_id.is_some());
                    assert!(actual.validation_basis.state_observed_at.is_some());
                }
            }
        }
    }
}

#[test]
fn mixed_static_outcomes_remain_complete_deterministic_batch_rows() {
    for mode in [Mode::StateAdvisory, Mode::StateRequired] {
        let mut request = batch(&input("scope", false, mode));
        request.service_profiles = CASES
            .iter()
            .filter(|(case, _, _)| *case != "unknown_scope")
            .flat_map(|(case, _, _)| {
                [false, true].map(|runtime| input(case, runtime, mode).service_profile)
            })
            .collect();
        let report =
            classify_batch_v1(request.clone()).expect("incompatible cells must not abort a batch");
        validate_batch_classification_report(&report).unwrap();
        assert_eq!(report.report.rows.len(), 12);
        assert!(report
            .report
            .rows
            .iter()
            .all(|row| row.verdict == Verdict::Indeterminate
                && row.primary_reason_code == Reason::StateMissing));
        let repeated = classify_batch_v1(request).unwrap();
        assert_eq!(
            serde_json::to_value(&report).unwrap(),
            serde_json::to_value(&repeated).unwrap()
        );
        assert_eq!(
            semantic_hash_hex_for_batch_classification_report(&report).unwrap(),
            semantic_hash_hex_for_batch_classification_report(&repeated).unwrap()
        );
    }
}

#[test]
fn standalone_thermal_basis_preserves_static_decisions() {
    for (case, verdict, reason) in CASES {
        for mode in [Mode::StateAdvisory, Mode::StateRequired] {
            let mut request = input(case, false, mode);
            let evidence = thermal_evidence();
            let expected_id = evidence.envelope.artifact_id.clone();
            request.thermal_evidence.push(evidence);
            let report = single(request);
            assert_eq!(
                (report.report.verdict, report.report.primary_reason_code),
                (verdict, reason)
            );
            assert!(report.validation_basis.state_artifact_id.is_none());
            assert_eq!(
                report.validation_basis.thermal_evidence_artifact_ids,
                vec![expected_id]
            );
            assert_eq!(
                report
                    .validation_basis
                    .thermal_evidence_semantic_hashes
                    .len(),
                1
            );
        }
    }
}

#[test]
fn missing_evidence_does_not_hide_invalid_input_errors() {
    for mode in [Mode::StateAdvisory, Mode::StateRequired] {
        for kind in ["age", "contract", "profile", "state", "identity", "thermal"] {
            let mut request = input("scope", false, mode);
            let checkpoint = match kind {
                "age" => {
                    request.max_state_age_seconds = Some(60);
                    "validation_state_input"
                }
                "contract" => {
                    request.contract.envelope.schema_version = 99;
                    "contract_load"
                }
                "profile" => {
                    request.service_profile.envelope.schema_version = 99;
                    "service_profile_load"
                }
                "state" | "identity" => {
                    let mut state = common::collect_state_fixture("linux-bare-metal-like-fresh-v1");
                    let checkpoint = if kind == "state" {
                        state.envelope.schema_version = 99;
                        "state_load"
                    } else {
                        state.state.local_identity = None;
                        state.state.host_alias = "different-host".into();
                        "validation_state_identity"
                    };
                    request.host_state = Some(state);
                    checkpoint
                }
                _ => {
                    let mut evidence = thermal_evidence();
                    evidence.envelope.schema_version = 99;
                    request.thermal_evidence.push(evidence);
                    "thermal_evidence_load"
                }
            };
            let error = validate_request_v1(request).unwrap_err();
            assert_eq!(error.error_model_id, "fitctl.validate.v1");
            assert_eq!(error.checkpoint_id, checkpoint, "{kind}: {error:?}");
            assert_eq!(
                error.code.as_str(),
                match kind {
                    "contract" => "contract_artifact_invalid",
                    "profile" => "service_profile_artifact_invalid",
                    "state" => "state_artifact_invalid",
                    "thermal" => "thermal_evidence_artifact_invalid",
                    _ => "validation_input_invalid",
                }
            );
        }
    }
}
