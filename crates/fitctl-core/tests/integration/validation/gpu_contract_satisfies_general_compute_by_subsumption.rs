// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common;
use fitctl_core::artifacts::validation_report_v1::{ValidationReasonCodeV1, ValidationVerdictV1};
use fitctl_core::validate::ValidationModeV1;

#[test]
fn gpu_contract_satisfies_general_compute_by_subsumption() {
    let contract = common::derive_contract_from_fixture_with_policy(
        "linux-gpu-dual-numa-like-v1",
        "gpu_compute_default.v1.json",
    );
    let report = common::validate_with_profile(
        contract,
        common::load_service_profile_file("general_compute_contract_only.v2.json"),
        None,
        ValidationModeV1::ContractOnly,
        None,
    );

    assert_eq!(report.report.verdict, ValidationVerdictV1::Fit);
    assert_eq!(
        report.report.primary_reason_code,
        ValidationReasonCodeV1::RequirementsSatisfied
    );
    assert!(report.report.summary.contains("via gpu_accelerated"));
}
