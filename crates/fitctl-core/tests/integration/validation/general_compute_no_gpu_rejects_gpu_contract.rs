// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common;
use fitctl_core::artifacts::validation_report_v1::{ValidationReasonCodeV1, ValidationVerdictV1};
use fitctl_core::validate::ValidationModeV1;

#[test]
fn general_compute_no_gpu_rejects_gpu_contract() {
    let contract = common::derive_contract_from_fixture_with_policy(
        "linux-gpu-dual-numa-like-v1",
        "gpu_compute_default.v1.json",
    );
    let report = common::validate_with_profile(
        contract,
        common::load_service_profile_file("general_compute_no_gpu_contract_only.v2.json"),
        None,
        ValidationModeV1::ContractOnly,
        None,
    );

    assert_eq!(report.report.verdict, ValidationVerdictV1::Unfit);
    assert_eq!(
        report.report.primary_reason_code,
        ValidationReasonCodeV1::RequirementUnsatisfied
    );
    assert_eq!(
        report.report.failed_requirements,
        vec!["exclusions.forbidden_capability_classes".to_string()]
    );
    assert!(report.report.summary.contains("gpu_accelerated"));
}
