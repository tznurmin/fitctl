// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use fitctl_core::artifacts::validation_report_v1::{
    ValidationModeV1, ValidationReasonCodeV1, ValidationVerdictV1,
};

use crate::common;

#[test]
fn accelerator_locality_constraints_are_explicit() {
    let report = common::validate_with_profile(
        common::derive_contract_from_fixture_with_policy(
            "linux-gpu-dual-numa-like-v1",
            "gpu_compute_default.v1.json",
        ),
        common::load_service_profile_file("gpu_locality_single_numa_contract_only.v2.json"),
        None,
        ValidationModeV1::ContractOnly,
        None,
    );

    assert_eq!(report.report.verdict, ValidationVerdictV1::Unfit);
    assert_eq!(
        report.report.primary_reason_code,
        ValidationReasonCodeV1::TopologyMismatch
    );
    assert_eq!(
        report.report.failed_requirements,
        vec!["core_requirements.max_accelerator_numa_nodes".to_string()]
    );
    assert!(report
        .report
        .summary
        .contains("exceeding the allowed maximum 1"));
}
