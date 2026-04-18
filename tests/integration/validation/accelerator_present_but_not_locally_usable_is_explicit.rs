// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use fitctl_core::survey::VisibilityScopeV1;
use fitctl_core::validate::ValidationModeV1;

use crate::common;

#[test]
fn accelerator_present_but_not_locally_usable_is_explicit() {
    let contract = common::derive_contract_from_fixture_with_policy(
        "linux-gpu-container-restricted-like-v1",
        "gpu_compute_default.v1.json",
    );
    let payload = common::decode_contract_payload(&contract);
    let claim = payload
        .core_contract
        .capability_classes
        .get("gpu_accelerated")
        .expect("gpu claim should be present");

    assert!(!claim.admissible);
    assert!(
        claim.summary.contains(
            "gpu hardware is present but no accelerator device nodes are visible under the current execution context"
        )
    );

    let mut profile = common::load_service_profile_file(
        "gpu_preferred_with_general_compute_fallback_contract_only.v2.json",
    );
    profile.profile.core_requirements.allowed_visibility_scopes =
        vec![VisibilityScopeV1::ContainerRestricted];
    profile.profile.degradation_ladder.clear();

    let report = common::validate_with_profile(
        contract,
        profile,
        None,
        ValidationModeV1::ContractOnly,
        None,
    );

    assert_eq!(report.report.verdict.as_str(), "unfit");
    assert_eq!(
        report.report.primary_reason_code.as_str(),
        "policy_not_admissible"
    );
    assert!(
        report.report.summary.contains(
            "gpu hardware is present but no accelerator device nodes are visible under the current execution context"
        )
    );
    assert!(!report
        .report
        .summary
        .contains("absent from the host contract"));
}
