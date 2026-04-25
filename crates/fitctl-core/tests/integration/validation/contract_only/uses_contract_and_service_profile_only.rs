// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common;
use fitctl_core::artifacts::semantic_hash_v1::{
    semantic_hash_hex_for_contract, semantic_hash_hex_for_service_profile,
};
use fitctl_core::validate::{
    validate_request_v1, ValidationModeV1, ValidationReasonCodeV1, ValidationRequestV1,
    ValidationVerdictV1,
};

#[test]
fn contract_only_uses_contract_and_service_profile_only() {
    let contract = common::derive_contract_from_fixture("linux-bare-metal-like-v1");
    let service_profile =
        common::load_service_profile_file("general_compute_contract_only.v2.json");

    let contract_artifact_id = contract.envelope.artifact_id.clone();
    let service_profile_artifact_id = service_profile.envelope.artifact_id.clone();
    let contract_semantic_hash =
        semantic_hash_hex_for_contract(&contract).expect("contract semantic hash");
    let service_profile_semantic_hash =
        semantic_hash_hex_for_service_profile(&service_profile).expect("service-profile hash");

    let report = validate_request_v1(ValidationRequestV1 {
        contract,
        service_profile,
        host_state: None,
        mode: ValidationModeV1::ContractOnly,
        validated_at: common::FIXED_TIMESTAMP.to_string(),
        notes: Some("integration-test".to_string()),
        max_state_age_seconds: None,
    })
    .expect("contract-only validation should succeed");

    assert_eq!(
        report.validation_basis.validation_mode,
        ValidationModeV1::ContractOnly
    );
    assert_eq!(
        report.validation_basis.contract_artifact_id,
        contract_artifact_id
    );
    assert_eq!(
        report.validation_basis.service_profile_artifact_id,
        service_profile_artifact_id
    );
    assert_eq!(
        report.validation_basis.contract_semantic_hash,
        contract_semantic_hash
    );
    assert_eq!(
        report.validation_basis.service_profile_semantic_hash,
        service_profile_semantic_hash
    );
    assert_eq!(report.report.verdict, ValidationVerdictV1::Fit);
    assert_eq!(
        report.report.primary_reason_code,
        ValidationReasonCodeV1::RequirementsSatisfied
    );
}
