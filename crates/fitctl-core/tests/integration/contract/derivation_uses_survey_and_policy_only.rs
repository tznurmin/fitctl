// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common;
use fitctl_core::contract::{
    derive_host_contract_v1, ContractDerivationErrorCode, ContractDerivationRequestV1,
    DerivationContextV1,
};
use fitctl_core::policy::load_policy_document_from_path;
use serde_json::json;

#[test]
fn derivation_uses_survey_and_policy_only() {
    let survey = common::collect_survey_fixture("linux-bare-metal-like-v1");
    let policy = load_policy_document_from_path(&common::repo_policy_path()).expect("policy");

    let success = derive_host_contract_v1(ContractDerivationRequestV1 {
        survey: survey.clone(),
        policy: policy.clone(),
        live_state: None,
        derivation_context: DerivationContextV1 {
            derived_at: common::FIXED_TIMESTAMP.to_string(),
            notes: Some("integration-test".to_string()),
        },
    });
    assert!(success.is_ok());

    let error = derive_host_contract_v1(ContractDerivationRequestV1 {
        survey,
        policy,
        live_state: Some(json!({"allocatable_memory_bytes": 0})),
        derivation_context: DerivationContextV1 {
            derived_at: common::FIXED_TIMESTAMP.to_string(),
            notes: Some("integration-test".to_string()),
        },
    })
    .expect_err("live_state must not participate in contract derivation");

    assert_eq!(
        error.code,
        ContractDerivationErrorCode::ContractDerivationFailed
    );
}
