// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common;
use fitctl_core::artifacts::contract_v1::ContractExtensionBasisV1;
use fitctl_core::artifacts::semantic_hash_v1::semantic_hash_hex_for_contract;
use fitctl_core::artifacts::validation_v1::{
    validate_host_contract, validate_host_state, validate_host_survey,
};
use fitctl_core::service_profile::load_service_profile_from_path;
use serde_json::json;
use std::collections::BTreeMap;

#[test]
fn ring_split_uses_core_and_extension_sections() {
    let survey = common::collect_survey_fixture("linux-bare-metal-like-v1");
    let survey_payload = common::decode_survey_payload(&survey);
    assert!(survey.survey.get("core_evidence").is_some());
    assert!(survey.survey.get("observations").is_none());
    assert!(survey_payload.extension_evidence.is_empty());
    validate_host_survey(&survey).expect("survey should validate");

    let contract = common::derive_contract_from_fixture("linux-bare-metal-like-v1");
    let payload = common::decode_contract_payload(&contract);
    assert!(contract.contract.get("core_contract").is_some());
    assert!(payload.extension_contract.is_empty());
    validate_host_contract(&contract).expect("contract should validate");

    let state = common::collect_state_fixture("linux-bare-metal-like-fresh-v1");
    assert!(state.state.extension_state.is_empty());
    validate_host_state(&state).expect("state should validate");

    let profile = load_service_profile_from_path(&common::repo_service_profile_path(
        "general_compute_contract_only.v2.json",
    ))
    .expect("service profile should load");
    let profile_json =
        serde_json::to_value(&profile.profile).expect("service-profile payload should encode");
    assert!(profile_json.get("core_requirements").is_some());
    assert!(profile_json.get("requirements").is_none());

    let base_hash = semantic_hash_hex_for_contract(&contract).expect("base contract hash");
    let mut extension_contract = contract.clone();
    let mut extension_payload = common::decode_contract_payload(&extension_contract);
    extension_payload.extension_contract.insert(
        "example.monitoring".to_string(),
        json!({"collector_status": "green", "collector_version": "1"}),
    );
    extension_contract.contract =
        serde_json::to_value(&extension_payload).expect("extension payload should encode");
    validate_host_contract(&extension_contract).expect("extension payload should validate");
    let hash_without_basis =
        semantic_hash_hex_for_contract(&extension_contract).expect("hash should compute");
    assert_eq!(base_hash, hash_without_basis);

    extension_contract.contract_basis.extension_basis = Some(ContractExtensionBasisV1 {
        enabled_extension_namespaces: vec!["example.monitoring".to_string()],
        extension_semantic_hashes: BTreeMap::from([(
            "example.monitoring".to_string(),
            "extension-monitoring-hash-v1".to_string(),
        )]),
    });
    let hash_with_basis =
        semantic_hash_hex_for_contract(&extension_contract).expect("extension basis hash");
    assert_ne!(hash_without_basis, hash_with_basis);
}
