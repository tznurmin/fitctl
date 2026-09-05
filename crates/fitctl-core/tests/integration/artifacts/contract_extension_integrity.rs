// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use fitctl_core::artifacts::contract_v1::{ContractExtensionBasisV1, HostContractV1};
use fitctl_core::artifacts::record_v1::ArtifactRecordV1;
use fitctl_core::artifacts::semantic_hash_v1::semantic_hash_hex_for_contract;
use fitctl_core::artifacts::validation_v1::{validate_host_contract, ArtifactValidationErrorCode};
use fitctl_core::sign::verify_artifact_signatures_v1;
use serde_json::json;

use crate::common;

const EXTENSION_NAMESPACE: &str = "example.monitoring";
const EXTENSION_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn contract_rejects_extension_payload_without_basis() {
    let contract = contract_with_payload(None, EXTENSION_NAMESPACE);
    let error = validate_host_contract(&contract)
        .expect_err("typed extension payload without basis must fail closed");
    assert_eq!(
        error.code,
        ArtifactValidationErrorCode::ContractBasisInvalid
    );
    assert!(error.message.contains("requires an extension basis"));
}

#[test]
fn contract_rejects_payload_namespace_not_enabled_by_basis() {
    let basis = basis(&["example.other"], &[("example.other", EXTENSION_HASH)]);
    let contract = contract_with_payload(Some(basis), EXTENSION_NAMESPACE);
    let error = validate_host_contract(&contract)
        .expect_err("payload namespace outside the enabled basis must fail closed");
    assert_eq!(
        error.code,
        ArtifactValidationErrorCode::ContractBasisInvalid
    );
    assert!(error.message.contains("subset"));
}

#[test]
fn contract_rejects_enabled_and_hash_namespace_mismatch() {
    let basis = basis(&[EXTENSION_NAMESPACE], &[("example.other", EXTENSION_HASH)]);
    let contract = contract_with_basis_only(basis);
    let error =
        validate_host_contract(&contract).expect_err("enabled namespaces and hash keys must match");
    assert_eq!(
        error.code,
        ArtifactValidationErrorCode::ContractBasisInvalid
    );
    assert!(error.message.contains("semantic-hash keys"));
}

#[test]
fn contract_rejects_noncanonical_extension_hash() {
    let basis = basis(
        &[EXTENSION_NAMESPACE],
        &[(EXTENSION_NAMESPACE, "extension-hash")],
    );
    let contract = contract_with_basis_only(basis);
    let error = validate_host_contract(&contract)
        .expect_err("noncanonical extension semantic hash must fail closed");
    assert_eq!(
        error.code,
        ArtifactValidationErrorCode::ContractBasisInvalid
    );
    assert!(error.message.contains("lowercase SHA-256"));
}

#[test]
fn enabled_extension_without_payload_remains_valid_incomplete_input() {
    let basis = basis(
        &[EXTENSION_NAMESPACE],
        &[(EXTENSION_NAMESPACE, EXTENSION_HASH)],
    );
    let contract = contract_with_basis_only(basis);
    validate_host_contract(&contract)
        .expect("enabled extension with unavailable payload remains structurally valid");
}

#[test]
fn based_extension_payload_is_bound_into_the_semantic_projection() {
    let extension_basis = basis(
        &[EXTENSION_NAMESPACE],
        &[(EXTENSION_NAMESPACE, EXTENSION_HASH)],
    );
    let baseline = contract_with_payload(Some(extension_basis.clone()), EXTENSION_NAMESPACE);
    let mut mutated = contract_with_payload(Some(extension_basis), EXTENSION_NAMESPACE);
    let mut payload = common::decode_contract_payload(&mutated);
    payload.extension_contract.insert(
        EXTENSION_NAMESPACE.to_string(),
        json!({"collector_status": "changed", "collector_version": "2"}),
    );
    mutated.contract = serde_json::to_value(payload).expect("mutated payload should encode");
    assert_ne!(
        semantic_hash_hex_for_contract(&baseline).expect("baseline hash"),
        semantic_hash_hex_for_contract(&mutated).expect("mutated extension hash")
    );
}

#[test]
fn signed_extension_payload_mutation_invalidates_signature() {
    let root = common::unique_temp_dir("contract-extension-signature");
    let key = common::generate_ed25519_keypair(&root, "signer");
    let basis = basis(
        &[EXTENSION_NAMESPACE],
        &[(EXTENSION_NAMESPACE, EXTENSION_HASH)],
    );
    let contract = contract_with_payload(Some(basis), EXTENSION_NAMESPACE);
    let signed = common::sign_artifact(ArtifactRecordV1::Contract(contract), &key);
    verify_artifact_signatures_v1(&signed).expect("original extension signature should verify");

    let ArtifactRecordV1::Contract(mut mutated) = signed else {
        panic!("signed artifact should remain a contract");
    };
    let mut payload = common::decode_contract_payload(&mutated);
    payload.extension_contract.insert(
        EXTENSION_NAMESPACE.to_string(),
        json!({"collector_status": "changed", "collector_version": "2"}),
    );
    mutated.contract = serde_json::to_value(payload).expect("mutated payload should encode");
    validate_host_contract(&mutated).expect("mutated extension contract should remain valid");
    verify_artifact_signatures_v1(&ArtifactRecordV1::Contract(mutated))
        .expect_err("extension payload mutation must invalidate its signature");
}

fn contract_with_payload(
    basis: Option<ContractExtensionBasisV1>,
    namespace: &str,
) -> HostContractV1 {
    let mut contract = common::derive_contract_from_fixture("linux-bare-metal-like-v1");
    contract.contract_basis.extension_basis = basis;
    let mut payload = common::decode_contract_payload(&contract);
    payload.extension_contract.insert(
        namespace.to_string(),
        json!({"collector_status": "green", "collector_version": "1"}),
    );
    contract.contract = serde_json::to_value(payload).expect("extension payload should encode");
    contract
}

fn contract_with_basis_only(basis: ContractExtensionBasisV1) -> HostContractV1 {
    let mut contract = common::derive_contract_from_fixture("linux-bare-metal-like-v1");
    contract.contract_basis.extension_basis = Some(basis);
    contract
}

fn basis(enabled: &[&str], hashes: &[(&str, &str)]) -> ContractExtensionBasisV1 {
    ContractExtensionBasisV1 {
        enabled_extension_namespaces: enabled.iter().map(|value| (*value).to_string()).collect(),
        extension_semantic_hashes: hashes
            .iter()
            .map(|(namespace, hash)| ((*namespace).to_string(), (*hash).to_string()))
            .collect::<BTreeMap<String, String>>(),
    }
}
