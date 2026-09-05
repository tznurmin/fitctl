// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use fitctl_core::artifacts::contract_v1::{ContractExtensionBasisV1, HostContractV1};
use fitctl_core::artifacts::record_v1::ArtifactRecordV1;
use fitctl_core::bundle::{assemble_decision_bundle_v1, DecisionBundleAssemblyRequestV1};
use fitctl_core::extensions::{CUDA_RUNTIME_NAMESPACE, NODE_RUNTIME_NAMESPACE};
use fitctl_core::redact::{
    redact_artifact_v1, BuiltInRedactionProfileV1, RedactionError, RedactionRequestV1,
};
use fitctl_core::validate::ValidationModeV1;

use crate::common;

const UNKNOWN_NAMESPACE: &str = "com.example.private.runtime";
const UNKNOWN_HASH: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

#[test]
fn unknown_contract_extension_basis_fails_closed() {
    for profile in sharing_profiles() {
        for nested in [false, true] {
            let contract =
                contract_with_basis(vec![UNKNOWN_NAMESPACE], [(UNKNOWN_NAMESPACE, UNKNOWN_HASH)]);
            let error = redact_contract_or_bundle(contract, profile, nested)
                .expect_err("unknown basis namespace must fail closed");
            assert_extension_dispatch_error(&error);
        }
    }
}

#[test]
fn unknown_namespace_in_basis_and_payload_fails_closed() {
    let mut contract =
        contract_with_basis(vec![UNKNOWN_NAMESPACE], [(UNKNOWN_NAMESPACE, UNKNOWN_HASH)]);
    let mut payload = common::decode_contract_payload(&contract);
    payload.extension_contract.insert(
        UNKNOWN_NAMESPACE.to_string(),
        serde_json::json!({"private_path": "/srv/private/runtime"}),
    );
    contract.contract = serde_json::to_value(payload).expect("payload should encode");

    let error = redact_contract_or_bundle(contract, BuiltInRedactionProfileV1::External, false)
        .expect_err("unknown basis and payload namespace must fail closed");
    assert_extension_dispatch_error(&error);
}

#[test]
fn registered_basis_and_payload_sets_must_match() {
    let cuda = cuda_contract();
    let mut wrong_basis = cuda;
    wrong_basis.contract_basis.extension_basis = Some(ContractExtensionBasisV1 {
        enabled_extension_namespaces: vec![NODE_RUNTIME_NAMESPACE.to_string()],
        extension_semantic_hashes: BTreeMap::from([(
            NODE_RUNTIME_NAMESPACE.to_string(),
            UNKNOWN_HASH.to_string(),
        )]),
    });

    let mut no_basis = cuda_contract();
    no_basis.contract_basis.extension_basis = None;

    let mut duplicate_enabled = cuda_contract();
    duplicate_enabled
        .contract_basis
        .extension_basis
        .as_mut()
        .expect("CUDA fixture should include extension basis")
        .enabled_extension_namespaces
        .push(CUDA_RUNTIME_NAMESPACE.to_string());

    for contract in [wrong_basis, no_basis, duplicate_enabled] {
        let error = redact_contract_or_bundle(contract, BuiltInRedactionProfileV1::External, false)
            .expect_err("basis and payload namespace mismatch must fail closed");
        assert_eq!(error.code.as_str(), "artifact_input_invalid");
        assert_eq!(error.checkpoint_id, "contract_extension_basis_validate");
    }
}

#[test]
fn registered_basis_without_payload_preserves_incomplete_semantics() {
    let mut contract = cuda_contract();
    let mut payload = common::decode_contract_payload(&contract);
    payload.extension_contract.clear();
    contract.contract = serde_json::to_value(payload).expect("payload should encode");

    redact_contract_or_bundle(contract, BuiltInRedactionProfileV1::External, false)
        .expect("enabled extension with unavailable payload should remain shareable");
}

#[test]
fn registered_basis_hash_must_be_canonical_lowercase_sha256() {
    for hash in [
        "private-extension-source-hash",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ] {
        let mut contract = cuda_contract();
        contract
            .contract_basis
            .extension_basis
            .as_mut()
            .expect("CUDA fixture should include extension basis")
            .extension_semantic_hashes
            .insert(CUDA_RUNTIME_NAMESPACE.to_string(), hash.to_string());

        let error = redact_contract_or_bundle(contract, BuiltInRedactionProfileV1::External, false)
            .expect_err("noncanonical extension hash must fail closed");
        assert_eq!(error.code.as_str(), "artifact_input_invalid");
        assert_eq!(error.checkpoint_id, "contract_extension_basis_validate");
    }
}

#[test]
fn enabled_basis_names_and_hash_keys_must_match() {
    let mut contract = cuda_contract();
    let basis = contract
        .contract_basis
        .extension_basis
        .as_mut()
        .expect("CUDA fixture should include extension basis");
    basis.extension_semantic_hashes =
        BTreeMap::from([(NODE_RUNTIME_NAMESPACE.to_string(), UNKNOWN_HASH.to_string())]);

    let error = redact_contract_or_bundle(contract, BuiltInRedactionProfileV1::Auditor, false)
        .expect_err("basis names and hash keys must match");
    assert_eq!(error.code.as_str(), "artifact_input_invalid");
    assert_eq!(error.checkpoint_id, "contract_extension_basis_validate");
}

#[test]
fn matching_registered_basis_retains_documented_hash_lineage() {
    let contract = cuda_contract();
    let original_basis = contract
        .contract_basis
        .extension_basis
        .clone()
        .expect("CUDA fixture should include extension basis");

    let redacted = redact_contract_or_bundle(contract, BuiltInRedactionProfileV1::External, false)
        .expect("matching registered basis should redact");
    let ArtifactRecordV1::Contract(redacted) = redacted else {
        panic!("standalone contract should remain a contract");
    };
    assert_eq!(
        redacted.contract_basis.extension_basis,
        Some(original_basis)
    );
    assert!(redacted
        .contract
        .to_string()
        .contains(CUDA_RUNTIME_NAMESPACE));
}

#[test]
fn local_and_fleet_preserve_unknown_basis_compatibility() {
    for profile in [
        BuiltInRedactionProfileV1::Local,
        BuiltInRedactionProfileV1::Fleet,
    ] {
        let contract =
            contract_with_basis(vec![UNKNOWN_NAMESPACE], [(UNKNOWN_NAMESPACE, UNKNOWN_HASH)]);
        let redacted = redact_contract_or_bundle(contract, profile, false)
            .expect("operator-boundary profiles should preserve unknown basis metadata");
        let encoded = serde_json::to_string(&redacted).expect("artifact should encode");
        assert!(encoded.contains(UNKNOWN_NAMESPACE));
        assert!(encoded.contains(UNKNOWN_HASH));
    }
}

fn contract_with_basis<const N: usize>(
    enabled: Vec<&str>,
    hashes: [(&str, &str); N],
) -> HostContractV1 {
    let mut contract = common::derive_contract_from_fixture("linux-bare-metal-like-v1");
    contract.contract_basis.extension_basis = Some(ContractExtensionBasisV1 {
        enabled_extension_namespaces: enabled.into_iter().map(str::to_string).collect(),
        extension_semantic_hashes: hashes
            .into_iter()
            .map(|(namespace, hash)| (namespace.to_string(), hash.to_string()))
            .collect(),
    });
    contract
}

fn cuda_contract() -> HostContractV1 {
    let path = common::repo_root()
        .join("fixtures/conformance/valid/host-contract.cuda-default-view-version-split.v2.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("CUDA contract should read"))
        .expect("CUDA contract should decode")
}

fn redact_contract_or_bundle(
    contract: HostContractV1,
    profile: BuiltInRedactionProfileV1,
    nested: bool,
) -> Result<ArtifactRecordV1, RedactionError> {
    let artifact = if nested {
        let validation_report = common::validate_with_profile(
            contract.clone(),
            common::load_service_profile_file("general_compute_contract_only.v2.json"),
            None,
            ValidationModeV1::ContractOnly,
            None,
        );
        let bundle = assemble_decision_bundle_v1(DecisionBundleAssemblyRequestV1 {
            validation_report,
            contract,
            state: None,
            resolved_config: None,
            config_bundle: None,
            verification_bundle: None,
            recommendation_report: None,
            bundled_at: common::FIXED_TIMESTAMP.to_string(),
            notes: None,
        })
        .expect("decision bundle should assemble");
        ArtifactRecordV1::DecisionBundle(bundle)
    } else {
        ArtifactRecordV1::Contract(contract)
    };

    redact_artifact_v1(RedactionRequestV1 {
        artifact,
        profile,
        redacted_at: common::FIXED_TIMESTAMP.to_string(),
    })
}

fn assert_extension_dispatch_error(error: &RedactionError) {
    assert_eq!(error.code.as_str(), "extension_redactor_unavailable");
    assert_eq!(error.checkpoint_id, "extension_redaction_dispatch");
    assert!(error.message.contains(UNKNOWN_NAMESPACE));
}

fn sharing_profiles() -> [BuiltInRedactionProfileV1; 2] {
    [
        BuiltInRedactionProfileV1::Auditor,
        BuiltInRedactionProfileV1::External,
    ]
}
