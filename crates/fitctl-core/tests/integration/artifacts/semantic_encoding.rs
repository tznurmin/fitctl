// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use fitctl_core::artifacts::record_v1::ArtifactRecordV1;

fn assert_independent_decode(record: &ArtifactRecordV1) {
    let bytes = record.semantic_bytes().unwrap();
    let decoded: serde_json::Value = cbor4ii::serde::from_slice(&bytes).unwrap();
    assert_eq!(
        decoded,
        serde_json::json!([
            "fitctl.semantic_cbor.v2",
            record.semantic_content_json().unwrap()
        ])
    );
    let mut decoder = minicbor::Decoder::new(&bytes);
    decoder.skip().expect("complete CBOR value");
    assert_eq!(decoder.position(), bytes.len());
}

#[test]
fn semantic_encoding_contract_without_extensions_is_complete_cbor() {
    let contract = crate::common::derive_contract_from_fixture("linux-bare-metal-like-v1");
    assert!(contract.contract_basis.extension_basis.is_none());
    let bytes = ArtifactRecordV1::Contract(contract)
        .semantic_bytes()
        .unwrap();
    let mut decoder = minicbor::Decoder::new(&bytes);
    decoder
        .skip()
        .expect("semantic bytes must contain a complete CBOR value");
    assert_eq!(decoder.position(), bytes.len(), "no trailing values");
}

#[test]
fn semantic_encoding_real_projections_decode_in_an_independent_implementation() {
    use fitctl_core::artifacts::record_v1::{
        load_artifact_record_from_path, ArtifactRecordErrorCode,
    };
    let root = crate::common::repo_root().join("fixtures/conformance/valid");
    let mut count = 0;
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|ext| ext == "json") {
            // Some conformance entries are auxiliary schemas outside ArtifactRecordV1.
            match load_artifact_record_from_path(&path) {
                Ok(record) => {
                    assert_independent_decode(&record);
                    count += 1;
                }
                Err(error) => assert_eq!(
                    error.code,
                    ArtifactRecordErrorCode::ArtifactSchemaUnsupported,
                    "{path:?}: {error:?}"
                ),
            }
        }
    }
    assert!(
        count > 20,
        "exercise the retained artifact corpus, not one fixture"
    );
    assert_independent_decode(&ArtifactRecordV1::Contract(
        crate::common::derive_contract_from_fixture("linux-bare-metal-like-v1"),
    ));
}

#[test]
fn semantic_encoding_policy_locks_bind_current_hashes_and_reject_old_encoding() {
    use fitctl_core::config::{
        create_policy_pack_lock_from_path, load_policy_pack_lock_from_path,
        resolve_policy_from_pack_with_lock_path, sign_policy_pack_lock_v1, CatalogueErrorCode,
    };
    let root = Root(crate::common::unique_temp_dir("semantic-lock"));
    let key = crate::common::generate_ed25519_keypair(&root.0, "signer");
    let pack = crate::common::repo_policy_pack_path("general_compute_default_pack.v1.json");
    let lock = create_policy_pack_lock_from_path(&pack, "general_compute_default_v1").unwrap();
    let mut signed = sign_policy_pack_lock_v1(&lock, &key, crate::common::FIXED_TIMESTAMP).unwrap();
    assert_eq!(
        signed.signatures[0].payload_encoding.as_deref(),
        Some("fitctl.policy-pack-lock.semantic_cbor.v2")
    );
    let path = root.0.join("lock.json");
    crate::common::write_json_file(&path, &signed);
    load_policy_pack_lock_from_path(&path).unwrap();
    resolve_policy_from_pack_with_lock_path(&pack, &path).unwrap();
    signed.signatures[0].payload_encoding = Some("fitctl.policy-pack-lock.semantic_cbor.v1".into());
    crate::common::write_json_file(&path, &signed);
    let error = load_policy_pack_lock_from_path(&path).unwrap_err();
    assert_eq!(error.code, CatalogueErrorCode::ManifestSignatureInvalid);
    assert!(error.message.contains("payload encoding"));
    let mut stale = lock;
    stale.policy_semantic_hash = "b".repeat(64);
    crate::common::write_json_file(&path, &stale);
    assert_eq!(
        resolve_policy_from_pack_with_lock_path(&pack, &path)
            .unwrap_err()
            .code,
        CatalogueErrorCode::ManifestCompatibilityInvalid
    );
}

struct Root(std::path::PathBuf);
impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn semantic_encoding_signatures_reject_old_labels_and_mutation() {
    use fitctl_core::sign::{verify_artifact_signatures_v1, SignErrorCode};
    let root = Root(crate::common::unique_temp_dir("semantic-signing"));
    let key = crate::common::generate_ed25519_keypair(&root.0, "signer");
    let record = ArtifactRecordV1::Contract(crate::common::derive_contract_from_fixture(
        "linux-bare-metal-like-v1",
    ));
    let before = record.semantic_hash_hex().unwrap();
    let signed = crate::common::sign_artifact(record, &key);
    assert_eq!(signed.semantic_hash_hex().unwrap(), before);
    verify_artifact_signatures_v1(&signed).unwrap();
    let ArtifactRecordV1::Contract(mut contract) = signed else {
        panic!("contract");
    };
    assert_eq!(
        contract.envelope.signatures[0].payload_encoding.as_deref(),
        Some("fitctl.semantic_cbor.v2")
    );
    contract.envelope.signatures[0].payload_encoding = Some("fitctl.semantic_cbor.v1".into());
    let error =
        verify_artifact_signatures_v1(&ArtifactRecordV1::Contract(contract.clone())).unwrap_err();
    assert_eq!(error.code, SignErrorCode::ArtifactInputInvalid);
    contract.envelope.signatures[0].payload_encoding = Some("fitctl.semantic_cbor.v2".into());
    contract
        .contract_basis
        .core_semantic_basis
        .policy_semantic_hash = "a".repeat(64);
    assert!(verify_artifact_signatures_v1(&ArtifactRecordV1::Contract(contract)).is_err());
}
