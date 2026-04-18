// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

use fitctl_core::artifacts::record_v1::load_artifact_record_from_path;

use crate::{common, e2e};

#[test]
fn decision_bundle_accepts_verification_bundle_handoff() {
    let root = common::unique_temp_dir("decision-bundle-verification-bundle");
    let survey_path = e2e::emit_survey_fixture(&root, "linux-bare-metal-like-v1");
    let contract_path =
        e2e::derive_contract(&root, &survey_path, "general_compute_default.v1.json");

    let validation_output = e2e::run_fitctl([
        "validate",
        "--contract",
        contract_path
            .to_str()
            .expect("contract path should be UTF-8"),
        "--profile",
        common::repo_service_profile_path("general_compute_contract_only.v2.json")
            .to_str()
            .expect("service-profile path should be UTF-8"),
        "--validated-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&validation_output);
    let validation_path = root.join("validation-report.json");
    e2e::write_stdout(&validation_path, &validation_output);

    let key_path = common::generate_ed25519_keypair(&root, "trusted-signer");
    let signed_contract_path = e2e::sign_artifact(&root, &contract_path, &key_path, "contract");
    let signed_contract_record =
        load_artifact_record_from_path(&signed_contract_path).expect("signed contract should load");
    let key_id = signed_contract_record.envelope().signatures[0]
        .key_id
        .clone();
    let trust_policy = common::trust_policy_for_signer(&key_id);
    let trust_policy_path = root.join("trust-policy.json");
    common::write_json_file(&trust_policy_path, &trust_policy);

    let verification_bundle_path = root.join("verification-bundle.json");
    let verify_output = e2e::run_fitctl([
        "verify",
        "--input",
        signed_contract_path
            .to_str()
            .expect("signed contract path should be UTF-8"),
        "--policy",
        trust_policy_path
            .to_str()
            .expect("trust-policy path should be UTF-8"),
        "--bundle-out",
        verification_bundle_path
            .to_str()
            .expect("verification-bundle path should be UTF-8"),
    ]);
    e2e::assert_success(&verify_output);

    let bundle_output = e2e::run_fitctl([
        "bundle",
        "--validation-report",
        validation_path
            .to_str()
            .expect("validation path should be UTF-8"),
        "--contract",
        contract_path
            .to_str()
            .expect("contract path should be UTF-8"),
        "--verification-bundle",
        verification_bundle_path
            .to_str()
            .expect("verification-bundle path should be UTF-8"),
        "--bundled-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&bundle_output);

    let bundle_json: Value = e2e::decode_json_stdout(&bundle_output);
    assert_eq!(
        bundle_json["envelope"]["schema_id"],
        "fitctl.decision-bundle.v2"
    );
    assert_eq!(
        bundle_json["bundle"]["verification_bundle"]["schema_id"],
        "fitctl.verification-bundle.v1"
    );
    assert_eq!(
        bundle_json["bundle_basis"]["verification_bundle_id"],
        bundle_json["bundle"]["verification_bundle"]["bundle_id"]
    );
    assert_eq!(
        bundle_json["bundle"]["verification_bundle"]["trust_policy_id"],
        "integration-trusted-policy-v1"
    );

    let bundle_path = root.join("decision-bundle.verification.json");
    e2e::write_stdout(&bundle_path, &bundle_output);
    let inspect_output = e2e::run_fitctl([
        "inspect",
        "--input",
        bundle_path.to_str().expect("bundle path should be UTF-8"),
    ]);
    e2e::assert_success(&inspect_output);
    let inspect_text = String::from_utf8_lossy(&inspect_output.stdout);
    assert!(inspect_text.contains("fitctl.verification-bundle.v1"));
    assert!(inspect_text.contains("Verification bundle id"));
    assert!(inspect_text.contains("Verification trust policy id"));
    assert!(inspect_text.contains("integration-trusted-policy-v1"));
}
