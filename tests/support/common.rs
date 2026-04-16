#![allow(dead_code)]
// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use fitctl_core::artifacts::contract_v1::HostContractV1;
use fitctl_core::artifacts::record_v1::ArtifactRecordV1;
use fitctl_core::artifacts::service_profile_v1::ServiceProfileV1;
use fitctl_core::artifacts::state_v1::HostStateV1;
use fitctl_core::artifacts::survey_v1::{
    decode_host_survey_payload, HostSurveyPayloadV1, HostSurveyV1,
};
use fitctl_core::artifacts::validation_report_v1::{ValidationModeV1, ValidationReportV1};
use fitctl_core::contract::{
    derive_host_contract_v1, ContractDerivationRequestV1, DerivationContextV1,
    HostContractPayloadV1,
};
use fitctl_core::policy::load_policy_document_from_path;
use fitctl_core::redact::{redact_artifact_v1, BuiltInRedactionProfileV1, RedactionRequestV1};
use fitctl_core::service_profile::load_service_profile_from_path;
use fitctl_core::sign::{sign_artifact_v1, SignatureRequestV1, SIGNATURE_NAMESPACE_V1};
use fitctl_core::state::{NoopLiveStateProbeV1, StateEngineV1, StateModeV1};
use fitctl_core::survey::{NoopLiveProbeV1, SurveyEngineV1, SurveyModeV1};
use fitctl_core::validate::{validate_request_v1, ValidationRequestV1};
use fitctl_core::verify::{
    ExternalEvidenceTrustActionV1, TrustPolicyV1, UnsignedActionV1, UntrustedSignerActionV1,
};

pub const FIXED_TIMESTAMP: &str = "2025-04-21T14:37:19Z";

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn repo_policy_path() -> PathBuf {
    repo_root().join("configs/policy/general_compute_default.v1.json")
}

pub fn repo_policy_file_path(file_name: &str) -> PathBuf {
    repo_root().join("configs/policy").join(file_name)
}

pub fn repo_service_profile_path(file_name: &str) -> PathBuf {
    repo_root().join("configs/service_profiles").join(file_name)
}

pub fn unique_temp_dir(prefix: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic enough for temp paths")
        .as_nanos();
    path.push(format!("fitctl-{prefix}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&path).expect("temp dir should be created");
    path
}

pub fn write_json_file<T: serde::Serialize>(path: &Path, value: &T) {
    fs::write(
        path,
        serde_json::to_vec_pretty(value).expect("json should encode"),
    )
    .expect("json file should be written");
}

pub fn write_text_file(path: &Path, text: &str) {
    fs::write(path, text).expect("text file should be written");
}

pub fn collect_survey_fixture(fixture_id: &str) -> HostSurveyV1 {
    SurveyEngineV1::new(NoopLiveProbeV1)
        .collect_host_survey(SurveyModeV1::Replay {
            fixtures_root: repo_root().join("fixtures/host_survey"),
            fixture_id: fixture_id.to_string(),
        })
        .expect("survey fixture should load")
}

pub fn decode_survey_payload(survey: &HostSurveyV1) -> HostSurveyPayloadV1 {
    decode_host_survey_payload(&survey.survey).expect("survey payload should decode")
}

pub fn collect_state_fixture(fixture_id: &str) -> HostStateV1 {
    StateEngineV1::new(NoopLiveStateProbeV1)
        .collect_host_state(StateModeV1::Replay {
            fixtures_root: repo_root().join("fixtures/host_state"),
            fixture_id: fixture_id.to_string(),
        })
        .expect("state fixture should load")
}

pub fn derive_contract_from_fixture(fixture_id: &str) -> HostContractV1 {
    let policy = load_policy_document_from_path(&repo_policy_path()).expect("policy should load");
    derive_host_contract_v1(ContractDerivationRequestV1 {
        survey: collect_survey_fixture(fixture_id),
        policy,
        live_state: None,
        derivation_context: DerivationContextV1 {
            derived_at: FIXED_TIMESTAMP.to_string(),
            notes: Some("integration-test".to_string()),
        },
    })
    .expect("contract should derive")
}

pub fn derive_contract_from_fixture_with_policy(
    fixture_id: &str,
    policy_file_name: &str,
) -> HostContractV1 {
    let policy = load_policy_document_from_path(&repo_policy_file_path(policy_file_name))
        .expect("policy should load");
    derive_host_contract_v1(ContractDerivationRequestV1 {
        survey: collect_survey_fixture(fixture_id),
        policy,
        live_state: None,
        derivation_context: DerivationContextV1 {
            derived_at: FIXED_TIMESTAMP.to_string(),
            notes: Some("integration-test".to_string()),
        },
    })
    .expect("contract should derive")
}

pub fn decode_contract_payload(contract: &HostContractV1) -> HostContractPayloadV1 {
    serde_json::from_value(contract.contract.clone()).expect("contract payload should decode")
}

pub fn load_service_profile_file(file_name: &str) -> ServiceProfileV1 {
    load_service_profile_from_path(&repo_service_profile_path(file_name))
        .expect("service profile should load")
}

pub fn write_temp_service_profile(
    root: &Path,
    file_name: &str,
    value: &serde_json::Value,
) -> PathBuf {
    let path = root.join(file_name);
    write_json_file(&path, value);
    path
}

pub fn validate_with_profile(
    contract: HostContractV1,
    service_profile: ServiceProfileV1,
    host_state: Option<HostStateV1>,
    mode: ValidationModeV1,
    max_state_age_seconds: Option<u64>,
) -> ValidationReportV1 {
    validate_request_v1(ValidationRequestV1 {
        contract,
        service_profile,
        host_state,
        mode,
        validated_at: FIXED_TIMESTAMP.to_string(),
        notes: Some("integration-test".to_string()),
        max_state_age_seconds,
    })
    .expect("validation should emit")
}

pub fn externally_redacted_contract_from_fixture(fixture_id: &str) -> ArtifactRecordV1 {
    redact_artifact_v1(RedactionRequestV1 {
        artifact: ArtifactRecordV1::Contract(derive_contract_from_fixture(fixture_id)),
        profile: BuiltInRedactionProfileV1::External,
        redacted_at: FIXED_TIMESTAMP.to_string(),
    })
    .expect("redacted contract should emit")
}

pub fn generate_ed25519_keypair(root: &Path, file_name: &str) -> PathBuf {
    let key_path = root.join(file_name);
    let output = Command::new("ssh-keygen")
        .args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-f",
            key_path.to_str().expect("key path should be valid UTF-8"),
        ])
        .output()
        .expect("ssh-keygen should execute");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    key_path
}

pub fn sign_artifact(artifact: ArtifactRecordV1, key_path: &Path) -> ArtifactRecordV1 {
    sign_artifact_v1(SignatureRequestV1 {
        artifact,
        private_key_path: key_path.to_path_buf(),
        signed_at: FIXED_TIMESTAMP.to_string(),
    })
    .expect("artifact should sign")
}

pub fn sign_survey_fixture(fixture_id: &str, key_path: &Path) -> ArtifactRecordV1 {
    sign_artifact(
        ArtifactRecordV1::Survey(collect_survey_fixture(fixture_id)),
        key_path,
    )
}

pub fn trust_policy_for_signer(key_id: &str) -> TrustPolicyV1 {
    TrustPolicyV1 {
        schema_id: "fitctl.trust-policy.v1".to_string(),
        schema_version: 1,
        policy_id: "integration-trusted-policy-v1".to_string(),
        trusted_signers: vec![key_id.to_string()],
        accepted_signature_namespaces: vec![SIGNATURE_NAMESPACE_V1.to_string()],
        unsigned_action: UnsignedActionV1::Deny,
        untrusted_signer_action: UntrustedSignerActionV1::Deny,
        allow_self_signed: true,
        accepted_external_evidence_types: vec![],
        external_evidence_trust_action: ExternalEvidenceTrustActionV1::Ignore,
        max_external_evidence_age_seconds: None,
    }
}
