// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use fitctl_core::artifacts::envelope_v1::SignatureEnvelopeV1;
use fitctl_core::artifacts::record_v1::{load_artifact_record_from_value, ArtifactRecordV1};
use fitctl_core::artifacts::validation_report_v1::{ValidationModeV1, ValidationReportV1};
use fitctl_core::validate::{validate_request_v1, ValidationRequestV1};
use serde_json::{json, Value};

pub struct Case {
    input: ArtifactRecordV1,
    error: Option<&'static str>,
}

const SIGNATURE_DUPLICATE: &str =
    "signature entries must not contain duplicate key, payload-hash, and namespace tuples";
const SIGNATURE_BLANK: &str = "signature entries must include populated signing metadata fields";
const COLLECTOR_DUPLICATE: &str = "collector metadata entries must not duplicate collector_id, collector_version, and source_family tuples";

fn signature(key: &str, hash: &str) -> SignatureEnvelopeV1 {
    SignatureEnvelopeV1 {
        key_id: key.into(),
        signer_identity: Some(key.into()),
        public_key: Some("fixture-key".into()),
        signature_format: Some("openssh_sshsig_v1".into()),
        signature_namespace: Some("fitctl-artifact-v1".into()),
        payload_encoding: Some("fitctl.semantic_cbor.v2".into()),
        payload_semantic_hash: Some(hash.into()),
        signed_at: Some(super::common::FIXED_TIMESTAMP.into()),
        signature: "fixture-signature".into(),
    }
}

pub fn signature_cases(auxiliary: bool) -> Vec<Case> {
    let baseline = if auxiliary {
        ArtifactRecordV1::ThermalEvidence(
            serde_json::from_str(include_str!(
                "../../../../fixtures/conformance/valid/thermal-evidence.out-of-band-bmc.v1.json"
            ))
            .unwrap(),
        )
    } else {
        ArtifactRecordV1::ServiceProfile(super::common::load_service_profile_file(
            "general_compute_contract_only.v2.json",
        ))
    };
    let a = signature("key-a", &"a".repeat(64));
    let b = signature("key-b", &"a".repeat(64));
    let c = signature("key-a", &"b".repeat(64));
    let mut malformed = a.clone();
    malformed.signature.clear();
    [
        (vec![], None),
        (vec![a.clone()], None),
        (vec![a.clone(), b.clone(), c], None),
        (
            vec![a.clone(), b.clone(), a.clone()],
            Some(SIGNATURE_DUPLICATE),
        ),
        (
            vec![a.clone(), b.clone(), malformed.clone()],
            Some(SIGNATURE_BLANK),
        ),
        (vec![a.clone(), b, a, malformed], Some(SIGNATURE_DUPLICATE)),
    ]
    .into_iter()
    .map(|(signatures, error)| {
        let mut input = baseline.clone();
        input.envelope_mut().signatures = signatures;
        Case { input, error }
    })
    .collect()
}

pub fn collector_cases() -> Vec<Case> {
    let baseline = super::common::collect_survey_fixture("linux-bare-metal-like-v1");
    let a = json!({"collector_id":"procfs", "collector_version":"1", "source_family":"procfs"});
    let b = json!({"collector_id":"sysfs", "collector_version":"1", "source_family":"sysfs"});
    let c = json!({"collector_id":"procfs", "collector_version":"1", "source_family":"sysfs"});
    let malformed =
        json!({"collector_id":"procfs", "collector_version":"", "source_family":"procfs"});
    [
        (vec![], None), (vec![a.clone()], None), (vec![a.clone(), b.clone(), c], None),
        (vec![a.clone(), b.clone(), a.clone()], Some(COLLECTOR_DUPLICATE)),
        (vec![a.clone(), malformed.clone()], Some("collector metadata entries must be fully populated")),
        (vec![a.clone(), a, malformed], Some(COLLECTOR_DUPLICATE)),
        (vec![json!({"collector_id":"unsupported", "collector_version":"1", "source_family":"procfs"})], Some("collector metadata contains an unsupported collector_id")),
        (vec![json!({"collector_id":"procfs", "collector_version":"2", "source_family":"procfs"})], Some("collector metadata contains an unsupported collector_version")),
        (vec![json!({"collector_id":"procfs", "collector_version":"1", "source_family":"unsupported"})], Some("collector metadata contains an unsupported source_family")),
    ].into_iter().map(|(collectors, error)| {
        let mut input = baseline.clone();
        input.survey["core_evidence"]["collectors"] = Value::Array(collectors);
        Case { input: ArtifactRecordV1::Survey(input), error }
    }).collect()
}

pub fn check(cases: &[Case]) {
    for case in cases {
        let value = case.input.full_artifact_json().unwrap();
        let result = load_artifact_record_from_value(value.clone());
        if let Some(message) = case.error {
            let error = result.unwrap_err();
            assert_eq!(error.error_model_id, "fitctl.artifact_record.v1");
            assert_eq!(error.error_model_version, 1);
            assert_eq!(error.code.as_str(), "artifact_load_invalid");
            assert_eq!(error.checkpoint_id, "artifact_load");
            assert_eq!(error.message, message);
        } else {
            let actual = result.unwrap();
            assert_eq!(actual.full_artifact_json().unwrap(), value);
            assert_eq!(
                actual.semantic_bytes().unwrap(),
                case.input.semantic_bytes().unwrap()
            );
            assert_eq!(
                actual.semantic_hash_hex().unwrap(),
                case.input.semantic_hash_hex().unwrap()
            );
            let mut unsigned = actual.clone();
            unsigned.envelope_mut().signatures.clear();
            assert_eq!(
                unsigned.semantic_bytes().unwrap(),
                actual.semantic_bytes().unwrap()
            );
            assert_eq!(
                unsigned.semantic_hash_hex().unwrap(),
                actual.semantic_hash_hex().unwrap()
            );
        }
    }
}

pub fn decision_cases() -> Vec<(ValidationRequestV1, ValidationReportV1)> {
    let contract = super::common::derive_contract_from_fixture("linux-bare-metal-like-v1");
    let state = super::common::collect_state_fixture("linux-bare-metal-like-fresh-v1");
    [
        ValidationModeV1::ContractOnly,
        ValidationModeV1::StateRequired,
    ]
    .into_iter()
    .map(|mode| {
        let state_required = mode == ValidationModeV1::StateRequired;
        let request = ValidationRequestV1 {
            contract: contract.clone(),
            service_profile: super::common::load_service_profile_file(if state_required {
                "general_compute_stateful_thresholds.v2.json"
            } else {
                "general_compute_contract_only.v2.json"
            }),
            host_state: state_required.then(|| state.clone()),
            thermal_evidence: vec![],
            mode,
            validated_at: super::common::FIXED_TIMESTAMP.into(),
            notes: None,
            max_state_age_seconds: state_required.then_some(3600),
        };
        let expected = validate_request_v1(request.clone()).unwrap();
        (request, expected)
    })
    .collect()
}
