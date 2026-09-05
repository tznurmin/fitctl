// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use fitctl_core::artifacts::record_v1::{load_artifact_record_from_value, ArtifactRecordV1};
use fitctl_core::bundle::{assemble_decision_bundle_v1, DecisionBundleAssemblyRequestV1};
use fitctl_core::redact::{
    redact_artifact_v1, BuiltInRedactionProfileV1, RedactionErrorCode, RedactionRequestV1,
};
use fitctl_core::validate::ValidationModeV1;
use serde_json::Value;

use crate::common;

const SENTINEL: &str = "audit-only-nested-provenance-83";
const SLOTS: [&str; 3] = ["contract", "state", "validation_report"];

#[test]
fn imported_bundle_core_versions_are_sanitized_without_breaking_lineage() {
    for profile in sharing_profiles() {
        let mut input = bundle();
        for slot in SLOTS {
            input["bundle"][slot]["envelope"]["provenance"]["fitctl_version"] =
                format!("0.6.0-{SENTINEL}").into();
        }
        let output = redact(input.clone(), profile).expect("bundle should redact");
        let encoded = serde_json::to_string(&output).unwrap();
        assert!(!encoded.contains(SENTINEL));
        let output = serde_json::to_value(output).unwrap();
        for slot in SLOTS {
            let provenance = &output["bundle"][slot]["envelope"]["provenance"];
            assert_eq!(
                provenance["fitctl_version"],
                format!("redacted:{}:fitctl_version", profile.as_str())
            );
            assert_eq!(
                provenance["command_name"],
                input["bundle"][slot]["envelope"]["provenance"]["command_name"]
            );
        }
        load_artifact_record_from_value(output).expect("complete bundle lineage must validate");
    }
}

#[test]
fn imported_bundle_each_bad_core_timestamp_rejects_the_whole_transform() {
    for profile in sharing_profiles() {
        for slot in SLOTS {
            let mut input = bundle();
            input["bundle"][slot]["envelope"]["provenance"]["collected_at"] = SENTINEL.into();
            let error = redact(input, profile).expect_err("bad nested envelope must fail closed");
            assert_eq!(error.code, RedactionErrorCode::ArtifactInputInvalid);
            assert_eq!(error.checkpoint_id, "provenance_validate");
            assert!(!error.message.contains(SENTINEL));
        }
    }
}

#[test]
fn imported_bundle_local_and_fleet_keep_nested_provenance_compatibility() {
    for profile in [
        BuiltInRedactionProfileV1::Local,
        BuiltInRedactionProfileV1::Fleet,
    ] {
        let mut input = bundle();
        for slot in SLOTS {
            let provenance = &mut input["bundle"][slot]["envelope"]["provenance"];
            provenance["collected_at"] = SENTINEL.into();
            provenance["fitctl_version"] = SENTINEL.into();
        }
        let output = redact(input, profile).expect("legacy-compatible bundle should redact");
        let output = serde_json::to_value(output).unwrap();
        for slot in SLOTS {
            let provenance = &output["bundle"][slot]["envelope"]["provenance"];
            assert_eq!(provenance["collected_at"], SENTINEL);
            assert_eq!(provenance["fitctl_version"], SENTINEL);
        }
        load_artifact_record_from_value(output).expect("output should validate");
    }
}

fn bundle() -> Value {
    let contract = common::derive_contract_from_fixture("linux-bare-metal-like-v1");
    let state = common::collect_state_fixture("linux-bare-metal-like-fresh-v1");
    let validation_report = common::validate_with_profile(
        contract.clone(),
        common::load_service_profile_file("general_compute_stateful_thresholds.v2.json"),
        Some(state.clone()),
        ValidationModeV1::StateRequired,
        Some(600),
    );
    let artifact = assemble_decision_bundle_v1(DecisionBundleAssemblyRequestV1 {
        validation_report,
        contract,
        state: Some(state),
        resolved_config: None,
        config_bundle: None,
        verification_bundle: None,
        recommendation_report: None,
        bundled_at: common::FIXED_TIMESTAMP.to_string(),
        notes: None,
    })
    .expect("stateful fixture bundle should assemble");
    serde_json::to_value(artifact).unwrap()
}

fn redact(
    input: Value,
    profile: BuiltInRedactionProfileV1,
) -> Result<ArtifactRecordV1, fitctl_core::redact::RedactionError> {
    redact_artifact_v1(RedactionRequestV1 {
        artifact: load_artifact_record_from_value(input).expect("input bundle must be valid"),
        profile,
        redacted_at: common::FIXED_TIMESTAMP.to_string(),
    })
}

fn sharing_profiles() -> [BuiltInRedactionProfileV1; 2] {
    [
        BuiltInRedactionProfileV1::Auditor,
        BuiltInRedactionProfileV1::External,
    ]
}
