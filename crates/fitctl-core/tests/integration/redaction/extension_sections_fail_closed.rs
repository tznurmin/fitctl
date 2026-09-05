// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use crate::common;
use fitctl_core::artifacts::contract_v1::ContractExtensionBasisV1;
use fitctl_core::artifacts::record_v1::ArtifactRecordV1;
use fitctl_core::redact::{redact_artifact_v1, BuiltInRedactionProfileV1, RedactionRequestV1};
use serde_json::json;

const UNKNOWN_NAMESPACE: &str = "example.site.runtime";
const UNKNOWN_SENTINEL: &str = "release-redaction-sensitive-unknown-extension";
const UNKNOWN_HASH: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

fn records_with_unknown_extension_sections() -> Vec<(&'static str, ArtifactRecordV1)> {
    let unknown = json!({
        "host": UNKNOWN_SENTINEL,
        "configuration_path": "/sensitive/release-redaction/extension.json"
    });

    let mut survey = common::collect_survey_fixture("linux-bare-metal-like-v1");
    survey.survey["extension_evidence"][UNKNOWN_NAMESPACE] = unknown.clone();

    let mut contract = common::derive_contract_from_fixture("linux-bare-metal-like-v1");
    contract.contract_basis.extension_basis = Some(ContractExtensionBasisV1 {
        enabled_extension_namespaces: vec![UNKNOWN_NAMESPACE.to_string()],
        extension_semantic_hashes: BTreeMap::from([(
            UNKNOWN_NAMESPACE.to_string(),
            UNKNOWN_HASH.to_string(),
        )]),
    });
    contract.contract["extension_contract"][UNKNOWN_NAMESPACE] = unknown.clone();

    let mut profile =
        common::load_service_profile_file("general_compute_no_gpu_contract_only.v2.json");
    profile
        .profile
        .extension_requirements
        .insert(UNKNOWN_NAMESPACE.to_string(), unknown.clone());

    let mut state = common::collect_state_fixture("linux-gpu-workstation-like-fresh-v1");
    state
        .state
        .extension_state
        .insert(UNKNOWN_NAMESPACE.to_string(), unknown.clone());

    let mut validation = common::validate_with_profile(
        common::derive_contract_from_fixture("linux-bare-metal-like-v1"),
        common::load_service_profile_file("general_compute_no_gpu_contract_only.v2.json"),
        None,
        fitctl_core::artifacts::validation_report_v1::ValidationModeV1::ContractOnly,
        None,
    );
    validation
        .report
        .extension_diagnostics
        .insert(UNKNOWN_NAMESPACE.to_string(), unknown);

    vec![
        ("extension_evidence", ArtifactRecordV1::Survey(survey)),
        ("extension_contract", ArtifactRecordV1::Contract(contract)),
        (
            "extension_requirements",
            ArtifactRecordV1::ServiceProfile(profile),
        ),
        ("extension_state", ArtifactRecordV1::State(state)),
        (
            "extension_diagnostics",
            ArtifactRecordV1::ValidationReport(validation),
        ),
    ]
}

#[test]
fn unknown_extension_sections_fail_closed_for_sharing_profiles() {
    for profile in [
        BuiltInRedactionProfileV1::Auditor,
        BuiltInRedactionProfileV1::External,
    ] {
        for (section, artifact) in records_with_unknown_extension_sections() {
            let result = redact_artifact_v1(RedactionRequestV1 {
                artifact,
                profile,
                redacted_at: common::FIXED_TIMESTAMP.to_string(),
            });
            let error = match result {
                Ok(_) => panic!("{section} must reject an unknown namespace for {profile:?}"),
                Err(error) => error,
            };

            assert_eq!(error.code.as_str(), "extension_redactor_unavailable");
            assert_eq!(error.checkpoint_id, "extension_redaction_dispatch");
            assert!(error.message.contains(UNKNOWN_NAMESPACE));
            assert!(error.message.contains(section));
        }
    }
}

#[test]
fn unknown_extension_sections_remain_compatible_inside_operator_boundary() {
    for profile in [
        BuiltInRedactionProfileV1::Local,
        BuiltInRedactionProfileV1::Fleet,
    ] {
        for (section, artifact) in records_with_unknown_extension_sections() {
            let redacted = redact_artifact_v1(RedactionRequestV1 {
                artifact,
                profile,
                redacted_at: common::FIXED_TIMESTAMP.to_string(),
            })
            .unwrap_or_else(|error| {
                panic!("{section} should remain compatible for {profile:?}: {error}")
            });
            let rendered = serde_json::to_string(&redacted).expect("artifact should encode");
            assert!(rendered.contains(UNKNOWN_SENTINEL));
        }
    }
}
