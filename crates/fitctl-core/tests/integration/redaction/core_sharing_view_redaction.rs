// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common;
use fitctl_core::artifacts::record_v1::{
    load_artifact_record_from_path, load_artifact_record_from_value, ArtifactRecordV1,
};
use fitctl_core::redact::{redact_artifact_v1, BuiltInRedactionProfileV1, RedactionRequestV1};
use serde_json::{json, Value};

const SENTINEL: &str = "core-sharing-sensitive";
const PCI_SENTINEL: &str = "0000:de:1a.0";
const DEVICE_NODE_SENTINEL: &str = "/dev/core-sharing-sensitive-gpu0";
const RENDER_NODE_SENTINEL: &str = "/dev/dri/renderD999";

fn load_conformance(file_name: &str) -> ArtifactRecordV1 {
    load_artifact_record_from_path(
        &common::repo_root()
            .join("fixtures/conformance/valid")
            .join(file_name),
    )
    .expect("conformance artifact should load")
}

fn decode_modified(value: Value) -> ArtifactRecordV1 {
    load_artifact_record_from_value(value).expect("modified artifact should remain valid")
}

fn populate_claim_metadata(metadata: &mut Value, scope: &str) {
    metadata["source_collectors"] = json!([format!("{SENTINEL}-{scope}-collector")]);
    metadata["evidence_paths"] = json!([format!("/{SENTINEL}/{scope}/evidence")]);
    metadata["policy_rule_id"] = json!(format!("{SENTINEL}-{scope}-rule"));
    metadata["trust_evidence_refs"] = json!([format!("{SENTINEL}-{scope}-trust")]);
}

fn sensitive_survey() -> ArtifactRecordV1 {
    let mut value = load_conformance("host-survey.cuda-default-view-version-split.v2.json")
        .full_artifact_json()
        .expect("survey should encode");
    for (scope, metadata) in value["survey"]["core_evidence"]["section_metadata"]
        .as_object_mut()
        .expect("section metadata should be an object")
    {
        populate_claim_metadata(metadata, scope);
    }
    value["survey"]["core_evidence"]["execution_context"]["container_runtime"] =
        json!(format!("{SENTINEL}-container-runtime"));
    value["survey"]["core_evidence"]["execution_context"]["notes"] =
        json!([format!("{SENTINEL}-execution-note")]);
    value["survey"]["core_evidence"]["identity_summary"]["composition_digest"] =
        json!(format!("{SENTINEL}-composition"));
    let accelerators =
        &mut value["survey"]["core_evidence"]["observations"]["accelerators"]["value"];
    accelerators["devices"][0]["pci_address"] = json!(PCI_SENTINEL);
    accelerators["operability"]["visible_device_nodes"] =
        json!([DEVICE_NODE_SENTINEL, RENDER_NODE_SENTINEL]);
    accelerators["operability"]["visible_render_nodes"] = json!([RENDER_NODE_SENTINEL]);
    decode_modified(value)
}

fn sensitive_contract() -> ArtifactRecordV1 {
    let mut value = load_conformance("host-contract.cuda-default-view-version-split.v2.json")
        .full_artifact_json()
        .expect("contract should encode");
    value["display_name"] = json!(format!("{SENTINEL}-display"));
    value["short_display_name"] = json!(format!("{SENTINEL}-short"));
    value["contract_basis"]["derivation_provenance"]["notes"] = json!(format!("{SENTINEL}-note"));
    value["contract_basis"]["core_semantic_basis"]["selected_policy_layers"] =
        json!([format!("{SENTINEL}-policy")]);
    value["contract_basis"]["core_semantic_basis"]["derivation_engine_id"] =
        json!(format!("{SENTINEL}-derivation-engine"));
    value["contract_basis"]["core_semantic_basis"]["derivation_engine_version"] =
        json!(format!("{SENTINEL}-derivation-version"));

    let classes = value["contract"]["core_contract"]["capability_classes"]
        .as_object_mut()
        .expect("capability classes should be an object");
    let mut claim = classes
        .remove("general_compute")
        .expect("fixture should contain the general compute claim");
    claim["rule_ids"] = json!([format!("{SENTINEL}-claim-rule")]);
    claim["evidence_refs"] = json!([format!("/{SENTINEL}/claim-evidence")]);
    claim["summary"] = json!(format!("{SENTINEL}-claim-summary"));
    populate_claim_metadata(&mut claim["claim_metadata"], "contract-claim");
    classes.insert(format!("{SENTINEL}-capability"), claim);

    let identity = &mut value["contract"]["core_contract"]["identity_summary"];
    identity["composition_digest"] = json!(format!("{SENTINEL}-contract-composition"));
    value["contract"]["core_contract"]["execution_constraints"]["container_runtime"] =
        json!(format!("{SENTINEL}-contract-runtime"));
    let operability = &mut value["contract"]["core_contract"]["accelerator_summary"]["operability"];
    operability["visible_device_nodes"] = json!([DEVICE_NODE_SENTINEL, RENDER_NODE_SENTINEL]);
    operability["visible_render_nodes"] = json!([RENDER_NODE_SENTINEL]);
    decode_modified(value)
}

fn assert_no_sensitive_core_values(artifact: &ArtifactRecordV1) {
    let rendered = serde_json::to_string(artifact).expect("artifact should encode");
    for prohibited in [
        SENTINEL,
        PCI_SENTINEL,
        DEVICE_NODE_SENTINEL,
        RENDER_NODE_SENTINEL,
    ] {
        assert!(
            !rendered.contains(prohibited),
            "{prohibited} survived: {rendered}"
        );
    }
}

#[test]
fn core_claim_metadata_sentinels_do_not_survive_sharing_profiles() {
    for profile in [
        BuiltInRedactionProfileV1::Auditor,
        BuiltInRedactionProfileV1::External,
    ] {
        for artifact in [sensitive_survey(), sensitive_contract()] {
            let redacted = redact_artifact_v1(RedactionRequestV1 {
                artifact,
                profile,
                redacted_at: common::FIXED_TIMESTAMP.to_string(),
            })
            .expect("sharing view should redact");
            assert_no_sensitive_core_values(&redacted);
        }
    }
}

#[test]
fn identity_and_accelerator_topology_are_minimized() {
    for artifact in [sensitive_survey(), sensitive_contract()] {
        let redacted = redact_artifact_v1(RedactionRequestV1 {
            artifact,
            profile: BuiltInRedactionProfileV1::External,
            redacted_at: common::FIXED_TIMESTAMP.to_string(),
        })
        .expect("external view should redact");
        let value = redacted
            .full_artifact_json()
            .expect("artifact should encode");
        let identity = value
            .pointer("/survey/core_evidence/identity_summary")
            .or_else(|| value.pointer("/contract/core_contract/identity_summary"))
            .expect("identity summary should remain present");
        assert_eq!(identity["identity_class"], "redacted");
        assert!(identity.get("local_stable_id_version").is_none());
        assert!(identity.get("local_stable_anchor_family").is_none());
        assert_no_sensitive_core_values(&redacted);
    }
}

#[test]
fn contract_core_sentinels_do_not_survive_sharing_profiles() {
    for profile in [
        BuiltInRedactionProfileV1::Auditor,
        BuiltInRedactionProfileV1::External,
    ] {
        let redacted = redact_artifact_v1(RedactionRequestV1 {
            artifact: sensitive_contract(),
            profile,
            redacted_at: common::FIXED_TIMESTAMP.to_string(),
        })
        .expect("contract sharing view should redact");
        assert_no_sensitive_core_values(&redacted);
    }
}

#[test]
fn redacted_identity_rejects_local_anchor_metadata() {
    let mut value = load_conformance("host-survey.local-stable-identity-v2.v2.json")
        .full_artifact_json()
        .expect("survey should encode");
    value["survey"]["core_evidence"]["identity_summary"]["identity_class"] = json!("redacted");

    let error = load_artifact_record_from_value(value)
        .expect_err("redacted identity with local anchor metadata must fail closed");
    assert!(error
        .message
        .contains("must not carry local identity derivation metadata"));
}
