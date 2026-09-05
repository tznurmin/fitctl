// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common;
use fitctl_core::artifacts::record_v1::{
    load_artifact_record_from_path, load_artifact_record_from_value, ArtifactRecordV1,
};
use fitctl_core::artifacts::validation_report_v1::{
    ValidationExplanationV1, ValidationModeV1, ValidationPathDiagnosticStatusV1,
    ValidationPathDiagnosticV1, ValidationReasonCodeV1, ValidationRemediationActionV1,
    ValidationRemediationHintV1, ValidationVerdictV1,
};
use fitctl_core::redact::{redact_artifact_v1, BuiltInRedactionProfileV1, RedactionRequestV1};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;

const SENTINEL: &str = "release-redaction-sensitive";

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

fn selected_environment_fields(state: bool) -> Value {
    let version = json!({"major": 12, "minor": 8, "patch": 1});
    let diagnostic = |name: &str| {
        json!({
            "source_tier": "primary",
            "source_kind": "command_probe",
            "source_ref": format!("/sensitive/{SENTINEL}/{name}"),
            "status": "observed"
        })
    };
    let version_value = |value: Value| {
        if state {
            json!({"state": "observed", "value": value})
        } else {
            value
        }
    };
    json!({
        "selected_environment": {
            "environment_id": format!("{SENTINEL}-environment"),
            "selection": {
                "kind": "toolkit_install_root",
                "install_root": format!("/sensitive/{SENTINEL}/selected-toolkit")
            }
        },
        "selected_environment_toolkit_version": version_value(version.clone()),
        "selected_environment_runtime_version": version_value(version),
        "selected_environment_probe_diagnostics": {
            "toolkit_version": diagnostic("selected-nvcc"),
            "runtime_version": diagnostic("selected-libcudart")
        }
    })
}

fn add_selected_environment(extension: &mut Value, state: bool) {
    let fields = selected_environment_fields(state);
    for field in [
        "selected_environment",
        "selected_environment_toolkit_version",
        "selected_environment_runtime_version",
        "selected_environment_probe_diagnostics",
    ] {
        extension[field] = fields[field].clone();
    }
}

fn sensitive_cuda_artifacts() -> Vec<ArtifactRecordV1> {
    let survey = load_conformance("host-survey.cuda-default-view-version-split.v2.json");
    let mut survey = survey.full_artifact_json().expect("survey should encode");
    let evidence = &mut survey["survey"]["extension_evidence"]["fitctl.runtime.cuda"];
    evidence["executable_path"] = json!(format!("/sensitive/{SENTINEL}/nvcc"));
    evidence["claim_metadata"]["source_collectors"] = json!([format!("{SENTINEL}-collector")]);
    evidence["claim_metadata"]["evidence_paths"] = json!([format!("/{SENTINEL}/evidence")]);
    evidence["claim_metadata"]["policy_rule_id"] = json!(format!("{SENTINEL}-rule"));
    evidence["claim_metadata"]["trust_evidence_refs"] = json!([format!("{SENTINEL}-trust")]);
    for (index, entry) in evidence["installed_toolkits"]
        .as_array_mut()
        .expect("toolkits should be an array")
        .iter_mut()
        .enumerate()
    {
        entry["install_root"] = json!(format!("/sensitive/{SENTINEL}/toolkit-{index}"));
    }
    for diagnostic in evidence["default_view_probe_diagnostics"]
        .as_object_mut()
        .expect("diagnostics should be an object")
        .values_mut()
    {
        diagnostic["source_ref"] = json!(format!("/sensitive/{SENTINEL}/default-probe"));
    }
    add_selected_environment(evidence, false);

    let contract = load_conformance("host-contract.cuda-default-view-version-split.v2.json");
    let mut contract = contract
        .full_artifact_json()
        .expect("contract should encode");
    let extension = &mut contract["contract"]["extension_contract"]["fitctl.runtime.cuda"];
    extension["claim_metadata"]["source_collectors"] =
        json!([format!("{SENTINEL}-contract-collector")]);
    extension["claim_metadata"]["evidence_paths"] =
        json!([format!("/{SENTINEL}/contract-evidence")]);
    for (index, entry) in extension["installed_toolkits"]
        .as_array_mut()
        .expect("toolkits should be an array")
        .iter_mut()
        .enumerate()
    {
        entry["install_root"] = json!(format!("/sensitive/{SENTINEL}/contract-toolkit-{index}"));
    }
    for diagnostic in extension["default_view_probe_diagnostics"]
        .as_object_mut()
        .expect("diagnostics should be an object")
        .values_mut()
    {
        diagnostic["source_ref"] = json!(format!("/sensitive/{SENTINEL}/contract-probe"));
    }
    add_selected_environment(extension, false);

    let state = load_conformance("host-state.cuda-default-view-version-split.v2.json");
    let mut state = state.full_artifact_json().expect("state should encode");
    let extension = &mut state["state"]["extension_state"]["fitctl.runtime.cuda"];
    extension["claim_metadata"]["source_collectors"] =
        json!([format!("{SENTINEL}-state-collector")]);
    extension["claim_metadata"]["evidence_paths"] = json!([format!("/{SENTINEL}/state-evidence")]);
    extension["devices"][0]["device_uuid"] = json!(format!("GPU-{SENTINEL}-uuid"));
    extension["probe_path"] = json!(format!("/sensitive/{SENTINEL}/probe"));
    for diagnostic in extension["default_view_probe_diagnostics"]
        .as_object_mut()
        .expect("diagnostics should be an object")
        .values_mut()
    {
        diagnostic["source_ref"] = json!(format!("/sensitive/{SENTINEL}/state-probe"));
    }
    add_selected_environment(extension, true);

    let validation = load_conformance("validation-report.cuda-runtime-multi-gpu-fit.v2.json");
    let mut validation = validation
        .full_artifact_json()
        .expect("validation should encode");
    let diagnostic = &mut validation["report"]["extension_diagnostics"]["fitctl.runtime.cuda"];
    diagnostic["related_requirements"] = json!([format!("{SENTINEL}-requirement")]);
    diagnostic["evidence_refs"] = json!([format!("/{SENTINEL}/diagnostic-evidence")]);

    vec![
        decode_modified(survey),
        decode_modified(contract),
        decode_modified(state),
        decode_modified(validation),
        ArtifactRecordV1::ServiceProfile(common::load_service_profile_file(
            "cuda_24gb_state_required.v2.json",
        )),
    ]
}

fn runtime_extension_fixture(runtime: &str) -> Value {
    let path = common::repo_root().join(format!(
        "fixtures/extensions/{runtime}_runtime/linux-bare-metal-like-v1.json"
    ));
    serde_json::from_str::<Value>(&fs::read_to_string(path).expect("fixture should read"))
        .expect("fixture should decode")["evidence"]
        .clone()
}

fn sensitive_runtime_survey() -> ArtifactRecordV1 {
    let survey = load_conformance("host-survey.local-stable-identity-v2.v2.json");
    let mut survey = survey.full_artifact_json().expect("survey should encode");
    for runtime in ["python", "node"] {
        let namespace = format!("fitctl.runtime.{runtime}");
        let mut evidence = runtime_extension_fixture(runtime);
        evidence["executable_path"] = json!(format!("/sensitive/{SENTINEL}/{runtime}"));
        evidence["claim_metadata"]["source_collectors"] =
            json!([format!("{SENTINEL}-{runtime}-collector")]);
        evidence["claim_metadata"]["evidence_paths"] =
            json!([format!("/{SENTINEL}/{runtime}-evidence")]);
        evidence["claim_metadata"]["policy_rule_id"] = json!(format!("{SENTINEL}-{runtime}-rule"));
        evidence["claim_metadata"]["trust_evidence_refs"] =
            json!([format!("{SENTINEL}-{runtime}-trust")]);
        survey["survey"]["extension_evidence"][namespace] = evidence;
    }
    decode_modified(survey)
}

#[test]
fn runtime_evidence_redaction_regression() {
    for profile in [
        BuiltInRedactionProfileV1::Auditor,
        BuiltInRedactionProfileV1::External,
    ] {
        let redacted = redact_artifact_v1(RedactionRequestV1 {
            artifact: sensitive_runtime_survey(),
            profile,
            redacted_at: common::FIXED_TIMESTAMP.to_string(),
        })
        .expect("known runtime evidence should redact");
        let rendered = serde_json::to_string(&redacted).expect("survey should encode");
        assert!(
            !rendered.contains(SENTINEL),
            "sentinel survived: {rendered}"
        );
        assert!(!rendered.contains("/usr/bin/python3"));
        assert!(!rendered.contains("/usr/bin/node"));
    }
}

#[test]
fn cuda_extension_sentinels_do_not_survive_complete_output() {
    for profile in [
        BuiltInRedactionProfileV1::Auditor,
        BuiltInRedactionProfileV1::External,
    ] {
        for artifact in sensitive_cuda_artifacts() {
            let redacted = redact_artifact_v1(RedactionRequestV1 {
                artifact,
                profile,
                redacted_at: common::FIXED_TIMESTAMP.to_string(),
            })
            .expect("known CUDA extension should redact");
            let rendered = serde_json::to_string(&redacted).expect("artifact should encode");
            assert!(
                !rendered.contains(SENTINEL),
                "sentinel survived: {rendered}"
            );
            for prohibited in [
                "/usr/local/cuda",
                "/proc/driver/nvidia/version",
                "libcuda.so.1",
                "libcudart.so",
                "GPU-7f64c1a9",
            ] {
                assert!(!rendered.contains(prohibited), "{prohibited} survived");
            }
        }
    }
}

#[test]
fn validation_sentinels_do_not_survive_complete_output() {
    let mut report = common::validate_with_profile(
        common::derive_contract_from_fixture("linux-bare-metal-like-v1"),
        common::load_service_profile_file("general_compute_no_gpu_contract_only.v2.json"),
        None,
        ValidationModeV1::ContractOnly,
        None,
    );
    report.report.matched_requirements = vec![format!("{SENTINEL}-matched")];
    report.report.evidence_refs = vec![format!("/{SENTINEL}/top-evidence")];
    report.report.policy_refs = vec![format!("{SENTINEL}-top-policy")];
    report.report.assurance_mismatches = vec![format!("{SENTINEL}-assurance")];
    report.report.warnings = vec![format!("{SENTINEL}-warning")];
    report.report.summary = format!("{SENTINEL}-summary");
    report.validation_basis.validation_engine_id = format!("{SENTINEL}-validation-engine");
    report.validation_basis.validation_engine_version = format!("{SENTINEL}-engine-version");
    report.report.explanations = vec![ValidationExplanationV1 {
        explanation_id: format!("{SENTINEL}-explanation"),
        reason_code: ValidationReasonCodeV1::RequirementsSatisfied,
        summary: format!("{SENTINEL}-explanation-summary"),
        related_requirements: vec![format!("{SENTINEL}-related")],
        evidence_refs: vec![format!("/{SENTINEL}/nested-evidence")],
        policy_refs: vec![format!("{SENTINEL}-nested-policy")],
    }];
    report.report.path_diagnostics = vec![ValidationPathDiagnosticV1 {
        diagnostic_id: format!("{SENTINEL}-diagnostic"),
        requirement_key: format!("{SENTINEL}-requirement"),
        path_ids: vec![format!("{SENTINEL}-path")],
        check_id: format!("{SENTINEL}-check"),
        status: ValidationPathDiagnosticStatusV1::Satisfied,
        reason_code: format!("{SENTINEL}-reason"),
        expected: BTreeMap::from([(
            format!("{SENTINEL}-expected-key"),
            format!("{SENTINEL}-expected-value"),
        )]),
        observed: BTreeMap::from([(
            format!("{SENTINEL}-observed-key"),
            format!("{SENTINEL}-observed-value"),
        )]),
        evidence_refs: vec![format!("/{SENTINEL}/path-evidence")],
    }];

    let redacted = redact_artifact_v1(RedactionRequestV1 {
        artifact: ArtifactRecordV1::ValidationReport(report),
        profile: BuiltInRedactionProfileV1::External,
        redacted_at: common::FIXED_TIMESTAMP.to_string(),
    })
    .expect("validation report should redact");
    let rendered = serde_json::to_string(&redacted).expect("report should encode");
    assert!(
        !rendered.contains(SENTINEL),
        "sentinel survived: {rendered}"
    );
}

#[test]
fn validation_remediation_text_does_not_survive_complete_output() {
    let mut report = common::validate_with_profile(
        common::derive_contract_from_fixture("linux-bare-metal-like-v1"),
        common::load_service_profile_file("general_compute_no_gpu_contract_only.v2.json"),
        None,
        ValidationModeV1::ContractOnly,
        None,
    );
    report.report.verdict = ValidationVerdictV1::Unfit;
    report.report.primary_reason_code = ValidationReasonCodeV1::RequirementUnsatisfied;
    report.report.matched_requirements.clear();
    report.report.failed_requirements = vec![format!("{SENTINEL}-failed")];
    report.report.explanations = vec![ValidationExplanationV1 {
        explanation_id: format!("{SENTINEL}-failure-explanation"),
        reason_code: ValidationReasonCodeV1::RequirementUnsatisfied,
        summary: format!("{SENTINEL}-failure-summary"),
        related_requirements: vec![format!("{SENTINEL}-failure-related")],
        evidence_refs: vec![],
        policy_refs: vec![],
    }];
    report.report.remediation_hints = vec![ValidationRemediationHintV1 {
        hint_id: format!("{SENTINEL}-hint"),
        reason_code: ValidationReasonCodeV1::RequirementUnsatisfied,
        summary: format!("{SENTINEL}-hint-summary"),
        actions: vec![ValidationRemediationActionV1 {
            action_id: format!("{SENTINEL}-action"),
            summary: format!("{SENTINEL}-action-summary"),
        }],
    }];
    report.report.summary = format!("{SENTINEL}-failure-report-summary");

    let redacted = redact_artifact_v1(RedactionRequestV1 {
        artifact: ArtifactRecordV1::ValidationReport(report),
        profile: BuiltInRedactionProfileV1::External,
        redacted_at: common::FIXED_TIMESTAMP.to_string(),
    })
    .expect("failure report should redact");
    let rendered = serde_json::to_string(&redacted).expect("report should encode");
    assert!(
        !rendered.contains(SENTINEL),
        "sentinel survived: {rendered}"
    );
}
