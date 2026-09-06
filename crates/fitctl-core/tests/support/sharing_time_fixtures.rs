// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use std::{fs, path::PathBuf};

use fitctl_core::artifacts::record_v1::ArtifactRecordV1;
use fitctl_core::bundle::{assemble_decision_bundle_v1, DecisionBundleAssemblyRequestV1};
use fitctl_core::classify::{classify_batch_v1, BatchClassificationRequestV1};
use fitctl_core::recommendation::{evaluate_recommendation_v1, RecommendationRequestV1};
use fitctl_core::validate::ValidationModeV1;
use fitctl_core::verify::{
    build_verification_bundle_v1, verify_artifact_with_policy_and_evidence_at_v1,
};
use serde_json::{json, Value};

use crate::common;

pub const SENTINEL: &str = "audit-only-private-sensor-time-070";

pub fn fixture(name: &str) -> Value {
    serde_json::from_slice(
        &fs::read(
            common::repo_root()
                .join("fixtures/conformance/valid")
                .join(name),
        )
        .unwrap(),
    )
    .unwrap()
}

pub fn rich_state() -> Value {
    let mut value = serde_json::to_value(common::collect_state_fixture(
        "linux-gpu-workstation-like-path-resources-fit-v1",
    ))
    .unwrap();
    let core = &mut value["state"]["core_state"];
    core["hardware_sensor_resources"] = fixture("host-state.hardware-sensors.v2.json")["state"]
        ["core_state"]["hardware_sensor_resources"]
        .clone();
    core["thermal_resources"] = fixture("host-state.thermal-resources.v2.json")["state"]
        ["core_state"]["thermal_resources"]
        .clone();
    let observed = |value: Value| json!({"state": "observed", "value": value});
    core["memory_reliability"] = json!({
        "observed_at": common::FIXED_TIMESTAMP,
        "providers": [{"provider_id": "local-edac", "provider_kind": "edac_sysfs",
            "outcome": "success", "observed_at": common::FIXED_TIMESTAMP}],
        "controller_count": observed(json!(1)), "dimm_count": observed(json!(8)),
        "corrected_error_count": observed(json!(0)), "uncorrected_error_count": observed(json!(0))
    });
    core["gpu_reliability"] = json!({
        "observed_at": common::FIXED_TIMESTAMP,
        "providers": [{"provider_id": "local-nvidia-smi-reliability", "provider_kind": "nvidia_smi_xml",
            "outcome": "success", "observed_at": common::FIXED_TIMESTAMP}],
        "devices": []
    });
    let resources = &mut core["path_resources"];
    resources["paths"][0]["link_capabilities"] = json!({
        "hardlink_supported": observed(json!(true)), "reflink_supported": observed(json!(true)),
        "symlink_supported": observed(json!(true)), "copy_possible": observed(json!(true)),
        "observed_at": common::FIXED_TIMESTAMP
    });
    resources["paths"][0]["storage_health"] = json!({
        "health_state": observed(json!("ok")), "temperature_celsius": observed(json!(41)),
        "percentage_used": observed(json!(3)), "available_spare_percent": observed(json!(100)),
        "observed_at": common::FIXED_TIMESTAMP
    });
    resources["paths"][0]["observed_at"] = common::FIXED_TIMESTAMP.into();
    resources["link_pairs"] = json!([{
        "pair_id": "fixture-pair", "from_path_id": resources["paths"][0]["path_id"],
        "to_path_id": resources["paths"][1]["path_id"],
        "same_filesystem": observed(json!(true)), "hardlink_supported": observed(json!(true)),
        "reflink_supported": observed(json!(true)), "symlink_supported": observed(json!(true)),
        "copy_possible": observed(json!(true)), "observed_at": common::FIXED_TIMESTAMP
    }]);
    value
}

pub fn bundle() -> Value {
    let contract = common::derive_contract_from_fixture("linux-bare-metal-like-v1");
    let state = common::collect_state_fixture("linux-bare-metal-like-fresh-v1");
    let report = common::validate_with_profile(
        contract.clone(),
        common::load_service_profile_file("general_compute_stateful_thresholds.v2.json"),
        Some(state.clone()),
        ValidationModeV1::StateRequired,
        Some(600),
    );
    let recommendation_pack = serde_json::from_slice(
        &fs::read(common::repo_recommendation_pack_path(
            "general_compute_advisory.v1.json",
        ))
        .unwrap(),
    )
    .unwrap();
    let recommendation = evaluate_recommendation_v1(RecommendationRequestV1 {
        validation_report: report.clone(),
        recommendation_pack,
        recommended_at: common::FIXED_TIMESTAMP.into(),
    })
    .unwrap();
    let root = TestRoot(common::unique_temp_dir("sharing-time-verification"));
    let key = common::generate_ed25519_keypair(&root.0, "fixture-key");
    let record = common::sign_artifact(ArtifactRecordV1::Contract(contract.clone()), &key);
    let signer = &record.envelope().signatures[0].key_id;
    let verification = verify_artifact_with_policy_and_evidence_at_v1(
        &record,
        &common::trust_policy_for_signer(signer),
        &[],
        common::FIXED_TIMESTAMP,
    )
    .unwrap();
    let verification =
        build_verification_bundle_v1(&record, &verification, common::FIXED_TIMESTAMP).unwrap();
    serde_json::to_value(
        assemble_decision_bundle_v1(DecisionBundleAssemblyRequestV1 {
            validation_report: report,
            contract,
            state: Some(state),
            resolved_config: None,
            config_bundle: None,
            verification_bundle: Some(verification),
            recommendation_report: Some(recommendation),
            bundled_at: common::FIXED_TIMESTAMP.into(),
            notes: None,
        })
        .unwrap(),
    )
    .unwrap()
}

pub fn inputs() -> Vec<Value> {
    let bundle = bundle();
    let contract = common::derive_contract_from_fixture("linux-bare-metal-like-v1");
    let request = BatchClassificationRequestV1 {
        contracts: vec![contract],
        service_profiles: vec![common::load_service_profile_file(
            "general_compute_stateful_thresholds.v2.json",
        )],
        host_states: vec![common::collect_state_fixture(
            "linux-bare-metal-like-fresh-v1",
        )],
        validation_mode: ValidationModeV1::StateRequired,
        max_state_age_seconds: Some(600),
        validated_at: common::FIXED_TIMESTAMP.into(),
    };
    let batch = classify_batch_v1(request.clone()).unwrap();
    let batch = serde_json::to_value(batch).unwrap();
    let mut legacy = serde_json::to_value(
        classify_batch_v1(BatchClassificationRequestV1 {
            host_states: vec![],
            validation_mode: ValidationModeV1::ContractOnly,
            max_state_age_seconds: None,
            ..request
        })
        .unwrap(),
    )
    .unwrap();
    legacy["envelope"]["schema_id"] =
        fitctl_core::artifacts::schema_ids_v1::LEGACY_BATCH_CLASSIFICATION_REPORT_SCHEMA_ID.into();
    vec![
        rich_state(),
        fixture("thermal-evidence.out-of-band-bmc.v1.json"),
        bundle["bundle"]["contract"].clone(),
        bundle["bundle"]["validation_report"].clone(),
        bundle["bundle"]["recommendation_report"].clone(),
        batch,
        legacy,
        bundle,
    ]
}

// Test-only traversal enumerates retained time fields in validated fixture families.
pub fn time_paths(value: &Value, prefix: &str) -> Vec<String> {
    let mut paths = Vec::new();
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let path = format!("{prefix}/{key}");
                if matches!(
                    key.as_str(),
                    "observed_at"
                        | "state_observed_at"
                        | "derived_at"
                        | "validated_at"
                        | "produced_at"
                        | "verified_at"
                ) && child.is_string()
                {
                    paths.push(path);
                } else {
                    paths.extend(time_paths(child, &path));
                }
            }
        }
        Value::Array(array) => {
            for (index, child) in array.iter().enumerate() {
                paths.extend(time_paths(child, &format!("{prefix}/{index}")));
            }
        }
        _ => {}
    }
    paths
}

pub fn mutation_groups(value: &Value) -> Vec<Vec<String>> {
    let paths = time_paths(value, "");
    let hardware: Vec<_> = paths
        .iter()
        .filter(|path| path.contains("/hardware_sensor_resources/"))
        .cloned()
        .collect();
    let mut groups: Vec<_> = paths
        .into_iter()
        .filter(|path| {
            !path.contains("/hardware_sensor_resources/") && !path.contains("/verification_bundle/")
        })
        .map(|path| vec![path])
        .collect();
    if !hardware.is_empty() {
        groups.push(hardware);
    }
    groups
}

pub fn replace(value: &mut Value, paths: &[String], timestamp: &str) {
    for path in paths {
        *value
            .pointer_mut(path)
            .expect("declared fixture time exists") = timestamp.into();
    }
    if value.get("bundle").is_some() {
        refresh_bundle_lineage(value);
    }
}

// Imported fixture metadata may change report hashes; assemble valid lineage before redaction.
fn refresh_bundle_lineage(value: &mut Value) {
    let mut payload: fitctl_core::artifacts::decision_bundle_v1::DecisionBundlePayloadV1 =
        serde_json::from_value(value["bundle"].clone()).unwrap();
    let report_hash = ArtifactRecordV1::ValidationReport(payload.validation_report.clone())
        .semantic_hash_hex()
        .unwrap();
    if let Some(recommendation) = &mut payload.recommendation_report {
        recommendation
            .recommendation_basis
            .validation_report_semantic_hash = report_hash;
    }
    *value = serde_json::to_value(
        assemble_decision_bundle_v1(DecisionBundleAssemblyRequestV1 {
            validation_report: payload.validation_report,
            contract: payload.contract,
            state: payload.state,
            resolved_config: payload.resolved_config,
            config_bundle: payload.config_bundle,
            verification_bundle: payload.verification_bundle,
            recommendation_report: payload.recommendation_report,
            bundled_at: common::FIXED_TIMESTAMP.into(),
            notes: None,
        })
        .unwrap(),
    )
    .unwrap();
}

struct TestRoot(PathBuf);
impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
