// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common;
use fitctl_core::artifacts::record_v1::{
    load_artifact_record_from_path, load_artifact_record_from_value,
};
use serde_json::{json, Value};

const SENTINEL: &str = "customer-alpha:/srv/private/runtime";

fn conformance_value(file_name: &str) -> Value {
    load_artifact_record_from_path(
        &common::repo_root()
            .join("fixtures/conformance/valid")
            .join(file_name),
    )
    .expect("conformance artifact should load")
    .full_artifact_json()
    .expect("artifact should encode")
}

#[test]
fn imported_survey_rejects_unknown_collection_mode() {
    let mut value = conformance_value("host-survey.local-stable-identity-v2.v2.json");
    value["survey"]["collection_mode"] = json!(SENTINEL);

    let error = load_artifact_record_from_value(value)
        .expect_err("unknown survey collection mode must fail closed");
    assert!(error.message.contains("collection_mode"));
    assert!(error.message.contains("supported"));
}

#[test]
fn imported_state_rejects_unknown_provider_error_codes() {
    let mut thermal = conformance_value("host-state.thermal-resources.v2.json");
    thermal["state"]["core_state"]["thermal_resources"]["providers"][0]["outcome"] =
        json!("partial");
    thermal["state"]["core_state"]["thermal_resources"]["providers"][0]["error_code"] =
        json!(SENTINEL);

    let mut memory = conformance_value("host-state.thermal-resources.v2.json");
    memory["state"]["core_state"]["memory_reliability"] = json!({
        "observed_at": common::FIXED_TIMESTAMP,
        "providers": [{
            "provider_id": "local-edac-sysfs",
            "provider_kind": "edac_sysfs",
            "outcome": "partial",
            "observed_at": common::FIXED_TIMESTAMP,
            "error_code": SENTINEL
        }]
    });

    let mut gpu = conformance_value("host-state.thermal-resources.v2.json");
    gpu["state"]["core_state"]["gpu_reliability"] = json!({
        "observed_at": common::FIXED_TIMESTAMP,
        "providers": [{
            "provider_id": "local-nvidia-smi",
            "provider_kind": "nvidia_smi_xml",
            "outcome": "partial",
            "observed_at": common::FIXED_TIMESTAMP,
            "error_code": SENTINEL
        }],
        "devices": []
    });

    for (label, value) in [("thermal", thermal), ("memory", memory), ("GPU", gpu)] {
        let error = load_artifact_record_from_value(value)
            .expect_err("unknown provider error code must fail closed");
        assert!(error.message.contains(label), "{}", error.message);
        assert!(error.message.contains("error_code"), "{}", error.message);
        assert!(error.message.contains("supported"), "{}", error.message);
    }
}
