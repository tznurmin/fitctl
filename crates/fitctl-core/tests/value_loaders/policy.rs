// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use serde_json::{json, Value};

use super::support::{assert_case, policy, Family};

#[test]
fn policy_value_path_matrix() {
    assert_case(Family::Policy, "valid", policy(), None);
    let mut omitted = policy();
    omitted.as_object_mut().unwrap().remove("display_name");
    omitted
        .as_object_mut()
        .unwrap()
        .remove("short_display_name");
    assert_case(Family::Policy, "omitted labels", omitted, None);

    for (pointer, replacement) in [
        ("/display_name", Value::Null),
        ("/schema_id", json!("unknown")),
        ("/schema_version", json!(2)),
        ("/policy_id", json!(" ")),
        ("/policy_id", json!(7)),
        ("/layers", json!({})),
        ("/layers/0/layer_id", json!("")),
        ("/layers/1/layer_id", json!("defaults/general_compute")),
        ("/layers/0/rules/min_cpu_logical_cores", Value::Null),
        (
            "/extension_policy/allowed_extension_namespaces",
            json!(["x", "x"]),
        ),
    ] {
        let mut raw = policy();
        *raw.pointer_mut(pointer).unwrap() = replacement;
        assert_case(
            Family::Policy,
            pointer,
            raw,
            Some(("policy_document_invalid", "policy_load")),
        );
    }
    for pointer in ["", "/layers/0", "/layers/0/rules", "/extension_policy"] {
        let mut raw = policy();
        raw.pointer_mut(pointer).unwrap()["unknown"] = json!(true);
        assert_case(
            Family::Policy,
            pointer,
            raw,
            Some(("policy_document_invalid", "policy_load")),
        );
    }
    let mut missing = policy();
    missing.as_object_mut().unwrap().remove("policy_id");
    for raw in [missing, json!([]), Value::Null] {
        assert_case(
            Family::Policy,
            "missing/nonobject",
            raw,
            Some(("policy_document_invalid", "policy_load")),
        );
    }
    for vendor in ["", "nvidia"] {
        let mut raw = policy();
        raw["layers"][0]["rules"]["required_accelerator_vendor"] = json!(vendor);
        assert_case(
            Family::Policy,
            "accelerator scope",
            raw,
            Some(("policy_document_invalid", "policy_scope_validate")),
        );
    }
}
