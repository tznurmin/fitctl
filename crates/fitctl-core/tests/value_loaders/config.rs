// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use serde_json::{json, Value};

use super::support::{assert_case, context, pack, Family};

#[test]
fn extension_pack_value_path_matrix() {
    assert_case(Family::Pack, "valid", pack(), None);
    for (pointer, replacement, checkpoint) in [
        ("/pack_id", Value::Null, "config_validate"),
        ("/pack_id", json!(" "), "config_validate"),
        ("/pack_id", json!(false), "config_load"),
        ("/schema_id", json!("unknown"), "config_validate"),
        ("/schema_version", json!(2), "config_validate"),
        (
            "/collector_ids",
            json!(["duplicate", "duplicate"]),
            "config_validate",
        ),
        (
            "/emitted_sections/0/schema_version",
            json!(0),
            "config_validate",
        ),
        (
            "/emitted_sections/0/section_kind",
            json!("unknown"),
            "config_load",
        ),
    ] {
        let mut raw = pack();
        *raw.pointer_mut(pointer).unwrap() = replacement;
        assert_case(
            Family::Pack,
            pointer,
            raw,
            Some(("config_input_invalid", checkpoint)),
        );
    }
    for pointer in ["", "/emitted_sections/0"] {
        let mut raw = pack();
        raw.pointer_mut(pointer).unwrap()["unknown"] = json!(true);
        assert_case(
            Family::Pack,
            pointer,
            raw,
            Some(("config_input_invalid", "config_validate")),
        );
    }
    let mut duplicate = pack();
    duplicate["emitted_sections"][1] = duplicate["emitted_sections"][0].clone();
    assert_case(
        Family::Pack,
        "duplicate section",
        duplicate,
        Some(("config_input_invalid", "config_validate")),
    );
    for raw in [json!([]), Value::Null] {
        assert_case(
            Family::Pack,
            "nonobject",
            raw,
            Some(("config_input_invalid", "config_validate")),
        );
    }
    let mut missing = pack();
    missing.as_object_mut().unwrap().remove("namespace_owner");
    assert_case(
        Family::Pack,
        "missing owner",
        missing,
        Some(("config_input_invalid", "config_load")),
    );
}

#[test]
fn invocation_context_value_path_matrix() {
    assert_case(Family::Context, "valid", context(), None);
    for (pointer, replacement, checkpoint) in [
        ("/invocation_id", Value::Null, "config_validate"),
        ("/invocation_id", json!(" "), "config_validate"),
        ("/invocation_id", json!([]), "config_load"),
        ("/schema_id", json!("unknown"), "config_validate"),
        ("/schema_version", json!(2), "config_validate"),
        (
            "/enabled_extension_namespaces",
            json!(["x", "x"]),
            "config_validate",
        ),
        (
            "/selected_recommendation_pack_ids",
            json!(["x", "x"]),
            "config_validate",
        ),
        (
            "/enabled_simulation_layer_ids",
            json!(["x", "x"]),
            "config_validate",
        ),
        ("/validation_mode", json!("unknown"), "config_load"),
    ] {
        let mut raw = context();
        *raw.pointer_mut(pointer).unwrap() = replacement;
        assert_case(
            Family::Context,
            pointer,
            raw,
            Some(("config_input_invalid", checkpoint)),
        );
    }
    let mut unknown = context();
    unknown["unknown"] = json!(true);
    assert_case(
        Family::Context,
        "unknown",
        unknown,
        Some(("config_input_invalid", "config_validate")),
    );
    let mut minimal = context();
    minimal
        .as_object_mut()
        .unwrap()
        .retain(|key, _| ["schema_id", "schema_version", "invocation_id"].contains(&key.as_str()));
    assert_case(Family::Context, "omitted optionals", minimal, None);
    for (field, value) in [
        ("selected_policy_id", Value::Null),
        ("selected_service_profile_id", json!(" ")),
        ("max_state_age_seconds", json!(0)),
        ("validation_mode", json!("state_aware")),
    ] {
        let mut raw = context();
        raw[field] = value;
        assert_case(
            Family::Context,
            field,
            raw,
            Some(("config_input_invalid", "config_validate")),
        );
    }
    for raw in [json!([]), Value::Null] {
        assert_case(
            Family::Context,
            "nonobject",
            raw,
            Some(("config_input_invalid", "config_validate")),
        );
    }
    let mut missing = context();
    missing.as_object_mut().unwrap().remove("invocation_id");
    assert_case(
        Family::Context,
        "missing id",
        missing,
        Some(("config_input_invalid", "config_load")),
    );
}
