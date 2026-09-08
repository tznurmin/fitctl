// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use fitctl_core::artifacts::record_v1::load_artifact_record_from_value;
use serde_json::{json, Value};

use super::support::{assert_case, profile, Family};

#[test]
fn profile_value_path_matrix() {
    assert_case(Family::Profile, "valid", profile(), None);
    let mut omitted = profile();
    omitted["profile"]
        .as_object_mut()
        .unwrap()
        .remove("display_name");
    omitted["profile"]
        .as_object_mut()
        .unwrap()
        .remove("short_display_name");
    assert_case(Family::Profile, "omitted labels", omitted, None);
    for (pointer, value, code, checkpoint) in [
        (
            "/profile/display_name",
            Value::Null,
            "service_profile_document_invalid",
            "profile_decode",
        ),
        (
            "/envelope/schema_id",
            json!("unknown"),
            "service_profile_schema_unsupported",
            "profile_validate",
        ),
        (
            "/envelope/schema_version",
            json!(1),
            "service_profile_schema_unsupported",
            "profile_validate",
        ),
        (
            "/profile/profile_id",
            json!(" "),
            "service_profile_requirement_invalid",
            "profile_validate",
        ),
        (
            "/profile/core_requirements",
            json!([]),
            "service_profile_document_invalid",
            "profile_decode",
        ),
    ] {
        let mut raw = profile();
        *raw.pointer_mut(pointer).unwrap() = value;
        assert_case(Family::Profile, pointer, raw, Some((code, checkpoint)));
    }
    for pointer in [
        "",
        "/profile",
        "/envelope",
        "/envelope/provenance",
        "/profile/core_requirements",
    ] {
        let mut raw = profile();
        raw.pointer_mut(pointer).unwrap()["unknown"] = json!(true);
        assert_case(
            Family::Profile,
            pointer,
            raw,
            Some(("service_profile_document_invalid", "profile_decode")),
        );
    }
}

#[test]
fn generic_profile_route_is_not_validated_ingress() {
    let mut raw = profile();
    raw["profile"]["display_name"] = Value::Null;
    assert!(load_artifact_record_from_value(raw.clone()).is_ok());
    assert_case(
        Family::Profile,
        "specialized null rejection",
        raw,
        Some(("service_profile_document_invalid", "profile_decode")),
    );
}
