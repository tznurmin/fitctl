// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use fitctl_core::artifacts::envelope_v1::ArtifactProvenanceV1;
use fitctl_core::artifacts::record_v1::ArtifactRecordV1;
use fitctl_core::redact::{redact_artifact_v1, BuiltInRedactionProfileV1, RedactionRequestV1};
use fitctl_core::service_profile::{
    load_service_profile_from_path, load_service_profile_from_value,
};
use serde_json::{json, Value};

use super::support::{assert_case, profile, Family, TestRoot};

fn complete_provenance() -> Value {
    serde_json::to_value(ArtifactProvenanceV1 {
        source: "synthetic-profile".into(),
        collected_at: "2026-01-01T00:00:00Z".into(),
        fitctl_version: Some("0.8.0-dev".into()),
        fitctl_vcs_revision: Some("0123456789abcdef".into()),
        fitctl_vcs_describe: Some("synthetic-build".into()),
        fitctl_build_dirty: Some(false),
        command_name: Some("synthetic-profile-export".into()),
        correlation_id: Some("synthetic-operation-two".into()),
    })
    .unwrap()
}

fn enriched_profile() -> Value {
    let mut raw = profile();
    raw["envelope"]["provenance"] = complete_provenance();
    raw
}

fn assert_record_roundtrip(record: &ArtifactRecordV1) {
    let raw = record.full_artifact_json().unwrap();
    let root = TestRoot::new();
    let path = root.path("profile.json");
    std::fs::write(&path, serde_json::to_vec(&raw).unwrap()).unwrap();
    for result in [
        load_service_profile_from_value(raw.clone()),
        load_service_profile_from_path(&path),
    ] {
        let reloaded = ArtifactRecordV1::ServiceProfile(result.expect("unchanged export reloads"));
        assert_eq!(reloaded.full_artifact_json().unwrap(), raw);
        assert_eq!(
            reloaded.semantic_bytes().unwrap(),
            record.semantic_bytes().unwrap()
        );
        assert_eq!(
            reloaded.semantic_hash_hex().unwrap(),
            record.semantic_hash_hex().unwrap()
        );
    }
}

#[test]
fn profile_redacted_exports_roundtrip() {
    for raw in [profile(), enriched_profile()] {
        for builtin in [
            BuiltInRedactionProfileV1::Local,
            BuiltInRedactionProfileV1::Fleet,
            BuiltInRedactionProfileV1::Auditor,
            BuiltInRedactionProfileV1::External,
        ] {
            let input = load_service_profile_from_value(raw.clone()).unwrap();
            let redacted = redact_artifact_v1(RedactionRequestV1 {
                artifact: ArtifactRecordV1::ServiceProfile(input),
                profile: builtin,
                redacted_at: "2026-01-01T00:00:00Z".into(),
            })
            .unwrap();
            let export = redacted.full_artifact_json().unwrap();
            assert_eq!(
                export["envelope"]["redaction"]["profile_id"],
                builtin.as_str()
            );
            if builtin != BuiltInRedactionProfileV1::Local {
                assert_eq!(
                    export["envelope"]["provenance"]["correlation_id"],
                    export["envelope"]["artifact_id"]
                );
            }
            assert_record_roundtrip(&redacted);
            let error = redact_artifact_v1(RedactionRequestV1 {
                artifact: redacted,
                profile: builtin,
                redacted_at: "2026-01-01T00:00:00Z".into(),
            })
            .unwrap_err();
            assert_eq!(error.code.as_str(), "redaction_input_already_redacted");
            assert_eq!(error.checkpoint_id, "redaction_preflight");
        }
    }
}

#[test]
fn profile_provenance_positive_matrix() {
    let mut cases = vec![profile(), enriched_profile()];
    for (field, value) in complete_provenance().as_object().unwrap() {
        let mut raw = profile();
        raw["envelope"]["provenance"][field] = value.clone();
        cases.push(raw);
    }
    let mut dirty = enriched_profile();
    dirty["envelope"]["provenance"]["fitctl_build_dirty"] = json!(true);
    cases.push(dirty);
    for raw in cases {
        let expected = raw["envelope"]["provenance"].clone();
        let loaded = load_service_profile_from_value(raw).unwrap();
        assert_eq!(
            serde_json::to_value(&loaded.envelope.provenance).unwrap(),
            expected
        );
        assert_record_roundtrip(&ArtifactRecordV1::ServiceProfile(loaded));
    }
}

#[test]
fn profile_provenance_decode_matrix() {
    for (field, valid) in complete_provenance().as_object().unwrap() {
        let mut invalid = vec![Value::Null, json!(0), json!([]), json!({})];
        invalid.push(if valid.is_boolean() {
            json!("false")
        } else {
            json!(false)
        });
        for value in invalid {
            let mut raw = enriched_profile();
            raw["envelope"]["provenance"][field] = value;
            decode_error(field, raw);
        }
    }
    for value in [
        Value::Null,
        json!([]),
        json!(0),
        json!(true),
        json!("provenance"),
    ] {
        let mut raw = profile();
        raw["envelope"]["provenance"] = value;
        decode_error("non-object", raw);
    }
    for field in ["source", "collected_at"] {
        let mut raw = enriched_profile();
        raw["envelope"]["provenance"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        decode_error(field, raw);
    }
    for mut raw in [profile(), enriched_profile()] {
        raw["envelope"]["provenance"]["unknown"] = json!("not an extension");
        decode_error("unknown", raw);
    }
}

#[test]
fn profile_provenance_blank_matrix() {
    for (field, valid) in complete_provenance().as_object().unwrap() {
        if !valid.is_string() {
            continue;
        }
        for blank in ["", " ", "\t\n"] {
            let mut raw = enriched_profile();
            raw["envelope"]["provenance"][field] = json!(blank);
            assert_case(
                Family::Profile,
                field,
                raw,
                Some(("service_profile_artifact_invalid", "profile_validate")),
            );
        }
    }
}

#[test]
fn profile_provenance_preserves_validation_pipeline() {
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
            "/profile/core_requirements/allowed_visibility_scopes",
            json!([]),
            "service_profile_requirement_invalid",
            "profile_validate",
        ),
        (
            "/envelope/artifact_id",
            json!(""),
            "service_profile_artifact_invalid",
            "profile_validate",
        ),
    ] {
        let mut raw = enriched_profile();
        *raw.pointer_mut(pointer).unwrap() = value;
        assert_case(Family::Profile, pointer, raw, Some((code, checkpoint)));
    }
}

fn decode_error(name: &str, raw: Value) {
    assert_case(
        Family::Profile,
        name,
        raw,
        Some(("service_profile_document_invalid", "profile_decode")),
    );
}
