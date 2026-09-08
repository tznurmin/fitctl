// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

#[path = "support/common.rs"]
mod common;

use fitctl_core::artifacts::record_v1::{load_artifact_record_from_value, ArtifactRecordV1};
use fitctl_core::artifacts::state_v1::HostStateV1;
use fitctl_core::artifacts::validation_v1::validate_host_state;
use fitctl_core::inspect::{render_artifact_summary_with_options_v1, InspectRenderOptionsV1};
use fitctl_core::redact::{redact_artifact_v1, BuiltInRedactionProfileV1, RedactionRequestV1};
use serde_json::{json, Value};

fn state() -> HostStateV1 {
    common::collect_state_fixture("linux-path-probe-cleanup-v1")
}
fn value() -> Value {
    serde_json::to_value(state()).unwrap()
}
fn single(value: &mut Value) -> &mut Value {
    &mut value["state"]["core_state"]["path_resources"]["paths"][0]["link_capabilities"]
}
fn pair(value: &mut Value) -> &mut Value {
    &mut value["state"]["core_state"]["path_resources"]["link_pairs"][0]
}

#[test]
fn path_cleanup_replay_normalization_and_recorded_presence_roundtrip() {
    for presence in ["recorded", "empty", "absent", "null"] {
        let mut input = value();
        for item in [single as fn(&mut Value) -> &mut Value, pair] {
            let item = item(&mut input);
            match presence {
                "empty" => item["cleanup"] = json!([]),
                "absent" => {
                    item.as_object_mut().unwrap().remove("cleanup");
                }
                "null" => item["cleanup"] = Value::Null,
                _ => {}
            }
        }
        let artifact = load_artifact_record_from_value(input).unwrap();
        let output = artifact.full_artifact_json().unwrap();
        let mut output_check = output.clone();
        assert_eq!(
            single(&mut output_check).get("cleanup").is_some(),
            matches!(presence, "recorded" | "empty")
        );
        let reloaded = load_artifact_record_from_value(output.clone()).unwrap();
        assert_eq!(reloaded.full_artifact_json().unwrap(), output);
        assert_eq!(
            reloaded.semantic_bytes().unwrap(),
            artifact.semantic_bytes().unwrap()
        );
        assert_eq!(
            reloaded.semantic_hash_hex().unwrap(),
            artifact.semantic_hash_hex().unwrap()
        );
    }
    let old = common::collect_state_fixture("linux-gpu-workstation-like-path-resources-fit-v1");
    assert!(!serde_json::to_string(&old).unwrap().contains("cleanup"));
}

#[test]
fn path_cleanup_malformed_evidence_fails_closed() {
    for is_pair in [false, true] {
        for mutation in [
            "blank_root",
            "unknown_outcome",
            "unknown_field",
            "missing_error",
            "blank_error",
            "removed_error",
            "not_created_error",
            "bad_count",
            "bad_type",
            "null_entry",
        ] {
            let mut input = value();
            let item = if is_pair {
                pair(&mut input)
            } else {
                single(&mut input)
            };
            match mutation {
                "blank_root" => item["cleanup"][0]["probe_root"] = json!(" "),
                "unknown_outcome" => item["cleanup"][0]["outcome"] = json!("assumed_clean"),
                "unknown_field" => item["cleanup"][0]["unexpected"] = json!(true),
                "missing_error" => {
                    item["cleanup"][0]["outcome"] = json!("remove_failed");
                    item["cleanup"][0].as_object_mut().unwrap().remove("error");
                }
                "blank_error" => {
                    item["cleanup"][0]["outcome"] = json!("remove_failed");
                    item["cleanup"][0]["error"] = json!(" ");
                }
                "removed_error" | "not_created_error" => {
                    item["cleanup"][0]["outcome"] = json!(if mutation == "removed_error" {
                        "removed"
                    } else {
                        "not_created"
                    });
                    item["cleanup"][0]["error"] = json!("unexpected failure");
                }
                "bad_count" => {
                    let row = item["cleanup"][0].clone();
                    item["cleanup"] = if is_pair {
                        json!([row])
                    } else {
                        json!([row, {"probe_root":"/distinct","outcome":"removed"}])
                    };
                }
                "bad_type" => item["cleanup"] = json!({}),
                "null_entry" => item["cleanup"][0] = Value::Null,
                _ => unreachable!(),
            }
            let error = load_artifact_record_from_value(input).expect_err(mutation);
            assert_eq!(error.error_model_id, "fitctl.artifact_record.v1");
            let code = if matches!(
                mutation,
                "unknown_outcome" | "unknown_field" | "bad_type" | "null_entry"
            ) {
                "artifact_decode_invalid"
            } else {
                "artifact_load_invalid"
            };
            assert_eq!(error.code.as_str(), code, "{mutation}: {error:?}");
            assert_eq!(error.checkpoint_id, "artifact_load");
        }
    }
    let mut input = value();
    let first = pair(&mut input)["cleanup"][0].clone();
    pair(&mut input)["cleanup"][1] = first;
    assert!(load_artifact_record_from_value(input).is_err());
}

#[test]
fn path_cleanup_inspect_is_independent_of_successful_links() {
    for verbose in [false, true] {
        let options = InspectRenderOptionsV1 {
            verbose,
            ..Default::default()
        };
        let text =
            render_artifact_summary_with_options_v1(&ArtifactRecordV1::State(state()), options)
                .unwrap();
        assert!(text.contains("cleanup removed"), "{text}");
        assert!(text.contains("remove_failed"), "{text}");
        assert!(text.contains("copy true"), "{text}");
    }
    let mut input = value();
    single(&mut input)
        .as_object_mut()
        .unwrap()
        .remove("cleanup");
    pair(&mut input).as_object_mut().unwrap().remove("cleanup");
    let text = render_artifact_summary_with_options_v1(
        &load_artifact_record_from_value(input).unwrap(),
        Default::default(),
    )
    .unwrap();
    assert!(text.contains("cleanup not_recorded"));
}

#[test]
fn path_cleanup_redaction_keeps_outcomes_without_roots_or_diagnostics() {
    for profile in [
        BuiltInRedactionProfileV1::Local,
        BuiltInRedactionProfileV1::Fleet,
        BuiltInRedactionProfileV1::Auditor,
        BuiltInRedactionProfileV1::External,
    ] {
        let mut input = value();
        pair(&mut input)["cleanup"][1]["error"] =
            json!("private-cleanup-diagnostic /private/cleanup/secret");
        pair(&mut input)["cleanup"][0]["probe_root"] = json!("/private/cleanup/source");
        pair(&mut input)["cleanup"][1]["probe_root"] = json!("/private/cleanup/destination");
        let artifact = load_artifact_record_from_value(input).unwrap();
        let redacted = redact_artifact_v1(RedactionRequestV1 {
            artifact,
            profile,
            redacted_at: common::FIXED_TIMESTAMP.into(),
        })
        .unwrap();
        let mut output = redacted.full_artifact_json().unwrap();
        assert_eq!(pair(&mut output)["cleanup"][0]["outcome"], "removed");
        assert_eq!(pair(&mut output)["cleanup"][1]["outcome"], "remove_failed");
        assert_eq!(pair(&mut output)["copy_possible"]["value"], true);
        let shared = matches!(
            profile,
            BuiltInRedactionProfileV1::Auditor | BuiltInRedactionProfileV1::External
        );
        let text = output.to_string();
        assert_eq!(text.contains("/private/cleanup/"), !shared);
        assert_eq!(text.contains("private-cleanup-diagnostic"), !shared);
        load_artifact_record_from_value(output).unwrap();
    }
}

#[test]
fn path_cleanup_hash_signatures_and_redaction_bind_outcomes() {
    let root = common::unique_temp_dir("probe-cleanup-signature");
    struct Owned(std::path::PathBuf);
    impl Drop for Owned {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    let _owned = Owned(root.clone());
    let key = common::generate_ed25519_keypair(&root, "signer");
    let signed = common::sign_artifact(ArtifactRecordV1::State(state()), &key);
    fitctl_core::sign::verify_artifact_signatures_v1(&signed).unwrap();
    let mut value = signed.full_artifact_json().unwrap();
    pair(&mut value)["cleanup"][1]["outcome"] = json!("removed");
    pair(&mut value)["cleanup"][1]
        .as_object_mut()
        .unwrap()
        .remove("error");
    let changed = load_artifact_record_from_value(value).unwrap();
    assert_ne!(
        signed.semantic_hash_hex().unwrap(),
        changed.semantic_hash_hex().unwrap()
    );
    assert!(fitctl_core::sign::verify_artifact_signatures_v1(&changed).is_err());
    let redacted = redact_artifact_v1(RedactionRequestV1 {
        artifact: signed,
        profile: BuiltInRedactionProfileV1::External,
        redacted_at: common::FIXED_TIMESTAMP.into(),
    })
    .unwrap();
    assert!(redacted.envelope().signatures.is_empty());
    let ArtifactRecordV1::State(state) = redacted else {
        panic!("state expected")
    };
    validate_host_state(&state).unwrap();
}
