// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common;
use fitctl_core::artifacts::record_v1::{load_artifact_record_from_value, ArtifactRecordV1};
use fitctl_core::redact::{redact_artifact_v1, BuiltInRedactionProfileV1, RedactionRequestV1};
use serde_json::{json, Value};

const SENTINEL: &str = "state-sharing-sensitive";

fn observed(value: Value) -> Value {
    json!({"state": "observed", "value": value})
}

fn unknown() -> Value {
    json!({"state": "unknown", "value": null})
}

fn sensitive_state() -> ArtifactRecordV1 {
    let state = common::collect_state_fixture("linux-gpu-workstation-like-path-resources-fit-v1");
    let mut value = serde_json::to_value(state).expect("state should encode");
    for (scope, metadata) in value["state"]["core_state"]["section_metadata"]
        .as_object_mut()
        .expect("section metadata should be an object")
    {
        metadata["source_collectors"] = json!([format!("{SENTINEL}-{scope}-collector")]);
        metadata["evidence_paths"] = json!([format!("/{SENTINEL}/{scope}/evidence")]);
        metadata["policy_rule_id"] = json!(format!("{SENTINEL}-{scope}-rule"));
        metadata["trust_evidence_refs"] = json!([format!("{SENTINEL}-{scope}-trust")]);
    }

    let paths = value["state"]["core_state"]["path_resources"]["paths"]
        .as_array_mut()
        .expect("paths should be an array");
    paths[0]["path_id"] = json!(format!("{SENTINEL}-cache"));
    paths[1]["path_id"] = json!(format!("{SENTINEL}-output"));
    paths[0]["mount_options"] = observed(json!([format!("{SENTINEL}-mount-option")]));
    paths[0]["link_capabilities"] = json!({
        "hardlink_supported": observed(json!(true)),
        "reflink_supported": observed(json!(true)),
        "symlink_supported": observed(json!(true)),
        "copy_possible": observed(json!(true)),
        "probe_method": format!("{SENTINEL}-path-probe"),
        "probe_error": format!("{SENTINEL}-path-error"),
        "probe_root": format!("/{SENTINEL}/probe-root"),
        "observed_at": common::FIXED_TIMESTAMP
    });
    paths[0]["storage_health"] = json!({
        "health_state": unknown(),
        "temperature_celsius": unknown(),
        "percentage_used": unknown(),
        "available_spare_percent": unknown(),
        "source": format!("{SENTINEL}-health-source"),
        "probe_method": format!("{SENTINEL}-health-probe"),
        "probe_error": format!("{SENTINEL}-health-error"),
        "observed_at": common::FIXED_TIMESTAMP
    });
    value["state"]["core_state"]["path_resources"]["link_pairs"] = json!([{
        "pair_id": format!("{SENTINEL}-pair"),
        "from_path_id": format!("{SENTINEL}-cache"),
        "to_path_id": format!("{SENTINEL}-output"),
        "same_filesystem": observed(json!(true)),
        "hardlink_supported": observed(json!(true)),
        "reflink_supported": observed(json!(true)),
        "symlink_supported": observed(json!(true)),
        "copy_possible": observed(json!(true)),
        "probe_method": format!("{SENTINEL}-pair-probe"),
        "probe_error": format!("{SENTINEL}-pair-error"),
        "observed_at": common::FIXED_TIMESTAMP
    }]);
    value["state"]["core_state"]["operability"]["degraded_capability_classes"] =
        json!([format!("{SENTINEL}-degraded-class")]);
    load_artifact_record_from_value(value).expect("modified state should remain valid")
}

#[test]
fn state_path_identity_sentinels_do_not_survive_sharing_profiles() {
    for profile in [
        BuiltInRedactionProfileV1::Auditor,
        BuiltInRedactionProfileV1::External,
    ] {
        let redacted = redact_artifact_v1(RedactionRequestV1 {
            artifact: sensitive_state(),
            profile,
            redacted_at: common::FIXED_TIMESTAMP.to_string(),
        })
        .expect("state sharing view should redact");
        let rendered = serde_json::to_string(&redacted).expect("state should encode");
        assert!(
            !rendered.contains(SENTINEL),
            "sentinel survived: {rendered}"
        );

        let ArtifactRecordV1::State(redacted) = redacted else {
            panic!("expected state artifact");
        };
        let resources = &redacted.state.core_state.path_resources;
        let ids = resources
            .paths
            .iter()
            .map(|path| path.path_id.as_str())
            .collect::<Vec<_>>();
        let expected_ids = (0..2)
            .map(|index| format!("redacted:{}:path_id:{index:08}", profile.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(ids, expected_ids);
        assert_eq!(
            resources.link_pairs[0].from_path_id,
            resources.paths[0].path_id
        );
        assert_eq!(
            resources.link_pairs[0].to_path_id,
            resources.paths[1].path_id
        );
    }
}
