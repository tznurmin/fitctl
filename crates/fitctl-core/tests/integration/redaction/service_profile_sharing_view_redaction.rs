// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common;
use fitctl_core::artifacts::record_v1::ArtifactRecordV1;
use fitctl_core::redact::{redact_artifact_v1, BuiltInRedactionProfileV1, RedactionRequestV1};
use serde_json::json;

const SENTINEL: &str = "profile-sharing-sensitive";

fn sensitive_profile() -> ArtifactRecordV1 {
    let profile =
        common::load_service_profile_file("local_image_generation_storage_state_required.v2.json");
    let mut value = serde_json::to_value(profile).expect("profile should encode");
    value["envelope"]["artifact_id"] = json!(format!("{SENTINEL}-artifact"));
    value["envelope"]["provenance"]["fitctl_version"] = json!(format!("0.6.0-{SENTINEL}+private"));
    value["envelope"]["provenance"]["command_name"] = json!(SENTINEL);
    value["profile"]["profile_id"] = json!(format!("{SENTINEL}-profile"));
    value["profile"]["display_name"] = json!(format!("{SENTINEL}-display"));
    value["profile"]["short_display_name"] = json!(format!("{SENTINEL}-short"));
    let requirements = &mut value["profile"]["core_requirements"];
    requirements["primary_capability_class"] = json!(format!("{SENTINEL}-primary-class"));
    requirements["required_paths"][0]["path_id"] = json!(format!("{SENTINEL}-cache"));
    requirements["required_paths"][1]["path_id"] = json!(format!("{SENTINEL}-output"));
    requirements["required_paths"][0]["accepted_filesystem_uuids"] =
        json!([format!("{SENTINEL}-filesystem-uuid")]);
    requirements["required_paths"][0]["accepted_partition_uuids"] =
        json!([format!("{SENTINEL}-partition-uuid")]);
    requirements["required_paths"][0]["accepted_persistent_device_links"] =
        json!([format!("/dev/disk/by-id/{SENTINEL}")]);
    requirements["path_relationships"] = json!([{
        "relationship_id": format!("{SENTINEL}-relationship"),
        "left_path_id": format!("{SENTINEL}-cache"),
        "right_path_id": format!("{SENTINEL}-output"),
        "must_not_share": ["filesystem_uuid"]
    }]);
    requirements["required_path_link_pairs"] = json!([{
        "pair_id": format!("{SENTINEL}-pair"),
        "from_path_id": format!("{SENTINEL}-cache"),
        "to_path_id": format!("{SENTINEL}-output"),
        "require_reflink": true
    }]);
    requirements["required_thermal_sensors"] = json!([{
        "requirement_id": format!("{SENTINEL}-thermal-requirement"),
        "provider_id": format!("{SENTINEL}-thermal-provider"),
        "sensor_id": format!("{SENTINEL}-thermal-sensor"),
        "sensor_alias": format!("{SENTINEL}-thermal-alias"),
        "max_temperature_millidegrees_celsius": 75000
    }]);
    value["profile"]["exclusions"]["forbidden_capability_classes"] =
        json!([format!("{SENTINEL}-forbidden-class")]);
    value["profile"]["degradation_ladder"] = json!([{
        "tier_id": format!("{SENTINEL}-tier"),
        "acceptable_capability_class": format!("{SENTINEL}-fallback-class"),
        "rationale": format!("{SENTINEL}-rationale")
    }]);
    value["profile"]["assurance_requirements"] = json!([{
        "target": format!("{SENTINEL}-assurance-target"),
        "accepted_assurance_sources": ["locally_verified"],
        "accepted_derivation_stages": ["observed"]
    }]);
    ArtifactRecordV1::ServiceProfile(
        serde_json::from_value(value).expect("modified service profile should decode"),
    )
}

#[test]
fn service_profile_sentinels_do_not_survive_sharing_profiles() {
    for profile in [
        BuiltInRedactionProfileV1::Auditor,
        BuiltInRedactionProfileV1::External,
    ] {
        let redacted = redact_artifact_v1(RedactionRequestV1 {
            artifact: sensitive_profile(),
            profile,
            redacted_at: common::FIXED_TIMESTAMP.to_string(),
        })
        .expect("service profile sharing view should redact");
        let rendered = serde_json::to_string(&redacted).expect("profile should encode");
        assert!(
            !rendered.contains(SENTINEL),
            "sentinel survived: {rendered}"
        );

        let ArtifactRecordV1::ServiceProfile(redacted) = redacted else {
            panic!("expected service profile");
        };
        let requirements = &redacted.profile.core_requirements;
        assert_eq!(
            requirements.path_relationships[0].left_path_id,
            requirements.required_paths[0].path_id
        );
        assert_eq!(
            requirements.required_path_link_pairs[0].to_path_id,
            requirements.required_paths[1].path_id
        );
    }
}

#[test]
fn validation_profile_lineage_uses_transformed_artifact_id() {
    let mut report = common::validate_with_profile(
        common::derive_contract_from_fixture("linux-bare-metal-like-v1"),
        common::load_service_profile_file("general_compute_contract_only.v2.json"),
        None,
        fitctl_core::artifacts::validation_report_v1::ValidationModeV1::ContractOnly,
        None,
    );
    report.validation_basis.service_profile_artifact_id = format!("{SENTINEL}-basis");

    for profile in [
        BuiltInRedactionProfileV1::Fleet,
        BuiltInRedactionProfileV1::Auditor,
        BuiltInRedactionProfileV1::External,
    ] {
        let redacted = redact_artifact_v1(RedactionRequestV1 {
            artifact: ArtifactRecordV1::ValidationReport(report.clone()),
            profile,
            redacted_at: common::FIXED_TIMESTAMP.to_string(),
        })
        .expect("validation report should redact");
        let rendered = serde_json::to_string(&redacted).expect("report should encode");
        assert!(!rendered.contains(SENTINEL));
    }
}
