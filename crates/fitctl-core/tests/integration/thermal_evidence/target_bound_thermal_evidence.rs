// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common;
use fitctl_core::artifacts::envelope_v1::{local_artifact_provenance_v1, ArtifactEnvelopeV1};
use fitctl_core::artifacts::record_v1::{load_artifact_record_from_path, ArtifactRecordV1};
use fitctl_core::artifacts::schema_ids_v1::TOP_LEVEL_ARTIFACT_SCHEMA_VERSION;
use fitctl_core::artifacts::semantic_hash_v1::semantic_hash_hex_for_thermal_evidence;
use fitctl_core::artifacts::state_v1::{
    HostStateThermalCollectorHostV1, HostStateThermalEvidenceTargetV1, HostStateThermalProviderV1,
    HostStateThermalReadingV1, HostStateThermalResourcesV1, ThermalCollectionPathV1,
    ThermalEvidenceTargetKindV1, ThermalProviderKindV1, ThermalProviderOutcomeV1,
    ThermalReadingStatusV1, ThermalSensorRoleV1,
};
use fitctl_core::artifacts::thermal_evidence_v1::ThermalEvidenceV1;
use fitctl_core::artifacts::validation_v1::validate_thermal_evidence;
use fitctl_core::redact::{redact_artifact_v1, BuiltInRedactionProfileV1, RedactionRequestV1};

#[test]
fn conformance_thermal_evidence_fixture_validates() {
    let path = common::repo_root()
        .join("fixtures/conformance/valid/thermal-evidence.out-of-band-bmc.v1.json");
    let artifact =
        load_artifact_record_from_path(&path).expect("thermal evidence fixture should load");

    let ArtifactRecordV1::ThermalEvidence(artifact) = artifact else {
        panic!("expected thermal evidence artifact");
    };
    validate_thermal_evidence(&artifact).expect("thermal evidence fixture should validate");
}

#[test]
fn target_bound_thermal_evidence_artifact_validates() {
    let artifact = thermal_evidence_artifact(41_000, common::FIXED_TIMESTAMP, "host.gpu-host-01");

    validate_thermal_evidence(&artifact).expect("thermal evidence artifact should validate");
    assert_eq!(
        artifact
            .thermal_evidence
            .collector_host
            .host_alias
            .as_deref(),
        Some("collector-host")
    );
    assert_eq!(
        artifact.thermal_evidence.providers[0]
            .evidence_target
            .host_id
            .as_deref(),
        Some("host.gpu-host-01")
    );
}

#[test]
fn thermal_evidence_excludes_collector_runtime_state() {
    let artifact = thermal_evidence_artifact(41_000, common::FIXED_TIMESTAMP, "host.gpu-host-01");
    let value = serde_json::to_value(&artifact).expect("thermal evidence should encode");

    assert!(value.get("thermal_evidence").is_some());
    assert!(value.get("state").is_none());
    assert!(value["thermal_evidence"].get("resources").is_none());
    assert!(value["thermal_evidence"].get("path_resources").is_none());
}

#[test]
fn thermal_evidence_observed_at_does_not_change_semantic_hash() {
    let left = thermal_evidence_artifact(41_000, "2026-06-16T12:00:00Z", "host.gpu-host-01");
    let right = thermal_evidence_artifact(41_000, "2026-06-16T12:01:00Z", "host.gpu-host-01");

    assert_eq!(
        semantic_hash_hex_for_thermal_evidence(&left).expect("left semantic hash"),
        semantic_hash_hex_for_thermal_evidence(&right).expect("right semantic hash")
    );
}

#[test]
fn thermal_evidence_temperature_contributes_to_semantic_hash() {
    let left = thermal_evidence_artifact(41_000, common::FIXED_TIMESTAMP, "host.gpu-host-01");
    let right = thermal_evidence_artifact(42_000, common::FIXED_TIMESTAMP, "host.gpu-host-01");

    assert_ne!(
        semantic_hash_hex_for_thermal_evidence(&left).expect("left semantic hash"),
        semantic_hash_hex_for_thermal_evidence(&right).expect("right semantic hash")
    );
}

#[test]
fn external_profile_redacts_thermal_evidence_identifiers() {
    let artifact = thermal_evidence_artifact(41_000, common::FIXED_TIMESTAMP, "host.gpu-host-01");
    let redacted = redact_artifact_v1(RedactionRequestV1 {
        artifact: ArtifactRecordV1::ThermalEvidence(artifact),
        profile: BuiltInRedactionProfileV1::External,
        redacted_at: common::FIXED_TIMESTAMP.to_string(),
    })
    .expect("redaction should succeed");

    let ArtifactRecordV1::ThermalEvidence(redacted) = redacted else {
        panic!("expected thermal evidence artifact");
    };
    validate_thermal_evidence(&redacted).expect("redacted artifact should validate");

    let rendered = serde_json::to_string(&redacted).expect("redacted artifact should encode");
    assert!(!rendered.contains("site-bmc-thermal"));
    assert!(!rendered.contains("Inlet Temp"));
    assert!(!rendered.contains("target_inlet"));
    assert!(!rendered.contains("collector-host"));
    assert!(rendered.contains("redacted:external:thermal_provider:0"));
    assert!(rendered.contains("redacted:external:thermal_sensor:0"));
}

pub(crate) fn thermal_evidence_artifact(
    temperature_millidegrees_celsius: i64,
    observed_at: &str,
    target_host_id: &str,
) -> ThermalEvidenceV1 {
    let artifact_id = "thermal-evidence-test".to_string();
    ThermalEvidenceV1 {
        envelope: ArtifactEnvelopeV1 {
            schema_id: "fitctl.thermal-evidence.v1".to_string(),
            schema_version: TOP_LEVEL_ARTIFACT_SCHEMA_VERSION,
            artifact_id: artifact_id.clone(),
            provenance: local_artifact_provenance_v1(
                "thermal:collect".to_string(),
                observed_at.to_string(),
                "thermal",
                artifact_id,
            ),
            redaction: None,
            signatures: vec![],
        },
        thermal_evidence: HostStateThermalResourcesV1 {
            observed_at: observed_at.to_string(),
            collector_host: HostStateThermalCollectorHostV1 {
                host_alias: Some("collector-host".to_string()),
                local_stable_id: Some("collector-stable-id".to_string()),
            },
            providers: vec![HostStateThermalProviderV1 {
                provider_id: "site-bmc-thermal".to_string(),
                provider_kind: ThermalProviderKindV1::IpmitoolSensor,
                outcome: ThermalProviderOutcomeV1::Success,
                evidence_target: target(target_host_id),
                observed_at: observed_at.to_string(),
                error_code: None,
                diagnostics: None,
            }],
            readings: vec![HostStateThermalReadingV1 {
                sensor_id: "site-bmc-thermal:inlet-temp".to_string(),
                sensor_role: ThermalSensorRoleV1::Inlet,
                sensor_alias: Some("target_inlet".to_string()),
                provider_id: "site-bmc-thermal".to_string(),
                raw_label: "Inlet Temp".to_string(),
                temperature_millidegrees_celsius,
                status: ThermalReadingStatusV1::Ok,
                observed_at: observed_at.to_string(),
                evidence_target: target(target_host_id),
                source: Some("ipmitool_sensor".to_string()),
            }],
        },
    }
}

fn target(target_host_id: &str) -> HostStateThermalEvidenceTargetV1 {
    HostStateThermalEvidenceTargetV1 {
        target_kind: ThermalEvidenceTargetKindV1::HostId,
        host_id: Some(target_host_id.to_string()),
        collection_path: ThermalCollectionPathV1::OutOfBandBmc,
    }
}
