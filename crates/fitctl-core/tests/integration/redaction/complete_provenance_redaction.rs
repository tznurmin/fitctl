// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use fitctl_core::artifacts::record_v1::ArtifactRecordV1;
use fitctl_core::redact::{redact_artifact_v1, BuiltInRedactionProfileV1, RedactionRequestV1};
use fitctl_core::validate::ValidationModeV1;

use crate::common;

const SOURCE_SENTINEL: &str = "sensitive-source-policy-prod-17";
const CORRELATION_SENTINEL: &str = "sensitive-correlation-host-prod-17";
const VCS_REVISION_SENTINEL: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const VCS_DESCRIBE_SENTINEL: &str = "private-release-train-17";

#[test]
fn non_local_profiles_redact_correlation_and_external_sources() {
    let local = redact(BuiltInRedactionProfileV1::Local);
    assert_eq!(local.envelope.provenance.source, SOURCE_SENTINEL);
    assert_eq!(
        local.envelope.provenance.correlation_id.as_deref(),
        Some(CORRELATION_SENTINEL)
    );
    assert_eq!(
        local.envelope.provenance.fitctl_vcs_revision.as_deref(),
        Some(VCS_REVISION_SENTINEL)
    );

    let fleet = redact(BuiltInRedactionProfileV1::Fleet);
    assert_eq!(fleet.envelope.provenance.source, SOURCE_SENTINEL);
    assert_eq!(
        fleet.envelope.provenance.correlation_id.as_deref(),
        Some(fleet.envelope.artifact_id.as_str())
    );
    assert_ne!(fleet.envelope.artifact_id, CORRELATION_SENTINEL);
    assert_eq!(
        fleet.envelope.provenance.fitctl_vcs_revision.as_deref(),
        Some(VCS_REVISION_SENTINEL)
    );

    for profile in [
        BuiltInRedactionProfileV1::Auditor,
        BuiltInRedactionProfileV1::External,
    ] {
        let redacted = redact(profile);
        let serialized = serde_json::to_string(&redacted).expect("redacted survey should encode");
        for sentinel in [
            SOURCE_SENTINEL,
            CORRELATION_SENTINEL,
            VCS_REVISION_SENTINEL,
            VCS_DESCRIBE_SENTINEL,
        ] {
            assert!(
                !serialized.contains(sentinel),
                "{} output retained prohibited sentinel {sentinel}",
                profile.as_str()
            );
        }
        assert_eq!(
            redacted.envelope.provenance.source,
            format!("redacted:{}:source", profile.as_str())
        );
        assert_eq!(
            redacted.envelope.provenance.correlation_id.as_deref(),
            Some(redacted.envelope.artifact_id.as_str())
        );
    }
}

#[test]
fn every_core_redaction_family_uses_complete_envelope_provenance_rules() {
    for profile in [
        BuiltInRedactionProfileV1::Auditor,
        BuiltInRedactionProfileV1::External,
    ] {
        for mut artifact in core_artifacts() {
            let original_artifact_id = artifact.artifact_id().to_string();
            let artifact_id_is_host_derived =
                !matches!(&artifact, ArtifactRecordV1::ServiceProfile(_));
            let envelope = artifact.envelope_mut();
            envelope.provenance.source = SOURCE_SENTINEL.to_string();
            envelope.provenance.correlation_id = Some(CORRELATION_SENTINEL.to_string());
            envelope.provenance.fitctl_vcs_revision = Some(VCS_REVISION_SENTINEL.to_string());
            envelope.provenance.fitctl_vcs_describe = Some(VCS_DESCRIBE_SENTINEL.to_string());
            envelope.provenance.fitctl_build_dirty = Some(true);

            let redacted = redact_artifact_v1(RedactionRequestV1 {
                artifact,
                profile,
                redacted_at: common::FIXED_TIMESTAMP.to_string(),
            })
            .expect("core artifact should redact");
            let serialized = serde_json::to_string(&redacted).expect("artifact should encode");
            for sentinel in [
                SOURCE_SENTINEL,
                CORRELATION_SENTINEL,
                VCS_REVISION_SENTINEL,
                VCS_DESCRIBE_SENTINEL,
            ] {
                assert!(
                    !serialized.contains(sentinel),
                    "{} {} output retained prohibited sentinel {sentinel}",
                    profile.as_str(),
                    redacted.schema_id()
                );
            }
            if artifact_id_is_host_derived {
                assert!(!serialized.contains(&original_artifact_id));
            }
        }
    }
}

fn redact(profile: BuiltInRedactionProfileV1) -> fitctl_core::artifacts::survey_v1::HostSurveyV1 {
    let mut survey = common::collect_survey_fixture("linux-bare-metal-like-v1");
    survey.envelope.provenance.source = SOURCE_SENTINEL.to_string();
    survey.envelope.provenance.correlation_id = Some(CORRELATION_SENTINEL.to_string());
    survey.envelope.provenance.fitctl_vcs_revision = Some(VCS_REVISION_SENTINEL.to_string());
    survey.envelope.provenance.fitctl_vcs_describe = Some(VCS_DESCRIBE_SENTINEL.to_string());
    survey.envelope.provenance.fitctl_build_dirty = Some(true);

    let redacted = redact_artifact_v1(RedactionRequestV1 {
        artifact: ArtifactRecordV1::Survey(survey),
        profile,
        redacted_at: common::FIXED_TIMESTAMP.to_string(),
    })
    .expect("survey redaction should succeed");
    let ArtifactRecordV1::Survey(redacted) = redacted else {
        panic!("redaction should preserve survey family");
    };
    redacted
}

fn core_artifacts() -> Vec<ArtifactRecordV1> {
    let survey = common::collect_survey_fixture("linux-bare-metal-like-v1");
    let contract = common::derive_contract_from_fixture("linux-bare-metal-like-v1");
    let profile = common::load_service_profile_file("general_compute_contract_only.v2.json");
    let state = common::collect_state_fixture("linux-bare-metal-like-fresh-v1");
    let validation = common::validate_with_profile(
        contract.clone(),
        profile.clone(),
        None,
        ValidationModeV1::ContractOnly,
        None,
    );
    let thermal: fitctl_core::artifacts::thermal_evidence_v1::ThermalEvidenceV1 =
        serde_json::from_str(
            &std::fs::read_to_string(
                common::repo_root()
                    .join("fixtures/conformance/valid/thermal-evidence.out-of-band-bmc.v1.json"),
            )
            .expect("thermal fixture should read"),
        )
        .expect("thermal fixture should decode");

    vec![
        ArtifactRecordV1::Survey(survey),
        ArtifactRecordV1::Contract(contract),
        ArtifactRecordV1::ServiceProfile(profile),
        ArtifactRecordV1::State(state),
        ArtifactRecordV1::ThermalEvidence(thermal),
        ArtifactRecordV1::ValidationReport(validation),
    ]
}
