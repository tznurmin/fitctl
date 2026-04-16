// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common;
use crate::e2e;
use fitctl_core::artifacts::batch_classification_report_v1::BatchClassificationReportV1;
use fitctl_core::artifacts::validation_report_v1::{ValidationReasonCodeV1, ValidationVerdictV1};

#[test]
fn batch_classification_proves_profile_matrix_use_case() {
    let temp_dir = common::unique_temp_dir("integration-e2e-classify");
    let bare_survey = e2e::emit_survey_fixture(&temp_dir, "linux-bare-metal-like-v1");
    let gpu_survey = e2e::emit_survey_fixture(&temp_dir, "linux-gpu-workstation-like-v1");
    let bare_contract =
        e2e::derive_contract(&temp_dir, &bare_survey, "general_compute_default.v1.json");
    let gpu_contract = e2e::derive_contract(&temp_dir, &gpu_survey, "gpu_compute_default.v1.json");

    let output = e2e::run_fitctl([
        "classify",
        "--contract",
        bare_contract
            .to_str()
            .expect("bare contract path should be valid UTF-8"),
        "--contract",
        gpu_contract
            .to_str()
            .expect("gpu contract path should be valid UTF-8"),
        "--profile",
        common::repo_service_profile_path("general_compute_contract_only.v1.json")
            .to_str()
            .expect("general profile path should be valid UTF-8"),
        "--profile",
        common::repo_service_profile_path("gpu_preferred_with_general_compute_fallback.v1.json")
            .to_str()
            .expect("gpu profile path should be valid UTF-8"),
        "--validated-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&output);

    let report: BatchClassificationReportV1 = e2e::decode_json_stdout(&output);
    assert_eq!(
        report.classification_basis.validation_mode.as_str(),
        "contract_only"
    );
    assert_eq!(report.report.rows.len(), 4);

    let bare_general = report
        .report
        .rows
        .iter()
        .find(|row| {
            row.contract_artifact_id == "contract-linux-bare-metal-like-v1"
                && row.service_profile_artifact_id
                    == "service-profile-general-compute-contract-only-v1"
        })
        .expect("bare/general row should be present");
    assert_eq!(bare_general.verdict, ValidationVerdictV1::Fit);
    assert_eq!(
        bare_general.primary_reason_code,
        ValidationReasonCodeV1::RequirementsSatisfied
    );

    let bare_gpu_fallback = report
        .report
        .rows
        .iter()
        .find(|row| {
            row.contract_artifact_id == "contract-linux-bare-metal-like-v1"
                && row.service_profile_artifact_id
                    == "service-profile-gpu-preferred-with-general-compute-fallback-v1"
        })
        .expect("bare/gpu row should be present");
    assert_eq!(
        bare_gpu_fallback.verdict,
        ValidationVerdictV1::FitWithDegradation
    );
    assert_eq!(
        bare_gpu_fallback.primary_reason_code,
        ValidationReasonCodeV1::DegradationPathRequired
    );
    assert_eq!(
        bare_gpu_fallback.selected_degradation_tier.as_deref(),
        Some("fallback/general_compute")
    );

    let gpu_general = report
        .report
        .rows
        .iter()
        .find(|row| {
            row.contract_artifact_id == "contract-linux-gpu-workstation-like-v1"
                && row.service_profile_artifact_id
                    == "service-profile-general-compute-contract-only-v1"
        })
        .expect("gpu/general row should be present");
    assert_eq!(gpu_general.verdict, ValidationVerdictV1::Unfit);
    assert_eq!(
        gpu_general.primary_reason_code,
        ValidationReasonCodeV1::CapabilityUnknown
    );

    let gpu_gpu = report
        .report
        .rows
        .iter()
        .find(|row| {
            row.contract_artifact_id == "contract-linux-gpu-workstation-like-v1"
                && row.service_profile_artifact_id
                    == "service-profile-gpu-preferred-with-general-compute-fallback-v1"
        })
        .expect("gpu/gpu row should be present");
    assert_eq!(gpu_gpu.verdict, ValidationVerdictV1::Fit);
    assert_eq!(
        gpu_gpu.primary_reason_code,
        ValidationReasonCodeV1::RequirementsSatisfied
    );

    let bare_summary = report
        .report
        .contract_summaries
        .iter()
        .find(|summary| summary.contract_artifact_id == "contract-linux-bare-metal-like-v1")
        .expect("bare summary should be present");
    assert_eq!(
        bare_summary.degraded_profile_ids,
        vec!["service-profile-gpu-preferred-with-general-compute-fallback-v1"]
    );
}
