// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common;
use crate::e2e;
use fitctl_core::artifacts::batch_classification_report_v1::BatchClassificationReportV1;

#[test]
fn same_survey_multi_policy_contracts_classify_cleanly() {
    let temp_dir = common::unique_temp_dir("integration-classify-same-survey");
    let survey = e2e::emit_survey_fixture(&temp_dir, "linux-gpu-workstation-like-v1");
    let general_contract =
        e2e::derive_contract(&temp_dir, &survey, "general_compute_default.v1.json");
    let gpu_contract = e2e::derive_contract(&temp_dir, &survey, "gpu_compute_default.v1.json");

    let output = e2e::run_fitctl([
        "classify",
        "--contract",
        general_contract
            .to_str()
            .expect("general contract path should be valid UTF-8"),
        "--contract",
        gpu_contract
            .to_str()
            .expect("gpu contract path should be valid UTF-8"),
        "--profile",
        common::repo_service_profile_path("general_compute_contract_only.v2.json")
            .to_str()
            .expect("general profile path should be valid UTF-8"),
        "--profile",
        common::repo_service_profile_path(
            "gpu_preferred_with_general_compute_fallback_contract_only.v2.json",
        )
        .to_str()
        .expect("gpu profile path should be valid UTF-8"),
        "--validated-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&output);

    let report: BatchClassificationReportV1 = e2e::decode_json_stdout(&output);
    assert_eq!(report.report.rows.len(), 4);

    let contract_ids = report
        .classification_basis
        .ordered_contracts
        .iter()
        .map(|contract| contract.artifact_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        contract_ids,
        vec![
            "contract-linux-gpu-workstation-like-v1-general-compute-default-v1",
            "contract-linux-gpu-workstation-like-v1-gpu-compute-default-v1",
        ]
    );
    assert_ne!(contract_ids[0], contract_ids[1]);
    assert_eq!(
        report.classification_basis.ordered_contracts[0]
            .host_alias
            .as_deref(),
        Some("gpu-host-01")
    );
    assert_eq!(
        report.classification_basis.ordered_contracts[0]
            .short_display_name
            .as_deref(),
        Some("General compute default")
    );
    assert_eq!(
        report.classification_basis.ordered_contracts[1]
            .short_display_name
            .as_deref(),
        Some("GPU compute default")
    );
}
