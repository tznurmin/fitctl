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
    let network_survey = e2e::emit_survey_fixture(&temp_dir, "linux-network-mixed-like-v1");
    let gpu_survey = e2e::emit_survey_fixture(&temp_dir, "linux-gpu-dual-numa-like-v1");
    let bare_contract =
        e2e::derive_contract(&temp_dir, &bare_survey, "general_compute_default.v1.json");
    let network_contract = e2e::derive_contract(
        &temp_dir,
        &network_survey,
        "general_compute_default.v1.json",
    );
    let gpu_contract = e2e::derive_contract(&temp_dir, &gpu_survey, "gpu_compute_default.v1.json");

    let output = e2e::run_fitctl([
        "classify",
        "--contract",
        bare_contract
            .to_str()
            .expect("bare contract path should be valid UTF-8"),
        "--contract",
        network_contract
            .to_str()
            .expect("network contract path should be valid UTF-8"),
        "--contract",
        gpu_contract
            .to_str()
            .expect("gpu contract path should be valid UTF-8"),
        "--profile",
        common::repo_service_profile_path("general_compute_contract_only.v2.json")
            .to_str()
            .expect("general profile path should be valid UTF-8"),
        "--profile",
        common::repo_service_profile_path("general_compute_no_gpu_contract_only.v2.json")
            .to_str()
            .expect("no-gpu profile path should be valid UTF-8"),
        "--profile",
        common::repo_service_profile_path("gpu_required_contract_only.v2.json")
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
    assert_eq!(report.report.rows.len(), 9);
    assert_eq!(
        report.classification_basis.ordered_service_profiles[0]
            .display_name
            .as_deref(),
        Some("General compute")
    );
    assert_eq!(
        report.classification_basis.ordered_service_profiles[0]
            .short_display_name
            .as_deref(),
        Some("General compute")
    );
    assert_eq!(
        report.classification_basis.ordered_service_profiles[1]
            .display_name
            .as_deref(),
        Some("CPU only")
    );
    assert_eq!(
        report.classification_basis.ordered_service_profiles[2]
            .short_display_name
            .as_deref(),
        Some("GPU required")
    );
    assert_eq!(
        report.classification_basis.ordered_contracts[0]
            .host_alias
            .as_deref(),
        Some("cpu-host-01")
    );
    assert_eq!(
        report.classification_basis.ordered_contracts[0]
            .short_display_name
            .as_deref(),
        Some("General compute default")
    );
    let gpu_contract_ref = report
        .classification_basis
        .ordered_contracts
        .iter()
        .find(|contract| {
            contract.artifact_id == "contract-linux-gpu-dual-numa-like-v1-gpu-compute-default-v1"
        })
        .expect("gpu contract ref should be present");
    assert_eq!(
        gpu_contract_ref.host_alias.as_deref(),
        Some("demo-gpu-numa-01")
    );
    assert_eq!(
        gpu_contract_ref.short_display_name.as_deref(),
        Some("GPU compute default")
    );

    for (contract_id, profile_id, verdict, reason_code) in [
        (
            "contract-linux-bare-metal-like-v1-general-compute-default-v1",
            "service-profile-general-compute-contract-only-v1",
            ValidationVerdictV1::Fit,
            ValidationReasonCodeV1::RequirementsSatisfied,
        ),
        (
            "contract-linux-bare-metal-like-v1-general-compute-default-v1",
            "service-profile-general-compute-no-gpu-contract-only-v1",
            ValidationVerdictV1::Fit,
            ValidationReasonCodeV1::RequirementsSatisfied,
        ),
        (
            "contract-linux-bare-metal-like-v1-general-compute-default-v1",
            "service-profile-gpu-required-contract-only-v1",
            ValidationVerdictV1::Unfit,
            ValidationReasonCodeV1::CapabilityUnknown,
        ),
        (
            "contract-linux-network-mixed-like-v1-general-compute-default-v1",
            "service-profile-general-compute-contract-only-v1",
            ValidationVerdictV1::Fit,
            ValidationReasonCodeV1::RequirementsSatisfied,
        ),
        (
            "contract-linux-network-mixed-like-v1-general-compute-default-v1",
            "service-profile-general-compute-no-gpu-contract-only-v1",
            ValidationVerdictV1::Fit,
            ValidationReasonCodeV1::RequirementsSatisfied,
        ),
        (
            "contract-linux-network-mixed-like-v1-general-compute-default-v1",
            "service-profile-gpu-required-contract-only-v1",
            ValidationVerdictV1::Unfit,
            ValidationReasonCodeV1::CapabilityUnknown,
        ),
        (
            "contract-linux-gpu-dual-numa-like-v1-gpu-compute-default-v1",
            "service-profile-general-compute-contract-only-v1",
            ValidationVerdictV1::Fit,
            ValidationReasonCodeV1::RequirementsSatisfied,
        ),
        (
            "contract-linux-gpu-dual-numa-like-v1-gpu-compute-default-v1",
            "service-profile-general-compute-no-gpu-contract-only-v1",
            ValidationVerdictV1::Unfit,
            ValidationReasonCodeV1::RequirementUnsatisfied,
        ),
        (
            "contract-linux-gpu-dual-numa-like-v1-gpu-compute-default-v1",
            "service-profile-gpu-required-contract-only-v1",
            ValidationVerdictV1::Fit,
            ValidationReasonCodeV1::RequirementsSatisfied,
        ),
    ] {
        let row = report
            .report
            .rows
            .iter()
            .find(|row| {
                row.contract_artifact_id == contract_id
                    && row.service_profile_artifact_id == profile_id
            })
            .expect("matrix row should be present");
        assert_eq!(row.verdict, verdict, "{contract_id} vs {profile_id}");
        assert_eq!(
            row.primary_reason_code, reason_code,
            "{contract_id} vs {profile_id}"
        );
    }
}
