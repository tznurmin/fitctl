// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::cli;
use crate::common;
use fitctl_core::artifacts::validation_report_v1::{ValidationReasonCodeV1, ValidationVerdictV1};
use fitctl_core::extensions::CUDA_RUNTIME_NAMESPACE;
use std::process::Command;

fn cuda_extension_pack_path() -> std::path::PathBuf {
    common::repo_root().join("configs/extensions/fitctl_runtime_cuda.v1.json")
}

#[test]
fn cuda_runtime_extension_end_to_end() {
    let fitctl_bin = cli::fitctl_bin();
    let temp_dir = common::unique_temp_dir("integration-cuda-extension");
    let survey_path = temp_dir.join("host-survey.v2.json");
    let contract_path = temp_dir.join("host-contract.v2.json");

    let survey_output = Command::new(&fitctl_bin)
        .current_dir(common::repo_root())
        .args([
            "survey",
            "--fixture",
            "linux-gpu-workstation-like-v1",
            "--extension-pack",
            cuda_extension_pack_path()
                .to_str()
                .expect("extension pack path should be valid UTF-8"),
            "--enable-extension",
            CUDA_RUNTIME_NAMESPACE,
        ])
        .output()
        .expect("fitctl survey should execute");
    assert!(
        survey_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&survey_output.stderr)
    );
    std::fs::write(&survey_path, &survey_output.stdout).expect("survey should be writable");

    let contract_output = Command::new(&fitctl_bin)
        .current_dir(common::repo_root())
        .args([
            "contract",
            "--survey",
            survey_path
                .to_str()
                .expect("survey path should be valid UTF-8"),
            "--policy",
            common::repo_policy_path()
                .to_str()
                .expect("policy path should be valid UTF-8"),
            "--extension-pack",
            cuda_extension_pack_path()
                .to_str()
                .expect("extension pack path should be valid UTF-8"),
            "--enable-extension",
            CUDA_RUNTIME_NAMESPACE,
            "--derived-at",
            common::FIXED_TIMESTAMP,
        ])
        .output()
        .expect("fitctl contract should execute");
    assert!(
        contract_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&contract_output.stderr)
    );
    std::fs::write(&contract_path, &contract_output.stdout).expect("contract should be writable");

    let fit_output = Command::new(&fitctl_bin)
        .current_dir(common::repo_root())
        .args([
            "validate",
            "--contract",
            contract_path
                .to_str()
                .expect("contract path should be valid UTF-8"),
            "--profile",
            common::repo_service_profile_path(
                "general_compute_cuda_extension_contract_only.v2.json",
            )
            .to_str()
            .expect("profile path should be valid UTF-8"),
            "--validation-mode",
            "contract_only",
        ])
        .output()
        .expect("fitctl validate should execute");
    assert!(
        fit_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&fit_output.stderr)
    );
    let fit_report: fitctl_core::artifacts::validation_report_v1::ValidationReportV1 =
        serde_json::from_slice(&fit_output.stdout).expect("fit report should decode");
    assert_eq!(fit_report.report.verdict, ValidationVerdictV1::Fit);
    assert_eq!(
        fit_report.report.primary_reason_code,
        ValidationReasonCodeV1::RequirementsSatisfied
    );
    assert!(fit_report
        .report
        .matched_requirements
        .contains(&format!("extension_requirements.{CUDA_RUNTIME_NAMESPACE}")));

    let unfit_profile_path = temp_dir.join("cuda-unfit-profile.v1.json");
    common::write_json_file(
        &unfit_profile_path,
        &serde_json::json!({
            "envelope": {
              "schema_id": "service-profile.v2",
              "schema_version": 2,
              "artifact_id": "service-profile-cuda-major-13-v1",
              "provenance": {
                "source": "test:integration",
                "collected_at": common::FIXED_TIMESTAMP
              },
              "signatures": []
            },
            "profile": {
              "profile_id": "general_compute_cuda_extension_major_13_v1",
              "core_requirements": {
                "primary_capability_class": "general_compute",
                "allowed_visibility_scopes": [
                  "bare_metal_like",
                  "vm_like",
                  "container_restricted"
                ]
              },
              "extension_requirements": {
                "fitctl.runtime.cuda": {
                  "schema_id": "fitctl.extension.runtime.cuda.requirement.v1",
                  "schema_version": 1,
                  "required_runtime": "cuda",
                  "require_presence": true,
                  "minimum_version": {
                    "major": 13,
                    "minor": 0,
                    "patch": 0
                  }
                }
              },
              "preferences": {
                "preferred_visibility_scope": "bare_metal_like"
              },
              "exclusions": {
                "forbidden_capability_classes": []
              },
              "degradation_ladder": [],
              "assurance_predicates": [],
              "assurance_requirements": []
            }
        }),
    );

    let unfit_output = Command::new(&fitctl_bin)
        .current_dir(common::repo_root())
        .args([
            "validate",
            "--contract",
            contract_path
                .to_str()
                .expect("contract path should be valid UTF-8"),
            "--profile",
            unfit_profile_path
                .to_str()
                .expect("profile path should be valid UTF-8"),
            "--validation-mode",
            "contract_only",
        ])
        .output()
        .expect("fitctl validate should execute for unfit case");
    assert!(
        unfit_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&unfit_output.stderr)
    );
    let unfit_report: fitctl_core::artifacts::validation_report_v1::ValidationReportV1 =
        serde_json::from_slice(&unfit_output.stdout).expect("unfit report should decode");
    assert_eq!(unfit_report.report.verdict, ValidationVerdictV1::Unfit);
    assert_eq!(
        unfit_report.report.primary_reason_code,
        ValidationReasonCodeV1::RequirementUnsatisfied
    );
    assert!(unfit_report
        .report
        .summary
        .contains("below the required minimum"));
}
