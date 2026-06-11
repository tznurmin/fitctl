// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use crate::common;
use crate::e2e;
use fitctl_core::artifacts::batch_classification_report_v1::BatchClassificationReportV1;
use fitctl_core::artifacts::validation_report_v1::{ValidationReportV1, ValidationVerdictV1};
use fitctl_core::config::{
    built_in_extension_pack_for_namespace_v1, load_extension_pack_from_path,
    semantic_hash_hex_for_extension_pack,
};

const CUDA_NAMESPACE: &str = "fitctl.runtime.cuda";
const GPU_RUNTIME_PROFILE: &str =
    "configs/service_profiles/general_compute_cuda_runtime_allocatable_memory_required.v2.json";
const HIGH_MEMORY_PROFILE: &str =
    "examples/host-matrix-selection/high-memory-state-required.profile.json";
const EXAMPLE_VALIDATED_AT: &str = "2025-06-17T10:00:00Z";

fn status_code(output: &std::process::Output) -> i32 {
    output.status.code().expect("process should exit normally")
}

fn repo_path(relative: &str) -> PathBuf {
    common::repo_root().join(relative)
}

fn write_output(path: &Path, output: &std::process::Output) {
    std::fs::write(path, &output.stdout).expect("stdout should be written");
}

fn emit_cuda_survey(root: &Path, fixture_id: &str) -> PathBuf {
    let output = e2e::run_fitctl([
        "survey",
        "--fixture",
        fixture_id,
        "--enable-extension",
        CUDA_NAMESPACE,
    ]);
    e2e::assert_success(&output);
    let path = root.join(format!("{fixture_id}.survey.json"));
    write_output(&path, &output);
    path
}

fn derive_cuda_contract(root: &Path, survey_path: &Path) -> PathBuf {
    let output = e2e::run_fitctl([
        "contract",
        "--survey",
        survey_path
            .to_str()
            .expect("survey path should be valid UTF-8"),
        "--policy",
        "configs/policy/general_compute_default.v1.json",
        "--enable-extension",
        CUDA_NAMESPACE,
        "--derived-at",
        EXAMPLE_VALIDATED_AT,
    ]);
    e2e::assert_success(&output);
    let path = root.join("gpu.contract.json");
    write_output(&path, &output);
    path
}

fn emit_cuda_state(root: &Path, fixture_id: &str) -> PathBuf {
    let output = e2e::run_fitctl([
        "state",
        "--fixture",
        fixture_id,
        "--enable-extension",
        CUDA_NAMESPACE,
    ]);
    e2e::assert_success(&output);
    let path = root.join(format!("{fixture_id}.state.json"));
    write_output(&path, &output);
    path
}

fn validate_gpu_runner(
    root: &Path,
    contract_path: &Path,
    state_path: &Path,
) -> std::process::Output {
    let validation_path = root.join("validation.json");
    let output = e2e::run_fitctl([
        "validate",
        "--contract",
        contract_path
            .to_str()
            .expect("contract path should be valid UTF-8"),
        "--profile",
        GPU_RUNTIME_PROFILE,
        "--state",
        state_path
            .to_str()
            .expect("state path should be valid UTF-8"),
        "--validation-mode",
        "state_required",
        "--validated-at",
        EXAMPLE_VALIDATED_AT,
        "--require-fit",
    ]);
    write_output(&validation_path, &output);
    output
}

fn prepare_general_contract_and_state(
    root: &Path,
    survey_fixture: &str,
    state_fixture: &str,
    contract_name: &str,
    state_name: &str,
) -> (PathBuf, PathBuf) {
    let survey = e2e::emit_survey_fixture(root, survey_fixture);
    let contract = e2e::derive_contract(root, &survey, "general_compute_default.v1.json");
    let state = e2e::emit_state_fixture(root, state_fixture);
    let contract_out = root.join(contract_name);
    let state_out = root.join(state_name);
    std::fs::copy(&contract, &contract_out).expect("contract copy should succeed");
    std::fs::copy(&state, &state_out).expect("state copy should succeed");
    (contract_out, state_out)
}

#[test]
fn built_in_runtime_extension_packs_match_public_manifests() {
    for (namespace, manifest_path) in [
        (
            "fitctl.runtime.cuda",
            "configs/extensions/fitctl_runtime_cuda.v1.json",
        ),
        (
            "fitctl.runtime.python",
            "configs/extensions/fitctl_runtime_python.v1.json",
        ),
        (
            "fitctl.runtime.node",
            "configs/extensions/fitctl_runtime_node.v1.json",
        ),
    ] {
        let manifest = load_extension_pack_from_path(&repo_path(manifest_path))
            .expect("public extension-pack manifest should load");
        let built_in = built_in_extension_pack_for_namespace_v1(namespace)
            .expect("built-in extension pack should exist");
        assert_eq!(
            semantic_hash_hex_for_extension_pack(&built_in)
                .expect("built-in extension-pack hash should encode"),
            semantic_hash_hex_for_extension_pack(&manifest)
                .expect("manifest extension-pack hash should encode"),
            "{namespace} built-in manifest drifted from {manifest_path}"
        );
    }
}

#[test]
fn github_gpu_runner_fit_flow_matches_docs() {
    let root = common::unique_temp_dir("gpu-runner-fit");
    let survey = emit_cuda_survey(&root, "linux-gpu-workstation-like-v1");
    let contract = derive_cuda_contract(&root, &survey);
    let state = emit_cuda_state(&root, "linux-gpu-workstation-like-cuda-runtime-fit-v1");

    let output = validate_gpu_runner(&root, &contract, &state);
    e2e::assert_success(&output);

    let report: ValidationReportV1 = e2e::decode_json_stdout(&output);
    assert_eq!(report.report.verdict, ValidationVerdictV1::Fit);
    assert!(report
        .report
        .matched_requirements
        .iter()
        .any(|value| value.contains("minimum_allocatable_memory_bytes")));

    let inspect = e2e::run_fitctl([
        "inspect",
        "--input",
        root.join("validation.json")
            .to_str()
            .expect("validation path should be UTF-8"),
    ]);
    e2e::assert_success(&inspect);
    let inspect_stdout = String::from_utf8(inspect.stdout).expect("inspect output should be UTF-8");
    assert!(inspect_stdout.contains("Verdict: fit"));
    assert!(inspect_stdout.contains("Extension diagnostics: fitctl.runtime.cuda"));
}

#[test]
fn github_gpu_runner_unfit_flow_preserves_artifact_feedback() {
    let root = common::unique_temp_dir("gpu-runner-unfit");
    let survey = emit_cuda_survey(&root, "linux-gpu-workstation-like-v1");
    let contract = derive_cuda_contract(&root, &survey);
    let state = emit_cuda_state(
        &root,
        "linux-gpu-workstation-like-cuda-runtime-insufficient-v1",
    );

    let output = validate_gpu_runner(&root, &contract, &state);
    assert_eq!(
        status_code(&output),
        i32::from(fitctl_core::EXIT_CODE_POLICY_REJECTION)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("--require-fit"));

    let report: ValidationReportV1 = e2e::decode_json_stdout(&output);
    assert_eq!(report.report.verdict, ValidationVerdictV1::Unfit);
    assert_eq!(
        report.report.primary_reason_code.as_str(),
        "requirement_unsatisfied"
    );
    assert!(report
        .report
        .failed_requirements
        .iter()
        .any(|value| value.contains("minimum_allocatable_memory_bytes")));
    let cuda_diagnostic = report
        .report
        .extension_diagnostics
        .get(CUDA_NAMESPACE)
        .expect("CUDA diagnostic should be present");
    assert_eq!(
        cuda_diagnostic["detail_code"].as_str(),
        Some("allocatable_memory_insufficient")
    );
    assert_eq!(
        cuda_diagnostic["observed_allocatable_memory_bytes"].as_u64(),
        Some(8 * 1024 * 1024 * 1024)
    );
    assert_eq!(
        cuda_diagnostic["required_allocatable_memory_bytes"].as_u64(),
        Some(16 * 1024 * 1024 * 1024)
    );
    assert!(report
        .report
        .remediation_hints
        .iter()
        .any(|hint| hint.summary.contains("more free CUDA memory")));

    let inspect = e2e::run_fitctl([
        "inspect",
        "--input",
        root.join("validation.json")
            .to_str()
            .expect("validation path should be UTF-8"),
    ]);
    e2e::assert_success(&inspect);
    let inspect_stdout = String::from_utf8(inspect.stdout).expect("inspect output should be UTF-8");
    assert!(inspect_stdout.contains("Operator posture: stop"));
    assert!(inspect_stdout.contains("CUDA allocatable memory 8.00 GiB is below required 16.00 GiB"));
}

#[test]
fn validate_rejects_mismatched_state_host_alias_when_identity_is_absent() {
    let root = common::unique_temp_dir("state-mismatch");
    let survey = e2e::emit_survey_fixture(&root, "linux-gpu-workstation-like-v1");
    let contract = e2e::derive_contract(&root, &survey, "general_compute_default.v1.json");
    let mismatched_state =
        e2e::emit_state_fixture(&root, "linux-gpu-dual-numa-like-cuda-runtime-fit-v1");

    let output = e2e::run_fitctl([
        "validate",
        "--contract",
        contract.to_str().expect("contract path should be UTF-8"),
        "--profile",
        "configs/service_profiles/general_compute_stateful_thresholds.v2.json",
        "--state",
        mismatched_state
            .to_str()
            .expect("state path should be UTF-8"),
        "--validation-mode",
        "state_required",
        "--validated-at",
        EXAMPLE_VALIDATED_AT,
        "--require-fit",
    ]);

    assert_eq!(
        status_code(&output),
        i32::from(fitctl_core::EXIT_CODE_USAGE_ERROR)
    );
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("host alias"));
    assert!(stderr.contains("gpu-host-01"));
    assert!(stderr.contains("demo-gpu-numa-01"));
}

#[test]
fn host_matrix_selection_example_generates_batch_and_matrix() {
    let root = common::unique_temp_dir("host-matrix");
    let (cpu_contract, cpu_state) = prepare_general_contract_and_state(
        &root,
        "linux-bare-metal-like-v1",
        "linux-bare-metal-like-fresh-v1",
        "cpu.contract.json",
        "cpu.state.json",
    );
    let (gpu_contract, gpu_state) = prepare_general_contract_and_state(
        &root,
        "linux-gpu-workstation-like-v1",
        "linux-gpu-workstation-like-fresh-v1",
        "gpu.contract.json",
        "gpu.state.json",
    );

    let output = e2e::run_fitctl([
        "classify",
        "--contract",
        cpu_contract
            .to_str()
            .expect("CPU contract path should be UTF-8"),
        "--contract",
        gpu_contract
            .to_str()
            .expect("GPU contract path should be UTF-8"),
        "--state",
        cpu_state.to_str().expect("CPU state path should be UTF-8"),
        "--state",
        gpu_state.to_str().expect("GPU state path should be UTF-8"),
        "--profile",
        HIGH_MEMORY_PROFILE,
        "--validation-mode",
        "state_required",
        "--validated-at",
        EXAMPLE_VALIDATED_AT,
    ]);
    e2e::assert_success(&output);
    let batch_path = root.join("batch.json");
    write_output(&batch_path, &output);

    let report: BatchClassificationReportV1 = e2e::decode_json_stdout(&output);
    assert_eq!(report.report.rows.len(), 2);
    let cpu_row = report
        .report
        .rows
        .iter()
        .find(|row| row.contract_artifact_id.contains("linux-bare-metal-like"))
        .expect("CPU row should exist");
    let gpu_row = report
        .report
        .rows
        .iter()
        .find(|row| {
            row.contract_artifact_id
                .contains("linux-gpu-workstation-like")
        })
        .expect("GPU row should exist");
    assert_eq!(cpu_row.verdict, ValidationVerdictV1::Unfit);
    assert_eq!(gpu_row.verdict, ValidationVerdictV1::Fit);
    assert!(cpu_row.summary.contains("below the required floor"));

    let matrix = e2e::run_fitctl([
        "inspect",
        "--input",
        batch_path.to_str().expect("batch path should be UTF-8"),
        "--view",
        "matrix",
    ]);
    e2e::assert_success(&matrix);
    let matrix_stdout = String::from_utf8(matrix.stdout).expect("matrix output should be UTF-8");
    assert!(matrix_stdout.contains("High memory | cpu-host-01 | General compute default | unfit"));
    assert!(matrix_stdout.contains("High memory | gpu-host-01 | General compute default | fit"));

    let rows_csv = e2e::run_fitctl([
        "classify",
        "--contract",
        cpu_contract
            .to_str()
            .expect("CPU contract path should be UTF-8"),
        "--contract",
        gpu_contract
            .to_str()
            .expect("GPU contract path should be UTF-8"),
        "--state",
        cpu_state.to_str().expect("CPU state path should be UTF-8"),
        "--state",
        gpu_state.to_str().expect("GPU state path should be UTF-8"),
        "--profile",
        HIGH_MEMORY_PROFILE,
        "--validation-mode",
        "state_required",
        "--validated-at",
        EXAMPLE_VALIDATED_AT,
        "--export-view",
        "rows_csv",
    ]);
    e2e::assert_success(&rows_csv);
    let csv_stdout = String::from_utf8(rows_csv.stdout).expect("CSV output should be UTF-8");
    assert!(csv_stdout.starts_with(
        "row_id,host_alias,contract_artifact_id,contract_display_name,contract_short_display_name,service_profile_artifact_id"
    ));
    assert!(csv_stdout.contains(",cpu-host-01,"));
    assert!(csv_stdout.contains(",gpu-host-01,"));
    assert!(csv_stdout.contains(",High memory,"));
    assert!(csv_stdout.contains(",unfit,requirement_unsatisfied,"));
    assert!(csv_stdout.contains(",fit,requirements_satisfied,"));
}

#[test]
fn public_readme_examples_and_gate_wording_are_traceable() {
    let readme = std::fs::read_to_string(repo_path("README.md")).expect("README should exist");
    for marker in [
        "command-line tool for producing host-fit artifacts",
        "returning failure exit codes",
        "validation rejects a host",
        "Commands emit typed JSON",
        "validation should control the process exit status",
        "--fail-on-unfit",
        "--require-fit",
        "examples/github-actions-gpu-runner/README.md",
        "examples/host-matrix-selection/README.md",
        "structured text view of supported `fitctl` artifacts",
    ] {
        assert!(readme.contains(marker), "missing README marker: {marker}");
    }
    assert!(!readme.contains("any artifact produced by `fitctl`"));
    assert!(!readme.contains("Kubernetes"));
    assert!(readme.contains("cargo install fitctl --locked"));
    assert!(!readme.contains("nix build"));

    let validation_doc =
        std::fs::read_to_string(repo_path("docs/validation.md")).expect("validation docs exist");
    assert!(validation_doc.contains("Both flags reject `unfit` and `indeterminate`"));
}

#[test]
fn issue_template_requests_redacted_or_inspect_output_by_default() {
    let template = std::fs::read_to_string(repo_path(".github/ISSUE_TEMPLATE/host-report.md"))
        .expect("host report template should exist");
    for marker in [
        "fitctl inspect --input validation.json",
        "jq -r '.report.verdict' validation.json",
        "fitctl redact --profile external --input host.survey.json",
        "Do not attach raw host artifacts by default",
        "operating system:",
        "CUDA runtime visibility:",
    ] {
        assert!(
            template.contains(marker),
            "missing issue-template marker: {marker}"
        );
    }
    assert!(!template.contains("unredacted"));

    let root = common::unique_temp_dir("redaction-command");
    let survey = e2e::emit_survey_fixture(&root, "linux-bare-metal-like-v1");
    let output = e2e::run_fitctl([
        "redact",
        "--profile",
        "external",
        "--input",
        survey.to_str().expect("survey path should be UTF-8"),
    ]);
    e2e::assert_success(&output);
    let redacted: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("redacted artifact should parse");
    assert_eq!(
        redacted["envelope"]["redaction"]["profile_id"].as_str(),
        Some("external")
    );
}
