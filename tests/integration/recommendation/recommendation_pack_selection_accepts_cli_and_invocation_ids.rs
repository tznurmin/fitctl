// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use serde_json::json;

use crate::common;
use crate::e2e;

fn write_alternate_recommendation_pack(root: &std::path::Path) -> std::path::PathBuf {
    let path = root.join("alternate_general_compute_advisory.v1.json");
    common::write_json_file(
        &path,
        &json!({
            "schema_id": "fitctl.recommendation-pack.v1",
            "schema_version": 1,
            "pack_id": "alternate-general-compute-advisory-v1",
            "pack_version": "1.0.0",
            "summary": "Alternate advisory recommendation pack used for selection tests.",
            "output_schema_id": "fitctl.recommendation-report.v2",
            "supported_extension_namespaces": ["org.example.runtime.python"]
        }),
    );
    path
}

fn write_invocation_context(
    root: &std::path::Path,
    file_name: &str,
    selected_pack_ids: &[&str],
) -> std::path::PathBuf {
    let path = root.join(file_name);
    common::write_json_file(
        &path,
        &json!({
            "schema_id": "fitctl.invocation-context.v1",
            "schema_version": 1,
            "invocation_id": file_name.replace(".json", ""),
            "enabled_extension_namespaces": [],
            "selected_recommendation_pack_ids": selected_pack_ids,
            "enabled_simulation_layer_ids": [],
            "validation_mode": "contract_only"
        }),
    );
    path
}

#[test]
fn recommendation_pack_selection_accepts_cli_and_invocation_ids() {
    let root = common::unique_temp_dir("recommendation-pack-selection");
    let validation_path = root.join("validation.json");
    common::write_json_file(
        &validation_path,
        &common::validate_with_profile(
            common::derive_contract_from_fixture("linux-bare-metal-like-v1"),
            common::load_service_profile_file("general_compute_contract_only.v2.json"),
            None,
            fitctl_core::validate::ValidationModeV1::ContractOnly,
            None,
        ),
    );

    let alternate_pack_path = write_alternate_recommendation_pack(&root);
    let selected_invocation_path = write_invocation_context(
        &root,
        "selected_general_compute_advisory.json",
        &["general-compute-advisory-v1"],
    );

    let direct = e2e::run_fitctl([
        "recommend",
        "--validation-report",
        validation_path
            .to_str()
            .expect("validation path should be UTF-8"),
        "--recommendation-pack",
        common::repo_recommendation_pack_path("general_compute_advisory.v1.json")
            .to_str()
            .expect("pack path should be UTF-8"),
        "--recommended-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&direct);

    let cli_selected = e2e::run_fitctl([
        "recommend",
        "--validation-report",
        validation_path
            .to_str()
            .expect("validation path should be UTF-8"),
        "--recommendation-pack",
        common::repo_recommendation_pack_path("general_compute_advisory.v1.json")
            .to_str()
            .expect("pack path should be UTF-8"),
        "--recommendation-pack",
        alternate_pack_path
            .to_str()
            .expect("alternate pack path should be UTF-8"),
        "--recommendation-pack-id",
        "general-compute-advisory-v1",
        "--recommended-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&cli_selected);

    let invocation_selected = e2e::run_fitctl([
        "recommend",
        "--validation-report",
        validation_path
            .to_str()
            .expect("validation path should be UTF-8"),
        "--recommendation-pack",
        common::repo_recommendation_pack_path("general_compute_advisory.v1.json")
            .to_str()
            .expect("pack path should be UTF-8"),
        "--recommendation-pack",
        alternate_pack_path
            .to_str()
            .expect("alternate pack path should be UTF-8"),
        "--invocation-context",
        selected_invocation_path
            .to_str()
            .expect("invocation path should be UTF-8"),
        "--recommended-at",
        common::FIXED_TIMESTAMP,
    ]);
    e2e::assert_success(&invocation_selected);

    let direct_json: serde_json::Value = e2e::decode_json_stdout(&direct);
    let cli_selected_json: serde_json::Value = e2e::decode_json_stdout(&cli_selected);
    let invocation_selected_json: serde_json::Value = e2e::decode_json_stdout(&invocation_selected);
    assert_eq!(direct_json, cli_selected_json);
    assert_eq!(direct_json, invocation_selected_json);
}

#[test]
fn recommendation_pack_selection_fails_closed_on_ambiguous_ids() {
    let root = common::unique_temp_dir("recommendation-pack-ambiguous");
    let validation_path = root.join("validation.json");
    common::write_json_file(
        &validation_path,
        &common::validate_with_profile(
            common::derive_contract_from_fixture("linux-bare-metal-like-v1"),
            common::load_service_profile_file("general_compute_contract_only.v2.json"),
            None,
            fitctl_core::validate::ValidationModeV1::ContractOnly,
            None,
        ),
    );
    let alternate_pack_path = write_alternate_recommendation_pack(&root);
    let ambiguous_invocation_path = write_invocation_context(
        &root,
        "ambiguous_recommendation_selection.json",
        &[
            "general-compute-advisory-v1",
            "alternate-general-compute-advisory-v1",
        ],
    );

    let output = e2e::run_fitctl([
        "recommend",
        "--validation-report",
        validation_path
            .to_str()
            .expect("validation path should be UTF-8"),
        "--recommendation-pack",
        common::repo_recommendation_pack_path("general_compute_advisory.v1.json")
            .to_str()
            .expect("pack path should be UTF-8"),
        "--recommendation-pack",
        alternate_pack_path
            .to_str()
            .expect("alternate pack path should be UTF-8"),
        "--invocation-context",
        ambiguous_invocation_path
            .to_str()
            .expect("invocation path should be UTF-8"),
    ]);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("must resolve to exactly one invocation-selected id"));
}
