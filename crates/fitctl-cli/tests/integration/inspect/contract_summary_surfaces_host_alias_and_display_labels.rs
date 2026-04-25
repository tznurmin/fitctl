// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::common;
use crate::e2e;

#[test]
fn contract_summary_surfaces_host_alias_and_display_labels() {
    let temp_dir = common::unique_temp_dir("integration-inspect-contract-labels");
    let survey = e2e::emit_survey_fixture(&temp_dir, "linux-bare-metal-like-v1");
    let contract = e2e::derive_contract(&temp_dir, &survey, "general_compute_default.v1.json");

    let inspect_output = e2e::run_fitctl([
        "inspect",
        "--input",
        contract
            .to_str()
            .expect("contract path should be valid UTF-8"),
    ]);
    e2e::assert_success(&inspect_output);

    let summary = String::from_utf8(inspect_output.stdout).expect("inspect output should be UTF-8");
    assert!(summary.contains("Host alias: cpu-host-01"));
    assert!(summary.contains("Display name: cpu-host-01 / General compute default policy"));
    assert!(summary.contains("Short display name: General compute default"));
}
