// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

use crate::cli;
use crate::common;

fn write_validation_report(root: &std::path::Path) -> std::path::PathBuf {
    let report = common::validate_with_profile(
        common::derive_contract_from_fixture("linux-bare-metal-like-v1"),
        common::load_service_profile_file("general_compute_contract_only.v2.json"),
        None,
        fitctl_core::artifacts::validation_report_v1::ValidationModeV1::ContractOnly,
        None,
    );
    let path = root.join("validation.json");
    common::write_json_file(&path, &report);
    path
}

#[test]
fn inspect_color_always_emits_ansi_for_validation_verdicts() {
    let fitctl_bin = cli::fitctl_bin();
    let temp_dir = common::unique_temp_dir("integration-inspect-color-always");
    let input_path = write_validation_report(&temp_dir);

    let output = Command::new(&fitctl_bin)
        .args([
            "inspect",
            "--input",
            input_path
                .to_str()
                .expect("input path should be valid UTF-8"),
            "--color",
            "always",
        ])
        .output()
        .expect("fitctl inspect should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("inspect output should be UTF-8");
    assert!(stdout.contains("\u{1b}[32mfit\u{1b}[0m"));
}

#[test]
fn inspect_color_auto_and_never_stay_plain_under_redirected_output() {
    let fitctl_bin = cli::fitctl_bin();
    let temp_dir = common::unique_temp_dir("integration-inspect-color-auto");
    let input_path = write_validation_report(&temp_dir);

    for mode in ["auto", "never"] {
        let output = Command::new(&fitctl_bin)
            .args([
                "inspect",
                "--input",
                input_path
                    .to_str()
                    .expect("input path should be valid UTF-8"),
                "--color",
                mode,
            ])
            .output()
            .expect("fitctl inspect should execute");

        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).expect("inspect output should be UTF-8");
        assert!(!stdout.contains("\u{1b}["));
        assert!(stdout.contains("Verdict: fit"));
    }
}
