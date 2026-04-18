// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::cli;
use crate::common;
use std::process::Command;

#[test]
fn inspect_renders_host_survey_summary() {
    let fitctl_bin = cli::ensure_fitctl_built();
    let temp_dir = common::unique_temp_dir("integration-inspect-survey");
    let input_path = temp_dir.join("survey.json");
    common::write_json_file(
        &input_path,
        &common::collect_survey_fixture("linux-bare-metal-like-v1"),
    );

    let output = Command::new(&fitctl_bin)
        .args([
            "inspect",
            "--input",
            input_path
                .to_str()
                .expect("input path should be valid UTF-8"),
        ])
        .output()
        .expect("fitctl inspect should execute");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("inspect output should be UTF-8");
    assert!(stdout.contains("Artifact\n  Family: host-survey.v2"));
    assert!(stdout.contains("Summary\n  Host alias: cpu-host-01"));
    assert!(stdout.contains("  Collection mode: replay"));
    assert!(stdout.contains("  Privilege level: elevated"));
    assert!(stdout.contains("  CPU: observed; x86_64;"));
    assert!(stdout.contains("  Network: observed; 2 interfaces;"));
    assert!(stdout.contains("Metadata\n  Collected at: 2025-04-21 14:37:19 UTC"));
}
