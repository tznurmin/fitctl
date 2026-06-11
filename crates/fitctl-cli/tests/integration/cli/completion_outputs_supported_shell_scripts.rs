// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

use crate::cli;

#[test]
fn completion_outputs_supported_shell_scripts() {
    let fitctl_bin = cli::fitctl_bin();

    for (shell, marker, color_flag, validation_mode_flag) in [
        (
            "bash",
            "complete -F _fitctl_completion fitctl",
            "--color",
            "--validation-mode",
        ),
        ("zsh", "#compdef fitctl", "--color", "--validation-mode"),
        (
            "fish",
            "complete -c fitctl -f",
            "-l color",
            "-l validation-mode",
        ),
    ] {
        let output = Command::new(&fitctl_bin)
            .args(["completion", shell])
            .output()
            .expect("fitctl completion should execute");

        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).expect("completion output should be UTF-8");
        assert!(stdout.contains(marker), "missing marker for {shell}");
        assert!(stdout.contains("survey"));
        assert!(stdout.contains("completion"));
        assert!(
            stdout.contains(color_flag),
            "missing color flag for {shell}"
        );
        assert!(
            stdout.contains(validation_mode_flag),
            "missing validation mode flag for {shell}"
        );
        assert!(
            stdout.contains("coverage"),
            "missing coverage view for {shell}"
        );
        for redaction_profile in ["local", "fleet", "auditor", "external"] {
            assert!(
                stdout.contains(redaction_profile),
                "missing redaction profile {redaction_profile} for {shell}"
            );
        }
        assert!(
            stdout.contains("--require-fit")
                || stdout.contains("-l require-fit")
                || stdout.contains("require-fit"),
            "missing require-fit flag for {shell}"
        );
        assert!(
            stdout.contains("--fail-on-unfit")
                || stdout.contains("-l fail-on-unfit")
                || stdout.contains("fail-on-unfit"),
            "missing fail-on-unfit flag for {shell}"
        );
        for option in [
            "cuda-environment-catalogue",
            "cuda-environment-id",
            "cuda-selected-environment-input",
            "config-bundle",
            "invocation-context",
            "live-state",
            "policy-pack-lock",
            "recommendation-pack-id",
        ] {
            assert!(
                stdout.contains(option),
                "missing completion option {option} for {shell}"
            );
        }
        if shell == "fish" {
            assert!(
                stdout.contains("__fish_seen_subcommand_from inspect-config resolve-config"),
                "fish completion should resolve inspect-config aliases for option completion"
            );
        }
    }
}

#[test]
fn completion_rejects_unsupported_shells() {
    let fitctl_bin = cli::fitctl_bin();
    let output = Command::new(&fitctl_bin)
        .args(["completion", "powershell"])
        .output()
        .expect("fitctl completion should execute");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("fitctl completion: unsupported shell 'powershell'"));
}
