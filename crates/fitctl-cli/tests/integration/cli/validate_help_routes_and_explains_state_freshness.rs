// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

use crate::cli;

#[test]
fn validate_help_routes_and_explains_state_freshness() {
    let fitctl_bin = cli::fitctl_bin();
    let direct_output = Command::new(&fitctl_bin)
        .args(["validate", "--help"])
        .output()
        .expect("validate help should execute");
    let routed_output = Command::new(&fitctl_bin)
        .args(["help", "validate"])
        .output()
        .expect("help validate should execute");
    let prefix_output = Command::new(&fitctl_bin)
        .args(["--help", "validate"])
        .output()
        .expect("--help validate should execute");

    assert!(
        direct_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&direct_output.stderr)
    );
    assert!(
        routed_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&routed_output.stderr)
    );
    assert!(
        prefix_output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&prefix_output.stderr)
    );
    assert_eq!(direct_output.stdout, routed_output.stdout);
    assert_eq!(direct_output.stderr, routed_output.stderr);
    assert_eq!(direct_output.stdout, prefix_output.stdout);
    assert_eq!(direct_output.stderr, prefix_output.stderr);

    let stdout = String::from_utf8(direct_output.stdout).expect("help output should be UTF-8");
    for marker in [
        "fitctl validate --contract <path>",
        "fitctl validate --survey <path>",
        "Modes:",
        "state_advisory",
        "state_required",
        "--validated-at <timestamp>",
        "--max-state-age <value>",
        "accepts UTC RFC3339 or unix:<seconds>",
        "contract_only does not accept host-state input",
    ] {
        assert!(
            stdout.contains(marker),
            "missing validate help marker: {marker}"
        );
    }
}
