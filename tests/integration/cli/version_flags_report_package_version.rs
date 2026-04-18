// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use crate::cli;
use fitctl_core::artifacts::envelope_v1::LOCAL_FITCTL_VERSION_V1;
use std::process::Command;

#[test]
fn version_flags_report_package_version() {
    let fitctl_bin = build_fitctl_for_version_check();

    for args in [["--version"], ["-V"], ["version"]] {
        let output = Command::new(&fitctl_bin)
            .args(args)
            .output()
            .expect("fitctl version command should execute");

        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            format!("fitctl {LOCAL_FITCTL_VERSION_V1}\n")
        );
        assert!(
            output.stderr.is_empty(),
            "stderr should be empty for version output"
        );
    }
}

fn build_fitctl_for_version_check() -> std::path::PathBuf {
    if std::env::var_os("CARGO_BIN_EXE_fitctl").is_some() {
        return cli::fitctl_bin();
    }

    let output = Command::new("cargo")
        .args(["build", "--quiet", "-p", "fitctl-cli", "--bin", "fitctl"])
        .current_dir(crate::common::repo_root())
        .output()
        .expect("cargo build --bin fitctl should execute");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    cli::fitctl_bin()
}
