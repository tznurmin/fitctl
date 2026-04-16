// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::process::Command;

pub fn fitctl_bin() -> PathBuf {
    std::env::var_os("CARGO_BIN_EXE_fitctl")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/fitctl")
        })
}

pub fn ensure_fitctl_built() -> PathBuf {
    let bin = fitctl_bin();
    if bin.exists() {
        return bin;
    }

    let output = Command::new("cargo")
        .args(["build", "--quiet", "-p", "fitctl-cli", "--bin", "fitctl"])
        .current_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .output()
        .expect("cargo build --bin fitctl should execute");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fitctl_bin()
}
