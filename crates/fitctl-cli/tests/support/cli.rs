// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::sync::OnceLock;

static FITCTL_BIN: OnceLock<PathBuf> = OnceLock::new();

pub fn fitctl_bin() -> PathBuf {
    FITCTL_BIN.get_or_init(resolve_fitctl_bin).clone()
}

fn resolve_fitctl_bin() -> PathBuf {
    if let Some(bin) = env_path("FITCTL_TEST_BIN") {
        assert!(
            bin.is_file(),
            "FITCTL_TEST_BIN points to a missing fitctl binary: {}",
            bin.display()
        );
        return bin;
    }

    if let Some(bin) = option_env!("CARGO_BIN_EXE_fitctl").map(PathBuf::from) {
        assert!(
            bin.is_file(),
            "CARGO_BIN_EXE_fitctl points to a missing fitctl binary: {}",
            bin.display()
        );
        return bin;
    }

    panic!("fitctl CLI integration tests require Cargo-provided CARGO_BIN_EXE_fitctl or explicit FITCTL_TEST_BIN")
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).map(PathBuf::from)
}
