// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! CLI binary entry point for fitctl.
//!
//! The binary stays intentionally small: argument parsing and command dispatch live in the local
//! commands module, while the semantic behavior lives in fitctl-core.

use std::process::ExitCode;

mod commands;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    commands::run(&args)
}
