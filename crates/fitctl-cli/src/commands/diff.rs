// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! CLI entrypoint for semantic artifact diffing.

use std::path::PathBuf;
use std::process::ExitCode;

use fitctl_core::diff::{diff_artifact_records_v1, load_artifact_record_for_diff};

pub fn run(args: &[String]) -> ExitCode {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{}", render_help());
        return ExitCode::SUCCESS;
    }

    let mut left_path: Option<PathBuf> = None;
    let mut right_path: Option<PathBuf> = None;

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--left" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl diff: --left requires a path");
                    return ExitCode::from(2);
                };
                left_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--right" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl diff: --right requires a path");
                    return ExitCode::from(2);
                };
                right_path = Some(PathBuf::from(value));
                index += 2;
            }
            unknown => {
                eprintln!("fitctl diff: unknown option '{unknown}'");
                return ExitCode::from(2);
            }
        }
    }

    let Some(left_path) = left_path else {
        eprintln!("fitctl diff: --left is required");
        return ExitCode::from(2);
    };
    let Some(right_path) = right_path else {
        eprintln!("fitctl diff: --right is required");
        return ExitCode::from(2);
    };

    let left = match load_artifact_record_for_diff(&left_path) {
        Ok(artifact) => artifact,
        Err(error) => {
            eprintln!("fitctl diff: {error}");
            return ExitCode::from(2);
        }
    };
    let right = match load_artifact_record_for_diff(&right_path) {
        Ok(artifact) => artifact,
        Err(error) => {
            eprintln!("fitctl diff: {error}");
            return ExitCode::from(2);
        }
    };

    match diff_artifact_records_v1(&left, &right) {
        Ok(report) => match serde_json::to_string_pretty(&report) {
            Ok(text) => {
                println!("{text}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("fitctl diff: failed to encode diff report: {error}");
                ExitCode::from(2)
            }
        },
        Err(error) => {
            eprintln!("fitctl diff: {error}");
            ExitCode::from(2)
        }
    }
}

fn render_help() -> &'static str {
    "Usage:\n  fitctl diff --left <path> --right <path>\n"
}
