// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! CLI entrypoint for local artifact signing.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use fitctl_core::sign::{load_artifact_record_for_signing, sign_artifact_v1, SignatureRequestV1};

pub fn run(args: &[String]) -> ExitCode {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{}", render_help());
        return ExitCode::SUCCESS;
    }

    let mut key_path: Option<PathBuf> = None;
    let mut input_path: Option<PathBuf> = None;

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--key" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl sign: --key requires a path");
                    return ExitCode::from(2);
                };
                key_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--input" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl sign: --input requires a path");
                    return ExitCode::from(2);
                };
                input_path = Some(PathBuf::from(value));
                index += 2;
            }
            unknown => {
                eprintln!("fitctl sign: unknown option '{unknown}'");
                return ExitCode::from(2);
            }
        }
    }

    let Some(key_path) = key_path else {
        eprintln!("fitctl sign: --key is required");
        return ExitCode::from(2);
    };
    let Some(input_path) = input_path else {
        eprintln!("fitctl sign: --input is required");
        return ExitCode::from(2);
    };

    let artifact = match load_artifact_record_for_signing(&input_path) {
        Ok(artifact) => artifact,
        Err(error) => {
            eprintln!("fitctl sign: {error}");
            return ExitCode::from(2);
        }
    };

    match sign_artifact_v1(SignatureRequestV1 {
        artifact,
        private_key_path: key_path,
        signed_at: current_epoch_marker(),
    }) {
        Ok(artifact) => match serde_json::to_string_pretty(&artifact) {
            Ok(text) => {
                println!("{text}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("fitctl sign: failed to encode signed artifact: {error}");
                ExitCode::from(2)
            }
        },
        Err(error) => {
            eprintln!("fitctl sign: {error}");
            ExitCode::from(2)
        }
    }
}

fn current_epoch_marker() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("unix:{seconds}")
}

fn render_help() -> &'static str {
    "Usage:\n  fitctl sign --key <private-key-path> --input <path>\n"
}
