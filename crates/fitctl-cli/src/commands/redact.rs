// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! CLI entrypoint for artifact redaction using built-in profiles.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use fitctl_core::redact::{
    load_artifact_record_for_redaction, parse_builtin_redaction_profile_v1, redact_artifact_v1,
    RedactionRequestV1,
};

pub fn run(args: &[String]) -> ExitCode {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{}", render_help());
        return ExitCode::SUCCESS;
    }

    let mut profile: Option<String> = None;
    let mut input_path: Option<PathBuf> = None;

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--profile" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl redact: --profile requires a value");
                    return ExitCode::from(2);
                };
                profile = Some(value.clone());
                index += 2;
            }
            "--input" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl redact: --input requires a path");
                    return ExitCode::from(2);
                };
                input_path = Some(PathBuf::from(value));
                index += 2;
            }
            unknown => {
                eprintln!("fitctl redact: unknown option '{unknown}'");
                return ExitCode::from(2);
            }
        }
    }

    let Some(profile) = profile else {
        eprintln!("fitctl redact: --profile is required");
        return ExitCode::from(2);
    };
    let Some(input_path) = input_path else {
        eprintln!("fitctl redact: --input is required");
        return ExitCode::from(2);
    };

    let profile = match parse_builtin_redaction_profile_v1(&profile) {
        Ok(profile) => profile,
        Err(error) => {
            eprintln!("fitctl redact: {error}");
            return ExitCode::from(2);
        }
    };
    let artifact = match load_artifact_record_for_redaction(&input_path) {
        Ok(artifact) => artifact,
        Err(error) => {
            eprintln!("fitctl redact: {error}");
            return ExitCode::from(2);
        }
    };

    match redact_artifact_v1(RedactionRequestV1 {
        artifact,
        profile,
        redacted_at: current_epoch_marker(),
    }) {
        Ok(artifact) => match serde_json::to_string_pretty(&artifact) {
            Ok(text) => {
                println!("{text}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("fitctl redact: failed to encode redacted artifact: {error}");
                ExitCode::from(2)
            }
        },
        Err(error) => {
            eprintln!("fitctl redact: {error}");
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
    "Usage:\n  fitctl redact --profile <local|fleet|auditor|external> --input <path>\n"
}
