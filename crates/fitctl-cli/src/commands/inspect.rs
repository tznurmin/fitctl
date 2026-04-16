// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! CLI entrypoint for human-readable artifact inspection.

use std::io::{self, IsTerminal, Read};
use std::path::PathBuf;
use std::process::ExitCode;

use fitctl_core::inspect::{
    load_artifact_record_for_inspect, load_artifact_record_for_inspect_from_value,
    render_inspect_artifact_summary_with_options_v1, InspectRenderOptionsV1,
};

pub fn run(args: &[String]) -> ExitCode {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{}", render_help());
        return ExitCode::SUCCESS;
    }

    let mut input_path: Option<PathBuf> = None;
    let mut verbose = false;
    let mut show_identifiers = false;

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--verbose" => {
                verbose = true;
                index += 1;
            }
            "--show-identifiers" => {
                show_identifiers = true;
                index += 1;
            }
            "--input" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl inspect: --input requires a path");
                    return ExitCode::from(2);
                };
                input_path = Some(PathBuf::from(value));
                index += 2;
            }
            unknown => {
                eprintln!("fitctl inspect: unknown option '{unknown}'");
                return ExitCode::from(2);
            }
        }
    }

    let artifact = if let Some(input_path) = input_path {
        if input_path.as_os_str() == "-" {
            match load_artifact_record_from_stdin() {
                Ok(artifact) => artifact,
                Err(error) => {
                    eprintln!("fitctl inspect: {error}");
                    return ExitCode::from(2);
                }
            }
        } else {
            match load_artifact_record_for_inspect(&input_path) {
                Ok(artifact) => artifact,
                Err(error) => {
                    eprintln!("fitctl inspect: {error}");
                    return ExitCode::from(2);
                }
            }
        }
    } else if io::stdin().is_terminal() {
        eprintln!("fitctl inspect: --input is required when stdin is interactive");
        return ExitCode::from(2);
    } else {
        match load_artifact_record_from_stdin() {
            Ok(artifact) => artifact,
            Err(error) => {
                eprintln!("fitctl inspect: {error}");
                return ExitCode::from(2);
            }
        }
    };

    match render_inspect_artifact_summary_with_options_v1(
        &artifact,
        InspectRenderOptionsV1 {
            verbose,
            show_identifiers,
        },
    ) {
        Ok(summary) => {
            print!("{summary}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("fitctl inspect: {error}");
            ExitCode::from(2)
        }
    }
}

fn render_help() -> &'static str {
    "Usage:\n  fitctl inspect [--input <path>] [--verbose] [--show-identifiers]\n\nNotes:\n  - when --input is omitted and stdin is piped, inspect reads the artifact from stdin\n  - pass --input - to force stdin explicitly\n  - pass --verbose to include provenance-heavy metadata and hidden diagnostic fields\n  - pass --show-identifiers to reveal full stable identifiers, digests, and fingerprints without the full verbose surface\n"
}

fn load_artifact_record_from_stdin() -> Result<fitctl_core::inspect::InspectArtifactV1, String> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|error| format!("failed to read stdin artifact input: {error}"))?;

    if input.trim().is_empty() {
        return Err("stdin artifact input must not be empty".to_string());
    }

    let raw: serde_json::Value = serde_json::from_str(&input)
        .map_err(|error| format!("failed to decode stdin artifact JSON: {error}"))?;

    load_artifact_record_for_inspect_from_value(raw).map_err(|error| error.to_string())
}
