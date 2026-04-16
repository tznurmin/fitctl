// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! CLI entrypoint for export adapters and presentation-friendly derived views.

use std::path::PathBuf;
use std::process::ExitCode;

use fitctl_core::export::{
    emit_adapter_export_with_options_v1, load_artifact_record_for_export, parse_adapter_target_v1,
    AdapterExportOptionsV1,
};

pub fn run(args: &[String]) -> ExitCode {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{}", render_help());
        return ExitCode::SUCCESS;
    }

    let mut input_path: Option<PathBuf> = None;
    let mut target: Option<String> = None;
    let mut trust_domain: Option<String> = None;
    let mut pseudonym_secret: Option<String> = None;

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl export: --input requires a path");
                    return ExitCode::from(2);
                };
                input_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--target" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl export: --target requires a value");
                    return ExitCode::from(2);
                };
                target = Some(value.clone());
                index += 2;
            }
            "--trust-domain" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl export: --trust-domain requires a value");
                    return ExitCode::from(2);
                };
                trust_domain = Some(value.clone());
                index += 2;
            }
            "--pseudonym-secret" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl export: --pseudonym-secret requires a value");
                    return ExitCode::from(2);
                };
                pseudonym_secret = Some(value.clone());
                index += 2;
            }
            unknown => {
                eprintln!("fitctl export: unknown option '{unknown}'");
                return ExitCode::from(2);
            }
        }
    }

    let Some(input_path) = input_path else {
        eprintln!("fitctl export: --input is required");
        return ExitCode::from(2);
    };
    let Some(target) = target else {
        eprintln!("fitctl export: --target is required");
        return ExitCode::from(2);
    };

    let target = match parse_adapter_target_v1(&target) {
        Ok(target) => target,
        Err(error) => {
            eprintln!("fitctl export: {error}");
            return ExitCode::from(2);
        }
    };

    let artifact = match load_artifact_record_for_export(&input_path) {
        Ok(artifact) => artifact,
        Err(error) => {
            eprintln!("fitctl export: {error}");
            return ExitCode::from(2);
        }
    };

    match emit_adapter_export_with_options_v1(
        target,
        &artifact,
        &AdapterExportOptionsV1 {
            trust_domain,
            pseudonym_secret,
        },
    ) {
        Ok(export) => {
            if let Err(error) = serde_json::to_writer_pretty(std::io::stdout(), &export) {
                eprintln!("fitctl export: failed to encode adapter export: {error}");
                return ExitCode::from(2);
            }
            println!();
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("fitctl export: {error}");
            ExitCode::from(2)
        }
    }
}

fn render_help() -> &'static str {
    "Usage:\n  fitctl export --target <kubernetes_labels|nomad_attributes|gating_summary|identity_summary> --input <path> [--trust-domain <value>] [--pseudonym-secret <value>]\n"
}
