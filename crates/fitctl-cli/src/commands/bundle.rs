// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! CLI entrypoint for local decision-bundle assembly.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use fitctl_core::bundle::{
    assemble_decision_bundle_v1, bundle_record_v1, load_decision_bundle_inputs_from_paths_v1,
};

pub fn run(args: &[String]) -> ExitCode {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{}", render_help());
        return ExitCode::SUCCESS;
    }

    let mut validation_report_path: Option<PathBuf> = None;
    let mut contract_path: Option<PathBuf> = None;
    let mut state_path: Option<PathBuf> = None;
    let mut resolved_config_path: Option<PathBuf> = None;
    let mut config_bundle_path: Option<PathBuf> = None;
    let mut verification_bundle_path: Option<PathBuf> = None;
    let mut recommendation_report_path: Option<PathBuf> = None;
    let mut bundled_at: Option<String> = None;
    let mut note: Option<String> = None;

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--validation-report" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl bundle: --validation-report requires a path");
                    return ExitCode::from(2);
                };
                validation_report_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--contract" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl bundle: --contract requires a path");
                    return ExitCode::from(2);
                };
                contract_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--state" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl bundle: --state requires a path");
                    return ExitCode::from(2);
                };
                state_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--resolved-config" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl bundle: --resolved-config requires a path");
                    return ExitCode::from(2);
                };
                resolved_config_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--config-bundle" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl bundle: --config-bundle requires a path");
                    return ExitCode::from(2);
                };
                config_bundle_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--verification-bundle" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl bundle: --verification-bundle requires a path");
                    return ExitCode::from(2);
                };
                verification_bundle_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--recommendation-report" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl bundle: --recommendation-report requires a path");
                    return ExitCode::from(2);
                };
                recommendation_report_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--bundled-at" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl bundle: --bundled-at requires a timestamp");
                    return ExitCode::from(2);
                };
                bundled_at = Some(value.clone());
                index += 2;
            }
            "--note" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl bundle: --note requires text");
                    return ExitCode::from(2);
                };
                note = Some(value.clone());
                index += 2;
            }
            unknown => {
                eprintln!("fitctl bundle: unknown option '{unknown}'");
                return ExitCode::from(2);
            }
        }
    }

    let Some(validation_report_path) = validation_report_path else {
        eprintln!("fitctl bundle: --validation-report is required");
        return ExitCode::from(2);
    };
    let Some(contract_path) = contract_path else {
        eprintln!("fitctl bundle: --contract is required");
        return ExitCode::from(2);
    };
    if resolved_config_path.is_some() && config_bundle_path.is_some() {
        eprintln!("fitctl bundle: --config-bundle must not be combined with --resolved-config");
        return ExitCode::from(2);
    }

    let request = match load_decision_bundle_inputs_from_paths_v1(
        &validation_report_path,
        &contract_path,
        state_path.as_deref(),
        resolved_config_path.as_deref(),
        config_bundle_path.as_deref(),
        verification_bundle_path.as_deref(),
        recommendation_report_path.as_deref(),
        bundled_at.unwrap_or_else(current_epoch_marker),
        note,
    ) {
        Ok(request) => request,
        Err(error) => {
            eprintln!("fitctl bundle: {error}");
            return ExitCode::from(2);
        }
    };

    match assemble_decision_bundle_v1(request) {
        Ok(bundle) => match serde_json::to_string_pretty(&bundle_record_v1(bundle)) {
            Ok(text) => {
                println!("{text}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("fitctl bundle: failed to encode decision bundle: {error}");
                ExitCode::from(2)
            }
        },
        Err(error) => {
            eprintln!("fitctl bundle: {error}");
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
    "Usage:\n  fitctl bundle --validation-report <path> --contract <path> [--state <path>] [--resolved-config <path> | --config-bundle <path>] [--verification-bundle <path>] [--recommendation-report <path>] [--bundled-at <timestamp>] [--note <text>]\n"
}
