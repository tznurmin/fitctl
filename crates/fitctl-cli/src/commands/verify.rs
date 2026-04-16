// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! CLI entrypoint for signature verification under local trust policy.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use fitctl_core::verify::{
    build_verification_bundle_v1, load_artifact_record_for_verification,
    load_external_trust_evidence_from_path, load_trust_policy_from_path,
    verify_artifact_with_policy_and_evidence_at_v1,
};

pub fn run(args: &[String]) -> ExitCode {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{}", render_help());
        return ExitCode::SUCCESS;
    }

    let mut input_path: Option<PathBuf> = None;
    let mut policy_path: Option<PathBuf> = None;
    let mut bundle_out_path: Option<PathBuf> = None;
    let mut trust_evidence_paths: Vec<PathBuf> = Vec::new();

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl verify: --input requires a path");
                    return ExitCode::from(2);
                };
                input_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--policy" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl verify: --policy requires a path");
                    return ExitCode::from(2);
                };
                policy_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--bundle-out" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl verify: --bundle-out requires a path");
                    return ExitCode::from(2);
                };
                bundle_out_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--trust-evidence" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl verify: --trust-evidence requires a path");
                    return ExitCode::from(2);
                };
                trust_evidence_paths.push(PathBuf::from(value));
                index += 2;
            }
            unknown => {
                eprintln!("fitctl verify: unknown option '{unknown}'");
                return ExitCode::from(2);
            }
        }
    }

    let Some(input_path) = input_path else {
        eprintln!("fitctl verify: --input is required");
        return ExitCode::from(2);
    };
    let Some(policy_path) = policy_path else {
        eprintln!("fitctl verify: --policy is required");
        return ExitCode::from(2);
    };

    let artifact = match load_artifact_record_for_verification(&input_path) {
        Ok(artifact) => artifact,
        Err(error) => {
            eprintln!("fitctl verify: {error}");
            return ExitCode::from(2);
        }
    };
    let policy = match load_trust_policy_from_path(&policy_path) {
        Ok(policy) => policy,
        Err(error) => {
            eprintln!("fitctl verify: {error}");
            return ExitCode::from(2);
        }
    };
    let mut trust_evidence = Vec::new();
    for path in trust_evidence_paths {
        match load_external_trust_evidence_from_path(&path) {
            Ok(document) => trust_evidence.push(document),
            Err(error) => {
                eprintln!("fitctl verify: {error}");
                return ExitCode::from(2);
            }
        }
    }

    let verified_at = current_epoch_marker();
    match verify_artifact_with_policy_and_evidence_at_v1(
        &artifact,
        &policy,
        &trust_evidence,
        &verified_at,
    ) {
        Ok(report) => match serde_json::to_string_pretty(&report) {
            Ok(text) => {
                if let Some(bundle_path) = bundle_out_path {
                    let bundle =
                        match build_verification_bundle_v1(&artifact, &report, &verified_at) {
                            Ok(bundle) => bundle,
                            Err(error) => {
                                eprintln!("fitctl verify: {error}");
                                return ExitCode::from(2);
                            }
                        };
                    let bundle_text = match serde_json::to_string_pretty(&bundle) {
                        Ok(bundle_text) => bundle_text,
                        Err(error) => {
                            eprintln!(
                                "fitctl verify: failed to encode verification bundle: {error}"
                            );
                            return ExitCode::from(2);
                        }
                    };
                    if let Err(error) = std::fs::write(&bundle_path, bundle_text) {
                        eprintln!(
                            "fitctl verify: failed to write verification bundle {}: {error}",
                            bundle_path.display()
                        );
                        return ExitCode::from(2);
                    }
                }
                println!("{text}");
                if report.accepted_by_policy {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(fitctl_core::EXIT_CODE_POLICY_REJECTION)
                }
            }
            Err(error) => {
                eprintln!("fitctl verify: failed to encode verification report: {error}");
                ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR)
            }
        },
        Err(error) => {
            eprintln!("fitctl verify: {error}");
            ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR)
        }
    }
}

fn render_help() -> &'static str {
    "Usage:\n  fitctl verify --input <path> --policy <trust-policy-path> [--trust-evidence <path> ...] [--bundle-out <path>]\n"
}

fn current_epoch_marker() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after the Unix epoch")
        .as_secs();
    format!("epoch:{seconds}")
}
