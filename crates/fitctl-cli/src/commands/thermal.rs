// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! CLI entrypoint for thermal-oriented helper commands.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use fitctl_core::artifacts::validation_v1::validate_service_profile;
use fitctl_core::state::load_host_state_from_path;
use fitctl_core::state::thermal_v1::load_thermal_provider_config_entries_from_paths_v1;
use fitctl_core::thermal_evidence::{
    collect_thermal_evidence_v1, load_thermal_evidence_from_path_v1,
    ThermalEvidenceCollectRequestV1,
};
use fitctl_core::thermal_profile::{
    init_thermal_profile_v1, ThermalProfileInitRequestV1, ThermalProfileInitSourceV1,
};

pub fn run(args: &[String]) -> ExitCode {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{}", render_help());
        return ExitCode::SUCCESS;
    }
    match args {
        [collect, rest @ ..] if collect == "collect" => run_collect(rest),
        [profile, init, rest @ ..] if profile == "profile" && init == "init" => {
            run_profile_init(rest)
        }
        [profile] if profile == "profile" => {
            eprintln!("fitctl thermal: expected nested command 'init'");
            ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR)
        }
        [] => {
            eprintln!("fitctl thermal: expected nested command 'collect' or 'profile init'");
            ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR)
        }
        [unknown, ..] => {
            eprintln!("fitctl thermal: unknown nested command '{unknown}'");
            ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR)
        }
    }
}

fn run_collect(args: &[String]) -> ExitCode {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{}", render_help());
        return ExitCode::SUCCESS;
    }

    let mut provider_config_paths = Vec::new();
    let mut out_path: Option<PathBuf> = None;
    let mut required_target_host_id: Option<String> = None;

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--thermal-provider-config" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl thermal collect: --thermal-provider-config requires a path");
                    return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
                };
                provider_config_paths.push(PathBuf::from(value));
                index += 2;
            }
            "--out" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl thermal collect: --out requires a path");
                    return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
                };
                out_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--require-target-host-id" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!(
                        "fitctl thermal collect: --require-target-host-id requires a host id"
                    );
                    return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
                };
                if value.trim().is_empty() || value.contains(char::is_whitespace) {
                    eprintln!(
                        "fitctl thermal collect: --require-target-host-id must be non-empty and contain no whitespace"
                    );
                    return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
                }
                required_target_host_id = Some(value.clone());
                index += 2;
            }
            unknown => {
                eprintln!("fitctl thermal collect: unknown option '{unknown}'");
                return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
            }
        }
    }

    let provider_configs =
        match load_thermal_provider_config_entries_from_paths_v1(&provider_config_paths) {
            Ok(configs) => configs,
            Err(error) => {
                eprintln!("fitctl thermal collect: {error}");
                return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
            }
        };
    let artifact = match collect_thermal_evidence_v1(ThermalEvidenceCollectRequestV1 {
        provider_configs,
        collected_at: None,
        required_target_host_id,
    }) {
        Ok(artifact) => artifact,
        Err(error) => {
            eprintln!("fitctl thermal collect: {error}");
            return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
        }
    };
    let text = match serde_json::to_string_pretty(&artifact) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("fitctl thermal collect: failed to encode thermal evidence: {error}");
            return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
        }
    };
    if let Some(path) = out_path {
        if let Err(error) = fs::write(&path, text.as_bytes()) {
            eprintln!(
                "fitctl thermal collect: failed to write {}: {error}",
                path.display()
            );
            return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
        }
    } else {
        println!("{text}");
    }

    ExitCode::SUCCESS
}

fn run_profile_init(args: &[String]) -> ExitCode {
    let mut state_path: Option<PathBuf> = None;
    let mut thermal_evidence_path: Option<PathBuf> = None;
    let mut profile_id = "generated_thermal_profile_v1".to_string();
    let mut display_name: Option<String> = None;
    let mut short_display_name: Option<String> = None;
    let mut primary_capability_class = "general_compute".to_string();
    let mut margin_millidegrees_celsius = 10_000;
    let mut out_path: Option<PathBuf> = None;

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--state" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl thermal profile init: --state requires a path");
                    return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
                };
                state_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--thermal-evidence" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl thermal profile init: --thermal-evidence requires a path");
                    return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
                };
                thermal_evidence_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--profile-id" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl thermal profile init: --profile-id requires a value");
                    return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
                };
                profile_id = value.clone();
                index += 2;
            }
            "--display-name" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl thermal profile init: --display-name requires a value");
                    return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
                };
                display_name = Some(value.clone());
                index += 2;
            }
            "--short-display-name" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl thermal profile init: --short-display-name requires a value");
                    return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
                };
                short_display_name = Some(value.clone());
                index += 2;
            }
            "--primary-capability-class" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!(
                        "fitctl thermal profile init: --primary-capability-class requires a value"
                    );
                    return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
                };
                primary_capability_class = value.clone();
                index += 2;
            }
            "--margin-mc" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl thermal profile init: --margin-mc requires a value");
                    return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
                };
                let Some(parsed) = value.parse::<i64>().ok().filter(|value| *value > 0) else {
                    eprintln!(
                        "fitctl thermal profile init: --margin-mc must be a positive integer"
                    );
                    return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
                };
                margin_millidegrees_celsius = parsed;
                index += 2;
            }
            "--out" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl thermal profile init: --out requires a path");
                    return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
                };
                out_path = Some(PathBuf::from(value));
                index += 2;
            }
            unknown => {
                eprintln!("fitctl thermal profile init: unknown option '{unknown}'");
                return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
            }
        }
    }

    let source = match (state_path, thermal_evidence_path) {
        (Some(state_path), None) => {
            let state = match load_host_state_from_path(&state_path) {
                Ok(state) => state,
                Err(error) => {
                    eprintln!("fitctl thermal profile init: {error}");
                    return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
                }
            };
            ThermalProfileInitSourceV1::State(Box::new(state))
        }
        (None, Some(thermal_evidence_path)) => {
            let thermal_evidence = match load_thermal_evidence_from_path_v1(&thermal_evidence_path)
            {
                Ok(artifact) => artifact,
                Err(error) => {
                    eprintln!("fitctl thermal profile init: {error}");
                    return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
                }
            };
            ThermalProfileInitSourceV1::ThermalEvidence(Box::new(thermal_evidence))
        }
        _ => {
            eprintln!(
                "fitctl thermal profile init: requires exactly one of --state or --thermal-evidence"
            );
            return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
        }
    };
    let profile = match init_thermal_profile_v1(ThermalProfileInitRequestV1 {
        source,
        profile_id,
        display_name,
        short_display_name,
        primary_capability_class,
        margin_millidegrees_celsius,
    }) {
        Ok(profile) => profile,
        Err(error) => {
            eprintln!("fitctl thermal profile init: {error}");
            return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
        }
    };
    if let Err(error) = validate_service_profile(&profile) {
        eprintln!("fitctl thermal profile init: {}", error.message);
        return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
    }
    let text = match serde_json::to_string_pretty(&profile) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("fitctl thermal profile init: failed to encode service profile: {error}");
            return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
        }
    };
    if let Some(path) = out_path {
        if let Err(error) = fs::write(&path, text.as_bytes()) {
            eprintln!(
                "fitctl thermal profile init: failed to write {}: {error}",
                path.display()
            );
            return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
        }
    } else {
        println!("{text}");
    }
    ExitCode::SUCCESS
}

fn render_help() -> &'static str {
    "Usage:\n  fitctl thermal collect --thermal-provider-config <path> ... [--require-target-host-id <host-id>] [--out <path>]\n  fitctl thermal profile init (--state <host-state.json> | --thermal-evidence <thermal-evidence.json>) [--margin-mc <millidegrees>] [--profile-id <id>] [--display-name <text>] [--short-display-name <text>] [--primary-capability-class <class>] [--out <path>]\n\nNotes:\n  - collect emits a fitctl.thermal-evidence.v1 artifact from exact-argv provider configs\n  - --require-target-host-id rejects provider configs whose evidence_target does not match the required host id before running providers\n  - profile init emits a reviewable service-profile.v2 skeleton from existing thermal state or standalone thermal evidence\n  - default profile margin is 10000 millidegrees Celsius above the observed reading\n  - fitctl does not assign workload shutdown or power policy\n"
}
