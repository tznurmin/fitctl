// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! CLI entrypoint for contract-only and state-aware service-profile validation.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use fitctl_core::config::resolve_service_profile_from_catalogue_path;
use fitctl_core::validate::{
    load_contract_artifact_for_validation, load_host_state_artifact_for_validation,
    load_service_profile_artifact_for_validation, validate_request_v1, ValidationModeV1,
    ValidationRequestV1,
};

pub fn run(args: &[String]) -> ExitCode {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{}", render_help());
        return ExitCode::SUCCESS;
    }

    let mut contract_path: Option<PathBuf> = None;
    let mut profile_path: Option<PathBuf> = None;
    let mut service_profile_catalogue_path: Option<PathBuf> = None;
    let mut profile_id: Option<String> = None;
    let mut state_path: Option<PathBuf> = None;
    let mut mode = ValidationModeV1::ContractOnly;
    let mut max_state_age_seconds: Option<u64> = None;
    let mut validated_at: Option<String> = None;
    let mut note: Option<String> = None;
    let mut mode_source = ValidationModeSourceV1::Default;

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--contract" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --contract requires a path");
                    return ExitCode::from(2);
                };
                contract_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--profile" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --profile requires a path");
                    return ExitCode::from(2);
                };
                profile_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--service-profile-catalogue" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --service-profile-catalogue requires a path");
                    return ExitCode::from(2);
                };
                service_profile_catalogue_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--profile-id" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --profile-id requires a value");
                    return ExitCode::from(2);
                };
                profile_id = Some(value.clone());
                index += 2;
            }
            "--state" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --state requires a path");
                    return ExitCode::from(2);
                };
                state_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--validation-mode" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --validation-mode requires a value");
                    return ExitCode::from(2);
                };
                if !matches!(mode_source, ValidationModeSourceV1::Default) {
                    eprintln!("fitctl validate: validation mode may be specified only once");
                    return ExitCode::from(2);
                }
                mode = match parse_primary_validation_mode(value) {
                    Ok(mode) => mode,
                    Err(error) => {
                        eprintln!("fitctl validate: {error}");
                        return ExitCode::from(2);
                    }
                };
                mode_source = ValidationModeSourceV1::Primary;
                index += 2;
            }
            "--mode" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --mode requires a value");
                    return ExitCode::from(2);
                };
                if !matches!(mode_source, ValidationModeSourceV1::Default) {
                    eprintln!("fitctl validate: validation mode may be specified only once");
                    return ExitCode::from(2);
                }
                mode = match parse_legacy_mode_alias(value) {
                    Ok(mode) => mode,
                    Err(error) => {
                        eprintln!("fitctl validate: {error}");
                        return ExitCode::from(2);
                    }
                };
                mode_source = ValidationModeSourceV1::Legacy;
                index += 2;
            }
            "--max-state-age" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --max-state-age requires a value");
                    return ExitCode::from(2);
                };
                max_state_age_seconds = match parse_max_state_age_seconds(value) {
                    Ok(value) => Some(value),
                    Err(error) => {
                        eprintln!("fitctl validate: {error}");
                        return ExitCode::from(2);
                    }
                };
                index += 2;
            }
            "--validated-at" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --validated-at requires a timestamp");
                    return ExitCode::from(2);
                };
                validated_at = Some(value.clone());
                index += 2;
            }
            "--note" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --note requires text");
                    return ExitCode::from(2);
                };
                note = Some(value.clone());
                index += 2;
            }
            unknown => {
                eprintln!("fitctl validate: unknown option '{unknown}'");
                return ExitCode::from(2);
            }
        }
    }

    let Some(contract_path) = contract_path else {
        eprintln!("fitctl validate: --contract is required");
        return ExitCode::from(2);
    };
    if profile_path.is_some() && service_profile_catalogue_path.is_some() {
        eprintln!(
            "fitctl validate: choose either --profile or --service-profile-catalogue/--profile-id"
        );
        return ExitCode::from(2);
    }
    if service_profile_catalogue_path.is_some() ^ profile_id.is_some() {
        eprintln!(
            "fitctl validate: --service-profile-catalogue and --profile-id must be used together"
        );
        return ExitCode::from(2);
    }
    if mode == ValidationModeV1::ContractOnly && state_path.is_some() {
        eprintln!("fitctl validate: --state is not allowed in contract_only mode");
        return ExitCode::from(2);
    }
    if mode == ValidationModeV1::ContractOnly && max_state_age_seconds.is_some() {
        eprintln!("fitctl validate: --max-state-age is not allowed in contract_only mode");
        return ExitCode::from(2);
    }
    if max_state_age_seconds.is_some() && state_path.is_none() {
        eprintln!("fitctl validate: --max-state-age requires --state");
        return ExitCode::from(2);
    }
    if mode == ValidationModeV1::StateAware && state_path.is_none() {
        eprintln!("fitctl validate: --mode state_aware requires --state");
        return ExitCode::from(2);
    }

    let contract = match load_contract_artifact_for_validation(&contract_path) {
        Ok(contract) => contract,
        Err(error) => {
            eprintln!("fitctl validate: {error}");
            return ExitCode::from(2);
        }
    };
    let service_profile = match (profile_path, service_profile_catalogue_path, profile_id) {
        (Some(path), None, None) => match load_service_profile_artifact_for_validation(&path) {
            Ok(profile) => profile,
            Err(error) => {
                eprintln!("fitctl validate: {error}");
                return ExitCode::from(2);
            }
        },
        (None, Some(catalogue_path), Some(profile_id)) => {
            match resolve_service_profile_from_catalogue_path(&catalogue_path, &profile_id) {
                Ok((_, _, profile)) => profile,
                Err(error) => {
                    eprintln!("fitctl validate: {error}");
                    return ExitCode::from(2);
                }
            }
        }
        _ => {
            eprintln!(
                "fitctl validate: --profile or --service-profile-catalogue/--profile-id is required"
            );
            return ExitCode::from(2);
        }
    };
    let host_state = match state_path {
        Some(path) => match load_host_state_artifact_for_validation(&path) {
            Ok(state) => Some(state),
            Err(error) => {
                eprintln!("fitctl validate: {error}");
                return ExitCode::from(2);
            }
        },
        None => None,
    };

    match validate_request_v1(ValidationRequestV1 {
        contract,
        service_profile,
        host_state,
        mode,
        validated_at: validated_at.unwrap_or_else(current_epoch_marker),
        notes: note,
        max_state_age_seconds,
    }) {
        Ok(report) => match serde_json::to_string_pretty(&report) {
            Ok(text) => {
                println!("{text}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("fitctl validate: failed to encode validation report: {error}");
                ExitCode::from(2)
            }
        },
        Err(error) => {
            eprintln!("fitctl validate: {error}");
            ExitCode::from(2)
        }
    }
}

fn render_help() -> &'static str {
    "Usage:\n  fitctl validate --contract <path> (--profile <path> | --service-profile-catalogue <path> --profile-id <id>) [--validation-mode <contract_only|state_advisory|state_required>] [--state <path>] [--max-state-age <value>] [--validated-at <timestamp>] [--note <text>]\n\nLegacy compatibility:\n  fitctl validate --mode <contract_only|state_aware> [--state <path>] [--max-state-age <value>] [--validated-at <timestamp>] [--note <text>]\n"
}

fn current_epoch_marker() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("unix:{seconds}")
}

fn parse_primary_validation_mode(value: &str) -> Result<ValidationModeV1, String> {
    match value {
        "contract_only" => Ok(ValidationModeV1::ContractOnly),
        "state_advisory" => Ok(ValidationModeV1::StateAdvisory),
        "state_required" => Ok(ValidationModeV1::StateRequired),
        unknown => Err(format!("unsupported validation mode '{unknown}'")),
    }
}

fn parse_legacy_mode_alias(value: &str) -> Result<ValidationModeV1, String> {
    match value {
        "contract_only" => Ok(ValidationModeV1::ContractOnly),
        "state_aware" => Ok(ValidationModeV1::StateAware),
        unknown => Err(format!("unsupported legacy validation mode '{unknown}'")),
    }
}

fn parse_max_state_age_seconds(value: &str) -> Result<u64, String> {
    if value.trim().is_empty() {
        return Err("max-state-age must be a non-blank duration value".to_string());
    }

    let (digits, multiplier) = match value.chars().last() {
        Some('s') => (&value[..value.len() - 1], 1_u64),
        Some('m') => (&value[..value.len() - 1], 60_u64),
        Some('h') => (&value[..value.len() - 1], 3_600_u64),
        Some(last) if last.is_ascii_digit() => (value, 1_u64),
        _ => {
            return Err(format!(
                "max-state-age '{value}' must use seconds, minutes, or hours"
            ));
        }
    };

    let scalar = digits
        .parse::<u64>()
        .map_err(|_| format!("max-state-age '{value}' is not a valid duration"))?;
    scalar
        .checked_mul(multiplier)
        .ok_or_else(|| format!("max-state-age '{value}' overflows the supported range"))
}

enum ValidationModeSourceV1 {
    Default,
    Primary,
    Legacy,
}
