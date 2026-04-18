// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! CLI entrypoint for batch contract-versus-profile classification.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use fitctl_core::classify::{
    classify_batch_v1, render_batch_classification_export_view, BatchClassificationExportViewV1,
    BatchClassificationRequestV1,
};
use fitctl_core::config::{
    load_invocation_context_from_path, resolve_invocation_selected_service_profile_id_v1,
    resolve_service_profile_from_catalogue_path,
};
use fitctl_core::validate::{
    load_contract_artifact_for_validation, load_service_profile_artifact_for_validation,
};

pub fn run(args: &[String]) -> ExitCode {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{}", render_help());
        return ExitCode::SUCCESS;
    }

    let mut contract_paths = Vec::new();
    let mut profile_paths = Vec::new();
    let mut service_profile_catalogue_path: Option<PathBuf> = None;
    let mut profile_ids = Vec::new();
    let mut invocation_context_path: Option<PathBuf> = None;
    let mut validated_at: Option<String> = None;
    let mut export_view: Option<BatchClassificationExportViewV1> = None;

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--contract" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl classify: --contract requires a path");
                    return ExitCode::from(2);
                };
                contract_paths.push(PathBuf::from(value));
                index += 2;
            }
            "--profile" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl classify: --profile requires a path");
                    return ExitCode::from(2);
                };
                profile_paths.push(PathBuf::from(value));
                index += 2;
            }
            "--service-profile-catalogue" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl classify: --service-profile-catalogue requires a path");
                    return ExitCode::from(2);
                };
                if service_profile_catalogue_path.is_some() {
                    eprintln!(
                        "fitctl classify: --service-profile-catalogue may be specified only once"
                    );
                    return ExitCode::from(2);
                }
                service_profile_catalogue_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--profile-id" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl classify: --profile-id requires a value");
                    return ExitCode::from(2);
                };
                profile_ids.push(value.clone());
                index += 2;
            }
            "--invocation-context" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl classify: --invocation-context requires a path");
                    return ExitCode::from(2);
                };
                if invocation_context_path.is_some() {
                    eprintln!("fitctl classify: --invocation-context may be specified only once");
                    return ExitCode::from(2);
                }
                invocation_context_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--validated-at" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl classify: --validated-at requires a timestamp");
                    return ExitCode::from(2);
                };
                if validated_at.is_some() {
                    eprintln!("fitctl classify: --validated-at may be specified only once");
                    return ExitCode::from(2);
                }
                validated_at = Some(value.clone());
                index += 2;
            }
            "--export-view" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl classify: --export-view requires a value");
                    return ExitCode::from(2);
                };
                let Some(parsed) = BatchClassificationExportViewV1::parse(value) else {
                    eprintln!(
                        "fitctl classify: --export-view must be one of rows_csv, contract_summary_csv, service_profile_summary_csv"
                    );
                    return ExitCode::from(2);
                };
                if export_view.replace(parsed).is_some() {
                    eprintln!("fitctl classify: --export-view may be specified only once");
                    return ExitCode::from(2);
                }
                index += 2;
            }
            unknown => {
                eprintln!("fitctl classify: unknown option '{unknown}'");
                return ExitCode::from(2);
            }
        }
    }

    if contract_paths.is_empty() {
        eprintln!("fitctl classify: at least one --contract is required");
        return ExitCode::from(2);
    }
    let invocation_context = match invocation_context_path {
        Some(path) => match load_invocation_context_from_path(&path) {
            Ok(context) => Some(context),
            Err(error) => {
                eprintln!("fitctl classify: {error}");
                return ExitCode::from(2);
            }
        },
        None => None,
    };
    let invocation_selected_profile_present = invocation_context
        .as_ref()
        .and_then(|context| context.selected_service_profile_id.as_ref())
        .is_some();
    if !profile_paths.is_empty()
        && (service_profile_catalogue_path.is_some()
            || !profile_ids.is_empty()
            || invocation_selected_profile_present)
    {
        eprintln!(
            "fitctl classify: choose either repeated --profile inputs or --service-profile-catalogue with --profile-id"
        );
        return ExitCode::from(2);
    }
    if service_profile_catalogue_path.is_none()
        && (!profile_ids.is_empty() || invocation_selected_profile_present)
    {
        eprintln!(
            "fitctl classify: --service-profile-catalogue and at least one --profile-id must be used together"
        );
        return ExitCode::from(2);
    }
    if invocation_selected_profile_present && profile_ids.len() > 1 {
        eprintln!(
            "fitctl classify: invocation-context profile selection must not be combined with repeated --profile-id inputs"
        );
        return ExitCode::from(2);
    }
    let selected_catalogue_profile =
        if service_profile_catalogue_path.is_some() && profile_ids.len() <= 1 {
            match resolve_invocation_selected_service_profile_id_v1(
                profile_ids.first().map(String::as_str),
                invocation_context.as_ref(),
            ) {
                Ok(selection) => selection,
                Err(error) => {
                    eprintln!("fitctl classify: {error}");
                    return ExitCode::from(2);
                }
            }
        } else {
            None
        };
    if profile_paths.is_empty() && profile_ids.is_empty() && selected_catalogue_profile.is_none() {
        eprintln!("fitctl classify: at least one --profile or one --profile-id is required");
        return ExitCode::from(2);
    }

    let mut contracts = Vec::new();
    for path in contract_paths {
        match load_contract_artifact_for_validation(&path) {
            Ok(contract) => contracts.push(contract),
            Err(error) => {
                eprintln!("fitctl classify: {error}");
                return ExitCode::from(2);
            }
        }
    }

    let mut service_profiles = Vec::new();
    if !profile_paths.is_empty() {
        for path in profile_paths {
            match load_service_profile_artifact_for_validation(&path) {
                Ok(profile) => service_profiles.push(profile),
                Err(error) => {
                    eprintln!("fitctl classify: {error}");
                    return ExitCode::from(2);
                }
            }
        }
    } else {
        let catalogue_path = service_profile_catalogue_path
            .expect("catalogue path must be present when profile ids are used");
        let selected_profile_ids = if profile_ids.is_empty() {
            match selected_catalogue_profile {
                Some((profile_id, _)) => vec![profile_id],
                None => {
                    eprintln!(
                        "fitctl classify: --service-profile-catalogue requires at least one direct or invocation-context-backed profile id"
                    );
                    return ExitCode::from(2);
                }
            }
        } else {
            profile_ids
        };
        for profile_id in selected_profile_ids {
            match resolve_service_profile_from_catalogue_path(&catalogue_path, &profile_id) {
                Ok((_, _, profile)) => service_profiles.push(profile),
                Err(error) => {
                    eprintln!("fitctl classify: {error}");
                    return ExitCode::from(2);
                }
            }
        }
    }

    match classify_batch_v1(BatchClassificationRequestV1 {
        contracts,
        service_profiles,
        validated_at: validated_at.unwrap_or_else(current_epoch_marker),
    }) {
        Ok(report) => {
            if let Some(view) = export_view {
                print!("{}", render_batch_classification_export_view(&report, view));
                return ExitCode::SUCCESS;
            }
            match serde_json::to_string_pretty(&report) {
                Ok(text) => {
                    println!("{text}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!(
                        "fitctl classify: failed to encode batch classification report: {error}"
                    );
                    ExitCode::from(2)
                }
            }
        }
        Err(error) => {
            eprintln!("fitctl classify: {error}");
            ExitCode::from(2)
        }
    }
}

fn render_help() -> &'static str {
    "Usage:\n  fitctl classify --contract <path> --contract <path> (--profile <path> ... | --service-profile-catalogue <path> (--profile-id <id> ... | --invocation-context <path>)) [--validated-at <timestamp>] [--export-view <rows_csv|contract_summary_csv|service_profile_summary_csv>]\n"
}

fn current_epoch_marker() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("unix:{seconds}")
}
