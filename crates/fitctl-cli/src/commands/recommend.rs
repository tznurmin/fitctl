// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! CLI entrypoint for minimal advisory recommendation evaluation.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use fitctl_core::config::{
    load_invocation_context_from_path, load_recommendation_pack_from_path,
    resolve_invocation_selected_recommendation_pack_id_v1,
};
use fitctl_core::recommendation::{evaluate_recommendation_v1, RecommendationRequestV1};
use fitctl_core::validate::load_validation_report_from_path;

pub fn run(args: &[String]) -> ExitCode {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{}", render_help());
        return ExitCode::SUCCESS;
    }

    let mut validation_report_path: Option<PathBuf> = None;
    let mut recommendation_pack_paths = Vec::new();
    let mut recommendation_pack_id: Option<String> = None;
    let mut invocation_context_path: Option<PathBuf> = None;
    let mut recommended_at: Option<String> = None;

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--validation-report" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl recommend: --validation-report requires a path");
                    return ExitCode::from(2);
                };
                if validation_report_path.is_some() {
                    eprintln!("fitctl recommend: --validation-report may be specified only once");
                    return ExitCode::from(2);
                }
                validation_report_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--recommendation-pack" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl recommend: --recommendation-pack requires a path");
                    return ExitCode::from(2);
                };
                recommendation_pack_paths.push(PathBuf::from(value));
                index += 2;
            }
            "--recommendation-pack-id" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl recommend: --recommendation-pack-id requires a value");
                    return ExitCode::from(2);
                };
                if recommendation_pack_id.is_some() {
                    eprintln!(
                        "fitctl recommend: --recommendation-pack-id may be specified only once"
                    );
                    return ExitCode::from(2);
                }
                recommendation_pack_id = Some(value.clone());
                index += 2;
            }
            "--invocation-context" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl recommend: --invocation-context requires a path");
                    return ExitCode::from(2);
                };
                if invocation_context_path.is_some() {
                    eprintln!("fitctl recommend: --invocation-context may be specified only once");
                    return ExitCode::from(2);
                }
                invocation_context_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--recommended-at" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl recommend: --recommended-at requires a timestamp");
                    return ExitCode::from(2);
                };
                if recommended_at.is_some() {
                    eprintln!("fitctl recommend: --recommended-at may be specified only once");
                    return ExitCode::from(2);
                }
                recommended_at = Some(value.clone());
                index += 2;
            }
            unknown => {
                eprintln!("fitctl recommend: unknown option '{unknown}'");
                return ExitCode::from(2);
            }
        }
    }

    let Some(validation_report_path) = validation_report_path else {
        eprintln!("fitctl recommend: --validation-report is required");
        return ExitCode::from(2);
    };
    if recommendation_pack_paths.is_empty() {
        eprintln!("fitctl recommend: --recommendation-pack is required");
        return ExitCode::from(2);
    }

    let validation_report = match load_validation_report_from_path(&validation_report_path) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("fitctl recommend: {error}");
            return ExitCode::from(2);
        }
    };
    let invocation_context = match invocation_context_path {
        Some(path) => match load_invocation_context_from_path(&path) {
            Ok(context) => Some(context),
            Err(error) => {
                eprintln!("fitctl recommend: {error}");
                return ExitCode::from(2);
            }
        },
        None => None,
    };
    let selected_pack_id = match resolve_invocation_selected_recommendation_pack_id_v1(
        recommendation_pack_id.as_deref(),
        invocation_context.as_ref(),
    ) {
        Ok(selection) => selection,
        Err(error) => {
            eprintln!("fitctl recommend: {error}");
            return ExitCode::from(2);
        }
    };
    let recommendation_pack = if recommendation_pack_paths.len() == 1 && selected_pack_id.is_none()
    {
        match load_recommendation_pack_from_path(&recommendation_pack_paths[0]) {
            Ok(pack) => pack,
            Err(error) => {
                eprintln!("fitctl recommend: {error}");
                return ExitCode::from(2);
            }
        }
    } else {
        let Some((selected_pack_id, _)) = selected_pack_id.as_ref() else {
            eprintln!(
                "fitctl recommend: repeated recommendation-pack inputs require a selected pack id from --recommendation-pack-id or --invocation-context"
            );
            return ExitCode::from(2);
        };
        let mut packs_by_id = std::collections::BTreeMap::new();
        for path in recommendation_pack_paths {
            let pack = match load_recommendation_pack_from_path(&path) {
                Ok(pack) => pack,
                Err(error) => {
                    eprintln!("fitctl recommend: {error}");
                    return ExitCode::from(2);
                }
            };
            if packs_by_id.insert(pack.pack_id.clone(), pack).is_some() {
                eprintln!("fitctl recommend: recommendation-pack ids must be unique");
                return ExitCode::from(2);
            }
        }
        let Some(pack) = packs_by_id.remove(selected_pack_id) else {
            eprintln!(
                "fitctl recommend: selected recommendation-pack id {selected_pack_id} does not match any configured recommendation-pack"
            );
            return ExitCode::from(2);
        };
        pack
    };

    match evaluate_recommendation_v1(RecommendationRequestV1 {
        validation_report,
        recommendation_pack,
        recommended_at: recommended_at.unwrap_or_else(current_epoch_marker),
    }) {
        Ok(report) => match serde_json::to_string_pretty(&report) {
            Ok(text) => {
                println!("{text}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("fitctl recommend: failed to encode recommendation report: {error}");
                ExitCode::from(2)
            }
        },
        Err(error) => {
            eprintln!("fitctl recommend: {error}");
            ExitCode::from(2)
        }
    }
}

fn render_help() -> &'static str {
    "Usage:\n  fitctl recommend --validation-report <path> --recommendation-pack <path> [--recommendation-pack <path> ...] [--recommendation-pack-id <id> | --invocation-context <path>] [--recommended-at <timestamp>]\n"
}

fn current_epoch_marker() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("unix:{seconds}")
}
