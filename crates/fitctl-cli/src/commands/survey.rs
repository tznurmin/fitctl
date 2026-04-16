// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! CLI entrypoint for host survey collection in live or replay mode.

use std::path::PathBuf;
use std::process::ExitCode;

use fitctl_core::config::{load_extension_pack_from_path, load_invocation_context_from_path};
use fitctl_core::extensions::{
    apply_node_runtime_extension_to_survey_v1, apply_python_runtime_extension_to_survey_v1,
    NODE_RUNTIME_NAMESPACE, PYTHON_RUNTIME_NAMESPACE,
};
use fitctl_core::survey::{LocalLiveProbeV1, SurveyEngineV1, SurveyModeV1};

pub fn run(args: &[String]) -> ExitCode {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{}", render_help());
        return ExitCode::SUCCESS;
    }

    let mut fixture_id: Option<String> = None;
    let mut fixtures_root = PathBuf::from("fixtures/host_survey");
    let mut use_live_mode = true;
    let mut extension_pack_paths = Vec::new();
    let mut invocation_context_path: Option<PathBuf> = None;
    let mut enabled_extension_namespaces = Vec::new();

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--fixture" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl survey: --fixture requires a fixture id");
                    return ExitCode::from(2);
                };
                fixture_id = Some(value.clone());
                use_live_mode = false;
                index += 2;
            }
            "--fixtures-root" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl survey: --fixtures-root requires a path");
                    return ExitCode::from(2);
                };
                fixtures_root = PathBuf::from(value);
                index += 2;
            }
            "--live" => {
                use_live_mode = true;
                index += 1;
            }
            "--extension-pack" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl survey: --extension-pack requires a path");
                    return ExitCode::from(2);
                };
                extension_pack_paths.push(PathBuf::from(value));
                index += 2;
            }
            "--invocation-context" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl survey: --invocation-context requires a path");
                    return ExitCode::from(2);
                };
                invocation_context_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--enable-extension" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl survey: --enable-extension requires a namespace");
                    return ExitCode::from(2);
                };
                enabled_extension_namespaces.push(value.clone());
                index += 2;
            }
            unknown => {
                eprintln!("fitctl survey: unknown option '{unknown}'");
                return ExitCode::from(2);
            }
        }
    }

    let replay_fixtures_root = fixtures_root.clone();
    let mode = match fixture_id {
        Some(fixture_id) if !use_live_mode => SurveyModeV1::Replay {
            fixtures_root,
            fixture_id,
        },
        _ => SurveyModeV1::Live,
    };

    let invocation_context = match invocation_context_path {
        Some(path) => match load_invocation_context_from_path(&path) {
            Ok(context) => Some(context),
            Err(error) => {
                eprintln!("fitctl survey: {error}");
                return ExitCode::from(2);
            }
        },
        None => None,
    };
    let mut extension_packs = Vec::new();
    for path in extension_pack_paths {
        match load_extension_pack_from_path(&path) {
            Ok(pack) => extension_packs.push(pack),
            Err(error) => {
                eprintln!("fitctl survey: {error}");
                return ExitCode::from(2);
            }
        }
    }

    let mut requested_extension_namespaces = invocation_context
        .as_ref()
        .map(|context| context.enabled_extension_namespaces.clone())
        .unwrap_or_default();
    requested_extension_namespaces.extend(enabled_extension_namespaces);
    requested_extension_namespaces.sort();
    requested_extension_namespaces.dedup();

    if requested_extension_namespaces
        .iter()
        .any(|namespace| namespace.trim().is_empty())
    {
        eprintln!("fitctl survey: enabled extension namespaces must be non-empty");
        return ExitCode::from(2);
    }
    if !requested_extension_namespaces.is_empty() && extension_packs.is_empty() {
        eprintln!("fitctl survey: --enable-extension requires at least one --extension-pack");
        return ExitCode::from(2);
    }
    for namespace in &requested_extension_namespaces {
        if !extension_packs
            .iter()
            .any(|pack| &pack.namespace == namespace)
        {
            eprintln!(
                "fitctl survey: extension namespace {namespace} was enabled but no matching extension pack is configured"
            );
            return ExitCode::from(2);
        }
        if namespace != PYTHON_RUNTIME_NAMESPACE && namespace != NODE_RUNTIME_NAMESPACE {
            eprintln!(
                "fitctl survey: extension namespace {namespace} is enabled but no survey collector is implemented for it"
            );
            return ExitCode::from(2);
        }
    }

    let engine = SurveyEngineV1::new(LocalLiveProbeV1);
    match engine.collect_host_survey(mode) {
        Ok(survey) => {
            let survey = if requested_extension_namespaces.is_empty() {
                survey
            } else {
                let replay_extensions_root = if use_live_mode {
                    None
                } else {
                    replay_fixtures_root
                        .parent()
                        .map(|root| root.join("extensions"))
                        .or_else(|| Some(PathBuf::from("fixtures/extensions")))
                };

                let mut survey = survey;
                let mut namespaces = requested_extension_namespaces;
                namespaces.sort();
                namespaces.dedup();
                for namespace in namespaces {
                    let result = match namespace.as_str() {
                        PYTHON_RUNTIME_NAMESPACE => apply_python_runtime_extension_to_survey_v1(
                            survey,
                            replay_extensions_root
                                .as_ref()
                                .map(|root| root.join("python_runtime"))
                                .as_deref(),
                        )
                        .map_err(|error| error.to_string()),
                        NODE_RUNTIME_NAMESPACE => apply_node_runtime_extension_to_survey_v1(
                            survey,
                            replay_extensions_root
                                .as_ref()
                                .map(|root| root.join("node_runtime"))
                                .as_deref(),
                        )
                        .map_err(|error| error.to_string()),
                        _ => unreachable!("validated above"),
                    };
                    survey = match result {
                        Ok(survey) => survey,
                        Err(error) => {
                            eprintln!("fitctl survey: {error}");
                            return ExitCode::from(2);
                        }
                    };
                }
                survey
            };

            match serde_json::to_string_pretty(&survey) {
                Ok(text) => {
                    println!("{text}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("fitctl survey: failed to encode survey artifact: {error}");
                    ExitCode::from(2)
                }
            }
        }
        Err(error) => {
            eprintln!("fitctl survey: {error}");
            ExitCode::from(2)
        }
    }
}

fn render_help() -> &'static str {
    "Usage:\n  fitctl survey [--live] [--extension-pack <path> ...] [--invocation-context <path>] [--enable-extension <namespace> ...]\n  fitctl survey --fixture <fixture-id> [--fixtures-root <path>] [--extension-pack <path> ...] [--invocation-context <path>] [--enable-extension <namespace> ...]\n\nNotes:\n  - live local survey is the default when --fixture is not provided\n  - fixture mode is explicit and intended for tests, examples, and deterministic replay\n"
}
