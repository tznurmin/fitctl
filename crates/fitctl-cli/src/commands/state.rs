// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! CLI entrypoint for host runtime-state capture.

use std::path::PathBuf;
use std::process::ExitCode;

use fitctl_core::artifacts::validation_v1::validate_host_state;
use fitctl_core::config::load_invocation_context_from_path;
use fitctl_core::state::{LocalLiveStateProbeV1, StateEngineV1, StateModeV1};

use crate::commands::state_support::{
    apply_state_extension_selection_v1, default_state_replay_extensions_root_v1,
    prepare_state_extension_selection_v1, CudaSelectedEnvironmentCliInputV1,
};

pub fn run(args: &[String]) -> ExitCode {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{}", render_help());
        return ExitCode::SUCCESS;
    }

    let mut fixture_id: Option<String> = None;
    let mut fixtures_root = PathBuf::from("fixtures/host_state");
    let mut use_live_mode = true;
    let mut live_flag_seen = false;
    let mut fixtures_root_flag_seen = false;
    let mut extension_pack_paths = Vec::new();
    let mut invocation_context_path: Option<PathBuf> = None;
    let mut enabled_extension_namespaces = Vec::new();
    let mut cuda_environment_catalogue_path: Option<PathBuf> = None;
    let mut cuda_environment_id: Option<String> = None;
    let mut cuda_selected_environment_input_path: Option<PathBuf> = None;

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--fixture" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl state: --fixture requires a fixture id");
                    return ExitCode::from(2);
                };
                fixture_id = Some(value.clone());
                use_live_mode = false;
                index += 2;
            }
            "--fixtures-root" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl state: --fixtures-root requires a path");
                    return ExitCode::from(2);
                };
                fixtures_root = PathBuf::from(value);
                fixtures_root_flag_seen = true;
                index += 2;
            }
            "--live" => {
                use_live_mode = true;
                live_flag_seen = true;
                index += 1;
            }
            "--extension-pack" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl state: --extension-pack requires a path");
                    return ExitCode::from(2);
                };
                extension_pack_paths.push(PathBuf::from(value));
                index += 2;
            }
            "--invocation-context" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl state: --invocation-context requires a path");
                    return ExitCode::from(2);
                };
                invocation_context_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--enable-extension" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl state: --enable-extension requires a namespace");
                    return ExitCode::from(2);
                };
                enabled_extension_namespaces.push(value.clone());
                index += 2;
            }
            "--cuda-environment-catalogue" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl state: --cuda-environment-catalogue requires a path");
                    return ExitCode::from(2);
                };
                cuda_environment_catalogue_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--cuda-environment-id" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl state: --cuda-environment-id requires an id");
                    return ExitCode::from(2);
                };
                cuda_environment_id = Some(value.clone());
                index += 2;
            }
            "--cuda-selected-environment-input" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl state: --cuda-selected-environment-input requires a path");
                    return ExitCode::from(2);
                };
                cuda_selected_environment_input_path = Some(PathBuf::from(value));
                index += 2;
            }
            unknown => {
                eprintln!("fitctl state: unknown option '{unknown}'");
                return ExitCode::from(2);
            }
        }
    }

    if live_flag_seen && fixture_id.is_some() {
        eprintln!("fitctl state: --live cannot be combined with --fixture");
        return ExitCode::from(2);
    }
    if fixtures_root_flag_seen && fixture_id.is_none() {
        eprintln!("fitctl state: --fixtures-root requires --fixture");
        return ExitCode::from(2);
    }
    let invocation_context = match invocation_context_path {
        Some(path) => match load_invocation_context_from_path(&path) {
            Ok(context) => Some(context),
            Err(error) => {
                eprintln!("fitctl state: {error}");
                return ExitCode::from(2);
            }
        },
        None => None,
    };
    let extension_selection = match prepare_state_extension_selection_v1(
        use_live_mode,
        invocation_context
            .as_ref()
            .map(|context| context.enabled_extension_namespaces.as_slice())
            .unwrap_or(&[]),
        &extension_pack_paths,
        &enabled_extension_namespaces,
        &CudaSelectedEnvironmentCliInputV1 {
            catalogue_path: cuda_environment_catalogue_path,
            environment_id: cuda_environment_id,
            replay_input_path: cuda_selected_environment_input_path,
        },
    ) {
        Ok(selection) => selection,
        Err(error) => {
            eprintln!("fitctl state: {error}");
            return ExitCode::from(2);
        }
    };

    let replay_fixtures_root = fixtures_root.clone();
    let mode = match fixture_id {
        Some(fixture_id) if !use_live_mode => StateModeV1::Replay {
            fixtures_root,
            fixture_id,
        },
        _ => StateModeV1::Live,
    };

    let engine = StateEngineV1::new(LocalLiveStateProbeV1);
    match engine.collect_host_state(mode) {
        Ok(state) => {
            let state = if extension_selection.is_empty() {
                state
            } else {
                let replay_extensions_root = (!use_live_mode)
                    .then(|| default_state_replay_extensions_root_v1(&replay_fixtures_root));
                match apply_state_extension_selection_v1(
                    state,
                    &extension_selection,
                    replay_extensions_root.as_deref(),
                ) {
                    Ok(state) => state,
                    Err(error) => {
                        eprintln!("fitctl state: {error}");
                        return ExitCode::from(2);
                    }
                }
            };

            if let Err(error) = validate_host_state(&state) {
                eprintln!("fitctl state: {}", error.message);
                return ExitCode::from(2);
            }

            match serde_json::to_string_pretty(&state) {
                Ok(text) => {
                    println!("{text}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("fitctl state: failed to encode host-state artifact: {error}");
                    ExitCode::from(2)
                }
            }
        }
        Err(error) => {
            eprintln!("fitctl state: {error}");
            ExitCode::from(2)
        }
    }
}

fn render_help() -> &'static str {
    "Usage:\n  fitctl state [--live] [--extension-pack <path> ...] [--invocation-context <path>] [--enable-extension <namespace> ...] [--cuda-environment-catalogue <path> --cuda-environment-id <id>]\n  fitctl state --fixture <fixture-id> [--fixtures-root <path>] [--extension-pack <path> ...] [--invocation-context <path>] [--enable-extension <namespace> ...] [--cuda-selected-environment-input <path>]\n"
}
