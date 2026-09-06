// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! CLI entrypoint for host runtime-state capture.

use std::path::PathBuf;
use std::process::ExitCode;

use fitctl_core::artifacts::validation_v1::validate_host_state;
use fitctl_core::config::load_invocation_context_from_path;
use fitctl_core::state::thermal_v1::{
    built_in_local_thermal_provider_entries_v1, load_thermal_provider_config_entries_from_paths_v1,
};
use fitctl_core::state::{
    LocalLiveStateProbeV1, StateEngineV1, StateModeV1, StatePathCheckRequestV1,
    StatePathLinkPairProbeRequestV1,
};

use crate::commands::state_support::{
    apply_state_extension_selection_v1, collect_feature_extension_namespaces_v1,
    default_state_replay_extensions_root_v1, parse_state_collect_feature_v1,
    prepare_state_extension_selection_v1, push_state_collect_feature_v1,
    CudaSelectedEnvironmentCliInputV1, StateCollectFeatureV1,
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
    let mut path_checks = Vec::new();
    let mut link_probe_path_ids = Vec::new();
    let mut link_pair_probe_requests = Vec::new();
    let mut health_probe_path_ids = Vec::new();
    let mut thermal_provider_config_paths = Vec::new();
    let mut collect_features = Vec::new();

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
            "--path-check" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl state: --path-check requires <id>=<path>");
                    return ExitCode::from(2);
                };
                match parse_path_check(value) {
                    Ok(path_check) => path_checks.push(path_check),
                    Err(error) => {
                        eprintln!("fitctl state: {error}");
                        return ExitCode::from(2);
                    }
                }
                index += 2;
            }
            "--probe-path-links" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl state: --probe-path-links requires a path-check id");
                    return ExitCode::from(2);
                };
                if value.trim().is_empty() || value.contains(char::is_whitespace) {
                    eprintln!("fitctl state: --probe-path-links id must be non-empty and contain no whitespace");
                    return ExitCode::from(2);
                }
                link_probe_path_ids.push(value.clone());
                index += 2;
            }
            "--probe-path-link-pair" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl state: --probe-path-link-pair requires <from-id>:<to-id>");
                    return ExitCode::from(2);
                };
                match parse_path_link_pair_probe(value) {
                    Ok(request) => link_pair_probe_requests.push(request),
                    Err(error) => {
                        eprintln!("fitctl state: {error}");
                        return ExitCode::from(2);
                    }
                }
                index += 2;
            }
            "--probe-path-health" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl state: --probe-path-health requires a path-check id");
                    return ExitCode::from(2);
                };
                if value.trim().is_empty() || value.contains(char::is_whitespace) {
                    eprintln!("fitctl state: --probe-path-health id must be non-empty and contain no whitespace");
                    return ExitCode::from(2);
                }
                health_probe_path_ids.push(value.clone());
                index += 2;
            }
            "--thermal-provider-config" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl state: --thermal-provider-config requires a path");
                    return ExitCode::from(2);
                };
                thermal_provider_config_paths.push(PathBuf::from(value));
                index += 2;
            }
            "--collect" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl state: --collect requires a feature");
                    return ExitCode::from(2);
                };
                match parse_state_collect_feature_v1(value) {
                    Ok(feature) => push_state_collect_feature_v1(&mut collect_features, feature),
                    Err(error) => {
                        eprintln!("fitctl state: {error}");
                        return ExitCode::from(2);
                    }
                }
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
    if !path_checks.is_empty() && !use_live_mode {
        eprintln!("fitctl state: --path-check is only supported for live state collection");
        return ExitCode::from(2);
    }
    if !link_probe_path_ids.is_empty() && !use_live_mode {
        eprintln!("fitctl state: --probe-path-links is only supported for live state collection");
        return ExitCode::from(2);
    }
    if !link_pair_probe_requests.is_empty() && !use_live_mode {
        eprintln!(
            "fitctl state: --probe-path-link-pair is only supported for live state collection"
        );
        return ExitCode::from(2);
    }
    if !health_probe_path_ids.is_empty() && !use_live_mode {
        eprintln!("fitctl state: --probe-path-health is only supported for live state collection");
        return ExitCode::from(2);
    }
    if !thermal_provider_config_paths.is_empty() && !use_live_mode {
        eprintln!(
            "fitctl state: --thermal-provider-config is only supported for live state collection"
        );
        return ExitCode::from(2);
    }
    if !collect_features.is_empty() && !use_live_mode {
        eprintln!("fitctl state: --collect is only supported for live state collection");
        return ExitCode::from(2);
    }
    if let Err(error) = apply_link_probe_selection(&mut path_checks, &link_probe_path_ids) {
        eprintln!("fitctl state: {error}");
        return ExitCode::from(2);
    }
    if let Err(error) = apply_health_probe_selection(&mut path_checks, &health_probe_path_ids) {
        eprintln!("fitctl state: {error}");
        return ExitCode::from(2);
    }
    if let Err(error) = validate_link_pair_probe_selection(&path_checks, &link_pair_probe_requests)
    {
        eprintln!("fitctl state: {error}");
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
    let mut collect_extension_namespaces =
        collect_feature_extension_namespaces_v1(&collect_features);
    collect_extension_namespaces.extend(enabled_extension_namespaces);
    let extension_selection = match prepare_state_extension_selection_v1(
        use_live_mode,
        invocation_context
            .as_ref()
            .map(|context| context.enabled_extension_namespaces.as_slice())
            .unwrap_or(&[]),
        &extension_pack_paths,
        &collect_extension_namespaces,
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
    let mut thermal_provider_configs =
        match load_thermal_provider_config_entries_from_paths_v1(&thermal_provider_config_paths) {
            Ok(configs) => configs,
            Err(error) => {
                eprintln!("fitctl state: {error}");
                return ExitCode::from(2);
            }
        };
    if collect_features.contains(&StateCollectFeatureV1::Thermal) {
        let mut built_ins = built_in_local_thermal_provider_entries_v1();
        built_ins.extend(thermal_provider_configs);
        thermal_provider_configs = built_ins;
    }

    let replay_fixtures_root = fixtures_root.clone();
    let mode = match fixture_id {
        Some(fixture_id) if !use_live_mode => StateModeV1::Replay {
            fixtures_root,
            fixture_id,
        },
        _ => StateModeV1::Live,
    };

    let live_probe = LocalLiveStateProbeV1::new_with_path_link_pairs_and_thermal_providers(
        path_checks,
        link_pair_probe_requests,
        thermal_provider_configs,
    )
    .with_memory_reliability_collection(
        collect_features.contains(&StateCollectFeatureV1::MemoryReliability),
    )
    .with_hardware_sensor_collection(
        collect_features.contains(&StateCollectFeatureV1::HardwareSensors),
    )
    .with_gpu_reliability_collection(
        collect_features.contains(&StateCollectFeatureV1::GpuReliability),
    );
    let engine = StateEngineV1::new(live_probe);
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
    "Usage:\n  fitctl state [--live] [--collect <thermal|memory-reliability|gpu-reliability|cuda-runtime|hardware-sensors> ...] [--path-check <id>=<path> ...] [--probe-path-links <id> ...] [--probe-path-link-pair <from-id>:<to-id> ...] [--probe-path-health <id> ...] [--thermal-provider-config <path> ...] [--extension-pack <path> ...] [--invocation-context <path>] [--enable-extension <namespace> ...] [--cuda-environment-catalogue <path> --cuda-environment-id <id>]\n  fitctl state --fixture <fixture-id> [--fixtures-root <path>] [--extension-pack <path> ...] [--invocation-context <path>] [--enable-extension <namespace> ...] [--cuda-selected-environment-input <path>]\n\nNotes:\n  - --collect thermal enables built-in local sensors and nvidia-smi thermal providers when available\n  - --collect hardware-sensors adds typed local voltage, current, power, fan, energy and humidity evidence\n  - --collect cuda-runtime enables the built-in fitctl.runtime.cuda state namespace\n  - --probe-path-links, --probe-path-link-pair, and --probe-path-health are opt-in and must reference --path-check ids\n  - --thermal-provider-config is live-only and loads exact-argv thermal provider definitions\n  - built-in extension packs are available for fitctl.runtime.cuda, fitctl.runtime.python, and fitctl.runtime.node\n"
}

fn parse_path_check(value: &str) -> Result<StatePathCheckRequestV1, &'static str> {
    let Some((path_id, path)) = value.split_once('=') else {
        return Err("--path-check must use <id>=<path>");
    };
    let path_id = path_id.trim();
    if path_id.is_empty() || path_id.contains(char::is_whitespace) {
        return Err("--path-check id must be non-empty and contain no whitespace");
    }
    if path.trim().is_empty() {
        return Err("--path-check path must be non-empty");
    }
    Ok(StatePathCheckRequestV1 {
        path_id: path_id.to_string(),
        path: PathBuf::from(path),
        probe_links: false,
        probe_health: false,
    })
}

fn apply_link_probe_selection(
    path_checks: &mut [StatePathCheckRequestV1],
    link_probe_path_ids: &[String],
) -> Result<(), String> {
    for path_id in link_probe_path_ids {
        let Some(path_check) = path_checks
            .iter_mut()
            .find(|candidate| candidate.path_id == *path_id)
        else {
            return Err(format!(
                "--probe-path-links id {path_id} does not match any --path-check id"
            ));
        };
        path_check.probe_links = true;
    }
    Ok(())
}

fn apply_health_probe_selection(
    path_checks: &mut [StatePathCheckRequestV1],
    health_probe_path_ids: &[String],
) -> Result<(), String> {
    for path_id in health_probe_path_ids {
        let Some(path_check) = path_checks
            .iter_mut()
            .find(|candidate| candidate.path_id == *path_id)
        else {
            return Err(format!(
                "--probe-path-health id {path_id} does not match any --path-check id"
            ));
        };
        path_check.probe_health = true;
    }
    Ok(())
}

fn parse_path_link_pair_probe(
    value: &str,
) -> Result<StatePathLinkPairProbeRequestV1, &'static str> {
    let Some((from_path_id, to_path_id)) = value.split_once(':') else {
        return Err("--probe-path-link-pair must use <from-id>:<to-id>");
    };
    let from_path_id = from_path_id.trim();
    let to_path_id = to_path_id.trim();
    if from_path_id.is_empty()
        || to_path_id.is_empty()
        || from_path_id.contains(char::is_whitespace)
        || to_path_id.contains(char::is_whitespace)
        || from_path_id == to_path_id
    {
        return Err(
            "--probe-path-link-pair ids must be non-empty, distinct, and contain no whitespace",
        );
    }
    Ok(StatePathLinkPairProbeRequestV1 {
        from_path_id: from_path_id.to_string(),
        to_path_id: to_path_id.to_string(),
    })
}

fn validate_link_pair_probe_selection(
    path_checks: &[StatePathCheckRequestV1],
    pair_requests: &[StatePathLinkPairProbeRequestV1],
) -> Result<(), String> {
    let mut seen = std::collections::BTreeSet::new();
    for pair in pair_requests {
        for path_id in [&pair.from_path_id, &pair.to_path_id] {
            if !path_checks
                .iter()
                .any(|candidate| candidate.path_id == *path_id)
            {
                return Err(format!(
                    "--probe-path-link-pair id {path_id} does not match any --path-check id"
                ));
            }
        }
        if !seen.insert((pair.from_path_id.clone(), pair.to_path_id.clone())) {
            return Err(format!(
                "--probe-path-link-pair {}:{} is duplicated",
                pair.from_path_id, pair.to_path_id
            ));
        }
    }
    Ok(())
}
