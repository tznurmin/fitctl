// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! CLI entrypoint for storage-oriented helper commands.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use fitctl_core::artifacts::validation_v1::validate_service_profile;
use fitctl_core::state::{
    LocalLiveStateProbeV1, StateEngineV1, StateModeV1, StatePathCheckRequestV1,
    StatePathLinkPairProbeRequestV1,
};
use fitctl_core::storage_profile::{init_storage_profile_v1, StorageProfileInitRequestV1};

pub fn run(args: &[String]) -> ExitCode {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{}", render_help());
        return ExitCode::SUCCESS;
    }
    match args {
        [profile, init, rest @ ..] if profile == "profile" && init == "init" => {
            run_profile_init(rest)
        }
        [profile] if profile == "profile" => {
            eprintln!("fitctl storage: expected nested command 'init'");
            ExitCode::from(2)
        }
        [] => {
            eprintln!("fitctl storage: expected nested command 'profile init'");
            ExitCode::from(2)
        }
        [unknown, ..] => {
            eprintln!("fitctl storage: unknown nested command '{unknown}'");
            ExitCode::from(2)
        }
    }
}

fn run_profile_init(args: &[String]) -> ExitCode {
    let mut path_checks = Vec::new();
    let mut link_probe_path_ids = Vec::new();
    let mut link_pair_probe_requests = Vec::new();
    let mut min_available_bytes_by_path_id = BTreeMap::new();
    let mut profile_id = "generated_storage_profile_v1".to_string();
    let mut display_name: Option<String> = None;
    let mut short_display_name: Option<String> = None;
    let mut primary_capability_class = "general_compute".to_string();
    let mut out_path: Option<PathBuf> = None;

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--path" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl storage profile init: --path requires <id>=<path>");
                    return ExitCode::from(2);
                };
                match parse_path_check(value) {
                    Ok(path_check) => path_checks.push(path_check),
                    Err(error) => {
                        eprintln!("fitctl storage profile init: {error}");
                        return ExitCode::from(2);
                    }
                }
                index += 2;
            }
            "--probe-path-links" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!(
                        "fitctl storage profile init: --probe-path-links requires a path-check id"
                    );
                    return ExitCode::from(2);
                };
                if value.trim().is_empty() || value.contains(char::is_whitespace) {
                    eprintln!("fitctl storage profile init: --probe-path-links id must be non-empty and contain no whitespace");
                    return ExitCode::from(2);
                }
                link_probe_path_ids.push(value.clone());
                index += 2;
            }
            "--probe-path-link-pair" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl storage profile init: --probe-path-link-pair requires <from-id>:<to-id>");
                    return ExitCode::from(2);
                };
                match parse_path_link_pair_probe(value) {
                    Ok(request) => link_pair_probe_requests.push(request),
                    Err(error) => {
                        eprintln!("fitctl storage profile init: {error}");
                        return ExitCode::from(2);
                    }
                }
                index += 2;
            }
            "--min-available-bytes" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!(
                        "fitctl storage profile init: --min-available-bytes requires <id>=<bytes>"
                    );
                    return ExitCode::from(2);
                };
                match parse_min_available_bytes(value) {
                    Ok((path_id, bytes)) => {
                        if min_available_bytes_by_path_id
                            .insert(path_id.clone(), bytes)
                            .is_some()
                        {
                            eprintln!(
                                "fitctl storage profile init: --min-available-bytes id {path_id} is duplicated"
                            );
                            return ExitCode::from(2);
                        }
                    }
                    Err(error) => {
                        eprintln!("fitctl storage profile init: {error}");
                        return ExitCode::from(2);
                    }
                }
                index += 2;
            }
            "--profile-id" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl storage profile init: --profile-id requires a value");
                    return ExitCode::from(2);
                };
                profile_id = value.clone();
                index += 2;
            }
            "--display-name" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl storage profile init: --display-name requires a value");
                    return ExitCode::from(2);
                };
                display_name = Some(value.clone());
                index += 2;
            }
            "--short-display-name" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl storage profile init: --short-display-name requires a value");
                    return ExitCode::from(2);
                };
                short_display_name = Some(value.clone());
                index += 2;
            }
            "--primary-capability-class" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!(
                        "fitctl storage profile init: --primary-capability-class requires a value"
                    );
                    return ExitCode::from(2);
                };
                primary_capability_class = value.clone();
                index += 2;
            }
            "--out" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl storage profile init: --out requires a path");
                    return ExitCode::from(2);
                };
                out_path = Some(PathBuf::from(value));
                index += 2;
            }
            unknown => {
                eprintln!("fitctl storage profile init: unknown option '{unknown}'");
                return ExitCode::from(2);
            }
        }
    }

    if path_checks.is_empty() {
        eprintln!("fitctl storage profile init: at least one --path is required");
        return ExitCode::from(2);
    }
    if let Err(error) = validate_unique_path_ids(&path_checks) {
        eprintln!("fitctl storage profile init: {error}");
        return ExitCode::from(2);
    }
    if let Err(error) = apply_link_probe_selection(&mut path_checks, &link_probe_path_ids) {
        eprintln!("fitctl storage profile init: {error}");
        return ExitCode::from(2);
    }
    if let Err(error) = validate_link_pair_probe_selection(&path_checks, &link_pair_probe_requests)
    {
        eprintln!("fitctl storage profile init: {error}");
        return ExitCode::from(2);
    }
    for path_id in min_available_bytes_by_path_id.keys() {
        if !path_checks
            .iter()
            .any(|candidate| candidate.path_id == *path_id)
        {
            eprintln!(
                "fitctl storage profile init: --min-available-bytes id {path_id} does not match any --path id"
            );
            return ExitCode::from(2);
        }
    }

    let engine = StateEngineV1::new(LocalLiveStateProbeV1::new_with_path_link_pairs(
        path_checks,
        link_pair_probe_requests,
    ));
    let state = match engine.collect_host_state(StateModeV1::Live) {
        Ok(state) => state,
        Err(error) => {
            eprintln!("fitctl storage profile init: {error}");
            return ExitCode::from(2);
        }
    };
    let profile = match init_storage_profile_v1(StorageProfileInitRequestV1 {
        state,
        profile_id,
        display_name,
        short_display_name,
        primary_capability_class,
        min_available_bytes_by_path_id,
    }) {
        Ok(profile) => profile,
        Err(error) => {
            eprintln!("fitctl storage profile init: {error}");
            return ExitCode::from(2);
        }
    };
    if let Err(error) = validate_service_profile(&profile) {
        eprintln!("fitctl storage profile init: {}", error.message);
        return ExitCode::from(2);
    }
    let text = match serde_json::to_string_pretty(&profile) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("fitctl storage profile init: failed to encode service profile: {error}");
            return ExitCode::from(2);
        }
    };
    if let Some(path) = out_path {
        if let Err(error) = fs::write(&path, text.as_bytes()) {
            eprintln!(
                "fitctl storage profile init: failed to write {}: {error}",
                path.display()
            );
            return ExitCode::from(2);
        }
    } else {
        println!("{text}");
    }
    ExitCode::SUCCESS
}

fn render_help() -> &'static str {
    "Usage:\n  fitctl storage profile init --path <id>=<path> ... [--probe-path-links <id> ...] [--probe-path-link-pair <from-id>:<to-id> ...] [--min-available-bytes <id>=<bytes> ...] [--profile-id <id>] [--display-name <text>] [--short-display-name <text>] [--primary-capability-class <class>] [--out <path>]\n\nNotes:\n  - emits a reviewable service-profile.v2 skeleton from observed checked-path evidence\n  - fitctl does not assign scratch, cache, output, or DVC semantics to path ids\n"
}

fn parse_path_check(value: &str) -> Result<StatePathCheckRequestV1, &'static str> {
    let Some((path_id, path)) = value.split_once('=') else {
        return Err("--path must use <id>=<path>");
    };
    let path_id = path_id.trim();
    if path_id.is_empty() || path_id.contains(char::is_whitespace) {
        return Err("--path id must be non-empty and contain no whitespace");
    }
    if path.trim().is_empty() {
        return Err("--path path must be non-empty");
    }
    Ok(StatePathCheckRequestV1 {
        path_id: path_id.to_string(),
        path: PathBuf::from(path),
        probe_links: false,
        probe_health: false,
    })
}

fn parse_min_available_bytes(value: &str) -> Result<(String, u64), &'static str> {
    let Some((path_id, bytes)) = value.split_once('=') else {
        return Err("--min-available-bytes must use <id>=<bytes>");
    };
    let path_id = path_id.trim();
    if path_id.is_empty() || path_id.contains(char::is_whitespace) {
        return Err("--min-available-bytes id must be non-empty and contain no whitespace");
    }
    let bytes = bytes
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or("--min-available-bytes value must be a positive integer")?;
    Ok((path_id.to_string(), bytes))
}

fn validate_unique_path_ids(path_checks: &[StatePathCheckRequestV1]) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for path_check in path_checks {
        if !seen.insert(path_check.path_id.clone()) {
            return Err(format!("duplicate path id {}", path_check.path_id));
        }
    }
    Ok(())
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
                "--probe-path-links id {path_id} does not match any --path id"
            ));
        };
        path_check.probe_links = true;
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
    let mut seen = BTreeSet::new();
    for pair in pair_requests {
        for path_id in [&pair.from_path_id, &pair.to_path_id] {
            if !path_checks
                .iter()
                .any(|candidate| candidate.path_id == *path_id)
            {
                return Err(format!(
                    "--probe-path-link-pair id {path_id} does not match any --path id"
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
