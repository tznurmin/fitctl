// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! CLI entrypoint for host runtime-state capture.

use std::path::PathBuf;
use std::process::ExitCode;

use fitctl_core::state::{LocalLiveStateProbeV1, StateEngineV1, StateModeV1};

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

    let mode = match fixture_id {
        Some(fixture_id) if !use_live_mode => StateModeV1::Replay {
            fixtures_root,
            fixture_id,
        },
        _ => StateModeV1::Live,
    };

    let engine = StateEngineV1::new(LocalLiveStateProbeV1);
    match engine.collect_host_state(mode) {
        Ok(state) => match serde_json::to_string_pretty(&state) {
            Ok(text) => {
                println!("{text}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("fitctl state: failed to encode host-state artifact: {error}");
                ExitCode::from(2)
            }
        },
        Err(error) => {
            eprintln!("fitctl state: {error}");
            ExitCode::from(2)
        }
    }
}

fn render_help() -> &'static str {
    "Usage:\n  fitctl state [--live]\n  fitctl state --fixture <fixture-id> [--fixtures-root <path>]\n"
}
