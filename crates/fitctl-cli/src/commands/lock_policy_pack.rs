// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! CLI entrypoint for policy-pack lock creation and signing.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use fitctl_core::config::{create_policy_pack_lock_from_path, sign_policy_pack_lock_v1};

pub fn run(args: &[String]) -> ExitCode {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{}", render_help());
        return ExitCode::SUCCESS;
    }

    let mut policy_pack_path: Option<PathBuf> = None;
    let mut policy_id: Option<String> = None;
    let mut key_path: Option<PathBuf> = None;
    let mut signed_at: Option<String> = None;

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--policy-pack" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl lock-policy-pack: --policy-pack requires a path");
                    return ExitCode::from(2);
                };
                policy_pack_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--policy-id" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl lock-policy-pack: --policy-id requires a value");
                    return ExitCode::from(2);
                };
                policy_id = Some(value.clone());
                index += 2;
            }
            "--key" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl lock-policy-pack: --key requires a path");
                    return ExitCode::from(2);
                };
                key_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--signed-at" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl lock-policy-pack: --signed-at requires a timestamp");
                    return ExitCode::from(2);
                };
                signed_at = Some(value.clone());
                index += 2;
            }
            unknown => {
                eprintln!("fitctl lock-policy-pack: unknown option '{unknown}'");
                return ExitCode::from(2);
            }
        }
    }

    let Some(policy_pack_path) = policy_pack_path else {
        eprintln!("fitctl lock-policy-pack: --policy-pack is required");
        return ExitCode::from(2);
    };
    let Some(policy_id) = policy_id else {
        eprintln!("fitctl lock-policy-pack: --policy-id is required");
        return ExitCode::from(2);
    };
    if key_path.is_none() && signed_at.is_some() {
        eprintln!("fitctl lock-policy-pack: --signed-at requires --key");
        return ExitCode::from(2);
    }

    let lock = match create_policy_pack_lock_from_path(&policy_pack_path, &policy_id) {
        Ok(lock) => lock,
        Err(error) => {
            eprintln!("fitctl lock-policy-pack: {error}");
            return ExitCode::from(2);
        }
    };

    let lock = match key_path {
        Some(key_path) => {
            let signed_at_value = signed_at.unwrap_or_else(current_epoch_marker);
            match sign_policy_pack_lock_v1(&lock, &key_path, &signed_at_value) {
                Ok(lock) => lock,
                Err(error) => {
                    eprintln!("fitctl lock-policy-pack: {error}");
                    return ExitCode::from(2);
                }
            }
        }
        None => lock,
    };

    match serde_json::to_string_pretty(&lock) {
        Ok(text) => {
            println!("{text}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("fitctl lock-policy-pack: failed to encode policy-pack lock: {error}");
            ExitCode::from(2)
        }
    }
}

fn render_help() -> &'static str {
    "Usage:\n  fitctl lock-policy-pack --policy-pack <path> --policy-id <id> [--key <private-key-path> [--signed-at <timestamp>]]\n"
}

fn current_epoch_marker() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("unix:{seconds}")
}
