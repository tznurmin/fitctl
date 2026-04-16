// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Thin CLI dispatch layer for the public fitctl subcommands.
//!
//! This module is intentionally procedural rather than clever: each subcommand routes into one
//! owned command module, while fitctl-core retains the semantic contracts.

use std::process::ExitCode;

mod classify;
mod contract;
mod diff;
mod export;
mod inspect;
mod inspect_config;
mod lock_policy_pack;
mod redact;
mod sign;
mod state;
mod survey;
mod validate;
mod verify;

// Keep dispatch explicit so the public command surface stays easy to audit during release work.
pub fn run(args: &[String]) -> ExitCode {
    if args.len() == 1 || args[1] == "--help" || args[1] == "-h" || args[1] == "help" {
        print!("{}", fitctl_core::render_help("fitctl"));
        return ExitCode::SUCCESS;
    }

    let raw_subcommand = args[1].as_str();
    let subcommand = fitctl_core::resolve_command_alias(raw_subcommand).unwrap_or(raw_subcommand);
    if subcommand == "survey" {
        return survey::run(&args[2..]);
    }
    if subcommand == "contract" {
        return contract::run(&args[2..]);
    }
    if subcommand == "classify" {
        return classify::run(&args[2..]);
    }
    if subcommand == "state" {
        return state::run(&args[2..]);
    }
    if subcommand == "validate" {
        return validate::run(&args[2..]);
    }
    if subcommand == "diff" {
        return diff::run(&args[2..]);
    }
    if subcommand == "export" {
        return export::run(&args[2..]);
    }
    if subcommand == "inspect" {
        return inspect::run(&args[2..]);
    }
    if subcommand == "inspect-config" {
        return inspect_config::run(&args[2..]);
    }
    if subcommand == "lock-policy-pack" {
        return lock_policy_pack::run(&args[2..]);
    }
    if subcommand == "redact" {
        return redact::run(&args[2..]);
    }
    if subcommand == "sign" {
        return sign::run(&args[2..]);
    }
    if subcommand == "verify" {
        return verify::run(&args[2..]);
    }

    if fitctl_core::is_known_command_or_alias(raw_subcommand) {
        eprintln!("fitctl: '{raw_subcommand}' is not implemented yet");
        return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
    }

    eprintln!(
        "fitctl: unknown subcommand '{raw_subcommand}'\n\n{}",
        fitctl_core::render_help("fitctl")
    );
    ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR)
}
