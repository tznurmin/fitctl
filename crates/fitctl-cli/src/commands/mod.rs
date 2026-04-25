// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Thin CLI dispatch layer for the public fitctl subcommands.
//!
//! This module is intentionally procedural rather than clever: each subcommand routes into one
//! owned command module, while fitctl-core retains the semantic contracts.

use std::process::ExitCode;

mod bundle;
mod bundle_config;
mod classify;
mod completion;
mod contract;
mod diff;
mod export;
mod inspect;
mod inspect_config;
mod lock_policy_pack;
mod recommend;
mod redact;
mod sign;
mod state;
mod state_support;
mod survey;
mod validate;
mod verify;

// Keep dispatch explicit so the public command surface stays easy to audit during release work.
pub fn run(args: &[String]) -> ExitCode {
    if args.len() == 1 {
        print!("{}", fitctl_core::render_help("fitctl"));
        return ExitCode::SUCCESS;
    }
    if args[1] == "--help" || args[1] == "-h" {
        if args.len() == 2 {
            print!("{}", fitctl_core::render_help("fitctl"));
            return ExitCode::SUCCESS;
        }

        let help_args = [String::from("--help")];
        return dispatch_subcommand(args[2].as_str(), &help_args);
    }
    if args[1] == "help" {
        if args.len() == 2 {
            print!("{}", fitctl_core::render_help("fitctl"));
            return ExitCode::SUCCESS;
        }

        let help_args = [String::from("--help")];
        return dispatch_subcommand(args[2].as_str(), &help_args);
    }

    if args[1] == "--version" || args[1] == "-V" || args[1] == "version" {
        println!(
            "fitctl {}",
            fitctl_core::artifacts::envelope_v1::LOCAL_FITCTL_VERSION_V1
        );
        return ExitCode::SUCCESS;
    }

    dispatch_subcommand(args[1].as_str(), &args[2..])
}

fn dispatch_subcommand(raw_subcommand: &str, subcommand_args: &[String]) -> ExitCode {
    let subcommand = fitctl_core::resolve_command_alias(raw_subcommand).unwrap_or(raw_subcommand);
    if subcommand == "survey" {
        return survey::run(subcommand_args);
    }
    if subcommand == "contract" {
        return contract::run(subcommand_args);
    }
    if subcommand == "classify" {
        return classify::run(subcommand_args);
    }
    if subcommand == "bundle" {
        return bundle::run(subcommand_args);
    }
    if subcommand == "bundle-config" {
        return bundle_config::run(subcommand_args);
    }
    if subcommand == "completion" {
        return completion::run(subcommand_args);
    }
    if subcommand == "state" {
        return state::run(subcommand_args);
    }
    if subcommand == "validate" {
        return validate::run(subcommand_args);
    }
    if subcommand == "diff" {
        return diff::run(subcommand_args);
    }
    if subcommand == "export" {
        return export::run(subcommand_args);
    }
    if subcommand == "inspect" {
        return inspect::run(subcommand_args);
    }
    if subcommand == "inspect-config" {
        return inspect_config::run(subcommand_args);
    }
    if subcommand == "lock-policy-pack" {
        return lock_policy_pack::run(subcommand_args);
    }
    if subcommand == "recommend" {
        return recommend::run(subcommand_args);
    }
    if subcommand == "redact" {
        return redact::run(subcommand_args);
    }
    if subcommand == "sign" {
        return sign::run(subcommand_args);
    }
    if subcommand == "verify" {
        return verify::run(subcommand_args);
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
