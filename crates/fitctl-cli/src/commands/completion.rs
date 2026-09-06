// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Static shell completion registry and command entry point.

use fitctl_core::{COMMANDS, COMMAND_ALIASES};
use std::process::ExitCode;

#[path = "completion_bash.rs"]
mod bash;
#[path = "completion_fish.rs"]
mod fish;
#[path = "completion_registry.rs"]
mod registry;
#[path = "completion_values.rs"]
mod values;
#[path = "completion_zsh.rs"]
mod zsh;
use bash::render_bash_completion;
use fish::render_fish_completion;
use registry::*;
use values::*;
use zsh::render_zsh_completion;

pub fn run(args: &[String]) -> ExitCode {
    if args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{}", render_help());
        return ExitCode::SUCCESS;
    }
    if args.len() != 1 {
        eprintln!("fitctl completion: expected exactly one shell name");
        return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
    }

    let script = match args[0].as_str() {
        "bash" => render_bash_completion(),
        "zsh" => render_zsh_completion(),
        "fish" => render_fish_completion(),
        shell => {
            eprintln!("fitctl completion: unsupported shell '{shell}'");
            return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
        }
    };

    print!("{script}");
    ExitCode::SUCCESS
}

fn render_help() -> &'static str {
    "Usage:\n  fitctl completion <bash|zsh|fish>\n\nNotes:\n  - completion scripts are emitted on stdout\n  - install the emitted script through your normal shell-local workflow\n"
}

fn completion_command_specs() -> Vec<(&'static str, &'static str)> {
    let mut commands: Vec<(&'static str, &'static str)> = COMMANDS
        .iter()
        .map(|command| (command.name, command.summary))
        .collect();
    commands.push(("help", "Show top-level help"));
    commands.push(("version", "Show fitctl version"));
    for alias in COMMAND_ALIASES {
        commands.push((alias.alias, "Alias command"));
    }
    commands
}

#[cfg(test)]
fn command_options_for(command: &str) -> &'static [&'static str] {
    let resolved = fitctl_core::resolve_command_alias(command).unwrap_or(command);
    COMMAND_OPTIONS
        .iter()
        .find(|entry| entry.command == resolved)
        .map(|entry| entry.options)
        .unwrap_or(&[])
}

#[cfg(test)]
fn completion_values_for(command: &str, previous: &str) -> &'static [&'static str] {
    let resolved = fitctl_core::resolve_command_alias(command).unwrap_or(command);
    VALUE_COMPLETIONS
        .iter()
        .find(|entry| entry.command == resolved && entry.previous == previous)
        .map(|entry| entry.values)
        .unwrap_or(&[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_shell_names_render_scripts() {
        for shell in ["bash", "zsh", "fish"] {
            let output = match shell {
                "bash" => render_bash_completion(),
                "zsh" => render_zsh_completion(),
                "fish" => render_fish_completion(),
                _ => unreachable!(),
            };
            assert!(output.contains("fitctl"));
        }
    }

    #[test]
    fn completion_registry_includes_alias_option_resolution() {
        assert_eq!(
            command_options_for("resolve-config"),
            command_options_for("inspect-config")
        );
        assert_eq!(
            completion_values_for("inspect", "--color"),
            ["auto", "always", "never"]
        );
        assert_eq!(
            completion_values_for("inspect", "--view"),
            ["summary", "coverage", "matrix"]
        );
        assert_eq!(
            completion_values_for("redact", "--profile"),
            ["local", "fleet", "auditor", "external"]
        );
        assert_eq!(
            completion_values_for("state", "--collect"),
            [
                "thermal",
                "memory-reliability",
                "gpu-reliability",
                "cuda-runtime",
                "hardware-sensors",
            ]
        );
        assert_eq!(
            completion_values_for("validate", "--collect"),
            [
                "thermal",
                "memory-reliability",
                "gpu-reliability",
                "cuda-runtime",
                "hardware-sensors",
            ]
        );
    }

    #[test]
    fn fish_completion_conditions_include_aliases() {
        assert_eq!(
            fish::fish_seen_subcommand_condition("inspect-config"),
            "__fish_seen_subcommand_from inspect-config resolve-config"
        );
    }

    #[test]
    fn fish_completion_models_config_as_nested_command() {
        let output = render_fish_completion();

        assert!(output.contains(
            "complete -c fitctl -n '__fish_seen_subcommand_from config; and not __fish_seen_subcommand_from list export' -a 'list export'"
        ));
        assert!(output.contains(
            "complete -c fitctl -n '__fish_seen_subcommand_from config; and __fish_seen_subcommand_from export' -l out-dir"
        ));
        assert!(!output
            .contains("complete -c fitctl -n '__fish_seen_subcommand_from config' -l out-dir"));
    }

    #[test]
    fn fish_completion_models_thermal_as_nested_command() {
        let output = render_fish_completion();

        assert!(output.contains(
            "complete -c fitctl -n '__fish_seen_subcommand_from thermal; and not __fish_seen_subcommand_from collect profile' -a 'collect profile'"
        ));
        assert!(output.contains(
            "complete -c fitctl -n '__fish_seen_subcommand_from thermal; and __fish_seen_subcommand_from collect' -l thermal-provider-config"
        ));
        assert!(output.contains(
            "complete -c fitctl -n '__fish_seen_subcommand_from thermal; and __fish_seen_subcommand_from collect' -l require-target-host-id"
        ));
        assert!(output.contains(
            "complete -c fitctl -n '__fish_seen_subcommand_from thermal; and __fish_seen_subcommand_from profile; and __fish_seen_subcommand_from init' -l state"
        ));
        assert!(output.contains(
            "complete -c fitctl -n '__fish_seen_subcommand_from thermal; and __fish_seen_subcommand_from profile; and __fish_seen_subcommand_from init' -l thermal-evidence"
        ));
        assert!(!output
            .contains("complete -c fitctl -n '__fish_seen_subcommand_from thermal' -l state"));
        assert!(!output.contains(
            "complete -c fitctl -n '__fish_seen_subcommand_from thermal' -l thermal-provider-config"
        ));
    }
}
