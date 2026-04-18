// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Emit static shell-completion scripts for the public fitctl command surface.

use std::process::ExitCode;

use fitctl_core::{COMMANDS, COMMAND_ALIASES};

struct CompletionOptionsV1 {
    command: &'static str,
    options: &'static [&'static str],
}

struct CompletionValuesV1 {
    command: &'static str,
    previous: &'static str,
    values: &'static [&'static str],
}

const SURVEY_OPTIONS: &[&str] = &[
    "--live",
    "--fixture",
    "--fixtures-root",
    "--extension-pack",
    "--invocation-context",
    "--enable-extension",
    "--help",
    "-h",
];
const CONTRACT_OPTIONS: &[&str] = &[
    "--survey",
    "--policy",
    "--policy-pack",
    "--policy-id",
    "--policy-pack-lock",
    "--extension-pack",
    "--invocation-context",
    "--enable-extension",
    "--derived-at",
    "--note",
    "--help",
    "-h",
];
const CLASSIFY_OPTIONS: &[&str] = &[
    "--contract",
    "--profile",
    "--service-profile-catalogue",
    "--profile-id",
    "--validated-at",
    "--export-view",
    "--help",
    "-h",
];
const STATE_OPTIONS: &[&str] = &["--live", "--fixture", "--fixtures-root", "--help", "-h"];
const VALIDATE_OPTIONS: &[&str] = &[
    "--contract",
    "--survey",
    "--policy",
    "--profile",
    "--service-profile-catalogue",
    "--profile-id",
    "--validation-mode",
    "--mode",
    "--state",
    "--max-state-age",
    "--validated-at",
    "--note",
    "--help",
    "-h",
];
const DIFF_OPTIONS: &[&str] = &["--left", "--right", "--drift-view", "--help", "-h"];
const EXPORT_OPTIONS: &[&str] = &[
    "--target",
    "--input",
    "--trust-domain",
    "--pseudonym-secret",
    "--help",
    "-h",
];
const REDACT_OPTIONS: &[&str] = &["--profile", "--input", "--help", "-h"];
const SIGN_OPTIONS: &[&str] = &["--key", "--input", "--help", "-h"];
const VERIFY_OPTIONS: &[&str] = &[
    "--input",
    "--policy",
    "--trust-evidence",
    "--bundle-out",
    "--help",
    "-h",
];
const COMPLETION_OPTIONS: &[&str] = &["--help", "-h"];
const INSPECT_OPTIONS: &[&str] = &[
    "--input",
    "--verbose",
    "--show-identifiers",
    "--color",
    "--view",
    "--matrix",
    "--help",
    "-h",
];
const INSPECT_CONFIG_OPTIONS: &[&str] = &[
    "--policy",
    "--policy-pack",
    "--policy-id",
    "--policy-pack-lock",
    "--service-profile-catalogue",
    "--profile-id",
    "--trust-policy",
    "--extension-pack",
    "--recommendation-pack",
    "--invocation-context",
    "--help",
    "-h",
];
const LOCK_POLICY_PACK_OPTIONS: &[&str] = &[
    "--policy-pack",
    "--policy-id",
    "--key",
    "--signed-at",
    "--help",
    "-h",
];
const RECOMMEND_OPTIONS: &[&str] = &[
    "--validation-report",
    "--recommendation-pack",
    "--recommended-at",
    "--help",
    "-h",
];

const COMMAND_OPTIONS: &[CompletionOptionsV1] = &[
    CompletionOptionsV1 {
        command: "survey",
        options: SURVEY_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "contract",
        options: CONTRACT_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "classify",
        options: CLASSIFY_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "state",
        options: STATE_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "validate",
        options: VALIDATE_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "diff",
        options: DIFF_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "export",
        options: EXPORT_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "redact",
        options: REDACT_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "sign",
        options: SIGN_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "verify",
        options: VERIFY_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "completion",
        options: COMPLETION_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "inspect",
        options: INSPECT_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "inspect-config",
        options: INSPECT_CONFIG_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "lock-policy-pack",
        options: LOCK_POLICY_PACK_OPTIONS,
    },
    CompletionOptionsV1 {
        command: "recommend",
        options: RECOMMEND_OPTIONS,
    },
];

const COMPLETION_SHELL_VALUES: &[&str] = &["bash", "zsh", "fish"];
const COLOR_VALUES: &[&str] = &["auto", "always", "never"];
const INSPECT_VIEW_VALUES: &[&str] = &["summary", "matrix"];
const VALIDATION_MODE_VALUES: &[&str] = &["contract_only", "state_advisory", "state_required"];
const LEGACY_MODE_VALUES: &[&str] = &["contract_only", "state_aware"];
const DRIFT_VIEW_VALUES: &[&str] = &["compact_json"];
const EXPORT_TARGET_VALUES: &[&str] = &[
    "kubernetes_labels",
    "nomad_attributes",
    "gating_summary",
    "identity_summary",
];
const CLASSIFY_EXPORT_VIEW_VALUES: &[&str] = &[
    "rows_csv",
    "contract_summary_csv",
    "service_profile_summary_csv",
];

const VALUE_COMPLETIONS: &[CompletionValuesV1] = &[
    CompletionValuesV1 {
        command: "completion",
        previous: "completion",
        values: COMPLETION_SHELL_VALUES,
    },
    CompletionValuesV1 {
        command: "inspect",
        previous: "--color",
        values: COLOR_VALUES,
    },
    CompletionValuesV1 {
        command: "inspect",
        previous: "--view",
        values: INSPECT_VIEW_VALUES,
    },
    CompletionValuesV1 {
        command: "validate",
        previous: "--validation-mode",
        values: VALIDATION_MODE_VALUES,
    },
    CompletionValuesV1 {
        command: "validate",
        previous: "--mode",
        values: LEGACY_MODE_VALUES,
    },
    CompletionValuesV1 {
        command: "diff",
        previous: "--drift-view",
        values: DRIFT_VIEW_VALUES,
    },
    CompletionValuesV1 {
        command: "export",
        previous: "--target",
        values: EXPORT_TARGET_VALUES,
    },
    CompletionValuesV1 {
        command: "classify",
        previous: "--export-view",
        values: CLASSIFY_EXPORT_VIEW_VALUES,
    },
];

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

fn render_bash_completion() -> String {
    let command_list = completion_command_specs()
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(" ");
    let alias_cases = COMMAND_ALIASES
        .iter()
        .map(|alias| format!("    {}) cmd=\"{}\" ;;\n", alias.alias, alias.target))
        .collect::<String>();
    let value_cases = VALUE_COMPLETIONS
        .iter()
        .map(|value| {
            format!(
                "    {})\n      if [[ \"$cmd\" == \"{}\" ]]; then COMPREPLY=( $(compgen -W \"{}\" -- \"$cur\") ); return 0; fi\n      ;;\n",
                value.previous,
                value.command,
                value.values.join(" ")
            )
        })
        .collect::<String>();
    let option_cases = COMMAND_OPTIONS
        .iter()
        .map(|entry| {
            format!(
                "    {}) COMPREPLY=( $(compgen -W \"{}\" -- \"$cur\") ) ;;\n",
                entry.command,
                entry.options.join(" ")
            )
        })
        .collect::<String>();

    format!(
        "_fitctl_completion() {{\n  local cur prev cmd\n  cur=\"${{COMP_WORDS[COMP_CWORD]}}\"\n  prev=\"${{COMP_WORDS[COMP_CWORD-1]}}\"\n\n  if [[ $COMP_CWORD -eq 1 ]]; then\n    COMPREPLY=( $(compgen -W \"{command_list}\" -- \"$cur\") )\n    return 0\n  fi\n\n  cmd=\"${{COMP_WORDS[1]}}\"\n  case \"$cmd\" in\n{alias_cases}  esac\n\n  case \"$prev\" in\n{value_cases}  esac\n\n  case \"$cmd\" in\n{option_cases}  esac\n}}\n\ncomplete -F _fitctl_completion fitctl\n"
    )
}

fn render_zsh_completion() -> String {
    let command_list = completion_command_specs()
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(" ");
    let alias_cases = COMMAND_ALIASES
        .iter()
        .map(|alias| format!("    {}) cmd=\"{}\" ;;\n", alias.alias, alias.target))
        .collect::<String>();
    let value_cases = VALUE_COMPLETIONS
        .iter()
        .map(|value| {
            format!(
                "    {})\n      if [[ \"$cmd\" == \"{}\" ]]; then compadd -- {}; return; fi\n      ;;\n",
                value.previous,
                value.command,
                value.values.join(" ")
            )
        })
        .collect::<String>();
    let option_cases = COMMAND_OPTIONS
        .iter()
        .map(|entry| {
            format!(
                "    {}) compadd -- {} ;;\n",
                entry.command,
                entry.options.join(" ")
            )
        })
        .collect::<String>();

    format!(
        "#compdef fitctl\n\n_fitctl_completion() {{\n  local cmd prev\n  if (( CURRENT == 2 )); then\n    compadd -- {command_list}\n    return\n  fi\n\n  cmd=\"${{words[2]}}\"\n  case \"$cmd\" in\n{alias_cases}  esac\n  prev=\"${{words[CURRENT-1]}}\"\n\n  case \"$prev\" in\n{value_cases}  esac\n\n  case \"$cmd\" in\n{option_cases}  esac\n}}\n\ncompdef _fitctl_completion fitctl\n"
    )
}

fn render_fish_completion() -> String {
    let mut lines = vec!["complete -c fitctl -f".to_string()];

    for (name, summary) in completion_command_specs() {
        lines.push(format!(
            "complete -c fitctl -n '__fish_is_first_arg' -a '{name}' -d '{summary}'"
        ));
    }

    for entry in COMMAND_OPTIONS {
        for option in entry.options {
            let condition = format!("__fish_seen_subcommand_from {}", entry.command);
            if let Some(long) = option.strip_prefix("--") {
                lines.push(format!("complete -c fitctl -n '{condition}' -l {long}"));
            } else if let Some(short) = option.strip_prefix('-') {
                lines.push(format!("complete -c fitctl -n '{condition}' -s {short}"));
            }
        }
    }

    for value in VALUE_COMPLETIONS {
        let condition = format!("__fish_seen_subcommand_from {}", value.command);
        lines.push(format!(
            "complete -c fitctl -n '{condition}' -a '{}'",
            value.values.join(" ")
        ));
    }

    lines.join("\n") + "\n"
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
            ["summary", "matrix"]
        );
    }
}
