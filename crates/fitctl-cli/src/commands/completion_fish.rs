// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use super::*;

pub(super) fn render_fish_completion() -> String {
    let mut lines = vec!["complete -c fitctl -f".to_string()];

    for (name, summary) in completion_command_specs() {
        lines.push(format!(
            "complete -c fitctl -n '__fish_is_first_arg' -a '{name}' -d '{summary}'"
        ));
    }

    lines.extend(fish_config_completion_lines());
    lines.extend(fish_storage_completion_lines());
    lines.extend(fish_thermal_completion_lines());

    for entry in COMMAND_OPTIONS {
        for option in entry.options {
            let condition = fish_seen_subcommand_condition(entry.command);
            if let Some(long) = option.strip_prefix("--") {
                lines.push(format!("complete -c fitctl -n '{condition}' -l {long}"));
            } else if let Some(short) = option.strip_prefix('-') {
                lines.push(format!("complete -c fitctl -n '{condition}' -s {short}"));
            }
        }
    }

    for value in VALUE_COMPLETIONS {
        let condition = fish_seen_subcommand_condition(value.command);
        let option = value
            .previous
            .strip_prefix("--")
            .map(|long| format!(" -l {long} -r"))
            .unwrap_or_default();
        lines.push(format!(
            "complete -c fitctl -n '{condition}'{option} -a '{}'",
            value.values.join(" ")
        ));
    }

    lines.join("\n") + "\n"
}

fn fish_config_completion_lines() -> Vec<String> {
    vec![
        "complete -c fitctl -n '__fish_seen_subcommand_from config; and not __fish_seen_subcommand_from list export' -a 'list export'".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from config; and not __fish_seen_subcommand_from list export' -l help".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from config; and not __fish_seen_subcommand_from list export' -s h".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from config; and __fish_seen_subcommand_from list' -l help".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from config; and __fish_seen_subcommand_from list' -s h".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from config; and __fish_seen_subcommand_from export' -l out-dir".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from config; and __fish_seen_subcommand_from export' -l help".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from config; and __fish_seen_subcommand_from export' -s h".to_string(),
    ]
}

fn fish_storage_completion_lines() -> Vec<String> {
    vec![
        "complete -c fitctl -n '__fish_seen_subcommand_from storage; and not __fish_seen_subcommand_from profile' -a 'profile'".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from storage; and not __fish_seen_subcommand_from profile' -l help".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from storage; and not __fish_seen_subcommand_from profile' -s h".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from storage; and __fish_seen_subcommand_from profile; and not __fish_seen_subcommand_from init' -a 'init'".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from storage; and __fish_seen_subcommand_from profile; and not __fish_seen_subcommand_from init' -l help".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from storage; and __fish_seen_subcommand_from profile; and not __fish_seen_subcommand_from init' -s h".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from storage; and __fish_seen_subcommand_from profile; and __fish_seen_subcommand_from init' -l path".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from storage; and __fish_seen_subcommand_from profile; and __fish_seen_subcommand_from init' -l probe-path-links".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from storage; and __fish_seen_subcommand_from profile; and __fish_seen_subcommand_from init' -l probe-path-link-pair".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from storage; and __fish_seen_subcommand_from profile; and __fish_seen_subcommand_from init' -l min-available-bytes".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from storage; and __fish_seen_subcommand_from profile; and __fish_seen_subcommand_from init' -l profile-id".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from storage; and __fish_seen_subcommand_from profile; and __fish_seen_subcommand_from init' -l display-name".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from storage; and __fish_seen_subcommand_from profile; and __fish_seen_subcommand_from init' -l short-display-name".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from storage; and __fish_seen_subcommand_from profile; and __fish_seen_subcommand_from init' -l primary-capability-class".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from storage; and __fish_seen_subcommand_from profile; and __fish_seen_subcommand_from init' -l out".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from storage; and __fish_seen_subcommand_from profile; and __fish_seen_subcommand_from init' -l help".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from storage; and __fish_seen_subcommand_from profile; and __fish_seen_subcommand_from init' -s h".to_string(),
    ]
}

fn fish_thermal_completion_lines() -> Vec<String> {
    vec![
        "complete -c fitctl -n '__fish_seen_subcommand_from thermal; and not __fish_seen_subcommand_from collect profile' -a 'collect profile'".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from thermal; and not __fish_seen_subcommand_from collect profile' -l help".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from thermal; and not __fish_seen_subcommand_from collect profile' -s h".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from thermal; and __fish_seen_subcommand_from collect' -l thermal-provider-config".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from thermal; and __fish_seen_subcommand_from collect' -l require-target-host-id".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from thermal; and __fish_seen_subcommand_from collect' -l out".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from thermal; and __fish_seen_subcommand_from collect' -l help".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from thermal; and __fish_seen_subcommand_from collect' -s h".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from thermal; and __fish_seen_subcommand_from profile; and not __fish_seen_subcommand_from init' -a 'init'".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from thermal; and __fish_seen_subcommand_from profile; and not __fish_seen_subcommand_from init' -l help".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from thermal; and __fish_seen_subcommand_from profile; and not __fish_seen_subcommand_from init' -s h".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from thermal; and __fish_seen_subcommand_from profile; and __fish_seen_subcommand_from init' -l state".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from thermal; and __fish_seen_subcommand_from profile; and __fish_seen_subcommand_from init' -l thermal-evidence".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from thermal; and __fish_seen_subcommand_from profile; and __fish_seen_subcommand_from init' -l profile-id".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from thermal; and __fish_seen_subcommand_from profile; and __fish_seen_subcommand_from init' -l display-name".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from thermal; and __fish_seen_subcommand_from profile; and __fish_seen_subcommand_from init' -l short-display-name".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from thermal; and __fish_seen_subcommand_from profile; and __fish_seen_subcommand_from init' -l primary-capability-class".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from thermal; and __fish_seen_subcommand_from profile; and __fish_seen_subcommand_from init' -l margin-mc".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from thermal; and __fish_seen_subcommand_from profile; and __fish_seen_subcommand_from init' -l out".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from thermal; and __fish_seen_subcommand_from profile; and __fish_seen_subcommand_from init' -l help".to_string(),
        "complete -c fitctl -n '__fish_seen_subcommand_from thermal; and __fish_seen_subcommand_from profile; and __fish_seen_subcommand_from init' -s h".to_string(),
    ]
}

pub(super) fn fish_seen_subcommand_condition(command: &str) -> String {
    let mut names = vec![command];
    names.extend(
        COMMAND_ALIASES
            .iter()
            .filter(|alias| alias.target == command)
            .map(|alias| alias.alias),
    );
    format!("__fish_seen_subcommand_from {}", names.join(" "))
}
