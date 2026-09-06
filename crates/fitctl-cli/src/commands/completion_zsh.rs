// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use super::*;

pub(super) fn render_zsh_completion() -> String {
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
                "    {}:{}) compadd -- {}; return ;;\n",
                value.command,
                value.previous,
                value.values.join(" ")
            )
        })
        .collect::<String>();
    let option_cases = COMMAND_OPTIONS
        .iter()
        .filter(|entry| !entry.options.is_empty())
        .map(|entry| {
            format!(
                "    {}) compadd -- {} ;;\n",
                entry.command,
                entry.options.join(" ")
            )
        })
        .collect::<String>();
    let config_root_completions = CONFIG_ROOT_COMPLETIONS.join(" ");
    let config_list_options = CONFIG_LIST_OPTIONS.join(" ");
    let config_export_options = CONFIG_EXPORT_OPTIONS.join(" ");
    let storage_root_completions = STORAGE_ROOT_COMPLETIONS.join(" ");
    let storage_profile_completions = STORAGE_PROFILE_COMPLETIONS.join(" ");
    let storage_profile_init_options = STORAGE_PROFILE_INIT_OPTIONS.join(" ");
    let thermal_root_completions = THERMAL_ROOT_COMPLETIONS.join(" ");
    let thermal_collect_options = THERMAL_COLLECT_OPTIONS.join(" ");
    let thermal_profile_completions = THERMAL_PROFILE_COMPLETIONS.join(" ");
    let thermal_profile_init_options = THERMAL_PROFILE_INIT_OPTIONS.join(" ");

    let mut script = format!(
        "#compdef fitctl\n\n_fitctl_completion() {{\n  local cmd prev\n  if (( CURRENT == 2 )); then\n    compadd -- {command_list}\n    return\n  fi\n\n  cmd=\"${{words[2]}}\"\n  case \"$cmd\" in\n{alias_cases}  esac\n  prev=\"${{words[CURRENT-1]}}\"\n\n  if [[ \"$cmd\" == \"config\" ]]; then\n    if (( CURRENT == 3 )); then\n      compadd -- {config_root_completions}\n      return\n    fi\n    case \"${{words[3]}}\" in\n      list)\n        compadd -- {config_list_options}\n        return\n        ;;\n      export)\n        if [[ \"$prev\" == \"--out-dir\" ]]; then return; fi\n        compadd -- {config_export_options}\n        return\n        ;;\n    esac\n  fi\n\n  if [[ \"$cmd\" == \"storage\" ]]; then\n    if (( CURRENT == 3 )); then\n      compadd -- {storage_root_completions}\n      return\n    fi\n    if [[ \"${{words[3]}}\" == \"profile\" ]]; then\n      if (( CURRENT == 4 )); then\n        compadd -- {storage_profile_completions}\n        return\n      fi\n      if [[ \"${{words[4]}}\" == \"init\" ]]; then\n        compadd -- {storage_profile_init_options}\n        return\n      fi\n    fi\n  fi\n\n  if [[ \"$cmd\" == \"thermal\" ]]; then\n    if (( CURRENT == 3 )); then\n      compadd -- {thermal_root_completions}\n      return\n    fi\n    if [[ \"${{words[3]}}\" == \"collect\" ]]; then\n      compadd -- {thermal_collect_options}\n      return\n    fi\n    if [[ \"${{words[3]}}\" == \"profile\" ]]; then\n      if (( CURRENT == 4 )); then\n        compadd -- {thermal_profile_completions}\n        return\n      fi\n      if [[ \"${{words[4]}}\" == \"init\" ]]; then\n        compadd -- {thermal_profile_init_options}\n        return\n      fi\n    fi\n  fi\n\n  case \"$cmd:$prev\" in\n{value_cases}  esac\n\n  case \"$cmd\" in\n{option_cases}  esac\n}}\n\ncompdef _fitctl_completion fitctl\n"
    );
    // An installed _fitctl file is itself an autoloaded function on the first request.
    script.push_str(
        "if [[ \"${funcstack[1]-}\" == _fitctl ]]; then\n  _fitctl_completion \"$@\"\nfi\n",
    );
    script
}
