// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use super::*;

pub(super) fn render_bash_completion() -> String {
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
                "    {}:{}) COMPREPLY=( $(compgen -W \"{}\" -- \"$cur\") ); return 0 ;;\n",
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
                "    {}) COMPREPLY=( $(compgen -W \"{}\" -- \"$cur\") ) ;;\n",
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

    format!(
        "_fitctl_completion() {{\n  local cur prev cmd\n  cur=\"${{COMP_WORDS[COMP_CWORD]}}\"\n  prev=\"${{COMP_WORDS[COMP_CWORD-1]}}\"\n\n  if [[ $COMP_CWORD -eq 1 ]]; then\n    COMPREPLY=( $(compgen -W \"{command_list}\" -- \"$cur\") )\n    return 0\n  fi\n\n  cmd=\"${{COMP_WORDS[1]}}\"\n  case \"$cmd\" in\n{alias_cases}  esac\n\n  if [[ \"$cmd\" == \"config\" ]]; then\n    if [[ $COMP_CWORD -eq 2 ]]; then\n      COMPREPLY=( $(compgen -W \"{config_root_completions}\" -- \"$cur\") )\n      return 0\n    fi\n    case \"${{COMP_WORDS[2]}}\" in\n      list)\n        COMPREPLY=( $(compgen -W \"{config_list_options}\" -- \"$cur\") )\n        return 0\n        ;;\n      export)\n        if [[ \"$prev\" == \"--out-dir\" ]]; then return 0; fi\n        COMPREPLY=( $(compgen -W \"{config_export_options}\" -- \"$cur\") )\n        return 0\n        ;;\n    esac\n  fi\n\n  if [[ \"$cmd\" == \"storage\" ]]; then\n    if [[ $COMP_CWORD -eq 2 ]]; then\n      COMPREPLY=( $(compgen -W \"{storage_root_completions}\" -- \"$cur\") )\n      return 0\n    fi\n    if [[ \"${{COMP_WORDS[2]}}\" == \"profile\" ]]; then\n      if [[ $COMP_CWORD -eq 3 ]]; then\n        COMPREPLY=( $(compgen -W \"{storage_profile_completions}\" -- \"$cur\") )\n        return 0\n      fi\n      if [[ \"${{COMP_WORDS[3]}}\" == \"init\" ]]; then\n        COMPREPLY=( $(compgen -W \"{storage_profile_init_options}\" -- \"$cur\") )\n        return 0\n      fi\n    fi\n  fi\n\n  if [[ \"$cmd\" == \"thermal\" ]]; then\n    if [[ $COMP_CWORD -eq 2 ]]; then\n      COMPREPLY=( $(compgen -W \"{thermal_root_completions}\" -- \"$cur\") )\n      return 0\n    fi\n    if [[ \"${{COMP_WORDS[2]}}\" == \"collect\" ]]; then\n      COMPREPLY=( $(compgen -W \"{thermal_collect_options}\" -- \"$cur\") )\n      return 0\n    fi\n    if [[ \"${{COMP_WORDS[2]}}\" == \"profile\" ]]; then\n      if [[ $COMP_CWORD -eq 3 ]]; then\n        COMPREPLY=( $(compgen -W \"{thermal_profile_completions}\" -- \"$cur\") )\n        return 0\n      fi\n      if [[ \"${{COMP_WORDS[3]}}\" == \"init\" ]]; then\n        COMPREPLY=( $(compgen -W \"{thermal_profile_init_options}\" -- \"$cur\") )\n        return 0\n      fi\n    fi\n  fi\n\n  case \"$cmd:$prev\" in\n{value_cases}  esac\n\n  case \"$cmd\" in\n{option_cases}  esac\n}}\n\ncomplete -F _fitctl_completion fitctl\n"
    )
}
