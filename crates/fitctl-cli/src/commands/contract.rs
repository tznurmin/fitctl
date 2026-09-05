// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! CLI entrypoint for host-contract derivation from survey evidence and policy.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use fitctl_core::config::{
    load_extension_pack_from_path, load_invocation_context_from_path,
    resolve_invocation_selected_policy_id_v1, resolve_policy_from_pack_path,
    resolve_policy_from_pack_with_lock_path,
};
use fitctl_core::config_bundle::load_config_bundle_from_path_v1;
use fitctl_core::contract::{
    derive_host_contract_v1, derive_host_contract_with_extensions_v1,
    load_host_survey_artifact_from_path, ContractDerivationRequestV1, DerivationContextV1,
};
use fitctl_core::policy::load_policy_document_from_path;

use super::contract_extension_activation::resolve_contract_extension_basis_v1;

pub fn run(args: &[String]) -> ExitCode {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{}", render_help());
        return ExitCode::SUCCESS;
    }

    let mut survey_path: Option<PathBuf> = None;
    let mut config_bundle_path: Option<PathBuf> = None;
    let mut policy_path: Option<PathBuf> = None;
    let mut policy_pack_path: Option<PathBuf> = None;
    let mut policy_id: Option<String> = None;
    let mut policy_pack_lock_path: Option<PathBuf> = None;
    let mut invocation_context_path: Option<PathBuf> = None;
    let mut extension_pack_paths = Vec::new();
    let mut enabled_extension_namespaces = Vec::new();
    let mut derived_at: Option<String> = None;
    let mut notes: Option<String> = None;

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--survey" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl contract: --survey requires a path");
                    return ExitCode::from(2);
                };
                survey_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--config-bundle" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl contract: --config-bundle requires a path");
                    return ExitCode::from(2);
                };
                config_bundle_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--policy" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl contract: --policy requires a path");
                    return ExitCode::from(2);
                };
                policy_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--policy-pack" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl contract: --policy-pack requires a path");
                    return ExitCode::from(2);
                };
                policy_pack_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--policy-id" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl contract: --policy-id requires a value");
                    return ExitCode::from(2);
                };
                policy_id = Some(value.clone());
                index += 2;
            }
            "--policy-pack-lock" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl contract: --policy-pack-lock requires a path");
                    return ExitCode::from(2);
                };
                policy_pack_lock_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--extension-pack" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl contract: --extension-pack requires a path");
                    return ExitCode::from(2);
                };
                extension_pack_paths.push(PathBuf::from(value));
                index += 2;
            }
            "--invocation-context" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl contract: --invocation-context requires a path");
                    return ExitCode::from(2);
                };
                invocation_context_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--enable-extension" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl contract: --enable-extension requires a namespace");
                    return ExitCode::from(2);
                };
                enabled_extension_namespaces.push(value.clone());
                index += 2;
            }
            "--derived-at" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl contract: --derived-at requires a timestamp");
                    return ExitCode::from(2);
                };
                derived_at = Some(value.clone());
                index += 2;
            }
            "--note" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl contract: --note requires text");
                    return ExitCode::from(2);
                };
                notes = Some(value.clone());
                index += 2;
            }
            unknown => {
                eprintln!("fitctl contract: unknown option '{unknown}'");
                return ExitCode::from(2);
            }
        }
    }

    let Some(survey_path) = survey_path else {
        eprintln!("fitctl contract: --survey is required");
        return ExitCode::from(2);
    };
    if config_bundle_path.is_some()
        && (policy_path.is_some()
            || policy_pack_path.is_some()
            || policy_id.is_some()
            || policy_pack_lock_path.is_some()
            || invocation_context_path.is_some()
            || !extension_pack_paths.is_empty()
            || !enabled_extension_namespaces.is_empty())
    {
        eprintln!(
            "fitctl contract: --config-bundle must not be combined with explicit policy, policy-pack, invocation-context, or extension selection inputs"
        );
        return ExitCode::from(2);
    }
    if policy_path.is_some() && policy_pack_path.is_some() {
        eprintln!("fitctl contract: choose either --policy or --policy-pack");
        return ExitCode::from(2);
    }
    if policy_pack_lock_path.is_some() && policy_pack_path.is_none() {
        eprintln!("fitctl contract: --policy-pack-lock requires --policy-pack");
        return ExitCode::from(2);
    }
    if policy_id.is_some() && policy_pack_lock_path.is_some() {
        eprintln!("fitctl contract: choose either --policy-id or --policy-pack-lock");
        return ExitCode::from(2);
    }
    let survey = match load_host_survey_artifact_from_path(&survey_path) {
        Ok(survey) => survey,
        Err(error) => {
            eprintln!("fitctl contract: {error}");
            return ExitCode::from(2);
        }
    };
    let config_bundle = match config_bundle_path {
        Some(path) => match load_config_bundle_from_path_v1(&path) {
            Ok(bundle) => Some(bundle),
            Err(error) => {
                eprintln!("fitctl contract: {error}");
                return ExitCode::from(2);
            }
        },
        None => None,
    };
    let invocation_context = match invocation_context_path {
        Some(path) => match load_invocation_context_from_path(&path) {
            Ok(context) => Some(context),
            Err(error) => {
                eprintln!("fitctl contract: {error}");
                return ExitCode::from(2);
            }
        },
        None => None,
    };
    let selected_policy_id = match resolve_invocation_selected_policy_id_v1(
        policy_id.as_deref(),
        invocation_context.as_ref(),
    ) {
        Ok(selection) => selection,
        Err(error) => {
            eprintln!("fitctl contract: {error}");
            return ExitCode::from(2);
        }
    };
    let policy = if let Some(bundle) = config_bundle.as_ref() {
        bundle.config_bundle.policy.clone()
    } else {
        if policy_pack_path.is_none() && selected_policy_id.is_some() {
            eprintln!(
                "fitctl contract: invocation-context or --policy-id selection requires --policy-pack"
            );
            return ExitCode::from(2);
        }
        if policy_pack_lock_path.is_some()
            && invocation_context
                .as_ref()
                .and_then(|context| context.selected_policy_id.as_ref())
                .is_some()
        {
            eprintln!(
                "fitctl contract: --policy-pack-lock must not be combined with invocation-context policy selection"
            );
            return ExitCode::from(2);
        }
        if policy_pack_path.is_some()
            && selected_policy_id.is_none()
            && policy_pack_lock_path.is_none()
        {
            eprintln!(
                "fitctl contract: --policy-pack requires a selected policy id from --policy-id, --invocation-context, or --policy-pack-lock"
            );
            return ExitCode::from(2);
        }
        match (
            policy_path,
            policy_pack_path,
            selected_policy_id
                .as_ref()
                .map(|(policy_id, _)| policy_id.as_str()),
            policy_pack_lock_path,
        ) {
            (Some(path), None, None, None) => match load_policy_document_from_path(&path) {
                Ok(policy) => policy,
                Err(error) => {
                    eprintln!("fitctl contract: {error}");
                    return ExitCode::from(2);
                }
            },
            (None, Some(pack_path), Some(policy_id), None) => {
                match resolve_policy_from_pack_path(&pack_path, policy_id) {
                    Ok((_, _, policy)) => policy,
                    Err(error) => {
                        eprintln!("fitctl contract: {error}");
                        return ExitCode::from(2);
                    }
                }
            }
            (None, Some(pack_path), None, Some(lock_path)) => {
                match resolve_policy_from_pack_with_lock_path(&pack_path, &lock_path) {
                    Ok((_, _, _, policy)) => policy,
                    Err(error) => {
                        eprintln!("fitctl contract: {error}");
                        return ExitCode::from(2);
                    }
                }
            }
            _ => {
                eprintln!(
                    "fitctl contract: --policy, --policy-pack, or --config-bundle is required"
                );
                return ExitCode::from(2);
            }
        }
    };

    let mut extension_packs = Vec::new();
    for path in extension_pack_paths {
        match load_extension_pack_from_path(&path) {
            Ok(pack) => extension_packs.push(pack),
            Err(error) => {
                eprintln!("fitctl contract: {error}");
                return ExitCode::from(2);
            }
        }
    }

    let extension_basis = match resolve_contract_extension_basis_v1(
        config_bundle.as_ref(),
        policy.clone(),
        extension_packs,
        invocation_context.as_ref(),
        enabled_extension_namespaces,
    ) {
        Ok(basis) => basis,
        Err(error) => {
            eprintln!("fitctl contract: {error}");
            return ExitCode::from(2);
        }
    };

    let request = ContractDerivationRequestV1 {
        survey,
        policy,
        live_state: None,
        derivation_context: DerivationContextV1 {
            derived_at: derived_at.unwrap_or_else(current_epoch_marker),
            notes,
        },
    };

    let derivation = match extension_basis {
        Some(basis) => derive_host_contract_with_extensions_v1(request, basis),
        None => derive_host_contract_v1(request),
    };
    match derivation {
        Ok(contract) => match serde_json::to_string_pretty(&contract) {
            Ok(text) => {
                println!("{text}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("fitctl contract: failed to encode host contract: {error}");
                ExitCode::from(2)
            }
        },
        Err(error) => {
            eprintln!("fitctl contract: {error}");
            ExitCode::from(2)
        }
    }
}

fn render_help() -> &'static str {
    "Usage:\n  fitctl contract --survey <path> (--policy <path> | --policy-pack <path> [--policy-id <id> | --policy-pack-lock <path>] [--invocation-context <path>] | --config-bundle <path>) [--extension-pack <path> ...] [--invocation-context <path>] [--enable-extension <namespace> ...] [--derived-at <timestamp>] [--note <text>]\n\nNotes:\n  - built-in extension packs are available for fitctl.runtime.cuda, fitctl.runtime.python, and fitctl.runtime.node\n"
}

fn current_epoch_marker() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("unix:{seconds}")
}
