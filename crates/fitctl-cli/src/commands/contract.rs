// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! CLI entrypoint for host-contract derivation from survey evidence and policy.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use fitctl_core::artifacts::validation_v1::validate_host_contract;
use fitctl_core::config::{
    build_extension_basis_v1, load_extension_pack_from_path, load_invocation_context_from_path,
    resolve_configuration_v1, resolve_invocation_selected_policy_id_v1,
    resolve_policy_from_pack_path, resolve_policy_from_pack_with_lock_path, InvocationContextV1,
    ResolveConfigurationRequestV1,
};
use fitctl_core::config_bundle::load_config_bundle_from_path_v1;
use fitctl_core::contract::{
    derive_host_contract_v1, load_host_survey_artifact_from_path, ContractDerivationRequestV1,
    DerivationContextV1,
};
use fitctl_core::policy::load_policy_document_from_path;

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

    let request = ContractDerivationRequestV1 {
        survey,
        policy: policy.clone(),
        live_state: None,
        derivation_context: DerivationContextV1 {
            derived_at: derived_at.unwrap_or_else(current_epoch_marker),
            notes,
        },
    };

    match derive_host_contract_v1(request) {
        Ok(mut contract) => {
            let extension_basis = if let Some(bundle) = config_bundle.as_ref() {
                if !bundle
                    .config_bundle
                    .resolved_config
                    .configured_extension_pack_ids
                    .is_empty()
                    || !bundle
                        .config_bundle
                        .resolved_config
                        .enabled_extension_namespaces
                        .is_empty()
                {
                    eprintln!(
                        "fitctl contract: config bundle extension selections are not supported in the first config-bundle contract flow"
                    );
                    return ExitCode::from(2);
                }
                None
            } else if extension_packs.is_empty()
                && invocation_context.is_none()
                && enabled_extension_namespaces.is_empty()
            {
                None
            } else {
                let mut requested_extension_namespaces = invocation_context
                    .as_ref()
                    .map(|context| context.enabled_extension_namespaces.clone())
                    .unwrap_or_default();
                requested_extension_namespaces.extend(enabled_extension_namespaces);
                if requested_extension_namespaces
                    .iter()
                    .any(|namespace| namespace.trim().is_empty())
                {
                    eprintln!("fitctl contract: enabled extension namespaces must be non-empty");
                    return ExitCode::from(2);
                }
                requested_extension_namespaces.sort();
                requested_extension_namespaces.dedup();

                let resolved = match resolve_configuration_v1(ResolveConfigurationRequestV1 {
                    policy,
                    trust_policy: None,
                    extension_packs: extension_packs.clone(),
                    recommendation_packs: vec![],
                    invocation_context: Some(InvocationContextV1 {
                        schema_id: "fitctl.invocation-context.v1".to_string(),
                        schema_version: 1,
                        invocation_id: invocation_context
                            .as_ref()
                            .map(|context| context.invocation_id.clone())
                            .unwrap_or_else(|| "contract-extension-activation-v1".to_string()),
                        selected_policy_id: None,
                        selected_service_profile_id: None,
                        enabled_extension_namespaces: requested_extension_namespaces,
                        selected_recommendation_pack_ids: vec![],
                        enabled_simulation_layer_ids: vec![],
                        validation_mode: None,
                        max_state_age_seconds: None,
                    }),
                    selected_policy_pack_id: None,
                    selected_policy_entry_id: None,
                    selected_policy_entry_source: None,
                    selected_policy_pack_lock_id: None,
                    selected_policy_pack_lock_signed: None,
                    selected_service_profile_catalogue_id: None,
                    selected_service_profile_entry_id: None,
                    selected_service_profile_entry_source: None,
                }) {
                    Ok(resolved) => resolved,
                    Err(error) => {
                        eprintln!("fitctl contract: {error}");
                        return ExitCode::from(2);
                    }
                };

                match build_extension_basis_v1(&resolved, &extension_packs) {
                    Ok(extension_basis) => extension_basis,
                    Err(error) => {
                        eprintln!("fitctl contract: {error}");
                        return ExitCode::from(2);
                    }
                }
            };

            contract.contract_basis.extension_basis = extension_basis;
            if let Err(error) = validate_host_contract(&contract) {
                eprintln!("fitctl contract: {}", error.message);
                return ExitCode::from(2);
            }

            match serde_json::to_string_pretty(&contract) {
                Ok(text) => {
                    println!("{text}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("fitctl contract: failed to encode host contract: {error}");
                    ExitCode::from(2)
                }
            }
        }
        Err(error) => {
            eprintln!("fitctl contract: {error}");
            ExitCode::from(2)
        }
    }
}

fn render_help() -> &'static str {
    "Usage:\n  fitctl contract --survey <path> (--policy <path> | --policy-pack <path> [--policy-id <id> | --policy-pack-lock <path>] [--invocation-context <path>] | --config-bundle <path>) [--extension-pack <path> ...] [--invocation-context <path>] [--enable-extension <namespace> ...] [--derived-at <timestamp>] [--note <text>]\n"
}

fn current_epoch_marker() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("unix:{seconds}")
}
