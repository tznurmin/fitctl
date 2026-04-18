// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! CLI entrypoint for local config-bundle assembly over selected advanced config inputs.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use fitctl_core::config::{
    load_extension_pack_from_path, load_invocation_context_from_path,
    load_recommendation_pack_from_path, resolve_configuration_v1,
    resolve_invocation_selected_policy_id_v1, resolve_invocation_selected_service_profile_id_v1,
    resolve_policy_from_pack_path, resolve_policy_from_pack_with_lock_path,
    resolve_service_profile_from_catalogue_path, ResolveConfigurationRequestV1,
};
use fitctl_core::config_bundle::{
    assemble_config_bundle_v1, config_bundle_record_v1, ConfigBundleAssemblyRequestV1,
};
use fitctl_core::policy::load_policy_document_from_path;
use fitctl_core::service_profile::load_service_profile_from_path;
use fitctl_core::verify::load_trust_policy_from_path;

pub fn run(args: &[String]) -> ExitCode {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{}", render_help());
        return ExitCode::SUCCESS;
    }

    let mut policy_path: Option<PathBuf> = None;
    let mut policy_pack_path: Option<PathBuf> = None;
    let mut policy_id: Option<String> = None;
    let mut policy_pack_lock_path: Option<PathBuf> = None;
    let mut profile_path: Option<PathBuf> = None;
    let mut service_profile_catalogue_path: Option<PathBuf> = None;
    let mut profile_id: Option<String> = None;
    let mut trust_policy_path: Option<PathBuf> = None;
    let mut invocation_context_path: Option<PathBuf> = None;
    let mut extension_pack_paths = Vec::new();
    let mut recommendation_pack_paths = Vec::new();
    let mut bundled_at: Option<String> = None;
    let mut note: Option<String> = None;

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--policy" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl bundle-config: --policy requires a path");
                    return ExitCode::from(2);
                };
                policy_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--policy-pack" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl bundle-config: --policy-pack requires a path");
                    return ExitCode::from(2);
                };
                policy_pack_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--policy-id" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl bundle-config: --policy-id requires a value");
                    return ExitCode::from(2);
                };
                policy_id = Some(value.clone());
                index += 2;
            }
            "--policy-pack-lock" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl bundle-config: --policy-pack-lock requires a path");
                    return ExitCode::from(2);
                };
                policy_pack_lock_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--profile" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl bundle-config: --profile requires a path");
                    return ExitCode::from(2);
                };
                profile_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--service-profile-catalogue" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl bundle-config: --service-profile-catalogue requires a path");
                    return ExitCode::from(2);
                };
                service_profile_catalogue_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--profile-id" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl bundle-config: --profile-id requires a value");
                    return ExitCode::from(2);
                };
                profile_id = Some(value.clone());
                index += 2;
            }
            "--trust-policy" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl bundle-config: --trust-policy requires a path");
                    return ExitCode::from(2);
                };
                trust_policy_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--extension-pack" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl bundle-config: --extension-pack requires a path");
                    return ExitCode::from(2);
                };
                extension_pack_paths.push(PathBuf::from(value));
                index += 2;
            }
            "--recommendation-pack" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl bundle-config: --recommendation-pack requires a path");
                    return ExitCode::from(2);
                };
                recommendation_pack_paths.push(PathBuf::from(value));
                index += 2;
            }
            "--invocation-context" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl bundle-config: --invocation-context requires a path");
                    return ExitCode::from(2);
                };
                invocation_context_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--bundled-at" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl bundle-config: --bundled-at requires a timestamp");
                    return ExitCode::from(2);
                };
                bundled_at = Some(value.clone());
                index += 2;
            }
            "--note" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl bundle-config: --note requires text");
                    return ExitCode::from(2);
                };
                note = Some(value.clone());
                index += 2;
            }
            unknown => {
                eprintln!("fitctl bundle-config: unknown option '{unknown}'");
                return ExitCode::from(2);
            }
        }
    }

    if policy_path.is_some() && policy_pack_path.is_some() {
        eprintln!("fitctl bundle-config: choose either --policy or --policy-pack/--policy-id");
        return ExitCode::from(2);
    }
    if policy_pack_lock_path.is_some() && policy_pack_path.is_none() {
        eprintln!("fitctl bundle-config: --policy-pack-lock requires --policy-pack");
        return ExitCode::from(2);
    }
    if policy_id.is_some() && policy_pack_lock_path.is_some() {
        eprintln!("fitctl bundle-config: choose either --policy-id or --policy-pack-lock");
        return ExitCode::from(2);
    }
    if profile_path.is_some() && service_profile_catalogue_path.is_some() {
        eprintln!(
            "fitctl bundle-config: choose either --profile or --service-profile-catalogue/--profile-id"
        );
        return ExitCode::from(2);
    }
    if profile_id.is_some() && service_profile_catalogue_path.is_none() {
        eprintln!("fitctl bundle-config: --profile-id requires --service-profile-catalogue");
        return ExitCode::from(2);
    }

    let invocation_context = match invocation_context_path {
        Some(path) => match load_invocation_context_from_path(&path) {
            Ok(context) => Some(context),
            Err(error) => {
                eprintln!("fitctl bundle-config: {error}");
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
            eprintln!("fitctl bundle-config: {error}");
            return ExitCode::from(2);
        }
    };
    let selected_profile_id = match resolve_invocation_selected_service_profile_id_v1(
        profile_id.as_deref(),
        invocation_context.as_ref(),
    ) {
        Ok(selection) => selection,
        Err(error) => {
            eprintln!("fitctl bundle-config: {error}");
            return ExitCode::from(2);
        }
    };
    if policy_pack_path.is_none() && selected_policy_id.is_some() {
        eprintln!(
            "fitctl bundle-config: invocation-context or --policy-id selection requires --policy-pack"
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
            "fitctl bundle-config: --policy-pack-lock must not be combined with invocation-context policy selection"
        );
        return ExitCode::from(2);
    }
    if policy_pack_path.is_some() && selected_policy_id.is_none() && policy_pack_lock_path.is_none()
    {
        eprintln!(
            "fitctl bundle-config: --policy-pack requires a selected policy id from --policy-id, --invocation-context, or --policy-pack-lock"
        );
        return ExitCode::from(2);
    }
    if service_profile_catalogue_path.is_some() && selected_profile_id.is_none() {
        eprintln!(
            "fitctl bundle-config: --service-profile-catalogue requires a selected profile id from --profile-id or --invocation-context"
        );
        return ExitCode::from(2);
    }
    if service_profile_catalogue_path.is_none() && selected_profile_id.is_some() {
        eprintln!(
            "fitctl bundle-config: invocation-context or --profile-id selection requires --service-profile-catalogue"
        );
        return ExitCode::from(2);
    }

    let (
        selected_policy_pack_id,
        selected_policy_entry_id,
        selected_policy_entry_source,
        selected_policy_pack_lock_id,
        selected_policy_pack_lock_signed,
        policy,
    ) = match (
        policy_path,
        policy_pack_path,
        selected_policy_id,
        policy_pack_lock_path,
    ) {
        (Some(path), None, None, None) => match load_policy_document_from_path(&path) {
            Ok(policy) => (None, None, None, None, None, policy),
            Err(error) => {
                eprintln!("fitctl bundle-config: {error}");
                return ExitCode::from(2);
            }
        },
        (None, Some(pack_path), Some((policy_id, selection_source)), None) => {
            match resolve_policy_from_pack_path(&pack_path, &policy_id) {
                Ok((pack, entry, policy)) => (
                    Some(pack.pack_id),
                    Some(entry.policy_id),
                    Some(selection_source),
                    None,
                    None,
                    policy,
                ),
                Err(error) => {
                    eprintln!("fitctl bundle-config: {error}");
                    return ExitCode::from(2);
                }
            }
        }
        (None, Some(pack_path), None, Some(lock_path)) => {
            match resolve_policy_from_pack_with_lock_path(&pack_path, &lock_path) {
                Ok((pack, lock, entry, policy)) => (
                    Some(pack.pack_id),
                    Some(entry.policy_id),
                    None,
                    Some(lock.lock_id),
                    Some(!lock.signatures.is_empty()),
                    policy,
                ),
                Err(error) => {
                    eprintln!("fitctl bundle-config: {error}");
                    return ExitCode::from(2);
                }
            }
        }
        _ => {
            eprintln!(
                "fitctl bundle-config: --policy or --policy-pack (--policy-id | --policy-pack-lock) is required"
            );
            return ExitCode::from(2);
        }
    };

    let (
        selected_service_profile_catalogue_id,
        selected_service_profile_entry_id,
        selected_service_profile_entry_source,
        service_profile,
    ) = match (
        profile_path,
        service_profile_catalogue_path,
        selected_profile_id,
    ) {
        (Some(path), None, None) => match load_service_profile_from_path(&path) {
            Ok(profile) => (None, None, None, Some(profile)),
            Err(error) => {
                eprintln!("fitctl bundle-config: {error}");
                return ExitCode::from(2);
            }
        },
        (None, Some(catalogue_path), Some((profile_id, selection_source))) => {
            match resolve_service_profile_from_catalogue_path(&catalogue_path, &profile_id) {
                Ok((catalogue, entry, profile)) => (
                    Some(catalogue.catalogue_id),
                    Some(entry.profile_id),
                    Some(selection_source),
                    Some(profile),
                ),
                Err(error) => {
                    eprintln!("fitctl bundle-config: {error}");
                    return ExitCode::from(2);
                }
            }
        }
        (None, None, None) => (None, None, None, None),
        _ => {
            eprintln!(
                "fitctl bundle-config: choose either --profile or --service-profile-catalogue/--profile-id"
            );
            return ExitCode::from(2);
        }
    };

    let trust_policy = match trust_policy_path {
        Some(path) => match load_trust_policy_from_path(&path) {
            Ok(policy) => Some(policy),
            Err(error) => {
                eprintln!("fitctl bundle-config: {error}");
                return ExitCode::from(2);
            }
        },
        None => None,
    };

    let mut extension_packs = Vec::new();
    for path in extension_pack_paths {
        match load_extension_pack_from_path(&path) {
            Ok(pack) => extension_packs.push(pack),
            Err(error) => {
                eprintln!("fitctl bundle-config: {error}");
                return ExitCode::from(2);
            }
        }
    }

    let mut recommendation_packs = Vec::new();
    for path in recommendation_pack_paths {
        match load_recommendation_pack_from_path(&path) {
            Ok(pack) => recommendation_packs.push(pack),
            Err(error) => {
                eprintln!("fitctl bundle-config: {error}");
                return ExitCode::from(2);
            }
        }
    }

    let resolved_config = match resolve_configuration_v1(ResolveConfigurationRequestV1 {
        policy: policy.clone(),
        trust_policy: trust_policy.clone(),
        extension_packs,
        recommendation_packs,
        invocation_context,
        selected_policy_pack_id,
        selected_policy_entry_id,
        selected_policy_entry_source,
        selected_policy_pack_lock_id,
        selected_policy_pack_lock_signed,
        selected_service_profile_catalogue_id,
        selected_service_profile_entry_id,
        selected_service_profile_entry_source,
    }) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("fitctl bundle-config: {error}");
            return ExitCode::from(2);
        }
    };

    match assemble_config_bundle_v1(ConfigBundleAssemblyRequestV1 {
        policy,
        service_profile,
        trust_policy,
        resolved_config,
        bundled_at: bundled_at.unwrap_or_else(current_epoch_marker),
        notes: note,
    }) {
        Ok(bundle) => match serde_json::to_string_pretty(&config_bundle_record_v1(bundle)) {
            Ok(text) => {
                println!("{text}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("fitctl bundle-config: failed to encode config bundle: {error}");
                ExitCode::from(2)
            }
        },
        Err(error) => {
            eprintln!("fitctl bundle-config: {error}");
            ExitCode::from(2)
        }
    }
}

fn current_epoch_marker() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("unix:{seconds}")
}

fn render_help() -> &'static str {
    "Usage:\n  fitctl bundle-config (--policy <path> | --policy-pack <path> [--policy-id <id> | --policy-pack-lock <path>] [--invocation-context <path>]) [--profile <path> | --service-profile-catalogue <path> --profile-id <id> | --service-profile-catalogue <path> --invocation-context <path>] [--trust-policy <path>] [--extension-pack <path> ...] [--recommendation-pack <path> ...] [--invocation-context <path>] [--bundled-at <timestamp>] [--note <text>]\n"
}
