// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! CLI entrypoint for resolved configuration inspection across policy, packs, and invocation.

use std::path::PathBuf;
use std::process::ExitCode;

use fitctl_core::config::{
    load_extension_pack_from_path, load_invocation_context_from_path,
    load_recommendation_pack_from_path, resolve_configuration_v1, resolve_policy_from_pack_path,
    resolve_policy_from_pack_with_lock_path, resolve_service_profile_from_catalogue_path,
    ResolveConfigurationRequestV1,
};
use fitctl_core::policy::load_policy_document_from_path;
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
    let mut trust_policy_path: Option<PathBuf> = None;
    let mut invocation_context_path: Option<PathBuf> = None;
    let mut service_profile_catalogue_path: Option<PathBuf> = None;
    let mut profile_id: Option<String> = None;
    let mut extension_pack_paths = Vec::new();
    let mut recommendation_pack_paths = Vec::new();

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--policy" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl inspect-config: --policy requires a path");
                    return ExitCode::from(2);
                };
                policy_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--policy-pack" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl inspect-config: --policy-pack requires a path");
                    return ExitCode::from(2);
                };
                policy_pack_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--policy-id" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl inspect-config: --policy-id requires a value");
                    return ExitCode::from(2);
                };
                policy_id = Some(value.clone());
                index += 2;
            }
            "--policy-pack-lock" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl inspect-config: --policy-pack-lock requires a path");
                    return ExitCode::from(2);
                };
                policy_pack_lock_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--trust-policy" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl inspect-config: --trust-policy requires a path");
                    return ExitCode::from(2);
                };
                trust_policy_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--extension-pack" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl inspect-config: --extension-pack requires a path");
                    return ExitCode::from(2);
                };
                extension_pack_paths.push(PathBuf::from(value));
                index += 2;
            }
            "--recommendation-pack" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl inspect-config: --recommendation-pack requires a path");
                    return ExitCode::from(2);
                };
                recommendation_pack_paths.push(PathBuf::from(value));
                index += 2;
            }
            "--invocation-context" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl inspect-config: --invocation-context requires a path");
                    return ExitCode::from(2);
                };
                invocation_context_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--service-profile-catalogue" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl inspect-config: --service-profile-catalogue requires a path");
                    return ExitCode::from(2);
                };
                service_profile_catalogue_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--profile-id" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl inspect-config: --profile-id requires a value");
                    return ExitCode::from(2);
                };
                profile_id = Some(value.clone());
                index += 2;
            }
            unknown => {
                eprintln!("fitctl inspect-config: unknown option '{unknown}'");
                return ExitCode::from(2);
            }
        }
    }

    if policy_path.is_some() && policy_pack_path.is_some() {
        eprintln!("fitctl inspect-config: choose either --policy or --policy-pack/--policy-id");
        return ExitCode::from(2);
    }
    if policy_pack_lock_path.is_some() && policy_pack_path.is_none() {
        eprintln!("fitctl inspect-config: --policy-pack-lock requires --policy-pack");
        return ExitCode::from(2);
    }
    if policy_id.is_some() && policy_pack_lock_path.is_some() {
        eprintln!("fitctl inspect-config: choose either --policy-id or --policy-pack-lock");
        return ExitCode::from(2);
    }
    if policy_pack_path.is_some() && policy_id.is_none() && policy_pack_lock_path.is_none() {
        eprintln!(
            "fitctl inspect-config: --policy-pack requires either --policy-id or --policy-pack-lock"
        );
        return ExitCode::from(2);
    }
    if service_profile_catalogue_path.is_some() ^ profile_id.is_some() {
        eprintln!(
            "fitctl inspect-config: --service-profile-catalogue and --profile-id must be used together"
        );
        return ExitCode::from(2);
    }

    let (
        selected_policy_pack_id,
        selected_policy_entry_id,
        selected_policy_pack_lock_id,
        selected_policy_pack_lock_signed,
        policy,
    ) = match (
        policy_path,
        policy_pack_path,
        policy_id,
        policy_pack_lock_path,
    ) {
        (Some(path), None, None, None) => match load_policy_document_from_path(&path) {
            Ok(policy) => (None, None, None, None, policy),
            Err(error) => {
                eprintln!("fitctl inspect-config: {error}");
                return ExitCode::from(2);
            }
        },
        (None, Some(pack_path), Some(policy_id), None) => {
            match resolve_policy_from_pack_path(&pack_path, &policy_id) {
                Ok((pack, entry, policy)) => (
                    Some(pack.pack_id),
                    Some(entry.policy_id),
                    None,
                    None,
                    policy,
                ),
                Err(error) => {
                    eprintln!("fitctl inspect-config: {error}");
                    return ExitCode::from(2);
                }
            }
        }
        (None, Some(pack_path), None, Some(lock_path)) => {
            match resolve_policy_from_pack_with_lock_path(&pack_path, &lock_path) {
                Ok((pack, lock, entry, policy)) => (
                    Some(pack.pack_id),
                    Some(entry.policy_id),
                    Some(lock.lock_id),
                    Some(!lock.signatures.is_empty()),
                    policy,
                ),
                Err(error) => {
                    eprintln!("fitctl inspect-config: {error}");
                    return ExitCode::from(2);
                }
            }
        }
        _ => {
            eprintln!(
                    "fitctl inspect-config: --policy or --policy-pack (--policy-id | --policy-pack-lock) is required"
                );
            return ExitCode::from(2);
        }
    };
    let (selected_service_profile_catalogue_id, selected_service_profile_entry_id) = match (
        service_profile_catalogue_path,
        profile_id,
    ) {
        (Some(catalogue_path), Some(profile_id)) => {
            match resolve_service_profile_from_catalogue_path(&catalogue_path, &profile_id) {
                Ok((catalogue, entry, _)) => (Some(catalogue.catalogue_id), Some(entry.profile_id)),
                Err(error) => {
                    eprintln!("fitctl inspect-config: {error}");
                    return ExitCode::from(2);
                }
            }
        }
        (None, None) => (None, None),
        _ => {
            eprintln!(
                    "fitctl inspect-config: --service-profile-catalogue and --profile-id must be used together"
                );
            return ExitCode::from(2);
        }
    };
    let trust_policy = match trust_policy_path {
        Some(path) => match load_trust_policy_from_path(&path) {
            Ok(policy) => Some(policy),
            Err(error) => {
                eprintln!("fitctl inspect-config: {error}");
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
                eprintln!("fitctl inspect-config: {error}");
                return ExitCode::from(2);
            }
        }
    }

    let mut recommendation_packs = Vec::new();
    for path in recommendation_pack_paths {
        match load_recommendation_pack_from_path(&path) {
            Ok(pack) => recommendation_packs.push(pack),
            Err(error) => {
                eprintln!("fitctl inspect-config: {error}");
                return ExitCode::from(2);
            }
        }
    }

    let invocation_context = match invocation_context_path {
        Some(path) => match load_invocation_context_from_path(&path) {
            Ok(context) => Some(context),
            Err(error) => {
                eprintln!("fitctl inspect-config: {error}");
                return ExitCode::from(2);
            }
        },
        None => None,
    };

    match resolve_configuration_v1(ResolveConfigurationRequestV1 {
        policy,
        trust_policy,
        extension_packs,
        recommendation_packs,
        invocation_context,
    }) {
        Ok(mut config) => {
            config.selected_policy_pack_id = selected_policy_pack_id;
            config.selected_policy_entry_id = selected_policy_entry_id;
            config.selected_policy_pack_lock_id = selected_policy_pack_lock_id;
            config.selected_policy_pack_lock_signed = selected_policy_pack_lock_signed;
            config.selected_service_profile_catalogue_id = selected_service_profile_catalogue_id;
            config.selected_service_profile_entry_id = selected_service_profile_entry_id;
            match serde_json::to_string_pretty(&config) {
                Ok(text) => {
                    println!("{text}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("fitctl inspect-config: failed to encode resolved config: {error}");
                    ExitCode::from(2)
                }
            }
        }
        Err(error) => {
            eprintln!("fitctl inspect-config: {error}");
            ExitCode::from(2)
        }
    }
}

fn render_help() -> &'static str {
    "Usage:\n  fitctl inspect-config (--policy <path> | --policy-pack <path> (--policy-id <id> | --policy-pack-lock <path>)) [--service-profile-catalogue <path> --profile-id <id>] [--trust-policy <path>] [--extension-pack <path> ...] [--recommendation-pack <path> ...] [--invocation-context <path>]\n"
}
