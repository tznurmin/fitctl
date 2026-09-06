// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! CLI entrypoint for contract-only and state-aware service-profile validation.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use fitctl_core::artifacts::validation_v1::validate_host_state;
use fitctl_core::config::{
    load_invocation_context_from_path, resolve_invocation_selected_policy_id_v1,
    resolve_invocation_selected_service_profile_id_v1, resolve_policy_from_pack_path,
    resolve_policy_from_pack_with_lock_path, resolve_service_profile_from_catalogue_path,
};
use fitctl_core::config_bundle::load_config_bundle_from_path_v1;
use fitctl_core::contract::{
    derive_host_contract_v1, load_host_survey_artifact_from_path, ContractDerivationRequestV1,
    DerivationContextV1,
};
use fitctl_core::policy::load_policy_document_from_path;
use fitctl_core::state::thermal_v1::{
    built_in_local_thermal_provider_entries_v1, load_thermal_provider_config_entries_from_paths_v1,
};
use fitctl_core::state::{
    LocalLiveStateProbeV1, StateEngineV1, StateModeV1, StatePathCheckRequestV1,
    StatePathLinkPairProbeRequestV1,
};
use fitctl_core::validate::{
    load_contract_artifact_for_validation, load_host_state_artifact_for_validation,
    load_service_profile_artifact_for_validation, load_thermal_evidence_artifact_for_validation,
    validate_request_v1, ValidationModeV1, ValidationRequestV1, ValidationVerdictV1,
};

use crate::commands::state_support::{
    apply_state_extension_selection_v1, collect_feature_extension_namespaces_v1,
    default_state_replay_extensions_root_v1, parse_state_collect_feature_v1,
    prepare_state_extension_selection_v1, push_state_collect_feature_v1,
    CudaSelectedEnvironmentCliInputV1, StateCollectFeatureV1,
};

pub fn run(args: &[String]) -> ExitCode {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{}", render_help());
        return ExitCode::SUCCESS;
    }

    let mut contract_path: Option<PathBuf> = None;
    let mut survey_path: Option<PathBuf> = None;
    let mut config_bundle_path: Option<PathBuf> = None;
    let mut policy_path: Option<PathBuf> = None;
    let mut policy_pack_path: Option<PathBuf> = None;
    let mut policy_id: Option<String> = None;
    let mut policy_pack_lock_path: Option<PathBuf> = None;
    let mut profile_path: Option<PathBuf> = None;
    let mut service_profile_catalogue_path: Option<PathBuf> = None;
    let mut profile_id: Option<String> = None;
    let mut invocation_context_path: Option<PathBuf> = None;
    let mut state_path: Option<PathBuf> = None;
    let mut thermal_evidence_paths = Vec::new();
    let mut live_state_requested = false;
    let mut extension_pack_paths = Vec::new();
    let mut enabled_extension_namespaces = Vec::new();
    let mut mode = ValidationModeV1::ContractOnly;
    let mut max_state_age_seconds: Option<u64> = None;
    let mut validated_at: Option<String> = None;
    let mut note: Option<String> = None;
    let mut mode_source = ValidationModeSourceV1::Default;
    let mut gate_policy = ValidationGatePolicyV1::ReportOnly;
    let mut path_checks = Vec::new();
    let mut link_probe_path_ids = Vec::new();
    let mut link_pair_probe_requests = Vec::new();
    let mut health_probe_path_ids = Vec::new();
    let mut thermal_provider_config_paths = Vec::new();
    let mut collect_features = Vec::new();
    let mut state_out_path: Option<PathBuf> = None;
    let mut validation_out_path: Option<PathBuf> = None;

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--contract" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --contract requires a path");
                    return ExitCode::from(2);
                };
                contract_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--survey" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --survey requires a path");
                    return ExitCode::from(2);
                };
                survey_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--config-bundle" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --config-bundle requires a path");
                    return ExitCode::from(2);
                };
                config_bundle_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--policy" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --policy requires a path");
                    return ExitCode::from(2);
                };
                policy_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--policy-pack" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --policy-pack requires a path");
                    return ExitCode::from(2);
                };
                policy_pack_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--policy-id" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --policy-id requires a value");
                    return ExitCode::from(2);
                };
                policy_id = Some(value.clone());
                index += 2;
            }
            "--policy-pack-lock" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --policy-pack-lock requires a path");
                    return ExitCode::from(2);
                };
                policy_pack_lock_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--profile" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --profile requires a path");
                    return ExitCode::from(2);
                };
                profile_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--service-profile-catalogue" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --service-profile-catalogue requires a path");
                    return ExitCode::from(2);
                };
                service_profile_catalogue_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--profile-id" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --profile-id requires a value");
                    return ExitCode::from(2);
                };
                profile_id = Some(value.clone());
                index += 2;
            }
            "--invocation-context" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --invocation-context requires a path");
                    return ExitCode::from(2);
                };
                invocation_context_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--state" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --state requires a path");
                    return ExitCode::from(2);
                };
                state_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--live-state" => {
                live_state_requested = true;
                index += 1;
            }
            "--extension-pack" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --extension-pack requires a path");
                    return ExitCode::from(2);
                };
                extension_pack_paths.push(PathBuf::from(value));
                index += 2;
            }
            "--enable-extension" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --enable-extension requires a namespace");
                    return ExitCode::from(2);
                };
                enabled_extension_namespaces.push(value.clone());
                index += 2;
            }
            "--path-check" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --path-check requires <id>=<path>");
                    return ExitCode::from(2);
                };
                match parse_path_check(value) {
                    Ok(path_check) => path_checks.push(path_check),
                    Err(error) => {
                        eprintln!("fitctl validate: {error}");
                        return ExitCode::from(2);
                    }
                }
                index += 2;
            }
            "--probe-path-links" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --probe-path-links requires a path-check id");
                    return ExitCode::from(2);
                };
                if value.trim().is_empty() || value.contains(char::is_whitespace) {
                    eprintln!("fitctl validate: --probe-path-links id must be non-empty and contain no whitespace");
                    return ExitCode::from(2);
                }
                link_probe_path_ids.push(value.clone());
                index += 2;
            }
            "--probe-path-link-pair" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --probe-path-link-pair requires <from-id>:<to-id>");
                    return ExitCode::from(2);
                };
                match parse_path_link_pair_probe(value) {
                    Ok(request) => link_pair_probe_requests.push(request),
                    Err(error) => {
                        eprintln!("fitctl validate: {error}");
                        return ExitCode::from(2);
                    }
                }
                index += 2;
            }
            "--probe-path-health" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --probe-path-health requires a path-check id");
                    return ExitCode::from(2);
                };
                if value.trim().is_empty() || value.contains(char::is_whitespace) {
                    eprintln!("fitctl validate: --probe-path-health id must be non-empty and contain no whitespace");
                    return ExitCode::from(2);
                }
                health_probe_path_ids.push(value.clone());
                index += 2;
            }
            "--thermal-provider-config" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --thermal-provider-config requires a path");
                    return ExitCode::from(2);
                };
                thermal_provider_config_paths.push(PathBuf::from(value));
                index += 2;
            }
            "--collect" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --collect requires a feature");
                    return ExitCode::from(2);
                };
                match parse_state_collect_feature_v1(value) {
                    Ok(feature) => push_state_collect_feature_v1(&mut collect_features, feature),
                    Err(error) => {
                        eprintln!("fitctl validate: {error}");
                        return ExitCode::from(2);
                    }
                }
                index += 2;
            }
            "--thermal-evidence" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --thermal-evidence requires a path");
                    return ExitCode::from(2);
                };
                thermal_evidence_paths.push(PathBuf::from(value));
                index += 2;
            }
            "--state-out" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --state-out requires a path");
                    return ExitCode::from(2);
                };
                state_out_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--validation-out" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --validation-out requires a path");
                    return ExitCode::from(2);
                };
                validation_out_path = Some(PathBuf::from(value));
                index += 2;
            }
            "--validation-mode" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --validation-mode requires a value");
                    return ExitCode::from(2);
                };
                if !matches!(mode_source, ValidationModeSourceV1::Default) {
                    eprintln!("fitctl validate: validation mode may be specified only once");
                    return ExitCode::from(2);
                }
                mode = match parse_primary_validation_mode(value) {
                    Ok(mode) => mode,
                    Err(error) => {
                        eprintln!("fitctl validate: {error}");
                        return ExitCode::from(2);
                    }
                };
                mode_source = ValidationModeSourceV1::Primary;
                index += 2;
            }
            "--mode" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --mode requires a value");
                    return ExitCode::from(2);
                };
                if !matches!(mode_source, ValidationModeSourceV1::Default) {
                    eprintln!("fitctl validate: validation mode may be specified only once");
                    return ExitCode::from(2);
                }
                mode = match parse_legacy_mode_alias(value) {
                    Ok(mode) => mode,
                    Err(error) => {
                        eprintln!("fitctl validate: {error}");
                        return ExitCode::from(2);
                    }
                };
                mode_source = ValidationModeSourceV1::Legacy;
                index += 2;
            }
            "--max-state-age" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --max-state-age requires a value");
                    return ExitCode::from(2);
                };
                max_state_age_seconds = match parse_max_state_age_seconds(value) {
                    Ok(value) => Some(value),
                    Err(error) => {
                        eprintln!("fitctl validate: {error}");
                        return ExitCode::from(2);
                    }
                };
                index += 2;
            }
            "--validated-at" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --validated-at requires a timestamp");
                    return ExitCode::from(2);
                };
                validated_at = Some(value.clone());
                index += 2;
            }
            "--note" => {
                let Some(value) = args.get(index + 1) else {
                    eprintln!("fitctl validate: --note requires text");
                    return ExitCode::from(2);
                };
                note = Some(value.clone());
                index += 2;
            }
            "--fail-on-unfit" => {
                if !matches!(gate_policy, ValidationGatePolicyV1::ReportOnly) {
                    eprintln!("fitctl validate: choose either --fail-on-unfit or --require-fit");
                    return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
                }
                gate_policy = ValidationGatePolicyV1::FailOnUnfit;
                index += 1;
            }
            "--require-fit" => {
                if !matches!(gate_policy, ValidationGatePolicyV1::ReportOnly) {
                    eprintln!("fitctl validate: choose either --fail-on-unfit or --require-fit");
                    return ExitCode::from(fitctl_core::EXIT_CODE_USAGE_ERROR);
                }
                gate_policy = ValidationGatePolicyV1::RequireFit;
                index += 1;
            }
            unknown => {
                eprintln!("fitctl validate: unknown option '{unknown}'");
                return ExitCode::from(2);
            }
        }
    }

    let explicit_contract_selected = contract_path.is_some();
    let inline_survey_selected = survey_path.is_some();
    let config_bundle_selected = config_bundle_path.is_some();
    let explicit_policy_inputs_selected = policy_path.is_some()
        || policy_pack_path.is_some()
        || policy_id.is_some()
        || policy_pack_lock_path.is_some();
    let explicit_profile_inputs_selected =
        profile_path.is_some() || service_profile_catalogue_path.is_some() || profile_id.is_some();

    if explicit_contract_selected && inline_survey_selected {
        eprintln!("fitctl validate: choose either --contract or --survey");
        return ExitCode::from(2);
    }
    if !explicit_contract_selected && !inline_survey_selected {
        eprintln!("fitctl validate: --contract or --survey is required");
        return ExitCode::from(2);
    }

    let config_bundle = match config_bundle_path {
        Some(path) => match load_config_bundle_from_path_v1(&path) {
            Ok(bundle) => Some(bundle),
            Err(error) => {
                eprintln!("fitctl validate: {error}");
                return ExitCode::from(2);
            }
        },
        None => None,
    };

    let (invocation_context, selected_policy_id, selected_profile_id) = if config_bundle_selected {
        if explicit_policy_inputs_selected
            || explicit_profile_inputs_selected
            || invocation_context_path.is_some()
        {
            eprintln!(
                "fitctl validate: --config-bundle must not be combined with explicit policy, policy-pack, profile, service-profile-catalogue, or invocation-context inputs"
            );
            return ExitCode::from(2);
        }
        (None, None, None)
    } else {
        if policy_path.is_some() && policy_pack_path.is_some() {
            eprintln!("fitctl validate: choose either --policy or --policy-pack");
            return ExitCode::from(2);
        }
        if policy_pack_lock_path.is_some() && policy_pack_path.is_none() {
            eprintln!("fitctl validate: --policy-pack-lock requires --policy-pack");
            return ExitCode::from(2);
        }
        if policy_id.is_some() && policy_pack_path.is_none() {
            eprintln!("fitctl validate: --policy-id requires --policy-pack");
            return ExitCode::from(2);
        }
        if policy_id.is_some() && policy_pack_lock_path.is_some() {
            eprintln!("fitctl validate: choose either --policy-id or --policy-pack-lock");
            return ExitCode::from(2);
        }
        if inline_survey_selected && policy_path.is_none() && policy_pack_path.is_none() {
            eprintln!("fitctl validate: --survey requires --policy or --policy-pack");
            return ExitCode::from(2);
        }
        if profile_path.is_some() && service_profile_catalogue_path.is_some() {
            eprintln!(
                "fitctl validate: choose either --profile or --service-profile-catalogue/--profile-id"
            );
            return ExitCode::from(2);
        }

        let invocation_context = match invocation_context_path {
            Some(path) => match load_invocation_context_from_path(&path) {
                Ok(context) => Some(context),
                Err(error) => {
                    eprintln!("fitctl validate: {error}");
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
                eprintln!("fitctl validate: {error}");
                return ExitCode::from(2);
            }
        };
        let selected_profile_id = match resolve_invocation_selected_service_profile_id_v1(
            profile_id.as_deref(),
            invocation_context.as_ref(),
        ) {
            Ok(selection) => selection,
            Err(error) => {
                eprintln!("fitctl validate: {error}");
                return ExitCode::from(2);
            }
        };
        if policy_pack_path.is_none() && selected_policy_id.is_some() {
            eprintln!(
                "fitctl validate: invocation-context or --policy-id selection requires --policy-pack"
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
                "fitctl validate: --policy-pack-lock must not be combined with invocation-context policy selection"
            );
            return ExitCode::from(2);
        }
        if policy_pack_path.is_some()
            && selected_policy_id.is_none()
            && policy_pack_lock_path.is_none()
        {
            eprintln!(
                "fitctl validate: --policy-pack requires a selected policy id from --policy-id, --invocation-context, or --policy-pack-lock"
            );
            return ExitCode::from(2);
        }
        if service_profile_catalogue_path.is_some() && selected_profile_id.is_none() {
            eprintln!(
                "fitctl validate: --service-profile-catalogue requires a selected profile id from --profile-id or --invocation-context"
            );
            return ExitCode::from(2);
        }
        if service_profile_catalogue_path.is_none() && selected_profile_id.is_some() {
            eprintln!(
                "fitctl validate: invocation-context or --profile-id selection requires --service-profile-catalogue"
            );
            return ExitCode::from(2);
        }
        (invocation_context, selected_policy_id, selected_profile_id)
    };

    if matches!(mode_source, ValidationModeSourceV1::Default) {
        if let Some(bundle) = config_bundle.as_ref() {
            if let Some(bundle_mode) = bundle.config_bundle.resolved_config.validation_mode {
                mode = bundle_mode;
            }
        } else if let Some(context_mode) = invocation_context
            .as_ref()
            .and_then(|context| context.validation_mode)
        {
            mode = context_mode;
        }
    }
    if max_state_age_seconds.is_none() {
        max_state_age_seconds = if let Some(bundle) = config_bundle.as_ref() {
            bundle.config_bundle.resolved_config.max_state_age_seconds
        } else {
            invocation_context
                .as_ref()
                .and_then(|context| context.max_state_age_seconds)
        };
    }
    if mode == ValidationModeV1::ContractOnly && state_path.is_some() {
        eprintln!("fitctl validate: --state is not allowed in contract_only mode");
        return ExitCode::from(2);
    }
    if live_state_requested && state_path.is_some() {
        eprintln!("fitctl validate: --live-state cannot be combined with --state");
        return ExitCode::from(2);
    }
    if !path_checks.is_empty() && !live_state_requested {
        eprintln!("fitctl validate: --path-check requires --live-state");
        return ExitCode::from(2);
    }
    if !link_probe_path_ids.is_empty() && !live_state_requested {
        eprintln!("fitctl validate: --probe-path-links requires --live-state");
        return ExitCode::from(2);
    }
    if !link_pair_probe_requests.is_empty() && !live_state_requested {
        eprintln!("fitctl validate: --probe-path-link-pair requires --live-state");
        return ExitCode::from(2);
    }
    if !health_probe_path_ids.is_empty() && !live_state_requested {
        eprintln!("fitctl validate: --probe-path-health requires --live-state");
        return ExitCode::from(2);
    }
    if !thermal_provider_config_paths.is_empty() && !live_state_requested {
        eprintln!("fitctl validate: --thermal-provider-config requires --live-state");
        return ExitCode::from(2);
    }
    if !collect_features.is_empty() && !live_state_requested {
        eprintln!("fitctl validate: --collect requires --live-state");
        return ExitCode::from(2);
    }
    if state_out_path.is_some() && !live_state_requested {
        eprintln!("fitctl validate: --state-out requires --live-state");
        return ExitCode::from(2);
    }
    if let Err(error) = apply_link_probe_selection(&mut path_checks, &link_probe_path_ids) {
        eprintln!("fitctl validate: {error}");
        return ExitCode::from(2);
    }
    if let Err(error) = apply_health_probe_selection(&mut path_checks, &health_probe_path_ids) {
        eprintln!("fitctl validate: {error}");
        return ExitCode::from(2);
    }
    if let Err(error) = validate_link_pair_probe_selection(&path_checks, &link_pair_probe_requests)
    {
        eprintln!("fitctl validate: {error}");
        return ExitCode::from(2);
    }
    if !live_state_requested
        && (!extension_pack_paths.is_empty() || !enabled_extension_namespaces.is_empty())
    {
        eprintln!("fitctl validate: --extension-pack and --enable-extension require --live-state");
        return ExitCode::from(2);
    }
    if live_state_requested && mode == ValidationModeV1::ContractOnly {
        eprintln!("fitctl validate: --live-state is not allowed in contract_only mode");
        return ExitCode::from(2);
    }
    if mode == ValidationModeV1::ContractOnly && max_state_age_seconds.is_some() {
        eprintln!("fitctl validate: --max-state-age is not allowed in contract_only mode");
        return ExitCode::from(2);
    }
    if mode == ValidationModeV1::ContractOnly && !thermal_evidence_paths.is_empty() {
        eprintln!("fitctl validate: --thermal-evidence is not allowed in contract_only mode");
        return ExitCode::from(2);
    }
    if live_state_requested && max_state_age_seconds.is_some() {
        eprintln!("fitctl validate: --max-state-age is not allowed with --live-state");
        return ExitCode::from(2);
    }
    if max_state_age_seconds.is_some()
        && state_path.is_none()
        && !live_state_requested
        && thermal_evidence_paths.is_empty()
    {
        eprintln!("fitctl validate: --max-state-age requires --state or --thermal-evidence");
        return ExitCode::from(2);
    }
    if mode == ValidationModeV1::StateAware && state_path.is_none() && !live_state_requested {
        eprintln!("fitctl validate: --mode state_aware requires --state or --live-state");
        return ExitCode::from(2);
    }
    if mode == ValidationModeV1::StateAware && !thermal_evidence_paths.is_empty() {
        eprintln!(
            "fitctl validate: --thermal-evidence is not supported in state_aware compatibility mode"
        );
        return ExitCode::from(2);
    }
    if matches!(mode, ValidationModeV1::StateRequired)
        && state_path.is_none()
        && !live_state_requested
        && thermal_evidence_paths.is_empty()
    {
        eprintln!(
            "fitctl validate: state-aware validation requires --state, --live-state, or --thermal-evidence"
        );
        return ExitCode::from(2);
    }

    let validated_at = validated_at.unwrap_or_else(current_epoch_marker);
    let contract = if let Some(bundle) = config_bundle.as_ref() {
        if let Some(path) = contract_path {
            match load_contract_artifact_for_validation(&path) {
                Ok(contract) => contract,
                Err(error) => {
                    eprintln!("fitctl validate: {error}");
                    return ExitCode::from(2);
                }
            }
        } else {
            let Some(survey_path) = survey_path else {
                eprintln!("fitctl validate: --survey is required when deriving a contract inline");
                return ExitCode::from(2);
            };
            if config_bundle_requests_extension_support(bundle) {
                eprintln!(
                    "fitctl validate: config bundle extension selections are not supported in the first config-bundle validate flow"
                );
                return ExitCode::from(2);
            }
            let survey = match load_host_survey_artifact_from_path(&survey_path) {
                Ok(survey) => survey,
                Err(error) => {
                    eprintln!("fitctl validate: {error}");
                    return ExitCode::from(2);
                }
            };
            match derive_host_contract_v1(ContractDerivationRequestV1 {
                survey,
                policy: bundle.config_bundle.policy.clone(),
                live_state: None,
                derivation_context: DerivationContextV1 {
                    derived_at: validated_at.clone(),
                    notes: None,
                },
            }) {
                Ok(contract) => contract,
                Err(error) => {
                    eprintln!("fitctl validate: {error}");
                    return ExitCode::from(2);
                }
            }
        }
    } else {
        match (
            contract_path,
            survey_path,
            policy_path,
            policy_pack_path,
            policy_pack_lock_path,
        ) {
            (Some(path), None, None, None, None) => {
                match load_contract_artifact_for_validation(&path) {
                    Ok(contract) => contract,
                    Err(error) => {
                        eprintln!("fitctl validate: {error}");
                        return ExitCode::from(2);
                    }
                }
            }
            (None, Some(survey_path), Some(policy_path), None, None) => {
                let survey = match load_host_survey_artifact_from_path(&survey_path) {
                    Ok(survey) => survey,
                    Err(error) => {
                        eprintln!("fitctl validate: {error}");
                        return ExitCode::from(2);
                    }
                };
                let policy = match load_policy_document_from_path(&policy_path) {
                    Ok(policy) => policy,
                    Err(error) => {
                        eprintln!("fitctl validate: {error}");
                        return ExitCode::from(2);
                    }
                };

                match derive_host_contract_v1(ContractDerivationRequestV1 {
                    survey,
                    policy,
                    live_state: None,
                    derivation_context: DerivationContextV1 {
                        derived_at: validated_at.clone(),
                        notes: None,
                    },
                }) {
                    Ok(contract) => contract,
                    Err(error) => {
                        eprintln!("fitctl validate: {error}");
                        return ExitCode::from(2);
                    }
                }
            }
            (None, Some(survey_path), None, Some(policy_pack_path), None) => {
                let survey = match load_host_survey_artifact_from_path(&survey_path) {
                    Ok(survey) => survey,
                    Err(error) => {
                        eprintln!("fitctl validate: {error}");
                        return ExitCode::from(2);
                    }
                };
                let Some((policy_id, _)) = selected_policy_id.as_ref() else {
                    eprintln!(
                        "fitctl validate: --policy-pack requires a selected policy id from --policy-id or --invocation-context"
                    );
                    return ExitCode::from(2);
                };
                let policy = match resolve_policy_from_pack_path(&policy_pack_path, policy_id) {
                    Ok((_, _, policy)) => policy,
                    Err(error) => {
                        eprintln!("fitctl validate: {error}");
                        return ExitCode::from(2);
                    }
                };

                match derive_host_contract_v1(ContractDerivationRequestV1 {
                    survey,
                    policy,
                    live_state: None,
                    derivation_context: DerivationContextV1 {
                        derived_at: validated_at.clone(),
                        notes: None,
                    },
                }) {
                    Ok(contract) => contract,
                    Err(error) => {
                        eprintln!("fitctl validate: {error}");
                        return ExitCode::from(2);
                    }
                }
            }
            (
                None,
                Some(survey_path),
                None,
                Some(policy_pack_path),
                Some(policy_pack_lock_path),
            ) => {
                let survey = match load_host_survey_artifact_from_path(&survey_path) {
                    Ok(survey) => survey,
                    Err(error) => {
                        eprintln!("fitctl validate: {error}");
                        return ExitCode::from(2);
                    }
                };
                let policy = match resolve_policy_from_pack_with_lock_path(
                    &policy_pack_path,
                    &policy_pack_lock_path,
                ) {
                    Ok((_, _, _, policy)) => policy,
                    Err(error) => {
                        eprintln!("fitctl validate: {error}");
                        return ExitCode::from(2);
                    }
                };

                match derive_host_contract_v1(ContractDerivationRequestV1 {
                    survey,
                    policy,
                    live_state: None,
                    derivation_context: DerivationContextV1 {
                        derived_at: validated_at.clone(),
                        notes: None,
                    },
                }) {
                    Ok(contract) => contract,
                    Err(error) => {
                        eprintln!("fitctl validate: {error}");
                        return ExitCode::from(2);
                    }
                }
            }
            _ => {
                eprintln!(
                    "fitctl validate: choose either --contract or --survey with --policy/--policy-pack, or pair them with --config-bundle"
                );
                return ExitCode::from(2);
            }
        }
    };
    let service_profile = if let Some(bundle) = config_bundle.as_ref() {
        match bundle.config_bundle.service_profile.clone() {
            Some(profile) => profile,
            None => {
                eprintln!(
                    "fitctl validate: --config-bundle requires an embedded selected service profile"
                );
                return ExitCode::from(2);
            }
        }
    } else {
        match (
            profile_path,
            service_profile_catalogue_path,
            selected_profile_id
                .as_ref()
                .map(|(profile_id, _)| profile_id.as_str()),
        ) {
            (Some(path), None, None) => match load_service_profile_artifact_for_validation(&path) {
                Ok(profile) => profile,
                Err(error) => {
                    eprintln!("fitctl validate: {error}");
                    return ExitCode::from(2);
                }
            },
            (None, Some(catalogue_path), Some(profile_id)) => {
                match resolve_service_profile_from_catalogue_path(&catalogue_path, profile_id) {
                    Ok((_, _, profile)) => profile,
                    Err(error) => {
                        eprintln!("fitctl validate: {error}");
                        return ExitCode::from(2);
                    }
                }
            }
            _ => {
                eprintln!(
                    "fitctl validate: --profile, --service-profile-catalogue/--profile-id, or --config-bundle is required"
                );
                return ExitCode::from(2);
            }
        }
    };
    let extension_selection = if live_state_requested {
        let mut collect_extension_namespaces =
            collect_feature_extension_namespaces_v1(&collect_features);
        collect_extension_namespaces.extend(enabled_extension_namespaces.iter().cloned());
        match prepare_state_extension_selection_v1(
            true,
            invocation_context
                .as_ref()
                .map(|context| context.enabled_extension_namespaces.as_slice())
                .unwrap_or(&[]),
            &extension_pack_paths,
            &collect_extension_namespaces,
            &CudaSelectedEnvironmentCliInputV1::default(),
        ) {
            Ok(selection) => Some(selection),
            Err(error) => {
                eprintln!("fitctl validate: {error}");
                return ExitCode::from(2);
            }
        }
    } else {
        None
    };
    let mut thermal_provider_configs = if live_state_requested {
        match load_thermal_provider_config_entries_from_paths_v1(&thermal_provider_config_paths) {
            Ok(configs) => configs,
            Err(error) => {
                eprintln!("fitctl validate: {error}");
                return ExitCode::from(2);
            }
        }
    } else {
        Vec::new()
    };
    if collect_features.contains(&StateCollectFeatureV1::Thermal) {
        let mut built_ins = built_in_local_thermal_provider_entries_v1();
        built_ins.extend(thermal_provider_configs);
        thermal_provider_configs = built_ins;
    }

    let host_state = match state_path {
        Some(path) => match load_host_state_artifact_for_validation(&path) {
            Ok(state) => Some(state),
            Err(error) => {
                eprintln!("fitctl validate: {error}");
                return ExitCode::from(2);
            }
        },
        None if live_state_requested => {
            let mode = resolve_inline_live_state_mode_v1();
            let replay_extensions_root = match &mode {
                StateModeV1::Replay { fixtures_root, .. } => {
                    Some(default_state_replay_extensions_root_v1(fixtures_root))
                }
                StateModeV1::Live => None,
            };
            let live_probe = LocalLiveStateProbeV1::new_with_path_link_pairs_and_thermal_providers(
                path_checks,
                link_pair_probe_requests,
                thermal_provider_configs,
            )
            .with_memory_reliability_collection(
                collect_features.contains(&StateCollectFeatureV1::MemoryReliability),
            )
            .with_hardware_sensor_collection(
                collect_features.contains(&StateCollectFeatureV1::HardwareSensors),
            )
            .with_gpu_reliability_collection(
                collect_features.contains(&StateCollectFeatureV1::GpuReliability),
            );
            let engine = StateEngineV1::new(live_probe);
            let state = match engine.collect_host_state(mode) {
                Ok(state) => state,
                Err(error) => {
                    eprintln!("fitctl validate: {error}");
                    return ExitCode::from(2);
                }
            };
            let selection = extension_selection
                .as_ref()
                .expect("live-state selection must be prepared");
            let state = match apply_state_extension_selection_v1(
                state,
                selection,
                replay_extensions_root.as_deref(),
            ) {
                Ok(state) => state,
                Err(error) => {
                    eprintln!("fitctl validate: {error}");
                    return ExitCode::from(2);
                }
            };
            if let Err(error) = validate_host_state(&state) {
                eprintln!("fitctl validate: {}", error.message);
                return ExitCode::from(2);
            }
            Some(state)
        }
        None => None,
    };

    let retained_state = host_state.clone();
    let thermal_evidence = {
        let mut artifacts = Vec::with_capacity(thermal_evidence_paths.len());
        for path in &thermal_evidence_paths {
            match load_thermal_evidence_artifact_for_validation(path) {
                Ok(artifact) => artifacts.push(artifact),
                Err(error) => {
                    eprintln!("fitctl validate: {error}");
                    return ExitCode::from(2);
                }
            }
        }
        artifacts
    };
    match validate_request_v1(ValidationRequestV1 {
        contract,
        service_profile,
        host_state,
        thermal_evidence,
        mode,
        validated_at,
        notes: note,
        max_state_age_seconds,
    }) {
        Ok(report) => match serde_json::to_string_pretty(&report) {
            Ok(text) => {
                if let Some(path) = state_out_path.as_deref() {
                    let Some(state) = retained_state.as_ref() else {
                        eprintln!("fitctl validate: --state-out requires retained live state");
                        return ExitCode::from(2);
                    };
                    if let Err(error) = write_pretty_json(path, state) {
                        eprintln!("fitctl validate: failed to write --state-out artifact: {error}");
                        return ExitCode::from(2);
                    }
                }
                if let Some(path) = validation_out_path.as_deref() {
                    if let Err(error) = fs::write(path, text.as_bytes()) {
                        eprintln!(
                            "fitctl validate: failed to write --validation-out artifact: {error}"
                        );
                        return ExitCode::from(2);
                    }
                }
                let verdict = report.report.verdict;
                println!("{text}");
                gate_policy.exit_code(verdict)
            }
            Err(error) => {
                eprintln!("fitctl validate: failed to encode validation report: {error}");
                ExitCode::from(2)
            }
        },
        Err(error) => {
            eprintln!("fitctl validate: {error}");
            ExitCode::from(2)
        }
    }
}

fn render_help() -> &'static str {
    concat!(
        "Usage:\n",
        "  fitctl validate --contract <path> ",
        "(--profile <path> | --service-profile-catalogue <path> [--profile-id <id>] ",
        "[--invocation-context <path>] | --config-bundle <path>) ",
        "[--validation-mode <contract_only|state_advisory|state_required>] ",
        "[--state <path> | --live-state [--collect <thermal|memory-reliability|gpu-reliability|cuda-runtime|hardware-sensors> ...] [--path-check <id>=<path> ...] ",
        "[--probe-path-links <id> ...] [--probe-path-link-pair <from-id>:<to-id> ...] ",
        "[--probe-path-health <id> ...] [--thermal-provider-config <path> ...] ",
        "[--extension-pack <path> ...] [--enable-extension <namespace> ...]] ",
        "[--thermal-evidence <path> ...] [--state-out <path>] [--validation-out <path>] ",
        "[--max-state-age <value>] [--validated-at <timestamp>] [--note <text>] ",
        "[--fail-on-unfit | --require-fit]\n",
        "  fitctl validate --survey <path> ",
        "(--policy <path> | --policy-pack <path> [--policy-id <id> | --policy-pack-lock <path>] ",
        "[--invocation-context <path>] | --config-bundle <path>) ",
        "(--profile <path> | --service-profile-catalogue <path> [--profile-id <id>] ",
        "[--invocation-context <path>] | --config-bundle <path>) ",
        "[--validation-mode <contract_only|state_advisory|state_required>] ",
        "[--state <path> | --live-state [--collect <thermal|memory-reliability|gpu-reliability|cuda-runtime|hardware-sensors> ...] [--path-check <id>=<path> ...] ",
        "[--probe-path-links <id> ...] [--probe-path-link-pair <from-id>:<to-id> ...] ",
        "[--probe-path-health <id> ...] [--thermal-provider-config <path> ...] ",
        "[--extension-pack <path> ...] [--enable-extension <namespace> ...]] ",
        "[--thermal-evidence <path> ...] [--state-out <path>] [--validation-out <path>] ",
        "[--max-state-age <value>] [--validated-at <timestamp>] [--note <text>] ",
        "[--fail-on-unfit | --require-fit]\n",
        "\nModes:\n",
        "  - contract_only decides from the contract and service profile only\n",
        "  - state_advisory uses host-state or target-bound thermal evidence when provided ",
        "and keeps missing or stale runtime evidence explicit\n",
        "  - state_required uses host-state or target-bound thermal evidence for ",
        "runtime-sensitive checks and treats missing or stale evidence as blocking\n",
        "\nGate flags:\n",
        "  - --fail-on-unfit exits with policy rejection for unfit or indeterminate verdicts\n",
        "  - --require-fit exits with policy rejection unless the verdict is fit\n",
        "  - both flags preserve the validation report on stdout\n",
        "\nFreshness:\n",
        "  - --validated-at <timestamp> sets the decision timestamp used for freshness checks\n",
        "    accepts UTC RFC3339 or unix:<seconds> and defaults to the current time when omitted\n",
        "  - --max-state-age <value> requires explicit --state or --thermal-evidence input ",
        "and rejects older evidence\n",
        "    accepts seconds or s/m/h suffixes such as 600, 10m, or 1h\n",
        "\nNotes:\n",
        "  - contract_only does not accept host-state or thermal-evidence input\n",
        "  - --state-out requires --live-state and writes the exact state artifact used for validation\n",
        "  - --validation-out writes the validation report artifact before gate flags affect process exit\n",
        "  - --path-check records filesystem capacity for named workload paths during --live-state\n",
        "  - --collect thermal enables built-in local sensors and nvidia-smi thermal providers when available\n",
        "  - --collect cuda-runtime enables the built-in fitctl.runtime.cuda state namespace\n",
        "  - --probe-path-links, --probe-path-link-pair, and --probe-path-health are opt-in ",
        "and must reference --path-check ids\n",
        "  - --thermal-provider-config adds exact-argv thermal providers to the live state artifact\n",
        "  - --thermal-evidence supplies target-bound fitctl.thermal-evidence.v1 artifacts ",
        "for thermal requirements\n",
        "  - --max-state-age is not allowed with --live-state\n",
        "  - built-in extension packs are available for fitctl.runtime.cuda, fitctl.runtime.python, ",
        "and fitctl.runtime.node\n",
        "\nLegacy compatibility:\n",
        "  fitctl validate --mode <contract_only|state_aware> ",
        "[--state <path> | --live-state [--collect <thermal|memory-reliability|gpu-reliability|cuda-runtime|hardware-sensors> ...] [--path-check <id>=<path> ...] ",
        "[--probe-path-links <id> ...] [--probe-path-link-pair <from-id>:<to-id> ...] ",
        "[--probe-path-health <id> ...] [--thermal-provider-config <path> ...] ",
        "[--extension-pack <path> ...] [--enable-extension <namespace> ...]] ",
        "[--state-out <path>] [--validation-out <path>] [--max-state-age <value>] ",
        "[--validated-at <timestamp>] [--note <text>] [--fail-on-unfit | --require-fit]\n",
    )
}

fn parse_path_check(value: &str) -> Result<StatePathCheckRequestV1, &'static str> {
    let Some((path_id, path)) = value.split_once('=') else {
        return Err("--path-check must use <id>=<path>");
    };
    let path_id = path_id.trim();
    if path_id.is_empty() || path_id.contains(char::is_whitespace) {
        return Err("--path-check id must be non-empty and contain no whitespace");
    }
    if path.trim().is_empty() {
        return Err("--path-check path must be non-empty");
    }
    Ok(StatePathCheckRequestV1 {
        path_id: path_id.to_string(),
        path: PathBuf::from(path),
        probe_links: false,
        probe_health: false,
    })
}

fn parse_path_link_pair_probe(
    value: &str,
) -> Result<StatePathLinkPairProbeRequestV1, &'static str> {
    let Some((from_path_id, to_path_id)) = value.split_once(':') else {
        return Err("--probe-path-link-pair must use <from-id>:<to-id>");
    };
    let from_path_id = from_path_id.trim();
    let to_path_id = to_path_id.trim();
    if from_path_id.is_empty()
        || to_path_id.is_empty()
        || from_path_id.contains(char::is_whitespace)
        || to_path_id.contains(char::is_whitespace)
        || from_path_id == to_path_id
    {
        return Err(
            "--probe-path-link-pair ids must be non-empty, distinct, and contain no whitespace",
        );
    }
    Ok(StatePathLinkPairProbeRequestV1 {
        from_path_id: from_path_id.to_string(),
        to_path_id: to_path_id.to_string(),
    })
}

fn apply_link_probe_selection(
    path_checks: &mut [StatePathCheckRequestV1],
    link_probe_path_ids: &[String],
) -> Result<(), String> {
    for path_id in link_probe_path_ids {
        let Some(path_check) = path_checks
            .iter_mut()
            .find(|candidate| candidate.path_id == *path_id)
        else {
            return Err(format!(
                "--probe-path-links id {path_id} does not match any --path-check id"
            ));
        };
        path_check.probe_links = true;
    }
    Ok(())
}

fn apply_health_probe_selection(
    path_checks: &mut [StatePathCheckRequestV1],
    health_probe_path_ids: &[String],
) -> Result<(), String> {
    for path_id in health_probe_path_ids {
        let Some(path_check) = path_checks
            .iter_mut()
            .find(|candidate| candidate.path_id == *path_id)
        else {
            return Err(format!(
                "--probe-path-health id {path_id} does not match any --path-check id"
            ));
        };
        path_check.probe_health = true;
    }
    Ok(())
}

fn validate_link_pair_probe_selection(
    path_checks: &[StatePathCheckRequestV1],
    pair_requests: &[StatePathLinkPairProbeRequestV1],
) -> Result<(), String> {
    let mut seen = std::collections::BTreeSet::new();
    for pair in pair_requests {
        for path_id in [&pair.from_path_id, &pair.to_path_id] {
            if !path_checks
                .iter()
                .any(|candidate| candidate.path_id == *path_id)
            {
                return Err(format!(
                    "--probe-path-link-pair id {path_id} does not match any --path-check id"
                ));
            }
        }
        if !seen.insert((pair.from_path_id.clone(), pair.to_path_id.clone())) {
            return Err(format!(
                "--probe-path-link-pair {}:{} is duplicated",
                pair.from_path_id, pair.to_path_id
            ));
        }
    }
    Ok(())
}

fn write_pretty_json<T: serde::Serialize>(
    path: &Path,
    value: &T,
) -> Result<(), Box<dyn std::error::Error>> {
    let text = serde_json::to_string_pretty(value)?;
    fs::write(path, text.as_bytes())?;
    Ok(())
}

fn current_epoch_marker() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("unix:{seconds}")
}

fn parse_primary_validation_mode(value: &str) -> Result<ValidationModeV1, String> {
    match value {
        "contract_only" => Ok(ValidationModeV1::ContractOnly),
        "state_advisory" => Ok(ValidationModeV1::StateAdvisory),
        "state_required" => Ok(ValidationModeV1::StateRequired),
        unknown => Err(format!("unsupported validation mode '{unknown}'")),
    }
}

fn parse_legacy_mode_alias(value: &str) -> Result<ValidationModeV1, String> {
    match value {
        "contract_only" => Ok(ValidationModeV1::ContractOnly),
        "state_aware" => Ok(ValidationModeV1::StateAware),
        unknown => Err(format!("unsupported legacy validation mode '{unknown}'")),
    }
}

fn parse_max_state_age_seconds(value: &str) -> Result<u64, String> {
    if value.trim().is_empty() {
        return Err("max-state-age must be a non-blank duration value".to_string());
    }

    let (digits, multiplier) = match value.chars().last() {
        Some('s') => (&value[..value.len() - 1], 1_u64),
        Some('m') => (&value[..value.len() - 1], 60_u64),
        Some('h') => (&value[..value.len() - 1], 3_600_u64),
        Some(last) if last.is_ascii_digit() => (value, 1_u64),
        _ => {
            return Err(format!(
                "max-state-age '{value}' must use seconds, minutes, or hours"
            ));
        }
    };

    let scalar = digits
        .parse::<u64>()
        .map_err(|_| format!("max-state-age '{value}' is not a valid duration"))?;
    scalar
        .checked_mul(multiplier)
        .ok_or_else(|| format!("max-state-age '{value}' overflows the supported range"))
}

fn config_bundle_requests_extension_support(
    bundle: &fitctl_core::artifacts::config_bundle_v1::ConfigBundleV1,
) -> bool {
    !bundle
        .config_bundle
        .resolved_config
        .configured_extension_pack_ids
        .is_empty()
        || !bundle
            .config_bundle
            .resolved_config
            .enabled_extension_namespaces
            .is_empty()
}

enum ValidationModeSourceV1 {
    Default,
    Primary,
    Legacy,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ValidationGatePolicyV1 {
    ReportOnly,
    FailOnUnfit,
    RequireFit,
}

impl ValidationGatePolicyV1 {
    fn accepts(self, verdict: ValidationVerdictV1) -> bool {
        match self {
            Self::ReportOnly => true,
            Self::FailOnUnfit => matches!(
                verdict,
                ValidationVerdictV1::Fit | ValidationVerdictV1::FitWithDegradation
            ),
            Self::RequireFit => matches!(verdict, ValidationVerdictV1::Fit),
        }
    }

    fn flag_name(self) -> Option<&'static str> {
        match self {
            Self::ReportOnly => None,
            Self::FailOnUnfit => Some("--fail-on-unfit"),
            Self::RequireFit => Some("--require-fit"),
        }
    }

    fn exit_code(self, verdict: ValidationVerdictV1) -> ExitCode {
        if self.accepts(verdict) {
            return ExitCode::SUCCESS;
        }

        let flag = self
            .flag_name()
            .expect("only explicit gate policies can reject a verdict");
        eprintln!(
            "fitctl validate: verdict '{}' rejected by {flag}",
            verdict.as_str()
        );
        ExitCode::from(fitctl_core::EXIT_CODE_POLICY_REJECTION)
    }
}

fn resolve_inline_live_state_mode_v1() -> StateModeV1 {
    StateModeV1::Live
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_on_unfit_accepts_fit_and_degraded_only() {
        let policy = ValidationGatePolicyV1::FailOnUnfit;

        assert!(policy.accepts(ValidationVerdictV1::Fit));
        assert!(policy.accepts(ValidationVerdictV1::FitWithDegradation));
        assert!(!policy.accepts(ValidationVerdictV1::Unfit));
        assert!(!policy.accepts(ValidationVerdictV1::Indeterminate));
    }

    #[test]
    fn require_fit_accepts_only_fit() {
        let policy = ValidationGatePolicyV1::RequireFit;

        assert!(policy.accepts(ValidationVerdictV1::Fit));
        assert!(!policy.accepts(ValidationVerdictV1::FitWithDegradation));
        assert!(!policy.accepts(ValidationVerdictV1::Unfit));
        assert!(!policy.accepts(ValidationVerdictV1::Indeterminate));
    }
}
