// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::PathBuf;

use fitctl_core::config::{
    build_extension_basis_v1, resolve_configuration_v1, ConfigErrorCode, DisabledExtensionReasonV1,
    ResolveConfigurationRequestV1,
};
use fitctl_core::contract::{
    derive_host_contract_v1, derive_host_contract_with_extensions_v1, ContractDerivationRequestV1,
    DerivationContextV1, HostContractPayloadV1,
};
use fitctl_core::extensions::apply_cuda_runtime_extension_to_survey_v1;
use fitctl_core::survey::{NoopLiveProbeV1, SurveyEngineV1, SurveyModeV1};
use serde_json::{json, Value};

use super::support::{context, pack, policy, Family, TestRoot};

fn request(
    policy: Value,
    packs: Vec<Value>,
    context: Value,
    disk: bool,
) -> ResolveConfigurationRequestV1 {
    let root = TestRoot::new();
    let load = |family: Family, raw: Value| {
        if disk {
            let path = root.path("input.json");
            fs::write(&path, serde_json::to_vec(&raw).unwrap()).unwrap();
            family.path(&path).unwrap()
        } else {
            family.value(raw).unwrap()
        }
    };
    ResolveConfigurationRequestV1 {
        policy: serde_json::from_value(load(Family::Policy, policy)).unwrap(),
        trust_policy: None,
        extension_packs: packs
            .into_iter()
            .map(|pack| serde_json::from_value(load(Family::Pack, pack)).unwrap())
            .collect(),
        recommendation_packs: vec![],
        invocation_context: Some(serde_json::from_value(load(Family::Context, context)).unwrap()),
        selected_policy_pack_id: None,
        selected_policy_entry_id: None,
        selected_policy_entry_source: None,
        selected_policy_pack_lock_id: None,
        selected_policy_pack_lock_signed: None,
        selected_service_profile_catalogue_id: None,
        selected_service_profile_entry_id: None,
        selected_service_profile_entry_source: None,
    }
}

#[test]
fn supplied_inputs_resolve_basis_and_derive() {
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    let survey = SurveyEngineV1::new(NoopLiveProbeV1)
        .collect_host_survey(SurveyModeV1::Replay {
            fixtures_root: fixtures.join("host_survey"),
            fixture_id: "linux-gpu-workstation-like-v1".to_string(),
        })
        .unwrap();
    for (enabled, allowed, has_evidence, disabled_reason) in [
        (true, true, true, None),
        (true, true, false, None),
        (
            false,
            true,
            true,
            Some(DisabledExtensionReasonV1::InvocationNotEnabled),
        ),
        (
            false,
            false,
            true,
            Some(DisabledExtensionReasonV1::PolicyDisallowed),
        ),
    ] {
        let survey = if has_evidence {
            apply_cuda_runtime_extension_to_survey_v1(
                survey.clone(),
                Some(&fixtures.join("extensions/cuda_runtime")),
            )
            .unwrap()
        } else {
            survey.clone()
        };
        let mut policy = policy();
        let mut context = context();
        if !allowed {
            policy["extension_policy"]["allowed_extension_namespaces"] = json!([]);
        }
        if enabled {
            context["enabled_extension_namespaces"] = json!(["fitctl.runtime.cuda"]);
        }
        let memory = request(policy.clone(), vec![pack()], context.clone(), false);
        let disk = request(policy, vec![pack()], context, true);
        let packs = memory.extension_packs.clone();
        let policy = memory.policy.clone();
        let disk_packs = disk.extension_packs.clone();
        let disk_policy = disk.policy.clone();
        let resolved = resolve_configuration_v1(memory).unwrap();
        let disk_resolved = resolve_configuration_v1(disk).unwrap();
        assert_eq!(resolved, disk_resolved);
        if let Some(reason) = disabled_reason {
            assert_eq!(resolved.disabled_extension_namespaces.len(), 1);
            assert_eq!(resolved.disabled_extension_namespaces[0].reason, reason);
        } else {
            assert_eq!(
                resolved.enabled_extension_namespaces,
                ["fitctl.runtime.cuda"]
            );
        }
        let basis = build_extension_basis_v1(&resolved, &packs).unwrap();
        let disk_basis = build_extension_basis_v1(&disk_resolved, &disk_packs).unwrap();
        assert_eq!(basis, disk_basis);
        let derivation = ContractDerivationRequestV1 {
            survey,
            policy,
            live_state: None,
            derivation_context: DerivationContextV1 {
                derived_at: "2025-04-21T14:37:19Z".to_string(),
                notes: None,
            },
        };
        let baseline = derive_host_contract_v1(derivation.clone()).unwrap();
        let disk_derivation = ContractDerivationRequestV1 {
            policy: disk_policy,
            ..derivation.clone()
        };
        match basis {
            Some(basis) => {
                assert_eq!(basis.enabled_extension_namespaces, ["fitctl.runtime.cuda"]);
                assert_eq!(basis.extension_semantic_hashes.len(), 1);
                let contract = derive_host_contract_with_extensions_v1(derivation, basis).unwrap();
                let disk_contract =
                    derive_host_contract_with_extensions_v1(disk_derivation, disk_basis.unwrap())
                        .unwrap();
                assert_eq!(contract, disk_contract);
                assert_eq!(
                    contract.contract_basis.core_semantic_basis,
                    baseline.contract_basis.core_semantic_basis
                );
                assert!(contract.contract_basis.extension_basis.is_some());
                let payload: HostContractPayloadV1 =
                    serde_json::from_value(contract.contract).unwrap();
                // Activation alone does not manufacture missing survey evidence.
                assert_eq!(
                    payload
                        .extension_contract
                        .contains_key("fitctl.runtime.cuda"),
                    has_evidence
                );
            }
            None => {
                assert!(!enabled);
                assert_eq!(baseline, derive_host_contract_v1(disk_derivation).unwrap());
                let payload: HostContractPayloadV1 =
                    serde_json::from_value(baseline.contract).unwrap();
                assert!(payload.extension_contract.is_empty());
            }
        }
    }
}

#[test]
fn resolution_conflicts_keep_error_identity() {
    for case in [
        "duplicate pack",
        "duplicate namespace",
        "unavailable",
        "disallowed",
    ] {
        let mut policy = policy();
        let mut packs = vec![pack()];
        let mut context = context();
        match case {
            "duplicate pack" => packs.push(pack()),
            "duplicate namespace" => {
                let mut other = pack();
                other["pack_id"] = json!("other");
                packs.push(other);
            }
            "unavailable" => {
                context["enabled_extension_namespaces"] = json!(["fitctl.runtime.python"])
            }
            "disallowed" => {
                policy["extension_policy"]["allowed_extension_namespaces"] = json!([]);
                context["enabled_extension_namespaces"] = json!(["fitctl.runtime.cuda"]);
            }
            _ => unreachable!(),
        }
        let memory = resolve_configuration_v1(request(
            policy.clone(),
            packs.clone(),
            context.clone(),
            false,
        ))
        .unwrap_err();
        let disk = resolve_configuration_v1(request(policy, packs, context, true)).unwrap_err();
        assert_eq!(memory, disk, "{case}");
        assert_eq!(memory.code, ConfigErrorCode::ConfigResolveConflict);
        assert_eq!(memory.checkpoint_id, "config_resolve");
        assert_eq!(memory.error_model_id, "fitctl.config.v1");
        assert_eq!(memory.error_model_version, 1);
    }
}
