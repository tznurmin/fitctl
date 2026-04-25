// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Derivation of coarse capability classes from survey evidence under effective policy.

use serde::{Deserialize, Serialize};

use crate::artifacts::metadata_v1::{AssuranceSourceV1, ClaimMetadataV1, DerivationStageV1};
use crate::contract::{ContractDerivationError, ContractDerivationErrorCode};
use crate::policy::{EffectivePolicyV1, PolicyScopedAcceleratorInventoryModeV1};
use crate::survey::execution_context_v1::{ObservationStateV1, VisibilityScopeV1};
use crate::survey::live_v1::{
    AcceleratorDetailsV1, AcceleratorDeviceV1, AcceleratorKindV1, CpuDetailsV1, MemoryDetailsV1,
    NetworkDetailsV1, SurveyFieldV1,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedCapabilityClaimV1 {
    pub admissible: bool,
    pub rule_ids: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub summary: String,
    #[serde(default)]
    pub claim_metadata: ClaimMetadataV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurveyCapabilityInputV1 {
    pub visibility_scope: VisibilityScopeV1,
    pub cpu: SurveyFieldV1<CpuDetailsV1>,
    pub memory: SurveyFieldV1<MemoryDetailsV1>,
    pub network: SurveyFieldV1<NetworkDetailsV1>,
    pub accelerators: SurveyFieldV1<AcceleratorDetailsV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyScopedAcceleratorInventoryV1 {
    pub full_inventory_complete: bool,
    pub policy_scoped_confirmed_accelerators: u32,
    pub policy_scoped_unresolved_accelerators: u32,
    pub policy_scoped_inventory_complete: bool,
    pub visible_confirmed_accelerators: u32,
}

fn effective_policy_scoped_inventory_mode(
    effective_policy: &EffectivePolicyV1,
) -> PolicyScopedAcceleratorInventoryModeV1 {
    effective_policy
        .policy_scoped_accelerator_inventory_mode
        .unwrap_or(PolicyScopedAcceleratorInventoryModeV1::ConfirmedSubsetSufficient)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScopedAcceleratorMatchV1 {
    ConfirmedInScope,
    ResolvedOutOfScope,
    UnresolvedInScopeCandidate,
}

pub fn derive_policy_shaped_capability_claim(
    survey: &SurveyCapabilityInputV1,
    effective_policy: &EffectivePolicyV1,
) -> Result<DerivedCapabilityClaimV1, ContractDerivationError> {
    let cpu =
        extract_required_observed_value(&survey.cpu, "$.survey.core_evidence.observations.cpu")?;
    let memory = extract_required_observed_value(
        &survey.memory,
        "$.survey.core_evidence.observations.memory",
    )?;

    let mut admissible = true;
    let mut summary_parts = Vec::new();
    let accelerator_details = if policy_scoped_accelerator_inventory_is_active(effective_policy) {
        Some(extract_required_accelerator_value(
            &survey.accelerators,
            "$.survey.core_evidence.observations.accelerators",
        )?)
    } else {
        None
    };
    let policy_scoped_inventory = accelerator_details
        .as_ref()
        .map(|details| {
            classify_policy_scoped_accelerator_inventory(
                &survey.accelerators,
                details,
                effective_policy,
            )
        })
        .transpose()?;

    if survey.visibility_scope == VisibilityScopeV1::ContainerRestricted
        && !effective_policy.allow_container_restricted
    {
        admissible = false;
        summary_parts.push("container-restricted execution is disallowed by policy".to_string());
    }

    if effective_policy.require_network_visibility {
        match survey.network.state {
            ObservationStateV1::Observed | ObservationStateV1::PartiallyObserved => {}
            _ => {
                admissible = false;
                summary_parts.push("network visibility is required by policy".to_string());
            }
        }
    }

    if cpu.logical_cores < effective_policy.min_cpu_logical_cores {
        admissible = false;
        summary_parts.push(format!(
            "logical core count {} is below the policy floor {}",
            cpu.logical_cores, effective_policy.min_cpu_logical_cores
        ));
    }

    if memory.total_bytes < effective_policy.min_memory_bytes {
        admissible = false;
        summary_parts.push(format!(
            "memory total {} is below the policy floor {}",
            memory.total_bytes, effective_policy.min_memory_bytes
        ));
    }

    if let Some(required_kind) = effective_policy.required_accelerator_kind {
        let matching_devices = policy_scoped_inventory
            .as_ref()
            .map(|inventory| inventory.visible_confirmed_accelerators)
            .unwrap_or_default();
        if matching_devices == 0 {
            admissible = false;
            summary_parts.push(no_visible_required_accelerator_summary(
                accelerator_details.as_ref(),
                required_kind,
                policy_scoped_inventory.as_ref(),
            ));
        }
    }

    if let Some(min_accelerator_devices) = effective_policy.min_accelerator_devices {
        let visible_devices = policy_scoped_inventory
            .as_ref()
            .map(|inventory| inventory.visible_confirmed_accelerators)
            .unwrap_or_default();
        if visible_devices < min_accelerator_devices {
            admissible = false;
            summary_parts.push(visible_accelerator_count_summary(
                accelerator_details.as_ref(),
                visible_devices,
                min_accelerator_devices,
                policy_scoped_inventory.as_ref(),
            ));
        }
    }

    if admissible
        && matches!(
            effective_policy_scoped_inventory_mode(effective_policy),
            PolicyScopedAcceleratorInventoryModeV1::CompleteRequired
        )
        && policy_scoped_inventory
            .as_ref()
            .is_some_and(|inventory| !inventory.policy_scoped_inventory_complete)
    {
        admissible = false;
        summary_parts.push(strict_policy_scoped_inventory_incomplete_summary(
            policy_scoped_inventory.as_ref(),
        ));
    }

    if summary_parts.is_empty() {
        summary_parts.push(format!(
            "host satisfies the {} capability baseline",
            effective_policy.capability_class
        ));
    }

    let mut evidence_refs = vec![
        "$.survey.core_evidence.observations.cpu".to_string(),
        "$.survey.core_evidence.observations.memory".to_string(),
        "$.survey.core_evidence.execution_context".to_string(),
    ];
    if effective_policy.require_network_visibility {
        evidence_refs.push("$.survey.core_evidence.observations.network".to_string());
    }
    if accelerator_details.is_some() {
        evidence_refs.push("$.survey.core_evidence.observations.accelerators".to_string());
    }

    let mut source_collectors = vec![
        "procfs".to_string(),
        "sysfs".to_string(),
        "cgroupfs".to_string(),
        "mountinfo".to_string(),
        "netdev".to_string(),
        "block_and_filesystem".to_string(),
    ];
    if accelerator_details.is_some() {
        source_collectors.push("pci_accelerators".to_string());
    }

    let mut claim_metadata_evidence_paths = vec![
        "$.survey.core_evidence.observations.cpu".to_string(),
        "$.survey.core_evidence.observations.memory".to_string(),
        "$.survey.core_evidence.execution_context".to_string(),
    ];
    if effective_policy.require_network_visibility {
        claim_metadata_evidence_paths
            .push("$.survey.core_evidence.observations.network".to_string());
    }
    if accelerator_details.is_some() {
        claim_metadata_evidence_paths
            .push("$.survey.core_evidence.observations.accelerators".to_string());
    }

    Ok(DerivedCapabilityClaimV1 {
        admissible,
        rule_ids: effective_policy.selected_policy_layers.clone(),
        evidence_refs,
        summary: summary_parts.join("; "),
        claim_metadata: ClaimMetadataV1 {
            assurance_source: AssuranceSourceV1::SelfObserved,
            derivation_stage: DerivationStageV1::PolicyAsserted,
            source_collectors,
            evidence_paths: claim_metadata_evidence_paths,
            policy_rule_id: effective_policy.selected_policy_layers.last().cloned(),
            trust_evidence_refs: Vec::new(),
        },
    })
}

pub(crate) fn policy_scoped_accelerator_inventory_is_active(
    effective_policy: &EffectivePolicyV1,
) -> bool {
    effective_policy.required_accelerator_kind.is_some()
        || effective_policy.required_accelerator_vendor.is_some()
        || effective_policy.required_accelerator_integration.is_some()
        || effective_policy.min_accelerator_devices.is_some()
}

pub(crate) fn classify_policy_scoped_accelerator_inventory(
    field: &SurveyFieldV1<AcceleratorDetailsV1>,
    details: &AcceleratorDetailsV1,
    effective_policy: &EffectivePolicyV1,
) -> Result<PolicyScopedAcceleratorInventoryV1, ContractDerivationError> {
    let full_inventory_complete = matches!(field.state, ObservationStateV1::Observed);
    let mut confirmed = 0u32;
    let mut unresolved = 0u32;

    for device in &details.devices {
        match classify_accelerator_device_for_policy_scope(device, effective_policy) {
            ScopedAcceleratorMatchV1::ConfirmedInScope => confirmed += 1,
            ScopedAcceleratorMatchV1::ResolvedOutOfScope => {}
            ScopedAcceleratorMatchV1::UnresolvedInScopeCandidate => unresolved += 1,
        }
    }

    let visible_confirmed_accelerators = if has_no_visible_accelerator_nodes(details) {
        0
    } else {
        confirmed
    };

    Ok(PolicyScopedAcceleratorInventoryV1 {
        full_inventory_complete,
        policy_scoped_confirmed_accelerators: confirmed,
        policy_scoped_unresolved_accelerators: unresolved,
        policy_scoped_inventory_complete: unresolved == 0,
        visible_confirmed_accelerators,
    })
}

fn classify_accelerator_device_for_policy_scope(
    device: &AcceleratorDeviceV1,
    effective_policy: &EffectivePolicyV1,
) -> ScopedAcceleratorMatchV1 {
    if effective_policy
        .required_accelerator_kind
        .is_some_and(|required| device.kind != required)
    {
        return ScopedAcceleratorMatchV1::ResolvedOutOfScope;
    }

    let mut scope_resolution_incomplete = false;

    if let Some(required_vendor) = effective_policy.required_accelerator_vendor.as_ref() {
        match device.vendor.as_deref() {
            Some(vendor) if vendor.eq_ignore_ascii_case(required_vendor) => {}
            Some(_) => return ScopedAcceleratorMatchV1::ResolvedOutOfScope,
            None => scope_resolution_incomplete = true,
        }
    }

    if let Some(required_integration) = effective_policy.required_accelerator_integration {
        match device.integration {
            Some(integration) if integration == required_integration => {}
            Some(_) => return ScopedAcceleratorMatchV1::ResolvedOutOfScope,
            None => scope_resolution_incomplete = true,
        }
    }

    if scope_resolution_incomplete {
        ScopedAcceleratorMatchV1::UnresolvedInScopeCandidate
    } else {
        ScopedAcceleratorMatchV1::ConfirmedInScope
    }
}

fn has_no_visible_accelerator_nodes(details: &AcceleratorDetailsV1) -> bool {
    details
        .operability
        .as_ref()
        .is_some_and(|operability| operability.visible_device_nodes.is_empty())
}

fn no_visible_required_accelerator_summary(
    accelerator_details: Option<&AcceleratorDetailsV1>,
    required_kind: AcceleratorKindV1,
    policy_scoped_inventory: Option<&PolicyScopedAcceleratorInventoryV1>,
) -> String {
    if accelerator_details.is_some_and(|details| {
        !details.devices.is_empty() && has_no_visible_accelerator_nodes(details)
    }) {
        return format!(
            "{} hardware is present but no accelerator device nodes are visible under the current execution context",
            required_kind.as_str()
        );
    }

    if policy_scoped_inventory
        .is_some_and(|inventory| inventory.policy_scoped_unresolved_accelerators > 0)
    {
        return format!(
            "no confirmed {} accelerator matches the current policy scope; policy-scoped accelerator inventory is incomplete",
            required_kind.as_str()
        );
    }

    format!(
        "no {} accelerator is visible under the active policy",
        required_kind.as_str()
    )
}

fn visible_accelerator_count_summary(
    accelerator_details: Option<&AcceleratorDetailsV1>,
    visible_devices: u32,
    min_accelerator_devices: u32,
    policy_scoped_inventory: Option<&PolicyScopedAcceleratorInventoryV1>,
) -> String {
    if accelerator_details.is_some_and(|details| {
        !details.devices.is_empty() && has_no_visible_accelerator_nodes(details)
    }) {
        return format!(
            "accelerator hardware is present but no accelerator device nodes are visible under the current execution context; visible accelerator count 0 is below the policy floor {}",
            min_accelerator_devices
        );
    }

    if let Some(inventory) = policy_scoped_inventory {
        if inventory.policy_scoped_unresolved_accelerators > 0 {
            return format!(
                "confirmed in-scope accelerator count {} is below the policy floor {}; policy-scoped accelerator inventory is incomplete with {} unresolved candidate(s)",
                visible_devices,
                min_accelerator_devices,
                inventory.policy_scoped_unresolved_accelerators
            );
        }
    }

    format!(
        "confirmed in-scope accelerator count {} is below the policy floor {}",
        visible_devices, min_accelerator_devices
    )
}

fn strict_policy_scoped_inventory_incomplete_summary(
    policy_scoped_inventory: Option<&PolicyScopedAcceleratorInventoryV1>,
) -> String {
    let unresolved = policy_scoped_inventory
        .map(|inventory| inventory.policy_scoped_unresolved_accelerators)
        .unwrap_or_default();
    if unresolved > 0 {
        return format!(
            "policy-scoped accelerator inventory is incomplete under complete_required mode with {} unresolved in-scope candidate(s)",
            unresolved
        );
    }

    "policy-scoped accelerator inventory is incomplete under complete_required mode".to_string()
}

fn extract_required_observed_value<T: Clone>(
    field: &SurveyFieldV1<T>,
    evidence_ref: &str,
) -> Result<T, ContractDerivationError> {
    match (&field.state, &field.value) {
        (ObservationStateV1::Observed, Some(value))
        | (ObservationStateV1::PartiallyObserved, Some(value)) => Ok(value.clone()),
        _ => Err(ContractDerivationError::new(
            ContractDerivationErrorCode::CapabilityClassUnresolved,
            "capability_classify",
            format!("required evidence at {evidence_ref} is not concretely available"),
        )),
    }
}

fn extract_required_accelerator_value(
    field: &SurveyFieldV1<AcceleratorDetailsV1>,
    evidence_ref: &str,
) -> Result<AcceleratorDetailsV1, ContractDerivationError> {
    match (&field.state, &field.value) {
        (ObservationStateV1::Observed, Some(value))
        | (ObservationStateV1::PartiallyObserved, Some(value)) => Ok(value.clone()),
        (ObservationStateV1::PartiallyObserved, None)
        | (ObservationStateV1::Missing, _)
        | (ObservationStateV1::HiddenByPrivilegeOrVisibility, _)
        | (ObservationStateV1::Unknown, _)
        | (ObservationStateV1::NotApplicable, _) => Err(ContractDerivationError::new(
            ContractDerivationErrorCode::CapabilityClassUnresolved,
            "capability_classify",
            format!("required accelerator evidence at {evidence_ref} is not concretely available"),
        )),
        (ObservationStateV1::Observed, None) => Err(ContractDerivationError::new(
            ContractDerivationErrorCode::CapabilityClassUnresolved,
            "capability_classify",
            format!("required accelerator evidence at {evidence_ref} is not concretely available"),
        )),
    }
}
