// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Derivation of coarse capability classes from survey evidence under effective policy.

use serde::{Deserialize, Serialize};

use crate::artifacts::metadata_v1::{AssuranceSourceV1, ClaimMetadataV1, DerivationStageV1};
use crate::contract::{ContractDerivationError, ContractDerivationErrorCode};
use crate::policy::EffectivePolicyV1;
use crate::survey::execution_context_v1::{ObservationStateV1, VisibilityScopeV1};
use crate::survey::live_v1::{
    AcceleratorDetailsV1, CpuDetailsV1, MemoryDetailsV1, NetworkDetailsV1, SurveyFieldV1,
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
    let accelerator_details = if effective_policy.required_accelerator_kind.is_some()
        || effective_policy.min_accelerator_devices.is_some()
    {
        Some(extract_required_accelerator_value(
            &survey.accelerators,
            "$.survey.core_evidence.observations.accelerators",
        )?)
    } else {
        None
    };

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
        let matching_devices = accelerator_details
            .as_ref()
            .map(|details| {
                details
                    .devices
                    .iter()
                    .filter(|device| device.kind == required_kind)
                    .count()
            })
            .unwrap_or_default();
        if matching_devices == 0 {
            admissible = false;
            summary_parts.push(format!(
                "no {} accelerator is visible under the active policy",
                required_kind.as_str()
            ));
        }
    }

    if let Some(min_accelerator_devices) = effective_policy.min_accelerator_devices {
        let visible_devices = accelerator_details
            .as_ref()
            .map(|details| details.devices.len())
            .unwrap_or_default();
        if visible_devices < min_accelerator_devices as usize {
            admissible = false;
            summary_parts.push(format!(
                "visible accelerator count {} is below the policy floor {}",
                visible_devices, min_accelerator_devices
            ));
        }
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
        (ObservationStateV1::Observed, Some(value)) => Ok(value.clone()),
        (ObservationStateV1::PartiallyObserved, Some(_))
        | (ObservationStateV1::PartiallyObserved, None)
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
