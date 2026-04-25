// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Policy-shaped host-contract derivation.
//!
//! This module converts validated survey evidence into a reusable host promise. It deliberately
//! excludes live runtime state so the contract remains a stable host-side claim rather than a
//! snapshot of current conditions.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde_json::Value;

use crate::artifacts::contract_v1::HostContractV1;
use crate::artifacts::envelope_v1::{local_artifact_provenance_v1, ArtifactEnvelopeV1};
use crate::artifacts::schema_ids_v1::{HOST_CONTRACT_SCHEMA_ID, TOP_LEVEL_ARTIFACT_SCHEMA_VERSION};
use crate::artifacts::survey_v1::{decode_host_survey_payload, HostSurveyPayloadV1, HostSurveyV1};
use crate::artifacts::validation_v1::{validate_host_contract, validate_host_survey};
use crate::contract::contract_basis_v1::{build_contract_basis_v1, DerivationContextV1};
use crate::contract::payload_v1::{
    ContractAcceleratorSummaryV1, ContractNetworkOperabilityV1, ContractNetworkSummaryV1,
    ContractStorageOperabilityV1, ContractStorageSummaryV1, ContractTopologySummaryV1,
    ExecutionConstraintsV1, HostContractCoreV1, HostContractPayloadV1,
};
use crate::contract::{ContractDerivationError, ContractDerivationErrorCode};
use crate::extensions::{
    derive_cuda_runtime_contract_value_from_survey_v1,
    derive_node_runtime_contract_value_from_survey_v1,
    derive_python_runtime_contract_value_from_survey_v1, CUDA_RUNTIME_NAMESPACE,
    NODE_RUNTIME_NAMESPACE, PYTHON_RUNTIME_NAMESPACE,
};
use crate::policy::capability_classes_v1::{
    classify_policy_scoped_accelerator_inventory, derive_policy_shaped_capability_claim,
    policy_scoped_accelerator_inventory_is_active, SurveyCapabilityInputV1,
};
use crate::policy::explanation_v1::validate_explanation_links;
use crate::policy::{merge_policy_document_v1, PolicyDocumentV1};
use crate::survey::{
    AcceleratorDetailsV1, AcceleratorIntegrationV1, AcceleratorKindV1, AcceleratorOperabilityV1,
    NetworkDetailsV1, NetworkInterfaceKindV1, NetworkInterfaceVirtualityV1, ObservationStateV1,
    StaticOperabilityV1, StorageBlockDeviceClassV1, StorageDetailsV1, StorageMountRoleV1,
    SurveyFieldV1,
};

#[derive(Debug, Clone, PartialEq)]
pub struct ContractDerivationRequestV1 {
    pub survey: HostSurveyV1,
    pub policy: PolicyDocumentV1,
    pub live_state: Option<Value>,
    pub derivation_context: DerivationContextV1,
}

pub fn derive_host_contract_v1(
    request: ContractDerivationRequestV1,
) -> Result<HostContractV1, ContractDerivationError> {
    // Contract derivation is intentionally pure over survey + policy. Runtime-sensitive checks
    // belong in validation with optional host-state input, not in the host promise itself.
    if request.live_state.is_some() {
        return Err(ContractDerivationError::new(
            ContractDerivationErrorCode::ContractDerivationFailed,
            "contract_emit",
            "canonical host-contract derivation must not consume live state",
        ));
    }

    validate_host_survey(&request.survey).map_err(|error| {
        ContractDerivationError::new(
            ContractDerivationErrorCode::ContractDerivationFailed,
            "capability_classify",
            error.message,
        )
    })?;

    let survey_payload: HostSurveyPayloadV1 = decode_host_survey_payload(&request.survey.survey)
        .map_err(|error| {
            ContractDerivationError::new(
                ContractDerivationErrorCode::ContractDerivationFailed,
                "capability_classify",
                format!("failed to decode host survey payload: {error}"),
            )
        })?;

    let effective_policy = merge_policy_document_v1(&request.policy)?;
    let claim = derive_policy_shaped_capability_claim(
        &SurveyCapabilityInputV1 {
            visibility_scope: survey_payload
                .core_evidence
                .execution_context
                .visibility_scope
                .clone(),
            cpu: survey_payload.core_evidence.observations.cpu.clone(),
            memory: survey_payload.core_evidence.observations.memory.clone(),
            network: survey_payload.core_evidence.observations.network.clone(),
            accelerators: survey_payload
                .core_evidence
                .observations
                .accelerators
                .clone(),
        },
        &effective_policy,
    )?;
    validate_explanation_links(&claim.rule_ids, &claim.evidence_refs)?;

    let contract_basis = build_contract_basis_v1(
        &request.survey,
        &effective_policy,
        &request.derivation_context,
    )?;

    let mut capability_classes = BTreeMap::new();
    capability_classes.insert(effective_policy.capability_class.clone(), claim);

    let mut extension_contract = BTreeMap::new();
    // Extension contract fragments are derived after the core claim so optional namespaces do not
    // obscure the host's base contract semantics.
    if let Some(python_runtime_contract) =
        derive_python_runtime_contract_value_from_survey_v1(&request.survey).map_err(|error| {
            ContractDerivationError::new(
                ContractDerivationErrorCode::ContractDerivationFailed,
                "python_extension_contract_derive",
                error.message,
            )
        })?
    {
        extension_contract.insert(
            PYTHON_RUNTIME_NAMESPACE.to_string(),
            python_runtime_contract,
        );
    }
    if let Some(node_runtime_contract) =
        derive_node_runtime_contract_value_from_survey_v1(&request.survey).map_err(|error| {
            ContractDerivationError::new(
                ContractDerivationErrorCode::ContractDerivationFailed,
                "node_extension_contract_derive",
                error.message,
            )
        })?
    {
        extension_contract.insert(NODE_RUNTIME_NAMESPACE.to_string(), node_runtime_contract);
    }
    if let Some(cuda_runtime_contract) =
        derive_cuda_runtime_contract_value_from_survey_v1(&request.survey).map_err(|error| {
            ContractDerivationError::new(
                ContractDerivationErrorCode::ContractDerivationFailed,
                "cuda_extension_contract_derive",
                error.message,
            )
        })?
    {
        extension_contract.insert(CUDA_RUNTIME_NAMESPACE.to_string(), cuda_runtime_contract);
    }

    let contract = serde_json::to_value(HostContractPayloadV1 {
        core_contract: HostContractCoreV1 {
            capability_classes,
            execution_constraints: ExecutionConstraintsV1 {
                visibility_scope: survey_payload
                    .core_evidence
                    .execution_context
                    .visibility_scope,
                container_runtime: survey_payload
                    .core_evidence
                    .execution_context
                    .container_runtime,
            },
            identity_summary: survey_payload.core_evidence.identity_summary,
            network_summary: derive_network_summary(
                survey_payload
                    .core_evidence
                    .observations
                    .network
                    .value
                    .as_ref(),
            ),
            storage_summary: derive_storage_summary(
                survey_payload
                    .core_evidence
                    .observations
                    .storage
                    .value
                    .as_ref(),
            ),
            accelerator_summary: derive_accelerator_summary(
                &survey_payload.core_evidence.observations.accelerators,
                &effective_policy,
            ),
            topology_summary: ContractTopologySummaryV1 {
                numa_nodes: survey_payload
                    .core_evidence
                    .observations
                    .topology
                    .value
                    .as_ref()
                    .map(|value| value.numa_nodes),
                cpu_packages: survey_payload
                    .core_evidence
                    .observations
                    .topology
                    .value
                    .as_ref()
                    .map(|value| value.cpu_packages),
            },
        },
        extension_contract,
    })
    .map_err(|error| {
        ContractDerivationError::new(
            ContractDerivationErrorCode::ContractDerivationFailed,
            "contract_emit",
            format!("failed to encode host contract payload: {error}"),
        )
    })?;

    let artifact_id =
        build_contract_artifact_id(&survey_payload.snapshot_id, &request.policy.policy_id);
    let contract_short_display_name = request
        .policy
        .short_display_name
        .clone()
        .or_else(|| request.policy.display_name.clone());
    let contract_display_name = request
        .policy
        .display_name
        .clone()
        .or_else(|| request.policy.short_display_name.clone())
        .map(|policy_label| format!("{} / {}", survey_payload.host_alias, policy_label));
    let artifact = HostContractV1 {
        envelope: ArtifactEnvelopeV1 {
            schema_id: HOST_CONTRACT_SCHEMA_ID.to_string(),
            schema_version: TOP_LEVEL_ARTIFACT_SCHEMA_VERSION,
            artifact_id: artifact_id.clone(),
            provenance: local_artifact_provenance_v1(
                format!("policy:{}", request.policy.policy_id),
                request.derivation_context.derived_at.clone(),
                "contract",
                artifact_id,
            ),
            redaction: None,
            signatures: vec![],
        },
        host_alias: Some(survey_payload.host_alias.clone()),
        display_name: contract_display_name,
        short_display_name: contract_short_display_name,
        contract_basis,
        contract,
    };

    validate_host_contract(&artifact).map_err(|error| {
        ContractDerivationError::new(
            ContractDerivationErrorCode::ContractDerivationFailed,
            "contract_emit",
            error.message,
        )
    })?;

    Ok(artifact)
}

pub fn load_host_contract_artifact_from_path(
    path: &Path,
) -> Result<HostContractV1, ContractDerivationError> {
    let text = fs::read_to_string(path).map_err(|error| {
        ContractDerivationError::new(
            ContractDerivationErrorCode::ContractDerivationFailed,
            "contract_load",
            format!(
                "failed to read contract artifact {}: {error}",
                path.display()
            ),
        )
    })?;
    let contract: HostContractV1 = serde_json::from_str(&text).map_err(|error| {
        ContractDerivationError::new(
            ContractDerivationErrorCode::ContractDerivationFailed,
            "contract_load",
            format!(
                "failed to decode contract artifact {}: {error}",
                path.display()
            ),
        )
    })?;

    validate_host_contract(&contract).map_err(|error| {
        ContractDerivationError::new(
            ContractDerivationErrorCode::ContractDerivationFailed,
            "contract_load",
            error.message,
        )
    })?;

    Ok(contract)
}

fn derive_network_summary(network: Option<&NetworkDetailsV1>) -> ContractNetworkSummaryV1 {
    // Contract summaries intentionally compress rich survey evidence into reusable validation
    // signals. They are not meant to preserve every per-interface detail.
    let Some(network) = network else {
        return ContractNetworkSummaryV1::default();
    };

    let total_interfaces = u32::try_from(network.interfaces.len()).ok();
    let non_loopback_interfaces = u32::try_from(
        network
            .interface_details
            .iter()
            .filter(|detail| detail.interface_kind != NetworkInterfaceKindV1::Loopback)
            .count(),
    )
    .ok();

    let mut interface_kinds = network
        .interface_details
        .iter()
        .map(|detail| detail.interface_kind)
        .collect::<Vec<_>>();
    interface_kinds.sort_by_key(|value| value.as_str());
    interface_kinds.dedup();

    let max_observed_speed_mbps = network
        .interface_details
        .iter()
        .filter(|detail| detail.interface_virtuality == NetworkInterfaceVirtualityV1::Physical)
        .filter_map(|detail| detail.speed_mbps)
        .max();

    ContractNetworkSummaryV1 {
        total_interfaces,
        non_loopback_interfaces,
        interface_kinds,
        max_observed_speed_mbps,
        operability: derive_network_operability(network),
    }
}

fn derive_network_operability(network: &NetworkDetailsV1) -> Option<ContractNetworkOperabilityV1> {
    // This is static operability, not runtime readiness. A visible physical interface with known
    // speed is enough for an operable result; missing speed evidence stays indeterminate.
    let physical_non_loopback_interfaces = u32::try_from(
        network
            .interface_details
            .iter()
            .filter(|detail| detail.interface_virtuality == NetworkInterfaceVirtualityV1::Physical)
            .filter(|detail| detail.interface_kind != NetworkInterfaceKindV1::Loopback)
            .count(),
    )
    .ok()?;
    let interfaces_with_known_speed = u32::try_from(
        network
            .interface_details
            .iter()
            .filter(|detail| detail.interface_virtuality == NetworkInterfaceVirtualityV1::Physical)
            .filter(|detail| detail.interface_kind != NetworkInterfaceKindV1::Loopback)
            .filter(|detail| detail.speed_mbps.is_some())
            .count(),
    )
    .ok()?;

    let static_operability = if physical_non_loopback_interfaces == 0 {
        StaticOperabilityV1::NotOperable
    } else if interfaces_with_known_speed > 0 {
        StaticOperabilityV1::Operable
    } else {
        StaticOperabilityV1::Indeterminate
    };

    Some(ContractNetworkOperabilityV1 {
        static_operability,
        physical_non_loopback_interfaces,
        interfaces_with_known_speed,
    })
}

fn derive_storage_summary(storage: Option<&StorageDetailsV1>) -> ContractStorageSummaryV1 {
    // Storage summary keeps only the structural signals later validation can consume directly:
    // counts, device classes, filesystem types, and coarse static operability.
    let Some(storage) = storage else {
        return ContractStorageSummaryV1::default();
    };

    let total_block_devices = u32::try_from(storage.block_devices.len()).ok();
    let total_mounts = u32::try_from(storage.mounts.len()).ok();

    let mut block_device_classes = storage
        .block_device_details
        .iter()
        .map(|detail| detail.class)
        .collect::<Vec<_>>();
    block_device_classes.sort_by_key(|class| class.as_str());
    block_device_classes.dedup();

    let mut filesystem_types = storage
        .mount_details
        .iter()
        .map(|detail| detail.filesystem_type.clone())
        .collect::<Vec<_>>();
    filesystem_types.sort();
    filesystem_types.dedup();

    ContractStorageSummaryV1 {
        total_block_devices,
        total_mounts,
        block_device_classes,
        filesystem_types,
        operability: derive_storage_operability(storage),
    }
}

fn derive_storage_operability(storage: &StorageDetailsV1) -> Option<ContractStorageOperabilityV1> {
    // Static storage operability asks only whether there is a plausible non-ephemeral device set
    // and an observed root mount. Deeper health and readiness belong to runtime state.
    let usable_block_devices = u32::try_from(
        storage
            .block_device_details
            .iter()
            .filter(|detail| {
                !matches!(
                    detail.class,
                    StorageBlockDeviceClassV1::Loop | StorageBlockDeviceClassV1::Ram
                )
            })
            .count(),
    )
    .ok()?;
    let root_mount_present = storage
        .mount_details
        .iter()
        .any(|detail| detail.role == StorageMountRoleV1::Root);

    let static_operability = if usable_block_devices == 0 {
        StaticOperabilityV1::NotOperable
    } else if root_mount_present {
        StaticOperabilityV1::Operable
    } else {
        StaticOperabilityV1::Indeterminate
    };

    Some(ContractStorageOperabilityV1 {
        static_operability,
        usable_block_devices,
        root_mount_present,
    })
}

fn derive_accelerator_summary(
    accelerator_field: &SurveyFieldV1<AcceleratorDetailsV1>,
    effective_policy: &crate::policy::EffectivePolicyV1,
) -> ContractAcceleratorSummaryV1 {
    // Accept both observed and partially observed survey data so thin accelerator evidence can
    // still inform conservative capability claims.
    let accelerators = match (&accelerator_field.state, &accelerator_field.value) {
        (ObservationStateV1::Observed, Some(accelerators))
        | (ObservationStateV1::PartiallyObserved, Some(accelerators)) => accelerators,
        _ => return ContractAcceleratorSummaryV1::default(),
    };

    let total_accelerators = u32::try_from(accelerators.devices.len()).ok();
    let gpu_accelerators = u32::try_from(
        accelerators
            .devices
            .iter()
            .filter(|device| device.kind == AcceleratorKindV1::Gpu)
            .count(),
    )
    .ok();

    let mut accelerator_kinds = accelerators
        .devices
        .iter()
        .map(|device| device.kind)
        .collect::<Vec<_>>();
    accelerator_kinds.sort_by_key(|kind| kind.as_str());
    accelerator_kinds.dedup();

    let mut vendors = accelerators
        .devices
        .iter()
        .filter_map(|device| device.vendor.clone())
        .collect::<Vec<_>>();
    vendors.sort();
    vendors.dedup();

    let mut families = accelerators
        .devices
        .iter()
        .filter_map(|device| device.family.clone())
        .collect::<Vec<_>>();
    families.sort();
    families.dedup();

    let mut models = accelerators
        .devices
        .iter()
        .filter_map(|device| device.model.clone())
        .collect::<Vec<_>>();
    models.sort();
    models.dedup();

    let integrated_accelerators = if accelerators
        .devices
        .iter()
        .all(|device| device.integration.is_some())
    {
        u32::try_from(
            accelerators
                .devices
                .iter()
                .filter(|device| device.integration == Some(AcceleratorIntegrationV1::Integrated))
                .count(),
        )
        .ok()
    } else {
        None
    };
    let accelerators_with_known_memory = u32::try_from(
        accelerators
            .devices
            .iter()
            .filter(|device| device.memory_bytes.is_some())
            .count(),
    )
    .ok()
    .filter(|count| *count > 0);
    let accelerators_with_known_numa_node = u32::try_from(
        accelerators
            .devices
            .iter()
            .filter(|device| device.numa_node.is_some())
            .count(),
    )
    .ok()
    .filter(|count| *count > 0);
    let accelerator_numa_nodes = accelerators
        .devices
        .iter()
        .filter_map(|device| device.numa_node)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let max_memory_bytes = accelerators
        .devices
        .iter()
        .filter_map(|device| device.memory_bytes)
        .max();
    let full_inventory_complete = Some(matches!(
        accelerator_field.state,
        ObservationStateV1::Observed
    ));
    let policy_scoped_inventory = if policy_scoped_accelerator_inventory_is_active(effective_policy)
    {
        classify_policy_scoped_accelerator_inventory(
            accelerator_field,
            accelerators,
            effective_policy,
        )
        .ok()
    } else {
        None
    };

    ContractAcceleratorSummaryV1 {
        total_accelerators,
        gpu_accelerators,
        full_inventory_complete,
        policy_scoped_confirmed_accelerators: policy_scoped_inventory
            .as_ref()
            .map(|inventory| inventory.policy_scoped_confirmed_accelerators),
        policy_scoped_unresolved_accelerators: policy_scoped_inventory
            .as_ref()
            .map(|inventory| inventory.policy_scoped_unresolved_accelerators),
        policy_scoped_inventory_complete: policy_scoped_inventory
            .as_ref()
            .map(|inventory| inventory.policy_scoped_inventory_complete),
        integrated_accelerators,
        accelerators_with_known_memory,
        accelerators_with_known_numa_node,
        max_memory_bytes,
        accelerator_numa_nodes,
        accelerator_kinds,
        vendors,
        families,
        models,
        operability: accelerators
            .operability
            .clone()
            .or_else(|| derive_fallback_accelerator_operability(accelerators)),
    }
}

fn derive_fallback_accelerator_operability(
    accelerators: &AcceleratorDetailsV1,
) -> Option<AcceleratorOperabilityV1> {
    // When survey collection did not populate explicit operability, only retain the clearly
    // broken no-driver case. Once visible-node access becomes part of the operability contract,
    // synthesizing an indeterminate value without node evidence would overstate what we know.
    if accelerators.devices.is_empty() {
        return None;
    }

    let driver_bound_devices = u32::try_from(
        accelerators
            .devices
            .iter()
            .filter(|device| device.driver.is_some())
            .count(),
    )
    .ok()?;
    if driver_bound_devices > 0 {
        return None;
    }

    Some(AcceleratorOperabilityV1 {
        static_operability: StaticOperabilityV1::NotOperable,
        driver_bound_devices,
        visible_device_nodes: Vec::new(),
        visible_render_nodes: Vec::new(),
    })
}

pub fn load_host_survey_artifact_from_path(
    path: &Path,
) -> Result<HostSurveyV1, ContractDerivationError> {
    let text = fs::read_to_string(path).map_err(|error| {
        ContractDerivationError::new(
            ContractDerivationErrorCode::ContractDerivationFailed,
            "survey_load",
            format!("failed to read survey artifact {}: {error}", path.display()),
        )
    })?;
    let survey: HostSurveyV1 = serde_json::from_str(&text).map_err(|error| {
        ContractDerivationError::new(
            ContractDerivationErrorCode::ContractDerivationFailed,
            "survey_load",
            format!(
                "failed to decode survey artifact {}: {error}",
                path.display()
            ),
        )
    })?;

    validate_host_survey(&survey).map_err(|error| {
        ContractDerivationError::new(
            ContractDerivationErrorCode::ContractDerivationFailed,
            "survey_load",
            error.message,
        )
    })?;

    Ok(survey)
}

fn sanitize_identifier(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len());

    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            sanitized.push(character.to_ascii_lowercase());
        } else {
            sanitized.push('-');
        }
    }

    sanitized.trim_matches('-').to_string()
}

fn build_contract_artifact_id(snapshot_id: &str, policy_id: &str) -> String {
    format!(
        "contract-{}-{}",
        sanitize_identifier(snapshot_id),
        sanitize_identifier(policy_id)
    )
}
