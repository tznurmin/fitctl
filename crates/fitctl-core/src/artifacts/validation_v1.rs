// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Structural and semantic validation for all supported artifact families.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};

mod report_semantics;

use self::report_semantics::*;

use crate::artifacts::batch_classification_report_v1::BatchClassificationReportV1;
use crate::artifacts::config_bundle_v1::ConfigBundleV1;
use crate::artifacts::contract_v1::{ContractBasisV1, HostContractV1};
use crate::artifacts::decision_bundle_v1::DecisionBundleV1;
use crate::artifacts::envelope_v1::{
    ArtifactEnvelopeV1, ArtifactProvenanceV1, SignatureEnvelopeV1,
};
use crate::artifacts::metadata_v1::{
    ClaimMetadataV1, CollectorMetadataV1, IdentitySummaryV1, LocalStableAnchorFamilyV1,
    LocalStableAnchorSourceV1, LocalStableIdDegradedReasonV1, LocalStableStabilityClassV1,
};
use crate::artifacts::recommendation_report_v1::RecommendationReportV1;
use crate::artifacts::schema_ids_v1::{
    is_supported_batch_classification_report_schema_id, is_supported_core_schema_id,
    BATCH_CLASSIFICATION_REPORT_SCHEMA_ID, CONFIG_BUNDLE_SCHEMA_ID, DECISION_BUNDLE_SCHEMA_ID,
    HOST_CONTRACT_SCHEMA_ID, HOST_STATE_SCHEMA_ID, HOST_SURVEY_SCHEMA_ID,
    LEGACY_BATCH_CLASSIFICATION_REPORT_SCHEMA_ID, RECOMMENDATION_REPORT_SCHEMA_ID,
    SERVICE_PROFILE_SCHEMA_ID, TOP_LEVEL_ARTIFACT_SCHEMA_VERSION, VALIDATION_REPORT_SCHEMA_ID,
};
use crate::artifacts::semantic_hash_v1::{
    semantic_hash_hex_for_config_bundle, semantic_hash_hex_for_contract,
    semantic_hash_hex_for_recommendation_report, semantic_hash_hex_for_service_profile,
    semantic_hash_hex_for_state, semantic_hash_hex_for_validation_report,
};
use crate::artifacts::service_profile_v1::ServiceProfileV1;
use crate::artifacts::state_v1::{HostStateV1, StateFieldV1, StateLocalIdentityV1};
use crate::artifacts::survey_v1::{decode_host_survey_payload, HostSurveyV1};
use crate::artifacts::validation_report_v1::ValidationReportV1;
use crate::artifacts::validation_report_v1::{
    ValidationExplanationV1, ValidationModeV1, ValidationReasonCodeV1,
    ValidationRemediationActionV1, ValidationRemediationHintV1, ValidationReportPayloadV1,
    ValidationVerdictV1,
};
use crate::config::{semantic_hash_hex_for_resolved_config, validate_resolved_config};
use crate::contract::payload_v1::{
    ContractAcceleratorSummaryV1, ContractNetworkOperabilityV1, ContractNetworkSummaryV1,
    ContractStorageOperabilityV1, ContractStorageSummaryV1,
};
use crate::extensions::{
    decode_cuda_runtime_contract_from_value, decode_cuda_runtime_evidence_from_value,
    decode_cuda_runtime_requirement_from_value, decode_cuda_runtime_state_from_value,
    decode_cuda_runtime_validation_diagnostic_from_value, decode_node_runtime_contract_from_value,
    decode_node_runtime_evidence_from_value, decode_node_runtime_requirement_from_value,
    decode_python_runtime_contract_from_value, decode_python_runtime_evidence_from_value,
    decode_python_runtime_requirement_from_value, CUDA_RUNTIME_NAMESPACE, NODE_RUNTIME_NAMESPACE,
    PYTHON_RUNTIME_NAMESPACE,
};
use crate::policy::schema_v1::validate_policy_document;
use crate::survey::{
    validate_observation_field_coherence_v1, AcceleratorDetailsV1, AcceleratorDeviceV1,
    AcceleratorDiscoverySourceV1, AcceleratorKindV1, AcceleratorOperabilityV1, CpuCacheSummaryV1,
    CpuDetailsV1, IpAddressFamilyV1, MemoryDetailsV1, NetworkAddressV1,
    NetworkAddressabilitySummaryV1, NetworkDetailsV1, NetworkInterfaceV1, ObservationStateV1,
    StaticOperabilityV1, StorageBlockDeviceV1, StorageDetailsV1, StorageMountV1, SurveyFieldV1,
    TopologyDetailsV1,
};
use crate::verify::validate_trust_policy_document_v1;
use crate::verify::validate_verification_bundle_v1;

pub const ARTIFACT_ERROR_MODEL_ID: &str = "fitctl.artifact_contracts.v1";
pub const ARTIFACT_ERROR_MODEL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactValidationErrorCode {
    ArtifactSchemaIdInvalid,
    ArtifactSchemaVersionInvalid,
    ArtifactPayloadCorrupt,
    ContractBasisInvalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactValidationError {
    pub code: ArtifactValidationErrorCode,
    pub message: String,
    pub error_model_id: &'static str,
    pub error_model_version: u32,
}

impl ArtifactValidationError {
    pub(crate) fn new(code: ArtifactValidationErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            error_model_id: ARTIFACT_ERROR_MODEL_ID,
            error_model_version: ARTIFACT_ERROR_MODEL_VERSION,
        }
    }
}

/// Validate a host-survey artifact, including both envelope structure and nested domain payloads.
pub fn validate_host_survey(survey: &HostSurveyV1) -> Result<(), ArtifactValidationError> {
    validate_envelope(&survey.envelope, HOST_SURVEY_SCHEMA_ID)?;
    validate_local_execution_provenance(&survey.envelope.provenance)?;

    if !survey.survey.is_object() || survey.survey.is_null() {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host survey payload must be a non-null object",
        ));
    }

    let payload = decode_host_survey_payload(&survey.survey).map_err(|error| {
        ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            format!("host survey payload must decode to the typed survey shape: {error}"),
        )
    })?;
    if is_blank(&payload.snapshot_id)
        || is_blank(&payload.host_alias)
        || is_blank(&payload.source_ref)
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host survey payload must include non-blank identity and source fields",
        ));
    }
    validate_collector_metadata(
        &payload.core_evidence.collectors,
        &[
            "procfs",
            "cpuinfo_flags",
            "sysfs",
            "sysfs_cpu_topology",
            "sysfs_cpu_cache",
            "cgroupfs",
            "mountinfo",
            "netdev",
            "iproute2_addr",
            "iproute2_route",
            "pci_accelerators",
            "pci_driver_binding",
            "nvidia_procfs_gpu_info",
            "drm_class",
            "drm_platform_graphics",
            "devfs_accelerator_nodes",
            "block_and_filesystem",
        ],
        &[
            "procfs",
            "sysfs",
            "cgroupfs",
            "mountinfo",
            "netdev",
            "block_and_filesystem",
            "devfs",
        ],
    )?;
    validate_namespaced_json_map(
        &payload.extension_evidence,
        "host survey extension evidence",
    )?;
    validate_known_extension_evidence(&payload.extension_evidence)?;
    validate_claim_metadata(&payload.core_evidence.section_metadata.execution_context)?;
    validate_claim_metadata(&payload.core_evidence.section_metadata.hostname)?;
    validate_claim_metadata(&payload.core_evidence.section_metadata.cpu)?;
    validate_claim_metadata(&payload.core_evidence.section_metadata.memory)?;
    validate_claim_metadata(&payload.core_evidence.section_metadata.storage)?;
    validate_claim_metadata(&payload.core_evidence.section_metadata.network)?;
    validate_claim_metadata(&payload.core_evidence.section_metadata.accelerators)?;
    validate_claim_metadata(&payload.core_evidence.section_metadata.topology)?;
    validate_identity_summary(&payload.core_evidence.identity_summary)?;
    validate_survey_field(
        &payload.core_evidence.observations.hostname,
        "hostname",
        |value| !value.trim().is_empty(),
    )?;
    validate_survey_field(
        &payload.core_evidence.observations.cpu,
        "cpu",
        validate_cpu_details,
    )?;
    validate_survey_field(
        &payload.core_evidence.observations.memory,
        "memory",
        |value: &MemoryDetailsV1| value.total_bytes > 0,
    )?;
    validate_survey_field(
        &payload.core_evidence.observations.storage,
        "storage",
        validate_storage_details,
    )?;
    validate_survey_field(
        &payload.core_evidence.observations.network,
        "network",
        validate_network_details,
    )?;
    validate_survey_field(
        &payload.core_evidence.observations.accelerators,
        "accelerators",
        validate_accelerator_details,
    )?;
    validate_survey_field(
        &payload.core_evidence.observations.topology,
        "topology",
        |value: &TopologyDetailsV1| value.numa_nodes > 0 && value.cpu_packages > 0,
    )?;

    Ok(())
}

fn validate_network_details(value: &NetworkDetailsV1) -> bool {
    let mut interfaces = value.interfaces.clone();
    if interfaces.is_empty() || interfaces.iter().any(|entry| entry.trim().is_empty()) {
        return false;
    }
    interfaces.sort();
    interfaces.dedup();
    if interfaces.len() != value.interfaces.len() {
        return false;
    }

    let mut detail_names = Vec::with_capacity(value.interface_details.len());
    for detail in &value.interface_details {
        if !validate_network_interface_detail(detail) {
            return false;
        }
        detail_names.push(detail.name.clone());
    }
    detail_names.sort();
    detail_names.dedup();
    if detail_names.len() != value.interface_details.len() {
        return false;
    }
    (value.interface_details.is_empty() || detail_names == interfaces)
        && value
            .addressability_summary
            .as_ref()
            .is_none_or(validate_network_addressability_summary)
}

fn validate_storage_details(value: &StorageDetailsV1) -> bool {
    let mut block_devices = value.block_devices.clone();
    if block_devices.iter().any(|entry| entry.trim().is_empty()) {
        return false;
    }
    block_devices.sort();
    block_devices.dedup();
    if block_devices.len() != value.block_devices.len() {
        return false;
    }

    let mut mounts = value.mounts.clone();
    if mounts.iter().any(|entry| entry.trim().is_empty()) {
        return false;
    }
    mounts.sort();
    mounts.dedup();
    if mounts.len() != value.mounts.len() {
        return false;
    }

    let mut detail_names = Vec::with_capacity(value.block_device_details.len());
    for detail in &value.block_device_details {
        if !validate_storage_block_device_detail(detail) {
            return false;
        }
        detail_names.push(detail.name.clone());
    }
    detail_names.sort();
    detail_names.dedup();
    if detail_names.len() != value.block_device_details.len() {
        return false;
    }

    let mut mount_paths = Vec::with_capacity(value.mount_details.len());
    for detail in &value.mount_details {
        if !validate_storage_mount_detail(detail) {
            return false;
        }
        mount_paths.push(detail.path.clone());
    }
    mount_paths.sort();
    mount_paths.dedup();
    if mount_paths.len() != value.mount_details.len() {
        return false;
    }

    (value.block_device_details.is_empty() || detail_names == block_devices)
        && (value.mount_details.is_empty() || mount_paths == mounts)
}

fn validate_storage_block_device_detail(detail: &StorageBlockDeviceV1) -> bool {
    !detail.name.trim().is_empty()
}

fn validate_storage_mount_detail(detail: &StorageMountV1) -> bool {
    !detail.path.trim().is_empty() && !detail.filesystem_type.trim().is_empty()
}

fn validate_network_interface_detail(detail: &NetworkInterfaceV1) -> bool {
    !detail.name.trim().is_empty()
        && detail.mtu.is_none_or(|candidate| candidate > 0)
        && detail.speed_mbps.is_none_or(|candidate| candidate > 0)
        && validate_network_interface_kind_and_virtuality(detail)
        && detail
            .mac_address
            .as_deref()
            .is_none_or(is_valid_mac_address)
        && detail.addresses.iter().all(validate_network_address)
        && {
            let mut addresses = detail
                .addresses
                .iter()
                .map(|address| {
                    (
                        address.family.as_str().to_string(),
                        address.address.clone(),
                        address.prefix_len,
                    )
                })
                .collect::<Vec<_>>();
            let original_len = addresses.len();
            addresses.sort();
            addresses.dedup();
            addresses.len() == original_len
        }
}

fn validate_network_addressability_summary(summary: &NetworkAddressabilitySummaryV1) -> bool {
    summary
        .non_loopback_address_families
        .as_ref()
        .is_none_or(|families| validate_ip_address_family_list(families))
        && summary
            .default_route_families
            .as_ref()
            .is_none_or(|families| validate_ip_address_family_list(families))
}

fn validate_ip_address_family_list(families: &[IpAddressFamilyV1]) -> bool {
    let mut values = families
        .iter()
        .map(|family| family.as_str().to_string())
        .collect::<Vec<_>>();
    let original_len = values.len();
    values.sort();
    values.dedup();
    values.len() == original_len
}

fn validate_network_interface_kind_and_virtuality(detail: &NetworkInterfaceV1) -> bool {
    use crate::survey::{NetworkInterfaceKindV1, NetworkInterfaceVirtualityV1};

    !matches!(
        (detail.interface_kind, detail.interface_virtuality),
        (
            NetworkInterfaceKindV1::Loopback,
            NetworkInterfaceVirtualityV1::Physical
        ) | (
            NetworkInterfaceKindV1::Bridge,
            NetworkInterfaceVirtualityV1::Physical
        ) | (
            NetworkInterfaceKindV1::Tunnel,
            NetworkInterfaceVirtualityV1::Physical
        ) | (
            NetworkInterfaceKindV1::Veth,
            NetworkInterfaceVirtualityV1::Physical
        )
    )
}

fn is_valid_mac_address(value: &str) -> bool {
    let segments = value.split(':').collect::<Vec<_>>();
    segments.len() == 6
        && segments.iter().all(|segment| {
            segment.len() == 2 && segment.chars().all(|value| value.is_ascii_hexdigit())
        })
}

fn validate_network_address(address: &NetworkAddressV1) -> bool {
    match address.family {
        IpAddressFamilyV1::Ipv4 => {
            address.address.parse::<Ipv4Addr>().is_ok() && address.prefix_len <= 32
        }
        IpAddressFamilyV1::Ipv6 => {
            address.address.parse::<Ipv6Addr>().is_ok() && address.prefix_len <= 128
        }
    }
}

/// Validate a host-contract artifact and the contract-side coarse summaries it exposes.
pub fn validate_host_contract(contract: &HostContractV1) -> Result<(), ArtifactValidationError> {
    validate_envelope(&contract.envelope, HOST_CONTRACT_SCHEMA_ID)?;
    validate_local_execution_provenance(&contract.envelope.provenance)?;
    validate_contract_basis(&contract.contract_basis, contract.envelope.schema_version)?;
    if contract
        .host_alias
        .as_ref()
        .is_some_and(|value| is_blank(value))
        || contract
            .display_name
            .as_ref()
            .is_some_and(|value| is_blank(value))
        || contract
            .short_display_name
            .as_ref()
            .is_some_and(|value| is_blank(value))
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract optional host and display labels must stay non-blank when present",
        ));
    }

    if !contract.contract.is_object() || contract.contract.is_null() {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract payload must be a non-null object",
        ));
    }

    let payload: crate::contract::HostContractPayloadV1 =
        serde_json::from_value(contract.contract.clone()).map_err(|error| {
            ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                format!("host contract payload must decode to the typed contract shape: {error}"),
            )
        })?;
    validate_namespaced_json_map(
        &payload.extension_contract,
        "host contract extension contract",
    )?;
    validate_known_extension_contract(&payload.extension_contract)?;
    validate_identity_summary(&payload.core_contract.identity_summary)?;
    if payload.core_contract.capability_classes.is_empty() {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract must include at least one capability class",
        ));
    }
    for claim in payload.core_contract.capability_classes.values() {
        validate_claim_metadata(&claim.claim_metadata)?;
    }
    validate_contract_network_summary(&payload.core_contract.network_summary)?;
    validate_contract_storage_summary(&payload.core_contract.storage_summary)?;
    validate_contract_accelerator_summary(&payload.core_contract.accelerator_summary)?;
    if payload
        .core_contract
        .topology_summary
        .numa_nodes
        .is_some_and(|value| value == 0)
        || payload
            .core_contract
            .topology_summary
            .cpu_packages
            .is_some_and(|value| value == 0)
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract topology summary must be positive when populated",
        ));
    }

    Ok(())
}

fn validate_accelerator_details(value: &AcceleratorDetailsV1) -> bool {
    value.devices.iter().all(validate_accelerator_device)
        && value.operability.as_ref().is_none_or(|operability| {
            validate_accelerator_operability(operability, value.devices.len())
        })
}

fn validate_accelerator_operability(
    operability: &AcceleratorOperabilityV1,
    total_devices: usize,
) -> bool {
    if total_devices == 0 {
        return false;
    }

    let mut visible_nodes = operability.visible_device_nodes.clone();
    if visible_nodes.iter().any(|node| {
        let trimmed = node.trim();
        trimmed.is_empty() || !trimmed.starts_with("/dev/")
    }) {
        return false;
    }
    let original_len = visible_nodes.len();
    visible_nodes.sort();
    visible_nodes.dedup();
    if visible_nodes.len() != original_len || visible_nodes != operability.visible_device_nodes {
        return false;
    }
    let mut visible_render_nodes = operability.visible_render_nodes.clone();
    if visible_render_nodes.iter().any(|node| {
        let trimmed = node.trim();
        trimmed.is_empty() || !trimmed.starts_with("/dev/dri/renderD")
    }) {
        return false;
    }
    let original_render_len = visible_render_nodes.len();
    visible_render_nodes.sort();
    visible_render_nodes.dedup();
    if visible_render_nodes.len() != original_render_len
        || visible_render_nodes != operability.visible_render_nodes
        || visible_render_nodes
            .iter()
            .any(|node| !operability.visible_device_nodes.contains(node))
    {
        return false;
    }

    let Ok(total_devices_u32) = u32::try_from(total_devices) else {
        return false;
    };
    if operability.driver_bound_devices > total_devices_u32 {
        return false;
    }

    match operability.static_operability {
        StaticOperabilityV1::Operable => {
            operability.driver_bound_devices == total_devices_u32 && !visible_nodes.is_empty()
        }
        StaticOperabilityV1::NotOperable => {
            operability.driver_bound_devices == 0 || visible_nodes.is_empty()
        }
        StaticOperabilityV1::Indeterminate => {
            operability.driver_bound_devices > 0
                && operability.driver_bound_devices < total_devices_u32
                && !visible_nodes.is_empty()
        }
    }
}

fn validate_accelerator_device(device: &AcceleratorDeviceV1) -> bool {
    let source_valid = match device.discovery_source {
        AcceleratorDiscoverySourceV1::Pci => true,
        AcceleratorDiscoverySourceV1::DrmPlatform => {
            device.vendor_id.is_none() && device.device_id.is_none() && device.pci_address.is_none()
        }
    };

    source_valid
        && device
            .vendor
            .as_deref()
            .is_none_or(|vendor| !is_blank(vendor))
        && device
            .family
            .as_deref()
            .is_none_or(|family| !is_blank(family))
        && device.model.as_deref().is_none_or(|model| !is_blank(model))
        && device.vendor_id.as_deref().is_none_or(is_valid_pci_hex_id)
        && device.device_id.as_deref().is_none_or(is_valid_pci_hex_id)
        && device.memory_bytes.is_none_or(|value| value > 0)
        && !matches!(
            (device.discovery_source, device.integration),
            (
                AcceleratorDiscoverySourceV1::DrmPlatform,
                Some(crate::survey::AcceleratorIntegrationV1::Discrete)
            )
        )
        && device
            .pci_address
            .as_deref()
            .is_none_or(is_valid_pci_address)
        && device
            .driver
            .as_deref()
            .is_none_or(|driver| !is_blank(driver))
}

fn validate_cpu_details(value: &CpuDetailsV1) -> bool {
    if is_blank(&value.architecture)
        || value.logical_cores == 0
        || is_blank(&value.model)
        || value
            .physical_cores
            .is_some_and(|candidate| candidate == 0 || candidate > value.logical_cores)
        || value
            .threads_per_core
            .is_some_and(|candidate| candidate == 0)
        || value
            .feature_flags
            .iter()
            .any(|candidate| is_blank(candidate))
    {
        return false;
    }

    let mut flags = value.feature_flags.clone();
    let original_len = flags.len();
    flags.sort();
    flags.dedup();
    if flags.len() != original_len || flags != value.feature_flags {
        return false;
    }

    if let (Some(physical_cores), Some(threads_per_core)) =
        (value.physical_cores, value.threads_per_core)
    {
        let Some(expected_logical_cores) = physical_cores.checked_mul(threads_per_core) else {
            return false;
        };
        if expected_logical_cores != value.logical_cores {
            return false;
        }
    }

    value
        .cache_summary
        .as_ref()
        .is_none_or(validate_cpu_cache_summary)
}

fn validate_cpu_cache_summary(summary: &CpuCacheSummaryV1) -> bool {
    let values = [
        summary.l1_data_bytes,
        summary.l1_instruction_bytes,
        summary.l2_bytes,
        summary.l3_bytes,
    ];

    values.iter().any(|value| value.is_some())
        && values
            .iter()
            .all(|value| value.is_none_or(|candidate| candidate > 0))
}

fn is_valid_pci_hex_id(value: &str) -> bool {
    value.len() == 4 && value.chars().all(|candidate| candidate.is_ascii_hexdigit())
}

fn is_valid_pci_address(value: &str) -> bool {
    let mut segments = value.split([':', '.']);
    let Some(domain) = segments.next() else {
        return false;
    };
    let Some(bus) = segments.next() else {
        return false;
    };
    let Some(device) = segments.next() else {
        return false;
    };
    let Some(function) = segments.next() else {
        return false;
    };
    segments.next().is_none()
        && domain.len() == 4
        && bus.len() == 2
        && device.len() == 2
        && function.len() == 1
        && [domain, bus, device, function].iter().all(|segment| {
            segment
                .chars()
                .all(|candidate| candidate.is_ascii_hexdigit())
        })
}

/// Validate a service-profile artifact before validation logic consumes it.
pub fn validate_service_profile(profile: &ServiceProfileV1) -> Result<(), ArtifactValidationError> {
    validate_envelope(&profile.envelope, SERVICE_PROFILE_SCHEMA_ID)?;

    if is_blank(&profile.profile.profile_id)
        || profile
            .profile
            .display_name
            .as_ref()
            .is_some_and(|value| is_blank(value))
        || profile
            .profile
            .short_display_name
            .as_ref()
            .is_some_and(|value| is_blank(value))
        || is_blank(&profile.profile.core_requirements.primary_capability_class)
        || profile
            .profile
            .core_requirements
            .allowed_visibility_scopes
            .is_empty()
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "service profile must include a profile id, non-blank optional display labels, a primary capability, and visibility allowlist",
        ));
    }

    validate_namespaced_json_map(
        &profile.profile.extension_requirements,
        "service profile extension requirements",
    )?;
    validate_known_extension_requirements(&profile.profile.extension_requirements)?;
    if profile
        .profile
        .core_requirements
        .max_accelerator_numa_nodes
        .is_some_and(|value| value == 0)
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "service profile accelerator locality limits must stay positive when populated",
        ));
    }

    Ok(())
}

fn validate_contract_network_summary(
    summary: &ContractNetworkSummaryV1,
) -> Result<(), ArtifactValidationError> {
    if summary.total_interfaces.is_some_and(|value| value == 0)
        || summary
            .max_observed_speed_mbps
            .is_some_and(|value| value == 0)
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract network summary must stay positive when populated",
        ));
    }
    if let (Some(non_loopback_interfaces), Some(total_interfaces)) =
        (summary.non_loopback_interfaces, summary.total_interfaces)
    {
        if non_loopback_interfaces > total_interfaces {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "host contract network summary non-loopback count must not exceed total interface count",
            ));
        }
    }
    let mut interface_kinds = summary
        .interface_kinds
        .iter()
        .map(|kind| kind.as_str())
        .collect::<Vec<_>>();
    interface_kinds.sort();
    interface_kinds.dedup();
    if interface_kinds.len() != summary.interface_kinds.len() {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract network summary interface kinds must be unique",
        ));
    }
    if let Some(operability) = summary.operability.as_ref() {
        validate_contract_network_operability(operability)?;
        if let Some(non_loopback_interfaces) = summary.non_loopback_interfaces {
            if operability.physical_non_loopback_interfaces > non_loopback_interfaces {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "host contract network operability physical interface count must not exceed non-loopback interface count",
                ));
            }
        }
    }

    Ok(())
}

fn validate_contract_network_operability(
    operability: &ContractNetworkOperabilityV1,
) -> Result<(), ArtifactValidationError> {
    if operability.interfaces_with_known_speed > operability.physical_non_loopback_interfaces {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract network operability known-speed count must not exceed physical interface count",
        ));
    }
    match operability.static_operability {
        StaticOperabilityV1::Operable => {
            if operability.physical_non_loopback_interfaces == 0
                || operability.interfaces_with_known_speed == 0
            {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "operable network summary must include at least one physical interface with known speed",
                ));
            }
        }
        StaticOperabilityV1::NotOperable => {
            if operability.physical_non_loopback_interfaces != 0 {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "not_operable network summary must not report physical non-loopback interfaces",
                ));
            }
        }
        StaticOperabilityV1::Indeterminate => {
            if operability.physical_non_loopback_interfaces == 0
                || operability.interfaces_with_known_speed != 0
            {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "indeterminate network summary must report physical interfaces without enough evidence to classify them operable",
                ));
            }
        }
    }
    Ok(())
}

fn validate_contract_storage_summary(
    summary: &ContractStorageSummaryV1,
) -> Result<(), ArtifactValidationError> {
    if summary.total_block_devices.is_none()
        && summary.total_mounts.is_none()
        && summary.block_device_classes.is_empty()
        && summary.filesystem_types.is_empty()
        && summary.operability.is_none()
    {
        return Ok(());
    }

    if summary.total_block_devices.is_some_and(|value| value == 0)
        || summary.total_mounts.is_some_and(|value| value == 0)
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract storage summary counts must stay positive when populated",
        ));
    }

    let mut block_device_classes = summary
        .block_device_classes
        .iter()
        .map(|class| class.as_str())
        .collect::<Vec<_>>();
    block_device_classes.sort();
    block_device_classes.dedup();
    if block_device_classes.len() != summary.block_device_classes.len() {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract storage summary block device classes must be unique",
        ));
    }

    let mut filesystem_types = summary.filesystem_types.clone();
    filesystem_types.sort();
    filesystem_types.dedup();
    if filesystem_types.len() != summary.filesystem_types.len() {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract storage summary filesystem types must be unique",
        ));
    }

    if let Some(operability) = summary.operability.as_ref() {
        validate_contract_storage_operability(operability)?;
        if let Some(total_block_devices) = summary.total_block_devices {
            if operability.usable_block_devices > total_block_devices {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "host contract storage operability usable block-device count must not exceed total block devices",
                ));
            }
        }
    }

    Ok(())
}

fn validate_contract_storage_operability(
    operability: &ContractStorageOperabilityV1,
) -> Result<(), ArtifactValidationError> {
    match operability.static_operability {
        StaticOperabilityV1::Operable => {
            if operability.usable_block_devices == 0 || !operability.root_mount_present {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "operable storage summary must include usable block devices and a root mount",
                ));
            }
        }
        StaticOperabilityV1::NotOperable => {
            if operability.usable_block_devices != 0 {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "not_operable storage summary must not report usable block devices",
                ));
            }
        }
        StaticOperabilityV1::Indeterminate => {
            if operability.usable_block_devices == 0 || operability.root_mount_present {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "indeterminate storage summary must report usable block devices without a root mount",
                ));
            }
        }
    }

    Ok(())
}

fn validate_contract_accelerator_summary(
    summary: &ContractAcceleratorSummaryV1,
) -> Result<(), ArtifactValidationError> {
    if summary.total_accelerators.is_none()
        && summary.gpu_accelerators.is_none()
        && summary.full_inventory_complete.is_none()
        && summary.policy_scoped_confirmed_accelerators.is_none()
        && summary.policy_scoped_unresolved_accelerators.is_none()
        && summary.policy_scoped_inventory_complete.is_none()
        && summary.integrated_accelerators.is_none()
        && summary.accelerators_with_known_memory.is_none()
        && summary.accelerators_with_known_numa_node.is_none()
        && summary.max_memory_bytes.is_none()
        && summary.accelerator_numa_nodes.is_empty()
        && summary.accelerator_kinds.is_empty()
        && summary.vendors.is_empty()
        && summary.families.is_empty()
        && summary.models.is_empty()
    {
        return Ok(());
    }

    let Some(total_accelerators) = summary.total_accelerators else {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator summary must include total_accelerators when populated",
        ));
    };
    let Some(gpu_accelerators) = summary.gpu_accelerators else {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator summary must include gpu_accelerators when populated",
        ));
    };
    if gpu_accelerators > total_accelerators {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator summary gpu count must not exceed total accelerator count",
        ));
    }
    if summary
        .integrated_accelerators
        .is_some_and(|value| value > total_accelerators)
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator summary integrated count must not exceed total accelerator count",
        ));
    }
    if summary
        .accelerators_with_known_memory
        .is_some_and(|value| value > total_accelerators)
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator summary known-memory count must not exceed total accelerator count",
        ));
    }
    if summary
        .accelerators_with_known_memory
        .is_some_and(|value| value == 0)
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator summary known-memory count must stay positive when populated",
        ));
    }
    if summary
        .accelerators_with_known_numa_node
        .is_some_and(|value| value > total_accelerators)
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator summary known-locality count must not exceed total accelerator count",
        ));
    }
    if summary
        .accelerators_with_known_numa_node
        .is_some_and(|value| value == 0)
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator summary known-locality count must stay positive when populated",
        ));
    }
    if summary.max_memory_bytes.is_some_and(|value| value == 0) {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator summary max memory must stay positive when populated",
        ));
    }
    if summary
        .policy_scoped_confirmed_accelerators
        .is_some_and(|value| value > total_accelerators)
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator summary confirmed policy-scoped count must not exceed total accelerator count",
        ));
    }
    if summary
        .policy_scoped_unresolved_accelerators
        .is_some_and(|value| value > total_accelerators)
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator summary unresolved policy-scoped count must not exceed total accelerator count",
        ));
    }
    if let (Some(confirmed), Some(unresolved)) = (
        summary.policy_scoped_confirmed_accelerators,
        summary.policy_scoped_unresolved_accelerators,
    ) {
        if confirmed + unresolved > total_accelerators {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "host contract accelerator summary policy-scoped confirmed and unresolved counts must not exceed total accelerator count",
            ));
        }
    }
    if let Some(policy_scoped_inventory_complete) = summary.policy_scoped_inventory_complete {
        match (
            policy_scoped_inventory_complete,
            summary.policy_scoped_unresolved_accelerators,
        ) {
            (true, Some(0)) => {}
            (false, Some(value)) if value > 0 => {}
            _ => {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "host contract accelerator summary policy-scoped completeness must agree with the unresolved scoped count",
                ));
            }
        }
    }

    let mut accelerator_kinds = summary
        .accelerator_kinds
        .iter()
        .map(|kind| kind.as_str())
        .collect::<Vec<_>>();
    accelerator_kinds.sort();
    accelerator_kinds.dedup();
    if accelerator_kinds.len() != summary.accelerator_kinds.len() {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator summary kinds must be unique",
        ));
    }

    let mut vendors = summary.vendors.clone();
    if vendors.iter().any(|vendor| is_blank(vendor)) {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator summary vendors must stay non-blank when populated",
        ));
    }
    vendors.sort();
    vendors.dedup();
    if vendors.len() != summary.vendors.len() {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator summary vendors must be unique",
        ));
    }
    let mut families = summary.families.clone();
    if families.iter().any(|family| is_blank(family)) {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator summary families must stay non-blank when populated",
        ));
    }
    families.sort();
    families.dedup();
    if families.len() != summary.families.len() {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator summary families must be unique",
        ));
    }
    let mut models = summary.models.clone();
    if models.iter().any(|model| is_blank(model)) {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator summary models must stay non-blank when populated",
        ));
    }
    models.sort();
    models.dedup();
    if models.len() != summary.models.len() {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator summary models must be unique",
        ));
    }

    if total_accelerators == 0
        && (!summary.accelerator_kinds.is_empty()
            || !summary.vendors.is_empty()
            || !summary.families.is_empty()
            || !summary.models.is_empty()
            || summary.integrated_accelerators.is_some()
            || summary.full_inventory_complete.is_some()
            || summary.policy_scoped_confirmed_accelerators.is_some()
            || summary.policy_scoped_unresolved_accelerators.is_some()
            || summary.policy_scoped_inventory_complete.is_some()
            || summary.accelerators_with_known_memory.is_some()
            || summary.accelerators_with_known_numa_node.is_some()
            || summary.max_memory_bytes.is_some())
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator summary must stay empty when accelerator count is zero",
        ));
    }
    if total_accelerators == 0 && !summary.accelerator_numa_nodes.is_empty() {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator summary must not list accelerator NUMA nodes when accelerator count is zero",
        ));
    }
    if total_accelerators > 0 && summary.accelerator_kinds.is_empty() {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator summary kinds must be populated when accelerators are present",
        ));
    }
    if gpu_accelerators > 0 && !summary.accelerator_kinds.contains(&AcceleratorKindV1::Gpu) {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator summary gpu count requires the gpu kind to be present",
        ));
    }
    if gpu_accelerators == 0 && summary.accelerator_kinds.contains(&AcceleratorKindV1::Gpu) {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator summary gpu kind requires a positive gpu count",
        ));
    }
    if summary.max_memory_bytes.is_some() && summary.accelerators_with_known_memory.is_none() {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator summary max memory requires a known-memory device count",
        ));
    }
    if summary.policy_scoped_inventory_complete.is_some()
        && summary.policy_scoped_confirmed_accelerators.is_none()
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator summary policy-scoped completeness requires a confirmed scoped count",
        ));
    }
    if summary.policy_scoped_confirmed_accelerators.is_some()
        && summary.policy_scoped_unresolved_accelerators.is_none()
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator summary confirmed scoped count requires an unresolved scoped count",
        ));
    }
    if summary.policy_scoped_unresolved_accelerators.is_some()
        && summary.policy_scoped_inventory_complete.is_none()
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator summary unresolved scoped count requires policy-scoped completeness",
        ));
    }
    if summary.full_inventory_complete.is_none() {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator summary must include full_inventory_complete when populated",
        ));
    }
    if !summary.accelerator_numa_nodes.is_empty()
        && summary.accelerators_with_known_numa_node.is_none()
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator summary NUMA node list requires a known-locality device count",
        ));
    }
    if summary
        .accelerator_numa_nodes
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .len()
        != summary.accelerator_numa_nodes.len()
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator summary NUMA nodes must be unique",
        ));
    }
    if let Some(known_locality_devices) = summary.accelerators_with_known_numa_node {
        let distinct_nodes = u32::try_from(summary.accelerator_numa_nodes.len()).map_err(|_| {
            ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "host contract accelerator summary NUMA node count overflowed u32",
            )
        })?;
        if distinct_nodes == 0 {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "host contract accelerator summary known-locality device count requires NUMA nodes",
            ));
        }
        if distinct_nodes > known_locality_devices {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "host contract accelerator summary NUMA node count must not exceed known-locality device count",
            ));
        }
    }
    if let Some(operability) = summary.operability.as_ref() {
        validate_contract_accelerator_operability(operability, total_accelerators)?;
    }

    Ok(())
}

fn validate_contract_accelerator_operability(
    operability: &AcceleratorOperabilityV1,
    total_accelerators: u32,
) -> Result<(), ArtifactValidationError> {
    if total_accelerators == 0 {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator operability must stay absent when accelerator count is zero",
        ));
    }
    if operability.driver_bound_devices > total_accelerators {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator operability driver-bound count must not exceed total accelerator count",
        ));
    }

    let mut visible_nodes = operability.visible_device_nodes.clone();
    if visible_nodes.iter().any(|node| {
        let trimmed = node.trim();
        trimmed.is_empty() || !trimmed.starts_with("/dev/")
    }) {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator operability visible nodes must stay rooted under /dev/",
        ));
    }
    let original_len = visible_nodes.len();
    visible_nodes.sort();
    visible_nodes.dedup();
    if visible_nodes.len() != original_len || visible_nodes != operability.visible_device_nodes {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator operability visible nodes must stay sorted and unique",
        ));
    }
    let mut visible_render_nodes = operability.visible_render_nodes.clone();
    if visible_render_nodes.iter().any(|node| {
        let trimmed = node.trim();
        trimmed.is_empty() || !trimmed.starts_with("/dev/dri/renderD")
    }) {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator operability render nodes must stay rooted under /dev/dri/renderD*",
        ));
    }
    let original_render_len = visible_render_nodes.len();
    visible_render_nodes.sort();
    visible_render_nodes.dedup();
    if visible_render_nodes.len() != original_render_len
        || visible_render_nodes != operability.visible_render_nodes
        || visible_render_nodes
            .iter()
            .any(|node| !operability.visible_device_nodes.contains(node))
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator operability render nodes must stay sorted, unique, and included in visible nodes",
        ));
    }

    let valid = match operability.static_operability {
        StaticOperabilityV1::Operable => {
            operability.driver_bound_devices == total_accelerators && !visible_nodes.is_empty()
        }
        StaticOperabilityV1::NotOperable => {
            operability.driver_bound_devices == 0 || visible_nodes.is_empty()
        }
        StaticOperabilityV1::Indeterminate => {
            operability.driver_bound_devices > 0
                && operability.driver_bound_devices < total_accelerators
                && !visible_nodes.is_empty()
        }
    };
    if !valid {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host contract accelerator operability carries a contradictory static-operability classification",
        ));
    }

    Ok(())
}

/// Validate a host-state artifact and its runtime-boundary/resource accounting.
pub fn validate_host_state(state: &HostStateV1) -> Result<(), ArtifactValidationError> {
    validate_envelope(&state.envelope, HOST_STATE_SCHEMA_ID)?;
    validate_local_execution_provenance(&state.envelope.provenance)?;

    if is_blank(&state.state.snapshot_id)
        || is_blank(&state.state.host_alias)
        || is_blank(&state.state.source_ref)
        || state.state.core_state.collectors.is_empty()
        || is_blank(&state.state.core_state.freshness.observed_at)
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host-state must include typed identity, freshness, and collector metadata",
        ));
    }
    if let Some(local_identity) = state.state.local_identity.as_ref() {
        validate_state_local_identity(local_identity)?;
    }
    validate_collector_metadata(
        &state.state.core_state.collectors,
        &[
            "runtime_cpu_capacity",
            "std::available_parallelism",
            "procfs_meminfo",
            "cgroupfs_cpuset",
            "cgroupfs_cpu_quota",
            "cgroupfs_memory_boundary",
            "sysfs_topology",
        ],
        &["rust_std", "procfs", "cgroupfs", "sysfs"],
    )?;
    validate_namespaced_json_map(&state.state.extension_state, "host-state extension state")?;

    validate_state_field(
        &state
            .state
            .core_state
            .resources
            .allocatable_cpu_logical_cores,
        "allocatable_cpu_logical_cores",
        |value| *value > 0,
    )?;
    validate_state_field(
        &state.state.core_state.resources.memory_total_bytes,
        "memory_total_bytes",
        |value| *value > 0,
    )?;
    validate_state_field(
        &state.state.core_state.resources.allocatable_memory_bytes,
        "allocatable_memory_bytes",
        |value| *value > 0,
    )?;
    validate_state_field(
        &state
            .state
            .core_state
            .resources
            .memory_used_excluding_cache_bytes,
        "memory_used_excluding_cache_bytes",
        |value| *value > 0,
    )?;
    validate_claim_metadata(&state.state.core_state.section_metadata.resources)?;
    validate_claim_metadata(&state.state.core_state.section_metadata.boundaries)?;
    validate_claim_metadata(&state.state.core_state.section_metadata.topology)?;
    validate_claim_metadata(&state.state.core_state.section_metadata.operability)?;
    validate_known_extension_state(&state.state.extension_state)?;
    validate_state_field(
        &state.state.core_state.boundaries.cgroup_version,
        "cgroup_version",
        |value| matches!(value.as_str(), "v1" | "v2"),
    )?;
    validate_state_field(
        &state.state.core_state.boundaries.cpuset_cpu_logical_cores,
        "cpuset_cpu_logical_cores",
        |value| *value > 0,
    )?;
    validate_state_field(
        &state.state.core_state.boundaries.cpu_quota_logical_cores,
        "cpu_quota_logical_cores",
        |value| *value > 0,
    )?;
    validate_state_field(
        &state.state.core_state.boundaries.memory_limit_bytes,
        "memory_limit_bytes",
        |value| *value > 0,
    )?;
    validate_state_field(
        &state.state.core_state.boundaries.memory_current_bytes,
        "memory_current_bytes",
        |_value| true,
    )?;
    validate_state_memory_accounting(state)?;
    validate_state_field(
        &state.state.core_state.topology.visible_numa_nodes,
        "visible_numa_nodes",
        |value| *value > 0,
    )?;
    if state
        .state
        .core_state
        .operability
        .degraded_capability_classes
        .iter()
        .any(|value| is_blank(value))
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "host-state degraded capability classes must be non-blank when present",
        ));
    }

    Ok(())
}

/// Validate a validation-report artifact, including explanation and remediation structure.
pub fn validate_validation_report(
    report: &ValidationReportV1,
) -> Result<(), ArtifactValidationError> {
    validate_envelope(&report.envelope, VALIDATION_REPORT_SCHEMA_ID)?;
    validate_local_execution_provenance(&report.envelope.provenance)?;

    if is_blank(&report.validation_basis.contract_artifact_id)
        || is_blank(&report.validation_basis.service_profile_artifact_id)
        || is_blank(&report.validation_basis.contract_semantic_hash)
        || is_blank(&report.validation_basis.service_profile_semantic_hash)
        || report
            .validation_basis
            .state_artifact_id
            .as_ref()
            .is_some_and(|value| is_blank(value))
        || report
            .validation_basis
            .state_semantic_hash
            .as_ref()
            .is_some_and(|value| is_blank(value))
        || report
            .validation_basis
            .state_observed_at
            .as_ref()
            .is_some_and(|value| is_blank(value))
        || is_blank(&report.validation_basis.validation_engine_id)
        || is_blank(&report.validation_basis.validation_engine_version)
        || is_blank(&report.report.summary)
        || report
            .report
            .matched_requirements
            .iter()
            .any(|value| is_blank(value))
        || report
            .report
            .failed_requirements
            .iter()
            .any(|value| is_blank(value))
        || report
            .report
            .evidence_refs
            .iter()
            .any(|value| is_blank(value))
        || report
            .report
            .policy_refs
            .iter()
            .any(|value| is_blank(value))
        || report
            .report
            .assurance_mismatches
            .iter()
            .any(|value| is_blank(value))
        || report
            .report
            .explanations
            .iter()
            .any(|entry| is_blank(&entry.explanation_id) || is_blank(&entry.summary))
        || report
            .report
            .remediation_hints
            .iter()
            .any(|entry| is_blank(&entry.hint_id) || is_blank(&entry.summary))
        || report
            .report
            .selected_degradation_tier
            .as_ref()
            .is_some_and(|value| is_blank(value))
        || report.report.warnings.iter().any(|value| is_blank(value))
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "validation report must include typed lineage, summary, and non-blank list entries",
        ));
    }

    validate_validation_basis_semantics(report)?;
    validate_validation_report_semantics(&report.report)?;
    validate_namespaced_json_map(
        &report.report.extension_diagnostics,
        "validation-report extension diagnostics",
    )?;
    validate_known_validation_extension_diagnostics(&report.report.extension_diagnostics)?;
    validate_validation_explanations(&report.report)?;
    validate_validation_remediation_hints(&report.report)?;

    Ok(())
}

pub fn validate_recommendation_report(
    report: &RecommendationReportV1,
) -> Result<(), ArtifactValidationError> {
    validate_auxiliary_envelope(&report.envelope, RECOMMENDATION_REPORT_SCHEMA_ID)?;

    if is_blank(&report.recommendation_basis.validation_report_artifact_id)
        || is_blank(&report.recommendation_basis.validation_report_semantic_hash)
        || is_blank(&report.recommendation_basis.recommendation_pack_id)
        || is_blank(&report.recommendation_basis.recommendation_pack_version)
        || is_blank(&report.recommendation_basis.recommendation_engine_id)
        || is_blank(&report.recommendation_basis.recommendation_engine_version)
        || report
            .recommendation_basis
            .state_artifact_id
            .as_ref()
            .is_some_and(|value| is_blank(value))
        || report
            .recommendation_basis
            .state_semantic_hash
            .as_ref()
            .is_some_and(|value| is_blank(value))
        || report
            .report
            .recommendation_class
            .as_ref()
            .is_some_and(|value| is_blank(value))
        || report
            .report
            .expected_operating_mode
            .as_ref()
            .is_some_and(|value| is_blank(value))
        || report
            .report
            .processing_time_band
            .as_ref()
            .is_some_and(|value| is_blank(value))
        || report
            .report
            .throughput_band
            .as_ref()
            .is_some_and(|value| is_blank(value))
        || report
            .report
            .advisory_reason_ids
            .iter()
            .any(|value| is_blank(value))
        || is_blank(&report.report.freshness.observed_at)
        || is_blank(&report.report.summary)
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "recommendation report must include non-blank basis, freshness, and summary fields",
        ));
    }

    if report.recommendation_basis.state_artifact_id.is_some()
        != report.recommendation_basis.state_semantic_hash.is_some()
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "recommendation report state_artifact_id and state_semantic_hash must appear together",
        ));
    }

    let mut advisory_reason_ids = report.report.advisory_reason_ids.clone();
    advisory_reason_ids.sort();
    advisory_reason_ids.dedup();
    if advisory_reason_ids.len() != report.report.advisory_reason_ids.len() {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "recommendation report advisory_reason_ids must be unique when present",
        ));
    }

    Ok(())
}

pub fn validate_batch_classification_report(
    report: &BatchClassificationReportV1,
) -> Result<(), ArtifactValidationError> {
    validate_batch_classification_report_envelope(&report.envelope)?;

    let is_legacy_v2 = report.envelope.schema_id == LEGACY_BATCH_CLASSIFICATION_REPORT_SCHEMA_ID;
    let is_current_v3 = report.envelope.schema_id == BATCH_CLASSIFICATION_REPORT_SCHEMA_ID;

    if is_blank(&report.classification_basis.validated_at)
        || is_blank(&report.classification_basis.validation_engine_id)
        || is_blank(&report.classification_basis.validation_engine_version)
        || report.classification_basis.ordered_contracts.is_empty()
        || report
            .classification_basis
            .ordered_service_profiles
            .is_empty()
        || report.report.rows.is_empty()
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "batch classification report must retain engine lineage and non-empty inputs",
        ));
    }

    if !is_legacy_v2 && !is_current_v3 {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactSchemaIdInvalid,
            "batch classification report schema id is not supported",
        ));
    }

    match report.classification_basis.validation_mode {
        ValidationModeV1::ContractOnly => {
            if report.classification_basis.max_state_age_seconds.is_some()
                || report
                    .classification_basis
                    .ordered_contracts
                    .iter()
                    .any(|value| value.matched_state.is_some())
            {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "contract-only batch classification reports must not record state lineage or max_state_age_seconds",
                ));
            }
        }
        ValidationModeV1::StateAdvisory | ValidationModeV1::StateRequired => {
            if is_legacy_v2 {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactSchemaIdInvalid,
                    "legacy batch-classification-report.v2 supports only contract_only validation mode",
                ));
            }
        }
        ValidationModeV1::StateAware => {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "batch classification reports must not use state_aware validation mode",
            ));
        }
    }

    validate_sorted_unique_refs(
        report
            .classification_basis
            .ordered_contracts
            .iter()
            .map(|value| (value.artifact_id.as_str(), value.semantic_hash.as_str())),
        "batch classification ordered_contracts",
    )?;
    validate_sorted_unique_refs(
        report
            .classification_basis
            .ordered_service_profiles
            .iter()
            .map(|value| (value.artifact_id.as_str(), value.semantic_hash.as_str())),
        "batch classification ordered_service_profiles",
    )?;
    if report
        .classification_basis
        .ordered_service_profiles
        .iter()
        .any(|value| {
            value
                .display_name
                .as_ref()
                .is_some_and(|label| is_blank(label))
                || value
                    .short_display_name
                    .as_ref()
                    .is_some_and(|label| is_blank(label))
        })
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "batch classification ordered_service_profiles must not contain blank display labels",
        ));
    }
    if report
        .classification_basis
        .ordered_contracts
        .iter()
        .any(|value| {
            value
                .host_alias
                .as_ref()
                .is_some_and(|label| is_blank(label))
                || value
                    .display_name
                    .as_ref()
                    .is_some_and(|label| is_blank(label))
                || value
                    .short_display_name
                    .as_ref()
                    .is_some_and(|label| is_blank(label))
                || value.matched_state.as_ref().is_some_and(|state| {
                    is_blank(&state.artifact_id)
                        || is_blank(&state.semantic_hash)
                        || is_blank(&state.observed_at)
                })
        })
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "batch classification ordered_contracts must not contain blank host, display, or matched-state labels",
        ));
    }
    if report
        .classification_basis
        .ordered_contracts
        .iter()
        .any(|value| value.matched_state.is_some() && value.host_alias.is_none())
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "batch classification ordered_contracts must retain host_alias when matched_state is present",
        ));
    }

    let allowed_contract_ids = report
        .classification_basis
        .ordered_contracts
        .iter()
        .map(|value| value.artifact_id.as_str())
        .collect::<BTreeSet<_>>();
    let allowed_profile_ids = report
        .classification_basis
        .ordered_service_profiles
        .iter()
        .map(|value| value.artifact_id.as_str())
        .collect::<BTreeSet<_>>();

    let row_keys = report
        .report
        .rows
        .iter()
        .map(|row| {
            if is_blank(&row.row_id)
                || is_blank(&row.contract_artifact_id)
                || is_blank(&row.contract_semantic_hash)
                || is_blank(&row.service_profile_artifact_id)
                || is_blank(&row.service_profile_semantic_hash)
                || is_blank(&row.summary)
                || row
                    .selected_degradation_tier
                    .as_ref()
                    .is_some_and(|value| is_blank(value))
            {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "batch classification rows must retain non-blank ids, hashes, and summaries",
                ));
            }
            if !allowed_contract_ids.contains(row.contract_artifact_id.as_str())
                || !allowed_profile_ids.contains(row.service_profile_artifact_id.as_str())
            {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "batch classification rows must reference declared contract and service-profile ids",
                ));
            }
            validate_batch_row_semantics(row.verdict, row.primary_reason_code, row.selected_degradation_tier.as_deref())?;
            Ok((
                row.row_id.as_str(),
                row.contract_artifact_id.as_str(),
                row.service_profile_artifact_id.as_str(),
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut sorted_row_keys = row_keys.clone();
    sorted_row_keys.sort();
    if row_keys != sorted_row_keys {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "batch classification rows must be deterministically sorted",
        ));
    }
    let deduped_row_keys = row_keys.iter().copied().collect::<BTreeSet<_>>();
    if deduped_row_keys.len() != row_keys.len() {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "batch classification rows must be unique by row id and tuple",
        ));
    }

    validate_sorted_unique_summary_lists(
        report.report.contract_summaries.iter().map(|summary| {
            (
                summary.contract_artifact_id.as_str(),
                [
                    &summary.fit_profile_ids,
                    &summary.degraded_profile_ids,
                    &summary.unfit_profile_ids,
                    &summary.indeterminate_profile_ids,
                ],
            )
        }),
        &allowed_contract_ids,
        &allowed_profile_ids,
        true,
    )?;
    validate_sorted_unique_summary_lists(
        report
            .report
            .service_profile_summaries
            .iter()
            .map(|summary| {
                (
                    summary.service_profile_artifact_id.as_str(),
                    [
                        &summary.fit_contract_ids,
                        &summary.degraded_contract_ids,
                        &summary.unfit_contract_ids,
                        &summary.indeterminate_contract_ids,
                    ],
                )
            }),
        &allowed_profile_ids,
        &allowed_contract_ids,
        false,
    )?;

    Ok(())
}

fn validate_batch_classification_report_envelope(
    envelope: &ArtifactEnvelopeV1,
) -> Result<(), ArtifactValidationError> {
    if !is_supported_batch_classification_report_schema_id(&envelope.schema_id) {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactSchemaIdInvalid,
            format!(
                "expected supported schema id {}, got {}",
                BATCH_CLASSIFICATION_REPORT_SCHEMA_ID, envelope.schema_id
            ),
        ));
    }

    validate_auxiliary_envelope(envelope, &envelope.schema_id)
}

/// Validate a decision-bundle artifact and fail closed on embedded lineage mismatches.
pub fn validate_config_bundle(bundle: &ConfigBundleV1) -> Result<(), ArtifactValidationError> {
    validate_auxiliary_envelope(&bundle.envelope, CONFIG_BUNDLE_SCHEMA_ID)?;
    validate_policy_document(&bundle.config_bundle.policy).map_err(|error| {
        ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            error.message,
        )
    })?;
    validate_resolved_config(&bundle.config_bundle.resolved_config).map_err(|error| {
        ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            error.message,
        )
    })?;
    if let Some(profile) = bundle.config_bundle.service_profile.as_ref() {
        validate_service_profile(profile)?;
    }
    if let Some(policy) = bundle.config_bundle.trust_policy.as_ref() {
        validate_trust_policy_document_v1(policy).map_err(|error| {
            ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                error.message,
            )
        })?;
    }

    if is_blank(&bundle.config_bundle_basis.policy_id)
        || is_blank(&bundle.config_bundle_basis.resolved_config_semantic_hash)
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "config bundle basis must include non-blank policy and resolved-config lineage",
        ));
    }
    if bundle
        .config_bundle_basis
        .service_profile_id
        .as_ref()
        .is_some_and(|value| is_blank(value))
        || bundle
            .config_bundle_basis
            .trust_policy_id
            .as_ref()
            .is_some_and(|value| is_blank(value))
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "config bundle optional basis ids must be non-blank when present",
        ));
    }
    if bundle.config_bundle_basis.policy_id != bundle.config_bundle.policy.policy_id {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "config bundle basis policy_id must match the embedded selected policy",
        ));
    }
    if bundle.config_bundle_basis.service_profile_id.as_deref()
        != bundle
            .config_bundle
            .service_profile
            .as_ref()
            .map(|profile| profile.profile.profile_id.as_str())
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "config bundle basis service_profile_id must match the embedded selected service profile when present",
        ));
    }
    if bundle.config_bundle_basis.trust_policy_id.as_deref()
        != bundle
            .config_bundle
            .trust_policy
            .as_ref()
            .map(|policy| policy.policy_id.as_str())
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "config bundle basis trust_policy_id must match the embedded trust policy when present",
        ));
    }

    let resolved_config_semantic_hash = semantic_hash_hex_for_resolved_config(
        &bundle.config_bundle.resolved_config,
    )
    .map_err(|error| {
        ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            error.message,
        )
    })?;
    if bundle.config_bundle_basis.resolved_config_semantic_hash != resolved_config_semantic_hash {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "config bundle resolved-config semantic hash must match the embedded resolved config",
        ));
    }
    if bundle.config_bundle.policy.policy_id != bundle.config_bundle.resolved_config.policy_id {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "config bundle embedded selected policy must match the resolved-config policy id",
        ));
    }
    if let Some(profile) = bundle.config_bundle.service_profile.as_ref() {
        if let Some(selected_profile_id) = bundle
            .config_bundle
            .resolved_config
            .selected_service_profile_entry_id
            .as_ref()
        {
            if selected_profile_id != &profile.profile.profile_id {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "config bundle embedded selected service profile must match the resolved-config selected service-profile entry when present",
                ));
            }
        }
    }
    if let Some(policy) = bundle.config_bundle.trust_policy.as_ref() {
        if bundle
            .config_bundle
            .resolved_config
            .trust_policy_id
            .as_deref()
            != Some(policy.policy_id.as_str())
        {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "config bundle embedded trust policy must match the resolved-config trust policy id",
            ));
        }
    } else if bundle
        .config_bundle
        .resolved_config
        .trust_policy_id
        .is_some()
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "config bundle resolved-config trust policy id requires an embedded trust policy",
        ));
    }

    Ok(())
}

/// Validate a decision-bundle artifact and fail closed on embedded lineage mismatches.
pub fn validate_decision_bundle(bundle: &DecisionBundleV1) -> Result<(), ArtifactValidationError> {
    validate_auxiliary_envelope(&bundle.envelope, DECISION_BUNDLE_SCHEMA_ID)?;
    validate_validation_report(&bundle.bundle.validation_report)?;
    validate_host_contract(&bundle.bundle.contract)?;
    if let Some(state) = bundle.bundle.state.as_ref() {
        validate_host_state(state)?;
    }
    if let Some(resolved_config) = bundle.bundle.resolved_config.as_ref() {
        validate_resolved_config(resolved_config).map_err(|error| {
            ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                error.message,
            )
        })?;
    }
    if let Some(config_bundle) = bundle.bundle.config_bundle.as_ref() {
        validate_config_bundle(config_bundle)?;
    }
    if let Some(verification_bundle) = bundle.bundle.verification_bundle.as_ref() {
        validate_verification_bundle_v1(verification_bundle).map_err(|error| {
            ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                error.message,
            )
        })?;
    }
    if let Some(recommendation_report) = bundle.bundle.recommendation_report.as_ref() {
        validate_recommendation_report(recommendation_report)?;
    }
    if bundle.bundle.resolved_config.is_some() && bundle.bundle.config_bundle.is_some() {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "decision bundle must not embed both raw resolved config and config bundle",
        ));
    }

    if is_blank(&bundle.bundle_basis.validation_report_artifact_id)
        || is_blank(&bundle.bundle_basis.validation_report_semantic_hash)
        || is_blank(&bundle.bundle_basis.contract_artifact_id)
        || is_blank(&bundle.bundle_basis.contract_semantic_hash)
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "decision bundle basis must include non-blank validation-report and contract lineage",
        ));
    }
    if bundle
        .bundle_basis
        .state_artifact_id
        .as_ref()
        .is_some_and(|value| is_blank(value))
        || bundle
            .bundle_basis
            .state_semantic_hash
            .as_ref()
            .is_some_and(|value| is_blank(value))
        || bundle
            .bundle_basis
            .config_bundle_artifact_id
            .as_ref()
            .is_some_and(|value| is_blank(value))
        || bundle
            .bundle_basis
            .config_bundle_semantic_hash
            .as_ref()
            .is_some_and(|value| is_blank(value))
        || bundle
            .bundle_basis
            .verification_bundle_id
            .as_ref()
            .is_some_and(|value| is_blank(value))
        || bundle
            .bundle_basis
            .recommendation_report_artifact_id
            .as_ref()
            .is_some_and(|value| is_blank(value))
        || bundle
            .bundle_basis
            .recommendation_report_semantic_hash
            .as_ref()
            .is_some_and(|value| is_blank(value))
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "decision bundle optional lineage fields must be non-blank when present",
        ));
    }
    if bundle.bundle_basis.validation_report_artifact_id
        != bundle.bundle.validation_report.envelope.artifact_id
        || bundle.bundle_basis.contract_artifact_id != bundle.bundle.contract.envelope.artifact_id
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "decision bundle basis artifact ids must match the embedded validation report and contract",
        ));
    }

    let validation_report_semantic_hash =
        semantic_hash_hex_for_validation_report(&bundle.bundle.validation_report)?;
    let contract_semantic_hash = semantic_hash_hex_for_contract(&bundle.bundle.contract)?;
    if bundle.bundle_basis.validation_report_semantic_hash != validation_report_semantic_hash
        || bundle.bundle_basis.contract_semantic_hash != contract_semantic_hash
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "decision bundle basis semantic hashes must match the embedded validation report and contract",
        ));
    }

    let validation_basis = &bundle.bundle.validation_report.validation_basis;
    if validation_basis.contract_artifact_id != bundle.bundle.contract.envelope.artifact_id
        || validation_basis.contract_semantic_hash != contract_semantic_hash
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "decision bundle embedded contract must match the validation basis contract lineage",
        ));
    }

    let report_has_state_lineage = validation_basis.state_artifact_id.is_some()
        || validation_basis.state_semantic_hash.is_some();
    let bundle_has_state_lineage = bundle.bundle_basis.state_artifact_id.is_some()
        || bundle.bundle_basis.state_semantic_hash.is_some();
    if report_has_state_lineage != bundle.bundle.state.is_some()
        || report_has_state_lineage != bundle_has_state_lineage
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "decision bundle state presence must align with validation-basis and bundle-basis state lineage",
        ));
    }
    if let Some(state) = bundle.bundle.state.as_ref() {
        let state_semantic_hash = semantic_hash_hex_for_state(state)?;
        if validation_basis.state_artifact_id.as_deref() != Some(&state.envelope.artifact_id)
            || validation_basis.state_semantic_hash.as_deref() != Some(state_semantic_hash.as_str())
            || bundle.bundle_basis.state_artifact_id.as_deref() != Some(&state.envelope.artifact_id)
            || bundle.bundle_basis.state_semantic_hash.as_deref()
                != Some(state_semantic_hash.as_str())
        {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "decision bundle embedded state must match the validation-basis and bundle-basis state lineage",
            ));
        }
    }
    let bundle_has_config_bundle_lineage = bundle.bundle_basis.config_bundle_artifact_id.is_some()
        || bundle.bundle_basis.config_bundle_semantic_hash.is_some();
    if bundle_has_config_bundle_lineage != bundle.bundle.config_bundle.is_some() {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "decision bundle config-bundle presence must align with bundle-basis config-bundle lineage",
        ));
    }
    if let Some(config_bundle) = bundle.bundle.config_bundle.as_ref() {
        let config_bundle_semantic_hash = semantic_hash_hex_for_config_bundle(config_bundle)?;
        if bundle.bundle_basis.config_bundle_artifact_id.as_deref()
            != Some(config_bundle.envelope.artifact_id.as_str())
            || bundle.bundle_basis.config_bundle_semantic_hash.as_deref()
                != Some(config_bundle_semantic_hash.as_str())
        {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "decision bundle embedded config bundle must match the bundle-basis config-bundle lineage",
            ));
        }

        let service_profile = config_bundle
            .config_bundle
            .service_profile
            .as_ref()
            .ok_or_else(|| {
                ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "decision bundle config bundle must embed the selected service profile used by the validation report",
                )
            })?;
        let service_profile_semantic_hash = semantic_hash_hex_for_service_profile(service_profile)?;
        if validation_basis.service_profile_artifact_id != service_profile.envelope.artifact_id
            || validation_basis.service_profile_semantic_hash != service_profile_semantic_hash
        {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "decision bundle config bundle selected service profile must match the embedded validation report basis",
            ));
        }

        let resolved_config = &config_bundle.config_bundle.resolved_config;
        if resolved_config
            .validation_mode
            .is_some_and(|mode| mode != validation_basis.validation_mode)
        {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "decision bundle config bundle validation_mode must match the embedded validation report when present",
            ));
        }
        if resolved_config.max_state_age_seconds.is_some()
            && resolved_config.max_state_age_seconds != validation_basis.max_state_age_seconds
        {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "decision bundle config bundle max_state_age_seconds must match the embedded validation report when present",
            ));
        }
    }
    let bundle_has_verification_bundle_lineage =
        bundle.bundle_basis.verification_bundle_id.is_some();
    if bundle_has_verification_bundle_lineage != bundle.bundle.verification_bundle.is_some() {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "decision bundle verification-bundle presence must align with bundle-basis verification-bundle lineage",
        ));
    }
    if let Some(verification_bundle) = bundle.bundle.verification_bundle.as_ref() {
        if bundle.bundle_basis.verification_bundle_id.as_deref()
            != Some(verification_bundle.bundle_id.as_str())
        {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "decision bundle embedded verification bundle must match the bundle-basis verification-bundle lineage",
            ));
        }
        if verification_bundle.artifact_schema_id != bundle.bundle.contract.envelope.schema_id
            || verification_bundle.artifact_id != bundle.bundle.contract.envelope.artifact_id
            || verification_bundle.artifact_semantic_hash != contract_semantic_hash
        {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "decision bundle embedded verification bundle must target the embedded contract lineage",
            ));
        }
        if let Some(config_bundle) = bundle.bundle.config_bundle.as_ref() {
            if config_bundle.config_bundle_basis.trust_policy_id.as_deref()
                != Some(verification_bundle.trust_policy_id.as_str())
            {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "decision bundle config bundle trust policy must match the embedded verification bundle when both are present",
                ));
            }
        }
    }
    let bundle_has_recommendation_report_lineage = bundle
        .bundle_basis
        .recommendation_report_artifact_id
        .is_some()
        || bundle
            .bundle_basis
            .recommendation_report_semantic_hash
            .is_some();
    if bundle
        .bundle_basis
        .recommendation_report_artifact_id
        .is_some()
        != bundle
            .bundle_basis
            .recommendation_report_semantic_hash
            .is_some()
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "decision bundle recommendation-report lineage fields must appear together",
        ));
    }
    if bundle_has_recommendation_report_lineage != bundle.bundle.recommendation_report.is_some() {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "decision bundle recommendation-report presence must align with bundle-basis recommendation-report lineage",
        ));
    }
    if let Some(recommendation_report) = bundle.bundle.recommendation_report.as_ref() {
        let recommendation_report_semantic_hash =
            semantic_hash_hex_for_recommendation_report(recommendation_report)?;
        if bundle
            .bundle_basis
            .recommendation_report_artifact_id
            .as_deref()
            != Some(recommendation_report.envelope.artifact_id.as_str())
            || bundle
                .bundle_basis
                .recommendation_report_semantic_hash
                .as_deref()
                != Some(recommendation_report_semantic_hash.as_str())
        {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "decision bundle embedded recommendation report must match the bundle-basis recommendation-report lineage",
            ));
        }
        if recommendation_report
            .recommendation_basis
            .validation_report_artifact_id
            != bundle.bundle.validation_report.envelope.artifact_id
            || recommendation_report
                .recommendation_basis
                .validation_report_semantic_hash
                != validation_report_semantic_hash
            || recommendation_report
                .recommendation_basis
                .validation_verdict
                != bundle.bundle.validation_report.report.verdict
        {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "decision bundle embedded recommendation report must target the embedded validation-report lineage",
            ));
        }

        let recommendation_has_state_lineage = recommendation_report
            .recommendation_basis
            .state_artifact_id
            .is_some()
            || recommendation_report
                .recommendation_basis
                .state_semantic_hash
                .is_some();
        if recommendation_has_state_lineage {
            let Some(state) = bundle.bundle.state.as_ref() else {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "decision bundle embedded recommendation report state lineage requires the embedded state",
                ));
            };
            let state_semantic_hash = semantic_hash_hex_for_state(state)?;
            if recommendation_report
                .recommendation_basis
                .state_artifact_id
                .as_deref()
                != Some(state.envelope.artifact_id.as_str())
                || recommendation_report
                    .recommendation_basis
                    .state_semantic_hash
                    .as_deref()
                    != Some(state_semantic_hash.as_str())
            {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "decision bundle embedded recommendation report state lineage must match the embedded state lineage",
                ));
            }
        }
    }
    if let Some(resolved_config) = bundle.bundle.resolved_config.as_ref() {
        if resolved_config
            .validation_mode
            .is_some_and(|mode| mode != validation_basis.validation_mode)
        {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "decision bundle resolved config validation_mode must match the embedded validation report",
            ));
        }
        if resolved_config.max_state_age_seconds.is_some()
            && resolved_config.max_state_age_seconds != validation_basis.max_state_age_seconds
        {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "decision bundle resolved config max_state_age_seconds must match the embedded validation report when present",
            ));
        }
    }

    Ok(())
}

fn validate_validation_basis_semantics(
    report: &ValidationReportV1,
) -> Result<(), ArtifactValidationError> {
    let has_state_lineage = report.validation_basis.state_artifact_id.is_some()
        && report.validation_basis.state_semantic_hash.is_some();
    let has_partial_state_lineage = report.validation_basis.state_artifact_id.is_some()
        ^ report.validation_basis.state_semantic_hash.is_some();
    let has_state_freshness_context = report.validation_basis.state_observed_at.is_some()
        && report.validation_basis.state_freshness_state.is_some();
    let has_partial_state_freshness_context = report.validation_basis.state_observed_at.is_some()
        ^ report.validation_basis.state_freshness_state.is_some();

    if has_partial_state_freshness_context {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "validation reports must carry complete state freshness context or none at all",
        ));
    }

    match report.validation_basis.validation_mode {
        ValidationModeV1::ContractOnly => {
            if report.validation_basis.state_artifact_id.is_some()
                || report.validation_basis.state_semantic_hash.is_some()
                || report.validation_basis.state_observed_at.is_some()
                || report.validation_basis.state_freshness_state.is_some()
                || report.validation_basis.max_state_age_seconds.is_some()
            {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "contract_only validation reports must not carry host-state freshness context",
                ));
            }
        }
        ValidationModeV1::StateAware => {
            if !has_state_lineage || !has_state_freshness_context {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "state_aware validation reports must carry host-state lineage and freshness context",
                ));
            }
        }
        ValidationModeV1::StateAdvisory | ValidationModeV1::StateRequired => {
            if has_partial_state_lineage {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "state_advisory and state_required validation reports must carry complete state lineage or none at all",
                ));
            }
            if has_state_lineage != has_state_freshness_context {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "state_advisory and state_required validation reports must keep state freshness context aligned with state lineage",
                ));
            }
            if !has_state_lineage
                && !matches!(
                    report.report.primary_reason_code,
                    ValidationReasonCodeV1::StateMissing | ValidationReasonCodeV1::StateStale
                )
            {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "state_advisory and state_required reports without state lineage must remain explicit about missing or stale state",
                ));
            }
        }
    }

    Ok(())
}

fn validate_envelope(
    envelope: &ArtifactEnvelopeV1,
    expected_schema_id: &str,
) -> Result<(), ArtifactValidationError> {
    if !is_supported_core_schema_id(&envelope.schema_id) || envelope.schema_id != expected_schema_id
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactSchemaIdInvalid,
            format!(
                "expected supported schema id {expected_schema_id}, got {}",
                envelope.schema_id
            ),
        ));
    }

    if envelope.schema_version != TOP_LEVEL_ARTIFACT_SCHEMA_VERSION {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactSchemaVersionInvalid,
            format!(
                "schema version {} is not supported for {}",
                envelope.schema_version, envelope.schema_id
            ),
        ));
    }

    if is_blank(&envelope.artifact_id)
        || is_blank(&envelope.provenance.source)
        || is_blank(&envelope.provenance.collected_at)
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "artifact identity and provenance fields must be populated",
        ));
    }

    validate_optional_provenance_string(
        envelope.provenance.fitctl_version.as_deref(),
        "fitctl_version",
    )?;
    validate_optional_provenance_string(
        envelope.provenance.fitctl_vcs_revision.as_deref(),
        "fitctl_vcs_revision",
    )?;
    validate_optional_provenance_string(
        envelope.provenance.fitctl_vcs_describe.as_deref(),
        "fitctl_vcs_describe",
    )?;
    validate_optional_provenance_string(
        envelope.provenance.command_name.as_deref(),
        "command_name",
    )?;
    validate_optional_provenance_string(
        envelope.provenance.correlation_id.as_deref(),
        "correlation_id",
    )?;

    if let Some(redaction) = envelope.redaction.as_ref() {
        if is_blank(&redaction.profile_id) || is_blank(&redaction.redacted_at) {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "artifact redaction metadata must be populated when present",
            ));
        }
    }

    let mut signature_tuples = HashSet::new();

    for signature in &envelope.signatures {
        validate_signature_entry(signature)?;

        let signature_tuple = (
            signature.key_id.as_str(),
            signature
                .payload_semantic_hash
                .as_deref()
                .unwrap_or_default(),
            signature.signature_namespace.as_deref().unwrap_or_default(),
        );

        if !signature_tuples.insert(signature_tuple) {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "signature entries must not contain duplicate key, payload-hash, and namespace tuples",
            ));
        }
    }

    Ok(())
}

fn validate_auxiliary_envelope(
    envelope: &ArtifactEnvelopeV1,
    expected_schema_id: &str,
) -> Result<(), ArtifactValidationError> {
    if envelope.schema_id != expected_schema_id {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactSchemaIdInvalid,
            format!(
                "expected supported schema id {expected_schema_id}, got {}",
                envelope.schema_id
            ),
        ));
    }

    if envelope.schema_version != TOP_LEVEL_ARTIFACT_SCHEMA_VERSION {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactSchemaVersionInvalid,
            format!(
                "schema version {} is not supported for {}",
                envelope.schema_version, envelope.schema_id
            ),
        ));
    }

    if is_blank(&envelope.artifact_id)
        || is_blank(&envelope.provenance.source)
        || is_blank(&envelope.provenance.collected_at)
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "artifact identity and provenance fields must be populated",
        ));
    }

    validate_optional_provenance_string(
        envelope.provenance.fitctl_version.as_deref(),
        "fitctl_version",
    )?;
    validate_optional_provenance_string(
        envelope.provenance.fitctl_vcs_revision.as_deref(),
        "fitctl_vcs_revision",
    )?;
    validate_optional_provenance_string(
        envelope.provenance.fitctl_vcs_describe.as_deref(),
        "fitctl_vcs_describe",
    )?;
    validate_optional_provenance_string(
        envelope.provenance.command_name.as_deref(),
        "command_name",
    )?;
    validate_optional_provenance_string(
        envelope.provenance.correlation_id.as_deref(),
        "correlation_id",
    )?;

    if let Some(redaction) = envelope.redaction.as_ref() {
        if is_blank(&redaction.profile_id) || is_blank(&redaction.redacted_at) {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "artifact redaction metadata must be populated when present",
            ));
        }
    }

    let mut signature_tuples = HashSet::new();
    for signature in &envelope.signatures {
        validate_signature_entry(signature)?;

        let signature_tuple = (
            signature.key_id.as_str(),
            signature
                .payload_semantic_hash
                .as_deref()
                .unwrap_or_default(),
            signature.signature_namespace.as_deref().unwrap_or_default(),
        );

        if !signature_tuples.insert(signature_tuple) {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "signature entries must not contain duplicate key, payload-hash, and namespace tuples",
            ));
        }
    }

    Ok(())
}

fn validate_local_execution_provenance(
    provenance: &ArtifactProvenanceV1,
) -> Result<(), ArtifactValidationError> {
    if option_is_blank(provenance.fitctl_version.as_deref())
        || option_is_blank(provenance.command_name.as_deref())
        || option_is_blank(provenance.correlation_id.as_deref())
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "local execution provenance must include fitctl_version, command_name, and correlation_id",
        ));
    }

    let Some(command_name) = provenance.command_name.as_deref() else {
        unreachable!("validated above")
    };
    if !matches!(command_name, "survey" | "contract" | "state" | "validate") {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "local execution provenance command_name must be a supported fitctl command",
        ));
    }

    Ok(())
}

fn validate_optional_provenance_string(
    value: Option<&str>,
    field_name: &str,
) -> Result<(), ArtifactValidationError> {
    if option_is_blank(value) && value.is_some() {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            format!("artifact {field_name} must be non-blank when present"),
        ));
    }

    Ok(())
}

fn validate_claim_metadata(metadata: &ClaimMetadataV1) -> Result<(), ArtifactValidationError> {
    if metadata.source_collectors.is_empty()
        || metadata
            .source_collectors
            .iter()
            .any(|value| is_blank(value))
        || metadata.evidence_paths.is_empty()
        || metadata.evidence_paths.iter().any(|value| is_blank(value))
        || metadata
            .policy_rule_id
            .as_ref()
            .is_some_and(|value| is_blank(value))
        || metadata
            .trust_evidence_refs
            .iter()
            .any(|value| is_blank(value))
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "claim metadata must include non-blank collectors and evidence paths",
        ));
    }

    Ok(())
}

fn validate_survey_field<T>(
    field: &SurveyFieldV1<T>,
    field_name: &str,
    validate_value: impl FnOnce(&T) -> bool,
) -> Result<(), ArtifactValidationError> {
    validate_observation_field_coherence_v1(
        &field.state,
        field.limitation_reason.as_ref(),
        field.value.as_ref(),
        validate_value,
    )
    .map_err(|message| {
        ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            format!("survey field {field_name} {message}"),
        )
    })
}

fn validate_identity_summary(summary: &IdentitySummaryV1) -> Result<(), ArtifactValidationError> {
    if is_blank(&summary.local_stable_id)
        || is_blank(&summary.composition_digest)
        || is_blank(&summary.provenance_fingerprint)
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "identity summary must include stable identity and digest fields",
        ));
    }

    let has_identity_v2_metadata = summary.local_stable_id_version != 0
        || summary.local_stable_anchor_family.is_some()
        || summary.local_stable_anchor_source.is_some()
        || summary.local_stable_stability_class.is_some()
        || summary.local_stable_id_degraded_reason.is_some();

    if !has_identity_v2_metadata {
        return Ok(());
    }

    if summary.local_stable_id_version != 2 {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "identity summary contains an unsupported local_stable_id_version",
        ));
    }

    let Some(anchor_family) = summary.local_stable_anchor_family else {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "identity summary v2 requires local_stable_anchor_family",
        ));
    };
    let Some(anchor_source) = summary.local_stable_anchor_source else {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "identity summary v2 requires local_stable_anchor_source",
        ));
    };
    let Some(stability_class) = summary.local_stable_stability_class else {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "identity summary v2 requires local_stable_stability_class",
        ));
    };

    match (anchor_family, anchor_source, stability_class) {
        (
            LocalStableAnchorFamilyV1::MachineId,
            LocalStableAnchorSourceV1::EtcMachineId | LocalStableAnchorSourceV1::DbusMachineId,
            LocalStableStabilityClassV1::OsInstanceLike,
        )
        | (
            LocalStableAnchorFamilyV1::DmiProductUuid,
            LocalStableAnchorSourceV1::SysfsDmiProductUuid,
            LocalStableStabilityClassV1::FirmwareOrVmLike,
        )
        | (
            LocalStableAnchorFamilyV1::Hostname,
            LocalStableAnchorSourceV1::KernelHostname,
            LocalStableStabilityClassV1::AliasOnly,
        )
        | (
            LocalStableAnchorFamilyV1::Fixture,
            LocalStableAnchorSourceV1::FixtureAlias,
            LocalStableStabilityClassV1::Fixture,
        ) => {}
        _ => {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "identity summary v2 contains an invalid family/source/stability combination",
            ));
        }
    }

    if summary.local_stable_id_degraded {
        if summary.local_stable_id_degraded_reason
            != Some(LocalStableIdDegradedReasonV1::HostnameFallback)
        {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "identity summary degraded identities require a supported degraded reason",
            ));
        }
        if anchor_family != LocalStableAnchorFamilyV1::Hostname
            || anchor_source != LocalStableAnchorSourceV1::KernelHostname
            || stability_class != LocalStableStabilityClassV1::AliasOnly
        {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "identity summary degraded hostname fallback must remain alias-only",
            ));
        }
    } else if summary.local_stable_id_degraded_reason.is_some() {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "identity summary non-degraded identities must not carry a degraded reason",
        ));
    }

    Ok(())
}

fn validate_state_local_identity(
    identity: &StateLocalIdentityV1,
) -> Result<(), ArtifactValidationError> {
    if is_blank(&identity.local_stable_id) {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "state local identity must include a non-blank local_stable_id",
        ));
    }
    if identity.local_stable_id_version != 2 {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "state local identity contains an unsupported local_stable_id_version",
        ));
    }

    match (
        identity.local_stable_anchor_family,
        identity.local_stable_anchor_source,
        identity.local_stable_stability_class,
    ) {
        (
            LocalStableAnchorFamilyV1::MachineId,
            LocalStableAnchorSourceV1::EtcMachineId | LocalStableAnchorSourceV1::DbusMachineId,
            LocalStableStabilityClassV1::OsInstanceLike,
        )
        | (
            LocalStableAnchorFamilyV1::DmiProductUuid,
            LocalStableAnchorSourceV1::SysfsDmiProductUuid,
            LocalStableStabilityClassV1::FirmwareOrVmLike,
        )
        | (
            LocalStableAnchorFamilyV1::Hostname,
            LocalStableAnchorSourceV1::KernelHostname,
            LocalStableStabilityClassV1::AliasOnly,
        )
        | (
            LocalStableAnchorFamilyV1::Fixture,
            LocalStableAnchorSourceV1::FixtureAlias,
            LocalStableStabilityClassV1::Fixture,
        ) => {}
        _ => {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "state local identity contains an invalid family/source/stability combination",
            ));
        }
    }

    if identity.local_stable_id_degraded {
        if identity.local_stable_id_degraded_reason
            != Some(LocalStableIdDegradedReasonV1::HostnameFallback)
        {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "state local identity degraded values require a supported degraded reason",
            ));
        }
        if identity.local_stable_anchor_family != LocalStableAnchorFamilyV1::Hostname
            || identity.local_stable_anchor_source != LocalStableAnchorSourceV1::KernelHostname
            || identity.local_stable_stability_class != LocalStableStabilityClassV1::AliasOnly
        {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "state local identity degraded hostname fallback must remain alias-only",
            ));
        }
    } else if identity.local_stable_id_degraded_reason.is_some() {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "state local identity non-degraded values must not carry a degraded reason",
        ));
    }

    Ok(())
}

fn validate_collector_metadata(
    collectors: &[CollectorMetadataV1],
    allowed_ids: &[&str],
    allowed_source_families: &[&str],
) -> Result<(), ArtifactValidationError> {
    let mut tuples = HashSet::new();

    for collector in collectors {
        if is_blank(&collector.collector_id)
            || is_blank(&collector.collector_version)
            || is_blank(&collector.source_family)
        {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "collector metadata entries must be fully populated",
            ));
        }
        if !allowed_ids
            .iter()
            .any(|value| *value == collector.collector_id)
        {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "collector metadata contains an unsupported collector_id",
            ));
        }
        if collector.collector_version != "1" {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "collector metadata contains an unsupported collector_version",
            ));
        }
        if !allowed_source_families
            .iter()
            .any(|value| *value == collector.source_family)
        {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "collector metadata contains an unsupported source_family",
            ));
        }

        let tuple = (
            collector.collector_id.as_str(),
            collector.collector_version.as_str(),
            collector.source_family.as_str(),
        );
        if !tuples.insert(tuple) {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "collector metadata entries must not duplicate collector_id, collector_version, and source_family tuples",
            ));
        }
    }

    Ok(())
}

fn validate_signature_entry(
    signature: &SignatureEnvelopeV1,
) -> Result<(), ArtifactValidationError> {
    if is_blank(&signature.key_id)
        || is_blank(&signature.signature)
        || option_is_blank(signature.signer_identity.as_deref())
        || option_is_blank(signature.public_key.as_deref())
        || option_is_blank(signature.signature_format.as_deref())
        || option_is_blank(signature.signature_namespace.as_deref())
        || option_is_blank(signature.payload_encoding.as_deref())
        || option_is_blank(signature.payload_semantic_hash.as_deref())
        || option_is_blank(signature.signed_at.as_deref())
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "signature entries must include populated signing metadata fields",
        ));
    }

    if signature.signer_identity.as_deref() != Some(signature.key_id.as_str())
        || signature.signature_format.as_deref() != Some("openssh_sshsig_v1")
        || signature.signature_namespace.as_deref() != Some("fitctl-artifact-v1")
        || signature.payload_encoding.as_deref() != Some("fitctl.semantic_cbor.v1")
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            "signature entries must use the pinned v1 signing metadata values",
        ));
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::validate_collector_metadata;
    use crate::artifacts::metadata_v1::CollectorMetadataV1;

    #[test]
    fn survey_collector_metadata_accepts_nvidia_procfs_gpu_info() {
        let collectors = [CollectorMetadataV1 {
            collector_id: "nvidia_procfs_gpu_info".to_string(),
            collector_version: "1".to_string(),
            source_family: "procfs".to_string(),
        }];

        let result = validate_collector_metadata(
            &collectors,
            &[
                "procfs",
                "cpuinfo_flags",
                "sysfs",
                "sysfs_cpu_topology",
                "sysfs_cpu_cache",
                "cgroupfs",
                "mountinfo",
                "netdev",
                "iproute2_addr",
                "iproute2_route",
                "pci_accelerators",
                "pci_driver_binding",
                "nvidia_procfs_gpu_info",
                "drm_class",
                "drm_platform_graphics",
                "devfs_accelerator_nodes",
                "block_and_filesystem",
            ],
            &[
                "procfs",
                "sysfs",
                "cgroupfs",
                "mountinfo",
                "netdev",
                "block_and_filesystem",
                "devfs",
            ],
        );

        assert!(result.is_ok());
    }
}

fn validate_contract_basis(
    contract_basis: &ContractBasisV1,
    expected_contract_schema_version: u32,
) -> Result<(), ArtifactValidationError> {
    let semantic_basis = &contract_basis.core_semantic_basis;
    let derivation_provenance = &contract_basis.derivation_provenance;

    if is_blank(&semantic_basis.source_survey_semantic_hash)
        || is_blank(&semantic_basis.policy_semantic_hash)
        || is_blank(&semantic_basis.derivation_engine_id)
        || is_blank(&semantic_basis.derivation_engine_version)
        || semantic_basis.contract_schema_version != expected_contract_schema_version
        || semantic_basis.selected_policy_layers.is_empty()
        || semantic_basis
            .selected_policy_layers
            .iter()
            .any(|layer| is_blank(layer))
        || is_blank(&derivation_provenance.derived_at)
    {
        return Err(ArtifactValidationError::new(
            ArtifactValidationErrorCode::ContractBasisInvalid,
            "contract basis must include semantic inputs and derivation provenance",
        ));
    }

    if let Some(extension_basis) = &contract_basis.extension_basis {
        if extension_basis.enabled_extension_namespaces.is_empty()
            || extension_basis.extension_semantic_hashes.is_empty()
            || extension_basis
                .enabled_extension_namespaces
                .iter()
                .any(|value| is_blank(value))
            || extension_basis
                .extension_semantic_hashes
                .iter()
                .any(|(namespace, hash)| is_blank(namespace) || is_blank(hash))
        {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ContractBasisInvalid,
                "contract extension basis must include non-blank namespaces and semantic hashes when present",
            ));
        }
    }

    Ok(())
}

fn validate_state_field<T>(
    field: &StateFieldV1<T>,
    field_name: &str,
    validate_value: impl FnOnce(&T) -> bool,
) -> Result<(), ArtifactValidationError> {
    validate_observation_field_coherence_v1(
        &field.state,
        field.limitation_reason.as_ref(),
        field.value.as_ref(),
        validate_value,
    )
    .map_err(|message| {
        ArtifactValidationError::new(
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
            format!("host-state field {field_name} {message}"),
        )
    })
}

fn validate_state_memory_accounting(state: &HostStateV1) -> Result<(), ArtifactValidationError> {
    let total = scalar_state_value(&state.state.core_state.resources.memory_total_bytes);
    let allocatable =
        scalar_state_value(&state.state.core_state.resources.allocatable_memory_bytes);
    let used = scalar_state_value(
        &state
            .state
            .core_state
            .resources
            .memory_used_excluding_cache_bytes,
    );
    let allocatable_cpu = scalar_state_value(
        &state
            .state
            .core_state
            .resources
            .allocatable_cpu_logical_cores,
    );
    let cpuset_cpu =
        scalar_state_value(&state.state.core_state.boundaries.cpuset_cpu_logical_cores);
    let quota_cpu = scalar_state_value(&state.state.core_state.boundaries.cpu_quota_logical_cores);
    let memory_limit = scalar_state_value(&state.state.core_state.boundaries.memory_limit_bytes);
    let memory_current =
        scalar_state_value(&state.state.core_state.boundaries.memory_current_bytes);

    if let (Some(total), Some(allocatable)) = (total, allocatable) {
        if allocatable > total {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "host-state allocatable_memory_bytes must not exceed memory_total_bytes",
            ));
        }
    }

    if let (Some(total), Some(used)) = (total, used) {
        if used > total {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "host-state memory_used_excluding_cache_bytes must not exceed memory_total_bytes",
            ));
        }
    }

    if let (Some(allocatable_cpu), Some(cpuset_cpu)) = (allocatable_cpu, cpuset_cpu) {
        if allocatable_cpu > cpuset_cpu {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "host-state allocatable_cpu_logical_cores must not exceed cpuset_cpu_logical_cores",
            ));
        }
    }

    if let (Some(allocatable_cpu), Some(quota_cpu)) = (allocatable_cpu, quota_cpu) {
        if allocatable_cpu > quota_cpu {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "host-state allocatable_cpu_logical_cores must not exceed cpu_quota_logical_cores",
            ));
        }
    }

    if let (Some(memory_limit), Some(memory_current)) = (memory_limit, memory_current) {
        if memory_current > memory_limit {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                "host-state memory_current_bytes must not exceed memory_limit_bytes",
            ));
        }
        if let Some(allocatable) = allocatable {
            let boundary_headroom = memory_limit.saturating_sub(memory_current);
            if allocatable > boundary_headroom {
                return Err(ArtifactValidationError::new(
                    ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                    "host-state allocatable_memory_bytes must not exceed cgroup memory headroom",
                ));
            }
        }
    }

    Ok(())
}

fn validate_namespaced_json_map(
    values: &BTreeMap<String, serde_json::Value>,
    label: &str,
) -> Result<(), ArtifactValidationError> {
    for (namespace, value) in values {
        if is_blank(namespace)
            || namespace
                .split('.')
                .any(|segment| segment.is_empty() || !segment.chars().all(is_namespace_char))
        {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                format!("{label} contains an invalid namespace key"),
            ));
        }

        if !value.is_object() || value.is_null() {
            return Err(ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                format!("{label} values must be non-null objects"),
            ));
        }
    }

    Ok(())
}

fn validate_known_extension_evidence(
    values: &BTreeMap<String, serde_json::Value>,
) -> Result<(), ArtifactValidationError> {
    if let Some(value) = values.get(CUDA_RUNTIME_NAMESPACE) {
        decode_cuda_runtime_evidence_from_value(value).map_err(|error| {
            ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                format!(
                    "host survey CUDA runtime extension evidence is invalid: {}",
                    error.message
                ),
            )
        })?;
    }
    if let Some(value) = values.get(NODE_RUNTIME_NAMESPACE) {
        decode_node_runtime_evidence_from_value(value).map_err(|error| {
            ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                format!(
                    "host survey Node runtime extension evidence is invalid: {}",
                    error.message
                ),
            )
        })?;
    }
    if let Some(value) = values.get(PYTHON_RUNTIME_NAMESPACE) {
        decode_python_runtime_evidence_from_value(value).map_err(|error| {
            ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                format!(
                    "host survey Python runtime extension evidence is invalid: {}",
                    error.message
                ),
            )
        })?;
    }
    Ok(())
}

fn validate_known_extension_contract(
    values: &BTreeMap<String, serde_json::Value>,
) -> Result<(), ArtifactValidationError> {
    if let Some(value) = values.get(CUDA_RUNTIME_NAMESPACE) {
        decode_cuda_runtime_contract_from_value(value).map_err(|error| {
            ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                format!(
                    "host contract CUDA runtime extension contract is invalid: {}",
                    error.message
                ),
            )
        })?;
    }
    if let Some(value) = values.get(NODE_RUNTIME_NAMESPACE) {
        decode_node_runtime_contract_from_value(value).map_err(|error| {
            ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                format!(
                    "host contract Node runtime extension contract is invalid: {}",
                    error.message
                ),
            )
        })?;
    }
    if let Some(value) = values.get(PYTHON_RUNTIME_NAMESPACE) {
        decode_python_runtime_contract_from_value(value).map_err(|error| {
            ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                format!(
                    "host contract Python runtime extension contract is invalid: {}",
                    error.message
                ),
            )
        })?;
    }
    Ok(())
}

fn validate_known_extension_requirements(
    values: &BTreeMap<String, serde_json::Value>,
) -> Result<(), ArtifactValidationError> {
    if let Some(value) = values.get(CUDA_RUNTIME_NAMESPACE) {
        decode_cuda_runtime_requirement_from_value(value).map_err(|error| {
            ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                format!(
                    "service profile CUDA runtime extension requirement is invalid: {}",
                    error.message
                ),
            )
        })?;
    }
    if let Some(value) = values.get(NODE_RUNTIME_NAMESPACE) {
        decode_node_runtime_requirement_from_value(value).map_err(|error| {
            ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                format!(
                    "service profile Node runtime extension requirement is invalid: {}",
                    error.message
                ),
            )
        })?;
    }
    if let Some(value) = values.get(PYTHON_RUNTIME_NAMESPACE) {
        decode_python_runtime_requirement_from_value(value).map_err(|error| {
            ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                format!(
                    "service profile Python runtime extension requirement is invalid: {}",
                    error.message
                ),
            )
        })?;
    }
    Ok(())
}

fn validate_known_extension_state(
    values: &BTreeMap<String, serde_json::Value>,
) -> Result<(), ArtifactValidationError> {
    if let Some(value) = values.get(CUDA_RUNTIME_NAMESPACE) {
        decode_cuda_runtime_state_from_value(value).map_err(|error| {
            ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                format!(
                    "host state CUDA runtime extension state is invalid: {}",
                    error.message
                ),
            )
        })?;
    }
    Ok(())
}

fn validate_known_validation_extension_diagnostics(
    values: &BTreeMap<String, serde_json::Value>,
) -> Result<(), ArtifactValidationError> {
    if let Some(value) = values.get(CUDA_RUNTIME_NAMESPACE) {
        decode_cuda_runtime_validation_diagnostic_from_value(value).map_err(|error| {
            ArtifactValidationError::new(
                ArtifactValidationErrorCode::ArtifactPayloadCorrupt,
                format!(
                    "validation report CUDA runtime extension diagnostic is invalid: {}",
                    error.message
                ),
            )
        })?;
    }
    Ok(())
}

fn is_namespace_char(value: char) -> bool {
    value.is_ascii_lowercase() || value.is_ascii_digit() || matches!(value, '-' | '_')
}

fn scalar_state_value<T: Copy>(field: &StateFieldV1<T>) -> Option<T> {
    match (&field.state, &field.value) {
        (ObservationStateV1::Observed, Some(value))
        | (ObservationStateV1::PartiallyObserved, Some(value)) => Some(*value),
        _ => None,
    }
}

fn is_blank(value: &str) -> bool {
    value.trim().is_empty()
}

fn option_is_blank(value: Option<&str>) -> bool {
    value.is_none_or(is_blank)
}
