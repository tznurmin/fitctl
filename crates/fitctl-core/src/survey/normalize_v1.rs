// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Normalize collected host-survey snapshots into host-survey.v1 artifacts.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::artifacts::envelope_v1::{local_artifact_provenance_v1, ArtifactEnvelopeV1};
use crate::artifacts::metadata_v1::{
    AssuranceSourceV1, ClaimMetadataV1, CollectorMetadataV1, DerivationStageV1, IdentityClassV1,
    IdentitySummaryV1,
};
use crate::artifacts::schema_ids_v1::HOST_SURVEY_SCHEMA_ID;
use crate::artifacts::survey_v1::{
    encode_host_survey_payload, HostSurveyCoreEvidenceV1, HostSurveyPayloadV1, HostSurveyV1,
    SurveySectionMetadataV1,
};
use crate::artifacts::validation_v1::validate_host_survey;
use crate::identity::{
    derive_composition_digest_v1, derive_local_stable_id_v1, derive_provenance_fingerprint_v1,
};
use crate::survey::collector_matrix_v1::is_supported_collector_family;
use crate::survey::live_v1::{
    AcceleratorDetailsV1, AcceleratorDeviceV1, AcceleratorDiscoverySourceV1,
    AcceleratorOperabilityV1, CollectedHostSnapshotV1, CpuCacheSummaryV1, CpuDetailsV1,
    IpAddressFamilyV1, MemoryDetailsV1, NetworkAddressV1, NetworkAddressabilitySummaryV1,
    NetworkDetailsV1, NetworkInterfaceV1, SnapshotSourceKindV1, StaticOperabilityV1,
    StorageDetailsV1, SurveyFieldV1, SurveyObservationsV1, TopologyDetailsV1,
};
use crate::survey::{validate_observation_field_coherence_v1, SurveyError, SurveyErrorCode};

pub(crate) fn build_host_survey_from_snapshot(
    mut snapshot: CollectedHostSnapshotV1,
) -> Result<HostSurveyV1, SurveyError> {
    if snapshot.collectors.is_empty() {
        return Err(SurveyError::new(
            SurveyErrorCode::CollectorPayloadMalformed,
            "collector_parse",
            "snapshot must contain at least one collector id",
        ));
    }

    if snapshot.collectors.iter().any(|collector| {
        !is_supported_collector_family(survey_source_family_for_collector(collector))
    }) {
        return Err(SurveyError::new(
            SurveyErrorCode::CollectorPayloadMalformed,
            "collector_parse",
            "snapshot contains an unsupported collector family",
        ));
    }

    validate_observations(&snapshot.observations)?;
    canonicalise_snapshot(&mut snapshot);

    let artifact_id = format!("survey-{}", sanitize_identifier(&snapshot.snapshot_id));
    let payload = HostSurveyPayloadV1 {
        collection_mode: source_kind_label(&snapshot.source_kind).to_string(),
        snapshot_id: snapshot.snapshot_id.clone(),
        host_alias: snapshot.host_alias.clone(),
        source_ref: snapshot.provenance_source.clone(),
        core_evidence: HostSurveyCoreEvidenceV1 {
            execution_context: snapshot.execution_context.clone(),
            collectors: typed_collectors_from_snapshot(&snapshot.collectors),
            section_metadata: build_section_metadata(&snapshot),
            identity_summary: build_identity_summary(&snapshot),
            observations: snapshot.observations.clone(),
        },
        extension_evidence: Default::default(),
    };

    let survey = encode_host_survey_payload(&payload).map_err(|error| {
        SurveyError::new(
            SurveyErrorCode::NormalizationFailed,
            "normalize_observation",
            format!("failed to encode normalized survey payload: {error}"),
        )
    })?;

    let artifact = HostSurveyV1 {
        envelope: ArtifactEnvelopeV1 {
            schema_id: HOST_SURVEY_SCHEMA_ID.to_string(),
            schema_version: 1,
            artifact_id: artifact_id.clone(),
            provenance: local_artifact_provenance_v1(
                snapshot.provenance_source,
                snapshot.collected_at,
                "survey",
                artifact_id,
            ),
            redaction: None,
            signatures: vec![],
        },
        survey,
    };

    validate_host_survey(&artifact).map_err(|error| {
        SurveyError::new(
            SurveyErrorCode::SurveyArtifactInvalid,
            "survey_emit",
            error.message,
        )
    })?;

    Ok(artifact)
}

fn build_section_metadata(snapshot: &CollectedHostSnapshotV1) -> SurveySectionMetadataV1 {
    let base = ClaimMetadataV1 {
        assurance_source: AssuranceSourceV1::SelfObserved,
        derivation_stage: DerivationStageV1::Normalized,
        source_collectors: snapshot.collectors.clone(),
        evidence_paths: Vec::new(),
        policy_rule_id: None,
        trust_evidence_refs: Vec::new(),
    };

    SurveySectionMetadataV1 {
        execution_context: ClaimMetadataV1 {
            evidence_paths: vec!["$.survey.core_evidence.execution_context".to_string()],
            ..base.clone()
        },
        hostname: ClaimMetadataV1 {
            evidence_paths: vec!["$.survey.core_evidence.observations.hostname".to_string()],
            ..base.clone()
        },
        cpu: ClaimMetadataV1 {
            evidence_paths: vec!["$.survey.core_evidence.observations.cpu".to_string()],
            ..base.clone()
        },
        memory: ClaimMetadataV1 {
            evidence_paths: vec!["$.survey.core_evidence.observations.memory".to_string()],
            ..base.clone()
        },
        storage: ClaimMetadataV1 {
            evidence_paths: vec!["$.survey.core_evidence.observations.storage".to_string()],
            ..base.clone()
        },
        network: ClaimMetadataV1 {
            evidence_paths: vec!["$.survey.core_evidence.observations.network".to_string()],
            ..base
        },
        accelerators: ClaimMetadataV1 {
            evidence_paths: vec!["$.survey.core_evidence.observations.accelerators".to_string()],
            assurance_source: AssuranceSourceV1::SelfObserved,
            derivation_stage: DerivationStageV1::Normalized,
            source_collectors: snapshot.collectors.clone(),
            policy_rule_id: None,
            trust_evidence_refs: Vec::new(),
        },
        topology: ClaimMetadataV1 {
            evidence_paths: vec!["$.survey.core_evidence.observations.topology".to_string()],
            assurance_source: AssuranceSourceV1::SelfObserved,
            derivation_stage: DerivationStageV1::Normalized,
            source_collectors: snapshot.collectors.clone(),
            policy_rule_id: None,
            trust_evidence_refs: Vec::new(),
        },
    }
}

fn build_identity_summary(snapshot: &CollectedHostSnapshotV1) -> IdentitySummaryV1 {
    let local_stable_id =
        derive_local_stable_id_v1(&snapshot.host_alias, &snapshot.provenance_source);
    let composition_digest = derive_composition_digest_v1(
        snapshot
            .observations
            .cpu
            .value
            .as_ref()
            .map(|value| value.logical_cores),
        snapshot
            .observations
            .memory
            .value
            .as_ref()
            .map(|value| value.total_bytes),
        snapshot
            .observations
            .storage
            .value
            .as_ref()
            .map(|value| value.block_devices.len())
            .unwrap_or_default(),
        snapshot
            .observations
            .storage
            .value
            .as_ref()
            .map(|value| value.mounts.len())
            .unwrap_or_default(),
        snapshot
            .observations
            .network
            .value
            .as_ref()
            .map(|value| value.interfaces.len())
            .unwrap_or_default(),
        snapshot
            .observations
            .accelerators
            .value
            .as_ref()
            .map(|value| value.devices.len())
            .unwrap_or_default(),
        snapshot.execution_context.visibility_scope.clone(),
    );
    let provenance_fingerprint = derive_provenance_fingerprint_v1(
        &local_stable_id,
        &snapshot.collectors,
        snapshot.execution_context.visibility_scope.clone(),
        snapshot.execution_context.container_runtime.as_deref(),
    );

    IdentitySummaryV1 {
        identity_class: IdentityClassV1::LocalStable,
        local_stable_id,
        composition_digest,
        provenance_fingerprint,
    }
}

fn typed_collectors_from_snapshot(collectors: &[String]) -> Vec<CollectorMetadataV1> {
    collectors
        .iter()
        .map(|collector_id| CollectorMetadataV1 {
            collector_id: collector_id.clone(),
            collector_version: "1".to_string(),
            source_family: survey_source_family_for_collector(collector_id).to_string(),
        })
        .collect()
}

fn validate_observations(observations: &SurveyObservationsV1) -> Result<(), SurveyError> {
    validate_field(&observations.hostname, "hostname", |value| {
        !value.trim().is_empty()
    })?;
    validate_field(&observations.cpu, "cpu", validate_cpu_details)?;
    validate_field(&observations.memory, "memory", |value: &MemoryDetailsV1| {
        value.total_bytes > 0
    })?;
    validate_field(
        &observations.storage,
        "storage",
        |_value: &StorageDetailsV1| true,
    )?;
    validate_field(&observations.network, "network", validate_network_details)?;
    validate_field(
        &observations.accelerators,
        "accelerators",
        validate_accelerator_details,
    )?;
    validate_field(
        &observations.topology,
        "topology",
        |value: &TopologyDetailsV1| value.numa_nodes > 0 && value.cpu_packages > 0,
    )?;
    Ok(())
}

fn validate_field<T>(
    field: &SurveyFieldV1<T>,
    field_name: &str,
    validate_value: impl FnOnce(&T) -> bool,
) -> Result<(), SurveyError> {
    validate_observation_field_coherence_v1(
        &field.state,
        field.limitation_reason.as_ref(),
        field.value.as_ref(),
        validate_value,
    )
    .map_err(|message| {
        SurveyError::new(
            SurveyErrorCode::NormalizationFailed,
            "normalize_observation",
            format!("field {field_name} {message}"),
        )
    })
}

fn canonicalise_snapshot(snapshot: &mut CollectedHostSnapshotV1) {
    snapshot.collectors.sort();
    snapshot.collectors.dedup();

    if let Some(storage) = snapshot.observations.storage.value.as_mut() {
        storage.block_devices.sort();
        storage.block_devices.dedup();
        storage.mounts.sort();
        storage.mounts.dedup();
        storage
            .block_device_details
            .sort_by(|left, right| left.name.cmp(&right.name));
        storage
            .mount_details
            .sort_by(|left, right| left.path.cmp(&right.path));
    }

    if let Some(network) = snapshot.observations.network.value.as_mut() {
        network.interfaces.sort();
        network.interfaces.dedup();
        for detail in &mut network.interface_details {
            detail.addresses.sort_by(|left, right| {
                left.family
                    .cmp(&right.family)
                    .then_with(|| left.address.cmp(&right.address))
                    .then_with(|| left.prefix_len.cmp(&right.prefix_len))
            });
            detail.addresses.dedup();
        }
        network
            .interface_details
            .sort_by(|left, right| left.name.cmp(&right.name));
        if let Some(summary) = network.addressability_summary.as_mut() {
            if let Some(families) = summary.non_loopback_address_families.as_mut() {
                families.sort();
                families.dedup();
            }
            if let Some(families) = summary.default_route_families.as_mut() {
                families.sort();
                families.dedup();
            }
        }
    }

    if let Some(accelerators) = snapshot.observations.accelerators.value.as_mut() {
        for device in &mut accelerators.devices {
            if let Some(driver) = device.driver.as_mut() {
                *driver = driver.trim().to_string();
            }
        }
        accelerators.devices.sort_by(|left, right| {
            left.kind
                .cmp(&right.kind)
                .then_with(|| left.discovery_source.cmp(&right.discovery_source))
                .then_with(|| left.vendor.cmp(&right.vendor))
                .then_with(|| left.vendor_id.cmp(&right.vendor_id))
                .then_with(|| left.device_id.cmp(&right.device_id))
                .then_with(|| left.pci_address.cmp(&right.pci_address))
        });
        if let Some(operability) = accelerators.operability.as_mut() {
            operability.visible_device_nodes.sort();
            operability.visible_device_nodes.dedup();
        }
    }

    if let Some(cpu) = snapshot.observations.cpu.value.as_mut() {
        cpu.feature_flags.sort();
        cpu.feature_flags.dedup();
    }

    snapshot.execution_context.notes.sort();
    snapshot.execution_context.notes.dedup();
}

fn validate_network_details(details: &NetworkDetailsV1) -> bool {
    let interface_names = details
        .interfaces
        .iter()
        .map(|value| value.trim())
        .collect::<Vec<_>>();
    if interface_names.is_empty() || interface_names.iter().any(|value| value.is_empty()) {
        return false;
    }

    let mut sorted_names = interface_names
        .iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>();
    sorted_names.sort();
    sorted_names.dedup();
    if sorted_names.len() != details.interfaces.len() {
        return false;
    }

    let mut detail_names = Vec::with_capacity(details.interface_details.len());
    for detail in &details.interface_details {
        if !validate_interface_detail(detail) {
            return false;
        }
        detail_names.push(detail.name.clone());
    }

    detail_names.sort();
    detail_names.dedup();
    if detail_names.len() != details.interface_details.len() {
        return false;
    }
    if !details.interface_details.is_empty() && detail_names != sorted_names {
        return false;
    }

    details
        .addressability_summary
        .as_ref()
        .is_none_or(validate_network_addressability_summary)
}

fn validate_interface_detail(detail: &NetworkInterfaceV1) -> bool {
    !detail.name.trim().is_empty()
        && detail.mtu.is_none_or(|value| value > 0)
        && detail.speed_mbps.is_none_or(|value| value > 0)
        && validate_interface_kind_and_virtuality(detail)
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

fn validate_interface_kind_and_virtuality(detail: &NetworkInterfaceV1) -> bool {
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

fn validate_accelerator_details(details: &AcceleratorDetailsV1) -> bool {
    details.devices.iter().all(validate_accelerator_device)
        && details.operability.as_ref().is_none_or(|operability| {
            validate_accelerator_operability(operability, details.devices.len())
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
        StaticOperabilityV1::NotOperable => operability.driver_bound_devices == 0,
        StaticOperabilityV1::Indeterminate => {
            operability.driver_bound_devices > 0
                && (operability.driver_bound_devices < total_devices_u32
                    || visible_nodes.is_empty())
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
            .is_none_or(|value| !value.trim().is_empty())
        && device.vendor_id.as_deref().is_none_or(is_valid_pci_hex_id)
        && device.device_id.as_deref().is_none_or(is_valid_pci_hex_id)
        && device
            .pci_address
            .as_deref()
            .is_none_or(is_valid_pci_address)
        && device
            .driver
            .as_deref()
            .is_none_or(|value| !value.trim().is_empty())
}

fn validate_cpu_details(details: &CpuDetailsV1) -> bool {
    if details.architecture.trim().is_empty()
        || details.logical_cores == 0
        || details.model.trim().is_empty()
        || details
            .physical_cores
            .is_some_and(|value| value == 0 || value > details.logical_cores)
        || details.threads_per_core.is_some_and(|value| value == 0)
        || details
            .feature_flags
            .iter()
            .any(|value| value.trim().is_empty())
    {
        return false;
    }

    let mut flags = details.feature_flags.clone();
    let original_len = flags.len();
    flags.sort();
    flags.dedup();
    if flags.len() != original_len || flags != details.feature_flags {
        return false;
    }

    if let (Some(physical_cores), Some(threads_per_core)) =
        (details.physical_cores, details.threads_per_core)
    {
        let Some(expected_logical_cores) = physical_cores.checked_mul(threads_per_core) else {
            return false;
        };
        if expected_logical_cores != details.logical_cores {
            return false;
        }
    }

    details
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

fn is_valid_mac_address(value: &str) -> bool {
    if value.trim().is_empty() {
        return false;
    }

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

fn survey_source_family_for_collector(collector_id: &str) -> &str {
    match collector_id {
        "cpuinfo_flags" => "procfs",
        "devfs_accelerator_nodes" => "devfs",
        "drm_class" | "drm_platform_graphics" => "sysfs",
        "iproute2_addr" => "netdev",
        "iproute2_route" => "netdev",
        "pci_accelerators" => "sysfs",
        "pci_driver_binding" | "sysfs_cpu_topology" | "sysfs_cpu_cache" => "sysfs",
        _ => collector_id,
    }
}

fn source_kind_label(source_kind: &SnapshotSourceKindV1) -> &'static str {
    match source_kind {
        SnapshotSourceKindV1::Live => "live",
        SnapshotSourceKindV1::Replay { .. } => "replay",
    }
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
