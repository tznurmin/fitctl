// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Helpers for generating reviewable storage-oriented service profiles from observed state.

use std::collections::BTreeMap;

use crate::artifacts::envelope_v1::{ArtifactEnvelopeV1, ArtifactProvenanceV1};
use crate::artifacts::schema_ids_v1::{
    SERVICE_PROFILE_SCHEMA_ID, TOP_LEVEL_ARTIFACT_SCHEMA_VERSION,
};
use crate::artifacts::service_profile_v1::{
    ServiceExclusionsV1, ServicePathLinkPairRequirementV1, ServicePathRequirementV1,
    ServicePreferencesV1, ServiceProfilePayloadV1, ServiceProfileV1, ServiceRequirementsV1,
};
use crate::artifacts::state_v1::{
    HostStatePathLinkPairV1, HostStateV1, StateFieldV1, StateStorageDurabilityClassV1,
    StateStorageMediaClassV1,
};
use crate::survey::{ObservationStateV1, VisibilityScopeV1};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageProfileInitRequestV1 {
    pub state: HostStateV1,
    pub profile_id: String,
    pub display_name: Option<String>,
    pub short_display_name: Option<String>,
    pub primary_capability_class: String,
    pub min_available_bytes_by_path_id: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageProfileError {
    pub message: String,
}

impl StorageProfileError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for StorageProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.message.fmt(f)
    }
}

impl std::error::Error for StorageProfileError {}

pub fn init_storage_profile_v1(
    request: StorageProfileInitRequestV1,
) -> Result<ServiceProfileV1, StorageProfileError> {
    if request
        .state
        .state
        .core_state
        .path_resources
        .paths
        .is_empty()
    {
        return Err(StorageProfileError::new(
            "storage profile init requires at least one checked path",
        ));
    }
    for path_id in request.min_available_bytes_by_path_id.keys() {
        if !request
            .state
            .state
            .core_state
            .path_resources
            .paths
            .iter()
            .any(|path| &path.path_id == path_id)
        {
            return Err(StorageProfileError::new(format!(
                "minimum available bytes declared for unknown path id {path_id}"
            )));
        }
    }

    let required_paths = request
        .state
        .state
        .core_state
        .path_resources
        .paths
        .iter()
        .map(|path| {
            let mut requirement = ServicePathRequirementV1 {
                path_id: path.path_id.clone(),
                min_available_bytes: request
                    .min_available_bytes_by_path_id
                    .get(&path.path_id)
                    .copied(),
                accepted_media_classes: Vec::new(),
                accepted_durability_classes: Vec::new(),
                required_filesystem_types: Vec::new(),
                accepted_filesystem_uuids: Vec::new(),
                accepted_partition_uuids: Vec::new(),
                accepted_persistent_device_links: Vec::new(),
                require_hardlink: None,
                require_reflink: None,
                require_symlink: None,
                require_copy: None,
                storage_health: None,
            };
            if let Some(media_class) = observed_value(&path.media_class)
                .filter(|value| *value != StateStorageMediaClassV1::Unknown)
            {
                requirement.accepted_media_classes.push(media_class);
            }
            if let Some(durability_class) = observed_value(&path.durability_class)
                .filter(|value| *value != StateStorageDurabilityClassV1::Unknown)
            {
                requirement
                    .accepted_durability_classes
                    .push(durability_class);
            }
            if let Some(filesystem_type) = observed_value(&path.filesystem_type) {
                requirement.required_filesystem_types.push(filesystem_type);
            }
            if let Some(filesystem_uuid) = observed_value(&path.filesystem_uuid) {
                requirement.accepted_filesystem_uuids.push(filesystem_uuid);
            }
            if let Some(partition_uuid) = observed_value(&path.partition_uuid) {
                requirement.accepted_partition_uuids.push(partition_uuid);
            }
            if let Some(persistent_links) = observed_value(&path.persistent_device_links) {
                requirement.accepted_persistent_device_links = persistent_links;
            }
            if let Some(link_capabilities) = path.link_capabilities.as_ref() {
                requirement.require_hardlink =
                    true_capability(&link_capabilities.hardlink_supported);
                requirement.require_reflink = true_capability(&link_capabilities.reflink_supported);
                requirement.require_symlink = true_capability(&link_capabilities.symlink_supported);
                requirement.require_copy = true_capability(&link_capabilities.copy_possible);
            }
            requirement
        })
        .collect::<Vec<_>>();

    let required_path_link_pairs = request
        .state
        .state
        .core_state
        .path_resources
        .link_pairs
        .iter()
        .filter_map(path_link_pair_requirement_from_state)
        .collect();

    Ok(ServiceProfileV1 {
        envelope: ArtifactEnvelopeV1 {
            schema_id: SERVICE_PROFILE_SCHEMA_ID.to_string(),
            schema_version: TOP_LEVEL_ARTIFACT_SCHEMA_VERSION,
            artifact_id: format!("service-profile-{}", request.profile_id.replace('_', "-")),
            provenance: ArtifactProvenanceV1 {
                source: "live:storage_profile_init_v1".to_string(),
                collected_at: request.state.envelope.provenance.collected_at,
                fitctl_version: None,
                fitctl_vcs_revision: None,
                fitctl_vcs_describe: None,
                fitctl_build_dirty: None,
                command_name: None,
                correlation_id: None,
            },
            redaction: None,
            signatures: Vec::new(),
        },
        profile: ServiceProfilePayloadV1 {
            profile_id: request.profile_id,
            display_name: request.display_name,
            short_display_name: request.short_display_name,
            core_requirements: ServiceRequirementsV1 {
                primary_capability_class: request.primary_capability_class,
                allowed_visibility_scopes: vec![
                    VisibilityScopeV1::BareMetalLike,
                    VisibilityScopeV1::VmLike,
                ],
                min_allocatable_cpu_logical_cores: None,
                min_allocatable_memory_bytes: None,
                min_non_loopback_interfaces: None,
                min_network_link_speed_mbps: None,
                required_network_interface_kinds: Vec::new(),
                min_numa_nodes: None,
                max_numa_nodes: None,
                min_cpu_packages: None,
                min_policy_scoped_accelerators: None,
                require_accelerator_locality_known: false,
                max_accelerator_numa_nodes: None,
                required_paths,
                path_relationships: Vec::new(),
                required_path_link_pairs,
                required_thermal_sensors: Vec::new(),
                required_memory_reliability: None,
                required_gpu_reliability: None,
            },
            extension_requirements: BTreeMap::new(),
            preferences: ServicePreferencesV1 {
                preferred_visibility_scope: Some(VisibilityScopeV1::BareMetalLike),
            },
            exclusions: ServiceExclusionsV1::default(),
            degradation_ladder: Vec::new(),
            assurance_predicates: Vec::new(),
            assurance_requirements: Vec::new(),
        },
    })
}

fn path_link_pair_requirement_from_state(
    pair: &HostStatePathLinkPairV1,
) -> Option<ServicePathLinkPairRequirementV1> {
    let requirement = ServicePathLinkPairRequirementV1 {
        pair_id: pair.pair_id.clone(),
        from_path_id: pair.from_path_id.clone(),
        to_path_id: pair.to_path_id.clone(),
        require_hardlink: true_capability(&pair.hardlink_supported),
        require_reflink: true_capability(&pair.reflink_supported),
        require_symlink: true_capability(&pair.symlink_supported),
        require_copy: true_capability(&pair.copy_possible),
    };
    (requirement.require_hardlink.is_some()
        || requirement.require_reflink.is_some()
        || requirement.require_symlink.is_some()
        || requirement.require_copy.is_some())
    .then_some(requirement)
}

fn true_capability(field: &StateFieldV1<bool>) -> Option<bool> {
    (field.state == ObservationStateV1::Observed && field.value == Some(true)).then_some(true)
}

fn observed_value<T: Clone>(field: &StateFieldV1<T>) -> Option<T> {
    (field.state == ObservationStateV1::Observed)
        .then(|| field.value.clone())
        .flatten()
}
