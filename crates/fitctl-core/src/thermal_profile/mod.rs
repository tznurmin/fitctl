// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Helpers for generating reviewable thermal service-profile skeletons from observed state.

use std::collections::{BTreeMap, BTreeSet};

use crate::artifacts::envelope_v1::{ArtifactEnvelopeV1, ArtifactProvenanceV1};
use crate::artifacts::schema_ids_v1::{
    SERVICE_PROFILE_SCHEMA_ID, TOP_LEVEL_ARTIFACT_SCHEMA_VERSION,
};
use crate::artifacts::service_profile_v1::{
    ServiceExclusionsV1, ServicePreferencesV1, ServiceProfilePayloadV1, ServiceProfileV1,
    ServiceRequirementsV1, ServiceThermalRequirementV1,
};
use crate::artifacts::state_v1::{
    HostStateThermalReadingV1, HostStateThermalResourcesV1, HostStateV1,
};
use crate::artifacts::thermal_evidence_v1::ThermalEvidenceV1;
use crate::survey::VisibilityScopeV1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThermalProfileInitRequestV1 {
    pub source: ThermalProfileInitSourceV1,
    pub profile_id: String,
    pub display_name: Option<String>,
    pub short_display_name: Option<String>,
    pub primary_capability_class: String,
    pub margin_millidegrees_celsius: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThermalProfileInitSourceV1 {
    State(Box<HostStateV1>),
    ThermalEvidence(Box<ThermalEvidenceV1>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThermalProfileError {
    pub message: String,
}

impl ThermalProfileError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ThermalProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.message.fmt(f)
    }
}

impl std::error::Error for ThermalProfileError {}

pub fn init_thermal_profile_v1(
    request: ThermalProfileInitRequestV1,
) -> Result<ServiceProfileV1, ThermalProfileError> {
    if request.margin_millidegrees_celsius <= 0 {
        return Err(ThermalProfileError::new(
            "thermal profile init margin must be positive",
        ));
    }
    let (thermal_resources, provenance_source, collected_at) =
        thermal_profile_source_parts(&request.source)?;
    if thermal_resources.readings.is_empty() {
        return Err(ThermalProfileError::new(
            "thermal profile init requires at least one thermal reading",
        ));
    }

    let mut used_requirement_ids = BTreeSet::new();
    let required_thermal_sensors = thermal_resources
        .readings
        .iter()
        .map(|reading| {
            thermal_requirement_from_reading(
                reading,
                request.margin_millidegrees_celsius,
                &mut used_requirement_ids,
            )
        })
        .collect::<Vec<_>>();

    Ok(ServiceProfileV1 {
        envelope: ArtifactEnvelopeV1 {
            schema_id: SERVICE_PROFILE_SCHEMA_ID.to_string(),
            schema_version: TOP_LEVEL_ARTIFACT_SCHEMA_VERSION,
            artifact_id: format!("service-profile-{}", request.profile_id.replace('_', "-")),
            provenance: ArtifactProvenanceV1 {
                source: provenance_source.to_string(),
                collected_at,
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
                required_paths: Vec::new(),
                path_relationships: Vec::new(),
                required_path_link_pairs: Vec::new(),
                required_thermal_sensors,
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

fn thermal_profile_source_parts(
    source: &ThermalProfileInitSourceV1,
) -> Result<(&HostStateThermalResourcesV1, &'static str, String), ThermalProfileError> {
    match source {
        ThermalProfileInitSourceV1::State(state) => {
            let thermal_resources = state
                .state
                .core_state
                .thermal_resources
                .as_ref()
                .ok_or_else(|| {
                    ThermalProfileError::new("thermal profile init requires thermal_resources")
                })?;
            Ok((
                thermal_resources,
                "state:thermal_profile_init_v1",
                state.envelope.provenance.collected_at.clone(),
            ))
        }
        ThermalProfileInitSourceV1::ThermalEvidence(thermal_evidence) => Ok((
            &thermal_evidence.thermal_evidence,
            "thermal_evidence:thermal_profile_init_v1",
            thermal_evidence.envelope.provenance.collected_at.clone(),
        )),
    }
}

fn thermal_requirement_from_reading(
    reading: &HostStateThermalReadingV1,
    margin_millidegrees_celsius: i64,
    used_requirement_ids: &mut BTreeSet<String>,
) -> ServiceThermalRequirementV1 {
    let base_id = reading
        .sensor_alias
        .as_deref()
        .map(sanitize_requirement_id_part)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| sanitize_requirement_id_part(&reading.sensor_id));
    let requirement_id = unique_requirement_id(base_id, used_requirement_ids);
    ServiceThermalRequirementV1 {
        requirement_id,
        provider_id: Some(reading.provider_id.clone()),
        sensor_id: reading
            .sensor_alias
            .is_none()
            .then(|| reading.sensor_id.clone()),
        sensor_alias: reading.sensor_alias.clone(),
        sensor_role: Some(reading.sensor_role),
        max_temperature_millidegrees_celsius: reading
            .temperature_millidegrees_celsius
            .saturating_add(margin_millidegrees_celsius),
        require_provider_success: true,
    }
}

fn unique_requirement_id(base_id: String, used_requirement_ids: &mut BTreeSet<String>) -> String {
    if used_requirement_ids.insert(base_id.clone()) {
        return base_id;
    }
    for index in 2.. {
        let candidate = format!("{base_id}-{index}");
        if used_requirement_ids.insert(candidate.clone()) {
            return candidate;
        }
    }
    unreachable!("unbounded counter should eventually find a unique id")
}

fn sanitize_requirement_id_part(value: &str) -> String {
    let mut output = String::new();
    let mut previous_dash = false;
    for character in value.chars() {
        let normalized = character.to_ascii_lowercase();
        if normalized.is_ascii_alphanumeric() {
            output.push(normalized);
            previous_dash = false;
        } else if !previous_dash {
            output.push('-');
            previous_dash = true;
        }
    }
    output.trim_matches('-').to_string()
}
