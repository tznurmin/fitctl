// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Profile semantics, preserving requirement, degradation and assurance error precedence.

use super::extensions_v1::validate_known_extension_requirement_semantics;
use super::helpers_v1::{
    assurance_predicate_key, is_blank, validate_explicit_assurance_requirement,
    visibility_scope_key,
};
use super::requirements_v1::validate_path_and_thermal_requirements;
use crate::artifacts::schema_ids_v1::{
    SERVICE_PROFILE_SCHEMA_ID, TOP_LEVEL_ARTIFACT_SCHEMA_VERSION,
};
use crate::artifacts::service_profile_v1::{AssurancePredicateV1, ServiceProfileV1};
use crate::service_profile::{ServiceProfileError, ServiceProfileErrorCode};
use std::collections::BTreeSet;

pub(crate) fn validate_service_profile_semantics(
    profile: &ServiceProfileV1,
) -> Result<(), ServiceProfileError> {
    if profile.envelope.schema_id != SERVICE_PROFILE_SCHEMA_ID
        || profile.envelope.schema_version != TOP_LEVEL_ARTIFACT_SCHEMA_VERSION
    {
        return Err(ServiceProfileError::new(
            ServiceProfileErrorCode::ServiceProfileSchemaUnsupported,
            "profile_validate",
            "service profile must declare the supported schema id and schema version",
        ));
    }

    let payload = &profile.profile;
    if is_blank(&payload.profile_id)
        || payload
            .display_name
            .as_ref()
            .is_some_and(|value| is_blank(value))
        || payload
            .short_display_name
            .as_ref()
            .is_some_and(|value| is_blank(value))
        || is_blank(&payload.core_requirements.primary_capability_class)
    {
        return Err(ServiceProfileError::new(
            ServiceProfileErrorCode::ServiceProfileRequirementInvalid,
            "profile_validate",
            "service profile ids, optional display labels, and primary capability class must be non-empty",
        ));
    }

    if payload
        .core_requirements
        .allowed_visibility_scopes
        .is_empty()
    {
        return Err(ServiceProfileError::new(
            ServiceProfileErrorCode::ServiceProfileRequirementInvalid,
            "profile_validate",
            "service profile must declare at least one allowed visibility scope",
        ));
    }
    let mut visibility_scopes = BTreeSet::new();
    for scope in &payload.core_requirements.allowed_visibility_scopes {
        if !visibility_scopes.insert(visibility_scope_key(scope)) {
            return Err(ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileRequirementInvalid,
                "profile_validate",
                "allowed visibility scopes must be unique",
            ));
        }
    }

    if payload
        .core_requirements
        .min_allocatable_cpu_logical_cores
        .is_some_and(|value| value == 0)
        || payload
            .core_requirements
            .min_allocatable_memory_bytes
            .is_some_and(|value| value == 0)
        || payload
            .core_requirements
            .min_non_loopback_interfaces
            .is_some_and(|value| value == 0)
        || payload
            .core_requirements
            .min_network_link_speed_mbps
            .is_some_and(|value| value == 0)
        || payload
            .core_requirements
            .min_numa_nodes
            .is_some_and(|value| value == 0)
        || payload
            .core_requirements
            .max_numa_nodes
            .is_some_and(|value| value == 0)
        || payload
            .core_requirements
            .min_cpu_packages
            .is_some_and(|value| value == 0)
        || payload
            .core_requirements
            .min_policy_scoped_accelerators
            .is_some_and(|value| value == 0)
        || payload
            .core_requirements
            .max_accelerator_numa_nodes
            .is_some_and(|value| value == 0)
    {
        return Err(ServiceProfileError::new(
            ServiceProfileErrorCode::ServiceProfileRequirementInvalid,
            "profile_validate",
            "allocatable, network, topology, accelerator-count, and accelerator-locality thresholds must be positive when present",
        ));
    }

    let mut required_network_interface_kinds = BTreeSet::new();
    for kind in &payload.core_requirements.required_network_interface_kinds {
        if !required_network_interface_kinds.insert(kind.as_str()) {
            return Err(ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileRequirementInvalid,
                "profile_validate",
                "required network interface kinds must be unique",
            ));
        }
    }

    validate_path_and_thermal_requirements(payload)?;

    if payload
        .exclusions
        .forbidden_capability_classes
        .iter()
        .any(|value| is_blank(value))
    {
        return Err(ServiceProfileError::new(
            ServiceProfileErrorCode::ServiceProfileRequirementInvalid,
            "profile_validate",
            "forbidden capability classes must be non-empty when present",
        ));
    }
    let mut forbidden_capability_classes = BTreeSet::new();
    for capability_class in &payload.exclusions.forbidden_capability_classes {
        if !forbidden_capability_classes.insert(capability_class.clone()) {
            return Err(ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileRequirementInvalid,
                "profile_validate",
                "forbidden capability classes must be unique",
            ));
        }
    }

    let mut tier_ids = BTreeSet::new();
    for tier in &payload.degradation_ladder {
        if is_blank(&tier.tier_id)
            || is_blank(&tier.acceptable_capability_class)
            || is_blank(&tier.rationale)
        {
            return Err(ServiceProfileError::new(
                ServiceProfileErrorCode::DegradationLadderInvalid,
                "profile_validate",
                "degradation tier ids, capability classes, and rationale must be non-empty",
            ));
        }
        if !tier_ids.insert(tier.tier_id.clone()) {
            return Err(ServiceProfileError::new(
                ServiceProfileErrorCode::DegradationLadderInvalid,
                "profile_validate",
                "degradation tier ids must be unique",
            ));
        }
        if tier.acceptable_capability_class == payload.core_requirements.primary_capability_class {
            return Err(ServiceProfileError::new(
                ServiceProfileErrorCode::DegradationLadderInvalid,
                "profile_validate",
                "degradation tiers must not duplicate the primary capability requirement",
            ));
        }
    }

    let mut assurance_predicates = BTreeSet::new();
    for predicate in &payload.assurance_predicates {
        if !matches!(
            predicate,
            AssurancePredicateV1::LocallyVerifiedRequired
                | AssurancePredicateV1::HardwareAttestedRequired
        ) {
            return Err(ServiceProfileError::new(
                ServiceProfileErrorCode::AssurancePredicateInvalid,
                "profile_validate",
                "unsupported assurance predicate",
            ));
        }
        if !assurance_predicates.insert(assurance_predicate_key(*predicate)) {
            return Err(ServiceProfileError::new(
                ServiceProfileErrorCode::AssurancePredicateInvalid,
                "profile_validate",
                "assurance predicates must be unique",
            ));
        }
    }

    let mut assurance_requirement_targets = BTreeSet::new();
    for requirement in &payload.assurance_requirements {
        validate_explicit_assurance_requirement(requirement)?;
        let target_key = requirement.target.clone();
        if !assurance_requirement_targets.insert(target_key) {
            return Err(ServiceProfileError::new(
                ServiceProfileErrorCode::AssurancePredicateInvalid,
                "profile_validate",
                "assurance requirement targets must be unique",
            ));
        }
    }

    validate_known_extension_requirement_semantics(profile)?;

    Ok(())
}
