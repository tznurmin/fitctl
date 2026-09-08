// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Typed storage, topology and thermal requirement relationships.

use super::helpers_v1::{is_blank, validate_unique_non_blank_strings};
use crate::artifacts::service_profile_v1::ServiceProfilePayloadV1;
use crate::service_profile::{ServiceProfileError, ServiceProfileErrorCode};
use std::collections::BTreeSet;

pub(super) fn validate_path_and_thermal_requirements(
    payload: &ServiceProfilePayloadV1,
) -> Result<(), ServiceProfileError> {
    let mut required_path_ids = BTreeSet::new();
    for path in &payload.core_requirements.required_paths {
        if is_blank(&path.path_id) {
            return Err(ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileRequirementInvalid,
                "profile_validate",
                "required path ids must be non-empty",
            ));
        }
        if !required_path_ids.insert(path.path_id.clone()) {
            return Err(ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileRequirementInvalid,
                "profile_validate",
                "required path ids must be unique",
            ));
        }
        if path.min_available_bytes.is_some_and(|value| value == 0) {
            return Err(ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileRequirementInvalid,
                "profile_validate",
                "required path minimum available bytes must be positive when present",
            ));
        }
        validate_unique_non_blank_strings(
            &path.accepted_persistent_device_links,
            "required path accepted persistent device links",
        )?;
    }
    let mut relationship_ids = BTreeSet::new();
    for relationship in &payload.core_requirements.path_relationships {
        if is_blank(&relationship.relationship_id)
            || is_blank(&relationship.left_path_id)
            || is_blank(&relationship.right_path_id)
            || relationship.left_path_id == relationship.right_path_id
        {
            return Err(ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileRequirementInvalid,
                "profile_validate",
                "path relationship ids and distinct path ids must be non-empty",
            ));
        }
        if !relationship_ids.insert(relationship.relationship_id.clone()) {
            return Err(ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileRequirementInvalid,
                "profile_validate",
                "path relationship ids must be unique",
            ));
        }
        if relationship.must_not_share.is_empty() {
            return Err(ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileRequirementInvalid,
                "profile_validate",
                "path relationships must declare at least one must_not_share identity",
            ));
        }
        let mut identity_fields = BTreeSet::new();
        for identity in &relationship.must_not_share {
            if !identity_fields.insert(identity.as_str()) {
                return Err(ServiceProfileError::new(
                    ServiceProfileErrorCode::ServiceProfileRequirementInvalid,
                    "profile_validate",
                    "path relationship must_not_share identities must be unique",
                ));
            }
        }
    }
    let mut link_pair_ids = BTreeSet::new();
    for pair in &payload.core_requirements.required_path_link_pairs {
        if is_blank(&pair.pair_id)
            || is_blank(&pair.from_path_id)
            || is_blank(&pair.to_path_id)
            || pair.from_path_id == pair.to_path_id
        {
            return Err(ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileRequirementInvalid,
                "profile_validate",
                "required path link-pair ids and distinct path ids must be non-empty",
            ));
        }
        if !link_pair_ids.insert(pair.pair_id.clone()) {
            return Err(ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileRequirementInvalid,
                "profile_validate",
                "required path link-pair ids must be unique",
            ));
        }
        if !matches!(pair.require_hardlink, Some(true))
            && !matches!(pair.require_reflink, Some(true))
            && !matches!(pair.require_symlink, Some(true))
            && !matches!(pair.require_copy, Some(true))
        {
            return Err(ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileRequirementInvalid,
                "profile_validate",
                "required path link-pair entries must require at least one positive capability",
            ));
        }
    }
    let mut thermal_requirement_ids = BTreeSet::new();
    for requirement in &payload.core_requirements.required_thermal_sensors {
        if is_blank(&requirement.requirement_id) {
            return Err(ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileRequirementInvalid,
                "profile_validate",
                "required thermal sensor requirement ids must be non-empty",
            ));
        }
        if !thermal_requirement_ids.insert(requirement.requirement_id.clone()) {
            return Err(ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileRequirementInvalid,
                "profile_validate",
                "required thermal sensor requirement ids must be unique",
            ));
        }
        if requirement
            .provider_id
            .as_ref()
            .is_some_and(|value| is_blank(value))
            || requirement
                .sensor_id
                .as_ref()
                .is_some_and(|value| is_blank(value))
            || requirement
                .sensor_alias
                .as_ref()
                .is_some_and(|value| is_blank(value))
        {
            return Err(ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileRequirementInvalid,
                "profile_validate",
                "required thermal sensor selectors must be non-empty when present",
            ));
        }
        if requirement.provider_id.is_none()
            && requirement.sensor_id.is_none()
            && requirement.sensor_alias.is_none()
            && requirement.sensor_role.is_none()
        {
            return Err(ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileRequirementInvalid,
                "profile_validate",
                "required thermal sensors must declare at least one selector",
            ));
        }
        if requirement.max_temperature_millidegrees_celsius <= 0 {
            return Err(ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileRequirementInvalid,
                "profile_validate",
                "required thermal sensor maximum temperature must be positive",
            ));
        }
    }

    if let (Some(min_numa_nodes), Some(max_numa_nodes)) = (
        payload.core_requirements.min_numa_nodes,
        payload.core_requirements.max_numa_nodes,
    ) {
        if min_numa_nodes > max_numa_nodes {
            return Err(ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileRequirementInvalid,
                "profile_validate",
                "minimum NUMA node requirement must not exceed the maximum",
            ));
        }
    }

    Ok(())
}
