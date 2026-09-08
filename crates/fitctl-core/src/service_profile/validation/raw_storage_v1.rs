// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Raw storage and path relationship constraints.

use super::helpers_v1::{
    reject_explicit_nulls, reject_unknown_keys, validate_positive_i64_json,
    validate_u32_percent_json,
};
use crate::service_profile::{ServiceProfileError, ServiceProfileErrorCode};
use serde_json::{Map, Value};

pub(super) fn validate_paths_json(
    requirements: &Map<String, Value>,
) -> Result<(), ServiceProfileError> {
    if let Some(required_paths) = requirements.get("required_paths") {
        let required_paths = required_paths.as_array().ok_or_else(|| {
            ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileDocumentInvalid,
                "profile_decode",
                "service profile required_paths must be an array",
            )
        })?;
        for (index, path) in required_paths.iter().enumerate() {
            let path = path.as_object().ok_or_else(|| {
                ServiceProfileError::new(
                    ServiceProfileErrorCode::ServiceProfileDocumentInvalid,
                    "profile_decode",
                    format!(
                        "service profile required_paths entry at index {index} must be an object"
                    ),
                )
            })?;
            reject_unknown_keys(
                path,
                &[
                    "path_id",
                    "min_available_bytes",
                    "accepted_media_classes",
                    "accepted_durability_classes",
                    "required_filesystem_types",
                    "accepted_filesystem_uuids",
                    "accepted_partition_uuids",
                    "accepted_persistent_device_links",
                    "require_hardlink",
                    "require_reflink",
                    "require_symlink",
                    "require_copy",
                    "storage_health",
                ],
            )?;
            reject_explicit_nulls(
                path,
                &[
                    "path_id",
                    "min_available_bytes",
                    "accepted_media_classes",
                    "accepted_durability_classes",
                    "required_filesystem_types",
                    "accepted_filesystem_uuids",
                    "accepted_partition_uuids",
                    "accepted_persistent_device_links",
                    "require_hardlink",
                    "require_reflink",
                    "require_symlink",
                    "require_copy",
                    "storage_health",
                ],
                "service profile required_paths field",
            )?;
            if let Some(storage_health) = path.get("storage_health") {
                let storage_health = storage_health.as_object().ok_or_else(|| {
                    ServiceProfileError::new(
                        ServiceProfileErrorCode::ServiceProfileDocumentInvalid,
                        "profile_decode",
                        format!(
                            "service profile required_paths entry at index {index} storage_health must be an object"
                        ),
                    )
                })?;
                reject_unknown_keys(
                    storage_health,
                    &[
                        "accepted_health_states",
                        "max_temperature_celsius",
                        "max_percentage_used",
                        "min_available_spare_percent",
                    ],
                )?;
                reject_explicit_nulls(
                    storage_health,
                    &[
                        "accepted_health_states",
                        "max_temperature_celsius",
                        "max_percentage_used",
                        "min_available_spare_percent",
                    ],
                    "service profile path storage_health field",
                )?;
                validate_positive_i64_json(
                    storage_health.get("max_temperature_celsius"),
                    "required path storage_health max_temperature_celsius",
                )?;
                validate_u32_percent_json(
                    storage_health.get("max_percentage_used"),
                    "required path storage_health max_percentage_used",
                )?;
                validate_u32_percent_json(
                    storage_health.get("min_available_spare_percent"),
                    "required path storage_health min_available_spare_percent",
                )?;
            }
        }
    }
    Ok(())
}

pub(super) fn validate_path_relationships_json(
    requirements: &Map<String, Value>,
) -> Result<(), ServiceProfileError> {
    if let Some(path_relationships) = requirements.get("path_relationships") {
        let path_relationships = path_relationships.as_array().ok_or_else(|| {
            ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileDocumentInvalid,
                "profile_decode",
                "service profile path_relationships must be an array",
            )
        })?;
        for (index, relationship) in path_relationships.iter().enumerate() {
            let relationship = relationship.as_object().ok_or_else(|| {
                ServiceProfileError::new(
                    ServiceProfileErrorCode::ServiceProfileDocumentInvalid,
                    "profile_decode",
                    format!(
                        "service profile path_relationships entry at index {index} must be an object"
                    ),
                )
            })?;
            reject_unknown_keys(
                relationship,
                &[
                    "relationship_id",
                    "left_path_id",
                    "right_path_id",
                    "must_not_share",
                ],
            )?;
            reject_explicit_nulls(
                relationship,
                &[
                    "relationship_id",
                    "left_path_id",
                    "right_path_id",
                    "must_not_share",
                ],
                "service profile path_relationships field",
            )?;
        }
    }
    if let Some(required_path_link_pairs) = requirements.get("required_path_link_pairs") {
        let required_path_link_pairs = required_path_link_pairs.as_array().ok_or_else(|| {
            ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileDocumentInvalid,
                "profile_decode",
                "service profile required_path_link_pairs must be an array",
            )
        })?;
        for (index, pair) in required_path_link_pairs.iter().enumerate() {
            let pair = pair.as_object().ok_or_else(|| {
                ServiceProfileError::new(
                    ServiceProfileErrorCode::ServiceProfileDocumentInvalid,
                    "profile_decode",
                    format!(
                        "service profile required_path_link_pairs entry at index {index} must be an object"
                    ),
                )
            })?;
            reject_unknown_keys(
                pair,
                &[
                    "pair_id",
                    "from_path_id",
                    "to_path_id",
                    "require_hardlink",
                    "require_reflink",
                    "require_symlink",
                    "require_copy",
                ],
            )?;
            reject_explicit_nulls(
                pair,
                &[
                    "pair_id",
                    "from_path_id",
                    "to_path_id",
                    "require_hardlink",
                    "require_reflink",
                    "require_symlink",
                    "require_copy",
                ],
                "service profile required_path_link_pairs field",
            )?;
        }
    }
    Ok(())
}
