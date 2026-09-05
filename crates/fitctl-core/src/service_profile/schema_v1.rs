// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Service-profile schema loading and semantic validation above raw artifact decoding.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde_json::{Map, Value};

use crate::artifacts::schema_ids_v1::{
    SERVICE_PROFILE_SCHEMA_ID, TOP_LEVEL_ARTIFACT_SCHEMA_VERSION,
};
use crate::artifacts::service_profile_v1::{
    AssurancePredicateV1, ExplicitAssuranceRequirementV1, ServiceProfileV1,
};
use crate::artifacts::validation_v1::{validate_service_profile, ArtifactValidationErrorCode};
use crate::extensions::{
    decode_cuda_runtime_requirement_from_value, CudaRuntimeRequirementV1, CUDA_RUNTIME_NAMESPACE,
};
use crate::service_profile::{ServiceProfileError, ServiceProfileErrorCode};

pub fn load_service_profile_from_path(
    path: &Path,
) -> Result<ServiceProfileV1, ServiceProfileError> {
    let text = fs::read_to_string(path).map_err(|error| {
        ServiceProfileError::new(
            ServiceProfileErrorCode::ServiceProfileDocumentInvalid,
            "profile_load",
            format!("failed to read service profile {}: {error}", path.display()),
        )
    })?;

    let raw: Value = serde_json::from_str(&text).map_err(|error| {
        ServiceProfileError::new(
            ServiceProfileErrorCode::ServiceProfileDocumentInvalid,
            "profile_decode",
            format!(
                "failed to decode service profile {}: {error}",
                path.display()
            ),
        )
    })?;
    validate_service_profile_json(&raw)?;

    let profile: ServiceProfileV1 = serde_json::from_value(raw).map_err(|error| {
        ServiceProfileError::new(
            ServiceProfileErrorCode::ServiceProfileDocumentInvalid,
            "profile_decode",
            format!(
                "failed to decode typed service profile {}: {error}",
                path.display()
            ),
        )
    })?;
    validate_service_profile_semantics(&profile)?;

    validate_service_profile(&profile).map_err(|error| {
        let code = match error.code {
            ArtifactValidationErrorCode::ArtifactSchemaIdInvalid
            | ArtifactValidationErrorCode::ArtifactSchemaVersionInvalid => {
                ServiceProfileErrorCode::ServiceProfileSchemaUnsupported
            }
            ArtifactValidationErrorCode::ArtifactPayloadCorrupt
            | ArtifactValidationErrorCode::ContractBasisInvalid => {
                ServiceProfileErrorCode::ServiceProfileArtifactInvalid
            }
        };
        ServiceProfileError::new(code, "profile_validate", error.message)
    })?;

    Ok(profile)
}

fn validate_service_profile_json(raw: &Value) -> Result<(), ServiceProfileError> {
    let root = raw.as_object().ok_or_else(|| {
        ServiceProfileError::new(
            ServiceProfileErrorCode::ServiceProfileDocumentInvalid,
            "profile_decode",
            "service profile must decode to a JSON object",
        )
    })?;

    reject_unknown_keys(root, &["envelope", "profile"])?;
    reject_explicit_nulls(root, &["envelope", "profile"], "service profile field")?;

    let envelope = require_object(root, "envelope", "service profile envelope")?;
    reject_unknown_keys(
        envelope,
        &[
            "schema_id",
            "schema_version",
            "artifact_id",
            "provenance",
            "redaction",
            "signatures",
        ],
    )?;
    reject_explicit_nulls(
        envelope,
        &[
            "schema_id",
            "schema_version",
            "artifact_id",
            "provenance",
            "signatures",
        ],
        "service profile envelope field",
    )?;

    let provenance = require_object(envelope, "provenance", "service profile provenance")?;
    reject_unknown_keys(provenance, &["source", "collected_at"])?;
    reject_explicit_nulls(
        provenance,
        &["source", "collected_at"],
        "service profile provenance field",
    )?;

    let profile = require_object(root, "profile", "service profile payload")?;
    reject_unknown_keys(
        profile,
        &[
            "profile_id",
            "display_name",
            "short_display_name",
            "core_requirements",
            "extension_requirements",
            "preferences",
            "exclusions",
            "degradation_ladder",
            "assurance_predicates",
            "assurance_requirements",
        ],
    )?;
    reject_explicit_nulls(
        profile,
        &[
            "profile_id",
            "display_name",
            "short_display_name",
            "core_requirements",
            "extension_requirements",
            "preferences",
            "exclusions",
            "degradation_ladder",
            "assurance_predicates",
            "assurance_requirements",
        ],
        "service profile field",
    )?;

    let requirements = require_object(
        profile,
        "core_requirements",
        "service profile core requirements",
    )?;
    reject_unknown_keys(
        requirements,
        &[
            "primary_capability_class",
            "allowed_visibility_scopes",
            "min_allocatable_cpu_logical_cores",
            "min_allocatable_memory_bytes",
            "min_non_loopback_interfaces",
            "min_network_link_speed_mbps",
            "required_network_interface_kinds",
            "min_numa_nodes",
            "max_numa_nodes",
            "min_cpu_packages",
            "min_policy_scoped_accelerators",
            "require_accelerator_locality_known",
            "max_accelerator_numa_nodes",
            "required_paths",
            "path_relationships",
            "required_path_link_pairs",
            "required_thermal_sensors",
            "required_memory_reliability",
            "required_gpu_reliability",
        ],
    )?;
    reject_explicit_nulls(
        requirements,
        &[
            "primary_capability_class",
            "allowed_visibility_scopes",
            "min_allocatable_cpu_logical_cores",
            "min_allocatable_memory_bytes",
            "min_non_loopback_interfaces",
            "min_network_link_speed_mbps",
            "required_network_interface_kinds",
            "min_numa_nodes",
            "max_numa_nodes",
            "min_cpu_packages",
            "min_policy_scoped_accelerators",
            "require_accelerator_locality_known",
            "max_accelerator_numa_nodes",
            "required_paths",
            "path_relationships",
            "required_path_link_pairs",
            "required_thermal_sensors",
            "required_memory_reliability",
            "required_gpu_reliability",
        ],
        "service profile requirement field",
    )?;
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
    if let Some(memory_reliability) = requirements.get("required_memory_reliability") {
        let memory_reliability = memory_reliability.as_object().ok_or_else(|| {
            ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileDocumentInvalid,
                "profile_decode",
                "service profile required_memory_reliability must be an object",
            )
        })?;
        reject_unknown_keys(
            memory_reliability,
            &[
                "require_provider_success",
                "max_corrected_error_count",
                "max_uncorrected_error_count",
            ],
        )?;
        reject_explicit_nulls(
            memory_reliability,
            &[
                "require_provider_success",
                "max_corrected_error_count",
                "max_uncorrected_error_count",
            ],
            "service profile required_memory_reliability field",
        )?;
        validate_u64_json(
            memory_reliability.get("max_corrected_error_count"),
            "required memory reliability max_corrected_error_count",
        )?;
        validate_u64_json(
            memory_reliability.get("max_uncorrected_error_count"),
            "required memory reliability max_uncorrected_error_count",
        )?;
    }
    if let Some(gpu_reliability) = requirements.get("required_gpu_reliability") {
        let gpu_reliability = gpu_reliability.as_object().ok_or_else(|| {
            ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileDocumentInvalid,
                "profile_decode",
                "service profile required_gpu_reliability must be an object",
            )
        })?;
        reject_unknown_keys(
            gpu_reliability,
            &[
                "require_provider_success",
                "require_ecc_mode_current",
                "max_volatile_corrected_ecc_error_count",
                "max_volatile_uncorrected_ecc_error_count",
                "require_no_retired_pages_pending",
                "require_no_row_remapper_pending",
            ],
        )?;
        reject_explicit_nulls(
            gpu_reliability,
            &[
                "require_provider_success",
                "require_ecc_mode_current",
                "max_volatile_corrected_ecc_error_count",
                "max_volatile_uncorrected_ecc_error_count",
                "require_no_retired_pages_pending",
                "require_no_row_remapper_pending",
            ],
            "service profile required_gpu_reliability field",
        )?;
        validate_non_blank_string_json(
            gpu_reliability.get("require_ecc_mode_current"),
            "required GPU reliability require_ecc_mode_current",
        )?;
        validate_u64_json(
            gpu_reliability.get("max_volatile_corrected_ecc_error_count"),
            "required GPU reliability max_volatile_corrected_ecc_error_count",
        )?;
        validate_u64_json(
            gpu_reliability.get("max_volatile_uncorrected_ecc_error_count"),
            "required GPU reliability max_volatile_uncorrected_ecc_error_count",
        )?;
    }
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
    if let Some(required_thermal_sensors) = requirements.get("required_thermal_sensors") {
        let required_thermal_sensors = required_thermal_sensors.as_array().ok_or_else(|| {
            ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileDocumentInvalid,
                "profile_decode",
                "service profile required_thermal_sensors must be an array",
            )
        })?;
        for (index, requirement) in required_thermal_sensors.iter().enumerate() {
            let requirement = requirement.as_object().ok_or_else(|| {
                ServiceProfileError::new(
                    ServiceProfileErrorCode::ServiceProfileDocumentInvalid,
                    "profile_decode",
                    format!(
                        "service profile required_thermal_sensors entry at index {index} must be an object"
                    ),
                )
            })?;
            reject_unknown_keys(
                requirement,
                &[
                    "requirement_id",
                    "provider_id",
                    "sensor_id",
                    "sensor_alias",
                    "sensor_role",
                    "max_temperature_millidegrees_celsius",
                    "require_provider_success",
                ],
            )?;
            reject_explicit_nulls(
                requirement,
                &[
                    "requirement_id",
                    "provider_id",
                    "sensor_id",
                    "sensor_alias",
                    "sensor_role",
                    "max_temperature_millidegrees_celsius",
                    "require_provider_success",
                ],
                "service profile required_thermal_sensors field",
            )?;
        }
    }

    if let Some(extension_requirements) = profile.get("extension_requirements") {
        let extension_requirements = extension_requirements.as_object().ok_or_else(|| {
            ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileDocumentInvalid,
                "profile_decode",
                "service profile extension_requirements must be an object",
            )
        })?;

        for (namespace, value) in extension_requirements {
            if is_blank(namespace)
                || namespace
                    .split('.')
                    .any(|segment| segment.is_empty() || !segment.chars().all(is_namespace_char))
            {
                return Err(ServiceProfileError::new(
                    ServiceProfileErrorCode::ServiceProfileDocumentInvalid,
                    "profile_decode",
                    "service profile extension_requirements must use valid namespace keys",
                ));
            }
            if !value.is_object() || value.is_null() {
                return Err(ServiceProfileError::new(
                    ServiceProfileErrorCode::ServiceProfileDocumentInvalid,
                    "profile_decode",
                    "service profile extension_requirements values must be non-null objects",
                ));
            }
        }
    }

    let preferences = require_object(profile, "preferences", "service profile preferences")?;
    reject_unknown_keys(preferences, &["preferred_visibility_scope"])?;
    reject_explicit_nulls(
        preferences,
        &["preferred_visibility_scope"],
        "service profile preference field",
    )?;

    let exclusions = require_object(profile, "exclusions", "service profile exclusions")?;
    reject_unknown_keys(exclusions, &["forbidden_capability_classes"])?;
    reject_explicit_nulls(
        exclusions,
        &["forbidden_capability_classes"],
        "service profile exclusion field",
    )?;

    let degradation_ladder = profile
        .get("degradation_ladder")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileDocumentInvalid,
                "profile_decode",
                "service profile degradation_ladder must be an array",
            )
        })?;
    for (index, tier) in degradation_ladder.iter().enumerate() {
        let tier = tier.as_object().ok_or_else(|| {
            ServiceProfileError::new(
                ServiceProfileErrorCode::DegradationLadderInvalid,
                "profile_validate",
                format!("degradation tier at index {index} must be an object"),
            )
        })?;
        reject_unknown_keys(
            tier,
            &["tier_id", "acceptable_capability_class", "rationale"],
        )?;
        reject_explicit_nulls(
            tier,
            &["tier_id", "acceptable_capability_class", "rationale"],
            "degradation tier field",
        )?;
    }

    if let Some(assurance_predicates) = profile.get("assurance_predicates") {
        let assurance_predicates = assurance_predicates.as_array().ok_or_else(|| {
            ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileDocumentInvalid,
                "profile_decode",
                "service profile assurance_predicates must be an array",
            )
        })?;
        for predicate in assurance_predicates {
            let Some(predicate) = predicate.as_str() else {
                return Err(ServiceProfileError::new(
                    ServiceProfileErrorCode::AssurancePredicateInvalid,
                    "profile_validate",
                    "service profile assurance predicates must be strings",
                ));
            };
            if !matches!(
                predicate,
                "locally_verified_required" | "hardware_attested_required"
            ) {
                return Err(ServiceProfileError::new(
                    ServiceProfileErrorCode::AssurancePredicateInvalid,
                    "profile_validate",
                    format!("unsupported assurance predicate {predicate}"),
                ));
            }
        }
    }

    if let Some(assurance_requirements) = profile.get("assurance_requirements") {
        let assurance_requirements = assurance_requirements.as_array().ok_or_else(|| {
            ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileDocumentInvalid,
                "profile_decode",
                "service profile assurance_requirements must be an array",
            )
        })?;
        for (index, requirement) in assurance_requirements.iter().enumerate() {
            let requirement = requirement.as_object().ok_or_else(|| {
                ServiceProfileError::new(
                    ServiceProfileErrorCode::AssurancePredicateInvalid,
                    "profile_validate",
                    format!("assurance requirement at index {index} must be an object"),
                )
            })?;
            reject_unknown_keys(
                requirement,
                &[
                    "target",
                    "accepted_assurance_sources",
                    "accepted_derivation_stages",
                    "allow_policy_asserted",
                    "allow_mixed_sources",
                    "allow_stale_evidence",
                ],
            )?;
            reject_explicit_nulls(
                requirement,
                &[
                    "target",
                    "accepted_assurance_sources",
                    "accepted_derivation_stages",
                    "allow_policy_asserted",
                    "allow_mixed_sources",
                    "allow_stale_evidence",
                ],
                "assurance requirement field",
            )?;
        }
    }

    Ok(())
}

fn validate_service_profile_semantics(
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

fn validate_known_extension_requirement_semantics(
    profile: &ServiceProfileV1,
) -> Result<(), ServiceProfileError> {
    let payload = &profile.profile;

    if let Some(value) = payload.extension_requirements.get(CUDA_RUNTIME_NAMESPACE) {
        let requirement = decode_cuda_runtime_requirement_from_value(value).map_err(|error| {
            ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileArtifactInvalid,
                "profile_validate",
                format!(
                    "service profile CUDA runtime extension requirement is invalid: {}",
                    error.message
                ),
            )
        })?;
        validate_cuda_runtime_requirement_semantics(requirement, payload)?;
    }

    Ok(())
}

fn validate_cuda_runtime_requirement_semantics(
    requirement: CudaRuntimeRequirementV1,
    payload: &crate::artifacts::service_profile_v1::ServiceProfilePayloadV1,
) -> Result<(), ServiceProfileError> {
    if requirement
        .minimum_qualifying_device_aggregate_allocatable_memory_bytes
        .is_some()
        && payload
            .core_requirements
            .min_policy_scoped_accelerators
            .is_none()
    {
        return Err(ServiceProfileError::new(
            ServiceProfileErrorCode::ServiceProfileRequirementInvalid,
            "profile_validate",
            "CUDA qualifying-device aggregate allocatable-memory thresholds require core_requirements.min_policy_scoped_accelerators",
        ));
    }

    Ok(())
}

fn is_namespace_char(value: char) -> bool {
    value.is_ascii_lowercase() || value.is_ascii_digit() || matches!(value, '-' | '_')
}

fn validate_explicit_assurance_requirement(
    requirement: &ExplicitAssuranceRequirementV1,
) -> Result<(), ServiceProfileError> {
    if is_blank(&requirement.target)
        || requirement.accepted_assurance_sources.is_empty()
        || requirement.accepted_derivation_stages.is_empty()
    {
        return Err(ServiceProfileError::new(
            ServiceProfileErrorCode::AssurancePredicateInvalid,
            "profile_validate",
            "explicit assurance requirements must include a target, sources, and derivation stages",
        ));
    }

    let mut sources = BTreeSet::new();
    for source in &requirement.accepted_assurance_sources {
        if !sources.insert(source.as_str()) {
            return Err(ServiceProfileError::new(
                ServiceProfileErrorCode::AssurancePredicateInvalid,
                "profile_validate",
                "explicit assurance requirement sources must be unique",
            ));
        }
    }

    let mut stages = BTreeSet::new();
    for stage in &requirement.accepted_derivation_stages {
        if !stages.insert(stage.as_str()) {
            return Err(ServiceProfileError::new(
                ServiceProfileErrorCode::AssurancePredicateInvalid,
                "profile_validate",
                "explicit assurance requirement derivation stages must be unique",
            ));
        }
    }

    Ok(())
}

fn require_object<'a>(
    map: &'a Map<String, Value>,
    key: &str,
    label: &str,
) -> Result<&'a Map<String, Value>, ServiceProfileError> {
    map.get(key).and_then(Value::as_object).ok_or_else(|| {
        ServiceProfileError::new(
            ServiceProfileErrorCode::ServiceProfileDocumentInvalid,
            "profile_decode",
            format!("{label} must be an object"),
        )
    })
}

fn reject_unknown_keys(
    map: &Map<String, Value>,
    allowed_keys: &[&str],
) -> Result<(), ServiceProfileError> {
    if let Some(key) = map.keys().find(|key| !allowed_keys.contains(&key.as_str())) {
        return Err(ServiceProfileError::new(
            ServiceProfileErrorCode::ServiceProfileDocumentInvalid,
            "profile_decode",
            format!("service profile contains unsupported field {key}"),
        ));
    }

    Ok(())
}

fn reject_explicit_nulls(
    map: &Map<String, Value>,
    fields: &[&str],
    label: &str,
) -> Result<(), ServiceProfileError> {
    if let Some(field) = fields
        .iter()
        .find(|field| matches!(map.get(**field), Some(Value::Null)))
    {
        return Err(ServiceProfileError::new(
            ServiceProfileErrorCode::ServiceProfileDocumentInvalid,
            "profile_decode",
            format!("{label} '{field}' must not be null"),
        ));
    }

    Ok(())
}

fn validate_positive_i64_json(
    value: Option<&Value>,
    label: &str,
) -> Result<(), ServiceProfileError> {
    let Some(value) = value else {
        return Ok(());
    };
    match value.as_i64() {
        Some(number) if number > 0 => Ok(()),
        _ => Err(ServiceProfileError::new(
            ServiceProfileErrorCode::ServiceProfileRequirementInvalid,
            "profile_validate",
            format!("{label} must be a positive integer"),
        )),
    }
}

fn validate_u64_json(value: Option<&Value>, label: &str) -> Result<(), ServiceProfileError> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.as_u64().is_some() {
        return Ok(());
    }
    Err(ServiceProfileError::new(
        ServiceProfileErrorCode::ServiceProfileRequirementInvalid,
        "profile_validate",
        format!("{label} must be an unsigned integer"),
    ))
}

fn validate_u32_percent_json(
    value: Option<&Value>,
    label: &str,
) -> Result<(), ServiceProfileError> {
    let Some(value) = value else {
        return Ok(());
    };
    match value.as_u64() {
        Some(number) if number <= 100 => Ok(()),
        _ => Err(ServiceProfileError::new(
            ServiceProfileErrorCode::ServiceProfileRequirementInvalid,
            "profile_validate",
            format!("{label} must be an integer percentage from 0 to 100"),
        )),
    }
}

fn validate_non_blank_string_json(
    value: Option<&Value>,
    label: &str,
) -> Result<(), ServiceProfileError> {
    let Some(value) = value else {
        return Ok(());
    };
    match value.as_str() {
        Some(text) if !is_blank(text) => Ok(()),
        _ => Err(ServiceProfileError::new(
            ServiceProfileErrorCode::ServiceProfileRequirementInvalid,
            "profile_validate",
            format!("{label} must be a non-empty string"),
        )),
    }
}

fn is_blank(value: &str) -> bool {
    value.trim().is_empty()
}

fn validate_unique_non_blank_strings(
    values: &[String],
    label: &str,
) -> Result<(), ServiceProfileError> {
    let mut seen = BTreeSet::new();
    for value in values {
        if is_blank(value) {
            return Err(ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileRequirementInvalid,
                "profile_validate",
                format!("{label} must be non-empty"),
            ));
        }
        if !seen.insert(value) {
            return Err(ServiceProfileError::new(
                ServiceProfileErrorCode::ServiceProfileRequirementInvalid,
                "profile_validate",
                format!("{label} must be unique"),
            ));
        }
    }
    Ok(())
}

fn visibility_scope_key(scope: &crate::survey::VisibilityScopeV1) -> &'static str {
    match scope {
        crate::survey::VisibilityScopeV1::BareMetalLike => "bare_metal_like",
        crate::survey::VisibilityScopeV1::VmLike => "vm_like",
        crate::survey::VisibilityScopeV1::ContainerRestricted => "container_restricted",
        crate::survey::VisibilityScopeV1::Unknown => "unknown",
    }
}

fn assurance_predicate_key(predicate: AssurancePredicateV1) -> &'static str {
    match predicate {
        AssurancePredicateV1::LocallyVerifiedRequired => "locally_verified_required",
        AssurancePredicateV1::HardwareAttestedRequired => "hardware_attested_required",
    }
}
