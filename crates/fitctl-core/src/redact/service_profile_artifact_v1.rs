// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Complete typed sharing views for workload service profiles.

use crate::artifacts::service_profile_v1::{ServiceProfilePayloadV1, ServiceProfileV1};
use crate::artifacts::validation_v1::validate_service_profile;
use crate::redact::extension_sections_v1::redact_extension_requirements_v1;
use crate::redact::path_resources_v1::{deterministic_identifier_map, mapped_identifier};
use crate::redact::profile_v1::BuiltInRedactionProfileV1;
use crate::redact::provenance_v1::apply_auxiliary_redaction_metadata_v1;
use crate::redact::{RedactionError, RedactionErrorCode};

pub(crate) fn redact_service_profile_artifact(
    mut artifact: ServiceProfileV1,
    profile: BuiltInRedactionProfileV1,
    redacted_at: &str,
) -> Result<ServiceProfileV1, RedactionError> {
    redact_extension_requirements_v1(&mut artifact.profile.extension_requirements, profile)?;
    if profile.applies_fleet_redactions() {
        artifact.envelope.artifact_id = profile.artifact_id_placeholder("service-profile");
    }
    if profile.applies_auditor_redactions() {
        redact_service_profile_payload(&mut artifact.profile, profile);
    }
    apply_auxiliary_redaction_metadata_v1(&mut artifact.envelope, profile, redacted_at)?;
    validate_service_profile(&artifact).map_err(output_error)?;
    Ok(artifact)
}

fn redact_service_profile_payload(
    payload: &mut ServiceProfilePayloadV1,
    profile: BuiltInRedactionProfileV1,
) {
    payload.profile_id = profile.indexed_placeholder("service_profile", 0);
    replace_optional(
        &mut payload.display_name,
        profile,
        "service_profile_display",
        0,
    );
    replace_optional(
        &mut payload.short_display_name,
        profile,
        "service_profile_short_display",
        0,
    );

    let class_ids = deterministic_identifier_map(
        std::iter::once(payload.core_requirements.primary_capability_class.as_str())
            .chain(
                payload
                    .exclusions
                    .forbidden_capability_classes
                    .iter()
                    .map(String::as_str),
            )
            .chain(
                payload
                    .degradation_ladder
                    .iter()
                    .map(|tier| tier.acceptable_capability_class.as_str()),
            ),
        profile,
        "capability_class",
    );
    payload.core_requirements.primary_capability_class = mapped_identifier(
        &payload.core_requirements.primary_capability_class,
        &class_ids,
    );
    for class in &mut payload.exclusions.forbidden_capability_classes {
        *class = mapped_identifier(class, &class_ids);
    }
    for (index, tier) in payload.degradation_ladder.iter_mut().enumerate() {
        tier.tier_id = profile.indexed_placeholder("degradation_tier", index);
        tier.acceptable_capability_class =
            mapped_identifier(&tier.acceptable_capability_class, &class_ids);
        tier.rationale = profile.indexed_placeholder("degradation_rationale", index);
    }

    redact_profile_paths(payload, profile);
    for (index, requirement) in payload
        .core_requirements
        .required_thermal_sensors
        .iter_mut()
        .enumerate()
    {
        requirement.requirement_id = profile.indexed_placeholder("thermal_requirement", index);
        replace_optional(
            &mut requirement.provider_id,
            profile,
            "thermal_provider",
            index,
        );
        replace_optional(&mut requirement.sensor_id, profile, "thermal_sensor", index);
        replace_optional(
            &mut requirement.sensor_alias,
            profile,
            "thermal_sensor_alias",
            index,
        );
    }
    for (index, requirement) in payload.assurance_requirements.iter_mut().enumerate() {
        requirement.target = profile.indexed_placeholder("assurance_target", index);
    }
}

fn redact_profile_paths(payload: &mut ServiceProfilePayloadV1, profile: BuiltInRedactionProfileV1) {
    let requirements = &mut payload.core_requirements;
    let path_ids = deterministic_identifier_map(
        requirements
            .required_paths
            .iter()
            .map(|path| path.path_id.as_str())
            .chain(
                requirements
                    .path_relationships
                    .iter()
                    .flat_map(|relationship| {
                        [
                            relationship.left_path_id.as_str(),
                            relationship.right_path_id.as_str(),
                        ]
                    }),
            )
            .chain(
                requirements
                    .required_path_link_pairs
                    .iter()
                    .flat_map(|pair| [pair.from_path_id.as_str(), pair.to_path_id.as_str()]),
            ),
        profile,
        "path_id",
    );

    let mut device_link_index = 0;
    for (path_index, path) in requirements.required_paths.iter_mut().enumerate() {
        path.path_id = mapped_identifier(&path.path_id, &path_ids);
        replace_indexed(
            &mut path.accepted_filesystem_uuids,
            profile,
            &format!("path_{path_index}_filesystem_uuid"),
        );
        replace_indexed(
            &mut path.accepted_partition_uuids,
            profile,
            &format!("path_{path_index}_partition_uuid"),
        );
        for value in &mut path.accepted_persistent_device_links {
            *value = format!(
                "{}:{device_link_index}",
                profile.storage_identity_placeholder()
            );
            device_link_index += 1;
        }
    }
    for (index, relationship) in requirements.path_relationships.iter_mut().enumerate() {
        relationship.relationship_id = profile.indexed_placeholder("path_relationship", index);
        relationship.left_path_id = mapped_identifier(&relationship.left_path_id, &path_ids);
        relationship.right_path_id = mapped_identifier(&relationship.right_path_id, &path_ids);
    }
    for (index, pair) in requirements.required_path_link_pairs.iter_mut().enumerate() {
        pair.pair_id = profile.indexed_placeholder("path_pair", index);
        pair.from_path_id = mapped_identifier(&pair.from_path_id, &path_ids);
        pair.to_path_id = mapped_identifier(&pair.to_path_id, &path_ids);
    }
}

fn replace_indexed(values: &mut [String], profile: BuiltInRedactionProfileV1, class: &str) {
    for (index, value) in values.iter_mut().enumerate() {
        *value = profile.indexed_placeholder(class, index);
    }
}

fn replace_optional(
    value: &mut Option<String>,
    profile: BuiltInRedactionProfileV1,
    class: &str,
    index: usize,
) {
    if value.is_some() {
        *value = Some(profile.indexed_placeholder(class, index));
    }
}

fn output_error(error: crate::artifacts::validation_v1::ArtifactValidationError) -> RedactionError {
    RedactionError::new(
        RedactionErrorCode::RedactionOutputInvalid,
        "redaction_emit",
        error.message,
    )
}
