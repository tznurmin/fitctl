// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Validate raw profile envelope and payload before Serde erases omission/null distinctions.

use super::helpers_v1::{
    is_blank, is_namespace_char, reject_explicit_nulls, reject_unknown_keys, require_object,
};
use super::raw_requirements_v1::validate_requirements_json;
use crate::service_profile::{ServiceProfileError, ServiceProfileErrorCode};
use serde_json::Value;

pub(crate) fn validate_service_profile_json(raw: &Value) -> Result<(), ServiceProfileError> {
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
    // Match the shared envelope without letting optional nulls disappear in Serde.
    let provenance_fields = [
        "source",
        "collected_at",
        "fitctl_version",
        "fitctl_vcs_revision",
        "fitctl_vcs_describe",
        "fitctl_build_dirty",
        "command_name",
        "correlation_id",
    ];
    reject_unknown_keys(provenance, &provenance_fields)?;
    reject_explicit_nulls(
        provenance,
        &provenance_fields,
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

    validate_requirements_json(profile)?;

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
