// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Shared validation primitives, retaining their existing typed failure identities.

use crate::artifacts::service_profile_v1::{AssurancePredicateV1, ExplicitAssuranceRequirementV1};
use crate::service_profile::{ServiceProfileError, ServiceProfileErrorCode};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

pub(super) fn is_namespace_char(value: char) -> bool {
    value.is_ascii_lowercase() || value.is_ascii_digit() || matches!(value, '-' | '_')
}

pub(super) fn validate_explicit_assurance_requirement(
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

pub(super) fn require_object<'a>(
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

pub(super) fn reject_unknown_keys(
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

pub(super) fn reject_explicit_nulls(
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

pub(super) fn validate_positive_i64_json(
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

pub(super) fn validate_u64_json(
    value: Option<&Value>,
    label: &str,
) -> Result<(), ServiceProfileError> {
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

pub(super) fn validate_u32_percent_json(
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

pub(super) fn validate_non_blank_string_json(
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

pub(super) fn is_blank(value: &str) -> bool {
    value.trim().is_empty()
}

pub(super) fn validate_unique_non_blank_strings(
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

pub(super) fn visibility_scope_key(scope: &crate::survey::VisibilityScopeV1) -> &'static str {
    match scope {
        crate::survey::VisibilityScopeV1::BareMetalLike => "bare_metal_like",
        crate::survey::VisibilityScopeV1::VmLike => "vm_like",
        crate::survey::VisibilityScopeV1::ContainerRestricted => "container_restricted",
        crate::survey::VisibilityScopeV1::Unknown => "unknown",
    }
}

pub(super) fn assurance_predicate_key(predicate: AssurancePredicateV1) -> &'static str {
    match predicate {
        AssurancePredicateV1::LocallyVerifiedRequired => "locally_verified_required",
        AssurancePredicateV1::HardwareAttestedRequired => "hardware_attested_required",
    }
}
