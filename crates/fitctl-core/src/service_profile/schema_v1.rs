// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Specialized profile ingress, including raw, typed, semantic and artifact validation.

use super::validation::{validate_service_profile_json, validate_service_profile_semantics};
use crate::artifacts::service_profile_v1::ServiceProfileV1;
use crate::artifacts::validation_v1::{validate_service_profile, ArtifactValidationErrorCode};
use crate::service_profile::{ServiceProfileError, ServiceProfileErrorCode};
use serde_json::Value;
use std::fs;
use std::path::Path;

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
    decode_service_profile(raw, Some(path))
}

/// Validate supplied profile JSON through the complete specialized ingress pipeline.
///
/// Unlike generic artifact-record loading, this rejects explicit optional nulls and
/// checks profile-specific requirements, degradation and assurance semantics.
/// Both specialized loaders preserve supported shared provenance, including redacted exports.
/// Performs no I/O; errors have no invented source path.
pub fn load_service_profile_from_value(
    raw: Value,
) -> Result<ServiceProfileV1, ServiceProfileError> {
    decode_service_profile(raw, None)
}

fn decode_service_profile(
    raw: Value,
    source_path: Option<&Path>,
) -> Result<ServiceProfileV1, ServiceProfileError> {
    validate_service_profile_json(&raw)?;

    let profile: ServiceProfileV1 = serde_json::from_value(raw).map_err(|error| {
        ServiceProfileError::new(
            ServiceProfileErrorCode::ServiceProfileDocumentInvalid,
            "profile_decode",
            match source_path {
                Some(path) => format!(
                    "failed to decode typed service profile {}: {error}",
                    path.display()
                ),
                None => format!("failed to decode typed service profile: {error}"),
            },
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
