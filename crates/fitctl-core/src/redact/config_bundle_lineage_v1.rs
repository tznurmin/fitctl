// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Lineage repair after nested service-profile sharing transforms.

use crate::artifacts::config_bundle_v1::ConfigBundleV1;
use crate::config::semantic_hash_hex_for_resolved_config;
use crate::redact::{RedactionError, RedactionErrorCode};

pub(crate) fn repair_config_bundle_service_profile_lineage(
    artifact: &mut ConfigBundleV1,
) -> Result<(), RedactionError> {
    let Some(service_profile) = artifact.config_bundle.service_profile.as_ref() else {
        return Ok(());
    };
    let profile_id = service_profile.profile.profile_id.clone();
    artifact.config_bundle_basis.service_profile_id = Some(profile_id.clone());
    if artifact
        .config_bundle
        .resolved_config
        .selected_service_profile_entry_id
        .is_some()
    {
        artifact
            .config_bundle
            .resolved_config
            .selected_service_profile_entry_id = Some(profile_id);
        artifact.config_bundle_basis.resolved_config_semantic_hash =
            semantic_hash_hex_for_resolved_config(&artifact.config_bundle.resolved_config)
                .map_err(|error| {
                    RedactionError::new(
                        RedactionErrorCode::RedactionApplyFailed,
                        "redaction_apply",
                        error.message,
                    )
                })?;
    }
    Ok(())
}
