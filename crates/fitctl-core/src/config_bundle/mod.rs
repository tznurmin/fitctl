// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Local config-bundle assembly over selected policy, optional profile, and optional trust policy.
//!
//! This module keeps the bundle narrow: one reusable advanced-run config object that stays local
//! and explicit, without widening into remote registries or decision outputs.

use std::path::Path;

use crate::artifacts::config_bundle_v1::{
    ConfigBundleBasisV1, ConfigBundlePayloadV1, ConfigBundleV1,
};
use crate::artifacts::envelope_v1::{local_artifact_provenance_v1, LOCAL_FITCTL_VERSION_V1};
use crate::artifacts::record_v1::{load_artifact_record_from_path, ArtifactRecordV1};
use crate::artifacts::schema_ids_v1::{CONFIG_BUNDLE_SCHEMA_ID, TOP_LEVEL_ARTIFACT_SCHEMA_VERSION};
use crate::artifacts::service_profile_v1::ServiceProfileV1;
use crate::artifacts::validation_v1::validate_config_bundle;
use crate::config::{semantic_hash_hex_for_resolved_config, ResolvedConfigV1};
use crate::policy::PolicyDocumentV1;
use crate::verify::TrustPolicyV1;

pub const CONFIG_BUNDLE_ERROR_MODEL_ID: &str = "fitctl.config_bundle.v1";
pub const CONFIG_BUNDLE_ERROR_MODEL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigBundleErrorCode {
    ConfigBundleInputInvalid,
    ConfigBundleLineageMismatch,
    ConfigBundleEmitInvalid,
}

impl ConfigBundleErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfigBundleInputInvalid => "config_bundle_input_invalid",
            Self::ConfigBundleLineageMismatch => "config_bundle_lineage_mismatch",
            Self::ConfigBundleEmitInvalid => "config_bundle_emit_invalid",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigBundleError {
    pub code: ConfigBundleErrorCode,
    pub checkpoint_id: &'static str,
    pub message: String,
    pub error_model_id: &'static str,
    pub error_model_version: u32,
}

impl ConfigBundleError {
    pub fn new(
        code: ConfigBundleErrorCode,
        checkpoint_id: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            checkpoint_id,
            message: message.into(),
            error_model_id: CONFIG_BUNDLE_ERROR_MODEL_ID,
            error_model_version: CONFIG_BUNDLE_ERROR_MODEL_VERSION,
        }
    }
}

impl std::fmt::Display for ConfigBundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} [{} at {}]",
            self.message,
            self.code.as_str(),
            self.checkpoint_id
        )
    }
}

impl std::error::Error for ConfigBundleError {}

#[derive(Debug, Clone, PartialEq)]
pub struct ConfigBundleAssemblyRequestV1 {
    pub policy: PolicyDocumentV1,
    pub service_profile: Option<ServiceProfileV1>,
    pub trust_policy: Option<TrustPolicyV1>,
    pub resolved_config: ResolvedConfigV1,
    pub bundled_at: String,
    pub notes: Option<String>,
}

/// Assemble one local config bundle and validate that the embedded config lineage stays aligned.
pub fn assemble_config_bundle_v1(
    request: ConfigBundleAssemblyRequestV1,
) -> Result<ConfigBundleV1, ConfigBundleError> {
    if request.bundled_at.trim().is_empty() {
        return Err(ConfigBundleError::new(
            ConfigBundleErrorCode::ConfigBundleInputInvalid,
            "config_bundle_assemble",
            "bundle timestamp must be populated",
        ));
    }

    let resolved_config_semantic_hash =
        semantic_hash_hex_for_resolved_config(&request.resolved_config).map_err(|error| {
            ConfigBundleError::new(
                ConfigBundleErrorCode::ConfigBundleInputInvalid,
                "config_bundle_assemble",
                error.message,
            )
        })?;

    let artifact_id = match request.service_profile.as_ref() {
        Some(profile) => format!(
            "config-bundle-{}-{}",
            request.policy.policy_id, profile.profile.profile_id
        ),
        None => format!("config-bundle-{}", request.policy.policy_id),
    };

    let bundle = ConfigBundleV1 {
        envelope: crate::artifacts::envelope_v1::ArtifactEnvelopeV1 {
            schema_id: CONFIG_BUNDLE_SCHEMA_ID.to_string(),
            schema_version: TOP_LEVEL_ARTIFACT_SCHEMA_VERSION,
            artifact_id: artifact_id.clone(),
            provenance: local_artifact_provenance_v1(
                "bundle-config:advanced_run",
                request.bundled_at,
                "bundle-config",
                artifact_id,
            ),
            redaction: None,
            signatures: vec![],
        },
        config_bundle_basis: ConfigBundleBasisV1 {
            policy_id: request.policy.policy_id.clone(),
            service_profile_id: request
                .service_profile
                .as_ref()
                .map(|profile| profile.profile.profile_id.clone()),
            trust_policy_id: request
                .trust_policy
                .as_ref()
                .map(|policy| policy.policy_id.clone()),
            resolved_config_semantic_hash,
        },
        config_bundle: ConfigBundlePayloadV1 {
            policy: request.policy,
            resolved_config: request.resolved_config,
            service_profile: request.service_profile,
            trust_policy: request.trust_policy,
        },
    };

    validate_config_bundle(&bundle).map_err(|error| {
        let code = match error.code {
            crate::artifacts::validation_v1::ArtifactValidationErrorCode::ArtifactPayloadCorrupt => {
                ConfigBundleErrorCode::ConfigBundleLineageMismatch
            }
            crate::artifacts::validation_v1::ArtifactValidationErrorCode::ArtifactSchemaIdInvalid
            | crate::artifacts::validation_v1::ArtifactValidationErrorCode::ArtifactSchemaVersionInvalid
            | crate::artifacts::validation_v1::ArtifactValidationErrorCode::ContractBasisInvalid => {
                ConfigBundleErrorCode::ConfigBundleEmitInvalid
            }
        };
        ConfigBundleError::new(code, "config_bundle_validate", error.message)
    })?;

    Ok(bundle)
}

/// Convert the config bundle into a generic artifact record for signing, inspect, and diff.
pub fn config_bundle_record_v1(bundle: ConfigBundleV1) -> ArtifactRecordV1 {
    ArtifactRecordV1::ConfigBundle(bundle)
}

/// Load one config-bundle artifact from disk and fail closed on wrong schema or invalid lineage.
pub fn load_config_bundle_from_path_v1(path: &Path) -> Result<ConfigBundleV1, ConfigBundleError> {
    match load_artifact_record_from_path(path).map_err(|error| {
        ConfigBundleError::new(
            ConfigBundleErrorCode::ConfigBundleInputInvalid,
            "config_bundle_load",
            error.message,
        )
    })? {
        ArtifactRecordV1::ConfigBundle(bundle) => Ok(bundle),
        other => Err(ConfigBundleError::new(
            ConfigBundleErrorCode::ConfigBundleInputInvalid,
            "config_bundle_load",
            format!(
                "expected fitctl.config-bundle.v2 artifact but found {}",
                other.schema_id()
            ),
        )),
    }
}

pub fn fitctl_version_v1() -> &'static str {
    LOCAL_FITCTL_VERSION_V1
}
