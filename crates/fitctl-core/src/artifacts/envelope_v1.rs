// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Shared artifact-envelope structures used by every top-level artifact family.

use serde::{Deserialize, Serialize};

pub const LOCAL_FITCTL_VERSION_V1: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactEnvelopeV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub artifact_id: String,
    pub provenance: ArtifactProvenanceV1,
    pub redaction: Option<RedactionEnvelopeV1>,
    #[serde(default)]
    pub signatures: Vec<SignatureEnvelopeV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactProvenanceV1 {
    pub source: String,
    pub collected_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fitctl_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fitctl_vcs_revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fitctl_vcs_describe: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fitctl_build_dirty: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionEnvelopeV1 {
    pub profile_id: String,
    pub redacted_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SignatureEnvelopeV1 {
    pub key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_encoding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_semantic_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<String>,
    pub signature: String,
}

/// Build the standard local provenance block for artifacts emitted by the CLI or core helpers.
pub fn local_artifact_provenance_v1(
    source: impl Into<String>,
    collected_at: impl Into<String>,
    command_name: impl Into<String>,
    correlation_id: impl Into<String>,
) -> ArtifactProvenanceV1 {
    ArtifactProvenanceV1 {
        source: source.into(),
        collected_at: collected_at.into(),
        fitctl_version: Some(LOCAL_FITCTL_VERSION_V1.to_string()),
        fitctl_vcs_revision: local_fitctl_vcs_revision_v1(),
        fitctl_vcs_describe: local_fitctl_vcs_describe_v1(),
        fitctl_build_dirty: local_fitctl_build_dirty_v1(),
        command_name: Some(command_name.into()),
        correlation_id: Some(correlation_id.into()),
    }
}

fn local_fitctl_vcs_revision_v1() -> Option<String> {
    option_env!("FITCTL_VCS_REVISION")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn local_fitctl_vcs_describe_v1() -> Option<String> {
    option_env!("FITCTL_VCS_DESCRIBE")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn local_fitctl_build_dirty_v1() -> Option<bool> {
    match option_env!("FITCTL_BUILD_DIRTY").map(str::trim) {
        Some("true") => Some(true),
        Some("false") => Some(false),
        _ => None,
    }
}
