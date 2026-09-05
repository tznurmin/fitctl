// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Shared artifact-envelope structures used by every top-level artifact family.

use serde::{Deserialize, Serialize};

mod build_provenance {
    include!(concat!(env!("OUT_DIR"), "/fitctl_build_provenance.rs"));
}

pub const LOCAL_FITCTL_VERSION_V1: &str = env!("CARGO_PKG_VERSION");

pub fn local_fitctl_version_display_v1() -> String {
    format_fitctl_version_display_v1(
        LOCAL_FITCTL_VERSION_V1,
        local_fitctl_vcs_revision_v1().as_deref(),
        local_fitctl_vcs_describe_v1().as_deref(),
        local_fitctl_build_dirty_v1(),
    )
}

pub fn format_fitctl_version_display_v1(
    version: &str,
    vcs_revision: Option<&str>,
    vcs_describe: Option<&str>,
    build_dirty: Option<bool>,
) -> String {
    let Some(revision_label) = vcs_revision
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(short_revision_label_v1)
        .or_else(|| {
            vcs_describe
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
        })
    else {
        return version.to_string();
    };

    let dirty_suffix = if build_dirty == Some(true) {
        ", dirty"
    } else {
        ""
    };
    format!("{version} ({revision_label}{dirty_suffix})")
}

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
    build_provenance::FITCTL_VCS_REVISION.map(ToOwned::to_owned)
}

fn local_fitctl_vcs_describe_v1() -> Option<String> {
    build_provenance::FITCTL_VCS_DESCRIBE.map(ToOwned::to_owned)
}

fn local_fitctl_build_dirty_v1() -> Option<bool> {
    build_provenance::FITCTL_BUILD_DIRTY
}

fn short_revision_label_v1(value: &str) -> String {
    value.chars().take(7).collect()
}

#[cfg(test)]
mod tests {
    use super::format_fitctl_version_display_v1;

    #[test]
    fn version_display_prefers_short_revision_when_available() {
        assert_eq!(
            format_fitctl_version_display_v1(
                "0.6.0-dev",
                Some("0123456789abcdef0123456789abcdef01234567"),
                Some("v0.0.0-test-0-g0123456"),
                Some(false),
            ),
            "0.6.0-dev (0123456)"
        );
    }

    #[test]
    fn version_display_falls_back_to_describe_without_revision() {
        assert_eq!(
            format_fitctl_version_display_v1(
                "0.6.0-dev",
                None,
                Some("v0.0.0-test-0-g0123456"),
                Some(false),
            ),
            "0.6.0-dev (v0.0.0-test-0-g0123456)"
        );
    }

    #[test]
    fn version_display_preserves_plain_version_without_revision() {
        assert_eq!(
            format_fitctl_version_display_v1("0.6.0-dev", None, None, Some(false)),
            "0.6.0-dev"
        );
    }

    #[test]
    fn version_display_marks_dirty_builds() {
        assert_eq!(
            format_fitctl_version_display_v1("0.6.0-dev", Some("0123456"), None, Some(true)),
            "0.6.0-dev (0123456, dirty)"
        );
    }
}
