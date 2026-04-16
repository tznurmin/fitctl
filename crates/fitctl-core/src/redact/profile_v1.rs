// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Built-in redaction profiles and the placeholder strategy they select.

use crate::redact::{RedactionError, RedactionErrorCode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuiltInRedactionProfileV1 {
    Local,
    Fleet,
    Auditor,
    External,
}

impl BuiltInRedactionProfileV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Fleet => "fleet",
            Self::Auditor => "auditor",
            Self::External => "external",
        }
    }

    pub(crate) fn applies_fleet_redactions(self) -> bool {
        !matches!(self, Self::Local)
    }

    pub(crate) fn applies_auditor_redactions(self) -> bool {
        matches!(self, Self::Auditor | Self::External)
    }

    pub(crate) fn applies_external_redactions(self) -> bool {
        matches!(self, Self::External)
    }

    pub(crate) fn host_placeholder(self) -> String {
        format!("redacted:{}:host", self.as_str())
    }

    pub(crate) fn source_ref_placeholder(self) -> String {
        format!("redacted:{}:source_ref", self.as_str())
    }

    pub(crate) fn cpu_model_placeholder(self) -> String {
        format!("redacted:{}:cpu_model", self.as_str())
    }

    pub(crate) fn block_device_placeholder(self) -> String {
        format!("redacted:{}:block_device", self.as_str())
    }

    pub(crate) fn mount_path_placeholder(self) -> String {
        format!("redacted:{}:mount_path", self.as_str())
    }

    pub(crate) fn network_interface_placeholder(self) -> String {
        format!("redacted:{}:network_interface", self.as_str())
    }

    pub(crate) fn policy_ref_placeholder(self) -> String {
        format!("redacted:{}:policy_ref", self.as_str())
    }

    pub(crate) fn evidence_ref_placeholder(self) -> String {
        format!("redacted:{}:evidence_ref", self.as_str())
    }

    pub(crate) fn policy_layer_placeholder(self) -> String {
        format!("redacted:{}:policy_layer", self.as_str())
    }

    pub(crate) fn local_stable_identity_placeholder(self) -> String {
        format!("redacted:{}:local_stable_id", self.as_str())
    }

    pub(crate) fn provenance_fingerprint_placeholder(self) -> String {
        format!("redacted:{}:provenance_fingerprint", self.as_str())
    }

    pub(crate) fn artifact_id_placeholder(self, schema_family: &str) -> String {
        format!("{schema_family}-redacted-{}-v1", self.as_str())
    }
}

/// Parse one built-in redaction profile id from user input.
pub fn parse_builtin_redaction_profile_v1(
    raw: &str,
) -> Result<BuiltInRedactionProfileV1, RedactionError> {
    match raw {
        "local" => Ok(BuiltInRedactionProfileV1::Local),
        "fleet" => Ok(BuiltInRedactionProfileV1::Fleet),
        "auditor" => Ok(BuiltInRedactionProfileV1::Auditor),
        "external" => Ok(BuiltInRedactionProfileV1::External),
        _ => Err(RedactionError::new(
            RedactionErrorCode::RedactionProfileInvalid,
            "redaction_profile_resolve",
            format!("unsupported built-in redaction profile '{raw}'"),
        )),
    }
}
