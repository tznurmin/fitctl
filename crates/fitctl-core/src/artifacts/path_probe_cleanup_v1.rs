// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Cleanup observations for explicitly requested path probes, not deletion authority.

use serde::{Deserialize, Serialize};

use super::validation_v1::{ArtifactValidationError, ArtifactValidationErrorCode};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostStatePathProbeCleanupV1 {
    pub probe_root: String,
    pub outcome: PathProbeCleanupOutcomeV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathProbeCleanupOutcomeV1 {
    NotCreated,
    Removed,
    RemoveFailed,
}

impl PathProbeCleanupOutcomeV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotCreated => "not_created",
            Self::Removed => "removed",
            Self::RemoveFailed => "remove_failed",
        }
    }
}

pub(crate) fn validate_cleanup(
    cleanup: Option<&[HostStatePathProbeCleanupV1]>,
    expected_roots: usize,
) -> Result<(), ArtifactValidationError> {
    let Some(cleanup) = cleanup else {
        return Ok(());
    };
    let invalid = |message| {
        ArtifactValidationError::new(ArtifactValidationErrorCode::ArtifactPayloadCorrupt, message)
    };
    if !cleanup.is_empty() && cleanup.len() != expected_roots {
        return Err(invalid(
            "path probe cleanup must record every attempted root or an empty list",
        ));
    }
    for (index, entry) in cleanup.iter().enumerate() {
        if entry.probe_root.trim().is_empty()
            || cleanup[..index]
                .iter()
                .any(|prior| prior.probe_root == entry.probe_root)
        {
            return Err(invalid(
                "path probe cleanup roots must be non-blank and distinct",
            ));
        }
        let error_valid = match entry.outcome {
            PathProbeCleanupOutcomeV1::RemoveFailed => entry
                .error
                .as_ref()
                .is_some_and(|error| !error.trim().is_empty()),
            _ => entry.error.is_none(),
        };
        if !error_valid {
            return Err(invalid(
                "path probe cleanup error must be present only for remove_failed",
            ));
        }
    }
    Ok(())
}
