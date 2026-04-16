// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Live runtime-state capture and replay.
//!
//! State is the volatile companion to survey and contract artifacts. It captures current runtime
//! ceilings and degradation signals without redefining the host contract.

use std::fs;
use std::path::{Path, PathBuf};

use crate::artifacts::state_v1::HostStateV1;
use crate::artifacts::validation_v1::{validate_host_state, ArtifactValidationErrorCode};

pub mod live_v1;
pub mod normalize_v1;
pub mod replay_v1;

pub use crate::artifacts::state_v1::{
    FreshnessStateV1, HostRuntimeResourcesV1, HostStateExecutionBoundariesV1,
    StateCollectionModeV1, StateFieldV1, StateFreshnessV1,
};
pub use live_v1::{
    CollectedHostStateSnapshotV1, LocalLiveStateProbeV1, NoopLiveStateProbeV1, SnapshotSourceKindV1,
};
pub use replay_v1::{
    load_fixture_corpus_manifest, FixtureCorpusEntryV1, FixtureCorpusManifestV1,
    HostStateFixtureSnapshotV1,
};

pub const STATE_ERROR_MODEL_ID: &str = "fitctl.state.v1";
pub const STATE_ERROR_MODEL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateErrorCode {
    FixtureCorpusInvalid,
    FixturePathInvalid,
    StateSourceUnavailable,
    StatePayloadMalformed,
    StateNormalizationFailed,
    HostStateArtifactInvalid,
}

impl StateErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FixtureCorpusInvalid => "fixture_corpus_invalid",
            Self::FixturePathInvalid => "fixture_path_invalid",
            Self::StateSourceUnavailable => "state_source_unavailable",
            Self::StatePayloadMalformed => "state_payload_malformed",
            Self::StateNormalizationFailed => "state_normalization_failed",
            Self::HostStateArtifactInvalid => "host_state_artifact_invalid",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateError {
    pub code: StateErrorCode,
    pub checkpoint_id: &'static str,
    pub message: String,
    pub error_model_id: &'static str,
    pub error_model_version: u32,
}

impl StateError {
    pub(crate) fn new(
        code: StateErrorCode,
        checkpoint_id: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            checkpoint_id,
            message: message.into(),
            error_model_id: STATE_ERROR_MODEL_ID,
            error_model_version: STATE_ERROR_MODEL_VERSION,
        }
    }
}

impl std::fmt::Display for StateError {
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

impl std::error::Error for StateError {}

pub trait LiveStateProbeV1 {
    fn collect_snapshot(&self) -> Result<CollectedHostStateSnapshotV1, StateError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateModeV1 {
    Live,
    Replay {
        fixtures_root: PathBuf,
        fixture_id: String,
    },
}

pub struct StateEngineV1<P> {
    live_probe: P,
}

impl<P> StateEngineV1<P> {
    pub fn new(live_probe: P) -> Self {
        Self { live_probe }
    }
}

impl<P> StateEngineV1<P>
where
    P: LiveStateProbeV1,
{
    // State collection mirrors survey collection: gather a live or replay snapshot first, then let
    // normalization own the final typed artifact shape.
    pub fn collect_host_state(&self, mode: StateModeV1) -> Result<HostStateV1, StateError> {
        let snapshot = match mode {
            StateModeV1::Live => self.live_probe.collect_snapshot()?,
            StateModeV1::Replay {
                fixtures_root,
                fixture_id,
            } => replay_v1::load_snapshot_from_corpus(&fixtures_root, &fixture_id)?,
        };

        normalize_v1::build_host_state_from_snapshot(snapshot)
    }
}

pub fn load_host_state_from_path(path: &Path) -> Result<HostStateV1, StateError> {
    let text = fs::read_to_string(path).map_err(|error| {
        StateError::new(
            StateErrorCode::HostStateArtifactInvalid,
            "state_load",
            format!(
                "failed to read host-state artifact {}: {error}",
                path.display()
            ),
        )
    })?;
    let host_state: HostStateV1 = serde_json::from_str(&text).map_err(|error| {
        StateError::new(
            StateErrorCode::HostStateArtifactInvalid,
            "state_load",
            format!(
                "failed to decode host-state artifact {}: {error}",
                path.display()
            ),
        )
    })?;

    validate_host_state(&host_state).map_err(|error| {
        let code = match error.code {
            ArtifactValidationErrorCode::ArtifactSchemaIdInvalid
            | ArtifactValidationErrorCode::ArtifactSchemaVersionInvalid
            | ArtifactValidationErrorCode::ArtifactPayloadCorrupt
            | ArtifactValidationErrorCode::ContractBasisInvalid => {
                StateErrorCode::HostStateArtifactInvalid
            }
        };
        StateError::new(code, "state_load", error.message)
    })?;

    Ok(host_state)
}
