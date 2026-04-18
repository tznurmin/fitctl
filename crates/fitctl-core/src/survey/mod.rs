// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Survey collection and replay.
//!
//! Survey is the observation side of the tool. It records what the host exposes through live Linux
//! sources or replay fixtures without yet deciding what the host may promise under policy.

use std::path::PathBuf;

use crate::artifacts::survey_v1::HostSurveyV1;

pub mod collector_matrix_v1;
pub mod execution_context_v1;
pub mod live_v1;
pub mod normalize_v1;
pub mod replay_v1;

pub use execution_context_v1::{
    deserialize_observation_limitation_reason_opt_v1, validate_observation_field_coherence_v1,
    ExecutionContextV1, ObservationLimitationReasonV1, ObservationStateV1, PrivilegeLevelV1,
    VisibilityScopeV1,
};
pub use live_v1::{
    AcceleratorDetailsV1, AcceleratorDeviceV1, AcceleratorDiscoverySourceV1,
    AcceleratorIntegrationV1, AcceleratorKindV1, AcceleratorOperabilityV1, CollectedHostSnapshotV1,
    CpuCacheSummaryBasisV1, CpuCacheSummaryV1, CpuDetailsV1, CpuModelBasisV1, IpAddressFamilyV1,
    LocalLiveProbeV1, MemoryDetailsV1, NetworkAddressV1, NetworkAddressabilitySummaryV1,
    NetworkCarrierStateV1, NetworkDetailsV1, NetworkDuplexV1, NetworkInterfaceKindV1,
    NetworkInterfaceV1, NetworkInterfaceVirtualityV1, NetworkLinkStateV1, NoopLiveProbeV1,
    StaticOperabilityV1, StorageBlockDeviceClassV1, StorageBlockDeviceV1, StorageDetailsV1,
    StorageMountRoleV1, StorageMountV1, SurveyFieldV1, SurveyObservationsV1, TopologyDetailsV1,
};
pub use replay_v1::{
    load_fixture_corpus_manifest, FixtureCorpusEntryV1, FixtureCorpusManifestV1,
    SurveyFixtureSnapshotV1,
};

pub const SURVEY_ERROR_MODEL_ID: &str = "fitctl.survey.v1";
pub const SURVEY_ERROR_MODEL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurveyErrorCode {
    FixtureCorpusInvalid,
    FixturePathInvalid,
    CollectorSourceUnavailable,
    CollectorPrivilegeInsufficient,
    CollectorPayloadMalformed,
    NormalizationFailed,
    SurveyArtifactInvalid,
    VisibilityScopeUnresolved,
}

impl SurveyErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FixtureCorpusInvalid => "fixture_corpus_invalid",
            Self::FixturePathInvalid => "fixture_path_invalid",
            Self::CollectorSourceUnavailable => "collector_source_unavailable",
            Self::CollectorPrivilegeInsufficient => "collector_privilege_insufficient",
            Self::CollectorPayloadMalformed => "collector_payload_malformed",
            Self::NormalizationFailed => "normalization_failed",
            Self::SurveyArtifactInvalid => "survey_artifact_invalid",
            Self::VisibilityScopeUnresolved => "visibility_scope_unresolved",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurveyError {
    pub code: SurveyErrorCode,
    pub checkpoint_id: &'static str,
    pub message: String,
    pub error_model_id: &'static str,
    pub error_model_version: u32,
}

impl SurveyError {
    pub(crate) fn new(
        code: SurveyErrorCode,
        checkpoint_id: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            checkpoint_id,
            message: message.into(),
            error_model_id: SURVEY_ERROR_MODEL_ID,
            error_model_version: SURVEY_ERROR_MODEL_VERSION,
        }
    }
}

impl std::fmt::Display for SurveyError {
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

impl std::error::Error for SurveyError {}

pub trait LiveSystemProbeV1 {
    fn collect_snapshot(&self) -> Result<CollectedHostSnapshotV1, SurveyError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SurveyModeV1 {
    Live,
    Replay {
        fixtures_root: PathBuf,
        fixture_id: String,
    },
}

pub struct SurveyEngineV1<P> {
    live_probe: P,
}

impl<P> SurveyEngineV1<P> {
    pub fn new(live_probe: P) -> Self {
        Self { live_probe }
    }
}

impl<P> SurveyEngineV1<P>
where
    P: LiveSystemProbeV1,
{
    // Survey collection is snapshot-oriented: collect raw evidence first, then let normalization
    // own the typed artifact shape and validation.
    pub fn collect_host_survey(&self, mode: SurveyModeV1) -> Result<HostSurveyV1, SurveyError> {
        let snapshot = match mode {
            SurveyModeV1::Live => self.live_probe.collect_snapshot()?,
            SurveyModeV1::Replay {
                fixtures_root,
                fixture_id,
            } => replay_v1::load_snapshot_from_corpus(&fixtures_root, &fixture_id)?,
        };

        normalize_v1::build_host_survey_from_snapshot(snapshot)
    }
}
