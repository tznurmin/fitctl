// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! CUDA runtime extension evidence, contract derivation, evaluation, and inspect helpers.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::artifacts::field_diagnostic_v1::{
    FieldDiagnosticProbeStatusV1, FieldDiagnosticSourceKindV1, FieldDiagnosticSourceTierV1,
    FieldDiagnosticV1,
};
use crate::artifacts::metadata_v1::{
    AssuranceSourceV1, ClaimMetadataV1, CollectorMetadataV1, DerivationStageV1,
};
use crate::artifacts::state_v1::{HostStateV1, StateFieldV1};
use crate::artifacts::survey_v1::{
    decode_host_survey_payload, encode_host_survey_payload, HostSurveyV1,
};
use crate::config::{
    CudaEnvironmentCatalogueEntryV1, CudaEnvironmentSelectionKindV1, CudaEnvironmentSelectionV1,
};
use crate::redact::profile_v1::BuiltInRedactionProfileV1;
use crate::survey::{
    deserialize_observation_limitation_reason_opt_v1, validate_observation_field_coherence_v1,
    ObservationLimitationReasonV1, ObservationStateV1,
};

pub const CUDA_RUNTIME_NAMESPACE: &str = "fitctl.runtime.cuda";
pub const CUDA_RUNTIME_EVIDENCE_SCHEMA_ID: &str = "fitctl.extension.runtime.cuda.evidence.v1";
pub const CUDA_RUNTIME_CONTRACT_SCHEMA_ID: &str = "fitctl.extension.runtime.cuda.contract.v1";
pub const CUDA_RUNTIME_REQUIREMENT_SCHEMA_ID: &str = "fitctl.extension.runtime.cuda.requirement.v1";
pub const CUDA_RUNTIME_STATE_SCHEMA_ID: &str = "fitctl.extension.runtime.cuda.state.v1";
pub const CUDA_RUNTIME_VALIDATION_DIAGNOSTIC_MODEL_ID: &str =
    "fitctl.cuda_runtime_validation_diagnostic.v1";
pub const CUDA_SELECTED_ENVIRONMENT_INPUT_SCHEMA_ID: &str =
    "fitctl.extension.runtime.cuda.selected_environment_input.v1";

const CUDA_RUNTIME_COLLECTOR_ID: &str = "fitctl.runtime.cuda.collector.v1";
const CUDA_RUNTIME_STATE_COLLECTOR_ID: &str = "fitctl.runtime.cuda.state_collector.v1";
const CUDA_RUNTIME_COLLECTOR_VERSION: &str = "1";
const CUDA_RUNTIME_LIVE_SOURCE_FAMILY: &str = "command_probe";
const CUDA_RUNTIME_REPLAY_SOURCE_FAMILY: &str = "fixture_replay";
const CUDA_RUNTIME_REPLAY_CORPUS_SCHEMA_ID: &str =
    "fitctl.fixture.extension.runtime.cuda.corpus.v1";
const CUDA_RUNTIME_REPLAY_SNAPSHOT_SCHEMA_ID: &str =
    "fitctl.fixture.extension.runtime.cuda.snapshot.v1";
const CUDA_RUNTIME_STATE_REPLAY_CORPUS_SCHEMA_ID: &str =
    "fitctl.fixture.extension.runtime.cuda.state.corpus.v1";
const CUDA_RUNTIME_STATE_REPLAY_SNAPSHOT_SCHEMA_ID: &str =
    "fitctl.fixture.extension.runtime.cuda.state.snapshot.v1";

const CUDA_EVIDENCE_PATH: &str = "$.survey.extension_evidence.fitctl.runtime.cuda";
const CUDA_CONTRACT_PATH: &str = "$.contract.extension_contract.fitctl.runtime.cuda";
const CUDA_STATE_PATH: &str = "$.state.extension_state.fitctl.runtime.cuda";

const TEST_CUDA_STUB_LIVE_PROBES_ENV: &str = "FITCTL_TEST_CUDA_STUB_LIVE_PROBES";
const TEST_CUDA_NVCC_PATH_ENV: &str = "FITCTL_TEST_CUDA_NVCC_PATH";
const TEST_CUDA_NVCC_VERSION_OUTPUT_ENV: &str = "FITCTL_TEST_CUDA_NVCC_VERSION_OUTPUT";
const TEST_CUDA_DRIVER_VERSION_TEXT_ENV: &str = "FITCTL_TEST_CUDA_DRIVER_VERSION_TEXT";
const TEST_CUDA_DRIVER_SUPPORTED_VERSION_ENV: &str = "FITCTL_TEST_CUDA_DRIVER_SUPPORTED_VERSION";
const TEST_CUDA_DEFAULT_RUNTIME_VERSION_ENV: &str = "FITCTL_TEST_CUDA_DEFAULT_RUNTIME_VERSION";
const TEST_CUDA_NVIDIA_SMI_PATH_ENV: &str = "FITCTL_TEST_CUDA_NVIDIA_SMI_PATH";
const TEST_CUDA_NVIDIA_SMI_OUTPUT_ENV: &str = "FITCTL_TEST_CUDA_NVIDIA_SMI_OUTPUT";
const TEST_CUDA_NVIDIA_SMI_BANNER_PATH_ENV: &str = "FITCTL_TEST_CUDA_NVIDIA_SMI_BANNER_PATH";
const TEST_CUDA_NVIDIA_SMI_BANNER_OUTPUT_ENV: &str = "FITCTL_TEST_CUDA_NVIDIA_SMI_BANNER_OUTPUT";
const TEST_CUDA_INSTALLED_TOOLKITS_JSON_ENV: &str = "FITCTL_TEST_CUDA_INSTALLED_TOOLKITS_JSON";
const TEST_CUDA_SELECTED_ENVIRONMENT_NVCC_VERSION_OUTPUT_ENV: &str =
    "FITCTL_TEST_CUDA_SELECTED_ENVIRONMENT_NVCC_VERSION_OUTPUT";
const TEST_CUDA_SELECTED_ENVIRONMENT_RUNTIME_VERSION_ENV: &str =
    "FITCTL_TEST_CUDA_SELECTED_ENVIRONMENT_RUNTIME_VERSION";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CudaRuntimeExtensionError {
    pub checkpoint_id: &'static str,
    pub message: String,
}

impl CudaRuntimeExtensionError {
    fn new(checkpoint_id: &'static str, message: impl Into<String>) -> Self {
        Self {
            checkpoint_id,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for CudaRuntimeExtensionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} [fitctl.cuda_runtime_extension.v1 at {}]",
            self.message, self.checkpoint_id
        )
    }
}

impl std::error::Error for CudaRuntimeExtensionError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CudaRuntimeEvidenceStateV1 {
    Observed,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CudaRuntimeVersionV1 {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CudaInstalledToolkitV1 {
    pub install_root: String,
    pub version: CudaRuntimeVersionV1,
    #[serde(default, skip_serializing_if = "is_false")]
    pub selected_by_default_toolkit_view: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CudaSelectedEnvironmentV1 {
    pub environment_id: String,
    pub selection: CudaEnvironmentSelectionV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CudaSelectedEnvironmentProbeDiagnosticsV1 {
    pub toolkit_version: CudaDefaultViewFieldDiagnosticV1,
    pub runtime_version: CudaDefaultViewFieldDiagnosticV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CudaSelectedEnvironmentInputV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub selected_environment: CudaSelectedEnvironmentV1,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_cuda_runtime_version_opt_v1"
    )]
    pub toolkit_version: Option<CudaRuntimeVersionV1>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_cuda_runtime_version_opt_v1"
    )]
    pub runtime_version: Option<CudaRuntimeVersionV1>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_cuda_selected_environment_probe_diagnostics_opt_v1"
    )]
    pub probe_diagnostics: Option<CudaSelectedEnvironmentProbeDiagnosticsV1>,
}

pub type CudaDefaultViewProbeSourceTierV1 = FieldDiagnosticSourceTierV1;
pub type CudaDefaultViewProbeSourceKindV1 = FieldDiagnosticSourceKindV1;
pub type CudaDefaultViewProbeStatusV1 = FieldDiagnosticProbeStatusV1;
pub type CudaDefaultViewFieldDiagnosticV1 = FieldDiagnosticV1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CudaDefaultViewProbeDiagnosticsV1 {
    pub default_toolkit_version: CudaDefaultViewFieldDiagnosticV1,
    pub driver_version: CudaDefaultViewFieldDiagnosticV1,
    pub driver_supported_cuda_version: CudaDefaultViewFieldDiagnosticV1,
    pub default_runtime_version: CudaDefaultViewFieldDiagnosticV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CudaRuntimeVersionRangeV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_inclusive: Option<CudaRuntimeVersionV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_exclusive: Option<CudaRuntimeVersionV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CudaRuntimeEvidenceV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub collector: CollectorMetadataV1,
    pub claim_metadata: ClaimMetadataV1,
    pub runtime_id: String,
    pub runtime_state: CudaRuntimeEvidenceStateV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<CudaRuntimeVersionV1>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_cuda_runtime_version_opt_v1"
    )]
    pub driver_version: Option<CudaRuntimeVersionV1>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_cuda_runtime_version_opt_v1"
    )]
    pub driver_supported_cuda_version: Option<CudaRuntimeVersionV1>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_cuda_runtime_version_opt_v1"
    )]
    pub default_runtime_version: Option<CudaRuntimeVersionV1>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_cuda_default_view_probe_diagnostics_opt_v1"
    )]
    pub default_view_probe_diagnostics: Option<CudaDefaultViewProbeDiagnosticsV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_environment: Option<CudaSelectedEnvironmentV1>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_cuda_runtime_version_opt_v1"
    )]
    pub selected_environment_toolkit_version: Option<CudaRuntimeVersionV1>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_cuda_runtime_version_opt_v1"
    )]
    pub selected_environment_runtime_version: Option<CudaRuntimeVersionV1>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_cuda_selected_environment_probe_diagnostics_opt_v1"
    )]
    pub selected_environment_probe_diagnostics: Option<CudaSelectedEnvironmentProbeDiagnosticsV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub installed_toolkits: Vec<CudaInstalledToolkitV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CudaRuntimeContractV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub claim_metadata: ClaimMetadataV1,
    pub runtime_id: String,
    pub runtime_available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<CudaRuntimeVersionV1>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_cuda_runtime_version_opt_v1"
    )]
    pub driver_version: Option<CudaRuntimeVersionV1>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_cuda_runtime_version_opt_v1"
    )]
    pub driver_supported_cuda_version: Option<CudaRuntimeVersionV1>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_cuda_runtime_version_opt_v1"
    )]
    pub default_runtime_version: Option<CudaRuntimeVersionV1>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_cuda_default_view_probe_diagnostics_opt_v1"
    )]
    pub default_view_probe_diagnostics: Option<CudaDefaultViewProbeDiagnosticsV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_environment: Option<CudaSelectedEnvironmentV1>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_cuda_runtime_version_opt_v1"
    )]
    pub selected_environment_toolkit_version: Option<CudaRuntimeVersionV1>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_cuda_runtime_version_opt_v1"
    )]
    pub selected_environment_runtime_version: Option<CudaRuntimeVersionV1>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_cuda_selected_environment_probe_diagnostics_opt_v1"
    )]
    pub selected_environment_probe_diagnostics: Option<CudaSelectedEnvironmentProbeDiagnosticsV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub installed_toolkits: Vec<CudaInstalledToolkitV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CudaRuntimeRequirementV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub required_runtime: String,
    #[serde(default = "default_true")]
    pub require_presence: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_version: Option<CudaRuntimeVersionV1>,
    #[serde(default)]
    pub accepted_version_ranges: Vec<CudaRuntimeVersionRangeV1>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_u64_opt_v1"
    )]
    pub minimum_allocatable_memory_bytes: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_u64_opt_v1"
    )]
    pub minimum_device_allocatable_memory_bytes: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_u64_opt_v1"
    )]
    pub minimum_qualifying_device_aggregate_allocatable_memory_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CudaRuntimeStateV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub collector: CollectorMetadataV1,
    pub claim_metadata: ClaimMetadataV1,
    pub runtime_id: String,
    pub runtime_state: ObservationStateV1,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_observation_limitation_reason_opt_v1"
    )]
    pub limitation_reason: Option<ObservationLimitationReasonV1>,
    #[serde(default)]
    pub devices: Vec<CudaRuntimeDeviceStateV1>,
    pub total_memory_bytes: StateFieldV1<u64>,
    pub allocatable_memory_bytes: StateFieldV1<u64>,
    #[serde(
        default = "missing_u64_state_field_v1",
        skip_serializing_if = "is_missing_u64_state_field_v1"
    )]
    pub used_memory_bytes: StateFieldV1<u64>,
    #[serde(
        default = "missing_cuda_runtime_version_state_field_v1",
        skip_serializing_if = "is_missing_cuda_runtime_version_state_field_v1"
    )]
    pub default_toolkit_version: StateFieldV1<CudaRuntimeVersionV1>,
    #[serde(
        default = "missing_cuda_runtime_version_state_field_v1",
        skip_serializing_if = "is_missing_cuda_runtime_version_state_field_v1"
    )]
    pub driver_version: StateFieldV1<CudaRuntimeVersionV1>,
    #[serde(
        default = "missing_cuda_runtime_version_state_field_v1",
        skip_serializing_if = "is_missing_cuda_runtime_version_state_field_v1"
    )]
    pub driver_supported_cuda_version: StateFieldV1<CudaRuntimeVersionV1>,
    #[serde(
        default = "missing_cuda_runtime_version_state_field_v1",
        skip_serializing_if = "is_missing_cuda_runtime_version_state_field_v1"
    )]
    pub default_runtime_version: StateFieldV1<CudaRuntimeVersionV1>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_cuda_default_view_probe_diagnostics_opt_v1"
    )]
    pub default_view_probe_diagnostics: Option<CudaDefaultViewProbeDiagnosticsV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_environment: Option<CudaSelectedEnvironmentV1>,
    #[serde(
        default = "missing_cuda_runtime_version_state_field_v1",
        skip_serializing_if = "is_missing_cuda_runtime_version_state_field_v1"
    )]
    pub selected_environment_toolkit_version: StateFieldV1<CudaRuntimeVersionV1>,
    #[serde(
        default = "missing_cuda_runtime_version_state_field_v1",
        skip_serializing_if = "is_missing_cuda_runtime_version_state_field_v1"
    )]
    pub selected_environment_runtime_version: StateFieldV1<CudaRuntimeVersionV1>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_cuda_selected_environment_probe_diagnostics_opt_v1"
    )]
    pub selected_environment_probe_diagnostics: Option<CudaSelectedEnvironmentProbeDiagnosticsV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CudaSelectedEnvironmentRequestV1 {
    CatalogueEntry(CudaEnvironmentCatalogueEntryV1),
    ReplayInput(CudaSelectedEnvironmentInputV1),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CudaRuntimeDeviceStateV1 {
    pub device_ordinal: u32,
    pub device_uuid: String,
    pub total_memory_bytes: StateFieldV1<u64>,
    pub allocatable_memory_bytes: StateFieldV1<u64>,
    #[serde(
        default = "missing_u64_state_field_v1",
        skip_serializing_if = "is_missing_u64_state_field_v1"
    )]
    pub used_memory_bytes: StateFieldV1<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CudaRuntimeValidationDetailCodeV1 {
    StaticRequirementUnsatisfied,
    RuntimeStateMissing,
    RuntimeStateStale,
    AllocatableMemoryInsufficient,
    QualifyingDeviceCountInsufficient,
    QualifyingDeviceAggregateAllocatableMemoryInsufficient,
    RuntimeThresholdSatisfied,
    QualifyingDeviceThresholdSatisfied,
    QualifyingDeviceAggregateAllocatableMemoryThresholdSatisfied,
}

impl CudaRuntimeValidationDetailCodeV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaticRequirementUnsatisfied => "static_requirement_unsatisfied",
            Self::RuntimeStateMissing => "runtime_state_missing",
            Self::RuntimeStateStale => "runtime_state_stale",
            Self::AllocatableMemoryInsufficient => "allocatable_memory_insufficient",
            Self::QualifyingDeviceCountInsufficient => "qualifying_device_count_insufficient",
            Self::QualifyingDeviceAggregateAllocatableMemoryInsufficient => {
                "qualifying_device_aggregate_allocatable_memory_insufficient"
            }
            Self::RuntimeThresholdSatisfied => "runtime_threshold_satisfied",
            Self::QualifyingDeviceThresholdSatisfied => "qualifying_device_threshold_satisfied",
            Self::QualifyingDeviceAggregateAllocatableMemoryThresholdSatisfied => {
                "qualifying_device_aggregate_allocatable_memory_threshold_satisfied"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CudaRuntimeValidationCheckpointV1 {
    RuntimeExtensionGate,
    RuntimeExtensionState,
    RuntimeExtensionFreshness,
    RuntimeExtensionSummary,
}

impl CudaRuntimeValidationCheckpointV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeExtensionGate => "runtime_extension_gate",
            Self::RuntimeExtensionState => "runtime_extension_state",
            Self::RuntimeExtensionFreshness => "runtime_extension_freshness",
            Self::RuntimeExtensionSummary => "runtime_extension_summary",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CudaRuntimeValidationDiagnosticV1 {
    pub diagnostic_model_id: String,
    pub diagnostic_model_version: u32,
    pub detail_code: CudaRuntimeValidationDetailCodeV1,
    pub checkpoint: CudaRuntimeValidationCheckpointV1,
    #[serde(default)]
    pub related_requirements: Vec<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_u64_opt_v1"
    )]
    pub required_allocatable_memory_bytes: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_u64_opt_v1"
    )]
    pub observed_allocatable_memory_bytes: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_u64_opt_v1"
    )]
    pub observed_total_memory_bytes: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_u32_opt_v1"
    )]
    pub required_qualifying_device_count: Option<u32>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_u32_opt_v1"
    )]
    pub observed_qualifying_device_count: Option<u32>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_u64_opt_v1"
    )]
    pub required_device_allocatable_memory_bytes: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_u64_opt_v1"
    )]
    pub required_qualifying_device_aggregate_allocatable_memory_bytes: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_non_null_u64_opt_v1"
    )]
    pub observed_qualifying_device_aggregate_allocatable_memory_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CudaLiveDefaultViewProbeOutputsV1 {
    nvcc: CudaCommandProbeOutputV1,
    driver_version: CudaFileProbeOutputV1,
    driver_supported_cuda_version: CudaLibraryProbeOutputV1,
    advisory_driver_supported_cuda_version: CudaCommandProbeOutputV1,
    default_runtime_version: CudaLibraryProbeOutputV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CudaLiveDefaultViewFieldsV1 {
    executable_path: Option<String>,
    toolkit_root: Option<PathBuf>,
    toolkit_version: Option<CudaRuntimeVersionV1>,
    driver_version: Option<CudaRuntimeVersionV1>,
    driver_supported_cuda_version: Option<CudaRuntimeVersionV1>,
    default_runtime_version: Option<CudaRuntimeVersionV1>,
    diagnostics: CudaDefaultViewProbeDiagnosticsV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CudaLiveSelectedEnvironmentProbeOutputsV1 {
    nvcc: CudaCommandProbeOutputV1,
    runtime_version: CudaLibraryProbeOutputV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CudaLiveSelectedEnvironmentFieldsV1 {
    selected_environment: CudaSelectedEnvironmentV1,
    toolkit_version: Option<CudaRuntimeVersionV1>,
    runtime_version: Option<CudaRuntimeVersionV1>,
    diagnostics: Option<CudaSelectedEnvironmentProbeDiagnosticsV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CudaCommandProbeOutputV1 {
    source_ref: String,
    status: CudaDefaultViewProbeStatusV1,
    output: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CudaFileProbeOutputV1 {
    source_ref: String,
    status: CudaDefaultViewProbeStatusV1,
    output: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CudaLibraryProbeOutputV1 {
    source_ref: String,
    status: CudaDefaultViewProbeStatusV1,
    raw_version: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CudaDiscoveredToolkitCandidateV1 {
    install_root: PathBuf,
    version: CudaRuntimeVersionV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CudaStubInstalledToolkitProbeEntryV1 {
    install_root: String,
    nvcc_version_output: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CudaRuntimeReplayCorpusV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub namespace: String,
    pub fixtures: Vec<CudaRuntimeReplayFixtureEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CudaRuntimeReplayFixtureEntryV1 {
    pub fixture_id: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CudaRuntimeReplayFixtureSnapshotV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub fixture_id: String,
    pub namespace: String,
    pub evidence: CudaRuntimeEvidenceV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CudaRuntimeStateReplayCorpusV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub namespace: String,
    pub fixtures: Vec<CudaRuntimeReplayFixtureEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CudaRuntimeStateReplayFixtureSnapshotV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub fixture_id: String,
    pub namespace: String,
    pub state: CudaRuntimeStateV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CudaRuntimeEvaluationOutcomeV1 {
    Satisfied,
    Unsatisfied { summary: String },
}

pub fn decode_cuda_runtime_evidence_from_value(
    value: &Value,
) -> Result<CudaRuntimeEvidenceV1, CudaRuntimeExtensionError> {
    let evidence: CudaRuntimeEvidenceV1 =
        serde_json::from_value(value.clone()).map_err(|error| {
            CudaRuntimeExtensionError::new(
                "cuda_extension_normalize",
                format!("failed to decode CUDA runtime extension evidence: {error}"),
            )
        })?;
    validate_cuda_runtime_evidence(&evidence)?;
    Ok(evidence)
}

pub fn decode_cuda_runtime_contract_from_value(
    value: &Value,
) -> Result<CudaRuntimeContractV1, CudaRuntimeExtensionError> {
    let contract: CudaRuntimeContractV1 =
        serde_json::from_value(value.clone()).map_err(|error| {
            CudaRuntimeExtensionError::new(
                "cuda_extension_contract_derive",
                format!("failed to decode CUDA runtime extension contract: {error}"),
            )
        })?;
    validate_cuda_runtime_contract(&contract)?;
    Ok(contract)
}

pub fn decode_cuda_runtime_requirement_from_value(
    value: &Value,
) -> Result<CudaRuntimeRequirementV1, CudaRuntimeExtensionError> {
    let requirement: CudaRuntimeRequirementV1 =
        serde_json::from_value(value.clone()).map_err(|error| {
            CudaRuntimeExtensionError::new(
                "cuda_extension_validate",
                format!("failed to decode CUDA runtime extension requirement: {error}"),
            )
        })?;
    validate_cuda_runtime_requirement(&requirement)?;
    Ok(requirement)
}

pub fn decode_cuda_runtime_state_from_value(
    value: &Value,
) -> Result<CudaRuntimeStateV1, CudaRuntimeExtensionError> {
    let state: CudaRuntimeStateV1 = serde_json::from_value(value.clone()).map_err(|error| {
        CudaRuntimeExtensionError::new(
            "cuda_state_extension_validate",
            format!("failed to decode CUDA runtime extension state: {error}"),
        )
    })?;
    validate_cuda_runtime_state(&state)?;
    Ok(state)
}

pub fn decode_cuda_runtime_validation_diagnostic_from_value(
    value: &Value,
) -> Result<CudaRuntimeValidationDiagnosticV1, CudaRuntimeExtensionError> {
    let diagnostic: CudaRuntimeValidationDiagnosticV1 = serde_json::from_value(value.clone())
        .map_err(|error| {
            CudaRuntimeExtensionError::new(
                "cuda_runtime_validation_diagnostic_decode",
                format!("failed to decode CUDA runtime validation diagnostic: {error}"),
            )
        })?;
    validate_cuda_runtime_validation_diagnostic(&diagnostic)?;
    Ok(diagnostic)
}

pub fn load_cuda_selected_environment_input_from_path(
    path: &Path,
) -> Result<CudaSelectedEnvironmentInputV1, CudaRuntimeExtensionError> {
    let raw = fs::read_to_string(path).map_err(|error| {
        CudaRuntimeExtensionError::new(
            "selected_cuda_environment_input_load",
            format!(
                "failed to read CUDA selected-environment input {}: {error}",
                path.display()
            ),
        )
    })?;
    let input: CudaSelectedEnvironmentInputV1 = serde_json::from_str(&raw).map_err(|error| {
        CudaRuntimeExtensionError::new(
            "selected_cuda_environment_input_load",
            format!(
                "failed to decode CUDA selected-environment input {}: {error}",
                path.display()
            ),
        )
    })?;
    validate_cuda_selected_environment_input(&input)?;
    Ok(input)
}

pub fn apply_cuda_runtime_extension_to_survey_v1(
    survey: HostSurveyV1,
    replay_root: Option<&Path>,
) -> Result<HostSurveyV1, CudaRuntimeExtensionError> {
    apply_cuda_runtime_extension_to_survey_with_selection_v1(survey, replay_root, None)
}

pub fn apply_cuda_runtime_extension_to_survey_with_selection_v1(
    mut survey: HostSurveyV1,
    replay_root: Option<&Path>,
    selected_environment: Option<&CudaSelectedEnvironmentRequestV1>,
) -> Result<HostSurveyV1, CudaRuntimeExtensionError> {
    let payload = decode_host_survey_payload(&survey.survey).map_err(|error| {
        CudaRuntimeExtensionError::new(
            "cuda_extension_normalize",
            format!("failed to decode host-survey payload for CUDA extension: {error}"),
        )
    })?;

    let evidence = match payload.collection_mode.as_str() {
        "live" => collect_live_cuda_runtime_evidence(selected_environment)?,
        "replay" => load_replay_cuda_runtime_evidence(
            replay_root.ok_or_else(|| {
                CudaRuntimeExtensionError::new(
                    "cuda_extension_collect",
                    "CUDA runtime replay collection requires an extension replay root",
                )
            })?,
            &payload.snapshot_id,
            selected_environment,
        )?,
        unknown => {
            return Err(CudaRuntimeExtensionError::new(
                "cuda_extension_collect",
                format!("unsupported survey collection mode {unknown} for CUDA runtime extension"),
            ))
        }
    };

    let mut payload = payload;
    payload.extension_evidence.insert(
        CUDA_RUNTIME_NAMESPACE.to_string(),
        serde_json::to_value(&evidence).map_err(|error| {
            CudaRuntimeExtensionError::new(
                "cuda_extension_normalize",
                format!("failed to encode CUDA runtime extension evidence: {error}"),
            )
        })?,
    );
    survey.survey = encode_host_survey_payload(&payload).map_err(|error| {
        CudaRuntimeExtensionError::new(
            "cuda_extension_normalize",
            format!("failed to encode host-survey payload for CUDA extension: {error}"),
        )
    })?;

    Ok(survey)
}

pub fn apply_cuda_runtime_extension_to_state_v1(
    state: HostStateV1,
    replay_root: Option<&Path>,
) -> Result<HostStateV1, CudaRuntimeExtensionError> {
    apply_cuda_runtime_extension_to_state_with_selection_v1(state, replay_root, None)
}

pub fn apply_cuda_runtime_extension_to_state_with_selection_v1(
    mut state: HostStateV1,
    replay_root: Option<&Path>,
    selected_environment: Option<&CudaSelectedEnvironmentRequestV1>,
) -> Result<HostStateV1, CudaRuntimeExtensionError> {
    let extension_state = match state.state.collection_mode.as_str() {
        "live" => collect_live_cuda_runtime_state(selected_environment)?,
        "replay" => load_replay_cuda_runtime_state(
            replay_root.ok_or_else(|| {
                CudaRuntimeExtensionError::new(
                    "cuda_state_extension_boundary",
                    "CUDA runtime state replay requires an extension replay root",
                )
            })?,
            &state.state.snapshot_id,
            selected_environment,
        )?,
        unknown => {
            return Err(CudaRuntimeExtensionError::new(
                "cuda_state_extension_boundary",
                format!("unsupported host-state collection mode {unknown} for CUDA runtime state"),
            ))
        }
    };

    state.state.extension_state.insert(
        CUDA_RUNTIME_NAMESPACE.to_string(),
        serde_json::to_value(&extension_state).map_err(|error| {
            CudaRuntimeExtensionError::new(
                "cuda_state_extension_validate",
                format!("failed to encode CUDA runtime extension state: {error}"),
            )
        })?,
    );

    Ok(state)
}

pub fn derive_cuda_runtime_contract_value_from_survey_v1(
    survey: &HostSurveyV1,
) -> Result<Option<Value>, CudaRuntimeExtensionError> {
    let payload = decode_host_survey_payload(&survey.survey).map_err(|error| {
        CudaRuntimeExtensionError::new(
            "cuda_extension_contract_derive",
            format!(
                "failed to decode host-survey payload for CUDA runtime contract derivation: {error}"
            ),
        )
    })?;
    let Some(value) = payload.extension_evidence.get(CUDA_RUNTIME_NAMESPACE) else {
        return Ok(None);
    };
    let evidence = decode_cuda_runtime_evidence_from_value(value)?;
    let contract = derive_cuda_runtime_contract_from_evidence(&evidence);
    Ok(Some(serde_json::to_value(contract).map_err(|error| {
        CudaRuntimeExtensionError::new(
            "cuda_extension_contract_derive",
            format!("failed to encode CUDA runtime extension contract: {error}"),
        )
    })?))
}

pub fn evaluate_cuda_runtime_requirement_v1(
    contract: &CudaRuntimeContractV1,
    requirement: &CudaRuntimeRequirementV1,
) -> Result<CudaRuntimeEvaluationOutcomeV1, CudaRuntimeExtensionError> {
    validate_cuda_runtime_contract(contract)?;
    validate_cuda_runtime_requirement(requirement)?;

    if contract.runtime_id != requirement.required_runtime {
        return Err(CudaRuntimeExtensionError::new(
            "cuda_extension_validate",
            "CUDA runtime contract and requirement use different runtime ids",
        ));
    }

    if !contract.runtime_available {
        return Ok(CudaRuntimeEvaluationOutcomeV1::Unsatisfied {
            summary: format!(
                "{} is required by the service profile but the contract records it as unavailable",
                requirement.required_runtime
            ),
        });
    }

    let version = contract.version.as_ref().ok_or_else(|| {
        CudaRuntimeExtensionError::new(
            "cuda_extension_validate",
            "CUDA runtime contract must carry a parsed version when runtime_available is true",
        )
    })?;

    if let Some(minimum_version) = requirement.minimum_version.as_ref() {
        if compare_versions(version, minimum_version) == Ordering::Less {
            return Ok(CudaRuntimeEvaluationOutcomeV1::Unsatisfied {
                summary: format!(
                    "{} version {} is below the required minimum {}",
                    requirement.required_runtime,
                    format_version(version),
                    format_version(minimum_version)
                ),
            });
        }
    }

    if !requirement.accepted_version_ranges.is_empty()
        && !requirement
            .accepted_version_ranges
            .iter()
            .any(|range| range_contains_version(range, version))
    {
        return Ok(CudaRuntimeEvaluationOutcomeV1::Unsatisfied {
            summary: format!(
                "{} version {} is outside the accepted version ranges",
                requirement.required_runtime,
                format_version(version)
            ),
        });
    }

    Ok(CudaRuntimeEvaluationOutcomeV1::Satisfied)
}

pub fn format_cuda_runtime_evidence_for_inspect(
    evidence: &CudaRuntimeEvidenceV1,
    _include_executable_path: bool,
) -> String {
    match evidence.runtime_state {
        CudaRuntimeEvidenceStateV1::Observed => format!("{} observed", evidence.runtime_id),
        CudaRuntimeEvidenceStateV1::NotFound => format!("{} not found", evidence.runtime_id),
    }
}

pub fn format_cuda_runtime_contract_for_inspect(contract: &CudaRuntimeContractV1) -> String {
    if contract.runtime_available {
        format!("{} available", contract.runtime_id)
    } else {
        format!("{} unavailable", contract.runtime_id)
    }
}

pub fn format_cuda_runtime_requirement_for_inspect(
    requirement: &CudaRuntimeRequirementV1,
) -> String {
    let mut parts = Vec::new();
    if requirement.require_presence {
        parts.push(format!("{} required", requirement.required_runtime));
    } else {
        parts.push(format!("{} optional", requirement.required_runtime));
    }
    if let Some(minimum_version) = requirement.minimum_version.as_ref() {
        parts.push(format!("minimum {}", format_version(minimum_version)));
    }
    if !requirement.accepted_version_ranges.is_empty() {
        parts.push(format!(
            "accepted ranges {}",
            requirement
                .accepted_version_ranges
                .iter()
                .map(format_version_range)
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    if let Some(minimum_allocatable_memory_bytes) = requirement.minimum_allocatable_memory_bytes {
        parts.push(format!(
            "minimum allocatable memory {}",
            format_bytes(minimum_allocatable_memory_bytes)
        ));
    }
    if let Some(minimum_device_allocatable_memory_bytes) =
        requirement.minimum_device_allocatable_memory_bytes
    {
        parts.push(format!(
            "minimum per-device allocatable memory {}",
            format_bytes(minimum_device_allocatable_memory_bytes)
        ));
    }
    if let Some(minimum_qualifying_device_aggregate_allocatable_memory_bytes) =
        requirement.minimum_qualifying_device_aggregate_allocatable_memory_bytes
    {
        parts.push(format!(
            "minimum qualifying-device aggregate allocatable memory {}",
            format_bytes(minimum_qualifying_device_aggregate_allocatable_memory_bytes)
        ));
    }
    parts.join("; ")
}

pub fn format_cuda_runtime_state_for_inspect(state: &CudaRuntimeStateV1) -> String {
    let mut parts = vec![state.runtime_state.as_str().to_string()];
    if let Some(reason) = state.limitation_reason {
        parts.push(reason.as_str().to_string());
    }
    if !state.devices.is_empty() {
        parts.push(format!("{} devices", state.devices.len()));
    }
    if let Some(total_memory_bytes) = scalar_state_value(&state.total_memory_bytes) {
        parts.push(format!("total {}", format_bytes(total_memory_bytes)));
    }
    if let Some(used_memory_bytes) = scalar_state_value(&state.used_memory_bytes) {
        parts.push(format!("used {}", format_bytes(used_memory_bytes)));
    }
    if let Some(allocatable_memory_bytes) = scalar_state_value(&state.allocatable_memory_bytes) {
        parts.push(format!(
            "allocatable {}",
            format_bytes(allocatable_memory_bytes)
        ));
    }
    parts.join("; ")
}

pub fn format_cuda_runtime_validation_diagnostic_for_inspect(
    diagnostic: &CudaRuntimeValidationDiagnosticV1,
) -> String {
    match diagnostic.detail_code {
        CudaRuntimeValidationDetailCodeV1::StaticRequirementUnsatisfied => format!(
            "CUDA runtime static requirement unsatisfied; checkpoint {}; {}",
            diagnostic.checkpoint.as_str(),
            format_cuda_runtime_thresholds_for_inspect(diagnostic)
        ),
        CudaRuntimeValidationDetailCodeV1::RuntimeStateMissing => format!(
            "CUDA runtime state missing; checkpoint {}; {}",
            diagnostic.checkpoint.as_str(),
            format_cuda_runtime_thresholds_for_inspect(diagnostic)
        ),
        CudaRuntimeValidationDetailCodeV1::RuntimeStateStale => format!(
            "CUDA runtime state stale; checkpoint {}; {}",
            diagnostic.checkpoint.as_str(),
            format_cuda_runtime_thresholds_for_inspect(diagnostic)
        ),
        CudaRuntimeValidationDetailCodeV1::AllocatableMemoryInsufficient => format!(
            "CUDA allocatable memory {} is below required {}; checkpoint {}; total {}",
            diagnostic
                .observed_allocatable_memory_bytes
                .map(format_bytes)
                .unwrap_or_else(|| "<unknown>".to_string()),
            diagnostic
                .required_allocatable_memory_bytes
                .map(format_bytes)
                .unwrap_or_else(|| "<unknown>".to_string()),
            diagnostic.checkpoint.as_str(),
            diagnostic
                .observed_total_memory_bytes
                .map(format_bytes)
                .unwrap_or_else(|| "<unknown>".to_string())
        ),
        CudaRuntimeValidationDetailCodeV1::QualifyingDeviceCountInsufficient => format!(
            "CUDA qualifying device count {} is below required {}; checkpoint {}; {}",
            diagnostic
                .observed_qualifying_device_count
                .map(|value| value.to_string())
                .unwrap_or_else(|| "<unknown>".to_string()),
            diagnostic
                .required_qualifying_device_count
                .map(|value| value.to_string())
                .unwrap_or_else(|| "<unknown>".to_string()),
            diagnostic.checkpoint.as_str(),
            format_cuda_runtime_per_device_floor_for_inspect(diagnostic)
        ),
        CudaRuntimeValidationDetailCodeV1::QualifyingDeviceAggregateAllocatableMemoryInsufficient => format!(
            "CUDA qualifying-device aggregate allocatable memory {} is below required {}; checkpoint {}; {}",
            diagnostic
                .observed_qualifying_device_aggregate_allocatable_memory_bytes
                .map(format_bytes)
                .unwrap_or_else(|| "<unknown>".to_string()),
            diagnostic
                .required_qualifying_device_aggregate_allocatable_memory_bytes
                .map(format_bytes)
                .unwrap_or_else(|| "<unknown>".to_string()),
            diagnostic.checkpoint.as_str(),
            format_cuda_runtime_per_device_floor_for_inspect(diagnostic)
        ),
        CudaRuntimeValidationDetailCodeV1::RuntimeThresholdSatisfied => format!(
            "CUDA allocatable memory {} satisfies required {}; checkpoint {}; total {}",
            diagnostic
                .observed_allocatable_memory_bytes
                .map(format_bytes)
                .unwrap_or_else(|| "<unknown>".to_string()),
            diagnostic
                .required_allocatable_memory_bytes
                .map(format_bytes)
                .unwrap_or_else(|| "<unknown>".to_string()),
            diagnostic.checkpoint.as_str(),
            diagnostic
                .observed_total_memory_bytes
                .map(format_bytes)
                .unwrap_or_else(|| "<unknown>".to_string())
        ),
        CudaRuntimeValidationDetailCodeV1::QualifyingDeviceThresholdSatisfied => format!(
            "CUDA qualifying device count {} satisfies required {}; checkpoint {}; {}",
            diagnostic
                .observed_qualifying_device_count
                .map(|value| value.to_string())
                .unwrap_or_else(|| "<unknown>".to_string()),
            diagnostic
                .required_qualifying_device_count
                .map(|value| value.to_string())
                .unwrap_or_else(|| "<unknown>".to_string()),
            diagnostic.checkpoint.as_str(),
            format_cuda_runtime_per_device_floor_for_inspect(diagnostic)
        ),
        CudaRuntimeValidationDetailCodeV1::QualifyingDeviceAggregateAllocatableMemoryThresholdSatisfied => format!(
            "CUDA qualifying-device aggregate allocatable memory {} satisfies required {}; checkpoint {}; {}",
            diagnostic
                .observed_qualifying_device_aggregate_allocatable_memory_bytes
                .map(format_bytes)
                .unwrap_or_else(|| "<unknown>".to_string()),
            diagnostic
                .required_qualifying_device_aggregate_allocatable_memory_bytes
                .map(format_bytes)
                .unwrap_or_else(|| "<unknown>".to_string()),
            diagnostic.checkpoint.as_str(),
            format_cuda_runtime_per_device_floor_for_inspect(diagnostic)
        ),
    }
}

fn format_cuda_runtime_thresholds_for_inspect(
    diagnostic: &CudaRuntimeValidationDiagnosticV1,
) -> String {
    let mut parts = Vec::new();
    if let Some(required_allocatable_memory_bytes) = diagnostic.required_allocatable_memory_bytes {
        parts.push(format!(
            "required allocatable memory {}",
            format_bytes(required_allocatable_memory_bytes)
        ));
    }
    if let Some(required_qualifying_device_count) = diagnostic.required_qualifying_device_count {
        parts.push(format!(
            "required qualifying device count {}",
            required_qualifying_device_count
        ));
    }
    if let Some(required_device_allocatable_memory_bytes) =
        diagnostic.required_device_allocatable_memory_bytes
    {
        parts.push(format!(
            "required per-device allocatable memory {}",
            format_bytes(required_device_allocatable_memory_bytes)
        ));
    }
    if let Some(required_qualifying_device_aggregate_allocatable_memory_bytes) =
        diagnostic.required_qualifying_device_aggregate_allocatable_memory_bytes
    {
        parts.push(format!(
            "required qualifying-device aggregate allocatable memory {}",
            format_bytes(required_qualifying_device_aggregate_allocatable_memory_bytes)
        ));
    }
    if parts.is_empty() {
        "<unknown threshold>".to_string()
    } else {
        parts.join("; ")
    }
}

fn format_cuda_runtime_per_device_floor_for_inspect(
    diagnostic: &CudaRuntimeValidationDiagnosticV1,
) -> String {
    diagnostic
        .required_device_allocatable_memory_bytes
        .map(|value| format!("per-device floor {}", format_bytes(value)))
        .unwrap_or_else(|| "no per-device floor".to_string())
}

pub fn redact_cuda_runtime_evidence_export_v1(
    evidence: &mut CudaRuntimeEvidenceV1,
    profile: BuiltInRedactionProfileV1,
) {
    if profile.applies_fleet_redactions() || profile.applies_auditor_redactions() {
        evidence.executable_path = None;
    }
}

fn collect_live_cuda_runtime_evidence(
    selected_environment: Option<&CudaSelectedEnvironmentRequestV1>,
) -> Result<CudaRuntimeEvidenceV1, CudaRuntimeExtensionError> {
    let collector = CollectorMetadataV1 {
        collector_id: CUDA_RUNTIME_COLLECTOR_ID.to_string(),
        collector_version: CUDA_RUNTIME_COLLECTOR_VERSION.to_string(),
        source_family: CUDA_RUNTIME_LIVE_SOURCE_FAMILY.to_string(),
    };
    let default_view = collect_live_cuda_default_view_fields()?;
    let installed_toolkits = collect_live_cuda_installed_toolkits(
        default_view.toolkit_root.as_deref(),
        default_view.toolkit_version.as_ref(),
    )?;
    let runtime_state = if default_view.toolkit_version.is_some() {
        CudaRuntimeEvidenceStateV1::Observed
    } else {
        CudaRuntimeEvidenceStateV1::NotFound
    };

    let mut evidence = CudaRuntimeEvidenceV1 {
        schema_id: CUDA_RUNTIME_EVIDENCE_SCHEMA_ID.to_string(),
        schema_version: 1,
        collector,
        claim_metadata: claim_metadata_for_collector(CUDA_RUNTIME_COLLECTOR_ID, CUDA_EVIDENCE_PATH),
        runtime_id: "cuda".to_string(),
        runtime_state,
        executable_path: default_view.executable_path,
        version: default_view.toolkit_version,
        driver_version: default_view.driver_version,
        driver_supported_cuda_version: default_view.driver_supported_cuda_version,
        default_runtime_version: default_view.default_runtime_version,
        default_view_probe_diagnostics: Some(default_view.diagnostics),
        selected_environment: None,
        selected_environment_toolkit_version: None,
        selected_environment_runtime_version: None,
        selected_environment_probe_diagnostics: None,
        installed_toolkits,
    };
    apply_selected_environment_request_to_evidence(&mut evidence, selected_environment, true)?;
    Ok(evidence)
}

fn collect_live_cuda_runtime_state(
    selected_environment: Option<&CudaSelectedEnvironmentRequestV1>,
) -> Result<CudaRuntimeStateV1, CudaRuntimeExtensionError> {
    let default_view = collect_live_cuda_default_view_fields()?;
    let collector = CollectorMetadataV1 {
        collector_id: CUDA_RUNTIME_STATE_COLLECTOR_ID.to_string(),
        collector_version: CUDA_RUNTIME_COLLECTOR_VERSION.to_string(),
        source_family: CUDA_RUNTIME_LIVE_SOURCE_FAMILY.to_string(),
    };
    let (probe_path, state_probe_output, missing_reason) = collect_live_cuda_state_probe_output();

    let mut state = match state_probe_output {
        Some(output) => {
            let devices = parse_cuda_runtime_state_probe_output(&output)?;
            if devices.is_empty() {
                missing_cuda_runtime_state(collector, None, probe_path)
            } else {
                let total_memory_bytes = devices
                    .iter()
                    .map(|device| {
                        scalar_state_value(&device.total_memory_bytes).unwrap_or_default()
                    })
                    .sum();
                let allocatable_memory_bytes = devices
                    .iter()
                    .map(|device| {
                        scalar_state_value(&device.allocatable_memory_bytes).unwrap_or_default()
                    })
                    .sum();
                let used_memory_bytes = devices
                    .iter()
                    .map(|device| scalar_state_value(&device.used_memory_bytes).unwrap_or_default())
                    .sum();

                CudaRuntimeStateV1 {
                    schema_id: CUDA_RUNTIME_STATE_SCHEMA_ID.to_string(),
                    schema_version: 1,
                    collector,
                    claim_metadata: claim_metadata_for_collector(
                        CUDA_RUNTIME_STATE_COLLECTOR_ID,
                        CUDA_STATE_PATH,
                    ),
                    runtime_id: "cuda".to_string(),
                    runtime_state: ObservationStateV1::Observed,
                    limitation_reason: None,
                    devices,
                    total_memory_bytes: observed_state_field(total_memory_bytes),
                    allocatable_memory_bytes: observed_state_field(allocatable_memory_bytes),
                    used_memory_bytes: observed_state_field(used_memory_bytes),
                    default_toolkit_version: missing_cuda_runtime_version_state_field_v1(),
                    driver_version: missing_cuda_runtime_version_state_field_v1(),
                    driver_supported_cuda_version: missing_cuda_runtime_version_state_field_v1(),
                    default_runtime_version: missing_cuda_runtime_version_state_field_v1(),
                    default_view_probe_diagnostics: None,
                    selected_environment: None,
                    selected_environment_toolkit_version:
                        missing_cuda_runtime_version_state_field_v1(),
                    selected_environment_runtime_version:
                        missing_cuda_runtime_version_state_field_v1(),
                    selected_environment_probe_diagnostics: None,
                    probe_path,
                }
            }
        }
        None => missing_cuda_runtime_state(collector, missing_reason, probe_path),
    };

    state.default_toolkit_version = version_state_field_from_optional(default_view.toolkit_version);
    state.driver_version = version_state_field_from_optional(default_view.driver_version);
    state.driver_supported_cuda_version =
        version_state_field_from_optional(default_view.driver_supported_cuda_version);
    state.default_runtime_version =
        version_state_field_from_optional(default_view.default_runtime_version);
    state.default_view_probe_diagnostics = Some(default_view.diagnostics);
    apply_selected_environment_request_to_state(&mut state, selected_environment, true)?;

    Ok(state)
}

fn load_replay_cuda_runtime_evidence(
    root: &Path,
    fixture_id: &str,
    selected_environment: Option<&CudaSelectedEnvironmentRequestV1>,
) -> Result<CudaRuntimeEvidenceV1, CudaRuntimeExtensionError> {
    let manifest_path = root.join("manifest.v1.json");
    let manifest_text = fs::read_to_string(&manifest_path).map_err(|error| {
        CudaRuntimeExtensionError::new(
            "cuda_extension_collect",
            format!(
                "failed to read CUDA runtime replay manifest {}: {error}",
                manifest_path.display()
            ),
        )
    })?;
    let manifest: CudaRuntimeReplayCorpusV1 =
        serde_json::from_str(&manifest_text).map_err(|error| {
            CudaRuntimeExtensionError::new(
                "cuda_extension_collect",
                format!(
                    "failed to decode CUDA runtime replay manifest {}: {error}",
                    manifest_path.display()
                ),
            )
        })?;
    validate_cuda_runtime_replay_manifest(&manifest)?;

    let entry = manifest
        .fixtures
        .iter()
        .find(|entry| entry.fixture_id == fixture_id)
        .ok_or_else(|| {
            CudaRuntimeExtensionError::new(
                "cuda_extension_collect",
                format!("CUDA runtime replay corpus does not contain fixture id {fixture_id}"),
            )
        })?;
    let fixture_path = resolve_replay_fixture_path(root, &entry.path)?;
    let fixture_text = fs::read_to_string(&fixture_path).map_err(|error| {
        CudaRuntimeExtensionError::new(
            "cuda_extension_collect",
            format!(
                "failed to read CUDA runtime replay fixture {}: {error}",
                fixture_path.display()
            ),
        )
    })?;
    let snapshot: CudaRuntimeReplayFixtureSnapshotV1 = serde_json::from_str(&fixture_text)
        .map_err(|error| {
            CudaRuntimeExtensionError::new(
                "cuda_extension_collect",
                format!(
                    "failed to decode CUDA runtime replay fixture {}: {error}",
                    fixture_path.display()
                ),
            )
        })?;

    if snapshot.schema_id != CUDA_RUNTIME_REPLAY_SNAPSHOT_SCHEMA_ID
        || snapshot.schema_version != 1
        || snapshot.fixture_id != fixture_id
        || snapshot.namespace != CUDA_RUNTIME_NAMESPACE
    {
        return Err(CudaRuntimeExtensionError::new(
            "cuda_extension_collect",
            "CUDA runtime replay fixture must declare the supported schema, namespace, and fixture id",
        ));
    }
    let mut evidence = snapshot.evidence;
    validate_cuda_runtime_evidence(&evidence)?;
    apply_selected_environment_request_to_evidence(&mut evidence, selected_environment, false)?;

    Ok(evidence)
}

fn load_replay_cuda_runtime_state(
    root: &Path,
    fixture_id: &str,
    selected_environment: Option<&CudaSelectedEnvironmentRequestV1>,
) -> Result<CudaRuntimeStateV1, CudaRuntimeExtensionError> {
    let manifest_path = root.join("manifest.v1.json");
    let manifest_text = fs::read_to_string(&manifest_path).map_err(|error| {
        CudaRuntimeExtensionError::new(
            "cuda_state_extension_replay",
            format!(
                "failed to read CUDA runtime state replay manifest {}: {error}",
                manifest_path.display()
            ),
        )
    })?;
    let manifest: CudaRuntimeStateReplayCorpusV1 =
        serde_json::from_str(&manifest_text).map_err(|error| {
            CudaRuntimeExtensionError::new(
                "cuda_state_extension_replay",
                format!(
                    "failed to decode CUDA runtime state replay manifest {}: {error}",
                    manifest_path.display()
                ),
            )
        })?;
    validate_cuda_runtime_state_replay_manifest(&manifest)?;

    let entry = manifest
        .fixtures
        .iter()
        .find(|entry| entry.fixture_id == fixture_id)
        .ok_or_else(|| {
            CudaRuntimeExtensionError::new(
                "cuda_state_extension_replay",
                format!(
                    "CUDA runtime state replay corpus does not contain fixture id {fixture_id}"
                ),
            )
        })?;
    let fixture_path = resolve_replay_fixture_path(root, &entry.path)?;
    let fixture_text = fs::read_to_string(&fixture_path).map_err(|error| {
        CudaRuntimeExtensionError::new(
            "cuda_state_extension_replay",
            format!(
                "failed to read CUDA runtime state replay fixture {}: {error}",
                fixture_path.display()
            ),
        )
    })?;
    let snapshot: CudaRuntimeStateReplayFixtureSnapshotV1 = serde_json::from_str(&fixture_text)
        .map_err(|error| {
            CudaRuntimeExtensionError::new(
                "cuda_state_extension_replay",
                format!(
                    "failed to decode CUDA runtime state replay fixture {}: {error}",
                    fixture_path.display()
                ),
            )
        })?;

    if snapshot.schema_id != CUDA_RUNTIME_STATE_REPLAY_SNAPSHOT_SCHEMA_ID
        || snapshot.schema_version != 1
        || snapshot.fixture_id != fixture_id
        || snapshot.namespace != CUDA_RUNTIME_NAMESPACE
    {
        return Err(CudaRuntimeExtensionError::new(
            "cuda_state_extension_replay",
            "CUDA runtime state replay fixture must declare the supported schema, namespace, and fixture id",
        ));
    }
    let mut state = snapshot.state;
    validate_cuda_runtime_state(&state)?;
    apply_selected_environment_request_to_state(&mut state, selected_environment, false)?;

    Ok(state)
}

fn derive_cuda_runtime_contract_from_evidence(
    evidence: &CudaRuntimeEvidenceV1,
) -> CudaRuntimeContractV1 {
    CudaRuntimeContractV1 {
        schema_id: CUDA_RUNTIME_CONTRACT_SCHEMA_ID.to_string(),
        schema_version: 1,
        claim_metadata: ClaimMetadataV1 {
            assurance_source: AssuranceSourceV1::SelfObserved,
            derivation_stage: DerivationStageV1::Derived,
            source_collectors: vec![evidence.collector.collector_id.clone()],
            evidence_paths: vec![
                CUDA_CONTRACT_PATH.to_string(),
                CUDA_EVIDENCE_PATH.to_string(),
            ],
            policy_rule_id: None,
            trust_evidence_refs: Vec::new(),
        },
        runtime_id: evidence.runtime_id.clone(),
        runtime_available: matches!(evidence.runtime_state, CudaRuntimeEvidenceStateV1::Observed),
        version: evidence.version.clone(),
        driver_version: evidence.driver_version.clone(),
        driver_supported_cuda_version: evidence.driver_supported_cuda_version.clone(),
        default_runtime_version: evidence.default_runtime_version.clone(),
        default_view_probe_diagnostics: evidence.default_view_probe_diagnostics.clone(),
        selected_environment: evidence.selected_environment.clone(),
        selected_environment_toolkit_version: evidence.selected_environment_toolkit_version.clone(),
        selected_environment_runtime_version: evidence.selected_environment_runtime_version.clone(),
        selected_environment_probe_diagnostics: evidence
            .selected_environment_probe_diagnostics
            .clone(),
        installed_toolkits: evidence.installed_toolkits.clone(),
    }
}

fn validate_cuda_runtime_evidence(
    evidence: &CudaRuntimeEvidenceV1,
) -> Result<(), CudaRuntimeExtensionError> {
    if evidence.schema_id != CUDA_RUNTIME_EVIDENCE_SCHEMA_ID
        || evidence.schema_version != 1
        || evidence.runtime_id != "cuda"
    {
        return Err(CudaRuntimeExtensionError::new(
            "cuda_extension_normalize",
            "CUDA runtime extension evidence must declare the supported schema and runtime id",
        ));
    }
    validate_collector(&evidence.collector)?;
    validate_claim_metadata(&evidence.claim_metadata)?;

    match evidence.runtime_state {
        CudaRuntimeEvidenceStateV1::Observed => {
            if evidence
                .executable_path
                .as_deref()
                .is_some_and(|value| value.trim().is_empty())
            {
                return Err(CudaRuntimeExtensionError::new(
                    "cuda_extension_normalize",
                    "observed CUDA runtime evidence executable_path must be non-blank when present",
                ));
            }
            validate_version(evidence.version.as_ref().ok_or_else(|| {
                CudaRuntimeExtensionError::new(
                    "cuda_extension_normalize",
                    "observed CUDA runtime evidence must include a parsed version",
                )
            })?)?;
        }
        CudaRuntimeEvidenceStateV1::NotFound => {
            if evidence.executable_path.is_some() || evidence.version.is_some() {
                return Err(CudaRuntimeExtensionError::new(
                    "cuda_extension_normalize",
                    "not_found CUDA runtime evidence must not include executable_path or version",
                ));
            }
        }
    }
    validate_optional_version(
        evidence.driver_version.as_ref(),
        "driver_version",
        "cuda_extension_normalize",
    )?;
    validate_optional_version(
        evidence.driver_supported_cuda_version.as_ref(),
        "driver_supported_cuda_version",
        "cuda_extension_normalize",
    )?;
    validate_optional_version(
        evidence.default_runtime_version.as_ref(),
        "default_runtime_version",
        "cuda_extension_normalize",
    )?;
    validate_cuda_default_view_probe_diagnostics(
        evidence.default_view_probe_diagnostics.as_ref(),
        evidence.version.is_some(),
        evidence.driver_version.is_some(),
        evidence.driver_supported_cuda_version.is_some(),
        evidence.default_runtime_version.is_some(),
        "cuda_extension_normalize",
    )?;
    validate_installed_toolkits(&evidence.installed_toolkits, "cuda_extension_normalize")?;
    validate_selected_environment_extension_fields(
        evidence.selected_environment.as_ref(),
        evidence
            .selected_environment_toolkit_version
            .as_ref()
            .is_some(),
        evidence
            .selected_environment_runtime_version
            .as_ref()
            .is_some(),
        evidence.selected_environment_probe_diagnostics.as_ref(),
        "cuda_extension_normalize",
    )?;

    Ok(())
}

fn validate_cuda_runtime_contract(
    contract: &CudaRuntimeContractV1,
) -> Result<(), CudaRuntimeExtensionError> {
    if contract.schema_id != CUDA_RUNTIME_CONTRACT_SCHEMA_ID
        || contract.schema_version != 1
        || contract.runtime_id != "cuda"
    {
        return Err(CudaRuntimeExtensionError::new(
            "cuda_extension_contract_derive",
            "CUDA runtime extension contract must declare the supported schema and runtime id",
        ));
    }
    validate_claim_metadata(&contract.claim_metadata)?;
    if contract.runtime_available {
        validate_version(contract.version.as_ref().ok_or_else(|| {
            CudaRuntimeExtensionError::new(
                "cuda_extension_contract_derive",
                "available CUDA runtime contract must include a parsed version",
            )
        })?)?;
    } else if contract.version.is_some() {
        return Err(CudaRuntimeExtensionError::new(
            "cuda_extension_contract_derive",
            "unavailable CUDA runtime contract must not include a version",
        ));
    }
    validate_optional_version(
        contract.driver_version.as_ref(),
        "driver_version",
        "cuda_extension_contract_derive",
    )?;
    validate_optional_version(
        contract.driver_supported_cuda_version.as_ref(),
        "driver_supported_cuda_version",
        "cuda_extension_contract_derive",
    )?;
    validate_optional_version(
        contract.default_runtime_version.as_ref(),
        "default_runtime_version",
        "cuda_extension_contract_derive",
    )?;
    validate_cuda_default_view_probe_diagnostics(
        contract.default_view_probe_diagnostics.as_ref(),
        contract.version.is_some(),
        contract.driver_version.is_some(),
        contract.driver_supported_cuda_version.is_some(),
        contract.default_runtime_version.is_some(),
        "cuda_extension_contract_derive",
    )?;
    validate_installed_toolkits(
        &contract.installed_toolkits,
        "cuda_extension_contract_derive",
    )?;
    validate_selected_environment_extension_fields(
        contract.selected_environment.as_ref(),
        contract
            .selected_environment_toolkit_version
            .as_ref()
            .is_some(),
        contract
            .selected_environment_runtime_version
            .as_ref()
            .is_some(),
        contract.selected_environment_probe_diagnostics.as_ref(),
        "cuda_extension_contract_derive",
    )?;
    Ok(())
}

fn validate_cuda_runtime_requirement(
    requirement: &CudaRuntimeRequirementV1,
) -> Result<(), CudaRuntimeExtensionError> {
    if requirement.schema_id != CUDA_RUNTIME_REQUIREMENT_SCHEMA_ID
        || requirement.schema_version != 1
        || requirement.required_runtime != "cuda"
    {
        return Err(CudaRuntimeExtensionError::new(
            "cuda_extension_validate",
            "CUDA runtime extension requirement must declare the supported schema and runtime id",
        ));
    }
    if !requirement.require_presence
        && requirement.minimum_version.is_none()
        && requirement.accepted_version_ranges.is_empty()
        && requirement.minimum_allocatable_memory_bytes.is_none()
        && requirement
            .minimum_device_allocatable_memory_bytes
            .is_none()
        && requirement
            .minimum_qualifying_device_aggregate_allocatable_memory_bytes
            .is_none()
    {
        return Err(CudaRuntimeExtensionError::new(
            "cuda_extension_validate",
            "CUDA runtime extension requirement must declare at least one effective constraint",
        ));
    }
    if let Some(minimum_version) = requirement.minimum_version.as_ref() {
        validate_version(minimum_version)?;
    }
    for range in &requirement.accepted_version_ranges {
        if range.minimum_inclusive.is_none() && range.maximum_exclusive.is_none() {
            return Err(CudaRuntimeExtensionError::new(
                "cuda_extension_validate",
                "CUDA runtime accepted version ranges must set at least one bound",
            ));
        }
        if let Some(minimum) = range.minimum_inclusive.as_ref() {
            validate_version(minimum)?;
        }
        if let Some(maximum) = range.maximum_exclusive.as_ref() {
            validate_version(maximum)?;
        }
        if let (Some(minimum), Some(maximum)) = (
            range.minimum_inclusive.as_ref(),
            range.maximum_exclusive.as_ref(),
        ) {
            if compare_versions(minimum, maximum) != Ordering::Less {
                return Err(CudaRuntimeExtensionError::new(
                    "cuda_extension_validate",
                    "CUDA runtime accepted version ranges must have minimum_inclusive < maximum_exclusive",
                ));
            }
        }
    }
    if let Some(minimum_allocatable_memory_bytes) = requirement.minimum_allocatable_memory_bytes {
        if minimum_allocatable_memory_bytes == 0 {
            return Err(CudaRuntimeExtensionError::new(
                "cuda_extension_validate",
                "CUDA runtime allocatable memory thresholds must be greater than zero",
            ));
        }
        if !requirement.require_presence {
            return Err(CudaRuntimeExtensionError::new(
                "cuda_extension_validate",
                "CUDA runtime allocatable memory thresholds require require_presence=true",
            ));
        }
    }
    if let Some(minimum_device_allocatable_memory_bytes) =
        requirement.minimum_device_allocatable_memory_bytes
    {
        if minimum_device_allocatable_memory_bytes == 0 {
            return Err(CudaRuntimeExtensionError::new(
                "cuda_extension_validate",
                "CUDA runtime per-device allocatable memory thresholds must be greater than zero",
            ));
        }
        if !requirement.require_presence {
            return Err(CudaRuntimeExtensionError::new(
                "cuda_extension_validate",
                "CUDA runtime per-device allocatable memory thresholds require require_presence=true",
            ));
        }
    }
    if let Some(minimum_qualifying_device_aggregate_allocatable_memory_bytes) =
        requirement.minimum_qualifying_device_aggregate_allocatable_memory_bytes
    {
        if minimum_qualifying_device_aggregate_allocatable_memory_bytes == 0 {
            return Err(CudaRuntimeExtensionError::new(
                "cuda_extension_validate",
                "CUDA runtime qualifying-device aggregate allocatable-memory thresholds must be greater than zero",
            ));
        }
        if !requirement.require_presence {
            return Err(CudaRuntimeExtensionError::new(
                "cuda_extension_validate",
                "CUDA runtime qualifying-device aggregate allocatable-memory thresholds require require_presence=true",
            ));
        }
        if requirement
            .minimum_device_allocatable_memory_bytes
            .is_none()
        {
            return Err(CudaRuntimeExtensionError::new(
                "cuda_extension_validate",
                "CUDA runtime qualifying-device aggregate allocatable-memory thresholds require minimum_device_allocatable_memory_bytes",
            ));
        }
    }
    Ok(())
}

fn validate_cuda_runtime_state(
    state: &CudaRuntimeStateV1,
) -> Result<(), CudaRuntimeExtensionError> {
    if state.schema_id != CUDA_RUNTIME_STATE_SCHEMA_ID
        || state.schema_version != 1
        || state.runtime_id != "cuda"
    {
        return Err(CudaRuntimeExtensionError::new(
            "cuda_state_extension_validate",
            "CUDA runtime extension state must declare the supported schema and runtime id",
        ));
    }
    validate_cuda_runtime_state_collector(&state.collector)?;
    validate_claim_metadata(&state.claim_metadata)?;
    if state
        .probe_path
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(CudaRuntimeExtensionError::new(
            "cuda_state_extension_validate",
            "CUDA runtime state probe_path must be non-blank when present",
        ));
    }
    validate_state_field_value(&state.total_memory_bytes, "total_memory_bytes", |value| {
        *value > 0
    })?;
    validate_state_field_value(
        &state.allocatable_memory_bytes,
        "allocatable_memory_bytes",
        |value| *value > 0,
    )?;
    validate_state_field_value(&state.used_memory_bytes, "used_memory_bytes", |value| {
        *value > 0
    })?;
    validate_cuda_runtime_version_state_field(
        &state.default_toolkit_version,
        "default_toolkit_version",
    )?;
    validate_cuda_runtime_version_state_field(&state.driver_version, "driver_version")?;
    validate_cuda_runtime_version_state_field(
        &state.driver_supported_cuda_version,
        "driver_supported_cuda_version",
    )?;
    validate_cuda_runtime_version_state_field(
        &state.default_runtime_version,
        "default_runtime_version",
    )?;
    validate_cuda_default_view_probe_diagnostics(
        state.default_view_probe_diagnostics.as_ref(),
        cuda_runtime_version_state_field_is_observed(&state.default_toolkit_version),
        cuda_runtime_version_state_field_is_observed(&state.driver_version),
        cuda_runtime_version_state_field_is_observed(&state.driver_supported_cuda_version),
        cuda_runtime_version_state_field_is_observed(&state.default_runtime_version),
        "cuda_state_extension_validate",
    )?;
    validate_selected_environment_extension_fields(
        state.selected_environment.as_ref(),
        cuda_runtime_version_state_field_is_observed(&state.selected_environment_toolkit_version),
        cuda_runtime_version_state_field_is_observed(&state.selected_environment_runtime_version),
        state.selected_environment_probe_diagnostics.as_ref(),
        "cuda_state_extension_validate",
    )?;

    let mut previous_ordinal = None;
    for device in &state.devices {
        if device.device_uuid.trim().is_empty() {
            return Err(CudaRuntimeExtensionError::new(
                "cuda_state_extension_validate",
                "CUDA runtime device state must carry a non-blank device_uuid",
            ));
        }
        if previous_ordinal
            .is_some_and(|previous_ordinal| previous_ordinal >= device.device_ordinal)
        {
            return Err(CudaRuntimeExtensionError::new(
                "cuda_state_extension_validate",
                "CUDA runtime device state ordinals must be unique and strictly increasing",
            ));
        }
        previous_ordinal = Some(device.device_ordinal);
        validate_state_field_value(
            &device.total_memory_bytes,
            "device.total_memory_bytes",
            |value| *value > 0,
        )?;
        validate_state_field_value(
            &device.allocatable_memory_bytes,
            "device.allocatable_memory_bytes",
            |value| *value > 0,
        )?;
        validate_state_field_value(
            &device.used_memory_bytes,
            "device.used_memory_bytes",
            |value| *value > 0,
        )?;
        validate_cuda_memory_triplet(
            scalar_state_value(&device.total_memory_bytes),
            scalar_state_value(&device.allocatable_memory_bytes),
            scalar_state_value(&device.used_memory_bytes),
            "CUDA runtime device",
            "cuda_used_memory_validate",
        )?;
    }

    match state.runtime_state {
        ObservationStateV1::Observed => {
            if state.limitation_reason.is_some() {
                return Err(CudaRuntimeExtensionError::new(
                    "cuda_state_extension_validate",
                    "observed CUDA runtime state must not carry a limitation reason",
                ));
            }
            if state.devices.is_empty() {
                return Err(CudaRuntimeExtensionError::new(
                    "cuda_state_extension_validate",
                    "observed CUDA runtime state must include at least one device",
                ));
            }
            if !matches!(state.total_memory_bytes.state, ObservationStateV1::Observed)
                || !matches!(
                    state.allocatable_memory_bytes.state,
                    ObservationStateV1::Observed
                )
            {
                return Err(CudaRuntimeExtensionError::new(
                    "cuda_state_extension_validate",
                    "observed CUDA runtime state aggregate memory fields must be observed",
                ));
            }
        }
        ObservationStateV1::PartiallyObserved => {
            if state.devices.is_empty() {
                return Err(CudaRuntimeExtensionError::new(
                    "cuda_state_extension_validate",
                    "partially observed CUDA runtime state must include at least one device",
                ));
            }
        }
        ObservationStateV1::Missing
        | ObservationStateV1::Unknown
        | ObservationStateV1::HiddenByPrivilegeOrVisibility
        | ObservationStateV1::NotApplicable => {
            if !state.devices.is_empty() {
                return Err(CudaRuntimeExtensionError::new(
                    "cuda_state_extension_validate",
                    "non-observed CUDA runtime state must not include device entries",
                ));
            }
            if scalar_state_value(&state.total_memory_bytes).is_some()
                || scalar_state_value(&state.allocatable_memory_bytes).is_some()
                || scalar_state_value(&state.used_memory_bytes).is_some()
            {
                return Err(CudaRuntimeExtensionError::new(
                    "cuda_state_extension_validate",
                    "non-observed CUDA runtime state must not carry aggregate memory values",
                ));
            }
            if matches!(
                state.runtime_state,
                ObservationStateV1::HiddenByPrivilegeOrVisibility
            ) && state.limitation_reason
                != Some(ObservationLimitationReasonV1::PrivilegeOrVisibilityLimit)
            {
                return Err(CudaRuntimeExtensionError::new(
                    "cuda_state_extension_validate",
                    "hidden CUDA runtime state must use privilege_or_visibility_limit",
                ));
            }
        }
    }

    if matches!(
        state.runtime_state,
        ObservationStateV1::Observed | ObservationStateV1::PartiallyObserved
    ) {
        let total_sum = state
            .devices
            .iter()
            .map(|device| scalar_state_value(&device.total_memory_bytes))
            .collect::<Option<Vec<_>>>()
            .map(|values| values.into_iter().sum::<u64>());
        let allocatable_sum = state
            .devices
            .iter()
            .map(|device| scalar_state_value(&device.allocatable_memory_bytes))
            .collect::<Option<Vec<_>>>()
            .map(|values| values.into_iter().sum::<u64>());
        let used_sum = state
            .devices
            .iter()
            .map(|device| scalar_state_value(&device.used_memory_bytes))
            .collect::<Option<Vec<_>>>()
            .map(|values| values.into_iter().sum::<u64>());
        if let (Some(expected_total), Some(observed_total)) =
            (total_sum, scalar_state_value(&state.total_memory_bytes))
        {
            if expected_total != observed_total {
                return Err(CudaRuntimeExtensionError::new(
                    "cuda_state_extension_validate",
                    "CUDA runtime aggregate total memory must match per-device totals",
                ));
            }
        }
        if let (Some(expected_allocatable), Some(observed_allocatable)) = (
            allocatable_sum,
            scalar_state_value(&state.allocatable_memory_bytes),
        ) {
            if expected_allocatable != observed_allocatable {
                return Err(CudaRuntimeExtensionError::new(
                    "cuda_state_extension_validate",
                    "CUDA runtime aggregate allocatable memory must match per-device values",
                ));
            }
        }
        if let (Some(expected_used), Some(observed_used)) =
            (used_sum, scalar_state_value(&state.used_memory_bytes))
        {
            if expected_used != observed_used {
                return Err(CudaRuntimeExtensionError::new(
                    "cuda_used_memory_validate",
                    "CUDA runtime aggregate used memory must match per-device values",
                ));
            }
        }
    }

    validate_cuda_memory_triplet(
        scalar_state_value(&state.total_memory_bytes),
        scalar_state_value(&state.allocatable_memory_bytes),
        scalar_state_value(&state.used_memory_bytes),
        "CUDA runtime aggregate",
        "cuda_used_memory_validate",
    )?;

    Ok(())
}

fn validate_cuda_runtime_validation_diagnostic(
    diagnostic: &CudaRuntimeValidationDiagnosticV1,
) -> Result<(), CudaRuntimeExtensionError> {
    if diagnostic.diagnostic_model_id != CUDA_RUNTIME_VALIDATION_DIAGNOSTIC_MODEL_ID
        || diagnostic.diagnostic_model_version != 1
    {
        return Err(CudaRuntimeExtensionError::new(
            "cuda_runtime_validation_diagnostic_decode",
            "CUDA runtime validation diagnostic must declare the supported model id and version",
        ));
    }

    if diagnostic.related_requirements.is_empty()
        || diagnostic
            .related_requirements
            .iter()
            .any(|value| value.trim().is_empty())
        || diagnostic
            .evidence_refs
            .iter()
            .any(|value| value.trim().is_empty())
    {
        return Err(CudaRuntimeExtensionError::new(
            "cuda_runtime_validation_diagnostic_decode",
            "CUDA runtime validation diagnostic must keep non-blank requirement and evidence refs",
        ));
    }

    let mut requirements = diagnostic.related_requirements.clone();
    requirements.sort();
    requirements.dedup();
    if requirements.len() != diagnostic.related_requirements.len() {
        return Err(CudaRuntimeExtensionError::new(
            "cuda_runtime_validation_diagnostic_decode",
            "CUDA runtime validation diagnostic related requirements must be unique",
        ));
    }

    let mut evidence_refs = diagnostic.evidence_refs.clone();
    evidence_refs.sort();
    evidence_refs.dedup();
    if evidence_refs.len() != diagnostic.evidence_refs.len() {
        return Err(CudaRuntimeExtensionError::new(
            "cuda_runtime_validation_diagnostic_decode",
            "CUDA runtime validation diagnostic evidence refs must be unique",
        ));
    }

    let has_memory_threshold = diagnostic.required_allocatable_memory_bytes.is_some();
    let has_device_count_threshold = diagnostic.required_qualifying_device_count.is_some();
    let has_qualifying_device_aggregate_threshold = diagnostic
        .required_qualifying_device_aggregate_allocatable_memory_bytes
        .is_some();
    if !has_memory_threshold
        && !has_device_count_threshold
        && !has_qualifying_device_aggregate_threshold
    {
        return Err(CudaRuntimeExtensionError::new(
            "cuda_runtime_validation_diagnostic_decode",
            "CUDA runtime validation diagnostic must include at least one required threshold",
        ));
    }
    if diagnostic
        .required_device_allocatable_memory_bytes
        .is_some()
        && !has_device_count_threshold
    {
        return Err(CudaRuntimeExtensionError::new(
            "cuda_runtime_validation_diagnostic_decode",
            "CUDA runtime validation diagnostic per-device memory floor requires a qualifying device count threshold",
        ));
    }

    match diagnostic.detail_code {
        CudaRuntimeValidationDetailCodeV1::StaticRequirementUnsatisfied => {
            if !matches!(
                diagnostic.checkpoint,
                CudaRuntimeValidationCheckpointV1::RuntimeExtensionGate
            ) || diagnostic.observed_allocatable_memory_bytes.is_some()
                || diagnostic.observed_total_memory_bytes.is_some()
                || diagnostic.observed_qualifying_device_count.is_some()
            {
                return Err(CudaRuntimeExtensionError::new(
                    "cuda_runtime_validation_diagnostic_decode",
                    "static CUDA runtime validation diagnostics must not carry observed values and must use runtime_extension_gate",
                ));
            }
        }
        CudaRuntimeValidationDetailCodeV1::RuntimeStateMissing => {
            if !matches!(
                diagnostic.checkpoint,
                CudaRuntimeValidationCheckpointV1::RuntimeExtensionState
            ) || diagnostic.observed_allocatable_memory_bytes.is_some()
                || diagnostic.observed_total_memory_bytes.is_some()
                || diagnostic.observed_qualifying_device_count.is_some()
            {
                return Err(CudaRuntimeExtensionError::new(
                    "cuda_runtime_validation_diagnostic_decode",
                    "missing CUDA runtime-state diagnostics must not carry observed values and must use runtime_extension_state",
                ));
            }
        }
        CudaRuntimeValidationDetailCodeV1::RuntimeStateStale => {
            if !matches!(
                diagnostic.checkpoint,
                CudaRuntimeValidationCheckpointV1::RuntimeExtensionFreshness
            ) || diagnostic.observed_allocatable_memory_bytes.is_some()
                || diagnostic.observed_total_memory_bytes.is_some()
                || diagnostic.observed_qualifying_device_count.is_some()
            {
                return Err(CudaRuntimeExtensionError::new(
                    "cuda_runtime_validation_diagnostic_decode",
                    "stale CUDA runtime-state diagnostics must not carry observed values and must use runtime_extension_freshness",
                ));
            }
        }
        CudaRuntimeValidationDetailCodeV1::AllocatableMemoryInsufficient
        | CudaRuntimeValidationDetailCodeV1::RuntimeThresholdSatisfied => {
            let required_allocatable_memory_bytes = diagnostic
                .required_allocatable_memory_bytes
                .ok_or_else(|| {
                    CudaRuntimeExtensionError::new(
                        "cuda_runtime_validation_diagnostic_decode",
                        "CUDA allocatable-memory diagnostics must include required allocatable memory",
                    )
                })?;
            let observed_allocatable_memory_bytes =
                diagnostic.observed_allocatable_memory_bytes.ok_or_else(|| {
                    CudaRuntimeExtensionError::new(
                        "cuda_runtime_validation_diagnostic_decode",
                        "CUDA allocatable-memory diagnostics must include observed allocatable memory",
                    )
                })?;
            if !matches!(
                diagnostic.checkpoint,
                CudaRuntimeValidationCheckpointV1::RuntimeExtensionSummary
            ) || diagnostic.observed_qualifying_device_count.is_some()
            {
                return Err(CudaRuntimeExtensionError::new(
                    "cuda_runtime_validation_diagnostic_decode",
                    "CUDA allocatable-memory diagnostics must use runtime_extension_summary and must not carry observed qualifying-device counts",
                ));
            }
            if let Some(observed_total_memory_bytes) = diagnostic.observed_total_memory_bytes {
                if observed_allocatable_memory_bytes > observed_total_memory_bytes {
                    return Err(CudaRuntimeExtensionError::new(
                        "cuda_runtime_validation_diagnostic_decode",
                        "CUDA runtime validation diagnostic observed allocatable memory must not exceed observed total memory",
                    ));
                }
            }
            match diagnostic.detail_code {
                CudaRuntimeValidationDetailCodeV1::AllocatableMemoryInsufficient => {
                    if observed_allocatable_memory_bytes >= required_allocatable_memory_bytes {
                        return Err(CudaRuntimeExtensionError::new(
                            "cuda_runtime_validation_diagnostic_decode",
                            "insufficient CUDA allocatable-memory diagnostics must stay below the required threshold",
                        ));
                    }
                }
                CudaRuntimeValidationDetailCodeV1::RuntimeThresholdSatisfied => {
                    if observed_allocatable_memory_bytes < required_allocatable_memory_bytes {
                        return Err(CudaRuntimeExtensionError::new(
                            "cuda_runtime_validation_diagnostic_decode",
                            "satisfied CUDA allocatable-memory diagnostics must meet or exceed the required threshold",
                        ));
                    }
                }
                _ => unreachable!("covered above"),
            }
        }
        CudaRuntimeValidationDetailCodeV1::QualifyingDeviceCountInsufficient
        | CudaRuntimeValidationDetailCodeV1::QualifyingDeviceThresholdSatisfied => {
            let required_qualifying_device_count =
                diagnostic.required_qualifying_device_count.ok_or_else(|| {
                    CudaRuntimeExtensionError::new(
                        "cuda_runtime_validation_diagnostic_decode",
                        "CUDA qualifying-device diagnostics must include a required device count",
                    )
                })?;
            let observed_qualifying_device_count =
                diagnostic.observed_qualifying_device_count.ok_or_else(|| {
                    CudaRuntimeExtensionError::new(
                        "cuda_runtime_validation_diagnostic_decode",
                        "CUDA qualifying-device diagnostics must include an observed device count",
                    )
                })?;
            if !matches!(
                diagnostic.checkpoint,
                CudaRuntimeValidationCheckpointV1::RuntimeExtensionSummary
            ) || diagnostic.observed_allocatable_memory_bytes.is_some()
                || diagnostic.observed_total_memory_bytes.is_some()
            {
                return Err(CudaRuntimeExtensionError::new(
                    "cuda_runtime_validation_diagnostic_decode",
                    "CUDA qualifying-device diagnostics must use runtime_extension_summary and must not carry aggregate memory observations",
                ));
            }
            match diagnostic.detail_code {
                CudaRuntimeValidationDetailCodeV1::QualifyingDeviceCountInsufficient => {
                    if observed_qualifying_device_count >= required_qualifying_device_count {
                        return Err(CudaRuntimeExtensionError::new(
                            "cuda_runtime_validation_diagnostic_decode",
                            "insufficient CUDA qualifying-device diagnostics must stay below the required device count",
                        ));
                    }
                }
                CudaRuntimeValidationDetailCodeV1::QualifyingDeviceThresholdSatisfied => {
                    if observed_qualifying_device_count < required_qualifying_device_count {
                        return Err(CudaRuntimeExtensionError::new(
                            "cuda_runtime_validation_diagnostic_decode",
                            "satisfied CUDA qualifying-device diagnostics must meet or exceed the required device count",
                        ));
                    }
                }
                _ => unreachable!("covered above"),
            }
        }
        CudaRuntimeValidationDetailCodeV1::QualifyingDeviceAggregateAllocatableMemoryInsufficient
        | CudaRuntimeValidationDetailCodeV1::QualifyingDeviceAggregateAllocatableMemoryThresholdSatisfied => {
            let required_qualifying_device_count =
                diagnostic.required_qualifying_device_count.ok_or_else(|| {
                    CudaRuntimeExtensionError::new(
                        "cuda_runtime_validation_diagnostic_decode",
                        "CUDA qualifying-device aggregate diagnostics must include a required device count",
                    )
                })?;
            let observed_qualifying_device_count =
                diagnostic.observed_qualifying_device_count.ok_or_else(|| {
                    CudaRuntimeExtensionError::new(
                        "cuda_runtime_validation_diagnostic_decode",
                        "CUDA qualifying-device aggregate diagnostics must include an observed device count",
                    )
                })?;
            let required_aggregate =
                diagnostic
                    .required_qualifying_device_aggregate_allocatable_memory_bytes
                    .ok_or_else(|| {
                        CudaRuntimeExtensionError::new(
                            "cuda_runtime_validation_diagnostic_decode",
                            "CUDA qualifying-device aggregate diagnostics must include a required aggregate threshold",
                        )
                    })?;
            let observed_aggregate =
                diagnostic
                    .observed_qualifying_device_aggregate_allocatable_memory_bytes
                    .ok_or_else(|| {
                        CudaRuntimeExtensionError::new(
                            "cuda_runtime_validation_diagnostic_decode",
                            "CUDA qualifying-device aggregate diagnostics must include an observed aggregate value",
                        )
                    })?;
            if diagnostic.required_device_allocatable_memory_bytes.is_none()
                || !matches!(
                    diagnostic.checkpoint,
                    CudaRuntimeValidationCheckpointV1::RuntimeExtensionSummary
                )
                || diagnostic.required_allocatable_memory_bytes.is_some()
                || diagnostic.observed_allocatable_memory_bytes.is_some()
                || diagnostic.observed_total_memory_bytes.is_some()
            {
                return Err(CudaRuntimeExtensionError::new(
                    "cuda_runtime_validation_diagnostic_decode",
                    "CUDA qualifying-device aggregate diagnostics must use runtime_extension_summary, carry per-device floor and count context, and must not carry total-aggregate observations",
                ));
            }
            if observed_qualifying_device_count < required_qualifying_device_count {
                return Err(CudaRuntimeExtensionError::new(
                    "cuda_runtime_validation_diagnostic_decode",
                    "CUDA qualifying-device aggregate diagnostics must only be emitted after the qualifying-device count threshold is satisfied",
                ));
            }
            match diagnostic.detail_code {
                CudaRuntimeValidationDetailCodeV1::QualifyingDeviceAggregateAllocatableMemoryInsufficient => {
                    if observed_aggregate >= required_aggregate {
                        return Err(CudaRuntimeExtensionError::new(
                            "cuda_runtime_validation_diagnostic_decode",
                            "insufficient CUDA qualifying-device aggregate diagnostics must stay below the required threshold",
                        ));
                    }
                }
                CudaRuntimeValidationDetailCodeV1::QualifyingDeviceAggregateAllocatableMemoryThresholdSatisfied => {
                    if observed_aggregate < required_aggregate {
                        return Err(CudaRuntimeExtensionError::new(
                            "cuda_runtime_validation_diagnostic_decode",
                            "satisfied CUDA qualifying-device aggregate diagnostics must meet or exceed the required threshold",
                        ));
                    }
                }
                _ => unreachable!("covered above"),
            }
        }
    }

    Ok(())
}

fn validate_collector(collector: &CollectorMetadataV1) -> Result<(), CudaRuntimeExtensionError> {
    if collector.collector_id != CUDA_RUNTIME_COLLECTOR_ID
        || collector.collector_version != CUDA_RUNTIME_COLLECTOR_VERSION
        || !matches!(
            collector.source_family.as_str(),
            CUDA_RUNTIME_LIVE_SOURCE_FAMILY | CUDA_RUNTIME_REPLAY_SOURCE_FAMILY
        )
    {
        return Err(CudaRuntimeExtensionError::new(
            "cuda_extension_normalize",
            "CUDA runtime collector metadata contains an unsupported collector tuple",
        ));
    }
    Ok(())
}

fn validate_cuda_runtime_state_collector(
    collector: &CollectorMetadataV1,
) -> Result<(), CudaRuntimeExtensionError> {
    if collector.collector_id != CUDA_RUNTIME_STATE_COLLECTOR_ID
        || collector.collector_version != CUDA_RUNTIME_COLLECTOR_VERSION
        || !matches!(
            collector.source_family.as_str(),
            CUDA_RUNTIME_LIVE_SOURCE_FAMILY | CUDA_RUNTIME_REPLAY_SOURCE_FAMILY
        )
    {
        return Err(CudaRuntimeExtensionError::new(
            "cuda_state_extension_validate",
            "CUDA runtime state collector metadata contains an unsupported collector tuple",
        ));
    }
    Ok(())
}

fn validate_claim_metadata(metadata: &ClaimMetadataV1) -> Result<(), CudaRuntimeExtensionError> {
    if metadata.source_collectors.is_empty()
        || metadata
            .source_collectors
            .iter()
            .any(|value| value.trim().is_empty())
        || metadata
            .evidence_paths
            .iter()
            .any(|value| value.trim().is_empty())
        || metadata
            .policy_rule_id
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        || metadata
            .trust_evidence_refs
            .iter()
            .any(|value| value.trim().is_empty())
    {
        return Err(CudaRuntimeExtensionError::new(
            "cuda_extension_normalize",
            "CUDA runtime claim metadata must remain fully populated and non-blank",
        ));
    }
    Ok(())
}

fn validate_version(version: &CudaRuntimeVersionV1) -> Result<(), CudaRuntimeExtensionError> {
    if version.major == 0 {
        return Err(CudaRuntimeExtensionError::new(
            "cuda_extension_validate",
            "CUDA runtime versions must use a positive major version",
        ));
    }
    Ok(())
}

fn validate_optional_version(
    version: Option<&CudaRuntimeVersionV1>,
    field_name: &str,
    checkpoint_id: &'static str,
) -> Result<(), CudaRuntimeExtensionError> {
    if let Some(version) = version {
        validate_version(version).map_err(|error| {
            CudaRuntimeExtensionError::new(
                checkpoint_id,
                format!("CUDA runtime {field_name} {}", error.message),
            )
        })?;
    }
    Ok(())
}

fn validate_cuda_default_view_probe_diagnostics(
    diagnostics: Option<&CudaDefaultViewProbeDiagnosticsV1>,
    toolkit_observed: bool,
    driver_observed: bool,
    driver_supported_observed: bool,
    runtime_observed: bool,
    checkpoint_id: &'static str,
) -> Result<(), CudaRuntimeExtensionError> {
    let Some(diagnostics) = diagnostics else {
        return Ok(());
    };
    validate_cuda_default_view_field_diagnostic(
        &diagnostics.default_toolkit_version,
        "default_toolkit_version",
        toolkit_observed,
        checkpoint_id,
    )?;
    validate_cuda_default_view_field_diagnostic(
        &diagnostics.driver_version,
        "driver_version",
        driver_observed,
        checkpoint_id,
    )?;
    validate_cuda_default_view_field_diagnostic(
        &diagnostics.driver_supported_cuda_version,
        "driver_supported_cuda_version",
        driver_supported_observed,
        checkpoint_id,
    )?;
    validate_cuda_default_view_field_diagnostic(
        &diagnostics.default_runtime_version,
        "default_runtime_version",
        runtime_observed,
        checkpoint_id,
    )?;
    Ok(())
}

fn validate_cuda_default_view_field_diagnostic(
    diagnostic: &CudaDefaultViewFieldDiagnosticV1,
    field_name: &str,
    value_observed: bool,
    checkpoint_id: &'static str,
) -> Result<(), CudaRuntimeExtensionError> {
    if diagnostic.source_ref.trim().is_empty() {
        return Err(CudaRuntimeExtensionError::new(
            checkpoint_id,
            format!("CUDA default-view diagnostic {field_name} must use a non-blank source_ref"),
        ));
    }
    if value_observed && diagnostic.status != CudaDefaultViewProbeStatusV1::Observed {
        return Err(CudaRuntimeExtensionError::new(
            checkpoint_id,
            format!(
                "CUDA default-view diagnostic {field_name} must use observed status when the field value is present"
            ),
        ));
    }
    if !value_observed && diagnostic.status == CudaDefaultViewProbeStatusV1::Observed {
        return Err(CudaRuntimeExtensionError::new(
            checkpoint_id,
            format!(
                "CUDA default-view diagnostic {field_name} must not use observed status when the field value is absent"
            ),
        ));
    }
    Ok(())
}

fn validate_cuda_memory_triplet(
    total: Option<u64>,
    allocatable: Option<u64>,
    used: Option<u64>,
    subject: &str,
    checkpoint_id: &'static str,
) -> Result<(), CudaRuntimeExtensionError> {
    if let (Some(total), Some(allocatable)) = (total, allocatable) {
        if allocatable > total {
            return Err(CudaRuntimeExtensionError::new(
                checkpoint_id,
                format!("{subject} allocatable memory must not exceed total memory"),
            ));
        }
    }
    if let (Some(total), Some(used)) = (total, used) {
        if used > total {
            return Err(CudaRuntimeExtensionError::new(
                checkpoint_id,
                format!("{subject} used memory must not exceed total memory"),
            ));
        }
    }
    if let (Some(total), Some(allocatable), Some(used)) = (total, allocatable, used) {
        if used.saturating_add(allocatable) > total {
            return Err(CudaRuntimeExtensionError::new(
                checkpoint_id,
                format!("{subject} used plus allocatable memory must not exceed total memory"),
            ));
        }
    }
    Ok(())
}

fn validate_installed_toolkits(
    installed_toolkits: &[CudaInstalledToolkitV1],
    checkpoint_id: &'static str,
) -> Result<(), CudaRuntimeExtensionError> {
    let mut install_roots = BTreeSet::new();
    let mut selected_count = 0usize;

    for entry in installed_toolkits {
        if entry.install_root.trim().is_empty() {
            return Err(CudaRuntimeExtensionError::new(
                checkpoint_id,
                "installed CUDA toolkit entries must use a non-blank install_root",
            ));
        }
        if !Path::new(&entry.install_root).is_absolute() {
            return Err(CudaRuntimeExtensionError::new(
                checkpoint_id,
                "installed CUDA toolkit entries must use absolute install_root paths",
            ));
        }
        validate_version(&entry.version).map_err(|error| {
            CudaRuntimeExtensionError::new(
                checkpoint_id,
                format!("installed CUDA toolkit version {}", error.message),
            )
        })?;
        if !install_roots.insert(entry.install_root.clone()) {
            return Err(CudaRuntimeExtensionError::new(
                checkpoint_id,
                "installed CUDA toolkit entries must not repeat one install_root",
            ));
        }
        if entry.selected_by_default_toolkit_view {
            selected_count += 1;
        }
    }

    if selected_count > 1 {
        return Err(CudaRuntimeExtensionError::new(
            checkpoint_id,
            "installed CUDA toolkit entries may mark at most one default-toolkit selection",
        ));
    }

    Ok(())
}

fn validate_cuda_runtime_replay_manifest(
    manifest: &CudaRuntimeReplayCorpusV1,
) -> Result<(), CudaRuntimeExtensionError> {
    if manifest.schema_id != CUDA_RUNTIME_REPLAY_CORPUS_SCHEMA_ID
        || manifest.schema_version != 1
        || manifest.namespace != CUDA_RUNTIME_NAMESPACE
        || manifest.fixtures.is_empty()
    {
        return Err(CudaRuntimeExtensionError::new(
            "cuda_extension_collect",
            "CUDA runtime replay manifest must declare the supported schema, namespace, and fixtures",
        ));
    }

    let mut ids = BTreeSet::new();
    for fixture in &manifest.fixtures {
        if fixture.fixture_id.trim().is_empty()
            || fixture.path.trim().is_empty()
            || Path::new(&fixture.path).is_absolute()
            || !ids.insert(fixture.fixture_id.clone())
        {
            return Err(CudaRuntimeExtensionError::new(
                "cuda_extension_collect",
                "CUDA runtime replay manifest contains duplicate ids or invalid paths",
            ));
        }
    }

    Ok(())
}

fn validate_cuda_runtime_state_replay_manifest(
    manifest: &CudaRuntimeStateReplayCorpusV1,
) -> Result<(), CudaRuntimeExtensionError> {
    if manifest.schema_id != CUDA_RUNTIME_STATE_REPLAY_CORPUS_SCHEMA_ID
        || manifest.schema_version != 1
        || manifest.namespace != CUDA_RUNTIME_NAMESPACE
        || manifest.fixtures.is_empty()
    {
        return Err(CudaRuntimeExtensionError::new(
            "cuda_state_extension_replay",
            "CUDA runtime state replay manifest must declare the supported schema, namespace, and fixtures",
        ));
    }

    let mut ids = BTreeSet::new();
    for fixture in &manifest.fixtures {
        if fixture.fixture_id.trim().is_empty()
            || fixture.path.trim().is_empty()
            || Path::new(&fixture.path).is_absolute()
            || !ids.insert(fixture.fixture_id.clone())
        {
            return Err(CudaRuntimeExtensionError::new(
                "cuda_state_extension_replay",
                "CUDA runtime state replay manifest contains duplicate ids or invalid paths",
            ));
        }
    }

    Ok(())
}

fn resolve_replay_fixture_path(
    root: &Path,
    relative_path: &str,
) -> Result<PathBuf, CudaRuntimeExtensionError> {
    let canonical_root = fs::canonicalize(root).map_err(|error| {
        CudaRuntimeExtensionError::new(
            "cuda_extension_collect",
            format!(
                "failed to resolve CUDA runtime replay root {}: {error}",
                root.display()
            ),
        )
    })?;
    let candidate = canonical_root.join(relative_path);
    let canonical_candidate = fs::canonicalize(&candidate).map_err(|error| {
        CudaRuntimeExtensionError::new(
            "cuda_extension_collect",
            format!(
                "failed to resolve CUDA runtime replay fixture {}: {error}",
                candidate.display()
            ),
        )
    })?;
    if !canonical_candidate.starts_with(&canonical_root) {
        return Err(CudaRuntimeExtensionError::new(
            "cuda_extension_collect",
            "CUDA runtime replay fixture path escapes the selected root",
        ));
    }
    Ok(canonical_candidate)
}

fn claim_metadata_for_collector(collector_id: &str, evidence_path: &str) -> ClaimMetadataV1 {
    ClaimMetadataV1 {
        assurance_source: AssuranceSourceV1::SelfObserved,
        derivation_stage: DerivationStageV1::Normalized,
        source_collectors: vec![collector_id.to_string()],
        evidence_paths: vec![evidence_path.to_string()],
        policy_rule_id: None,
        trust_evidence_refs: Vec::new(),
    }
}

fn missing_cuda_runtime_state(
    collector: CollectorMetadataV1,
    limitation_reason: Option<ObservationLimitationReasonV1>,
    probe_path: Option<String>,
) -> CudaRuntimeStateV1 {
    CudaRuntimeStateV1 {
        schema_id: CUDA_RUNTIME_STATE_SCHEMA_ID.to_string(),
        schema_version: 1,
        collector,
        claim_metadata: claim_metadata_for_collector(
            CUDA_RUNTIME_STATE_COLLECTOR_ID,
            CUDA_STATE_PATH,
        ),
        runtime_id: "cuda".to_string(),
        runtime_state: ObservationStateV1::Missing,
        limitation_reason,
        devices: Vec::new(),
        total_memory_bytes: missing_state_field(),
        allocatable_memory_bytes: missing_state_field(),
        used_memory_bytes: missing_state_field(),
        default_toolkit_version: missing_cuda_runtime_version_state_field_v1(),
        driver_version: missing_cuda_runtime_version_state_field_v1(),
        driver_supported_cuda_version: missing_cuda_runtime_version_state_field_v1(),
        default_runtime_version: missing_cuda_runtime_version_state_field_v1(),
        default_view_probe_diagnostics: None,
        selected_environment: None,
        selected_environment_toolkit_version: missing_cuda_runtime_version_state_field_v1(),
        selected_environment_runtime_version: missing_cuda_runtime_version_state_field_v1(),
        selected_environment_probe_diagnostics: None,
        probe_path,
    }
}

fn selected_environment_from_catalogue_entry(
    entry: &CudaEnvironmentCatalogueEntryV1,
) -> CudaSelectedEnvironmentV1 {
    CudaSelectedEnvironmentV1 {
        environment_id: entry.environment_id.clone(),
        selection: entry.selection.clone(),
    }
}

fn validate_cuda_selected_environment(
    selected_environment: &CudaSelectedEnvironmentV1,
    checkpoint_id: &'static str,
) -> Result<(), CudaRuntimeExtensionError> {
    if selected_environment.environment_id.trim().is_empty() {
        return Err(CudaRuntimeExtensionError::new(
            checkpoint_id,
            "CUDA selected environment must use a non-blank environment_id",
        ));
    }
    match selected_environment.selection.kind {
        CudaEnvironmentSelectionKindV1::DefaultView => {
            if selected_environment.selection.install_root.is_some() {
                return Err(CudaRuntimeExtensionError::new(
                    checkpoint_id,
                    "CUDA selected environment default_view must not carry install_root",
                ));
            }
        }
        CudaEnvironmentSelectionKindV1::ToolkitInstallRoot => {
            let Some(install_root) = selected_environment.selection.install_root.as_deref() else {
                return Err(CudaRuntimeExtensionError::new(
                    checkpoint_id,
                    "CUDA selected environment toolkit_install_root must carry install_root",
                ));
            };
            if install_root.trim().is_empty() || !Path::new(install_root).is_absolute() {
                return Err(CudaRuntimeExtensionError::new(
                    checkpoint_id,
                    "CUDA selected environment toolkit_install_root must use an absolute non-blank install_root",
                ));
            }
        }
    }
    Ok(())
}

fn validate_cuda_selected_environment_input(
    input: &CudaSelectedEnvironmentInputV1,
) -> Result<(), CudaRuntimeExtensionError> {
    if input.schema_id != CUDA_SELECTED_ENVIRONMENT_INPUT_SCHEMA_ID || input.schema_version != 1 {
        return Err(CudaRuntimeExtensionError::new(
            "selected_cuda_environment_input_load",
            "CUDA selected-environment input must declare the supported schema id and schema version",
        ));
    }
    validate_cuda_selected_environment(
        &input.selected_environment,
        "selected_cuda_environment_input_load",
    )?;
    validate_optional_version(
        input.toolkit_version.as_ref(),
        "selected_environment_toolkit_version",
        "selected_cuda_environment_input_load",
    )?;
    validate_optional_version(
        input.runtime_version.as_ref(),
        "selected_environment_runtime_version",
        "selected_cuda_environment_input_load",
    )?;
    validate_selected_environment_extension_fields(
        Some(&input.selected_environment),
        input.toolkit_version.is_some(),
        input.runtime_version.is_some(),
        input.probe_diagnostics.as_ref(),
        "selected_cuda_environment_input_load",
    )?;
    Ok(())
}

fn validate_cuda_selected_environment_probe_diagnostics(
    diagnostics: Option<&CudaSelectedEnvironmentProbeDiagnosticsV1>,
    toolkit_observed: bool,
    runtime_observed: bool,
    checkpoint_id: &'static str,
) -> Result<(), CudaRuntimeExtensionError> {
    let Some(diagnostics) = diagnostics else {
        return Ok(());
    };
    validate_cuda_default_view_field_diagnostic(
        &diagnostics.toolkit_version,
        "selected_environment_toolkit_version",
        toolkit_observed,
        checkpoint_id,
    )?;
    validate_cuda_default_view_field_diagnostic(
        &diagnostics.runtime_version,
        "selected_environment_runtime_version",
        runtime_observed,
        checkpoint_id,
    )?;
    Ok(())
}

fn validate_selected_environment_extension_fields(
    selected_environment: Option<&CudaSelectedEnvironmentV1>,
    toolkit_version_observed: bool,
    runtime_version_observed: bool,
    diagnostics: Option<&CudaSelectedEnvironmentProbeDiagnosticsV1>,
    checkpoint_id: &'static str,
) -> Result<(), CudaRuntimeExtensionError> {
    let Some(selected_environment) = selected_environment else {
        if toolkit_version_observed || runtime_version_observed || diagnostics.is_some() {
            return Err(CudaRuntimeExtensionError::new(
                checkpoint_id,
                "selected-environment CUDA fields require selected_environment metadata",
            ));
        }
        return Ok(());
    };

    validate_cuda_selected_environment(selected_environment, checkpoint_id)?;
    match selected_environment.selection.kind {
        CudaEnvironmentSelectionKindV1::DefaultView => {
            if toolkit_version_observed || runtime_version_observed || diagnostics.is_some() {
                return Err(CudaRuntimeExtensionError::new(
                    checkpoint_id,
                    "default_view selected CUDA environment must not redefine selected toolkit or runtime fields",
                ));
            }
        }
        CudaEnvironmentSelectionKindV1::ToolkitInstallRoot => {
            if diagnostics.is_none() {
                return Err(CudaRuntimeExtensionError::new(
                    checkpoint_id,
                    "toolkit_install_root selected CUDA environment must carry probe diagnostics",
                ));
            }
            validate_cuda_selected_environment_probe_diagnostics(
                diagnostics,
                toolkit_version_observed,
                runtime_version_observed,
                checkpoint_id,
            )?;
        }
    }
    Ok(())
}

fn apply_selected_environment_request_to_evidence(
    evidence: &mut CudaRuntimeEvidenceV1,
    selected_environment: Option<&CudaSelectedEnvironmentRequestV1>,
    live_mode: bool,
) -> Result<(), CudaRuntimeExtensionError> {
    let Some(selected_environment) = selected_environment else {
        return Ok(());
    };
    match selected_environment {
        CudaSelectedEnvironmentRequestV1::CatalogueEntry(entry) if !live_mode => Err(
            CudaRuntimeExtensionError::new(
                "selected_cuda_environment_selection",
                "replay CUDA collection must not consume live selected-environment catalogue entries",
            ),
        ),
        CudaSelectedEnvironmentRequestV1::ReplayInput(_) if live_mode => Err(
            CudaRuntimeExtensionError::new(
                "selected_cuda_environment_selection",
                "live CUDA collection must not consume replay selected-environment input",
            ),
        ),
        CudaSelectedEnvironmentRequestV1::CatalogueEntry(entry) => {
            let fields = collect_live_selected_environment_fields(entry)?;
            evidence.selected_environment = Some(fields.selected_environment);
            evidence.selected_environment_toolkit_version = fields.toolkit_version;
            evidence.selected_environment_runtime_version = fields.runtime_version;
            evidence.selected_environment_probe_diagnostics = fields.diagnostics;
            Ok(())
        }
        CudaSelectedEnvironmentRequestV1::ReplayInput(input) => {
            evidence.selected_environment = Some(input.selected_environment.clone());
            evidence.selected_environment_toolkit_version = input.toolkit_version.clone();
            evidence.selected_environment_runtime_version = input.runtime_version.clone();
            evidence.selected_environment_probe_diagnostics = input.probe_diagnostics.clone();
            validate_cuda_runtime_evidence(evidence)
        }
    }
}

fn apply_selected_environment_request_to_state(
    state: &mut CudaRuntimeStateV1,
    selected_environment: Option<&CudaSelectedEnvironmentRequestV1>,
    live_mode: bool,
) -> Result<(), CudaRuntimeExtensionError> {
    let Some(selected_environment) = selected_environment else {
        return Ok(());
    };
    match selected_environment {
        CudaSelectedEnvironmentRequestV1::CatalogueEntry(entry) if !live_mode => Err(
            CudaRuntimeExtensionError::new(
                "selected_cuda_environment_selection",
                "replay CUDA state collection must not consume live selected-environment catalogue entries",
            ),
        ),
        CudaSelectedEnvironmentRequestV1::ReplayInput(_) if live_mode => Err(
            CudaRuntimeExtensionError::new(
                "selected_cuda_environment_selection",
                "live CUDA state collection must not consume replay selected-environment input",
            ),
        ),
        CudaSelectedEnvironmentRequestV1::CatalogueEntry(entry) => {
            let fields = collect_live_selected_environment_fields(entry)?;
            state.selected_environment = Some(fields.selected_environment);
            state.selected_environment_toolkit_version =
                version_state_field_from_optional(fields.toolkit_version);
            state.selected_environment_runtime_version =
                version_state_field_from_optional(fields.runtime_version);
            state.selected_environment_probe_diagnostics = fields.diagnostics;
            validate_cuda_runtime_state(state)
        }
        CudaSelectedEnvironmentRequestV1::ReplayInput(input) => {
            state.selected_environment = Some(input.selected_environment.clone());
            state.selected_environment_toolkit_version =
                version_state_field_from_optional(input.toolkit_version.clone());
            state.selected_environment_runtime_version =
                version_state_field_from_optional(input.runtime_version.clone());
            state.selected_environment_probe_diagnostics = input.probe_diagnostics.clone();
            validate_cuda_runtime_state(state)
        }
    }
}

fn collect_live_selected_environment_fields(
    entry: &CudaEnvironmentCatalogueEntryV1,
) -> Result<CudaLiveSelectedEnvironmentFieldsV1, CudaRuntimeExtensionError> {
    let selected_environment = selected_environment_from_catalogue_entry(entry);
    validate_cuda_selected_environment(
        &selected_environment,
        "selected_cuda_environment_selection",
    )?;

    match selected_environment.selection.kind {
        CudaEnvironmentSelectionKindV1::DefaultView => Ok(CudaLiveSelectedEnvironmentFieldsV1 {
            selected_environment,
            toolkit_version: None,
            runtime_version: None,
            diagnostics: None,
        }),
        CudaEnvironmentSelectionKindV1::ToolkitInstallRoot => {
            let install_root = PathBuf::from(
                selected_environment
                    .selection
                    .install_root
                    .as_deref()
                    .expect("validated above"),
            );
            let probe_outputs = collect_live_selected_environment_probe_outputs(&install_root)?;
            let toolkit_version = probe_outputs
                .nvcc
                .output
                .as_deref()
                .map(parse_cuda_version_output)
                .transpose()?;
            let runtime_version = probe_outputs
                .runtime_version
                .raw_version
                .map(|raw| parse_cuda_api_version_number(raw, "selected CUDA runtime"))
                .transpose()?
                .flatten();
            let diagnostics = Some(CudaSelectedEnvironmentProbeDiagnosticsV1 {
                toolkit_version: CudaDefaultViewFieldDiagnosticV1 {
                    source_tier: CudaDefaultViewProbeSourceTierV1::Primary,
                    source_kind: CudaDefaultViewProbeSourceKindV1::CommandProbe,
                    source_ref: probe_outputs.nvcc.source_ref,
                    status: if toolkit_version.is_some() {
                        CudaDefaultViewProbeStatusV1::Observed
                    } else {
                        probe_outputs.nvcc.status
                    },
                },
                runtime_version: CudaDefaultViewFieldDiagnosticV1 {
                    source_tier: CudaDefaultViewProbeSourceTierV1::Primary,
                    source_kind: CudaDefaultViewProbeSourceKindV1::DynamicLibraryProbe,
                    source_ref: probe_outputs.runtime_version.source_ref,
                    status: if runtime_version.is_some() {
                        CudaDefaultViewProbeStatusV1::Observed
                    } else {
                        probe_outputs.runtime_version.status
                    },
                },
            });
            Ok(CudaLiveSelectedEnvironmentFieldsV1 {
                selected_environment,
                toolkit_version,
                runtime_version,
                diagnostics,
            })
        }
    }
}

fn collect_live_selected_environment_probe_outputs(
    install_root: &Path,
) -> Result<CudaLiveSelectedEnvironmentProbeOutputsV1, CudaRuntimeExtensionError> {
    let install_root = install_root.display().to_string();
    let nvcc_path = Path::new(&install_root).join("bin").join("nvcc");
    let nvcc = if env::var_os(TEST_CUDA_STUB_LIVE_PROBES_ENV).is_some() {
        let output = env::var(TEST_CUDA_SELECTED_ENVIRONMENT_NVCC_VERSION_OUTPUT_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty());
        CudaCommandProbeOutputV1 {
            source_ref: nvcc_path.display().to_string(),
            status: if output.is_some() {
                CudaDefaultViewProbeStatusV1::Observed
            } else {
                CudaDefaultViewProbeStatusV1::SourceUnavailable
            },
            output,
        }
    } else if !nvcc_path.is_file() {
        CudaCommandProbeOutputV1 {
            source_ref: nvcc_path.display().to_string(),
            status: CudaDefaultViewProbeStatusV1::SourceUnavailable,
            output: None,
        }
    } else {
        let output = collect_command_probe_output(&nvcc_path, &["--version"]);
        CudaCommandProbeOutputV1 {
            source_ref: nvcc_path.display().to_string(),
            status: if output.is_some() {
                CudaDefaultViewProbeStatusV1::Observed
            } else {
                CudaDefaultViewProbeStatusV1::ProbeFailed
            },
            output,
        }
    };

    let runtime_version = if env::var_os(TEST_CUDA_STUB_LIVE_PROBES_ENV).is_some() {
        collect_stubbed_library_probe_output(
            TEST_CUDA_SELECTED_ENVIRONMENT_RUNTIME_VERSION_ENV,
            &[&format!("{install_root}/lib64/libcudart.so")],
        )?
    } else {
        let candidates = selected_environment_runtime_library_candidates(Path::new(&install_root));
        probe_cuda_api_version_from_owned_library_refs_with_status(
            &candidates,
            b"cudaRuntimeGetVersion\0",
        )
    };

    Ok(CudaLiveSelectedEnvironmentProbeOutputsV1 {
        nvcc,
        runtime_version,
    })
}

fn selected_environment_runtime_library_candidates(install_root: &Path) -> Vec<String> {
    [
        "lib64/libcudart.so",
        "lib64/libcudart.so.12",
        "lib64/libcudart.so.11.0",
        "lib/libcudart.so",
    ]
    .iter()
    .map(|suffix| install_root.join(suffix).display().to_string())
    .collect()
}

fn collect_live_cuda_default_view_fields(
) -> Result<CudaLiveDefaultViewFieldsV1, CudaRuntimeExtensionError> {
    let probe_outputs = collect_live_cuda_default_view_probe_outputs()?;
    let toolkit_version = probe_outputs
        .nvcc
        .output
        .as_deref()
        .map(parse_cuda_version_output)
        .transpose()?;
    let driver_version = probe_outputs
        .driver_version
        .output
        .as_deref()
        .map(parse_nvidia_driver_version_output)
        .transpose()?;
    let (driver_supported_cuda_version, driver_supported_diagnostic) =
        select_driver_supported_cuda_version_with_fallback(&probe_outputs)?;
    let default_runtime_version = probe_outputs
        .default_runtime_version
        .raw_version
        .map(|raw| parse_cuda_api_version_number(raw, "default CUDA runtime"))
        .transpose()?
        .flatten();
    let toolkit_root = toolkit_version.as_ref().and_then(|_| {
        infer_cuda_toolkit_root_from_nvcc_path(Path::new(&probe_outputs.nvcc.source_ref))
    });
    let toolkit_observed = toolkit_version.is_some();
    let driver_observed = driver_version.is_some();
    let driver_supported_observed = driver_supported_cuda_version.is_some();
    let default_runtime_observed = default_runtime_version.is_some();

    Ok(CudaLiveDefaultViewFieldsV1 {
        executable_path: toolkit_version
            .as_ref()
            .map(|_| probe_outputs.nvcc.source_ref.clone()),
        toolkit_root,
        toolkit_version,
        driver_version,
        driver_supported_cuda_version,
        default_runtime_version,
        diagnostics: CudaDefaultViewProbeDiagnosticsV1 {
            default_toolkit_version: CudaDefaultViewFieldDiagnosticV1 {
                source_tier: CudaDefaultViewProbeSourceTierV1::Primary,
                source_kind: CudaDefaultViewProbeSourceKindV1::CommandProbe,
                source_ref: probe_outputs.nvcc.source_ref,
                status: if toolkit_observed {
                    CudaDefaultViewProbeStatusV1::Observed
                } else {
                    probe_outputs.nvcc.status
                },
            },
            driver_version: CudaDefaultViewFieldDiagnosticV1 {
                source_tier: CudaDefaultViewProbeSourceTierV1::Primary,
                source_kind: CudaDefaultViewProbeSourceKindV1::FileProbe,
                source_ref: probe_outputs.driver_version.source_ref,
                status: if driver_observed {
                    CudaDefaultViewProbeStatusV1::Observed
                } else {
                    probe_outputs.driver_version.status
                },
            },
            driver_supported_cuda_version: CudaDefaultViewFieldDiagnosticV1 {
                source_tier: driver_supported_diagnostic.source_tier,
                source_kind: driver_supported_diagnostic.source_kind,
                source_ref: driver_supported_diagnostic.source_ref,
                status: if driver_supported_observed {
                    CudaDefaultViewProbeStatusV1::Observed
                } else {
                    driver_supported_diagnostic.status
                },
            },
            default_runtime_version: CudaDefaultViewFieldDiagnosticV1 {
                source_tier: CudaDefaultViewProbeSourceTierV1::Primary,
                source_kind: CudaDefaultViewProbeSourceKindV1::DynamicLibraryProbe,
                source_ref: probe_outputs.default_runtime_version.source_ref,
                status: if default_runtime_observed {
                    CudaDefaultViewProbeStatusV1::Observed
                } else {
                    probe_outputs.default_runtime_version.status
                },
            },
        },
    })
}

fn collect_live_cuda_default_view_probe_outputs(
) -> Result<CudaLiveDefaultViewProbeOutputsV1, CudaRuntimeExtensionError> {
    if env::var_os(TEST_CUDA_STUB_LIVE_PROBES_ENV).is_some() {
        return collect_stubbed_cuda_live_default_view_probe_outputs();
    }

    Ok(CudaLiveDefaultViewProbeOutputsV1 {
        nvcc: collect_command_probe_output_with_status("nvcc", &["--version"]),
        driver_version: collect_file_probe_output_with_status("/proc/driver/nvidia/version"),
        driver_supported_cuda_version: probe_cuda_api_version_from_libraries_with_status(
            &["libcuda.so.1", "libcuda.so"],
            b"cuDriverGetVersion\0",
        ),
        advisory_driver_supported_cuda_version: collect_command_probe_output_with_status(
            "nvidia-smi",
            &[],
        ),
        default_runtime_version: probe_cuda_api_version_from_libraries_with_status(
            &["libcudart.so", "libcudart.so.12", "libcudart.so.11.0"],
            b"cudaRuntimeGetVersion\0",
        ),
    })
}

fn collect_stubbed_cuda_live_default_view_probe_outputs(
) -> Result<CudaLiveDefaultViewProbeOutputsV1, CudaRuntimeExtensionError> {
    Ok(CudaLiveDefaultViewProbeOutputsV1 {
        nvcc: collect_stubbed_command_probe_output(
            TEST_CUDA_NVCC_PATH_ENV,
            TEST_CUDA_NVCC_VERSION_OUTPUT_ENV,
            "nvcc",
        ),
        driver_version: collect_stubbed_file_probe_output(
            TEST_CUDA_DRIVER_VERSION_TEXT_ENV,
            "/proc/driver/nvidia/version",
        ),
        driver_supported_cuda_version: collect_stubbed_library_probe_output(
            TEST_CUDA_DRIVER_SUPPORTED_VERSION_ENV,
            &["libcuda.so.1", "libcuda.so"],
        )?,
        advisory_driver_supported_cuda_version: collect_stubbed_command_probe_output(
            TEST_CUDA_NVIDIA_SMI_BANNER_PATH_ENV,
            TEST_CUDA_NVIDIA_SMI_BANNER_OUTPUT_ENV,
            "nvidia-smi",
        ),
        default_runtime_version: collect_stubbed_library_probe_output(
            TEST_CUDA_DEFAULT_RUNTIME_VERSION_ENV,
            &["libcudart.so", "libcudart.so.12", "libcudart.so.11.0"],
        )?,
    })
}

fn collect_live_cuda_installed_toolkits(
    default_toolkit_root: Option<&Path>,
    default_toolkit_version: Option<&CudaRuntimeVersionV1>,
) -> Result<Vec<CudaInstalledToolkitV1>, CudaRuntimeExtensionError> {
    let discovered = collect_live_cuda_installed_toolkit_candidates(
        default_toolkit_root,
        default_toolkit_version,
    )?;
    normalize_cuda_installed_toolkits(discovered, default_toolkit_root)
}

fn collect_live_cuda_installed_toolkit_candidates(
    default_toolkit_root: Option<&Path>,
    default_toolkit_version: Option<&CudaRuntimeVersionV1>,
) -> Result<Vec<CudaDiscoveredToolkitCandidateV1>, CudaRuntimeExtensionError> {
    if env::var_os(TEST_CUDA_STUB_LIVE_PROBES_ENV).is_some() {
        return collect_stubbed_cuda_installed_toolkit_candidates();
    }

    let default_toolkit_root = default_toolkit_root.map(Path::to_path_buf);
    let default_toolkit_canonical_root = default_toolkit_root
        .as_deref()
        .and_then(|path| canonicalize_toolkit_root(path).ok());
    let mut candidates = collect_standard_cuda_install_root_candidates()?;
    if let Some(default_toolkit_root) = default_toolkit_root.filter(|path| path.exists()) {
        candidates.insert(default_toolkit_root);
    }

    let mut discovered = Vec::new();
    for candidate in candidates {
        let canonical_root = canonicalize_toolkit_root(&candidate)?;
        let version = if default_toolkit_canonical_root.as_ref() == Some(&canonical_root) {
            default_toolkit_version.cloned().ok_or_else(|| {
                CudaRuntimeExtensionError::new(
                    "cuda_installed_toolkit_inventory_collect",
                    format!(
                        "default CUDA toolkit root {} must carry a parsed default-toolkit version",
                        canonical_root.display()
                    ),
                )
            })?
        } else {
            probe_cuda_toolkit_version_for_root(&canonical_root)?
        };
        discovered.push(CudaDiscoveredToolkitCandidateV1 {
            install_root: canonical_root,
            version,
        });
    }

    Ok(discovered)
}

fn collect_stubbed_cuda_installed_toolkit_candidates(
) -> Result<Vec<CudaDiscoveredToolkitCandidateV1>, CudaRuntimeExtensionError> {
    let Some(raw_json) = env::var(TEST_CUDA_INSTALLED_TOOLKITS_JSON_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(Vec::new());
    };

    let entries: Vec<CudaStubInstalledToolkitProbeEntryV1> =
        serde_json::from_str(&raw_json).map_err(|error| {
            CudaRuntimeExtensionError::new(
                "cuda_installed_toolkit_inventory_collect",
                format!(
                    "failed to decode {TEST_CUDA_INSTALLED_TOOLKITS_JSON_ENV} as installed toolkit inventory JSON: {error}"
                ),
            )
        })?;

    let mut discovered = Vec::new();
    for entry in entries {
        let install_root = entry.install_root.trim();
        if install_root.is_empty() {
            return Err(CudaRuntimeExtensionError::new(
                "cuda_installed_toolkit_inventory_collect",
                format!(
                    "{TEST_CUDA_INSTALLED_TOOLKITS_JSON_ENV} must not contain blank install_root entries"
                ),
            ));
        }
        let version = parse_cuda_version_output(&entry.nvcc_version_output).map_err(|error| {
            CudaRuntimeExtensionError::new(
                "cuda_installed_toolkit_inventory_collect",
                format!(
                    "failed to parse installed CUDA toolkit version for {install_root}: {}",
                    error.message
                ),
            )
        })?;
        discovered.push(CudaDiscoveredToolkitCandidateV1 {
            install_root: PathBuf::from(install_root),
            version,
        });
    }
    Ok(discovered)
}

fn collect_standard_cuda_install_root_candidates(
) -> Result<BTreeSet<PathBuf>, CudaRuntimeExtensionError> {
    let mut roots = BTreeSet::new();
    let root = Path::new("/usr/local");
    let directory_entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(roots),
        Err(error) => {
            return Err(CudaRuntimeExtensionError::new(
                "cuda_installed_toolkit_inventory_collect",
                format!(
                    "failed to inspect standard CUDA install roots under {}: {error}",
                    root.display()
                ),
            ))
        }
    };

    for entry in directory_entries {
        let entry = entry.map_err(|error| {
            CudaRuntimeExtensionError::new(
                "cuda_installed_toolkit_inventory_collect",
                format!(
                    "failed to inspect standard CUDA install roots under {}: {error}",
                    root.display()
                ),
            )
        })?;
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        if file_name == "cuda" || file_name.starts_with("cuda-") {
            roots.insert(entry.path());
        }
    }

    Ok(roots)
}

fn infer_cuda_toolkit_root_from_nvcc_path(path: &Path) -> Option<PathBuf> {
    let parent = path.parent()?;
    if parent.file_name()? != "bin" {
        return None;
    }
    Some(parent.parent()?.to_path_buf())
}

fn probe_cuda_toolkit_version_for_root(
    install_root: &Path,
) -> Result<CudaRuntimeVersionV1, CudaRuntimeExtensionError> {
    let nvcc_path = install_root.join("bin").join("nvcc");
    if !nvcc_path.is_file() {
        return Err(CudaRuntimeExtensionError::new(
            "cuda_installed_toolkit_inventory_collect",
            format!(
                "discovered CUDA toolkit root {} does not contain bin/nvcc",
                install_root.display()
            ),
        ));
    }
    let version_output =
        collect_command_probe_output(&nvcc_path, &["--version"]).ok_or_else(|| {
            CudaRuntimeExtensionError::new(
                "cuda_installed_toolkit_inventory_collect",
                format!(
                    "discovered CUDA toolkit root {} did not yield a successful nvcc version probe",
                    install_root.display()
                ),
            )
        })?;
    parse_cuda_version_output(&version_output).map_err(|error| {
        CudaRuntimeExtensionError::new(
            "cuda_installed_toolkit_inventory_collect",
            format!(
                "failed to parse discovered CUDA toolkit version at {}: {}",
                install_root.display(),
                error.message
            ),
        )
    })
}

fn normalize_cuda_installed_toolkits(
    discovered: Vec<CudaDiscoveredToolkitCandidateV1>,
    default_toolkit_root: Option<&Path>,
) -> Result<Vec<CudaInstalledToolkitV1>, CudaRuntimeExtensionError> {
    let default_toolkit_root = default_toolkit_root
        .and_then(|path| canonicalize_toolkit_root(path).ok())
        .map(path_buf_to_utf8_string)
        .transpose()?;
    let mut normalized = BTreeMap::<String, CudaRuntimeVersionV1>::new();

    for candidate in discovered {
        let canonical_root = canonicalize_toolkit_root(&candidate.install_root)?;
        let canonical_root = path_buf_to_utf8_string(canonical_root)?;
        match normalized.get(&canonical_root) {
            Some(existing_version) if existing_version != &candidate.version => {
                return Err(CudaRuntimeExtensionError::new(
                    "cuda_installed_toolkit_inventory_normalize",
                    format!(
                        "canonical CUDA toolkit root {canonical_root} produced conflicting successful version claims"
                    ),
                ));
            }
            Some(_) => {}
            None => {
                normalized.insert(canonical_root, candidate.version);
            }
        }
    }

    let mut selected_count = 0usize;
    let mut installed_toolkits = Vec::new();
    for (install_root, version) in normalized {
        let selected_by_default_toolkit_view =
            default_toolkit_root.as_deref() == Some(install_root.as_str());
        if selected_by_default_toolkit_view {
            selected_count += 1;
        }
        installed_toolkits.push(CudaInstalledToolkitV1 {
            install_root,
            version,
            selected_by_default_toolkit_view,
        });
    }

    if selected_count > 1 {
        return Err(CudaRuntimeExtensionError::new(
            "cuda_installed_toolkit_inventory_normalize",
            "installed CUDA toolkit inventory may mark at most one selected default-toolkit entry",
        ));
    }

    Ok(installed_toolkits)
}

fn canonicalize_toolkit_root(path: &Path) -> Result<PathBuf, CudaRuntimeExtensionError> {
    if path.as_os_str().is_empty() || !path.is_absolute() {
        return Err(CudaRuntimeExtensionError::new(
            "cuda_installed_toolkit_inventory_normalize",
            format!(
                "discovered CUDA toolkit root {} must be an absolute non-blank path",
                path.display()
            ),
        ));
    }
    fs::canonicalize(path).map_err(|error| {
        CudaRuntimeExtensionError::new(
            "cuda_installed_toolkit_inventory_normalize",
            format!(
                "failed to canonicalize discovered CUDA toolkit root {}: {error}",
                path.display()
            ),
        )
    })
}

fn path_buf_to_utf8_string(path: PathBuf) -> Result<String, CudaRuntimeExtensionError> {
    path.into_os_string().into_string().map_err(|_| {
        CudaRuntimeExtensionError::new(
            "cuda_installed_toolkit_inventory_normalize",
            "CUDA toolkit install roots must be valid UTF-8",
        )
    })
}

fn collect_live_cuda_state_probe_output() -> (
    Option<String>,
    Option<String>,
    Option<ObservationLimitationReasonV1>,
) {
    if env::var_os(TEST_CUDA_STUB_LIVE_PROBES_ENV).is_some() {
        let probe_path = env::var(TEST_CUDA_NVIDIA_SMI_PATH_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty());
        let output = env::var(TEST_CUDA_NVIDIA_SMI_OUTPUT_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty());
        let missing_reason = if output.is_some() {
            None
        } else if probe_path.is_some() {
            Some(ObservationLimitationReasonV1::SourceError)
        } else {
            Some(ObservationLimitationReasonV1::SourceUnavailable)
        };
        return (probe_path, output, missing_reason);
    }

    let Some(executable_path) = find_executable_in_path("nvidia-smi") else {
        return (
            None,
            None,
            Some(ObservationLimitationReasonV1::SourceUnavailable),
        );
    };
    let probe_path = executable_path.display().to_string();
    let output = collect_command_probe_output(
        &executable_path,
        &[
            "--query-gpu=index,uuid,memory.total,memory.free,memory.used",
            "--format=csv,noheader,nounits",
        ],
    );
    let missing_reason = if output.is_some() {
        None
    } else {
        Some(ObservationLimitationReasonV1::SourceError)
    };
    (Some(probe_path), output, missing_reason)
}

fn select_driver_supported_cuda_version_with_fallback(
    probe_outputs: &CudaLiveDefaultViewProbeOutputsV1,
) -> Result<
    (
        Option<CudaRuntimeVersionV1>,
        CudaDefaultViewFieldDiagnosticV1,
    ),
    CudaRuntimeExtensionError,
> {
    let primary_version = probe_outputs
        .driver_supported_cuda_version
        .raw_version
        .map(|raw| parse_cuda_api_version_number(raw, "driver-supported CUDA"))
        .transpose()?
        .flatten();
    if let Some(version) = primary_version {
        return Ok((
            Some(version),
            CudaDefaultViewFieldDiagnosticV1 {
                source_tier: CudaDefaultViewProbeSourceTierV1::Primary,
                source_kind: CudaDefaultViewProbeSourceKindV1::DynamicLibraryProbe,
                source_ref: probe_outputs
                    .driver_supported_cuda_version
                    .source_ref
                    .clone(),
                status: CudaDefaultViewProbeStatusV1::Observed,
            },
        ));
    }

    let primary_diagnostic = CudaDefaultViewFieldDiagnosticV1 {
        source_tier: CudaDefaultViewProbeSourceTierV1::Primary,
        source_kind: CudaDefaultViewProbeSourceKindV1::DynamicLibraryProbe,
        source_ref: probe_outputs
            .driver_supported_cuda_version
            .source_ref
            .clone(),
        status: probe_outputs.driver_supported_cuda_version.status,
    };

    if probe_outputs.driver_supported_cuda_version.status == CudaDefaultViewProbeStatusV1::Observed
    {
        return Ok((None, primary_diagnostic));
    }

    let advisory_version = probe_outputs
        .advisory_driver_supported_cuda_version
        .output
        .as_deref()
        .and_then(|output| parse_nvidia_smi_banner_cuda_version(output).ok())
        .flatten();
    if let Some(version) = advisory_version {
        return Ok((
            Some(version),
            CudaDefaultViewFieldDiagnosticV1 {
                source_tier: CudaDefaultViewProbeSourceTierV1::AdvisoryFallback,
                source_kind: CudaDefaultViewProbeSourceKindV1::AdvisoryCommandProbe,
                source_ref: probe_outputs
                    .advisory_driver_supported_cuda_version
                    .source_ref
                    .clone(),
                status: CudaDefaultViewProbeStatusV1::Observed,
            },
        ));
    }

    Ok((None, primary_diagnostic))
}

fn collect_command_probe_output(path: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new(path).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !stdout.is_empty() {
        return Some(stdout);
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !stderr.is_empty() {
        Some(stderr)
    } else {
        None
    }
}

fn collect_command_probe_output_with_status(
    executable: &str,
    args: &[&str],
) -> CudaCommandProbeOutputV1 {
    let Some(path) = find_executable_in_path(executable) else {
        return CudaCommandProbeOutputV1 {
            source_ref: executable.to_string(),
            status: CudaDefaultViewProbeStatusV1::SourceUnavailable,
            output: None,
        };
    };
    let source_ref = path.display().to_string();
    let output = collect_command_probe_output(&path, args);
    let status = if output.is_some() {
        CudaDefaultViewProbeStatusV1::Observed
    } else {
        CudaDefaultViewProbeStatusV1::ProbeFailed
    };
    CudaCommandProbeOutputV1 {
        source_ref,
        status,
        output,
    }
}

fn collect_stubbed_command_probe_output(
    path_env: &str,
    output_env: &str,
    fallback_source_ref: &str,
) -> CudaCommandProbeOutputV1 {
    let path = env::var(path_env)
        .ok()
        .filter(|value| !value.trim().is_empty());
    let output = env::var(output_env)
        .ok()
        .filter(|value| !value.trim().is_empty());
    let status = if output.is_some() {
        CudaDefaultViewProbeStatusV1::Observed
    } else if path.is_some() {
        CudaDefaultViewProbeStatusV1::ProbeFailed
    } else {
        CudaDefaultViewProbeStatusV1::SourceUnavailable
    };
    CudaCommandProbeOutputV1 {
        source_ref: path.unwrap_or_else(|| fallback_source_ref.to_string()),
        status,
        output,
    }
}

fn collect_file_probe_output_with_status(path: &str) -> CudaFileProbeOutputV1 {
    match fs::read_to_string(path) {
        Ok(output) if !output.trim().is_empty() => CudaFileProbeOutputV1 {
            source_ref: path.to_string(),
            status: CudaDefaultViewProbeStatusV1::Observed,
            output: Some(output),
        },
        Ok(_) => CudaFileProbeOutputV1 {
            source_ref: path.to_string(),
            status: CudaDefaultViewProbeStatusV1::ProbeFailed,
            output: None,
        },
        Err(error) => CudaFileProbeOutputV1 {
            source_ref: path.to_string(),
            status: match error.kind() {
                std::io::ErrorKind::NotFound => CudaDefaultViewProbeStatusV1::SourceUnavailable,
                std::io::ErrorKind::PermissionDenied => {
                    CudaDefaultViewProbeStatusV1::SourceUnreadable
                }
                _ => CudaDefaultViewProbeStatusV1::ProbeFailed,
            },
            output: None,
        },
    }
}

fn collect_stubbed_file_probe_output(path_env: &str, source_ref: &str) -> CudaFileProbeOutputV1 {
    let output = env::var(path_env)
        .ok()
        .filter(|value| !value.trim().is_empty());
    let status = if output.is_some() {
        CudaDefaultViewProbeStatusV1::Observed
    } else {
        CudaDefaultViewProbeStatusV1::SourceUnavailable
    };
    CudaFileProbeOutputV1 {
        source_ref: source_ref.to_string(),
        status,
        output,
    }
}

fn probe_cuda_api_version_from_libraries_with_status(
    library_names: &[&str],
    symbol_name: &[u8],
) -> CudaLibraryProbeOutputV1 {
    let mut symbol_sources = Vec::new();
    let mut probe_failed_sources = Vec::new();

    for library_name in library_names {
        match probe_cuda_api_version_from_library_with_status(library_name, symbol_name) {
            CudaLibrarySingleProbeOutcomeV1::Observed(raw_version) => {
                return CudaLibraryProbeOutputV1 {
                    source_ref: (*library_name).to_string(),
                    status: CudaDefaultViewProbeStatusV1::Observed,
                    raw_version: Some(raw_version),
                };
            }
            CudaLibrarySingleProbeOutcomeV1::SymbolUnavailable => {
                symbol_sources.push((*library_name).to_string());
            }
            CudaLibrarySingleProbeOutcomeV1::ProbeFailed => {
                probe_failed_sources.push((*library_name).to_string());
            }
            CudaLibrarySingleProbeOutcomeV1::LibraryUnavailable => {}
        }
    }

    if !probe_failed_sources.is_empty() {
        return CudaLibraryProbeOutputV1 {
            source_ref: probe_failed_sources.join(", "),
            status: CudaDefaultViewProbeStatusV1::ProbeFailed,
            raw_version: None,
        };
    }
    if !symbol_sources.is_empty() {
        return CudaLibraryProbeOutputV1 {
            source_ref: symbol_sources.join(", "),
            status: CudaDefaultViewProbeStatusV1::SymbolUnavailable,
            raw_version: None,
        };
    }
    CudaLibraryProbeOutputV1 {
        source_ref: library_names.join(", "),
        status: CudaDefaultViewProbeStatusV1::LibraryUnavailable,
        raw_version: None,
    }
}

fn probe_cuda_api_version_from_owned_library_refs_with_status(
    library_refs: &[String],
    symbol_name: &[u8],
) -> CudaLibraryProbeOutputV1 {
    let mut symbol_sources = Vec::new();
    let mut probe_failed_sources = Vec::new();

    for library_ref in library_refs {
        match probe_cuda_api_version_from_library_with_status(library_ref, symbol_name) {
            CudaLibrarySingleProbeOutcomeV1::Observed(raw_version) => {
                return CudaLibraryProbeOutputV1 {
                    source_ref: library_ref.clone(),
                    status: CudaDefaultViewProbeStatusV1::Observed,
                    raw_version: Some(raw_version),
                };
            }
            CudaLibrarySingleProbeOutcomeV1::SymbolUnavailable => {
                symbol_sources.push(library_ref.clone());
            }
            CudaLibrarySingleProbeOutcomeV1::ProbeFailed => {
                probe_failed_sources.push(library_ref.clone());
            }
            CudaLibrarySingleProbeOutcomeV1::LibraryUnavailable => {}
        }
    }

    if !probe_failed_sources.is_empty() {
        return CudaLibraryProbeOutputV1 {
            source_ref: probe_failed_sources.join(", "),
            status: CudaDefaultViewProbeStatusV1::ProbeFailed,
            raw_version: None,
        };
    }
    if !symbol_sources.is_empty() {
        return CudaLibraryProbeOutputV1 {
            source_ref: symbol_sources.join(", "),
            status: CudaDefaultViewProbeStatusV1::SymbolUnavailable,
            raw_version: None,
        };
    }
    CudaLibraryProbeOutputV1 {
        source_ref: library_refs.join(", "),
        status: CudaDefaultViewProbeStatusV1::LibraryUnavailable,
        raw_version: None,
    }
}

fn collect_stubbed_library_probe_output(
    value_env: &str,
    library_names: &[&str],
) -> Result<CudaLibraryProbeOutputV1, CudaRuntimeExtensionError> {
    let raw_version = env::var(value_env)
        .ok()
        .map(|value| parse_cuda_probe_integer(&value, value_env))
        .transpose()?;
    let status = if raw_version.is_some() {
        CudaDefaultViewProbeStatusV1::Observed
    } else {
        CudaDefaultViewProbeStatusV1::LibraryUnavailable
    };
    Ok(CudaLibraryProbeOutputV1 {
        source_ref: if raw_version.is_some() {
            library_names
                .first()
                .copied()
                .unwrap_or("unknown_cuda_library")
                .to_string()
        } else {
            library_names.join(", ")
        },
        status,
        raw_version,
    })
}

enum CudaLibrarySingleProbeOutcomeV1 {
    Observed(i32),
    SymbolUnavailable,
    ProbeFailed,
    LibraryUnavailable,
}

fn probe_cuda_api_version_from_library_with_status(
    library_name: &str,
    symbol_name: &[u8],
) -> CudaLibrarySingleProbeOutcomeV1 {
    let Ok(library_name) = CString::new(library_name) else {
        return CudaLibrarySingleProbeOutcomeV1::LibraryUnavailable;
    };
    let library = unsafe { libc::dlopen(library_name.as_ptr(), libc::RTLD_LAZY) };
    if library.is_null() {
        return CudaLibrarySingleProbeOutcomeV1::LibraryUnavailable;
    }

    type VersionFn = unsafe extern "C" fn(*mut libc::c_int) -> libc::c_int;
    let symbol = unsafe { libc::dlsym(library, symbol_name.as_ptr().cast()) };
    if symbol.is_null() {
        unsafe {
            libc::dlclose(library);
        }
        return CudaLibrarySingleProbeOutcomeV1::SymbolUnavailable;
    }

    let function: VersionFn = unsafe { std::mem::transmute(symbol) };
    let mut version: libc::c_int = 0;
    let status = unsafe { function(&mut version as *mut libc::c_int) };
    unsafe {
        libc::dlclose(library);
    }
    if status != 0 || version <= 0 {
        return CudaLibrarySingleProbeOutcomeV1::ProbeFailed;
    }
    CudaLibrarySingleProbeOutcomeV1::Observed(version)
}

fn parse_cuda_runtime_state_probe_output(
    output: &str,
) -> Result<Vec<CudaRuntimeDeviceStateV1>, CudaRuntimeExtensionError> {
    let mut devices = Vec::new();

    for line in output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let columns = line.split(',').map(|part| part.trim()).collect::<Vec<_>>();
        if columns.len() != 5 {
            return Err(CudaRuntimeExtensionError::new(
                "cuda_used_memory_collect",
                format!("CUDA runtime state probe returned an unsupported row: {line}"),
            ));
        }
        let device_ordinal = columns[0].parse::<u32>().map_err(|error| {
            CudaRuntimeExtensionError::new(
                "cuda_used_memory_collect",
                format!(
                    "failed to parse CUDA device ordinal {}: {error}",
                    columns[0]
                ),
            )
        })?;
        let device_uuid = columns[1].to_string();
        if device_uuid.trim().is_empty() {
            return Err(CudaRuntimeExtensionError::new(
                "cuda_used_memory_collect",
                "CUDA runtime state probe returned a blank device UUID",
            ));
        }
        let total_memory_bytes = mib_to_bytes(columns[2])?;
        let allocatable_memory_bytes = mib_to_bytes(columns[3])?;
        let used_memory_bytes = mib_to_bytes(columns[4])?;
        if allocatable_memory_bytes > total_memory_bytes {
            return Err(CudaRuntimeExtensionError::new(
                "cuda_used_memory_collect",
                "CUDA runtime state probe reported allocatable memory above total memory",
            ));
        }
        if used_memory_bytes > total_memory_bytes {
            return Err(CudaRuntimeExtensionError::new(
                "cuda_used_memory_collect",
                "CUDA runtime state probe reported used memory above total memory",
            ));
        }
        if used_memory_bytes.saturating_add(allocatable_memory_bytes) > total_memory_bytes {
            return Err(CudaRuntimeExtensionError::new(
                "cuda_used_memory_collect",
                "CUDA runtime state probe reported inconsistent used and allocatable memory",
            ));
        }
        devices.push(CudaRuntimeDeviceStateV1 {
            device_ordinal,
            device_uuid,
            total_memory_bytes: observed_state_field(total_memory_bytes),
            allocatable_memory_bytes: observed_state_field(allocatable_memory_bytes),
            used_memory_bytes: observed_state_field(used_memory_bytes),
        });
    }

    devices.sort_by(|left, right| left.device_ordinal.cmp(&right.device_ordinal));

    Ok(devices)
}

fn parse_nvidia_smi_banner_cuda_version(
    output: &str,
) -> Result<Option<CudaRuntimeVersionV1>, CudaRuntimeExtensionError> {
    for line in output.lines() {
        let Some((_, suffix)) = line.split_once("CUDA Version:") else {
            continue;
        };
        let token = suffix
            .split(|character: char| {
                character.is_ascii_whitespace() || matches!(character, '|' | ',' | ';' | '(' | ')')
            })
            .find(|token| !token.trim().is_empty())
            .ok_or_else(|| {
                CudaRuntimeExtensionError::new(
                    "cuda_extension_collect",
                    "nvidia-smi banner did not contain a CUDA Version token",
                )
            })?;
        return parse_version_token(token).map(Some);
    }
    Ok(None)
}

fn validate_state_field_value<T>(
    field: &StateFieldV1<T>,
    field_name: &str,
    validate_value: impl FnOnce(&T) -> bool,
) -> Result<(), CudaRuntimeExtensionError> {
    validate_observation_field_coherence_v1(
        &field.state,
        field.limitation_reason.as_ref(),
        field.value.as_ref(),
        validate_value,
    )
    .map_err(|message| {
        CudaRuntimeExtensionError::new(
            "cuda_state_extension_validate",
            format!("CUDA runtime state field {field_name} {message}"),
        )
    })
}

fn validate_cuda_runtime_version_state_field(
    field: &StateFieldV1<CudaRuntimeVersionV1>,
    field_name: &str,
) -> Result<(), CudaRuntimeExtensionError> {
    validate_state_field_value(field, field_name, |value| validate_version(value).is_ok())
}

fn observed_state_field<T>(value: T) -> StateFieldV1<T> {
    StateFieldV1 {
        state: ObservationStateV1::Observed,
        limitation_reason: None,
        value: Some(value),
    }
}

fn version_state_field_from_optional(
    value: Option<CudaRuntimeVersionV1>,
) -> StateFieldV1<CudaRuntimeVersionV1> {
    value
        .map(observed_state_field)
        .unwrap_or_else(missing_cuda_runtime_version_state_field_v1)
}

fn cuda_runtime_version_state_field_is_observed(
    field: &StateFieldV1<CudaRuntimeVersionV1>,
) -> bool {
    matches!(
        (&field.state, field.value.as_ref()),
        (ObservationStateV1::Observed, Some(_)) | (ObservationStateV1::PartiallyObserved, Some(_))
    )
}

fn missing_state_field<T>() -> StateFieldV1<T> {
    StateFieldV1 {
        state: ObservationStateV1::Missing,
        limitation_reason: None,
        value: None,
    }
}

fn missing_cuda_runtime_version_state_field_v1() -> StateFieldV1<CudaRuntimeVersionV1> {
    missing_state_field()
}

fn missing_u64_state_field_v1() -> StateFieldV1<u64> {
    missing_state_field()
}

fn is_missing_cuda_runtime_version_state_field_v1(
    field: &StateFieldV1<CudaRuntimeVersionV1>,
) -> bool {
    matches!(field.state, ObservationStateV1::Missing)
        && field.limitation_reason.is_none()
        && field.value.is_none()
}

fn is_missing_u64_state_field_v1(field: &StateFieldV1<u64>) -> bool {
    matches!(field.state, ObservationStateV1::Missing)
        && field.limitation_reason.is_none()
        && field.value.is_none()
}

fn scalar_state_value<T: Copy>(field: &StateFieldV1<T>) -> Option<T> {
    match (&field.state, &field.value) {
        (ObservationStateV1::Observed, Some(value))
        | (ObservationStateV1::PartiallyObserved, Some(value)) => Some(*value),
        _ => None,
    }
}

fn mib_to_bytes(value: &str) -> Result<u64, CudaRuntimeExtensionError> {
    let value = value.parse::<u64>().map_err(|error| {
        CudaRuntimeExtensionError::new(
            "cuda_state_extension_collect",
            format!("failed to parse CUDA memory counter {value}: {error}"),
        )
    })?;
    Ok(value.saturating_mul(1024).saturating_mul(1024))
}

fn find_executable_in_path(executable: &str) -> Option<PathBuf> {
    let paths = env::var_os("PATH")?;
    env::split_paths(&paths)
        .map(|path| path.join(executable))
        .find(|candidate| candidate.is_file())
}

fn parse_cuda_probe_integer(
    value: &str,
    field_name: &str,
) -> Result<i32, CudaRuntimeExtensionError> {
    value.trim().parse::<i32>().map_err(|error| {
        CudaRuntimeExtensionError::new(
            "cuda_extension_collect",
            format!("failed to parse {field_name} probe integer {value}: {error}"),
        )
    })
}

fn parse_cuda_version_output(
    output: &str,
) -> Result<CudaRuntimeVersionV1, CudaRuntimeExtensionError> {
    let mut release_token: Option<&str> = None;
    let words = output.split_whitespace().collect::<Vec<_>>();

    for (index, word) in words.iter().enumerate() {
        let token = word.trim_matches(|value: char| {
            value.is_ascii_whitespace() || matches!(value, ',' | ';' | '(' | ')' | ':')
        });
        if token.is_empty() {
            continue;
        }
        if token.eq_ignore_ascii_case("release") {
            if let Some(candidate) = words.get(index + 1) {
                let trimmed = candidate.trim_matches(|value: char| {
                    value.is_ascii_whitespace() || matches!(value, ',' | ';' | '(' | ')' | ':')
                });
                if !trimmed.is_empty() {
                    release_token = Some(trimmed);
                }
            }
            continue;
        }
        if let Some(version_token) = token.strip_prefix('v').or_else(|| token.strip_prefix('V')) {
            if !version_token.is_empty() {
                return parse_version_token(version_token);
            }
        }
    }

    if let Some(version_token) = release_token {
        return parse_version_token(version_token);
    }

    Err(CudaRuntimeExtensionError::new(
        "cuda_extension_collect",
        format!("CUDA runtime probe produced an unsupported version string: {output}"),
    ))
}

fn parse_nvidia_driver_version_output(
    output: &str,
) -> Result<CudaRuntimeVersionV1, CudaRuntimeExtensionError> {
    for line in output.lines() {
        if line.contains("Kernel Module") || line.contains("NVRM version") {
            if let Some(token) = find_version_token_in_text(line) {
                return parse_version_token(token);
            }
        }
    }

    Err(CudaRuntimeExtensionError::new(
        "cuda_extension_collect",
        format!("CUDA driver version probe produced an unsupported string: {output}"),
    ))
}

fn find_version_token_in_text(text: &str) -> Option<&str> {
    text.split_whitespace().find_map(|token| {
        let trimmed = token.trim_matches(|character: char| {
            character.is_ascii_whitespace() || matches!(character, ',' | ';' | '(' | ')' | ':')
        });
        if trimmed.contains('.')
            && trimmed
                .chars()
                .all(|character| character.is_ascii_digit() || character == '.')
        {
            Some(trimmed)
        } else {
            None
        }
    })
}

fn parse_cuda_api_version_number(
    raw_version: i32,
    field_name: &str,
) -> Result<Option<CudaRuntimeVersionV1>, CudaRuntimeExtensionError> {
    if raw_version <= 0 {
        return Ok(None);
    }
    if raw_version < 1000 || raw_version % 10 != 0 {
        return Err(CudaRuntimeExtensionError::new(
            "cuda_extension_collect",
            format!("{field_name} probe returned unsupported version integer {raw_version}"),
        ));
    }

    let version = CudaRuntimeVersionV1 {
        major: (raw_version / 1000) as u32,
        minor: ((raw_version % 1000) / 10) as u32,
        patch: 0,
    };
    validate_version(&version)?;
    Ok(Some(version))
}

fn parse_version_token(token: &str) -> Result<CudaRuntimeVersionV1, CudaRuntimeExtensionError> {
    let mut parts = token.split('.');
    let major = parse_numeric_component(parts.next(), token)?;
    let minor = parse_numeric_component(parts.next(), token)?;
    let patch = match parts.next() {
        Some(value) => parse_numeric_component(Some(value), token)?,
        None => 0,
    };
    if parts.next().is_some() {
        return Err(CudaRuntimeExtensionError::new(
            "cuda_extension_collect",
            format!("CUDA runtime version string {token} contains too many components"),
        ));
    }
    Ok(CudaRuntimeVersionV1 {
        major,
        minor,
        patch,
    })
}

fn parse_numeric_component(
    value: Option<&str>,
    original: &str,
) -> Result<u32, CudaRuntimeExtensionError> {
    let value = value.ok_or_else(|| {
        CudaRuntimeExtensionError::new(
            "cuda_extension_collect",
            format!("CUDA runtime version string {original} is incomplete"),
        )
    })?;
    let digits = value
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .collect::<String>();
    if digits.is_empty() {
        return Err(CudaRuntimeExtensionError::new(
            "cuda_extension_collect",
            format!("CUDA runtime version component {value} is not numeric"),
        ));
    }
    digits.parse::<u32>().map_err(|error| {
        CudaRuntimeExtensionError::new(
            "cuda_extension_collect",
            format!("CUDA runtime version component {value} is invalid: {error}"),
        )
    })
}

fn compare_versions(left: &CudaRuntimeVersionV1, right: &CudaRuntimeVersionV1) -> Ordering {
    left.major
        .cmp(&right.major)
        .then_with(|| left.minor.cmp(&right.minor))
        .then_with(|| left.patch.cmp(&right.patch))
}

fn range_contains_version(
    range: &CudaRuntimeVersionRangeV1,
    version: &CudaRuntimeVersionV1,
) -> bool {
    if let Some(minimum) = range.minimum_inclusive.as_ref() {
        if compare_versions(version, minimum) == Ordering::Less {
            return false;
        }
    }
    if let Some(maximum) = range.maximum_exclusive.as_ref() {
        if compare_versions(version, maximum) != Ordering::Less {
            return false;
        }
    }
    true
}

fn format_version(version: &CudaRuntimeVersionV1) -> String {
    format!("{}.{}.{}", version.major, version.minor, version.patch)
}

fn format_version_range(range: &CudaRuntimeVersionRangeV1) -> String {
    match (&range.minimum_inclusive, &range.maximum_exclusive) {
        (Some(minimum), Some(maximum)) => {
            format!("[{}, {})", format_version(minimum), format_version(maximum))
        }
        (Some(minimum), None) => format!("[{}, +inf)", format_version(minimum)),
        (None, Some(maximum)) => format!("(-inf, {})", format_version(maximum)),
        (None, None) => "<invalid>".to_string(),
    }
}

fn format_bytes(bytes: u64) -> String {
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;

    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GiB", bytes as f64 / GIB)
    } else {
        format!("{:.2} MiB", bytes as f64 / MIB)
    }
}

fn deserialize_non_null_u64_opt_v1<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    match value {
        Value::Number(number) => number.as_u64().map(Some).ok_or_else(|| {
            serde::de::Error::custom("expected non-negative integer for optional u64 field")
        }),
        Value::Null => Err(serde::de::Error::custom(
            "explicit null is not allowed for optional u64 field",
        )),
        _ => Err(serde::de::Error::custom(
            "expected integer value for optional u64 field",
        )),
    }
}

fn deserialize_non_null_u32_opt_v1<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    match value {
        Value::Number(number) => number
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .map(Some)
            .ok_or_else(|| {
                serde::de::Error::custom("expected non-negative integer for optional u32 field")
            }),
        Value::Null => Err(serde::de::Error::custom(
            "explicit null is not allowed for optional u32 field",
        )),
        _ => Err(serde::de::Error::custom(
            "expected integer value for optional u32 field",
        )),
    }
}

fn deserialize_non_null_cuda_runtime_version_opt_v1<'de, D>(
    deserializer: D,
) -> Result<Option<CudaRuntimeVersionV1>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    match value {
        Value::Object(_) => serde_json::from_value(value)
            .map(Some)
            .map_err(serde::de::Error::custom),
        Value::Null => Err(serde::de::Error::custom(
            "explicit null is not allowed for optional CUDA runtime version field",
        )),
        _ => Err(serde::de::Error::custom(
            "expected object value for optional CUDA runtime version field",
        )),
    }
}

fn deserialize_non_null_cuda_default_view_probe_diagnostics_opt_v1<'de, D>(
    deserializer: D,
) -> Result<Option<CudaDefaultViewProbeDiagnosticsV1>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    match value {
        Value::Object(_) => serde_json::from_value(value)
            .map(Some)
            .map_err(serde::de::Error::custom),
        Value::Null => Err(serde::de::Error::custom(
            "explicit null is not allowed for optional CUDA default-view probe diagnostics",
        )),
        _ => Err(serde::de::Error::custom(
            "expected object value for optional CUDA default-view probe diagnostics",
        )),
    }
}

fn deserialize_non_null_cuda_selected_environment_probe_diagnostics_opt_v1<'de, D>(
    deserializer: D,
) -> Result<Option<CudaSelectedEnvironmentProbeDiagnosticsV1>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    match value {
        Value::Object(_) => serde_json::from_value(value)
            .map(Some)
            .map_err(serde::de::Error::custom),
        Value::Null => Err(serde::de::Error::custom(
            "explicit null is not allowed for optional CUDA selected-environment probe diagnostics",
        )),
        _ => Err(serde::de::Error::custom(
            "expected object value for optional CUDA selected-environment probe diagnostics",
        )),
    }
}

fn default_true() -> bool {
    true
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cuda_version_output_prefers_explicit_v_token() {
        let version = parse_cuda_version_output(
            "nvcc: NVIDIA (R) Cuda compiler driver\nCuda compilation tools, release 12.4, V12.4.131",
        )
        .expect("CUDA version output should decode");

        assert_eq!(
            version,
            CudaRuntimeVersionV1 {
                major: 12,
                minor: 4,
                patch: 131,
            }
        );
    }

    #[test]
    fn parse_cuda_version_output_accepts_release_token_without_patch() {
        let version = parse_cuda_version_output("Cuda compilation tools, release 12.2")
            .expect("release token without patch should decode");

        assert_eq!(
            version,
            CudaRuntimeVersionV1 {
                major: 12,
                minor: 2,
                patch: 0,
            }
        );
    }

    #[test]
    fn parse_nvidia_driver_version_output_decodes_kernel_module_line() {
        let version = parse_nvidia_driver_version_output(
            "NVRM version: NVIDIA UNIX x86_64 Kernel Module  550.54.14  Wed Feb 7 16:37:11 UTC 2024",
        )
        .expect("driver version output should decode");

        assert_eq!(
            version,
            CudaRuntimeVersionV1 {
                major: 550,
                minor: 54,
                patch: 14,
            }
        );
    }

    #[test]
    fn parse_cuda_api_version_number_decodes_major_minor_encoding() {
        let version = parse_cuda_api_version_number(12040, "driver-supported CUDA")
            .expect("version integer should decode")
            .expect("positive version should be observed");

        assert_eq!(
            version,
            CudaRuntimeVersionV1 {
                major: 12,
                minor: 4,
                patch: 0,
            }
        );
    }

    #[test]
    fn parse_cuda_api_version_number_rejects_non_multiple_of_ten() {
        let error = parse_cuda_api_version_number(12045, "default CUDA runtime")
            .expect_err("unsupported encoded version should fail");

        assert_eq!(error.checkpoint_id, "cuda_extension_collect");
        assert!(error.message.contains("unsupported version integer 12045"));
    }
}
