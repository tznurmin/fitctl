// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! CUDA runtime extension evidence, contract derivation, evaluation, and inspect helpers.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::artifacts::metadata_v1::{
    AssuranceSourceV1, ClaimMetadataV1, CollectorMetadataV1, DerivationStageV1,
};
use crate::artifacts::survey_v1::{
    decode_host_survey_payload, encode_host_survey_payload, HostSurveyV1,
};
use crate::redact::profile_v1::BuiltInRedactionProfileV1;

pub const CUDA_RUNTIME_NAMESPACE: &str = "org.example.runtime.cuda";
pub const CUDA_RUNTIME_EVIDENCE_SCHEMA_ID: &str =
    "fitctl.extension.org.example.runtime.cuda.evidence.v1";
pub const CUDA_RUNTIME_CONTRACT_SCHEMA_ID: &str =
    "fitctl.extension.org.example.runtime.cuda.contract.v1";
pub const CUDA_RUNTIME_REQUIREMENT_SCHEMA_ID: &str =
    "fitctl.extension.org.example.runtime.cuda.requirement.v1";

const CUDA_RUNTIME_COLLECTOR_ID: &str = "org.example.runtime.cuda.collector.v1";
const CUDA_RUNTIME_COLLECTOR_VERSION: &str = "1";
const CUDA_RUNTIME_LIVE_SOURCE_FAMILY: &str = "command_probe";
const CUDA_RUNTIME_REPLAY_SOURCE_FAMILY: &str = "fixture_replay";
const CUDA_RUNTIME_REPLAY_CORPUS_SCHEMA_ID: &str =
    "fitctl.fixture.extension.org.example.runtime.cuda.corpus.v1";
const CUDA_RUNTIME_REPLAY_SNAPSHOT_SCHEMA_ID: &str =
    "fitctl.fixture.extension.org.example.runtime.cuda.snapshot.v1";

const CUDA_EVIDENCE_PATH: &str = "$.survey.extension_evidence.org.example.runtime.cuda";
const CUDA_CONTRACT_PATH: &str = "$.contract.extension_contract.org.example.runtime.cuda";

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

pub fn apply_cuda_runtime_extension_to_survey_v1(
    mut survey: HostSurveyV1,
    replay_root: Option<&Path>,
) -> Result<HostSurveyV1, CudaRuntimeExtensionError> {
    let payload = decode_host_survey_payload(&survey.survey).map_err(|error| {
        CudaRuntimeExtensionError::new(
            "cuda_extension_normalize",
            format!("failed to decode host-survey payload for CUDA extension: {error}"),
        )
    })?;

    let evidence = match payload.collection_mode.as_str() {
        "live" => collect_live_cuda_runtime_evidence()?,
        "replay" => load_replay_cuda_runtime_evidence(
            replay_root.ok_or_else(|| {
                CudaRuntimeExtensionError::new(
                    "cuda_extension_collect",
                    "CUDA runtime replay collection requires an extension replay root",
                )
            })?,
            &payload.snapshot_id,
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
    include_executable_path: bool,
) -> String {
    match evidence.runtime_state {
        CudaRuntimeEvidenceStateV1::Observed => {
            let version = evidence
                .version
                .as_ref()
                .map(format_version)
                .unwrap_or_else(|| "<unknown>".to_string());
            if include_executable_path {
                match evidence.executable_path.as_deref() {
                    Some(path) => format!("{} {}; path {}", evidence.runtime_id, version, path),
                    None => format!("{} {}", evidence.runtime_id, version),
                }
            } else {
                format!("{} {}", evidence.runtime_id, version)
            }
        }
        CudaRuntimeEvidenceStateV1::NotFound => format!("{} not found", evidence.runtime_id),
    }
}

pub fn format_cuda_runtime_contract_for_inspect(contract: &CudaRuntimeContractV1) -> String {
    if contract.runtime_available {
        format!(
            "{} available; version {}",
            contract.runtime_id,
            contract
                .version
                .as_ref()
                .map(format_version)
                .unwrap_or_else(|| "<unknown>".to_string())
        )
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
    parts.join("; ")
}

pub fn redact_cuda_runtime_evidence_export_v1(
    evidence: &mut CudaRuntimeEvidenceV1,
    profile: BuiltInRedactionProfileV1,
) {
    if profile.applies_fleet_redactions() || profile.applies_auditor_redactions() {
        evidence.executable_path = None;
    }
}

fn collect_live_cuda_runtime_evidence() -> Result<CudaRuntimeEvidenceV1, CudaRuntimeExtensionError>
{
    let collector = CollectorMetadataV1 {
        collector_id: CUDA_RUNTIME_COLLECTOR_ID.to_string(),
        collector_version: CUDA_RUNTIME_COLLECTOR_VERSION.to_string(),
        source_family: CUDA_RUNTIME_LIVE_SOURCE_FAMILY.to_string(),
    };

    let Some(executable_path) = find_executable_in_path("nvcc") else {
        return Ok(CudaRuntimeEvidenceV1 {
            schema_id: CUDA_RUNTIME_EVIDENCE_SCHEMA_ID.to_string(),
            schema_version: 1,
            collector,
            claim_metadata: observed_claim_metadata(CUDA_EVIDENCE_PATH),
            runtime_id: "cuda".to_string(),
            runtime_state: CudaRuntimeEvidenceStateV1::NotFound,
            executable_path: None,
            version: None,
        });
    };

    let output = Command::new(&executable_path)
        .arg("--version")
        .output()
        .map_err(|error| {
            CudaRuntimeExtensionError::new(
                "cuda_extension_collect",
                format!(
                    "failed to execute CUDA runtime probe {} --version: {error}",
                    executable_path.display()
                ),
            )
        })?;
    if !output.status.success() {
        return Err(CudaRuntimeExtensionError::new(
            "cuda_extension_collect",
            format!(
                "CUDA runtime probe {} --version exited with status {}",
                executable_path.display(),
                output.status
            ),
        ));
    }

    let version_output = {
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !stdout.is_empty() {
            stdout
        } else {
            String::from_utf8_lossy(&output.stderr).trim().to_string()
        }
    };
    let version = parse_cuda_version_output(&version_output)?;

    Ok(CudaRuntimeEvidenceV1 {
        schema_id: CUDA_RUNTIME_EVIDENCE_SCHEMA_ID.to_string(),
        schema_version: 1,
        collector,
        claim_metadata: observed_claim_metadata(CUDA_EVIDENCE_PATH),
        runtime_id: "cuda".to_string(),
        runtime_state: CudaRuntimeEvidenceStateV1::Observed,
        executable_path: Some(executable_path.display().to_string()),
        version: Some(version),
    })
}

fn load_replay_cuda_runtime_evidence(
    root: &Path,
    fixture_id: &str,
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
    validate_cuda_runtime_evidence(&snapshot.evidence)?;

    Ok(snapshot.evidence)
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

fn observed_claim_metadata(evidence_path: &str) -> ClaimMetadataV1 {
    ClaimMetadataV1 {
        assurance_source: AssuranceSourceV1::SelfObserved,
        derivation_stage: DerivationStageV1::Normalized,
        source_collectors: vec![CUDA_RUNTIME_COLLECTOR_ID.to_string()],
        evidence_paths: vec![evidence_path.to_string()],
        policy_rule_id: None,
        trust_evidence_refs: Vec::new(),
    }
}

fn find_executable_in_path(executable: &str) -> Option<PathBuf> {
    let paths = env::var_os("PATH")?;
    env::split_paths(&paths)
        .map(|path| path.join(executable))
        .find(|candidate| candidate.is_file())
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

fn default_true() -> bool {
    true
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
}
