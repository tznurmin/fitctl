// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Python runtime extension evidence, contract derivation, evaluation, and inspect helpers.

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

pub const PYTHON_RUNTIME_NAMESPACE: &str = "org.example.runtime.python";
pub const PYTHON_RUNTIME_EVIDENCE_SCHEMA_ID: &str =
    "fitctl.extension.org.example.runtime.python.evidence.v1";
pub const PYTHON_RUNTIME_CONTRACT_SCHEMA_ID: &str =
    "fitctl.extension.org.example.runtime.python.contract.v1";
pub const PYTHON_RUNTIME_REQUIREMENT_SCHEMA_ID: &str =
    "fitctl.extension.org.example.runtime.python.requirement.v1";

const PYTHON_RUNTIME_COLLECTOR_ID: &str = "org.example.runtime.python.collector.v1";
const PYTHON_RUNTIME_COLLECTOR_VERSION: &str = "1";
const PYTHON_RUNTIME_LIVE_SOURCE_FAMILY: &str = "command_probe";
const PYTHON_RUNTIME_REPLAY_SOURCE_FAMILY: &str = "fixture_replay";
const PYTHON_RUNTIME_REPLAY_CORPUS_SCHEMA_ID: &str =
    "fitctl.fixture.extension.org.example.runtime.python.corpus.v1";
const PYTHON_RUNTIME_REPLAY_SNAPSHOT_SCHEMA_ID: &str =
    "fitctl.fixture.extension.org.example.runtime.python.snapshot.v1";

const PYTHON_EVIDENCE_PATH: &str = "$.survey.extension_evidence.org.example.runtime.python";
const PYTHON_CONTRACT_PATH: &str = "$.contract.extension_contract.org.example.runtime.python";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonRuntimeExtensionError {
    pub checkpoint_id: &'static str,
    pub message: String,
}

impl PythonRuntimeExtensionError {
    fn new(checkpoint_id: &'static str, message: impl Into<String>) -> Self {
        Self {
            checkpoint_id,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for PythonRuntimeExtensionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} [fitctl.python_runtime_extension.v1 at {}]",
            self.message, self.checkpoint_id
        )
    }
}

impl std::error::Error for PythonRuntimeExtensionError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PythonRuntimeEvidenceStateV1 {
    Observed,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PythonRuntimeVersionV1 {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PythonRuntimeVersionRangeV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_inclusive: Option<PythonRuntimeVersionV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_exclusive: Option<PythonRuntimeVersionV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PythonRuntimeEvidenceV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub collector: CollectorMetadataV1,
    pub claim_metadata: ClaimMetadataV1,
    pub runtime_id: String,
    pub runtime_state: PythonRuntimeEvidenceStateV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<PythonRuntimeVersionV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PythonRuntimeContractV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub claim_metadata: ClaimMetadataV1,
    pub runtime_id: String,
    pub runtime_available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<PythonRuntimeVersionV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PythonRuntimeRequirementV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub required_runtime: String,
    #[serde(default = "default_true")]
    pub require_presence: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_version: Option<PythonRuntimeVersionV1>,
    #[serde(default)]
    pub accepted_version_ranges: Vec<PythonRuntimeVersionRangeV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PythonRuntimeReplayCorpusV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub namespace: String,
    pub fixtures: Vec<PythonRuntimeReplayFixtureEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PythonRuntimeReplayFixtureEntryV1 {
    pub fixture_id: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PythonRuntimeReplayFixtureSnapshotV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub fixture_id: String,
    pub namespace: String,
    pub evidence: PythonRuntimeEvidenceV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PythonRuntimeEvaluationOutcomeV1 {
    Satisfied,
    Unsatisfied { summary: String },
}

pub fn decode_python_runtime_evidence_from_value(
    value: &Value,
) -> Result<PythonRuntimeEvidenceV1, PythonRuntimeExtensionError> {
    let evidence: PythonRuntimeEvidenceV1 =
        serde_json::from_value(value.clone()).map_err(|error| {
            PythonRuntimeExtensionError::new(
                "python_extension_normalize",
                format!("failed to decode Python runtime extension evidence: {error}"),
            )
        })?;
    validate_python_runtime_evidence(&evidence)?;
    Ok(evidence)
}

pub fn decode_python_runtime_contract_from_value(
    value: &Value,
) -> Result<PythonRuntimeContractV1, PythonRuntimeExtensionError> {
    let contract: PythonRuntimeContractV1 =
        serde_json::from_value(value.clone()).map_err(|error| {
            PythonRuntimeExtensionError::new(
                "python_extension_contract_derive",
                format!("failed to decode Python runtime extension contract: {error}"),
            )
        })?;
    validate_python_runtime_contract(&contract)?;
    Ok(contract)
}

pub fn decode_python_runtime_requirement_from_value(
    value: &Value,
) -> Result<PythonRuntimeRequirementV1, PythonRuntimeExtensionError> {
    let requirement: PythonRuntimeRequirementV1 =
        serde_json::from_value(value.clone()).map_err(|error| {
            PythonRuntimeExtensionError::new(
                "python_extension_validate",
                format!("failed to decode Python runtime extension requirement: {error}"),
            )
        })?;
    validate_python_runtime_requirement(&requirement)?;
    Ok(requirement)
}

pub fn apply_python_runtime_extension_to_survey_v1(
    mut survey: HostSurveyV1,
    replay_root: Option<&Path>,
) -> Result<HostSurveyV1, PythonRuntimeExtensionError> {
    let payload = decode_host_survey_payload(&survey.survey).map_err(|error| {
        PythonRuntimeExtensionError::new(
            "python_extension_normalize",
            format!("failed to decode host-survey payload for Python extension: {error}"),
        )
    })?;

    let evidence = match payload.collection_mode.as_str() {
        "live" => collect_live_python_runtime_evidence()?,
        "replay" => load_replay_python_runtime_evidence(
            replay_root.ok_or_else(|| {
                PythonRuntimeExtensionError::new(
                    "python_extension_collect",
                    "Python runtime replay collection requires an extension replay root",
                )
            })?,
            &payload.snapshot_id,
        )?,
        unknown => {
            return Err(PythonRuntimeExtensionError::new(
                "python_extension_collect",
                format!(
                    "unsupported survey collection mode {unknown} for Python runtime extension"
                ),
            ))
        }
    };

    let mut payload = payload;
    payload.extension_evidence.insert(
        PYTHON_RUNTIME_NAMESPACE.to_string(),
        serde_json::to_value(&evidence).map_err(|error| {
            PythonRuntimeExtensionError::new(
                "python_extension_normalize",
                format!("failed to encode Python runtime extension evidence: {error}"),
            )
        })?,
    );
    survey.survey = encode_host_survey_payload(&payload).map_err(|error| {
        PythonRuntimeExtensionError::new(
            "python_extension_normalize",
            format!("failed to encode host-survey payload for Python extension: {error}"),
        )
    })?;

    Ok(survey)
}

pub fn derive_python_runtime_contract_value_from_survey_v1(
    survey: &HostSurveyV1,
) -> Result<Option<Value>, PythonRuntimeExtensionError> {
    let payload = decode_host_survey_payload(&survey.survey).map_err(|error| {
        PythonRuntimeExtensionError::new(
            "python_extension_contract_derive",
            format!(
                "failed to decode host-survey payload for Python runtime contract derivation: {error}"
            ),
        )
    })?;
    let Some(value) = payload.extension_evidence.get(PYTHON_RUNTIME_NAMESPACE) else {
        return Ok(None);
    };
    let evidence = decode_python_runtime_evidence_from_value(value)?;
    let contract = derive_python_runtime_contract_from_evidence(&evidence);
    Ok(Some(serde_json::to_value(contract).map_err(|error| {
        PythonRuntimeExtensionError::new(
            "python_extension_contract_derive",
            format!("failed to encode Python runtime extension contract: {error}"),
        )
    })?))
}

pub fn evaluate_python_runtime_requirement_v1(
    contract: &PythonRuntimeContractV1,
    requirement: &PythonRuntimeRequirementV1,
) -> Result<PythonRuntimeEvaluationOutcomeV1, PythonRuntimeExtensionError> {
    validate_python_runtime_contract(contract)?;
    validate_python_runtime_requirement(requirement)?;

    if contract.runtime_id != requirement.required_runtime {
        return Err(PythonRuntimeExtensionError::new(
            "python_extension_validate",
            "Python runtime contract and requirement use different runtime ids",
        ));
    }

    if !contract.runtime_available {
        return Ok(PythonRuntimeEvaluationOutcomeV1::Unsatisfied {
            summary: format!(
                "{} is required by the service profile but the contract records it as unavailable",
                requirement.required_runtime
            ),
        });
    }

    let version = contract.version.as_ref().ok_or_else(|| {
        PythonRuntimeExtensionError::new(
            "python_extension_validate",
            "Python runtime contract must carry a parsed version when runtime_available is true",
        )
    })?;

    if let Some(minimum_version) = requirement.minimum_version.as_ref() {
        if compare_versions(version, minimum_version) == Ordering::Less {
            return Ok(PythonRuntimeEvaluationOutcomeV1::Unsatisfied {
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
        return Ok(PythonRuntimeEvaluationOutcomeV1::Unsatisfied {
            summary: format!(
                "{} version {} is outside the accepted version ranges",
                requirement.required_runtime,
                format_version(version)
            ),
        });
    }

    Ok(PythonRuntimeEvaluationOutcomeV1::Satisfied)
}

pub fn format_python_runtime_evidence_for_inspect(
    evidence: &PythonRuntimeEvidenceV1,
    include_executable_path: bool,
) -> String {
    match evidence.runtime_state {
        PythonRuntimeEvidenceStateV1::Observed => {
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
        PythonRuntimeEvidenceStateV1::NotFound => {
            format!("{} not found", evidence.runtime_id)
        }
    }
}

pub fn format_python_runtime_contract_for_inspect(contract: &PythonRuntimeContractV1) -> String {
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

pub fn format_python_runtime_requirement_for_inspect(
    requirement: &PythonRuntimeRequirementV1,
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

pub fn redact_python_runtime_evidence_export_v1(
    evidence: &mut PythonRuntimeEvidenceV1,
    profile: BuiltInRedactionProfileV1,
) {
    if profile.applies_fleet_redactions() || profile.applies_auditor_redactions() {
        evidence.executable_path = None;
    }
}

fn collect_live_python_runtime_evidence(
) -> Result<PythonRuntimeEvidenceV1, PythonRuntimeExtensionError> {
    let collector = CollectorMetadataV1 {
        collector_id: PYTHON_RUNTIME_COLLECTOR_ID.to_string(),
        collector_version: PYTHON_RUNTIME_COLLECTOR_VERSION.to_string(),
        source_family: PYTHON_RUNTIME_LIVE_SOURCE_FAMILY.to_string(),
    };

    let Some(executable_path) = find_executable_in_path("python3") else {
        return Ok(PythonRuntimeEvidenceV1 {
            schema_id: PYTHON_RUNTIME_EVIDENCE_SCHEMA_ID.to_string(),
            schema_version: 1,
            collector,
            claim_metadata: observed_claim_metadata(PYTHON_EVIDENCE_PATH),
            runtime_id: "python3".to_string(),
            runtime_state: PythonRuntimeEvidenceStateV1::NotFound,
            executable_path: None,
            version: None,
        });
    };

    let output = Command::new(&executable_path)
        .arg("--version")
        .output()
        .map_err(|error| {
            PythonRuntimeExtensionError::new(
                "python_extension_collect",
                format!(
                    "failed to execute Python runtime probe {} --version: {error}",
                    executable_path.display()
                ),
            )
        })?;
    if !output.status.success() {
        return Err(PythonRuntimeExtensionError::new(
            "python_extension_collect",
            format!(
                "Python runtime probe {} --version exited with status {}",
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
    let version = parse_python_version_output(&version_output)?;

    Ok(PythonRuntimeEvidenceV1 {
        schema_id: PYTHON_RUNTIME_EVIDENCE_SCHEMA_ID.to_string(),
        schema_version: 1,
        collector,
        claim_metadata: observed_claim_metadata(PYTHON_EVIDENCE_PATH),
        runtime_id: "python3".to_string(),
        runtime_state: PythonRuntimeEvidenceStateV1::Observed,
        executable_path: Some(executable_path.display().to_string()),
        version: Some(version),
    })
}

fn load_replay_python_runtime_evidence(
    root: &Path,
    fixture_id: &str,
) -> Result<PythonRuntimeEvidenceV1, PythonRuntimeExtensionError> {
    let manifest_path = root.join("manifest.v1.json");
    let manifest_text = fs::read_to_string(&manifest_path).map_err(|error| {
        PythonRuntimeExtensionError::new(
            "python_extension_collect",
            format!(
                "failed to read Python runtime replay manifest {}: {error}",
                manifest_path.display()
            ),
        )
    })?;
    let manifest: PythonRuntimeReplayCorpusV1 =
        serde_json::from_str(&manifest_text).map_err(|error| {
            PythonRuntimeExtensionError::new(
                "python_extension_collect",
                format!(
                    "failed to decode Python runtime replay manifest {}: {error}",
                    manifest_path.display()
                ),
            )
        })?;
    validate_python_runtime_replay_manifest(&manifest)?;

    let entry = manifest
        .fixtures
        .iter()
        .find(|entry| entry.fixture_id == fixture_id)
        .ok_or_else(|| {
            PythonRuntimeExtensionError::new(
                "python_extension_collect",
                format!("Python runtime replay corpus does not contain fixture id {fixture_id}"),
            )
        })?;
    let fixture_path = resolve_replay_fixture_path(root, &entry.path)?;
    let fixture_text = fs::read_to_string(&fixture_path).map_err(|error| {
        PythonRuntimeExtensionError::new(
            "python_extension_collect",
            format!(
                "failed to read Python runtime replay fixture {}: {error}",
                fixture_path.display()
            ),
        )
    })?;
    let snapshot: PythonRuntimeReplayFixtureSnapshotV1 = serde_json::from_str(&fixture_text)
        .map_err(|error| {
            PythonRuntimeExtensionError::new(
                "python_extension_collect",
                format!(
                    "failed to decode Python runtime replay fixture {}: {error}",
                    fixture_path.display()
                ),
            )
        })?;

    if snapshot.schema_id != PYTHON_RUNTIME_REPLAY_SNAPSHOT_SCHEMA_ID
        || snapshot.schema_version != 1
        || snapshot.fixture_id != fixture_id
        || snapshot.namespace != PYTHON_RUNTIME_NAMESPACE
    {
        return Err(PythonRuntimeExtensionError::new(
            "python_extension_collect",
            "Python runtime replay fixture must declare the supported schema, namespace, and fixture id",
        ));
    }
    validate_python_runtime_evidence(&snapshot.evidence)?;

    Ok(snapshot.evidence)
}

fn derive_python_runtime_contract_from_evidence(
    evidence: &PythonRuntimeEvidenceV1,
) -> PythonRuntimeContractV1 {
    PythonRuntimeContractV1 {
        schema_id: PYTHON_RUNTIME_CONTRACT_SCHEMA_ID.to_string(),
        schema_version: 1,
        claim_metadata: ClaimMetadataV1 {
            assurance_source: AssuranceSourceV1::SelfObserved,
            derivation_stage: DerivationStageV1::Derived,
            source_collectors: vec![evidence.collector.collector_id.clone()],
            evidence_paths: vec![
                PYTHON_CONTRACT_PATH.to_string(),
                PYTHON_EVIDENCE_PATH.to_string(),
            ],
            policy_rule_id: None,
            trust_evidence_refs: Vec::new(),
        },
        runtime_id: evidence.runtime_id.clone(),
        runtime_available: matches!(
            evidence.runtime_state,
            PythonRuntimeEvidenceStateV1::Observed
        ),
        version: evidence.version.clone(),
    }
}

fn validate_python_runtime_evidence(
    evidence: &PythonRuntimeEvidenceV1,
) -> Result<(), PythonRuntimeExtensionError> {
    if evidence.schema_id != PYTHON_RUNTIME_EVIDENCE_SCHEMA_ID
        || evidence.schema_version != 1
        || evidence.runtime_id != "python3"
    {
        return Err(PythonRuntimeExtensionError::new(
            "python_extension_normalize",
            "Python runtime extension evidence must declare the supported schema and runtime id",
        ));
    }
    validate_collector(&evidence.collector)?;
    validate_claim_metadata(&evidence.claim_metadata)?;

    match evidence.runtime_state {
        PythonRuntimeEvidenceStateV1::Observed => {
            if evidence
                .executable_path
                .as_deref()
                .is_some_and(|value| value.trim().is_empty())
            {
                return Err(PythonRuntimeExtensionError::new(
                    "python_extension_normalize",
                    "observed Python runtime evidence executable_path must be non-blank when present",
                ));
            }
            validate_version(evidence.version.as_ref().ok_or_else(|| {
                PythonRuntimeExtensionError::new(
                    "python_extension_normalize",
                    "observed Python runtime evidence must include a parsed version",
                )
            })?)?;
        }
        PythonRuntimeEvidenceStateV1::NotFound => {
            if evidence.executable_path.is_some() || evidence.version.is_some() {
                return Err(PythonRuntimeExtensionError::new(
                    "python_extension_normalize",
                    "not_found Python runtime evidence must not include executable_path or version",
                ));
            }
        }
    }

    Ok(())
}

fn validate_python_runtime_contract(
    contract: &PythonRuntimeContractV1,
) -> Result<(), PythonRuntimeExtensionError> {
    if contract.schema_id != PYTHON_RUNTIME_CONTRACT_SCHEMA_ID
        || contract.schema_version != 1
        || contract.runtime_id != "python3"
    {
        return Err(PythonRuntimeExtensionError::new(
            "python_extension_contract_derive",
            "Python runtime extension contract must declare the supported schema and runtime id",
        ));
    }
    validate_claim_metadata(&contract.claim_metadata)?;
    if contract.runtime_available {
        validate_version(contract.version.as_ref().ok_or_else(|| {
            PythonRuntimeExtensionError::new(
                "python_extension_contract_derive",
                "available Python runtime contract must include a parsed version",
            )
        })?)?;
    } else if contract.version.is_some() {
        return Err(PythonRuntimeExtensionError::new(
            "python_extension_contract_derive",
            "unavailable Python runtime contract must not include a version",
        ));
    }
    Ok(())
}

fn validate_python_runtime_requirement(
    requirement: &PythonRuntimeRequirementV1,
) -> Result<(), PythonRuntimeExtensionError> {
    if requirement.schema_id != PYTHON_RUNTIME_REQUIREMENT_SCHEMA_ID
        || requirement.schema_version != 1
        || requirement.required_runtime != "python3"
    {
        return Err(PythonRuntimeExtensionError::new(
            "python_extension_validate",
            "Python runtime extension requirement must declare the supported schema and runtime id",
        ));
    }
    if !requirement.require_presence
        && requirement.minimum_version.is_none()
        && requirement.accepted_version_ranges.is_empty()
    {
        return Err(PythonRuntimeExtensionError::new(
            "python_extension_validate",
            "Python runtime extension requirement must declare at least one effective constraint",
        ));
    }
    if let Some(minimum_version) = requirement.minimum_version.as_ref() {
        validate_version(minimum_version)?;
    }
    for range in &requirement.accepted_version_ranges {
        if range.minimum_inclusive.is_none() && range.maximum_exclusive.is_none() {
            return Err(PythonRuntimeExtensionError::new(
                "python_extension_validate",
                "Python runtime accepted version ranges must set at least one bound",
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
                return Err(PythonRuntimeExtensionError::new(
                    "python_extension_validate",
                    "Python runtime accepted version ranges must have minimum_inclusive < maximum_exclusive",
                ));
            }
        }
    }
    Ok(())
}

fn validate_collector(collector: &CollectorMetadataV1) -> Result<(), PythonRuntimeExtensionError> {
    if collector.collector_id != PYTHON_RUNTIME_COLLECTOR_ID
        || collector.collector_version != PYTHON_RUNTIME_COLLECTOR_VERSION
        || !matches!(
            collector.source_family.as_str(),
            PYTHON_RUNTIME_LIVE_SOURCE_FAMILY | PYTHON_RUNTIME_REPLAY_SOURCE_FAMILY
        )
    {
        return Err(PythonRuntimeExtensionError::new(
            "python_extension_normalize",
            "Python runtime collector metadata contains an unsupported collector tuple",
        ));
    }
    Ok(())
}

fn validate_claim_metadata(metadata: &ClaimMetadataV1) -> Result<(), PythonRuntimeExtensionError> {
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
        return Err(PythonRuntimeExtensionError::new(
            "python_extension_normalize",
            "Python runtime claim metadata must remain fully populated and non-blank",
        ));
    }
    Ok(())
}

fn validate_version(version: &PythonRuntimeVersionV1) -> Result<(), PythonRuntimeExtensionError> {
    if version.major == 0 {
        return Err(PythonRuntimeExtensionError::new(
            "python_extension_validate",
            "Python runtime versions must use a positive major version",
        ));
    }
    Ok(())
}

fn validate_python_runtime_replay_manifest(
    manifest: &PythonRuntimeReplayCorpusV1,
) -> Result<(), PythonRuntimeExtensionError> {
    if manifest.schema_id != PYTHON_RUNTIME_REPLAY_CORPUS_SCHEMA_ID
        || manifest.schema_version != 1
        || manifest.namespace != PYTHON_RUNTIME_NAMESPACE
        || manifest.fixtures.is_empty()
    {
        return Err(PythonRuntimeExtensionError::new(
            "python_extension_collect",
            "Python runtime replay manifest must declare the supported schema, namespace, and fixtures",
        ));
    }

    let mut ids = BTreeSet::new();
    for fixture in &manifest.fixtures {
        if fixture.fixture_id.trim().is_empty()
            || fixture.path.trim().is_empty()
            || Path::new(&fixture.path).is_absolute()
            || !ids.insert(fixture.fixture_id.clone())
        {
            return Err(PythonRuntimeExtensionError::new(
                "python_extension_collect",
                "Python runtime replay manifest contains duplicate ids or invalid paths",
            ));
        }
    }

    Ok(())
}

fn resolve_replay_fixture_path(
    root: &Path,
    relative_path: &str,
) -> Result<PathBuf, PythonRuntimeExtensionError> {
    let canonical_root = fs::canonicalize(root).map_err(|error| {
        PythonRuntimeExtensionError::new(
            "python_extension_collect",
            format!(
                "failed to resolve Python runtime replay root {}: {error}",
                root.display()
            ),
        )
    })?;
    let candidate = canonical_root.join(relative_path);
    let canonical_candidate = fs::canonicalize(&candidate).map_err(|error| {
        PythonRuntimeExtensionError::new(
            "python_extension_collect",
            format!(
                "failed to resolve Python runtime replay fixture {}: {error}",
                candidate.display()
            ),
        )
    })?;
    if !canonical_candidate.starts_with(&canonical_root) {
        return Err(PythonRuntimeExtensionError::new(
            "python_extension_collect",
            "Python runtime replay fixture path escapes the selected root",
        ));
    }
    Ok(canonical_candidate)
}

fn observed_claim_metadata(evidence_path: &str) -> ClaimMetadataV1 {
    ClaimMetadataV1 {
        assurance_source: AssuranceSourceV1::SelfObserved,
        derivation_stage: DerivationStageV1::Normalized,
        source_collectors: vec![PYTHON_RUNTIME_COLLECTOR_ID.to_string()],
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

fn parse_python_version_output(
    output: &str,
) -> Result<PythonRuntimeVersionV1, PythonRuntimeExtensionError> {
    let version_token = output
        .split_whitespace()
        .find(|token| {
            token
                .chars()
                .next()
                .is_some_and(|value| value.is_ascii_digit())
        })
        .ok_or_else(|| {
            PythonRuntimeExtensionError::new(
                "python_extension_collect",
                format!("Python runtime probe produced an unsupported version string: {output}"),
            )
        })?;
    parse_version_token(version_token)
}

fn parse_version_token(token: &str) -> Result<PythonRuntimeVersionV1, PythonRuntimeExtensionError> {
    let mut parts = token.split('.');
    let major = parse_numeric_component(parts.next(), token)?;
    let minor = parse_numeric_component(parts.next(), token)?;
    let patch = parse_numeric_component(parts.next(), token)?;
    Ok(PythonRuntimeVersionV1 {
        major,
        minor,
        patch,
    })
}

fn parse_numeric_component(
    value: Option<&str>,
    original: &str,
) -> Result<u32, PythonRuntimeExtensionError> {
    let value = value.ok_or_else(|| {
        PythonRuntimeExtensionError::new(
            "python_extension_collect",
            format!("Python runtime version string {original} is incomplete"),
        )
    })?;
    let digits = value
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .collect::<String>();
    if digits.is_empty() {
        return Err(PythonRuntimeExtensionError::new(
            "python_extension_collect",
            format!("Python runtime version component {value} is not numeric"),
        ));
    }
    digits.parse::<u32>().map_err(|error| {
        PythonRuntimeExtensionError::new(
            "python_extension_collect",
            format!("Python runtime version component {value} is invalid: {error}"),
        )
    })
}

fn compare_versions(left: &PythonRuntimeVersionV1, right: &PythonRuntimeVersionV1) -> Ordering {
    left.major
        .cmp(&right.major)
        .then_with(|| left.minor.cmp(&right.minor))
        .then_with(|| left.patch.cmp(&right.patch))
}

fn range_contains_version(
    range: &PythonRuntimeVersionRangeV1,
    version: &PythonRuntimeVersionV1,
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

fn format_version(version: &PythonRuntimeVersionV1) -> String {
    format!("{}.{}.{}", version.major, version.minor, version.patch)
}

fn format_version_range(range: &PythonRuntimeVersionRangeV1) -> String {
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
