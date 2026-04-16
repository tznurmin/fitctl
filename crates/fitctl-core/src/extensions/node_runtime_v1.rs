// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Node.js runtime extension evidence, contract derivation, evaluation, and inspect helpers.

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

pub const NODE_RUNTIME_NAMESPACE: &str = "org.example.runtime.node";
pub const NODE_RUNTIME_EVIDENCE_SCHEMA_ID: &str =
    "fitctl.extension.org.example.runtime.node.evidence.v1";
pub const NODE_RUNTIME_CONTRACT_SCHEMA_ID: &str =
    "fitctl.extension.org.example.runtime.node.contract.v1";
pub const NODE_RUNTIME_REQUIREMENT_SCHEMA_ID: &str =
    "fitctl.extension.org.example.runtime.node.requirement.v1";

const NODE_RUNTIME_COLLECTOR_ID: &str = "org.example.runtime.node.collector.v1";
const NODE_RUNTIME_COLLECTOR_VERSION: &str = "1";
const NODE_RUNTIME_LIVE_SOURCE_FAMILY: &str = "command_probe";
const NODE_RUNTIME_REPLAY_SOURCE_FAMILY: &str = "fixture_replay";
const NODE_RUNTIME_REPLAY_CORPUS_SCHEMA_ID: &str =
    "fitctl.fixture.extension.org.example.runtime.node.corpus.v1";
const NODE_RUNTIME_REPLAY_SNAPSHOT_SCHEMA_ID: &str =
    "fitctl.fixture.extension.org.example.runtime.node.snapshot.v1";

const NODE_EVIDENCE_PATH: &str = "$.survey.extension_evidence.org.example.runtime.node";
const NODE_CONTRACT_PATH: &str = "$.contract.extension_contract.org.example.runtime.node";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRuntimeExtensionError {
    pub checkpoint_id: &'static str,
    pub message: String,
}

impl NodeRuntimeExtensionError {
    fn new(checkpoint_id: &'static str, message: impl Into<String>) -> Self {
        Self {
            checkpoint_id,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for NodeRuntimeExtensionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} [fitctl.node_runtime_extension.v1 at {}]",
            self.message, self.checkpoint_id
        )
    }
}

impl std::error::Error for NodeRuntimeExtensionError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeRuntimeEvidenceStateV1 {
    Observed,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeRuntimeVersionV1 {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeRuntimeVersionRangeV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_inclusive: Option<NodeRuntimeVersionV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_exclusive: Option<NodeRuntimeVersionV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeRuntimeEvidenceV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub collector: CollectorMetadataV1,
    pub claim_metadata: ClaimMetadataV1,
    pub runtime_id: String,
    pub runtime_state: NodeRuntimeEvidenceStateV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<NodeRuntimeVersionV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeRuntimeContractV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub claim_metadata: ClaimMetadataV1,
    pub runtime_id: String,
    pub runtime_available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<NodeRuntimeVersionV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeRuntimeRequirementV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub required_runtime: String,
    #[serde(default = "default_true")]
    pub require_presence: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_version: Option<NodeRuntimeVersionV1>,
    #[serde(default)]
    pub accepted_version_ranges: Vec<NodeRuntimeVersionRangeV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeRuntimeReplayCorpusV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub namespace: String,
    pub fixtures: Vec<NodeRuntimeReplayFixtureEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeRuntimeReplayFixtureEntryV1 {
    pub fixture_id: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeRuntimeReplayFixtureSnapshotV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub fixture_id: String,
    pub namespace: String,
    pub evidence: NodeRuntimeEvidenceV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeRuntimeEvaluationOutcomeV1 {
    Satisfied,
    Unsatisfied { summary: String },
}

pub fn decode_node_runtime_evidence_from_value(
    value: &Value,
) -> Result<NodeRuntimeEvidenceV1, NodeRuntimeExtensionError> {
    let evidence: NodeRuntimeEvidenceV1 =
        serde_json::from_value(value.clone()).map_err(|error| {
            NodeRuntimeExtensionError::new(
                "node_extension_normalize",
                format!("failed to decode Node runtime extension evidence: {error}"),
            )
        })?;
    validate_node_runtime_evidence(&evidence)?;
    Ok(evidence)
}

pub fn decode_node_runtime_contract_from_value(
    value: &Value,
) -> Result<NodeRuntimeContractV1, NodeRuntimeExtensionError> {
    let contract: NodeRuntimeContractV1 =
        serde_json::from_value(value.clone()).map_err(|error| {
            NodeRuntimeExtensionError::new(
                "node_extension_contract_derive",
                format!("failed to decode Node runtime extension contract: {error}"),
            )
        })?;
    validate_node_runtime_contract(&contract)?;
    Ok(contract)
}

pub fn decode_node_runtime_requirement_from_value(
    value: &Value,
) -> Result<NodeRuntimeRequirementV1, NodeRuntimeExtensionError> {
    let requirement: NodeRuntimeRequirementV1 =
        serde_json::from_value(value.clone()).map_err(|error| {
            NodeRuntimeExtensionError::new(
                "node_extension_validate",
                format!("failed to decode Node runtime extension requirement: {error}"),
            )
        })?;
    validate_node_runtime_requirement(&requirement)?;
    Ok(requirement)
}

pub fn apply_node_runtime_extension_to_survey_v1(
    mut survey: HostSurveyV1,
    replay_root: Option<&Path>,
) -> Result<HostSurveyV1, NodeRuntimeExtensionError> {
    let payload = decode_host_survey_payload(&survey.survey).map_err(|error| {
        NodeRuntimeExtensionError::new(
            "node_extension_normalize",
            format!("failed to decode host-survey payload for Node extension: {error}"),
        )
    })?;

    let evidence = match payload.collection_mode.as_str() {
        "live" => collect_live_node_runtime_evidence()?,
        "replay" => load_replay_node_runtime_evidence(
            replay_root.ok_or_else(|| {
                NodeRuntimeExtensionError::new(
                    "node_extension_collect",
                    "Node runtime replay collection requires an extension replay root",
                )
            })?,
            &payload.snapshot_id,
        )?,
        unknown => {
            return Err(NodeRuntimeExtensionError::new(
                "node_extension_collect",
                format!("unsupported survey collection mode {unknown} for Node runtime extension"),
            ))
        }
    };

    let mut payload = payload;
    payload.extension_evidence.insert(
        NODE_RUNTIME_NAMESPACE.to_string(),
        serde_json::to_value(&evidence).map_err(|error| {
            NodeRuntimeExtensionError::new(
                "node_extension_normalize",
                format!("failed to encode Node runtime extension evidence: {error}"),
            )
        })?,
    );
    survey.survey = encode_host_survey_payload(&payload).map_err(|error| {
        NodeRuntimeExtensionError::new(
            "node_extension_normalize",
            format!("failed to encode host-survey payload for Node extension: {error}"),
        )
    })?;

    Ok(survey)
}

pub fn derive_node_runtime_contract_value_from_survey_v1(
    survey: &HostSurveyV1,
) -> Result<Option<Value>, NodeRuntimeExtensionError> {
    let payload = decode_host_survey_payload(&survey.survey).map_err(|error| {
        NodeRuntimeExtensionError::new(
            "node_extension_contract_derive",
            format!(
                "failed to decode host-survey payload for Node runtime contract derivation: {error}"
            ),
        )
    })?;
    let Some(value) = payload.extension_evidence.get(NODE_RUNTIME_NAMESPACE) else {
        return Ok(None);
    };
    let evidence = decode_node_runtime_evidence_from_value(value)?;
    let contract = derive_node_runtime_contract_from_evidence(&evidence);
    Ok(Some(serde_json::to_value(contract).map_err(|error| {
        NodeRuntimeExtensionError::new(
            "node_extension_contract_derive",
            format!("failed to encode Node runtime extension contract: {error}"),
        )
    })?))
}

pub fn evaluate_node_runtime_requirement_v1(
    contract: &NodeRuntimeContractV1,
    requirement: &NodeRuntimeRequirementV1,
) -> Result<NodeRuntimeEvaluationOutcomeV1, NodeRuntimeExtensionError> {
    validate_node_runtime_contract(contract)?;
    validate_node_runtime_requirement(requirement)?;

    if contract.runtime_id != requirement.required_runtime {
        return Err(NodeRuntimeExtensionError::new(
            "node_extension_validate",
            "Node runtime contract and requirement use different runtime ids",
        ));
    }

    if !contract.runtime_available {
        return Ok(NodeRuntimeEvaluationOutcomeV1::Unsatisfied {
            summary: format!(
                "{} is required by the service profile but the contract records it as unavailable",
                requirement.required_runtime
            ),
        });
    }

    let version = contract.version.as_ref().ok_or_else(|| {
        NodeRuntimeExtensionError::new(
            "node_extension_validate",
            "Node runtime contract must carry a parsed version when runtime_available is true",
        )
    })?;

    if let Some(minimum_version) = requirement.minimum_version.as_ref() {
        if compare_versions(version, minimum_version) == Ordering::Less {
            return Ok(NodeRuntimeEvaluationOutcomeV1::Unsatisfied {
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
        return Ok(NodeRuntimeEvaluationOutcomeV1::Unsatisfied {
            summary: format!(
                "{} version {} is outside the accepted version ranges",
                requirement.required_runtime,
                format_version(version)
            ),
        });
    }

    Ok(NodeRuntimeEvaluationOutcomeV1::Satisfied)
}

pub fn format_node_runtime_evidence_for_inspect(
    evidence: &NodeRuntimeEvidenceV1,
    include_executable_path: bool,
) -> String {
    match evidence.runtime_state {
        NodeRuntimeEvidenceStateV1::Observed => {
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
        NodeRuntimeEvidenceStateV1::NotFound => format!("{} not found", evidence.runtime_id),
    }
}

pub fn format_node_runtime_contract_for_inspect(contract: &NodeRuntimeContractV1) -> String {
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

pub fn format_node_runtime_requirement_for_inspect(
    requirement: &NodeRuntimeRequirementV1,
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

pub fn redact_node_runtime_evidence_export_v1(
    evidence: &mut NodeRuntimeEvidenceV1,
    profile: BuiltInRedactionProfileV1,
) {
    if profile.applies_fleet_redactions() || profile.applies_auditor_redactions() {
        evidence.executable_path = None;
    }
}

fn collect_live_node_runtime_evidence() -> Result<NodeRuntimeEvidenceV1, NodeRuntimeExtensionError>
{
    let collector = CollectorMetadataV1 {
        collector_id: NODE_RUNTIME_COLLECTOR_ID.to_string(),
        collector_version: NODE_RUNTIME_COLLECTOR_VERSION.to_string(),
        source_family: NODE_RUNTIME_LIVE_SOURCE_FAMILY.to_string(),
    };

    let Some(executable_path) = find_executable_in_path("node") else {
        return Ok(NodeRuntimeEvidenceV1 {
            schema_id: NODE_RUNTIME_EVIDENCE_SCHEMA_ID.to_string(),
            schema_version: 1,
            collector,
            claim_metadata: observed_claim_metadata(NODE_EVIDENCE_PATH),
            runtime_id: "node".to_string(),
            runtime_state: NodeRuntimeEvidenceStateV1::NotFound,
            executable_path: None,
            version: None,
        });
    };

    let output = Command::new(&executable_path)
        .arg("--version")
        .output()
        .map_err(|error| {
            NodeRuntimeExtensionError::new(
                "node_extension_collect",
                format!(
                    "failed to execute Node runtime probe {} --version: {error}",
                    executable_path.display()
                ),
            )
        })?;
    if !output.status.success() {
        return Err(NodeRuntimeExtensionError::new(
            "node_extension_collect",
            format!(
                "Node runtime probe {} --version exited with status {}",
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
    let version = parse_node_version_output(&version_output)?;

    Ok(NodeRuntimeEvidenceV1 {
        schema_id: NODE_RUNTIME_EVIDENCE_SCHEMA_ID.to_string(),
        schema_version: 1,
        collector,
        claim_metadata: observed_claim_metadata(NODE_EVIDENCE_PATH),
        runtime_id: "node".to_string(),
        runtime_state: NodeRuntimeEvidenceStateV1::Observed,
        executable_path: Some(executable_path.display().to_string()),
        version: Some(version),
    })
}

fn load_replay_node_runtime_evidence(
    root: &Path,
    fixture_id: &str,
) -> Result<NodeRuntimeEvidenceV1, NodeRuntimeExtensionError> {
    let manifest_path = root.join("manifest.v1.json");
    let manifest_text = fs::read_to_string(&manifest_path).map_err(|error| {
        NodeRuntimeExtensionError::new(
            "node_extension_collect",
            format!(
                "failed to read Node runtime replay manifest {}: {error}",
                manifest_path.display()
            ),
        )
    })?;
    let manifest: NodeRuntimeReplayCorpusV1 =
        serde_json::from_str(&manifest_text).map_err(|error| {
            NodeRuntimeExtensionError::new(
                "node_extension_collect",
                format!(
                    "failed to decode Node runtime replay manifest {}: {error}",
                    manifest_path.display()
                ),
            )
        })?;
    validate_node_runtime_replay_manifest(&manifest)?;

    let entry = manifest
        .fixtures
        .iter()
        .find(|entry| entry.fixture_id == fixture_id)
        .ok_or_else(|| {
            NodeRuntimeExtensionError::new(
                "node_extension_collect",
                format!("Node runtime replay corpus does not contain fixture id {fixture_id}"),
            )
        })?;
    let fixture_path = resolve_replay_fixture_path(root, &entry.path)?;
    let fixture_text = fs::read_to_string(&fixture_path).map_err(|error| {
        NodeRuntimeExtensionError::new(
            "node_extension_collect",
            format!(
                "failed to read Node runtime replay fixture {}: {error}",
                fixture_path.display()
            ),
        )
    })?;
    let snapshot: NodeRuntimeReplayFixtureSnapshotV1 = serde_json::from_str(&fixture_text)
        .map_err(|error| {
            NodeRuntimeExtensionError::new(
                "node_extension_collect",
                format!(
                    "failed to decode Node runtime replay fixture {}: {error}",
                    fixture_path.display()
                ),
            )
        })?;

    if snapshot.schema_id != NODE_RUNTIME_REPLAY_SNAPSHOT_SCHEMA_ID
        || snapshot.schema_version != 1
        || snapshot.fixture_id != fixture_id
        || snapshot.namespace != NODE_RUNTIME_NAMESPACE
    {
        return Err(NodeRuntimeExtensionError::new(
            "node_extension_collect",
            "Node runtime replay fixture must declare the supported schema, namespace, and fixture id",
        ));
    }
    validate_node_runtime_evidence(&snapshot.evidence)?;

    Ok(snapshot.evidence)
}

fn derive_node_runtime_contract_from_evidence(
    evidence: &NodeRuntimeEvidenceV1,
) -> NodeRuntimeContractV1 {
    NodeRuntimeContractV1 {
        schema_id: NODE_RUNTIME_CONTRACT_SCHEMA_ID.to_string(),
        schema_version: 1,
        claim_metadata: ClaimMetadataV1 {
            assurance_source: AssuranceSourceV1::SelfObserved,
            derivation_stage: DerivationStageV1::Derived,
            source_collectors: vec![evidence.collector.collector_id.clone()],
            evidence_paths: vec![
                NODE_CONTRACT_PATH.to_string(),
                NODE_EVIDENCE_PATH.to_string(),
            ],
            policy_rule_id: None,
            trust_evidence_refs: Vec::new(),
        },
        runtime_id: evidence.runtime_id.clone(),
        runtime_available: matches!(evidence.runtime_state, NodeRuntimeEvidenceStateV1::Observed),
        version: evidence.version.clone(),
    }
}

fn validate_node_runtime_evidence(
    evidence: &NodeRuntimeEvidenceV1,
) -> Result<(), NodeRuntimeExtensionError> {
    if evidence.schema_id != NODE_RUNTIME_EVIDENCE_SCHEMA_ID
        || evidence.schema_version != 1
        || evidence.runtime_id != "node"
    {
        return Err(NodeRuntimeExtensionError::new(
            "node_extension_normalize",
            "Node runtime extension evidence must declare the supported schema and runtime id",
        ));
    }
    validate_collector(&evidence.collector)?;
    validate_claim_metadata(&evidence.claim_metadata)?;

    match evidence.runtime_state {
        NodeRuntimeEvidenceStateV1::Observed => {
            if evidence
                .executable_path
                .as_deref()
                .is_some_and(|value| value.trim().is_empty())
            {
                return Err(NodeRuntimeExtensionError::new(
                    "node_extension_normalize",
                    "observed Node runtime evidence executable_path must be non-blank when present",
                ));
            }
            validate_version(evidence.version.as_ref().ok_or_else(|| {
                NodeRuntimeExtensionError::new(
                    "node_extension_normalize",
                    "observed Node runtime evidence must include a parsed version",
                )
            })?)?;
        }
        NodeRuntimeEvidenceStateV1::NotFound => {
            if evidence.executable_path.is_some() || evidence.version.is_some() {
                return Err(NodeRuntimeExtensionError::new(
                    "node_extension_normalize",
                    "not_found Node runtime evidence must not include executable_path or version",
                ));
            }
        }
    }

    Ok(())
}

fn validate_node_runtime_contract(
    contract: &NodeRuntimeContractV1,
) -> Result<(), NodeRuntimeExtensionError> {
    if contract.schema_id != NODE_RUNTIME_CONTRACT_SCHEMA_ID
        || contract.schema_version != 1
        || contract.runtime_id != "node"
    {
        return Err(NodeRuntimeExtensionError::new(
            "node_extension_contract_derive",
            "Node runtime extension contract must declare the supported schema and runtime id",
        ));
    }
    validate_claim_metadata(&contract.claim_metadata)?;
    if contract.runtime_available {
        validate_version(contract.version.as_ref().ok_or_else(|| {
            NodeRuntimeExtensionError::new(
                "node_extension_contract_derive",
                "available Node runtime contract must include a parsed version",
            )
        })?)?;
    } else if contract.version.is_some() {
        return Err(NodeRuntimeExtensionError::new(
            "node_extension_contract_derive",
            "unavailable Node runtime contract must not include a version",
        ));
    }
    Ok(())
}

fn validate_node_runtime_requirement(
    requirement: &NodeRuntimeRequirementV1,
) -> Result<(), NodeRuntimeExtensionError> {
    if requirement.schema_id != NODE_RUNTIME_REQUIREMENT_SCHEMA_ID
        || requirement.schema_version != 1
        || requirement.required_runtime != "node"
    {
        return Err(NodeRuntimeExtensionError::new(
            "node_extension_validate",
            "Node runtime extension requirement must declare the supported schema and runtime id",
        ));
    }
    if !requirement.require_presence
        && requirement.minimum_version.is_none()
        && requirement.accepted_version_ranges.is_empty()
    {
        return Err(NodeRuntimeExtensionError::new(
            "node_extension_validate",
            "Node runtime extension requirement must declare at least one effective constraint",
        ));
    }
    if let Some(minimum_version) = requirement.minimum_version.as_ref() {
        validate_version(minimum_version)?;
    }
    for range in &requirement.accepted_version_ranges {
        if range.minimum_inclusive.is_none() && range.maximum_exclusive.is_none() {
            return Err(NodeRuntimeExtensionError::new(
                "node_extension_validate",
                "Node runtime accepted version ranges must set at least one bound",
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
                return Err(NodeRuntimeExtensionError::new(
                    "node_extension_validate",
                    "Node runtime accepted version ranges must have minimum_inclusive < maximum_exclusive",
                ));
            }
        }
    }
    Ok(())
}

fn validate_collector(collector: &CollectorMetadataV1) -> Result<(), NodeRuntimeExtensionError> {
    if collector.collector_id != NODE_RUNTIME_COLLECTOR_ID
        || collector.collector_version != NODE_RUNTIME_COLLECTOR_VERSION
        || !matches!(
            collector.source_family.as_str(),
            NODE_RUNTIME_LIVE_SOURCE_FAMILY | NODE_RUNTIME_REPLAY_SOURCE_FAMILY
        )
    {
        return Err(NodeRuntimeExtensionError::new(
            "node_extension_normalize",
            "Node runtime collector metadata contains an unsupported collector tuple",
        ));
    }
    Ok(())
}

fn validate_claim_metadata(metadata: &ClaimMetadataV1) -> Result<(), NodeRuntimeExtensionError> {
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
        return Err(NodeRuntimeExtensionError::new(
            "node_extension_normalize",
            "Node runtime claim metadata must remain fully populated and non-blank",
        ));
    }
    Ok(())
}

fn validate_version(version: &NodeRuntimeVersionV1) -> Result<(), NodeRuntimeExtensionError> {
    if version.major == 0 {
        return Err(NodeRuntimeExtensionError::new(
            "node_extension_validate",
            "Node runtime versions must use a positive major version",
        ));
    }
    Ok(())
}

fn validate_node_runtime_replay_manifest(
    manifest: &NodeRuntimeReplayCorpusV1,
) -> Result<(), NodeRuntimeExtensionError> {
    if manifest.schema_id != NODE_RUNTIME_REPLAY_CORPUS_SCHEMA_ID
        || manifest.schema_version != 1
        || manifest.namespace != NODE_RUNTIME_NAMESPACE
        || manifest.fixtures.is_empty()
    {
        return Err(NodeRuntimeExtensionError::new(
            "node_extension_collect",
            "Node runtime replay manifest must declare the supported schema, namespace, and fixtures",
        ));
    }

    let mut ids = BTreeSet::new();
    for fixture in &manifest.fixtures {
        if fixture.fixture_id.trim().is_empty()
            || fixture.path.trim().is_empty()
            || Path::new(&fixture.path).is_absolute()
            || !ids.insert(fixture.fixture_id.clone())
        {
            return Err(NodeRuntimeExtensionError::new(
                "node_extension_collect",
                "Node runtime replay manifest contains duplicate ids or invalid paths",
            ));
        }
    }

    Ok(())
}

fn resolve_replay_fixture_path(
    root: &Path,
    relative_path: &str,
) -> Result<PathBuf, NodeRuntimeExtensionError> {
    let canonical_root = fs::canonicalize(root).map_err(|error| {
        NodeRuntimeExtensionError::new(
            "node_extension_collect",
            format!(
                "failed to resolve Node runtime replay root {}: {error}",
                root.display()
            ),
        )
    })?;
    let candidate = canonical_root.join(relative_path);
    let canonical_candidate = fs::canonicalize(&candidate).map_err(|error| {
        NodeRuntimeExtensionError::new(
            "node_extension_collect",
            format!(
                "failed to resolve Node runtime replay fixture {}: {error}",
                candidate.display()
            ),
        )
    })?;
    if !canonical_candidate.starts_with(&canonical_root) {
        return Err(NodeRuntimeExtensionError::new(
            "node_extension_collect",
            "Node runtime replay fixture path escapes the selected root",
        ));
    }
    Ok(canonical_candidate)
}

fn observed_claim_metadata(evidence_path: &str) -> ClaimMetadataV1 {
    ClaimMetadataV1 {
        assurance_source: AssuranceSourceV1::SelfObserved,
        derivation_stage: DerivationStageV1::Normalized,
        source_collectors: vec![NODE_RUNTIME_COLLECTOR_ID.to_string()],
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

fn parse_node_version_output(
    output: &str,
) -> Result<NodeRuntimeVersionV1, NodeRuntimeExtensionError> {
    let version_token = output
        .split_whitespace()
        .next()
        .ok_or_else(|| {
            NodeRuntimeExtensionError::new(
                "node_extension_collect",
                format!("Node runtime probe produced an unsupported version string: {output}"),
            )
        })?
        .trim_start_matches(['v', 'V']);
    if version_token.is_empty() {
        return Err(NodeRuntimeExtensionError::new(
            "node_extension_collect",
            format!("Node runtime probe produced an unsupported version string: {output}"),
        ));
    }
    parse_version_token(version_token)
}

fn parse_version_token(token: &str) -> Result<NodeRuntimeVersionV1, NodeRuntimeExtensionError> {
    let mut parts = token.split('.');
    let major = parse_numeric_component(parts.next(), token)?;
    let minor = parse_numeric_component(parts.next(), token)?;
    let patch = parse_numeric_component(parts.next(), token)?;
    Ok(NodeRuntimeVersionV1 {
        major,
        minor,
        patch,
    })
}

fn parse_numeric_component(
    value: Option<&str>,
    original: &str,
) -> Result<u32, NodeRuntimeExtensionError> {
    let value = value.ok_or_else(|| {
        NodeRuntimeExtensionError::new(
            "node_extension_collect",
            format!("Node runtime version string {original} is incomplete"),
        )
    })?;
    let digits = value
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .collect::<String>();
    if digits.is_empty() {
        return Err(NodeRuntimeExtensionError::new(
            "node_extension_collect",
            format!("Node runtime version component {value} is not numeric"),
        ));
    }
    digits.parse::<u32>().map_err(|error| {
        NodeRuntimeExtensionError::new(
            "node_extension_collect",
            format!("Node runtime version component {value} is invalid: {error}"),
        )
    })
}

fn compare_versions(left: &NodeRuntimeVersionV1, right: &NodeRuntimeVersionV1) -> Ordering {
    left.major
        .cmp(&right.major)
        .then_with(|| left.minor.cmp(&right.minor))
        .then_with(|| left.patch.cmp(&right.patch))
}

fn range_contains_version(
    range: &NodeRuntimeVersionRangeV1,
    version: &NodeRuntimeVersionV1,
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

fn format_version(version: &NodeRuntimeVersionV1) -> String {
    format!("{}.{}.{}", version.major, version.minor, version.patch)
}

fn format_version_range(range: &NodeRuntimeVersionRangeV1) -> String {
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
