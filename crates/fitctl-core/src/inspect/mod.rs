// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Human-readable rendering for typed artifacts.
//!
//! Inspect is intentionally presentation-only: it explains typed artifacts to operators without
//! becoming the canonical machine-readable surface.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use serde_json::Value;

mod format;

use self::format::*;

use crate::artifacts::batch_classification_report_v1::BatchClassificationReportV1;
use crate::artifacts::contract_v1::HostContractV1;
use crate::artifacts::envelope_v1::{ArtifactEnvelopeV1, SignatureEnvelopeV1};
use crate::artifacts::metadata_v1::CollectorMetadataV1;
use crate::artifacts::recommendation_report_v1::{
    RecommendationConfidenceV1, RecommendationFreshnessStateV1, RecommendationReportV1,
};
use crate::artifacts::record_v1::{
    load_artifact_record_from_path, load_artifact_record_from_value, ArtifactRecordErrorCode,
    ArtifactRecordV1,
};
use crate::artifacts::schema_ids_v1::{
    BATCH_CLASSIFICATION_REPORT_SCHEMA_ID, RECOMMENDATION_REPORT_SCHEMA_ID,
};
use crate::artifacts::service_profile_v1::{
    AssurancePredicateV1, DegradationTierV1, ServiceProfileV1,
};
use crate::artifacts::state_v1::{HostStateV1, StateFieldV1};
use crate::artifacts::survey_v1::{decode_host_survey_payload, HostSurveyV1};
use crate::artifacts::validation_report_v1::ValidationReportV1;
use crate::classify::{
    load_batch_classification_report_from_path, load_batch_classification_report_from_value,
};
use crate::contract::HostContractPayloadV1;
use crate::extensions::{
    decode_node_runtime_contract_from_value, decode_node_runtime_evidence_from_value,
    decode_node_runtime_requirement_from_value, decode_python_runtime_contract_from_value,
    decode_python_runtime_evidence_from_value, decode_python_runtime_requirement_from_value,
    format_node_runtime_contract_for_inspect, format_node_runtime_evidence_for_inspect,
    format_node_runtime_requirement_for_inspect, format_python_runtime_contract_for_inspect,
    format_python_runtime_evidence_for_inspect, format_python_runtime_requirement_for_inspect,
    NODE_RUNTIME_NAMESPACE, PYTHON_RUNTIME_NAMESPACE,
};
use crate::recommendation::{
    load_recommendation_report_from_path, load_recommendation_report_from_value,
};
use crate::survey::{
    AcceleratorDetailsV1, AcceleratorOperabilityV1, CpuCacheSummaryBasisV1, CpuCacheSummaryV1,
    CpuDetailsV1, NetworkCarrierStateV1, NetworkDetailsV1, NetworkDuplexV1,
    NetworkInterfaceVirtualityV1, ObservationLimitationReasonV1, ObservationStateV1,
    PrivilegeLevelV1, StorageDetailsV1, SurveyFieldV1, VisibilityScopeV1,
};
use crate::validate::{ValidationModeV1, ValidationReasonCodeV1, ValidationVerdictV1};

pub const INSPECT_ERROR_MODEL_ID: &str = "fitctl.inspect.v1";
pub const INSPECT_ERROR_MODEL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectErrorCode {
    InspectInputInvalid,
    InspectSchemaUnsupported,
    InspectRenderFailed,
}

impl InspectErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InspectInputInvalid => "inspect_input_invalid",
            Self::InspectSchemaUnsupported => "inspect_schema_unsupported",
            Self::InspectRenderFailed => "inspect_render_failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectError {
    pub code: InspectErrorCode,
    pub checkpoint_id: &'static str,
    pub message: String,
    pub error_model_id: &'static str,
    pub error_model_version: u32,
}

impl InspectError {
    fn new(
        code: InspectErrorCode,
        checkpoint_id: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            checkpoint_id,
            message: message.into(),
            error_model_id: INSPECT_ERROR_MODEL_ID,
            error_model_version: INSPECT_ERROR_MODEL_VERSION,
        }
    }
}

impl std::fmt::Display for InspectError {
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

impl std::error::Error for InspectError {}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InspectRenderOptionsV1 {
    pub verbose: bool,
    pub show_identifiers: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum InspectArtifactV1 {
    Core(Box<ArtifactRecordV1>),
    BatchClassificationReport(Box<BatchClassificationReportV1>),
    RecommendationReport(Box<RecommendationReportV1>),
}

impl InspectArtifactV1 {
    fn envelope(&self) -> &ArtifactEnvelopeV1 {
        match self {
            Self::Core(artifact) => artifact.envelope(),
            Self::BatchClassificationReport(artifact) => &artifact.envelope,
            Self::RecommendationReport(artifact) => &artifact.envelope,
        }
    }

    fn schema_id(&self) -> &str {
        &self.envelope().schema_id
    }

    fn artifact_id(&self) -> &str {
        &self.envelope().artifact_id
    }
}

// Batch and recommendation reports have their own typed loaders, so inspect resolves those first
// and falls back to the generic artifact-record path for the core artifact families.
pub fn load_artifact_record_for_inspect(path: &Path) -> Result<InspectArtifactV1, InspectError> {
    let schema_id = load_schema_id_for_inspect(path)?;

    if schema_id == BATCH_CLASSIFICATION_REPORT_SCHEMA_ID {
        return load_batch_classification_report_from_path(path)
            .map(Box::new)
            .map(InspectArtifactV1::BatchClassificationReport)
            .map_err(|error| {
                InspectError::new(
                    InspectErrorCode::InspectInputInvalid,
                    "inspect_load",
                    error.message,
                )
            });
    }

    if schema_id == RECOMMENDATION_REPORT_SCHEMA_ID {
        return load_recommendation_report_from_path(path)
            .map(Box::new)
            .map(InspectArtifactV1::RecommendationReport)
            .map_err(|error| {
                InspectError::new(
                    InspectErrorCode::InspectInputInvalid,
                    "inspect_load",
                    error.message,
                )
            });
    }

    load_artifact_record_from_path(path)
        .map(Box::new)
        .map(InspectArtifactV1::Core)
        .map_err(|error| match error.code {
            ArtifactRecordErrorCode::ArtifactSchemaUnsupported => InspectError::new(
                InspectErrorCode::InspectSchemaUnsupported,
                "inspect_load",
                "artifact schema id is not supported by the inspect surface",
            ),
            _ => InspectError::new(
                InspectErrorCode::InspectInputInvalid,
                "inspect_load",
                error.message,
            ),
        })
}

pub fn load_artifact_record_for_inspect_from_value(
    raw: Value,
) -> Result<InspectArtifactV1, InspectError> {
    let schema_id = load_schema_id_for_inspect_from_value(&raw)?;

    if schema_id == BATCH_CLASSIFICATION_REPORT_SCHEMA_ID {
        return load_batch_classification_report_from_value(raw)
            .map(Box::new)
            .map(InspectArtifactV1::BatchClassificationReport)
            .map_err(|error| {
                InspectError::new(
                    InspectErrorCode::InspectInputInvalid,
                    "inspect_load",
                    error.message,
                )
            });
    }

    if schema_id == RECOMMENDATION_REPORT_SCHEMA_ID {
        return load_recommendation_report_from_value(raw)
            .map(Box::new)
            .map(InspectArtifactV1::RecommendationReport)
            .map_err(|error| {
                InspectError::new(
                    InspectErrorCode::InspectInputInvalid,
                    "inspect_load",
                    error.message,
                )
            });
    }

    load_artifact_record_from_value(raw)
        .map(Box::new)
        .map(InspectArtifactV1::Core)
        .map_err(|error| match error.code {
            ArtifactRecordErrorCode::ArtifactSchemaUnsupported => InspectError::new(
                InspectErrorCode::InspectSchemaUnsupported,
                "inspect_load",
                "artifact schema id is not supported by the inspect surface",
            ),
            _ => InspectError::new(
                InspectErrorCode::InspectInputInvalid,
                "inspect_load",
                error.message,
            ),
        })
}

fn load_schema_id_for_inspect(path: &Path) -> Result<String, InspectError> {
    let text = fs::read_to_string(path).map_err(|error| {
        InspectError::new(
            InspectErrorCode::InspectInputInvalid,
            "inspect_load",
            format!("failed to read artifact {}: {error}", path.display()),
        )
    })?;
    let raw: Value = serde_json::from_str(&text).map_err(|error| {
        InspectError::new(
            InspectErrorCode::InspectInputInvalid,
            "inspect_load",
            format!("failed to decode artifact {}: {error}", path.display()),
        )
    })?;
    let schema_id = raw
        .get("envelope")
        .and_then(|value| value.get("schema_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            InspectError::new(
                InspectErrorCode::InspectInputInvalid,
                "inspect_load",
                format!(
                    "artifact {} must include envelope.schema_id",
                    path.display()
                ),
            )
        })?;

    Ok(schema_id.to_string())
}

fn load_schema_id_for_inspect_from_value(raw: &Value) -> Result<String, InspectError> {
    raw.get("envelope")
        .and_then(|value| value.get("schema_id"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            InspectError::new(
                InspectErrorCode::InspectInputInvalid,
                "inspect_load",
                "artifact input must include envelope.schema_id",
            )
        })
}

pub fn render_artifact_summary_v1(artifact: &ArtifactRecordV1) -> Result<String, InspectError> {
    render_artifact_summary_with_options_v1(artifact, InspectRenderOptionsV1::default())
}

/// Render a core artifact into the standard inspect view using explicit render options.
pub fn render_artifact_summary_with_options_v1(
    artifact: &ArtifactRecordV1,
    options: InspectRenderOptionsV1,
) -> Result<String, InspectError> {
    render_inspect_artifact_summary_with_options_v1(
        &InspectArtifactV1::Core(Box::new(artifact.clone())),
        options,
    )
}

pub fn render_inspect_artifact_summary_v1(
    artifact: &InspectArtifactV1,
) -> Result<String, InspectError> {
    render_inspect_artifact_summary_with_options_v1(artifact, InspectRenderOptionsV1::default())
}

/// Render the family-specific summary first, then the shared envelope metadata section.
///
/// That split mirrors the product model: the summary explains the artifact's semantic content,
/// while metadata is secondary provenance and presentation detail.
pub fn render_inspect_artifact_summary_with_options_v1(
    artifact: &InspectArtifactV1,
    options: InspectRenderOptionsV1,
) -> Result<String, InspectError> {
    let mut output = String::new();

    writeln!(&mut output, "Artifact").map_err(|error| {
        InspectError::new(
            InspectErrorCode::InspectRenderFailed,
            "inspect_render",
            format!("failed to render artifact header: {error}"),
        )
    })?;
    push_line(&mut output, "Family", artifact.schema_id())?;
    push_line(
        &mut output,
        "Schema version",
        artifact.envelope().schema_version.to_string(),
    )?;
    push_line(&mut output, "Artifact id", artifact.artifact_id())?;
    writeln!(&mut output).map_err(|error| {
        InspectError::new(
            InspectErrorCode::InspectRenderFailed,
            "inspect_render",
            format!("failed to render summary separator: {error}"),
        )
    })?;

    writeln!(&mut output, "Summary").map_err(|error| {
        InspectError::new(
            InspectErrorCode::InspectRenderFailed,
            "inspect_render",
            format!("failed to render summary header: {error}"),
        )
    })?;

    let collectors = match artifact {
        InspectArtifactV1::Core(artifact) => match artifact.as_ref() {
            ArtifactRecordV1::Survey(artifact) => {
                render_survey_summary(&mut output, artifact, options)?;
                Some(
                    decode_host_survey_payload(&artifact.survey)
                        .map_err(|error| {
                            InspectError::new(
                                InspectErrorCode::InspectInputInvalid,
                                "inspect_decode",
                                format!(
                                    "failed to decode host survey payload for inspect: {error}"
                                ),
                            )
                        })?
                        .core_evidence
                        .collectors,
                )
            }
            ArtifactRecordV1::Contract(artifact) => {
                render_contract_summary(&mut output, artifact, options)?;
                None
            }
            ArtifactRecordV1::ServiceProfile(artifact) => {
                render_service_profile_summary(&mut output, artifact)?;
                None
            }
            ArtifactRecordV1::State(artifact) => {
                render_state_summary(&mut output, artifact, options)?;
                Some(artifact.state.core_state.collectors.clone())
            }
            ArtifactRecordV1::ValidationReport(artifact) => {
                render_validation_report_summary(&mut output, artifact, options)?;
                None
            }
        },
        InspectArtifactV1::BatchClassificationReport(artifact) => {
            render_batch_classification_report_summary(&mut output, artifact, options)?;
            None
        }
        InspectArtifactV1::RecommendationReport(artifact) => {
            render_recommendation_report_summary(&mut output, artifact, options)?;
            None
        }
    };

    writeln!(&mut output).map_err(|error| {
        InspectError::new(
            InspectErrorCode::InspectRenderFailed,
            "inspect_render",
            format!("failed to render metadata separator: {error}"),
        )
    })?;
    writeln!(&mut output, "Metadata").map_err(|error| {
        InspectError::new(
            InspectErrorCode::InspectRenderFailed,
            "inspect_render",
            format!("failed to render metadata header: {error}"),
        )
    })?;
    render_metadata_section(
        &mut output,
        artifact.envelope(),
        collectors.as_deref(),
        options,
    )?;

    Ok(output)
}

fn render_survey_summary(
    output: &mut String,
    artifact: &HostSurveyV1,
    options: InspectRenderOptionsV1,
) -> Result<(), InspectError> {
    // Survey inspect stays on raw observed evidence and limitation signals; it intentionally does
    // not present policy-shaped promises or validation outcomes.
    let payload = decode_host_survey_payload(&artifact.survey).map_err(|error| {
        InspectError::new(
            InspectErrorCode::InspectInputInvalid,
            "inspect_decode",
            format!("failed to decode host survey payload for inspect: {error}"),
        )
    })?;

    push_line(output, "Host alias", payload.host_alias)?;
    push_line(output, "Collection mode", payload.collection_mode)?;
    if options.verbose {
        push_line(output, "Snapshot id", payload.snapshot_id)?;
        push_line(output, "Source ref", payload.source_ref)?;
    }
    if options.verbose
        || !matches!(
            payload.core_evidence.execution_context.visibility_scope,
            VisibilityScopeV1::BareMetalLike
        )
    {
        push_line(
            output,
            "Visibility scope",
            format_visibility_scope(&payload.core_evidence.execution_context.visibility_scope),
        )?;
    }
    push_line(
        output,
        "Privilege level",
        format_privilege_level(&payload.core_evidence.execution_context.privilege_level),
    )?;
    if options.verbose
        || payload
            .core_evidence
            .execution_context
            .container_runtime
            .is_some()
    {
        push_line(
            output,
            "Container runtime",
            format_optional_str(
                payload
                    .core_evidence
                    .execution_context
                    .container_runtime
                    .as_deref(),
            ),
        )?;
    }
    if options.verbose || !payload.core_evidence.execution_context.notes.is_empty() {
        push_line(
            output,
            "Execution notes",
            join_or_placeholder(&payload.core_evidence.execution_context.notes),
        )?;
    }
    push_line(
        output,
        "Hostname",
        format_survey_field(&payload.core_evidence.observations.hostname, |value| {
            value.clone()
        }),
    )?;
    push_line(
        output,
        "CPU",
        format_survey_field(&payload.core_evidence.observations.cpu, |value| {
            format_cpu_details_for_inspect(value, options)
        }),
    )?;
    push_line(
        output,
        "Memory total",
        format_survey_field(&payload.core_evidence.observations.memory, |value| {
            format_bytes(value.total_bytes)
        }),
    )?;
    push_line(
        output,
        "Storage",
        format_survey_field(&payload.core_evidence.observations.storage, |value| {
            format_storage_details_for_inspect(value)
        }),
    )?;
    if options.verbose {
        if let Some(value) = payload.core_evidence.observations.storage.value.as_ref() {
            push_line(
                output,
                "Storage filesystems",
                format_storage_filesystems_for_verbose_inspect(value),
            )?;
            push_line(
                output,
                "Storage roles",
                format_storage_roles_for_verbose_inspect(value),
            )?;
        }
    }
    push_line(
        output,
        "Network",
        format_survey_field(&payload.core_evidence.observations.network, |value| {
            format_network_details_for_inspect(value)
        }),
    )?;
    if options.verbose {
        if let Some(value) = payload.core_evidence.observations.network.value.as_ref() {
            push_line(
                output,
                "Network addressability",
                format_network_addressability_for_verbose_inspect(value),
            )?;
            push_line(
                output,
                "Network carrier",
                format_network_carrier_for_verbose_inspect(value),
            )?;
            push_line(
                output,
                "Network duplex",
                format_network_duplex_for_verbose_inspect(value),
            )?;
        }
    }
    push_line(
        output,
        "Graphics / accelerators",
        format_survey_field(&payload.core_evidence.observations.accelerators, |value| {
            format_accelerator_details_for_inspect(value, options)
        }),
    )?;
    push_line(
        output,
        "Topology",
        format_survey_field(&payload.core_evidence.observations.topology, |value| {
            format!(
                "{} NUMA nodes; {} CPU packages",
                value.numa_nodes, value.cpu_packages
            )
        }),
    )?;
    push_line(
        output,
        "Local stable identity",
        format_identifier_value_for_inspect(
            &payload.core_evidence.identity_summary.local_stable_id,
            options,
        ),
    )?;
    push_line(
        output,
        "Composition digest",
        format_identifier_value_for_inspect(
            &payload.core_evidence.identity_summary.composition_digest,
            options,
        ),
    )?;
    push_line(
        output,
        "Provenance fingerprint",
        format_identifier_value_for_inspect(
            &payload
                .core_evidence
                .identity_summary
                .provenance_fingerprint,
            options,
        ),
    )?;
    if let Some(value) = payload.extension_evidence.get(PYTHON_RUNTIME_NAMESPACE) {
        let evidence = decode_python_runtime_evidence_from_value(value).map_err(|error| {
            InspectError::new(
                InspectErrorCode::InspectInputInvalid,
                "inspect_decode",
                error.message,
            )
        })?;
        push_line(
            output,
            "Python runtime extension",
            format_python_runtime_evidence_for_inspect(&evidence, true),
        )?;
    }
    if let Some(value) = payload.extension_evidence.get(NODE_RUNTIME_NAMESPACE) {
        let evidence = decode_node_runtime_evidence_from_value(value).map_err(|error| {
            InspectError::new(
                InspectErrorCode::InspectInputInvalid,
                "inspect_decode",
                error.message,
            )
        })?;
        push_line(
            output,
            "Node runtime extension",
            format_node_runtime_evidence_for_inspect(&evidence, true),
        )?;
    }

    Ok(())
}

fn render_contract_summary(
    output: &mut String,
    artifact: &HostContractV1,
    options: InspectRenderOptionsV1,
) -> Result<(), InspectError> {
    // Contract inspect shows the conservative host promise after policy derivation, so summaries
    // here may be coarser than the underlying survey details by design.
    let payload: HostContractPayloadV1 = serde_json::from_value(artifact.contract.clone())
        .map_err(|error| {
            InspectError::new(
                InspectErrorCode::InspectInputInvalid,
                "inspect_decode",
                format!("failed to decode host contract payload for inspect: {error}"),
            )
        })?;

    push_line(
        output,
        "Capability classes",
        format_capability_classes(&payload),
    )?;
    push_line(
        output,
        "Capability summaries",
        join_or_placeholder(
            &payload
                .core_contract
                .capability_classes
                .iter()
                .map(|(class_id, claim)| format!("{class_id}: {}", claim.summary))
                .collect::<Vec<_>>(),
        ),
    )?;
    if options.verbose
        || !matches!(
            payload.core_contract.execution_constraints.visibility_scope,
            VisibilityScopeV1::BareMetalLike
        )
    {
        push_line(
            output,
            "Visibility scope",
            format_visibility_scope(&payload.core_contract.execution_constraints.visibility_scope),
        )?;
    }
    if options.verbose
        || payload
            .core_contract
            .execution_constraints
            .container_runtime
            .is_some()
    {
        push_line(
            output,
            "Container runtime",
            format_optional_str(
                payload
                    .core_contract
                    .execution_constraints
                    .container_runtime
                    .as_deref(),
            ),
        )?;
    }
    push_line(output, "Network summary", {
        let mut summary = format!(
            "{} total; {} non-loopback; kinds {}; max speed {}",
            payload
                .core_contract
                .network_summary
                .total_interfaces
                .map(|value| value.to_string())
                .unwrap_or_else(|| "<none>".to_string()),
            payload
                .core_contract
                .network_summary
                .non_loopback_interfaces
                .map(|value| value.to_string())
                .unwrap_or_else(|| "<none>".to_string()),
            if payload
                .core_contract
                .network_summary
                .interface_kinds
                .is_empty()
            {
                "<none>".to_string()
            } else {
                payload
                    .core_contract
                    .network_summary
                    .interface_kinds
                    .iter()
                    .map(|kind| kind.as_str().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            },
            payload
                .core_contract
                .network_summary
                .max_observed_speed_mbps
                .map(|value| format!("{value} Mbps"))
                .unwrap_or_else(|| "<none>".to_string())
        );
        if let Some(operability) = payload.core_contract.network_summary.operability.as_ref() {
            summary.push_str("; ");
            summary.push_str(&format!(
                "static operability: {}; {} physical; {} known-speed",
                operability.static_operability.as_str(),
                operability.physical_non_loopback_interfaces,
                operability.interfaces_with_known_speed
            ));
        }
        summary
    })?;
    push_line(output, "Storage summary", {
        let mut summary = format!(
            "{} block devices; {} mounts; classes {}; filesystems {}",
            payload
                .core_contract
                .storage_summary
                .total_block_devices
                .map(|value| value.to_string())
                .unwrap_or_else(|| "<none>".to_string()),
            payload
                .core_contract
                .storage_summary
                .total_mounts
                .map(|value| value.to_string())
                .unwrap_or_else(|| "<none>".to_string()),
            if payload
                .core_contract
                .storage_summary
                .block_device_classes
                .is_empty()
            {
                "<none>".to_string()
            } else {
                payload
                    .core_contract
                    .storage_summary
                    .block_device_classes
                    .iter()
                    .map(|class| class.as_str().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            },
            if payload
                .core_contract
                .storage_summary
                .filesystem_types
                .is_empty()
            {
                "<none>".to_string()
            } else {
                payload
                    .core_contract
                    .storage_summary
                    .filesystem_types
                    .join(", ")
            }
        );
        if let Some(operability) = payload.core_contract.storage_summary.operability.as_ref() {
            summary.push_str("; ");
            summary.push_str(&format!(
                "static operability: {}; {} usable devices; root mount {}",
                operability.static_operability.as_str(),
                operability.usable_block_devices,
                if operability.root_mount_present {
                    "present"
                } else {
                    "absent"
                }
            ));
        }
        summary
    })?;
    push_line(output, "Graphics / accelerator summary", {
        let mut summary = format!(
            "{} total; {} gpu; kinds {}; vendors {}",
            payload
                .core_contract
                .accelerator_summary
                .total_accelerators
                .map(|value| value.to_string())
                .unwrap_or_else(|| "<none>".to_string()),
            payload
                .core_contract
                .accelerator_summary
                .gpu_accelerators
                .map(|value| value.to_string())
                .unwrap_or_else(|| "<none>".to_string()),
            if payload
                .core_contract
                .accelerator_summary
                .accelerator_kinds
                .is_empty()
            {
                "<none>".to_string()
            } else {
                payload
                    .core_contract
                    .accelerator_summary
                    .accelerator_kinds
                    .iter()
                    .map(|kind| kind.as_str().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            },
            if payload.core_contract.accelerator_summary.vendors.is_empty() {
                "<none>".to_string()
            } else {
                payload.core_contract.accelerator_summary.vendors.join(", ")
            }
        );
        if let Some(operability) = payload
            .core_contract
            .accelerator_summary
            .operability
            .as_ref()
        {
            summary.push_str("; ");
            summary.push_str(&format_accelerator_operability_for_inspect(
                operability,
                options.verbose,
            ));
        }
        summary
    })?;
    push_line(
        output,
        "Topology summary",
        format!(
            "{} NUMA nodes; {} CPU packages",
            payload
                .core_contract
                .topology_summary
                .numa_nodes
                .map(|value| value.to_string())
                .unwrap_or_else(|| "<none>".to_string()),
            payload
                .core_contract
                .topology_summary
                .cpu_packages
                .map(|value| value.to_string())
                .unwrap_or_else(|| "<none>".to_string())
        ),
    )?;
    push_line(
        output,
        "Local stable identity",
        format_identifier_value_for_inspect(
            &payload.core_contract.identity_summary.local_stable_id,
            options,
        ),
    )?;
    push_line(
        output,
        "Composition digest",
        format_identifier_value_for_inspect(
            &payload.core_contract.identity_summary.composition_digest,
            options,
        ),
    )?;
    push_line(
        output,
        "Provenance fingerprint",
        format_identifier_value_for_inspect(
            &payload
                .core_contract
                .identity_summary
                .provenance_fingerprint,
            options,
        ),
    )?;
    if options.verbose {
        push_line(
            output,
            "Selected policy layers",
            join_or_placeholder(
                &artifact
                    .contract_basis
                    .core_semantic_basis
                    .selected_policy_layers,
            ),
        )?;
        push_line(
            output,
            "Derivation engine",
            format!(
                "{}@{}",
                artifact
                    .contract_basis
                    .core_semantic_basis
                    .derivation_engine_id,
                artifact
                    .contract_basis
                    .core_semantic_basis
                    .derivation_engine_version
            ),
        )?;
        push_line(
            output,
            "Derived at",
            format_timestamp_for_inspect(
                &artifact.contract_basis.derivation_provenance.derived_at,
                options,
            ),
        )?;
        push_line(
            output,
            "Derivation notes",
            format_optional_str(
                artifact
                    .contract_basis
                    .derivation_provenance
                    .notes
                    .as_deref(),
            ),
        )?;
        push_line(
            output,
            "Source survey semantic hash",
            artifact
                .contract_basis
                .core_semantic_basis
                .source_survey_semantic_hash
                .clone(),
        )?;
        push_line(
            output,
            "Policy semantic hash",
            artifact
                .contract_basis
                .core_semantic_basis
                .policy_semantic_hash
                .clone(),
        )?;
    }
    push_line(
        output,
        "Enabled extensions",
        artifact
            .contract_basis
            .extension_basis
            .as_ref()
            .map(|basis| join_or_placeholder(&basis.enabled_extension_namespaces))
            .unwrap_or_else(|| "<none>".to_string()),
    )?;
    if let Some(value) = payload.extension_contract.get(PYTHON_RUNTIME_NAMESPACE) {
        let contract = decode_python_runtime_contract_from_value(value).map_err(|error| {
            InspectError::new(
                InspectErrorCode::InspectInputInvalid,
                "inspect_decode",
                error.message,
            )
        })?;
        push_line(
            output,
            "Python runtime extension",
            format_python_runtime_contract_for_inspect(&contract),
        )?;
    }
    if let Some(value) = payload.extension_contract.get(NODE_RUNTIME_NAMESPACE) {
        let contract = decode_node_runtime_contract_from_value(value).map_err(|error| {
            InspectError::new(
                InspectErrorCode::InspectInputInvalid,
                "inspect_decode",
                error.message,
            )
        })?;
        push_line(
            output,
            "Node runtime extension",
            format_node_runtime_contract_for_inspect(&contract),
        )?;
    }

    Ok(())
}

fn render_service_profile_summary(
    output: &mut String,
    artifact: &ServiceProfileV1,
) -> Result<(), InspectError> {
    push_line(output, "Profile id", artifact.profile.profile_id.clone())?;
    push_line(
        output,
        "Primary capability class",
        artifact
            .profile
            .core_requirements
            .primary_capability_class
            .clone(),
    )?;
    push_line(
        output,
        "Allowed visibility scopes",
        artifact
            .profile
            .core_requirements
            .allowed_visibility_scopes
            .iter()
            .map(format_visibility_scope)
            .collect::<Vec<_>>()
            .join(", "),
    )?;
    push_line(
        output,
        "Minimum allocatable CPU",
        artifact
            .profile
            .core_requirements
            .min_allocatable_cpu_logical_cores
            .map(|value| value.to_string())
            .unwrap_or_else(|| "<none>".to_string()),
    )?;
    push_line(
        output,
        "Minimum allocatable memory",
        artifact
            .profile
            .core_requirements
            .min_allocatable_memory_bytes
            .map(format_bytes)
            .unwrap_or_else(|| "<none>".to_string()),
    )?;
    push_line(
        output,
        "Minimum non-loopback interfaces",
        artifact
            .profile
            .core_requirements
            .min_non_loopback_interfaces
            .map(|value| value.to_string())
            .unwrap_or_else(|| "<none>".to_string()),
    )?;
    push_line(
        output,
        "Minimum network link speed",
        artifact
            .profile
            .core_requirements
            .min_network_link_speed_mbps
            .map(|value| format!("{value} Mbps"))
            .unwrap_or_else(|| "<none>".to_string()),
    )?;
    push_line(
        output,
        "Required network interface kinds",
        if artifact
            .profile
            .core_requirements
            .required_network_interface_kinds
            .is_empty()
        {
            "<none>".to_string()
        } else {
            artifact
                .profile
                .core_requirements
                .required_network_interface_kinds
                .iter()
                .map(|kind| kind.as_str().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        },
    )?;
    push_line(
        output,
        "Minimum NUMA nodes",
        artifact
            .profile
            .core_requirements
            .min_numa_nodes
            .map(|value| value.to_string())
            .unwrap_or_else(|| "<none>".to_string()),
    )?;
    push_line(
        output,
        "Maximum NUMA nodes",
        artifact
            .profile
            .core_requirements
            .max_numa_nodes
            .map(|value| value.to_string())
            .unwrap_or_else(|| "<none>".to_string()),
    )?;
    push_line(
        output,
        "Minimum CPU packages",
        artifact
            .profile
            .core_requirements
            .min_cpu_packages
            .map(|value| value.to_string())
            .unwrap_or_else(|| "<none>".to_string()),
    )?;
    push_line(
        output,
        "Extension requirement namespaces",
        if artifact.profile.extension_requirements.is_empty() {
            "<none>".to_string()
        } else {
            artifact
                .profile
                .extension_requirements
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        },
    )?;
    if let Some(value) = artifact
        .profile
        .extension_requirements
        .get(PYTHON_RUNTIME_NAMESPACE)
    {
        let requirement = decode_python_runtime_requirement_from_value(value).map_err(|error| {
            InspectError::new(
                InspectErrorCode::InspectInputInvalid,
                "inspect_decode",
                error.message,
            )
        })?;
        push_line(
            output,
            "Python runtime requirement",
            format_python_runtime_requirement_for_inspect(&requirement),
        )?;
    }
    if let Some(value) = artifact
        .profile
        .extension_requirements
        .get(NODE_RUNTIME_NAMESPACE)
    {
        let requirement = decode_node_runtime_requirement_from_value(value).map_err(|error| {
            InspectError::new(
                InspectErrorCode::InspectInputInvalid,
                "inspect_decode",
                error.message,
            )
        })?;
        push_line(
            output,
            "Node runtime requirement",
            format_node_runtime_requirement_for_inspect(&requirement),
        )?;
    }
    push_line(
        output,
        "Preferred visibility scope",
        artifact
            .profile
            .preferences
            .preferred_visibility_scope
            .as_ref()
            .map(format_visibility_scope)
            .unwrap_or("<none>")
            .to_string(),
    )?;
    push_line(
        output,
        "Forbidden capability classes",
        join_or_placeholder(&artifact.profile.exclusions.forbidden_capability_classes),
    )?;
    push_line(
        output,
        "Degradation ladder",
        format_degradation_ladder(&artifact.profile.degradation_ladder),
    )?;
    push_line(
        output,
        "Assurance predicates",
        format_assurance_predicates(&artifact.profile.assurance_predicates),
    )?;
    push_line(
        output,
        "Explicit assurance requirements",
        format_explicit_assurance_requirements(&artifact.profile.assurance_requirements),
    )?;

    Ok(())
}

fn render_state_summary(
    output: &mut String,
    artifact: &HostStateV1,
    options: InspectRenderOptionsV1,
) -> Result<(), InspectError> {
    push_line(output, "Host alias", artifact.state.host_alias.clone())?;
    push_line(
        output,
        "Collection mode",
        artifact.state.collection_mode.as_str(),
    )?;
    if options.verbose {
        push_line(output, "Snapshot id", artifact.state.snapshot_id.clone())?;
        push_line(output, "Source ref", artifact.state.source_ref.clone())?;
    }
    push_line(
        output,
        "Freshness state",
        artifact.state.core_state.freshness.freshness_state.as_str(),
    )?;
    push_line(
        output,
        "Observed at",
        format_timestamp_for_inspect(&artifact.state.core_state.freshness.observed_at, options),
    )?;
    push_line(
        output,
        "Allocatable CPU",
        format_state_field(
            &artifact
                .state
                .core_state
                .resources
                .allocatable_cpu_logical_cores,
            |value| value.to_string(),
        ),
    )?;
    push_line(
        output,
        "Memory total",
        format_state_field(
            &artifact.state.core_state.resources.memory_total_bytes,
            |value| format_bytes(*value),
        ),
    )?;
    push_line(
        output,
        "Allocatable memory",
        format_state_field(
            &artifact.state.core_state.resources.allocatable_memory_bytes,
            |value| format_bytes(*value),
        ),
    )?;
    push_line(
        output,
        "Memory used excluding cache",
        format_state_field(
            &artifact
                .state
                .core_state
                .resources
                .memory_used_excluding_cache_bytes,
            |value| format_bytes(*value),
        ),
    )?;
    push_line(
        output,
        "Cgroup version",
        format_state_field(
            &artifact.state.core_state.boundaries.cgroup_version,
            |value| value.clone(),
        ),
    )?;
    push_line(
        output,
        "Cpuset CPU ceiling",
        format_state_field(
            &artifact
                .state
                .core_state
                .boundaries
                .cpuset_cpu_logical_cores,
            |value| value.to_string(),
        ),
    )?;
    push_line(
        output,
        "CPU quota ceiling",
        format_state_field(
            &artifact.state.core_state.boundaries.cpu_quota_logical_cores,
            |value| value.to_string(),
        ),
    )?;
    push_line(
        output,
        "Memory limit",
        format_state_field(
            &artifact.state.core_state.boundaries.memory_limit_bytes,
            |value| format_bytes(*value),
        ),
    )?;
    push_line(
        output,
        "Memory current",
        format_state_field(
            &artifact.state.core_state.boundaries.memory_current_bytes,
            |value| format_bytes(*value),
        ),
    )?;
    push_line(
        output,
        "Visible NUMA nodes",
        format_state_field(
            &artifact.state.core_state.topology.visible_numa_nodes,
            |value| value.to_string(),
        ),
    )?;
    push_line(
        output,
        "Degraded capability classes",
        join_or_placeholder(
            &artifact
                .state
                .core_state
                .operability
                .degraded_capability_classes,
        ),
    )?;

    Ok(())
}

fn render_validation_report_summary(
    output: &mut String,
    artifact: &ValidationReportV1,
    options: InspectRenderOptionsV1,
) -> Result<(), InspectError> {
    // Validation inspect is organised around the decision chain: verdict, failed requirements,
    // evidence/policy references, and remediation.
    push_line(
        output,
        "Validation mode",
        format_validation_mode(artifact.validation_basis.validation_mode),
    )?;
    push_line(
        output,
        "Verdict",
        format_validation_verdict(artifact.report.verdict),
    )?;
    push_line(
        output,
        "Primary reason code",
        format_validation_reason_code(artifact.report.primary_reason_code),
    )?;
    push_line(output, "Summary", artifact.report.summary.clone())?;
    push_line(
        output,
        "Selected degradation tier",
        artifact
            .report
            .selected_degradation_tier
            .clone()
            .unwrap_or_else(|| "<none>".to_string()),
    )?;
    push_line(
        output,
        "Matched requirements",
        join_or_placeholder(&artifact.report.matched_requirements),
    )?;
    push_line(
        output,
        format_validation_requirement_label(&artifact.report),
        join_or_placeholder(&artifact.report.failed_requirements),
    )?;
    push_line(
        output,
        "Policy refs",
        join_or_placeholder(&artifact.report.policy_refs),
    )?;
    push_line(
        output,
        "Evidence refs",
        join_or_placeholder(&artifact.report.evidence_refs),
    )?;
    push_line(
        output,
        "Warnings",
        join_or_placeholder(&artifact.report.warnings),
    )?;
    push_line(
        output,
        "Explanations",
        join_or_placeholder(
            &artifact
                .report
                .explanations
                .iter()
                .map(|entry| format!("{}: {}", entry.explanation_id, entry.summary))
                .collect::<Vec<_>>(),
        ),
    )?;
    push_line(
        output,
        "Remediation hints",
        join_or_placeholder(
            &artifact
                .report
                .remediation_hints
                .iter()
                .map(|entry| format!("{}: {}", entry.hint_id, entry.summary))
                .collect::<Vec<_>>(),
        ),
    )?;
    push_line(
        output,
        "Remediation actions",
        join_or_placeholder(
            &artifact
                .report
                .remediation_hints
                .iter()
                .flat_map(|hint| {
                    hint.actions
                        .iter()
                        .map(|action| format!("{}: {}", action.action_id, action.summary))
                })
                .collect::<Vec<_>>(),
        ),
    )?;
    push_line(
        output,
        "Contract artifact id",
        artifact.validation_basis.contract_artifact_id.clone(),
    )?;
    push_line(
        output,
        "Service profile artifact id",
        artifact
            .validation_basis
            .service_profile_artifact_id
            .clone(),
    )?;
    push_line(
        output,
        "State artifact id",
        artifact
            .validation_basis
            .state_artifact_id
            .clone()
            .unwrap_or_else(|| "<none>".to_string()),
    )?;
    if let Some(state_freshness) = format_validation_state_freshness(
        &artifact.validation_basis,
        &artifact.envelope.provenance.collected_at,
        options,
    ) {
        push_line(output, "State freshness", state_freshness)?;
    }

    Ok(())
}

fn render_recommendation_report_summary(
    output: &mut String,
    artifact: &RecommendationReportV1,
    options: InspectRenderOptionsV1,
) -> Result<(), InspectError> {
    push_line(
        output,
        "Referenced validation verdict",
        format_validation_verdict(artifact.recommendation_basis.validation_verdict),
    )?;
    push_line(
        output,
        "Recommendation class",
        artifact
            .report
            .recommendation_class
            .clone()
            .unwrap_or_else(|| "<none>".to_string()),
    )?;
    push_line(
        output,
        "Expected operating mode",
        artifact
            .report
            .expected_operating_mode
            .clone()
            .unwrap_or_else(|| "<none>".to_string()),
    )?;
    push_line(
        output,
        "Processing-time band",
        artifact
            .report
            .processing_time_band
            .clone()
            .unwrap_or_else(|| "<none>".to_string()),
    )?;
    push_line(
        output,
        "Throughput band",
        artifact
            .report
            .throughput_band
            .clone()
            .unwrap_or_else(|| "<none>".to_string()),
    )?;
    push_line(
        output,
        "Confidence",
        format_recommendation_confidence(artifact.report.confidence),
    )?;
    push_line(
        output,
        "Freshness",
        format!(
            "{}; {}",
            format_recommendation_freshness_state(artifact.report.freshness.freshness_state),
            format_timestamp_for_inspect(&artifact.report.freshness.observed_at, options)
        ),
    )?;
    push_line(output, "Summary", artifact.report.summary.clone())?;
    push_line(
        output,
        "Advisory reason ids",
        join_or_placeholder(&artifact.report.advisory_reason_ids),
    )?;
    push_line(
        output,
        "Validation report artifact id",
        artifact
            .recommendation_basis
            .validation_report_artifact_id
            .clone(),
    )?;
    push_line(
        output,
        "Recommendation pack",
        format!(
            "{}@{}",
            artifact.recommendation_basis.recommendation_pack_id,
            artifact.recommendation_basis.recommendation_pack_version
        ),
    )?;
    push_line(
        output,
        "Recommendation engine",
        format!(
            "{}@{}",
            artifact.recommendation_basis.recommendation_engine_id,
            artifact.recommendation_basis.recommendation_engine_version
        ),
    )?;
    push_line(
        output,
        "State artifact id",
        artifact
            .recommendation_basis
            .state_artifact_id
            .clone()
            .unwrap_or_else(|| "<none>".to_string()),
    )?;

    Ok(())
}

fn render_batch_classification_report_summary(
    output: &mut String,
    artifact: &BatchClassificationReportV1,
    options: InspectRenderOptionsV1,
) -> Result<(), InspectError> {
    let fit_rows = artifact
        .report
        .rows
        .iter()
        .filter(|row| matches!(row.verdict, ValidationVerdictV1::Fit))
        .count();
    let degraded_rows = artifact
        .report
        .rows
        .iter()
        .filter(|row| matches!(row.verdict, ValidationVerdictV1::FitWithDegradation))
        .count();
    let unfit_rows = artifact
        .report
        .rows
        .iter()
        .filter(|row| matches!(row.verdict, ValidationVerdictV1::Unfit))
        .count();
    let indeterminate_rows = artifact
        .report
        .rows
        .iter()
        .filter(|row| matches!(row.verdict, ValidationVerdictV1::Indeterminate))
        .count();

    push_line(
        output,
        "Validation mode",
        format_validation_mode(artifact.classification_basis.validation_mode),
    )?;
    push_line(
        output,
        "Validated at",
        format_timestamp_for_inspect(&artifact.classification_basis.validated_at, options),
    )?;
    push_line(
        output,
        "Contracts",
        join_or_placeholder(
            &artifact
                .classification_basis
                .ordered_contracts
                .iter()
                .map(|value| value.artifact_id.clone())
                .collect::<Vec<_>>(),
        ),
    )?;
    push_line(
        output,
        "Service profiles",
        join_or_placeholder(
            &artifact
                .classification_basis
                .ordered_service_profiles
                .iter()
                .map(|value| value.artifact_id.clone())
                .collect::<Vec<_>>(),
        ),
    )?;
    push_line(
        output,
        "Batch classification rows",
        artifact.report.rows.len().to_string(),
    )?;
    push_line(output, "Fit rows", fit_rows.to_string())?;
    push_line(
        output,
        "Fit-with-degradation rows",
        degraded_rows.to_string(),
    )?;
    push_line(output, "Unfit rows", unfit_rows.to_string())?;
    push_line(output, "Indeterminate rows", indeterminate_rows.to_string())?;
    push_line(
        output,
        "Contract summaries",
        artifact.report.contract_summaries.len().to_string(),
    )?;
    push_line(
        output,
        "Service-profile summaries",
        artifact.report.service_profile_summaries.len().to_string(),
    )?;

    Ok(())
}

fn render_metadata_section(
    output: &mut String,
    envelope: &ArtifactEnvelopeV1,
    collectors: Option<&[CollectorMetadataV1]>,
    options: InspectRenderOptionsV1,
) -> Result<(), InspectError> {
    // Metadata is rendered after the summary because provenance and signatures explain how the
    // artifact was produced, not what semantic claim it makes.
    if options.verbose {
        push_line(
            output,
            "Provenance source",
            envelope.provenance.source.clone(),
        )?;
    }
    push_line(
        output,
        "Collected at",
        format_timestamp_for_inspect(&envelope.provenance.collected_at, options),
    )?;
    push_line(
        output,
        "Tool version",
        format_optional_str(envelope.provenance.tool_version.as_deref()),
    )?;
    if options.verbose {
        push_line(
            output,
            "Command name",
            format_optional_str(envelope.provenance.command_name.as_deref()),
        )?;
        push_line(
            output,
            "Correlation id",
            format_optional_str(envelope.provenance.correlation_id.as_deref()),
        )?;
    }
    if options.verbose {
        if let Some(collectors) = collectors {
            push_line(output, "Collectors", format_collectors(collectors))?;
        }
    }
    push_line(
        output,
        "Redaction",
        format_redaction_state(envelope, options),
    )?;
    push_line(
        output,
        "Signatures",
        format_signature_state(&envelope.signatures),
    )?;
    if options.verbose || !envelope.signatures.is_empty() {
        push_line(
            output,
            "Signature key ids",
            format_signature_key_ids(&envelope.signatures),
        )?;
        push_line(
            output,
            "Signature namespaces",
            format_signature_namespaces(&envelope.signatures),
        )?;
    }
    Ok(())
}

fn format_network_addressability_for_verbose_inspect(value: &NetworkDetailsV1) -> String {
    let Some(summary) = value.addressability_summary.as_ref() else {
        return "<none>".to_string();
    };

    let families = summary
        .non_loopback_address_families
        .as_deref()
        .map(format_ip_address_families_for_inspect)
        .unwrap_or_else(|| "<not_collected>".to_string());
    let default_routes = summary
        .default_route_families
        .as_deref()
        .map(format_ip_address_families_for_inspect)
        .unwrap_or_else(|| "<not_collected>".to_string());

    format!("families {families}; default routes {default_routes}")
}

fn format_storage_filesystems_for_verbose_inspect(value: &StorageDetailsV1) -> String {
    if value.mount_details.is_empty() {
        return "<none>".to_string();
    }

    let mut tallies = BTreeMap::new();
    for detail in &value.mount_details {
        *tallies
            .entry(detail.filesystem_type.clone())
            .or_insert(0usize) += 1;
    }
    format_tally_map_for_inspect(&tallies, usize::MAX)
}

fn format_storage_roles_for_verbose_inspect(value: &StorageDetailsV1) -> String {
    if value.mount_details.is_empty() {
        return "<none>".to_string();
    }

    let mut tallies = BTreeMap::new();
    for detail in &value.mount_details {
        *tallies
            .entry(detail.role.as_str().to_string())
            .or_insert(0usize) += 1;
    }
    format_tally_map_for_inspect(&tallies, usize::MAX)
}

fn format_network_carrier_for_verbose_inspect(value: &NetworkDetailsV1) -> String {
    let mut up = 0usize;
    let mut down = 0usize;
    let mut unknown = 0usize;

    for detail in value
        .interface_details
        .iter()
        .filter(|detail| detail.interface_virtuality == NetworkInterfaceVirtualityV1::Physical)
    {
        match detail.carrier_state {
            NetworkCarrierStateV1::Up => up += 1,
            NetworkCarrierStateV1::Down => down += 1,
            NetworkCarrierStateV1::Unknown => unknown += 1,
        }
    }

    format!("physical up {up}; down {down}; unknown {unknown}")
}

fn format_network_duplex_for_verbose_inspect(value: &NetworkDetailsV1) -> String {
    let mut full = 0usize;
    let mut half = 0usize;
    let mut unknown = 0usize;

    for detail in value
        .interface_details
        .iter()
        .filter(|detail| detail.interface_virtuality == NetworkInterfaceVirtualityV1::Physical)
    {
        match detail.duplex {
            NetworkDuplexV1::Full => full += 1,
            NetworkDuplexV1::Half => half += 1,
            NetworkDuplexV1::Unknown => unknown += 1,
        }
    }

    format!("physical full {full}; half {half}; unknown {unknown}")
}
