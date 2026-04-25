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

mod field_diagnostic;
mod format;

use self::field_diagnostic::*;
use self::format::*;

use crate::artifacts::batch_classification_report_v1::BatchClassificationReportV1;
use crate::artifacts::config_bundle_v1::ConfigBundleV1;
use crate::artifacts::contract_v1::HostContractV1;
use crate::artifacts::decision_bundle_v1::DecisionBundleV1;
use crate::artifacts::envelope_v1::{ArtifactEnvelopeV1, SignatureEnvelopeV1};
use crate::artifacts::field_diagnostic_v1::{
    FieldDiagnosticProbeStatusV1, FieldDiagnosticSourceTierV1,
};
use crate::artifacts::metadata_v1::CollectorMetadataV1;
use crate::artifacts::recommendation_report_v1::{
    RecommendationConfidenceV1, RecommendationFreshnessStateV1, RecommendationReportV1,
};
use crate::artifacts::record_v1::{
    load_artifact_record_from_path, load_artifact_record_from_value, ArtifactRecordErrorCode,
    ArtifactRecordV1,
};
use crate::artifacts::schema_ids_v1::{
    is_supported_batch_classification_report_schema_id, RECOMMENDATION_REPORT_SCHEMA_ID,
};
use crate::artifacts::service_profile_v1::{
    AssurancePredicateV1, DegradationTierV1, ServiceProfileV1,
};
use crate::artifacts::state_v1::{HostRuntimeResourcesV1, HostStateV1, StateFieldV1};
use crate::artifacts::survey_v1::{decode_host_survey_payload, HostSurveyV1};
use crate::artifacts::validation_report_v1::ValidationReportV1;
use crate::classify::{
    load_batch_classification_report_from_path, load_batch_classification_report_from_value,
};
use crate::config::CudaEnvironmentSelectionKindV1;
use crate::contract::HostContractPayloadV1;
use crate::extensions::cuda_runtime_v1::{
    CudaDefaultViewFieldDiagnosticV1, CudaInstalledToolkitV1,
};
use crate::extensions::{
    decode_cuda_runtime_contract_from_value, decode_cuda_runtime_evidence_from_value,
    decode_cuda_runtime_requirement_from_value, decode_cuda_runtime_state_from_value,
    decode_cuda_runtime_validation_diagnostic_from_value, decode_node_runtime_contract_from_value,
    decode_node_runtime_evidence_from_value, decode_node_runtime_requirement_from_value,
    decode_python_runtime_contract_from_value, decode_python_runtime_evidence_from_value,
    decode_python_runtime_requirement_from_value, format_cuda_runtime_contract_for_inspect,
    format_cuda_runtime_evidence_for_inspect, format_cuda_runtime_requirement_for_inspect,
    format_cuda_runtime_state_for_inspect, format_cuda_runtime_validation_diagnostic_for_inspect,
    format_node_runtime_contract_for_inspect, format_node_runtime_evidence_for_inspect,
    format_node_runtime_requirement_for_inspect, format_python_runtime_contract_for_inspect,
    format_python_runtime_evidence_for_inspect, format_python_runtime_requirement_for_inspect,
    CudaRuntimeContractV1, CudaRuntimeDeviceStateV1, CudaRuntimeEvidenceV1, CudaRuntimeStateV1,
    CudaRuntimeVersionV1, CudaSelectedEnvironmentV1, CUDA_RUNTIME_NAMESPACE,
    NODE_RUNTIME_NAMESPACE, PYTHON_RUNTIME_NAMESPACE,
};
use crate::recommendation::{
    load_recommendation_report_from_path, load_recommendation_report_from_value,
};
use crate::survey::{
    AcceleratorDetailsV1, AcceleratorOperabilityV1, CpuCacheSummaryBasisV1, CpuCacheSummaryV1,
    CpuDetailsV1, NetworkCarrierStateV1, NetworkDetailsV1, NetworkDuplexV1,
    NetworkInterfaceVirtualityV1, ObservationLimitationReasonV1, ObservationStateV1,
    PrivilegeLevelV1, StorageDetailsV1, SurveyFieldV1, TopologyDetailsV1, VisibilityScopeV1,
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
pub enum InspectViewV1 {
    #[default]
    Summary,
    Coverage,
    Matrix,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum InspectPaletteV1 {
    #[default]
    Default,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InspectStyleOptionsV1 {
    pub color_enabled: bool,
    pub palette: InspectPaletteV1,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InspectRenderOptionsV1 {
    pub verbose: bool,
    pub show_identifiers: bool,
    pub style: InspectStyleOptionsV1,
    pub view: InspectViewV1,
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

    if is_supported_batch_classification_report_schema_id(&schema_id) {
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

    if is_supported_batch_classification_report_schema_id(&schema_id) {
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

    writeln!(
        &mut output,
        "{}",
        match options.view {
            InspectViewV1::Summary => "Summary",
            InspectViewV1::Coverage => "Coverage",
            InspectViewV1::Matrix => "Matrix",
        }
    )
    .map_err(|error| {
        InspectError::new(
            InspectErrorCode::InspectRenderFailed,
            "inspect_render",
            format!("failed to render summary header: {error}"),
        )
    })?;

    let collectors = match (artifact, options.view) {
        (InspectArtifactV1::Core(artifact), InspectViewV1::Summary) => {
            render_core_inspect_summary_view(&mut output, artifact, options)?
        }
        (InspectArtifactV1::Core(artifact), InspectViewV1::Coverage) => {
            render_core_inspect_coverage_view(&mut output, artifact, options)?
        }
        (InspectArtifactV1::BatchClassificationReport(artifact), InspectViewV1::Summary) => {
            render_batch_classification_report_summary(&mut output, artifact, options)?;
            None
        }
        (InspectArtifactV1::BatchClassificationReport(_), InspectViewV1::Coverage) => {
            return Err(InspectError::new(
                InspectErrorCode::InspectInputInvalid,
                "inspect_view_select",
                "coverage view is supported only for survey, contract, and state artifacts",
            ));
        }
        (InspectArtifactV1::BatchClassificationReport(artifact), InspectViewV1::Matrix) => {
            render_batch_classification_report_matrix(&mut output, artifact, options)?;
            None
        }
        (InspectArtifactV1::RecommendationReport(artifact), InspectViewV1::Summary) => {
            render_recommendation_report_summary(&mut output, artifact, options)?;
            None
        }
        (InspectArtifactV1::RecommendationReport(_), InspectViewV1::Coverage) => {
            return Err(InspectError::new(
                InspectErrorCode::InspectInputInvalid,
                "inspect_view_select",
                "coverage view is supported only for survey, contract, and state artifacts",
            ));
        }
        (_, InspectViewV1::Matrix) => {
            return Err(InspectError::new(
                InspectErrorCode::InspectInputInvalid,
                "inspect_view_select",
                "matrix view is supported only for batch-classification report artifacts",
            ));
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

    push_summary_group_header(output, "Host")?;
    let host_alias = payload.host_alias.clone();
    push_summary_group_line(output, "Host alias", &host_alias)?;
    if should_render_survey_summary_hostname_line(
        &host_alias,
        &payload.core_evidence.observations.hostname,
        options,
    ) {
        let hostname = if options.verbose {
            format_survey_field(&payload.core_evidence.observations.hostname, |value| {
                value.clone()
            })
        } else {
            format_survey_field_compact(&payload.core_evidence.observations.hostname, |value| {
                value.clone()
            })
        };
        push_summary_group_line(output, "Hostname", hostname)?;
    }
    push_summary_group_line(
        output,
        "Local stable identity",
        format_local_stable_identity_for_inspect(&payload.core_evidence.identity_summary, options),
    )?;

    push_summary_group_separator(output)?;
    push_summary_group_header(output, "Collection")?;
    push_summary_group_line(output, "Collection mode", payload.collection_mode)?;
    if options.verbose {
        push_summary_group_line(output, "Snapshot id", payload.snapshot_id)?;
        push_summary_group_line(output, "Source ref", payload.source_ref)?;
    }
    if options.verbose
        || !matches!(
            payload.core_evidence.execution_context.visibility_scope,
            VisibilityScopeV1::BareMetalLike
        )
    {
        push_summary_group_line(
            output,
            "Visibility scope",
            format_visibility_scope(&payload.core_evidence.execution_context.visibility_scope),
        )?;
    }
    push_summary_group_line(
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
        push_summary_group_line(
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
        push_summary_group_line(
            output,
            "Execution notes",
            join_or_placeholder(&payload.core_evidence.execution_context.notes),
        )?;
    }

    push_summary_group_separator(output)?;
    push_summary_group_header(output, "Core")?;
    push_summary_group_line(
        output,
        "CPU",
        if options.verbose {
            format_survey_field(&payload.core_evidence.observations.cpu, |value| {
                format_cpu_details_for_inspect(value, options)
            })
        } else {
            format_survey_field_compact(&payload.core_evidence.observations.cpu, |value| {
                format_cpu_details_for_inspect(value, options)
            })
        },
    )?;
    push_summary_group_line(
        output,
        "Memory total",
        if options.verbose {
            format_survey_field(&payload.core_evidence.observations.memory, |value| {
                format_bytes(value.total_bytes)
            })
        } else {
            format_survey_field_compact(&payload.core_evidence.observations.memory, |value| {
                format_bytes_human_first(value.total_bytes)
            })
        },
    )?;
    push_summary_group_line(
        output,
        "Storage",
        if options.verbose {
            format_survey_field(&payload.core_evidence.observations.storage, |value| {
                format_storage_details_for_inspect(value)
            })
        } else {
            format_survey_field_compact(&payload.core_evidence.observations.storage, |value| {
                format_storage_details_for_inspect(value)
            })
        },
    )?;
    if options.verbose {
        if let Some(value) = payload.core_evidence.observations.storage.value.as_ref() {
            push_summary_group_line(
                output,
                "Storage filesystems",
                format_storage_filesystems_for_verbose_inspect(value),
            )?;
            push_summary_group_line(
                output,
                "Storage roles",
                format_storage_roles_for_verbose_inspect(value),
            )?;
        }
    }
    push_summary_group_line(
        output,
        "Network",
        if options.verbose {
            format_survey_field(&payload.core_evidence.observations.network, |value| {
                format_network_details_for_inspect(value)
            })
        } else {
            format_survey_field_compact(&payload.core_evidence.observations.network, |value| {
                format_network_details_for_inspect(value)
            })
        },
    )?;
    if options.verbose {
        if let Some(value) = payload.core_evidence.observations.network.value.as_ref() {
            push_summary_group_line(
                output,
                "Network addressability",
                format_network_addressability_for_verbose_inspect(value),
            )?;
            push_summary_group_line(
                output,
                "Network carrier",
                format_network_carrier_for_verbose_inspect(value),
            )?;
            push_summary_group_line(
                output,
                "Network duplex",
                format_network_duplex_for_verbose_inspect(value),
            )?;
        }
    }

    push_summary_group_separator(output)?;
    push_summary_group_header(output, "Accelerators")?;
    if options.verbose
        || !try_render_compact_survey_accelerator_lines_grouped(
            output,
            &payload.core_evidence.observations.accelerators,
        )?
    {
        push_summary_group_line(
            output,
            "Graphics / accelerators",
            if options.verbose {
                format_survey_field(&payload.core_evidence.observations.accelerators, |value| {
                    format_accelerator_details_for_inspect(value, options)
                })
            } else {
                format_survey_field_compact(
                    &payload.core_evidence.observations.accelerators,
                    |value| format_accelerator_details_for_inspect(value, options),
                )
            },
        )?;
    }
    if let Some(value) = payload.extension_evidence.get(CUDA_RUNTIME_NAMESPACE) {
        let evidence = decode_cuda_runtime_evidence_from_value(value).map_err(|error| {
            InspectError::new(
                InspectErrorCode::InspectInputInvalid,
                "inspect_decode",
                error.message,
            )
        })?;
        render_cuda_runtime_evidence_summary_grouped(output, &evidence, options)?;
    }

    let render_context_group = options.verbose
        || should_render_survey_summary_topology_line(
            &payload.core_evidence.observations.topology,
            options,
        )
        || payload
            .extension_evidence
            .contains_key(PYTHON_RUNTIME_NAMESPACE)
        || payload
            .extension_evidence
            .contains_key(NODE_RUNTIME_NAMESPACE);
    if render_context_group {
        push_summary_group_separator(output)?;
        push_summary_group_header(output, "Context")?;
        push_survey_summary_topology_line(
            output,
            "Topology",
            &payload.core_evidence.observations.topology,
            options,
            |value| {
                format!(
                    "{} NUMA nodes; {} CPU packages",
                    value.numa_nodes, value.cpu_packages
                )
            },
        )?;
    }
    if let Some(value) = payload.extension_evidence.get(PYTHON_RUNTIME_NAMESPACE) {
        let evidence = decode_python_runtime_evidence_from_value(value).map_err(|error| {
            InspectError::new(
                InspectErrorCode::InspectInputInvalid,
                "inspect_decode",
                error.message,
            )
        })?;
        push_summary_group_line(
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
        push_summary_group_line(
            output,
            "Node runtime extension",
            format_node_runtime_evidence_for_inspect(&evidence, true),
        )?;
    }

    let render_provenance_group = options.verbose || options.show_identifiers;
    if render_provenance_group {
        push_summary_group_separator(output)?;
        push_summary_group_header(output, "Provenance")?;
    }
    push_survey_summary_value_line(
        output,
        "Composition digest",
        format_identifier_value_for_inspect(
            &payload.core_evidence.identity_summary.composition_digest,
            options,
        ),
        options,
        SurveySummaryCompactLinePolicyV1::HideInCompactUnlessShowIdentifiers,
    )?;
    push_survey_summary_value_line(
        output,
        "Provenance fingerprint",
        format_identifier_value_for_inspect(
            &payload
                .core_evidence
                .identity_summary
                .provenance_fingerprint,
            options,
        ),
        options,
        SurveySummaryCompactLinePolicyV1::HideInCompactUnlessShowIdentifiers,
    )?;

    Ok(())
}

fn render_core_inspect_summary_view(
    output: &mut String,
    artifact: &ArtifactRecordV1,
    options: InspectRenderOptionsV1,
) -> Result<Option<Vec<CollectorMetadataV1>>, InspectError> {
    match artifact {
        ArtifactRecordV1::Survey(artifact) => {
            render_survey_summary(output, artifact, options)?;
            Ok(Some(
                decode_host_survey_payload(&artifact.survey)
                    .map_err(|error| {
                        InspectError::new(
                            InspectErrorCode::InspectInputInvalid,
                            "inspect_decode",
                            format!("failed to decode host survey payload for inspect: {error}"),
                        )
                    })?
                    .core_evidence
                    .collectors,
            ))
        }
        ArtifactRecordV1::Contract(artifact) => {
            render_contract_summary(output, artifact, options)?;
            Ok(None)
        }
        ArtifactRecordV1::ServiceProfile(artifact) => {
            render_service_profile_summary(output, artifact)?;
            Ok(None)
        }
        ArtifactRecordV1::State(artifact) => {
            render_state_summary(output, artifact, options)?;
            Ok(Some(artifact.state.core_state.collectors.clone()))
        }
        ArtifactRecordV1::ValidationReport(artifact) => {
            render_validation_report_summary(output, artifact, options)?;
            Ok(None)
        }
        ArtifactRecordV1::ConfigBundle(artifact) => {
            render_config_bundle_summary(output, artifact)?;
            Ok(None)
        }
        ArtifactRecordV1::DecisionBundle(artifact) => {
            render_decision_bundle_summary(output, artifact, options)?;
            Ok(None)
        }
    }
}

fn render_core_inspect_coverage_view(
    output: &mut String,
    artifact: &ArtifactRecordV1,
    options: InspectRenderOptionsV1,
) -> Result<Option<Vec<CollectorMetadataV1>>, InspectError> {
    match artifact {
        ArtifactRecordV1::Survey(artifact) => {
            render_survey_coverage(output, artifact, options)?;
            Ok(Some(
                decode_host_survey_payload(&artifact.survey)
                    .map_err(|error| {
                        InspectError::new(
                            InspectErrorCode::InspectInputInvalid,
                            "inspect_decode",
                            format!("failed to decode host survey payload for inspect: {error}"),
                        )
                    })?
                    .core_evidence
                    .collectors,
            ))
        }
        ArtifactRecordV1::Contract(artifact) => {
            render_contract_coverage(output, artifact, options)?;
            Ok(None)
        }
        ArtifactRecordV1::State(artifact) => {
            render_state_coverage(output, artifact, options)?;
            Ok(Some(artifact.state.core_state.collectors.clone()))
        }
        _ => Err(InspectError::new(
            InspectErrorCode::InspectInputInvalid,
            "inspect_view_select",
            "coverage view is supported only for survey, contract, and state artifacts",
        )),
    }
}

fn render_survey_coverage(
    output: &mut String,
    artifact: &HostSurveyV1,
    _options: InspectRenderOptionsV1,
) -> Result<(), InspectError> {
    let payload = decode_host_survey_payload(&artifact.survey).map_err(|error| {
        InspectError::new(
            InspectErrorCode::InspectInputInvalid,
            "inspect_decode",
            format!("failed to decode host survey payload for inspect: {error}"),
        )
    })?;

    push_summary_group_header(output, "Host")?;
    push_summary_group_line(
        output,
        "Hostname",
        format_survey_field_coverage(&payload.core_evidence.observations.hostname),
    )?;
    push_summary_group_line(output, "Local stable identity", "present".to_string())?;

    push_summary_group_separator(output)?;
    push_summary_group_header(output, "Collection")?;
    push_summary_group_line(output, "Visibility scope", "present")?;
    push_summary_group_line(output, "Privilege level", "present")?;

    push_summary_group_separator(output)?;
    push_summary_group_header(output, "Core")?;
    push_summary_group_line(
        output,
        "CPU",
        format_survey_field_coverage(&payload.core_evidence.observations.cpu),
    )?;
    push_summary_group_line(
        output,
        "Memory total",
        format_survey_field_coverage(&payload.core_evidence.observations.memory),
    )?;
    push_summary_group_line(
        output,
        "Storage",
        format_survey_field_coverage(&payload.core_evidence.observations.storage),
    )?;
    push_summary_group_line(
        output,
        "Network",
        format_survey_field_coverage(&payload.core_evidence.observations.network),
    )?;

    push_summary_group_separator(output)?;
    push_summary_group_header(output, "Accelerators")?;
    push_summary_group_line(
        output,
        "Graphics / accelerators",
        format_survey_field_coverage(&payload.core_evidence.observations.accelerators),
    )?;
    if let Some(value) = payload.extension_evidence.get(CUDA_RUNTIME_NAMESPACE) {
        let evidence = decode_cuda_runtime_evidence_from_value(value).map_err(|error| {
            InspectError::new(
                InspectErrorCode::InspectInputInvalid,
                "inspect_decode",
                error.message,
            )
        })?;
        push_summary_group_line(
            output,
            "CUDA runtime extension",
            format_evidence_state_coverage(evidence.runtime_state),
        )?;
        push_summary_group_line(
            output,
            "CUDA default toolkit version",
            format_optional_cuda_version_coverage(
                evidence.version.as_ref(),
                evidence
                    .default_view_probe_diagnostics
                    .as_ref()
                    .map(|diagnostics| &diagnostics.default_toolkit_version),
            )?,
        )?;
        push_summary_group_line(
            output,
            "CUDA driver version",
            format_optional_cuda_version_coverage(
                evidence.driver_version.as_ref(),
                evidence
                    .default_view_probe_diagnostics
                    .as_ref()
                    .map(|diagnostics| &diagnostics.driver_version),
            )?,
        )?;
        push_summary_group_line(
            output,
            "CUDA driver-supported CUDA",
            format_optional_cuda_version_coverage(
                evidence.driver_supported_cuda_version.as_ref(),
                evidence
                    .default_view_probe_diagnostics
                    .as_ref()
                    .map(|diagnostics| &diagnostics.driver_supported_cuda_version),
            )?,
        )?;
        push_summary_group_line(
            output,
            "CUDA default runtime version",
            format_optional_cuda_version_coverage(
                evidence.default_runtime_version.as_ref(),
                evidence
                    .default_view_probe_diagnostics
                    .as_ref()
                    .map(|diagnostics| &diagnostics.default_runtime_version),
            )?,
        )?;
        if evidence.selected_environment.is_some() {
            push_summary_group_line(output, "CUDA selected environment", "present")?;
            push_summary_group_line(
                output,
                "CUDA selected toolkit version",
                format_optional_cuda_version_coverage(
                    evidence.selected_environment_toolkit_version.as_ref(),
                    evidence
                        .selected_environment_probe_diagnostics
                        .as_ref()
                        .map(|diagnostics| &diagnostics.toolkit_version),
                )?,
            )?;
            push_summary_group_line(
                output,
                "CUDA selected runtime version",
                format_optional_cuda_version_coverage(
                    evidence.selected_environment_runtime_version.as_ref(),
                    evidence
                        .selected_environment_probe_diagnostics
                        .as_ref()
                        .map(|diagnostics| &diagnostics.runtime_version),
                )?,
            )?;
        }
    }

    push_summary_group_separator(output)?;
    push_summary_group_header(output, "Context")?;
    push_summary_group_line(
        output,
        "Topology",
        format_survey_field_coverage(&payload.core_evidence.observations.topology),
    )?;

    Ok(())
}

fn render_contract_coverage(
    output: &mut String,
    artifact: &HostContractV1,
    _options: InspectRenderOptionsV1,
) -> Result<(), InspectError> {
    let payload: HostContractPayloadV1 = serde_json::from_value(artifact.contract.clone())
        .map_err(|error| {
            InspectError::new(
                InspectErrorCode::InspectInputInvalid,
                "inspect_decode",
                format!("failed to decode host contract payload for inspect: {error}"),
            )
        })?;

    push_summary_group_header(output, "Host")?;
    push_summary_group_line(
        output,
        "Host alias",
        format_presence_coverage(artifact.host_alias.is_some()),
    )?;
    push_summary_group_line(output, "Local stable identity", "present")?;

    push_summary_group_separator(output)?;
    push_summary_group_header(output, "Collection")?;
    push_summary_group_line(output, "Visibility scope", "present")?;
    push_summary_group_line(
        output,
        "Container runtime",
        format_presence_coverage(
            payload
                .core_contract
                .execution_constraints
                .container_runtime
                .is_some(),
        ),
    )?;

    push_summary_group_separator(output)?;
    push_summary_group_header(output, "Core")?;
    push_summary_group_line(
        output,
        "Capability classes",
        format_presence_coverage(!payload.core_contract.capability_classes.is_empty()),
    )?;
    push_summary_group_line(output, "Network summary", "present")?;
    push_summary_group_line(
        output,
        "Storage summary",
        format_presence_coverage(
            payload
                .core_contract
                .storage_summary
                .total_block_devices
                .is_some()
                || payload.core_contract.storage_summary.total_mounts.is_some()
                || !payload
                    .core_contract
                    .storage_summary
                    .block_device_classes
                    .is_empty()
                || !payload
                    .core_contract
                    .storage_summary
                    .filesystem_types
                    .is_empty()
                || payload.core_contract.storage_summary.operability.is_some(),
        ),
    )?;

    push_summary_group_separator(output)?;
    push_summary_group_header(output, "Accelerators")?;
    push_summary_group_line(
        output,
        "Accelerator summary",
        format_presence_coverage(contract_accelerator_summary_present(
            &payload.core_contract.accelerator_summary,
        )),
    )?;
    if let Some(value) = payload.extension_contract.get(CUDA_RUNTIME_NAMESPACE) {
        let contract = decode_cuda_runtime_contract_from_value(value).map_err(|error| {
            InspectError::new(
                InspectErrorCode::InspectInputInvalid,
                "inspect_decode",
                error.message,
            )
        })?;
        push_summary_group_line(output, "CUDA runtime extension", "present")?;
        push_summary_group_line(
            output,
            "CUDA default toolkit version",
            format_optional_cuda_version_coverage(
                contract.version.as_ref(),
                contract
                    .default_view_probe_diagnostics
                    .as_ref()
                    .map(|diagnostics| &diagnostics.default_toolkit_version),
            )?,
        )?;
        push_summary_group_line(
            output,
            "CUDA driver version",
            format_optional_cuda_version_coverage(
                contract.driver_version.as_ref(),
                contract
                    .default_view_probe_diagnostics
                    .as_ref()
                    .map(|diagnostics| &diagnostics.driver_version),
            )?,
        )?;
        push_summary_group_line(
            output,
            "CUDA driver-supported CUDA",
            format_optional_cuda_version_coverage(
                contract.driver_supported_cuda_version.as_ref(),
                contract
                    .default_view_probe_diagnostics
                    .as_ref()
                    .map(|diagnostics| &diagnostics.driver_supported_cuda_version),
            )?,
        )?;
        push_summary_group_line(
            output,
            "CUDA default runtime version",
            format_optional_cuda_version_coverage(
                contract.default_runtime_version.as_ref(),
                contract
                    .default_view_probe_diagnostics
                    .as_ref()
                    .map(|diagnostics| &diagnostics.default_runtime_version),
            )?,
        )?;
    }

    push_summary_group_separator(output)?;
    push_summary_group_header(output, "Context")?;
    push_summary_group_line(output, "Topology summary", "present")?;

    Ok(())
}

fn render_state_coverage(
    output: &mut String,
    artifact: &HostStateV1,
    _options: InspectRenderOptionsV1,
) -> Result<(), InspectError> {
    push_summary_group_header(output, "Host")?;
    push_summary_group_line(output, "Host alias", "present")?;
    push_summary_group_line(
        output,
        "Local stable identity",
        format_presence_coverage(artifact.state.local_identity.is_some()),
    )?;

    push_summary_group_separator(output)?;
    push_summary_group_header(output, "Collection")?;
    push_summary_group_line(output, "Collection mode", "present")?;
    push_summary_group_line(output, "Freshness state", "present")?;

    push_summary_group_separator(output)?;
    push_summary_group_header(output, "Core")?;
    push_summary_group_line(
        output,
        "Allocatable CPU",
        format_state_field_coverage(
            &artifact
                .state
                .core_state
                .resources
                .allocatable_cpu_logical_cores,
        ),
    )?;
    push_summary_group_line(
        output,
        "Memory total",
        format_state_field_coverage(&artifact.state.core_state.resources.memory_total_bytes),
    )?;
    push_summary_group_line(
        output,
        "Allocatable memory",
        format_state_field_coverage(&artifact.state.core_state.resources.allocatable_memory_bytes),
    )?;
    push_summary_group_line(
        output,
        "Memory used excluding cache",
        format_state_field_coverage(
            &artifact
                .state
                .core_state
                .resources
                .memory_used_excluding_cache_bytes,
        ),
    )?;
    push_summary_group_line(
        output,
        "Cgroup version",
        format_state_field_coverage(&artifact.state.core_state.boundaries.cgroup_version),
    )?;

    push_summary_group_separator(output)?;
    push_summary_group_header(output, "Accelerators")?;
    if let Some(value) = artifact.state.extension_state.get(CUDA_RUNTIME_NAMESPACE) {
        let state = decode_cuda_runtime_state_from_value(value).map_err(|error| {
            InspectError::new(
                InspectErrorCode::InspectInputInvalid,
                "inspect_decode",
                error.message,
            )
        })?;
        push_summary_group_line(
            output,
            "CUDA runtime state",
            format_observation_surface(&state.runtime_state, state.limitation_reason.as_ref()),
        )?;
        push_summary_group_line(
            output,
            "CUDA total memory",
            format_state_field_coverage(&state.total_memory_bytes),
        )?;
        push_summary_group_line(
            output,
            "CUDA allocatable memory",
            format_state_field_coverage(&state.allocatable_memory_bytes),
        )?;
        push_summary_group_line(
            output,
            "CUDA default toolkit version",
            format_cuda_state_version_coverage(
                &state.default_toolkit_version,
                state
                    .default_view_probe_diagnostics
                    .as_ref()
                    .map(|diagnostics| &diagnostics.default_toolkit_version),
            )?,
        )?;
        push_summary_group_line(
            output,
            "CUDA driver version",
            format_cuda_state_version_coverage(
                &state.driver_version,
                state
                    .default_view_probe_diagnostics
                    .as_ref()
                    .map(|diagnostics| &diagnostics.driver_version),
            )?,
        )?;
        push_summary_group_line(
            output,
            "CUDA driver-supported CUDA",
            format_cuda_state_version_coverage(
                &state.driver_supported_cuda_version,
                state
                    .default_view_probe_diagnostics
                    .as_ref()
                    .map(|diagnostics| &diagnostics.driver_supported_cuda_version),
            )?,
        )?;
        push_summary_group_line(
            output,
            "CUDA default runtime version",
            format_cuda_state_version_coverage(
                &state.default_runtime_version,
                state
                    .default_view_probe_diagnostics
                    .as_ref()
                    .map(|diagnostics| &diagnostics.default_runtime_version),
            )?,
        )?;
        if state.selected_environment.is_some() {
            push_summary_group_line(output, "CUDA selected environment", "present")?;
            push_summary_group_line(
                output,
                "CUDA selected toolkit version",
                format_cuda_state_version_coverage(
                    &state.selected_environment_toolkit_version,
                    state
                        .selected_environment_probe_diagnostics
                        .as_ref()
                        .map(|diagnostics| &diagnostics.toolkit_version),
                )?,
            )?;
            push_summary_group_line(
                output,
                "CUDA selected runtime version",
                format_cuda_state_version_coverage(
                    &state.selected_environment_runtime_version,
                    state
                        .selected_environment_probe_diagnostics
                        .as_ref()
                        .map(|diagnostics| &diagnostics.runtime_version),
                )?,
            )?;
        }
    }

    push_summary_group_separator(output)?;
    push_summary_group_header(output, "Context")?;
    push_summary_group_line(
        output,
        "Visible NUMA nodes",
        format_state_field_coverage(&artifact.state.core_state.topology.visible_numa_nodes),
    )?;

    Ok(())
}

fn format_presence_coverage(present: bool) -> &'static str {
    if present {
        "present"
    } else {
        "absent"
    }
}

fn format_evidence_state_coverage(
    state: crate::extensions::CudaRuntimeEvidenceStateV1,
) -> &'static str {
    match state {
        crate::extensions::CudaRuntimeEvidenceStateV1::Observed => "observed",
        crate::extensions::CudaRuntimeEvidenceStateV1::NotFound => "missing",
    }
}

fn format_survey_field_coverage<T>(field: &SurveyFieldV1<T>) -> String {
    format_observation_surface(&field.state, field.limitation_reason.as_ref())
}

fn format_state_field_coverage<T>(field: &StateFieldV1<T>) -> String {
    format_observation_surface(&field.state, field.limitation_reason.as_ref())
}

fn contract_accelerator_summary_present(
    summary: &crate::contract::payload_v1::ContractAcceleratorSummaryV1,
) -> bool {
    summary.total_accelerators.is_some()
        || summary.gpu_accelerators.is_some()
        || summary.full_inventory_complete.is_some()
        || summary.policy_scoped_confirmed_accelerators.is_some()
        || summary.policy_scoped_unresolved_accelerators.is_some()
        || summary.policy_scoped_inventory_complete.is_some()
        || summary.integrated_accelerators.is_some()
        || summary.accelerators_with_known_memory.is_some()
        || summary.accelerators_with_known_numa_node.is_some()
        || summary.max_memory_bytes.is_some()
        || !summary.accelerator_numa_nodes.is_empty()
        || !summary.accelerator_kinds.is_empty()
        || !summary.vendors.is_empty()
        || !summary.families.is_empty()
        || !summary.models.is_empty()
        || summary.operability.is_some()
}

fn validate_field_diagnostic_for_coverage(
    diagnostic: &CudaDefaultViewFieldDiagnosticV1,
    value_observed: bool,
) -> Result<(), InspectError> {
    if diagnostic.source_ref.trim().is_empty() {
        return Err(InspectError::new(
            InspectErrorCode::InspectInputInvalid,
            "inspect_coverage_diagnostic_validate",
            "field diagnostic must use a non-blank source_ref",
        ));
    }
    if value_observed && diagnostic.status != FieldDiagnosticProbeStatusV1::Observed {
        return Err(InspectError::new(
            InspectErrorCode::InspectInputInvalid,
            "inspect_coverage_diagnostic_validate",
            "observed coverage fields must use observed diagnostics when diagnostics are present",
        ));
    }
    if !value_observed && diagnostic.status == FieldDiagnosticProbeStatusV1::Observed {
        return Err(InspectError::new(
            InspectErrorCode::InspectInputInvalid,
            "inspect_coverage_diagnostic_validate",
            "missing coverage fields must not use observed diagnostics when diagnostics are present",
        ));
    }
    Ok(())
}

fn format_coverage_with_diagnostic(
    base: &str,
    diagnostic: &CudaDefaultViewFieldDiagnosticV1,
    value_observed: bool,
) -> Result<String, InspectError> {
    validate_field_diagnostic_for_coverage(diagnostic, value_observed)?;
    if diagnostic.status == FieldDiagnosticProbeStatusV1::Observed {
        Ok(format!(
            "{base}; {} {} via {}",
            diagnostic.source_tier.as_str(),
            diagnostic.source_kind.as_str(),
            diagnostic.source_ref
        ))
    } else {
        Ok(format!(
            "{base}; {} {}; {} via {}",
            diagnostic.source_tier.as_str(),
            diagnostic.source_kind.as_str(),
            diagnostic.status.as_str(),
            diagnostic.source_ref
        ))
    }
}

fn format_optional_cuda_version_coverage(
    version: Option<&CudaRuntimeVersionV1>,
    diagnostic: Option<&CudaDefaultViewFieldDiagnosticV1>,
) -> Result<String, InspectError> {
    match (version, diagnostic) {
        (Some(_), Some(diagnostic)) => {
            format_coverage_with_diagnostic("observed", diagnostic, true)
        }
        (Some(_), None) => Ok("observed".to_string()),
        (None, Some(diagnostic)) => format_coverage_with_diagnostic("missing", diagnostic, false),
        (None, None) => Ok("missing".to_string()),
    }
}

fn format_cuda_state_version_coverage(
    field: &StateFieldV1<CudaRuntimeVersionV1>,
    diagnostic: Option<&CudaDefaultViewFieldDiagnosticV1>,
) -> Result<String, InspectError> {
    let observed = field.state == ObservationStateV1::Observed
        && field.limitation_reason.is_none()
        && field.value.is_some();
    let base = format_observation_surface(&field.state, field.limitation_reason.as_ref());
    match diagnostic {
        Some(diagnostic) => format_coverage_with_diagnostic(&base, diagnostic, observed),
        None => Ok(base),
    }
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

    if let Some(host_alias) = artifact.host_alias.as_deref() {
        push_line(output, "Host alias", host_alias)?;
    }
    if let Some(display_name) = artifact.display_name.as_deref() {
        push_line(output, "Display name", display_name)?;
    }
    if let Some(short_display_name) = artifact.short_display_name.as_deref() {
        push_line(output, "Short display name", short_display_name)?;
    }
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
        if !payload
            .core_contract
            .accelerator_summary
            .families
            .is_empty()
        {
            summary.push_str("; ");
            summary.push_str(&format!(
                "families {}",
                payload
                    .core_contract
                    .accelerator_summary
                    .families
                    .join(", ")
            ));
        }
        if !payload.core_contract.accelerator_summary.models.is_empty() {
            summary.push_str("; ");
            summary.push_str(&format!(
                "models {}",
                payload.core_contract.accelerator_summary.models.join(", ")
            ));
        }
        if let Some(integrated_accelerators) = payload
            .core_contract
            .accelerator_summary
            .integrated_accelerators
        {
            summary.push_str("; ");
            summary.push_str(&format!("{integrated_accelerators} integrated"));
        }
        if let Some(full_inventory_complete) = payload
            .core_contract
            .accelerator_summary
            .full_inventory_complete
        {
            summary.push_str("; ");
            summary.push_str(&format!(
                "full accelerator inventory {}",
                if full_inventory_complete {
                    "complete"
                } else {
                    "incomplete"
                }
            ));
        }
        if let (
            Some(confirmed_scoped),
            Some(unresolved_scoped),
            Some(policy_scoped_inventory_complete),
        ) = (
            payload
                .core_contract
                .accelerator_summary
                .policy_scoped_confirmed_accelerators,
            payload
                .core_contract
                .accelerator_summary
                .policy_scoped_unresolved_accelerators,
            payload
                .core_contract
                .accelerator_summary
                .policy_scoped_inventory_complete,
        ) {
            summary.push_str("; ");
            summary.push_str(&format!(
                "policy-scoped accelerator inventory {}; {} confirmed in-scope; {} unresolved in-scope",
                if policy_scoped_inventory_complete {
                    "complete"
                } else {
                    "incomplete"
                },
                confirmed_scoped,
                unresolved_scoped
            ));
        }
        if let Some(known_memory_devices) = payload
            .core_contract
            .accelerator_summary
            .accelerators_with_known_memory
        {
            summary.push_str("; ");
            summary.push_str(&format!("{known_memory_devices} known-memory"));
            if let Some(max_memory_bytes) =
                payload.core_contract.accelerator_summary.max_memory_bytes
            {
                summary.push_str("; ");
                summary.push_str(&format!(
                    "max memory {}",
                    format_bytes_compact(max_memory_bytes)
                ));
            }
        }
        if let Some(locality) = format_accelerator_locality_for_inspect(
            payload.core_contract.accelerator_summary.total_accelerators,
            payload
                .core_contract
                .accelerator_summary
                .accelerators_with_known_numa_node,
            &payload
                .core_contract
                .accelerator_summary
                .accelerator_numa_nodes,
        ) {
            summary.push_str("; ");
            summary.push_str(&locality);
        }
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
        format_local_stable_identity_for_inspect(&payload.core_contract.identity_summary, options),
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
    if let Some(value) = payload.extension_contract.get(CUDA_RUNTIME_NAMESPACE) {
        let contract = decode_cuda_runtime_contract_from_value(value).map_err(|error| {
            InspectError::new(
                InspectErrorCode::InspectInputInvalid,
                "inspect_decode",
                error.message,
            )
        })?;
        render_cuda_runtime_contract_summary(output, &contract, options)?;
    }
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
        "Display name",
        artifact
            .profile
            .display_name
            .clone()
            .unwrap_or_else(|| "<none>".to_string()),
    )?;
    push_line(
        output,
        "Short display name",
        artifact
            .profile
            .short_display_name
            .clone()
            .unwrap_or_else(|| "<none>".to_string()),
    )?;
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
        "Minimum policy-scoped accelerators",
        artifact
            .profile
            .core_requirements
            .min_policy_scoped_accelerators
            .map(|value| value.to_string())
            .unwrap_or_else(|| "<none>".to_string()),
    )?;
    push_line(
        output,
        "Require accelerator locality known",
        if artifact
            .profile
            .core_requirements
            .require_accelerator_locality_known
        {
            "yes".to_string()
        } else {
            "no".to_string()
        },
    )?;
    push_line(
        output,
        "Maximum accelerator NUMA nodes",
        artifact
            .profile
            .core_requirements
            .max_accelerator_numa_nodes
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
        .get(CUDA_RUNTIME_NAMESPACE)
    {
        let requirement = decode_cuda_runtime_requirement_from_value(value).map_err(|error| {
            InspectError::new(
                InspectErrorCode::InspectInputInvalid,
                "inspect_decode",
                error.message,
            )
        })?;
        push_line(
            output,
            "CUDA runtime requirement",
            format_cuda_runtime_requirement_for_inspect(&requirement),
        )?;
    }
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
    push_summary_group_header(output, "Host")?;
    push_summary_group_line(output, "Host alias", artifact.state.host_alias.clone())?;
    if let Some(local_identity) = artifact.state.local_identity.as_ref() {
        push_summary_group_line(
            output,
            "Local stable identity",
            format_state_local_identity_for_inspect(local_identity, options),
        )?;
    }

    push_summary_group_separator(output)?;
    push_summary_group_header(output, "Collection")?;
    push_summary_group_line(
        output,
        "Collection mode",
        artifact.state.collection_mode.as_str(),
    )?;
    if options.verbose {
        push_summary_group_line(output, "Snapshot id", artifact.state.snapshot_id.clone())?;
        push_summary_group_line(output, "Source ref", artifact.state.source_ref.clone())?;
    }
    push_summary_group_line(
        output,
        "Freshness state",
        artifact.state.core_state.freshness.freshness_state.as_str(),
    )?;
    push_summary_group_line(
        output,
        "Observed at",
        format_timestamp_for_inspect(&artifact.state.core_state.freshness.observed_at, options),
    )?;

    push_summary_group_separator(output)?;
    push_summary_group_header(output, "Core")?;
    push_summary_group_line(
        output,
        "Allocatable CPU",
        if options.verbose {
            format_state_field(
                &artifact
                    .state
                    .core_state
                    .resources
                    .allocatable_cpu_logical_cores,
                |value| value.to_string(),
            )
        } else {
            format_state_field_compact(
                &artifact
                    .state
                    .core_state
                    .resources
                    .allocatable_cpu_logical_cores,
                |value| value.to_string(),
            )
        },
    )?;
    let rendered_compact_memory = if options.verbose {
        false
    } else {
        try_render_compact_state_memory_summary_line(output, &artifact.state.core_state.resources)?
    };
    if options.verbose || !rendered_compact_memory {
        push_summary_group_line(
            output,
            "Memory total",
            if options.verbose {
                format_state_field(
                    &artifact.state.core_state.resources.memory_total_bytes,
                    |value| format_bytes(*value),
                )
            } else {
                format_state_field_compact(
                    &artifact.state.core_state.resources.memory_total_bytes,
                    |value| format_bytes_human_first(*value),
                )
            },
        )?;
        push_summary_group_line(
            output,
            "Allocatable memory",
            if options.verbose {
                format_state_field(
                    &artifact.state.core_state.resources.allocatable_memory_bytes,
                    |value| format_bytes(*value),
                )
            } else {
                format_state_field_compact(
                    &artifact.state.core_state.resources.allocatable_memory_bytes,
                    |value| format_bytes_human_first(*value),
                )
            },
        )?;
        push_summary_group_line(
            output,
            "Memory used excluding cache",
            if options.verbose {
                format_state_field(
                    &artifact
                        .state
                        .core_state
                        .resources
                        .memory_used_excluding_cache_bytes,
                    |value| format_bytes(*value),
                )
            } else {
                format_state_field_compact(
                    &artifact
                        .state
                        .core_state
                        .resources
                        .memory_used_excluding_cache_bytes,
                    |value| format_bytes_human_first(*value),
                )
            },
        )?;
    }
    push_state_summary_field_line(
        output,
        "Cgroup version",
        &artifact.state.core_state.boundaries.cgroup_version,
        options,
        StateSummaryCompactFieldPolicyV1::Always,
        |value| value.clone(),
    )?;
    if should_render_state_summary_cpuset_line(
        &artifact
            .state
            .core_state
            .resources
            .allocatable_cpu_logical_cores,
        &artifact
            .state
            .core_state
            .boundaries
            .cpuset_cpu_logical_cores,
        options,
    ) {
        push_state_summary_field_line(
            output,
            "Cpuset CPU ceiling",
            &artifact
                .state
                .core_state
                .boundaries
                .cpuset_cpu_logical_cores,
            options,
            StateSummaryCompactFieldPolicyV1::Always,
            |value| value.to_string(),
        )?;
    }
    push_state_summary_field_line(
        output,
        "CPU quota ceiling",
        &artifact.state.core_state.boundaries.cpu_quota_logical_cores,
        options,
        StateSummaryCompactFieldPolicyV1::HidePlainUnknown,
        |value| value.to_string(),
    )?;
    let memory_limit = &artifact.state.core_state.boundaries.memory_limit_bytes;
    if should_render_state_summary_field_line(
        memory_limit,
        options,
        StateSummaryCompactFieldPolicyV1::HidePlainUnknown,
    ) {
        push_summary_group_line(
            output,
            "Memory limit",
            if options.verbose {
                format_state_field(memory_limit, |value| format_bytes(*value))
            } else {
                format_state_field_compact(memory_limit, |value| format_bytes_human_first(*value))
            },
        )?;
    }
    let memory_current = &artifact.state.core_state.boundaries.memory_current_bytes;
    if should_render_state_summary_field_line(
        memory_current,
        options,
        StateSummaryCompactFieldPolicyV1::HidePlainUnknown,
    ) {
        push_summary_group_line(
            output,
            "Memory current",
            if options.verbose {
                format_state_field(memory_current, |value| format_bytes(*value))
            } else {
                format_state_field_compact(memory_current, |value| format_bytes_human_first(*value))
            },
        )?;
    }
    if artifact
        .state
        .extension_state
        .contains_key(CUDA_RUNTIME_NAMESPACE)
    {
        push_summary_group_separator(output)?;
        push_summary_group_header(output, "Accelerators")?;
    }
    if let Some(value) = artifact.state.extension_state.get(CUDA_RUNTIME_NAMESPACE) {
        let state = decode_cuda_runtime_state_from_value(value).map_err(|error| {
            InspectError::new(
                InspectErrorCode::InspectInputInvalid,
                "inspect_decode",
                error.message,
            )
        })?;
        render_cuda_runtime_state_summary_grouped(output, &state, options)?;
    }

    push_summary_group_separator(output)?;
    push_summary_group_header(output, "Context")?;
    push_state_summary_field_line(
        output,
        "Visible NUMA nodes",
        &artifact.state.core_state.topology.visible_numa_nodes,
        options,
        StateSummaryCompactFieldPolicyV1::Always,
        |value| value.to_string(),
    )?;
    push_state_summary_string_list_line(
        output,
        "Degraded capability classes",
        &artifact
            .state
            .core_state
            .operability
            .degraded_capability_classes,
        options,
        StateSummaryCompactListPolicyV1::HideWhenEmpty,
    )?;

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StateSummaryCompactFieldPolicyV1 {
    Always,
    HidePlainUnknown,
}

enum SurveySummaryCompactLinePolicyV1 {
    HideInCompactUnlessShowIdentifiers,
}

fn should_render_survey_summary_hostname_line(
    host_alias: &str,
    field: &SurveyFieldV1<String>,
    options: InspectRenderOptionsV1,
) -> bool {
    if options.verbose {
        return true;
    }

    !(field.state == ObservationStateV1::Observed
        && field.limitation_reason.is_none()
        && matches!(field.value.as_deref(), Some(value) if value == host_alias))
}

fn push_survey_summary_value_line(
    output: &mut String,
    label: &str,
    value: impl Into<String>,
    options: InspectRenderOptionsV1,
    compact_policy: SurveySummaryCompactLinePolicyV1,
) -> Result<(), InspectError> {
    let value = value.into();
    if should_render_survey_summary_value_line(options, compact_policy) {
        push_summary_group_line(output, label, value)?;
    }
    Ok(())
}

fn should_render_survey_summary_value_line(
    options: InspectRenderOptionsV1,
    compact_policy: SurveySummaryCompactLinePolicyV1,
) -> bool {
    if options.verbose {
        return true;
    }

    match compact_policy {
        SurveySummaryCompactLinePolicyV1::HideInCompactUnlessShowIdentifiers => {
            options.show_identifiers
        }
    }
}

fn push_survey_summary_topology_line(
    output: &mut String,
    label: &str,
    field: &SurveyFieldV1<TopologyDetailsV1>,
    options: InspectRenderOptionsV1,
    value_formatter: impl Fn(&TopologyDetailsV1) -> String,
) -> Result<(), InspectError> {
    if should_render_survey_summary_topology_line(field, options) {
        let rendered = if options.verbose {
            format_survey_field(field, value_formatter)
        } else {
            format_survey_field_compact(field, value_formatter)
        };
        push_summary_group_line(output, label, rendered)?;
    }
    Ok(())
}

fn should_render_survey_summary_topology_line(
    field: &SurveyFieldV1<TopologyDetailsV1>,
    options: InspectRenderOptionsV1,
) -> bool {
    if options.verbose {
        return true;
    }

    !(field.state == ObservationStateV1::Observed
        && field.limitation_reason.is_none()
        && matches!(
            field.value.as_ref(),
            Some(value) if value.numa_nodes == 1 && value.cpu_packages == 1
        ))
}

fn push_state_summary_field_line<T>(
    output: &mut String,
    label: &str,
    field: &StateFieldV1<T>,
    options: InspectRenderOptionsV1,
    compact_policy: StateSummaryCompactFieldPolicyV1,
    value_formatter: impl Fn(&T) -> String,
) -> Result<(), InspectError> {
    if !should_render_state_summary_field_line(field, options, compact_policy) {
        return Ok(());
    }

    let rendered = if options.verbose {
        format_state_field(field, value_formatter)
    } else {
        format_state_field_compact(field, value_formatter)
    };

    push_summary_group_line(output, label, rendered)
}

fn should_render_state_summary_field_line<T>(
    field: &StateFieldV1<T>,
    options: InspectRenderOptionsV1,
    compact_policy: StateSummaryCompactFieldPolicyV1,
) -> bool {
    if options.verbose {
        return true;
    }

    match compact_policy {
        StateSummaryCompactFieldPolicyV1::Always => true,
        StateSummaryCompactFieldPolicyV1::HidePlainUnknown => {
            !(field.state == ObservationStateV1::Unknown
                && field.limitation_reason.is_none()
                && field.value.is_none())
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StateSummaryCompactListPolicyV1 {
    HideWhenEmpty,
}

fn push_state_summary_string_list_line(
    output: &mut String,
    label: &str,
    values: &[String],
    options: InspectRenderOptionsV1,
    compact_policy: StateSummaryCompactListPolicyV1,
) -> Result<(), InspectError> {
    if !should_render_state_summary_string_list_line(values, options, compact_policy) {
        return Ok(());
    }

    push_summary_group_line(output, label, join_or_placeholder(values))
}

fn should_render_state_summary_string_list_line(
    values: &[String],
    options: InspectRenderOptionsV1,
    compact_policy: StateSummaryCompactListPolicyV1,
) -> bool {
    if options.verbose {
        return true;
    }

    match compact_policy {
        StateSummaryCompactListPolicyV1::HideWhenEmpty => !values.is_empty(),
    }
}

fn render_cuda_runtime_evidence_summary_grouped(
    output: &mut String,
    evidence: &CudaRuntimeEvidenceV1,
    options: InspectRenderOptionsV1,
) -> Result<(), InspectError> {
    let compact_default_view = if options.verbose {
        None
    } else {
        format_cuda_default_view_compact_line_for_evidence(evidence)
    };

    if options.verbose
        || evidence.runtime_state != crate::extensions::CudaRuntimeEvidenceStateV1::Observed
    {
        push_summary_group_line(
            output,
            "CUDA runtime extension",
            format_cuda_runtime_evidence_for_inspect(evidence, false),
        )?;
    }
    if let Some(default_view) = compact_default_view {
        push_summary_group_line(output, "CUDA default view", default_view)?;
    } else {
        push_optional_cuda_runtime_version_line_grouped(
            output,
            "CUDA default toolkit version",
            evidence.version.as_ref(),
            evidence
                .default_view_probe_diagnostics
                .as_ref()
                .map(|diagnostics| &diagnostics.default_toolkit_version),
        )?;
        push_optional_cuda_runtime_version_line_grouped(
            output,
            "CUDA driver version",
            evidence.driver_version.as_ref(),
            evidence
                .default_view_probe_diagnostics
                .as_ref()
                .map(|diagnostics| &diagnostics.driver_version),
        )?;
        push_optional_cuda_runtime_version_line_grouped(
            output,
            "CUDA driver-supported CUDA",
            evidence.driver_supported_cuda_version.as_ref(),
            evidence
                .default_view_probe_diagnostics
                .as_ref()
                .map(|diagnostics| &diagnostics.driver_supported_cuda_version),
        )?;
        push_optional_cuda_runtime_version_line_grouped(
            output,
            "CUDA default runtime version",
            evidence.default_runtime_version.as_ref(),
            evidence
                .default_view_probe_diagnostics
                .as_ref()
                .map(|diagnostics| &diagnostics.default_runtime_version),
        )?;
    }
    if let Some(selected_environment) = evidence.selected_environment.as_ref() {
        push_summary_group_line(
            output,
            "CUDA selected environment",
            format_cuda_selected_environment_for_inspect(selected_environment),
        )?;
    }
    push_optional_cuda_runtime_version_line_grouped(
        output,
        "CUDA selected toolkit version",
        evidence.selected_environment_toolkit_version.as_ref(),
        evidence
            .selected_environment_probe_diagnostics
            .as_ref()
            .map(|diagnostics| &diagnostics.toolkit_version),
    )?;
    push_optional_cuda_runtime_version_line_grouped(
        output,
        "CUDA selected runtime version",
        evidence.selected_environment_runtime_version.as_ref(),
        evidence
            .selected_environment_probe_diagnostics
            .as_ref()
            .map(|diagnostics| &diagnostics.runtime_version),
    )?;
    if should_render_cuda_installed_toolkit_summary_in_compact(
        &evidence.installed_toolkits,
        options,
    ) {
        push_summary_group_line(
            output,
            "Installed CUDA toolkits",
            format_cuda_installed_toolkit_summary_for_inspect(&evidence.installed_toolkits),
        )?;
    }
    if options.verbose {
        if let Some(path) = evidence.executable_path.as_deref() {
            push_summary_group_line(output, "CUDA executable path", path)?;
        }
        push_cuda_installed_toolkit_entries_grouped(output, &evidence.installed_toolkits)?;
    }
    Ok(())
}

fn render_cuda_runtime_contract_summary(
    output: &mut String,
    contract: &CudaRuntimeContractV1,
    options: InspectRenderOptionsV1,
) -> Result<(), InspectError> {
    push_line(
        output,
        "CUDA runtime extension",
        format_cuda_runtime_contract_for_inspect(contract),
    )?;
    push_optional_cuda_runtime_version_line(
        output,
        "CUDA default toolkit version",
        contract.version.as_ref(),
        contract
            .default_view_probe_diagnostics
            .as_ref()
            .map(|diagnostics| &diagnostics.default_toolkit_version),
    )?;
    push_optional_cuda_runtime_version_line(
        output,
        "CUDA driver version",
        contract.driver_version.as_ref(),
        contract
            .default_view_probe_diagnostics
            .as_ref()
            .map(|diagnostics| &diagnostics.driver_version),
    )?;
    push_optional_cuda_runtime_version_line(
        output,
        "CUDA driver-supported CUDA",
        contract.driver_supported_cuda_version.as_ref(),
        contract
            .default_view_probe_diagnostics
            .as_ref()
            .map(|diagnostics| &diagnostics.driver_supported_cuda_version),
    )?;
    push_optional_cuda_runtime_version_line(
        output,
        "CUDA default runtime version",
        contract.default_runtime_version.as_ref(),
        contract
            .default_view_probe_diagnostics
            .as_ref()
            .map(|diagnostics| &diagnostics.default_runtime_version),
    )?;
    if let Some(selected_environment) = contract.selected_environment.as_ref() {
        push_line(
            output,
            "CUDA selected environment",
            format_cuda_selected_environment_for_inspect(selected_environment),
        )?;
    }
    push_optional_cuda_runtime_version_line(
        output,
        "CUDA selected toolkit version",
        contract.selected_environment_toolkit_version.as_ref(),
        contract
            .selected_environment_probe_diagnostics
            .as_ref()
            .map(|diagnostics| &diagnostics.toolkit_version),
    )?;
    push_optional_cuda_runtime_version_line(
        output,
        "CUDA selected runtime version",
        contract.selected_environment_runtime_version.as_ref(),
        contract
            .selected_environment_probe_diagnostics
            .as_ref()
            .map(|diagnostics| &diagnostics.runtime_version),
    )?;
    if !contract.installed_toolkits.is_empty() {
        push_line(
            output,
            "Installed CUDA toolkits",
            format_cuda_installed_toolkit_summary_for_inspect(&contract.installed_toolkits),
        )?;
    }
    if options.verbose {
        push_cuda_installed_toolkit_entries(output, &contract.installed_toolkits)?;
    }
    Ok(())
}

fn render_cuda_runtime_state_summary_grouped(
    output: &mut String,
    state: &CudaRuntimeStateV1,
    options: InspectRenderOptionsV1,
) -> Result<(), InspectError> {
    let rendered_compact_devices = if options.verbose {
        false
    } else {
        try_render_compact_cuda_runtime_state_device_lines_grouped(output, state)?
    };

    if options.verbose || !rendered_compact_devices {
        push_summary_group_line(
            output,
            "CUDA runtime state",
            if options.verbose {
                format_cuda_runtime_state_for_inspect(state)
            } else {
                format_cuda_runtime_state_compact_for_inspect(state)
            },
        )?;
    }

    if let Some(default_view) = if options.verbose {
        None
    } else {
        format_cuda_default_view_compact_line_for_state(state)
    } {
        push_summary_group_line(output, "CUDA default view", default_view)?;
    } else {
        push_optional_cuda_runtime_state_version_line_grouped(
            output,
            "CUDA default toolkit version",
            &state.default_toolkit_version,
            state
                .default_view_probe_diagnostics
                .as_ref()
                .map(|diagnostics| &diagnostics.default_toolkit_version),
            options,
        )?;
        push_optional_cuda_runtime_state_version_line_grouped(
            output,
            "CUDA driver version",
            &state.driver_version,
            state
                .default_view_probe_diagnostics
                .as_ref()
                .map(|diagnostics| &diagnostics.driver_version),
            options,
        )?;
        push_optional_cuda_runtime_state_version_line_grouped(
            output,
            "CUDA driver-supported CUDA",
            &state.driver_supported_cuda_version,
            state
                .default_view_probe_diagnostics
                .as_ref()
                .map(|diagnostics| &diagnostics.driver_supported_cuda_version),
            options,
        )?;
        push_optional_cuda_runtime_state_version_line_grouped(
            output,
            "CUDA default runtime version",
            &state.default_runtime_version,
            state
                .default_view_probe_diagnostics
                .as_ref()
                .map(|diagnostics| &diagnostics.default_runtime_version),
            options,
        )?;
    }
    if let Some(selected_environment) = state.selected_environment.as_ref() {
        push_summary_group_line(
            output,
            "CUDA selected environment",
            format_cuda_selected_environment_for_inspect(selected_environment),
        )?;
    }
    push_optional_cuda_runtime_state_version_line_grouped(
        output,
        "CUDA selected toolkit version",
        &state.selected_environment_toolkit_version,
        state
            .selected_environment_probe_diagnostics
            .as_ref()
            .map(|diagnostics| &diagnostics.toolkit_version),
        options,
    )?;
    push_optional_cuda_runtime_state_version_line_grouped(
        output,
        "CUDA selected runtime version",
        &state.selected_environment_runtime_version,
        state
            .selected_environment_probe_diagnostics
            .as_ref()
            .map(|diagnostics| &diagnostics.runtime_version),
        options,
    )?;
    if options.verbose {
        if let Some(path) = state.probe_path.as_deref() {
            push_summary_group_line(output, "CUDA probe path", path)?;
        }
        push_cuda_runtime_device_lines_grouped(output, &state.devices)?;
    }
    Ok(())
}

fn format_cuda_selected_environment_for_inspect(
    selected_environment: &CudaSelectedEnvironmentV1,
) -> String {
    let kind = match selected_environment.selection.kind {
        CudaEnvironmentSelectionKindV1::DefaultView => "default_view".to_string(),
        CudaEnvironmentSelectionKindV1::ToolkitInstallRoot => format!(
            "toolkit_install_root; {}",
            selected_environment
                .selection
                .install_root
                .as_deref()
                .unwrap_or("<unknown>")
        ),
    };
    format!("{}; {}", selected_environment.environment_id, kind)
}

fn push_optional_cuda_runtime_version_line(
    output: &mut String,
    label: &str,
    version: Option<&CudaRuntimeVersionV1>,
    diagnostic: Option<&CudaDefaultViewFieldDiagnosticV1>,
) -> Result<(), InspectError> {
    if let Some(version) = version {
        push_line(
            output,
            label,
            format_cuda_runtime_version_value_with_diagnostic_for_inspect(version, diagnostic),
        )?;
    } else if let Some(diagnostic) = diagnostic {
        push_line(
            output,
            label,
            format_missing_field_diagnostic_for_inspect(diagnostic),
        )?;
    }
    Ok(())
}

fn push_optional_cuda_runtime_version_line_grouped(
    output: &mut String,
    label: &str,
    version: Option<&CudaRuntimeVersionV1>,
    diagnostic: Option<&CudaDefaultViewFieldDiagnosticV1>,
) -> Result<(), InspectError> {
    if let Some(version) = version {
        push_summary_group_line(
            output,
            label,
            format_cuda_runtime_version_value_with_diagnostic_for_inspect(version, diagnostic),
        )?;
    } else if let Some(diagnostic) = diagnostic {
        push_summary_group_line(
            output,
            label,
            format_missing_field_diagnostic_for_inspect(diagnostic),
        )?;
    }
    Ok(())
}

fn push_optional_cuda_runtime_state_version_line_grouped(
    output: &mut String,
    label: &str,
    field: &StateFieldV1<CudaRuntimeVersionV1>,
    diagnostic: Option<&CudaDefaultViewFieldDiagnosticV1>,
    options: InspectRenderOptionsV1,
) -> Result<(), InspectError> {
    if field.state != ObservationStateV1::Missing {
        let value = field.value.as_ref().ok_or_else(|| {
            InspectError::new(
                InspectErrorCode::InspectRenderFailed,
                "inspect_render",
                format!("state field {label} was not missing but had no value"),
            )
        })?;
        let rendered_value =
            format_cuda_runtime_version_value_with_diagnostic_for_inspect(value, diagnostic);
        let rendered = if options.verbose {
            format_state_field_rendered_value(
                &field.state,
                field.limitation_reason.as_ref(),
                rendered_value,
            )
        } else {
            format_state_field_rendered_value_compact(
                &field.state,
                field.limitation_reason.as_ref(),
                rendered_value,
            )
        };
        push_summary_group_line(output, label, rendered)?;
    } else if let Some(diagnostic) = diagnostic {
        push_summary_group_line(
            output,
            label,
            format_missing_field_diagnostic_for_inspect(diagnostic),
        )?;
    }
    Ok(())
}

fn try_render_compact_survey_accelerator_lines_grouped(
    output: &mut String,
    field: &SurveyFieldV1<AcceleratorDetailsV1>,
) -> Result<bool, InspectError> {
    if field.state != ObservationStateV1::Observed || field.limitation_reason.is_some() {
        return Ok(false);
    }
    let Some(value) = field.value.as_ref() else {
        return Ok(false);
    };
    if value.devices.is_empty() {
        return Ok(false);
    }

    push_summary_group_line(
        output,
        &format_accelerator_compact_count_label_for_inspect(value),
        value.devices.len().to_string(),
    )?;
    for (index, device) in value.devices.iter().enumerate() {
        push_summary_group_line(
            output,
            &format_accelerator_device_label_for_inspect(device, value.devices.len(), index),
            format_accelerator_device_value_for_inspect(
                device,
                value.operability.as_ref(),
                value.devices.len(),
            ),
        )?;
    }

    Ok(true)
}

fn try_render_compact_cuda_runtime_state_device_lines_grouped(
    output: &mut String,
    state: &CudaRuntimeStateV1,
) -> Result<bool, InspectError> {
    if state.runtime_state != ObservationStateV1::Observed || state.limitation_reason.is_some() {
        return Ok(false);
    }
    if state.devices.is_empty() {
        return Ok(false);
    }

    push_summary_group_line(
        output,
        "Observed CUDA devices",
        state.devices.len().to_string(),
    )?;
    push_cuda_runtime_device_lines_compact_grouped(output, &state.devices)?;
    Ok(true)
}

fn format_cuda_default_view_compact_line_for_evidence(
    evidence: &CudaRuntimeEvidenceV1,
) -> Option<String> {
    let diagnostics = evidence.default_view_probe_diagnostics.as_ref();
    let toolkit = evidence.version.as_ref()?;
    let driver = evidence.driver_version.as_ref()?;
    let supported = evidence.driver_supported_cuda_version.as_ref()?;
    let runtime = evidence.default_runtime_version.as_ref()?;

    if !cuda_default_view_compaction_allowed(
        diagnostics.map(|value| &value.default_toolkit_version),
    ) || !cuda_default_view_compaction_allowed(diagnostics.map(|value| &value.driver_version))
        || !cuda_default_view_compaction_allowed(
            diagnostics.map(|value| &value.driver_supported_cuda_version),
        )
        || !cuda_default_view_compaction_allowed(
            diagnostics.map(|value| &value.default_runtime_version),
        )
    {
        return None;
    }

    Some(format_cuda_default_view_compact_line(
        toolkit, driver, supported, runtime,
    ))
}

fn format_cuda_default_view_compact_line_for_state(state: &CudaRuntimeStateV1) -> Option<String> {
    let diagnostics = state.default_view_probe_diagnostics.as_ref();
    let toolkit = observed_state_value_for_inspect(&state.default_toolkit_version)?;
    let driver = observed_state_value_for_inspect(&state.driver_version)?;
    let supported = observed_state_value_for_inspect(&state.driver_supported_cuda_version)?;
    let runtime = observed_state_value_for_inspect(&state.default_runtime_version)?;

    if !cuda_default_view_compaction_allowed(
        diagnostics.map(|value| &value.default_toolkit_version),
    ) || !cuda_default_view_compaction_allowed(diagnostics.map(|value| &value.driver_version))
        || !cuda_default_view_compaction_allowed(
            diagnostics.map(|value| &value.driver_supported_cuda_version),
        )
        || !cuda_default_view_compaction_allowed(
            diagnostics.map(|value| &value.default_runtime_version),
        )
    {
        return None;
    }

    Some(format_cuda_default_view_compact_line(
        toolkit, driver, supported, runtime,
    ))
}

fn format_cuda_default_view_compact_line(
    toolkit: &CudaRuntimeVersionV1,
    driver: &CudaRuntimeVersionV1,
    supported: &CudaRuntimeVersionV1,
    runtime: &CudaRuntimeVersionV1,
) -> String {
    format!(
        "toolkit {}; driver {}; supported {}; runtime {}",
        format_cuda_runtime_version_value_for_inspect(toolkit),
        format_cuda_runtime_version_value_for_inspect(driver),
        format_cuda_runtime_version_value_for_inspect(supported),
        format_cuda_runtime_version_value_for_inspect(runtime)
    )
}

fn cuda_default_view_compaction_allowed(
    diagnostic: Option<&CudaDefaultViewFieldDiagnosticV1>,
) -> bool {
    diagnostic.is_none_or(|diagnostic| {
        diagnostic.source_tier == FieldDiagnosticSourceTierV1::Primary
            && diagnostic.status == FieldDiagnosticProbeStatusV1::Observed
    })
}

fn should_render_cuda_installed_toolkit_summary_in_compact(
    installed_toolkits: &[CudaInstalledToolkitV1],
    options: InspectRenderOptionsV1,
) -> bool {
    if options.verbose {
        return !installed_toolkits.is_empty();
    }

    if installed_toolkits.len() > 1 {
        return true;
    }

    installed_toolkits
        .iter()
        .any(|entry| !entry.selected_by_default_toolkit_view)
}

fn push_cuda_installed_toolkit_entries(
    output: &mut String,
    installed_toolkits: &[CudaInstalledToolkitV1],
) -> Result<(), InspectError> {
    for (index, entry) in installed_toolkits.iter().enumerate() {
        push_line(
            output,
            &format!("CUDA toolkit #{index}"),
            format_cuda_installed_toolkit_entry_for_inspect(entry),
        )?;
    }
    Ok(())
}

fn push_cuda_installed_toolkit_entries_grouped(
    output: &mut String,
    installed_toolkits: &[CudaInstalledToolkitV1],
) -> Result<(), InspectError> {
    for (index, entry) in installed_toolkits.iter().enumerate() {
        push_summary_group_line(
            output,
            &format!("CUDA toolkit #{index}"),
            format_cuda_installed_toolkit_entry_for_inspect(entry),
        )?;
    }
    Ok(())
}

fn push_cuda_runtime_device_lines_grouped(
    output: &mut String,
    devices: &[CudaRuntimeDeviceStateV1],
) -> Result<(), InspectError> {
    for device in devices {
        push_summary_group_line(
            output,
            &format!("CUDA device #{}", device.device_ordinal),
            format_cuda_runtime_device_state_for_inspect(device),
        )?;
    }
    Ok(())
}

fn push_cuda_runtime_device_lines_compact_grouped(
    output: &mut String,
    devices: &[CudaRuntimeDeviceStateV1],
) -> Result<(), InspectError> {
    for device in devices {
        push_summary_group_line(
            output,
            &format_cuda_runtime_device_compact_label_for_inspect(device, devices.len()),
            format_cuda_runtime_device_state_compact_for_inspect(device),
        )?;
    }
    Ok(())
}

fn try_render_compact_state_memory_summary_line(
    output: &mut String,
    resources: &HostRuntimeResourcesV1,
) -> Result<bool, InspectError> {
    let Some(total) = scalar_state_value_for_inspect(&resources.memory_total_bytes) else {
        return Ok(false);
    };
    let Some(allocatable) = scalar_state_value_for_inspect(&resources.allocatable_memory_bytes)
    else {
        return Ok(false);
    };
    let Some(used) = scalar_state_value_for_inspect(&resources.memory_used_excluding_cache_bytes)
    else {
        return Ok(false);
    };

    push_summary_group_line(
        output,
        "Memory",
        format_state_memory_usage_compact(used, total, allocatable),
    )?;
    Ok(true)
}

fn scalar_state_value_for_inspect<T: Copy>(field: &StateFieldV1<T>) -> Option<T> {
    if field.state == ObservationStateV1::Observed && field.limitation_reason.is_none() {
        field.value
    } else {
        None
    }
}

fn observed_state_value_for_inspect<T>(field: &StateFieldV1<T>) -> Option<&T> {
    if field.state == ObservationStateV1::Observed && field.limitation_reason.is_none() {
        field.value.as_ref()
    } else {
        None
    }
}

fn format_cuda_runtime_version_value_for_inspect(version: &CudaRuntimeVersionV1) -> String {
    format!("{}.{}.{}", version.major, version.minor, version.patch)
}

fn format_cuda_runtime_version_value_with_diagnostic_for_inspect(
    version: &CudaRuntimeVersionV1,
    diagnostic: Option<&CudaDefaultViewFieldDiagnosticV1>,
) -> String {
    let version = format_cuda_runtime_version_value_for_inspect(version);
    let Some(diagnostic) = diagnostic else {
        return version;
    };
    if diagnostic.source_tier == FieldDiagnosticSourceTierV1::AdvisoryFallback
        && diagnostic.status == FieldDiagnosticProbeStatusV1::Observed
    {
        return format!(
            "{version} (advisory fallback via {})",
            diagnostic.source_ref
        );
    }
    version
}

fn format_cuda_installed_toolkit_summary_for_inspect(
    installed_toolkits: &[CudaInstalledToolkitV1],
) -> String {
    let mut parts = vec![
        "advisory".to_string(),
        format!("{} discovered", installed_toolkits.len()),
    ];
    if let Some(selected) = installed_toolkits
        .iter()
        .find(|entry| entry.selected_by_default_toolkit_view)
    {
        parts.push(format!(
            "default {}",
            format_cuda_runtime_version_value_for_inspect(&selected.version)
        ));
    }
    parts.join("; ")
}

fn format_cuda_installed_toolkit_entry_for_inspect(entry: &CudaInstalledToolkitV1) -> String {
    let mut parts = vec![format!(
        "{} ({})",
        entry.install_root,
        format_cuda_runtime_version_value_for_inspect(&entry.version)
    )];
    if entry.selected_by_default_toolkit_view {
        parts.push("selected by default toolkit view".to_string());
    }
    parts.join("; ")
}

fn format_cuda_runtime_device_state_for_inspect(device: &CudaRuntimeDeviceStateV1) -> String {
    format!(
        "{}; total {}; used {}; allocatable {}",
        device.device_uuid,
        format_state_field(&device.total_memory_bytes, |value| format_bytes(*value)),
        format_state_field(&device.used_memory_bytes, |value| format_bytes(*value)),
        format_state_field(&device.allocatable_memory_bytes, |value| format_bytes(
            *value
        ))
    )
}

fn format_cuda_runtime_device_compact_label_for_inspect(
    device: &CudaRuntimeDeviceStateV1,
    total_devices: usize,
) -> String {
    if total_devices == 1 {
        "CUDA device".to_string()
    } else {
        let trimmed = device.device_uuid.trim();
        if trimmed.is_empty() {
            format!("CUDA device #{}", device.device_ordinal)
        } else {
            format!("CUDA device {}", shorten_identifier_for_inspect(trimmed))
        }
    }
}

fn format_cuda_runtime_state_compact_for_inspect(state: &CudaRuntimeStateV1) -> String {
    let mut parts = Vec::new();

    if state.runtime_state != ObservationStateV1::Observed || state.limitation_reason.is_some() {
        parts.push(format_observation_surface(
            &state.runtime_state,
            state.limitation_reason.as_ref(),
        ));
    }
    if !state.devices.is_empty() {
        parts.push(if state.devices.len() == 1 {
            "1 device".to_string()
        } else {
            format!("{} devices", state.devices.len())
        });
    }
    match (
        scalar_state_value_for_inspect(&state.used_memory_bytes),
        scalar_state_value_for_inspect(&state.allocatable_memory_bytes),
        scalar_state_value_for_inspect(&state.total_memory_bytes),
    ) {
        (Some(used), Some(allocatable), Some(total))
            if used <= total
                && allocatable <= total
                && used.saturating_add(allocatable) <= total =>
        {
            parts.push(format_cuda_memory_triplet_compact(used, allocatable, total))
        }
        (None, Some(allocatable), Some(total)) if allocatable <= total => {
            parts.push(format_cuda_allocatable_memory_compact(allocatable, total))
        }
        (_, Some(allocatable), None) => parts.push(format!(
            "allocatable {}",
            format_bytes_human_first_compact(allocatable)
        )),
        (_, None, Some(total)) => {
            parts.push(format!("total {}", format_bytes_human_first_compact(total)))
        }
        (_, Some(allocatable), Some(total)) => parts.push(format!(
            "total {}; allocatable {}",
            format_bytes_human_first_compact(total),
            format_bytes_human_first_compact(allocatable)
        )),
        (_, None, None) => {}
    }

    if parts.is_empty() {
        format_observation_surface(&state.runtime_state, state.limitation_reason.as_ref())
    } else {
        parts.join("; ")
    }
}

fn format_cuda_runtime_device_state_compact_for_inspect(
    device: &CudaRuntimeDeviceStateV1,
) -> String {
    match (
        scalar_state_value_for_inspect(&device.used_memory_bytes),
        scalar_state_value_for_inspect(&device.allocatable_memory_bytes),
        scalar_state_value_for_inspect(&device.total_memory_bytes),
    ) {
        (Some(used), Some(allocatable), Some(total))
            if used <= total
                && allocatable <= total
                && used.saturating_add(allocatable) <= total =>
        {
            format_cuda_memory_triplet_compact(used, allocatable, total)
        }
        (None, Some(allocatable), Some(total)) if allocatable <= total => {
            format_cuda_allocatable_memory_compact(allocatable, total)
        }
        _ => format!(
            "total {}; used {}; allocatable {}",
            format_state_field_compact(&device.total_memory_bytes, |value| {
                format_bytes_human_first(*value)
            }),
            format_state_field_compact(&device.used_memory_bytes, |value| {
                format_bytes_human_first(*value)
            }),
            format_state_field_compact(&device.allocatable_memory_bytes, |value| {
                format_bytes_human_first(*value)
            })
        ),
    }
}

fn should_render_state_summary_cpuset_line(
    allocatable_cpu: &StateFieldV1<u32>,
    cpuset_cpu: &StateFieldV1<u32>,
    options: InspectRenderOptionsV1,
) -> bool {
    if options.verbose {
        return true;
    }

    !matches!(
        (
            scalar_state_value_for_inspect(allocatable_cpu),
            scalar_state_value_for_inspect(cpuset_cpu),
        ),
        (Some(allocatable), Some(cpuset)) if allocatable == cpuset
    )
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
        format_validation_verdict(artifact.report.verdict, options),
    )?;
    push_line(
        output,
        "Operator posture",
        format_operator_posture(artifact.report.verdict),
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
    if let Some(extension_diagnostics) =
        format_validation_extension_diagnostics_for_inspect(&artifact.report.extension_diagnostics)?
    {
        push_line(output, "Extension diagnostics", extension_diagnostics)?;
    }
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

fn format_validation_extension_diagnostics_for_inspect(
    values: &BTreeMap<String, Value>,
) -> Result<Option<String>, InspectError> {
    let mut diagnostics = Vec::new();

    if let Some(value) = values.get(CUDA_RUNTIME_NAMESPACE) {
        let diagnostic =
            decode_cuda_runtime_validation_diagnostic_from_value(value).map_err(|error| {
                InspectError::new(
                    InspectErrorCode::InspectInputInvalid,
                    "inspect_decode",
                    format!(
                        "failed to decode CUDA runtime validation diagnostic for inspect: {}",
                        error.message
                    ),
                )
            })?;
        diagnostics.push(format!(
            "{}: {}",
            CUDA_RUNTIME_NAMESPACE,
            format_cuda_runtime_validation_diagnostic_for_inspect(&diagnostic)
        ));
    }

    if diagnostics.is_empty() {
        Ok(None)
    } else {
        Ok(Some(diagnostics.join(", ")))
    }
}

fn render_decision_bundle_summary(
    output: &mut String,
    artifact: &DecisionBundleV1,
    options: InspectRenderOptionsV1,
) -> Result<(), InspectError> {
    let report = &artifact.bundle.validation_report;

    push_line(output, "Bundle scope", "single local decision")?;
    push_line(
        output,
        "Validation mode",
        format_validation_mode(report.validation_basis.validation_mode),
    )?;
    push_line(
        output,
        "Verdict",
        format_validation_verdict(report.report.verdict, options),
    )?;
    push_line(
        output,
        "Operator posture",
        format_operator_posture(report.report.verdict),
    )?;
    push_line(
        output,
        "Primary reason code",
        format_validation_reason_code(report.report.primary_reason_code),
    )?;
    push_line(output, "Summary", report.report.summary.clone())?;
    push_line(output, "Lineage status", "aligned")?;

    let mut contents = vec![
        "validation-report.v2".to_string(),
        "host-contract.v2".to_string(),
    ];
    if artifact.bundle.state.is_some() {
        contents.push("host-state.v2".to_string());
    }
    if artifact.bundle.resolved_config.is_some() {
        contents.push("fitctl.resolved-config.v1".to_string());
    }
    if artifact.bundle.config_bundle.is_some() {
        contents.push("fitctl.config-bundle.v2".to_string());
    }
    if artifact.bundle.verification_bundle.is_some() {
        contents.push("fitctl.verification-bundle.v1".to_string());
    }
    if artifact.bundle.recommendation_report.is_some() {
        contents.push("fitctl.recommendation-report.v2".to_string());
    }
    push_line(output, "Bundle contents", contents.join(", "))?;
    push_line(
        output,
        "Validation report artifact id",
        artifact.bundle_basis.validation_report_artifact_id.clone(),
    )?;
    push_line(
        output,
        "Contract artifact id",
        artifact.bundle_basis.contract_artifact_id.clone(),
    )?;
    push_line(
        output,
        "State artifact id",
        artifact
            .bundle_basis
            .state_artifact_id
            .clone()
            .unwrap_or_else(|| "<none>".to_string()),
    )?;
    push_line(
        output,
        "Config bundle artifact id",
        artifact
            .bundle_basis
            .config_bundle_artifact_id
            .clone()
            .unwrap_or_else(|| "<none>".to_string()),
    )?;
    push_line(
        output,
        "Verification bundle id",
        artifact
            .bundle_basis
            .verification_bundle_id
            .clone()
            .unwrap_or_else(|| "<none>".to_string()),
    )?;
    push_line(
        output,
        "Recommendation report artifact id",
        artifact
            .bundle_basis
            .recommendation_report_artifact_id
            .clone()
            .unwrap_or_else(|| "<none>".to_string()),
    )?;

    if let Some(config_bundle) = artifact.bundle.config_bundle.as_ref() {
        push_line(
            output,
            "Config policy id",
            config_bundle.config_bundle.policy.policy_id.clone(),
        )?;
        push_line(
            output,
            "Config service profile id",
            config_bundle
                .config_bundle_basis
                .service_profile_id
                .clone()
                .unwrap_or_else(|| "<none>".to_string()),
        )?;
        push_line(
            output,
            "Config trust policy id",
            config_bundle
                .config_bundle_basis
                .trust_policy_id
                .clone()
                .unwrap_or_else(|| "<none>".to_string()),
        )?;
        push_line(
            output,
            "Config validation mode",
            config_bundle
                .config_bundle
                .resolved_config
                .validation_mode
                .map(format_validation_mode)
                .unwrap_or("<none>"),
        )?;
        if let Some(verification_bundle) = artifact.bundle.verification_bundle.as_ref() {
            push_line(
                output,
                "Verification trust policy id",
                verification_bundle.trust_policy_id.clone(),
            )?;
            push_line(
                output,
                "Verification summary",
                verification_bundle.summary.clone(),
            )?;
        }
    } else if let Some(resolved_config) = artifact.bundle.resolved_config.as_ref() {
        push_line(
            output,
            "Resolved policy id",
            resolved_config.policy_id.clone(),
        )?;
        push_line(
            output,
            "Resolved service profile entry",
            resolved_config
                .selected_service_profile_entry_id
                .clone()
                .unwrap_or_else(|| "<none>".to_string()),
        )?;
        push_line(
            output,
            "Resolved validation mode",
            resolved_config
                .validation_mode
                .map(format_validation_mode)
                .unwrap_or("<none>"),
        )?;
        if let Some(verification_bundle) = artifact.bundle.verification_bundle.as_ref() {
            push_line(
                output,
                "Verification trust policy id",
                verification_bundle.trust_policy_id.clone(),
            )?;
            push_line(
                output,
                "Verification summary",
                verification_bundle.summary.clone(),
            )?;
        }
    } else if let Some(verification_bundle) = artifact.bundle.verification_bundle.as_ref() {
        push_line(
            output,
            "Verification trust policy id",
            verification_bundle.trust_policy_id.clone(),
        )?;
        push_line(
            output,
            "Verification summary",
            verification_bundle.summary.clone(),
        )?;
    } else {
        push_line(output, "Config provenance", "<none>")?;
    }

    if let Some(recommendation_report) = artifact.bundle.recommendation_report.as_ref() {
        push_line(
            output,
            "Recommendation pack",
            recommendation_report
                .recommendation_basis
                .recommendation_pack_id
                .clone(),
        )?;
        push_line(
            output,
            "Recommendation summary",
            recommendation_report.report.summary.clone(),
        )?;
    }

    if let Some(state_freshness) = format_validation_state_freshness(
        &report.validation_basis,
        &report.envelope.provenance.collected_at,
        options,
    ) {
        push_line(output, "State freshness", state_freshness)?;
    }

    Ok(())
}

fn render_config_bundle_summary(
    output: &mut String,
    artifact: &ConfigBundleV1,
) -> Result<(), InspectError> {
    push_line(output, "Bundle scope", "single local advanced run config")?;
    push_line(
        output,
        "Policy id",
        artifact.config_bundle_basis.policy_id.clone(),
    )?;
    push_line(
        output,
        "Service profile id",
        artifact
            .config_bundle_basis
            .service_profile_id
            .clone()
            .unwrap_or_else(|| "<none>".to_string()),
    )?;
    push_line(
        output,
        "Trust policy id",
        artifact
            .config_bundle_basis
            .trust_policy_id
            .clone()
            .unwrap_or_else(|| "<none>".to_string()),
    )?;
    push_line(
        output,
        "Validation mode",
        artifact
            .config_bundle
            .resolved_config
            .validation_mode
            .map(format_validation_mode)
            .unwrap_or("<none>"),
    )?;
    push_line(
        output,
        "Max state age",
        artifact
            .config_bundle
            .resolved_config
            .max_state_age_seconds
            .map(format_duration_compact)
            .unwrap_or_else(|| "<none>".to_string()),
    )?;

    let mut contents = vec![
        "fitctl.policy.document.v1".to_string(),
        "fitctl.resolved-config.v1".to_string(),
    ];
    if artifact.config_bundle.service_profile.is_some() {
        contents.push("service-profile.v2".to_string());
    }
    if artifact.config_bundle.trust_policy.is_some() {
        contents.push("fitctl.trust-policy.v1".to_string());
    }
    push_line(output, "Bundle contents", contents.join(", "))?;

    if let Some(source) = artifact
        .config_bundle
        .resolved_config
        .selected_policy_entry_source
    {
        push_line(
            output,
            "Policy selection source",
            match source {
                crate::config::ConfigSelectionSourceV1::Cli => "cli",
                crate::config::ConfigSelectionSourceV1::InvocationContext => "invocation_context",
            },
        )?;
    }
    if let Some(source) = artifact
        .config_bundle
        .resolved_config
        .selected_service_profile_entry_source
    {
        push_line(
            output,
            "Service profile selection source",
            match source {
                crate::config::ConfigSelectionSourceV1::Cli => "cli",
                crate::config::ConfigSelectionSourceV1::InvocationContext => "invocation_context",
            },
        )?;
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
        format_validation_verdict(artifact.recommendation_basis.validation_verdict, options),
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
    if let Some(max_state_age_seconds) = artifact.classification_basis.max_state_age_seconds {
        push_line(
            output,
            "Max state age",
            format_duration_compact(max_state_age_seconds),
        )?;
    }
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
    if artifact.classification_basis.validation_mode != ValidationModeV1::ContractOnly {
        push_line(
            output,
            "State lineage",
            format_batch_state_lineage(artifact, options),
        )?;
    }
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
        "Operator posture counts",
        format_batch_operator_posture_counts(&artifact.report.rows),
    )?;
    push_line(
        output,
        "Primary reason tally",
        format_batch_primary_reason_tally(&artifact.report.rows),
    )?;
    push_line(
        output,
        "Row summaries",
        format_batch_row_summaries(&artifact.report.rows, 6),
    )?;
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

fn render_batch_classification_report_matrix(
    output: &mut String,
    artifact: &BatchClassificationReportV1,
    options: InspectRenderOptionsV1,
) -> Result<(), InspectError> {
    push_line(
        output,
        "Validation mode",
        format_validation_mode(artifact.classification_basis.validation_mode),
    )?;
    if let Some(max_state_age_seconds) = artifact.classification_basis.max_state_age_seconds {
        push_line(
            output,
            "Max state age",
            format_duration_compact(max_state_age_seconds),
        )?;
    }
    push_line(
        output,
        "Validated at",
        format_timestamp_for_inspect(&artifact.classification_basis.validated_at, options),
    )?;
    if artifact.classification_basis.validation_mode != ValidationModeV1::ContractOnly {
        push_line(
            output,
            "State lineage",
            format_batch_state_lineage(artifact, options),
        )?;
    }
    writeln!(output, "  Verdict matrix:").map_err(|error| {
        InspectError::new(
            InspectErrorCode::InspectRenderFailed,
            "inspect_render",
            format!("failed to render matrix label: {error}"),
        )
    })?;
    for line in format_batch_verdict_matrix(artifact, options)?.lines() {
        writeln!(output, "    {line}").map_err(|error| {
            InspectError::new(
                InspectErrorCode::InspectRenderFailed,
                "inspect_render",
                format!("failed to render matrix row: {error}"),
            )
        })?;
    }

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
        "fitctl version",
        format_optional_str(envelope.provenance.fitctl_version.as_deref()),
    )?;
    if options.verbose {
        if let Some(vcs_revision) = envelope.provenance.fitctl_vcs_revision.as_deref() {
            push_line(output, "fitctl vcs revision", vcs_revision)?;
        }
        if let Some(vcs_describe) = envelope.provenance.fitctl_vcs_describe.as_deref() {
            push_line(output, "fitctl vcs describe", vcs_describe)?;
        }
        if let Some(build_dirty) = envelope.provenance.fitctl_build_dirty {
            push_line(output, "fitctl build dirty", build_dirty.to_string())?;
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_cuda_device_formatter_falls_back_when_allocatable_exceeds_total() {
        let device = CudaRuntimeDeviceStateV1 {
            device_ordinal: 0,
            device_uuid: "GPU-test".to_string(),
            total_memory_bytes: StateFieldV1 {
                state: ObservationStateV1::Observed,
                limitation_reason: None,
                value: Some(25_769_803_776),
            },
            allocatable_memory_bytes: StateFieldV1 {
                state: ObservationStateV1::Observed,
                limitation_reason: None,
                value: Some(26_843_545_600),
            },
            used_memory_bytes: StateFieldV1 {
                state: ObservationStateV1::Missing,
                limitation_reason: None,
                value: None,
            },
        };

        assert_eq!(
            format_cuda_runtime_device_state_compact_for_inspect(&device),
            "total 24.00 GiB (25769803776 bytes); used missing; allocatable 25.00 GiB (26843545600 bytes)"
        );
    }
}
