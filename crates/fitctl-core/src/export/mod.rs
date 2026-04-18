// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Adapter-style exports derived from owned artifacts.
//!
//! These exports are convenience views for external systems; they do not replace the authoritative
//! typed artifact surfaces.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::artifacts::record_v1::{load_artifact_record_from_path, ArtifactRecordV1};
use crate::artifacts::survey_v1::{decode_host_survey_payload, HostSurveyPayloadV1};
use crate::artifacts::validation_report_v1::{ValidationReportV1, ValidationVerdictV1};
use crate::contract::HostContractPayloadV1;
use crate::identity::derive_export_pseudonym_v1;
use crate::survey::VisibilityScopeV1;

pub const ADAPTER_ERROR_MODEL_ID: &str = "fitctl.adapters.v1";
pub const ADAPTER_ERROR_MODEL_VERSION: u32 = 1;
pub const ADAPTER_EXPORT_SCHEMA_ID: &str = "fitctl.adapter.export.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterErrorCode {
    AdapterTargetInvalid,
    AdapterInputInvalid,
    AdapterEmitFailed,
    PackagingEnvironmentInvalid,
}

impl AdapterErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AdapterTargetInvalid => "adapter_target_invalid",
            Self::AdapterInputInvalid => "adapter_input_invalid",
            Self::AdapterEmitFailed => "adapter_emit_failed",
            Self::PackagingEnvironmentInvalid => "packaging_environment_invalid",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterError {
    pub code: AdapterErrorCode,
    pub checkpoint_id: &'static str,
    pub message: String,
    pub error_model_id: &'static str,
    pub error_model_version: u32,
}

impl AdapterError {
    fn new(
        code: AdapterErrorCode,
        checkpoint_id: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            checkpoint_id,
            message: message.into(),
            error_model_id: ADAPTER_ERROR_MODEL_ID,
            error_model_version: ADAPTER_ERROR_MODEL_VERSION,
        }
    }
}

impl std::fmt::Display for AdapterError {
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

impl std::error::Error for AdapterError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterTargetV1 {
    KubernetesLabels,
    NomadAttributes,
    GatingSummary,
    IdentitySummary,
}

impl AdapterTargetV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KubernetesLabels => "kubernetes_labels",
            Self::NomadAttributes => "nomad_attributes",
            Self::GatingSummary => "gating_summary",
            Self::IdentitySummary => "identity_summary",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AdapterExportOptionsV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pseudonym_secret: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterSourceMetadataV1 {
    pub artifact_schema_id: String,
    pub artifact_schema_version: u32,
    pub semantic_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redaction_profile_id: Option<String>,
    pub signature_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterExportDocumentV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub target: AdapterTargetV1,
    pub source: AdapterSourceMetadataV1,
    pub export: Value,
}

pub fn parse_adapter_target_v1(raw: &str) -> Result<AdapterTargetV1, AdapterError> {
    match raw {
        "kubernetes_labels" => Ok(AdapterTargetV1::KubernetesLabels),
        "nomad_attributes" => Ok(AdapterTargetV1::NomadAttributes),
        "gating_summary" => Ok(AdapterTargetV1::GatingSummary),
        "identity_summary" => Ok(AdapterTargetV1::IdentitySummary),
        _ => Err(AdapterError::new(
            AdapterErrorCode::AdapterTargetInvalid,
            "adapter_parse",
            format!("unsupported adapter target '{raw}'"),
        )),
    }
}

pub fn load_artifact_record_for_export(path: &Path) -> Result<ArtifactRecordV1, AdapterError> {
    load_artifact_record_from_path(path).map_err(|error| {
        AdapterError::new(
            AdapterErrorCode::AdapterInputInvalid,
            "adapter_parse",
            error.message,
        )
    })
}

pub fn emit_adapter_export_v1(
    target: AdapterTargetV1,
    artifact: &ArtifactRecordV1,
) -> Result<AdapterExportDocumentV1, AdapterError> {
    emit_adapter_export_with_options_v1(target, artifact, &AdapterExportOptionsV1::default())
}

pub fn emit_adapter_export_with_options_v1(
    target: AdapterTargetV1,
    artifact: &ArtifactRecordV1,
    options: &AdapterExportOptionsV1,
) -> Result<AdapterExportDocumentV1, AdapterError> {
    Ok(AdapterExportDocumentV1 {
        schema_id: ADAPTER_EXPORT_SCHEMA_ID.to_string(),
        schema_version: 1,
        target,
        source: build_source_metadata(artifact)?,
        export: match target {
            AdapterTargetV1::KubernetesLabels => export_kubernetes_labels(artifact)?,
            AdapterTargetV1::NomadAttributes => export_nomad_attributes(artifact)?,
            AdapterTargetV1::GatingSummary => export_gating_summary(artifact)?,
            AdapterTargetV1::IdentitySummary => export_identity_summary(artifact, options)?,
        },
    })
}

fn build_source_metadata(
    artifact: &ArtifactRecordV1,
) -> Result<AdapterSourceMetadataV1, AdapterError> {
    let envelope = artifact.envelope();
    let semantic_hash = artifact.semantic_hash_hex().map_err(|error| {
        AdapterError::new(
            AdapterErrorCode::AdapterInputInvalid,
            "adapter_source_validate",
            error.message,
        )
    })?;

    Ok(AdapterSourceMetadataV1 {
        artifact_schema_id: envelope.schema_id.clone(),
        artifact_schema_version: envelope.schema_version,
        semantic_hash,
        redaction_profile_id: envelope
            .redaction
            .as_ref()
            .map(|redaction| redaction.profile_id.clone()),
        signature_count: envelope.signatures.len(),
    })
}

fn export_kubernetes_labels(artifact: &ArtifactRecordV1) -> Result<Value, AdapterError> {
    let contract = expect_contract_input(artifact, AdapterTargetV1::KubernetesLabels)?;
    let payload = decode_contract_payload(contract)?;

    let mut labels = BTreeMap::new();
    for (capability_class, claim) in payload.core_contract.capability_classes {
        labels.insert(
            format!("fitctl.io/capability.{}", sanitize_token(&capability_class)),
            if claim.admissible {
                "admissible".to_string()
            } else {
                "not_admissible".to_string()
            },
        );
    }
    labels.insert(
        "fitctl.io/visibility_scope".to_string(),
        visibility_scope_as_str(&payload.core_contract.execution_constraints.visibility_scope)
            .to_string(),
    );
    if let Some(non_loopback_interfaces) = payload
        .core_contract
        .network_summary
        .non_loopback_interfaces
    {
        labels.insert(
            "fitctl.io/network.non_loopback_interfaces".to_string(),
            non_loopback_interfaces.to_string(),
        );
    }
    if let Some(max_observed_speed_mbps) = payload
        .core_contract
        .network_summary
        .max_observed_speed_mbps
    {
        labels.insert(
            "fitctl.io/network.max_speed_mbps".to_string(),
            max_observed_speed_mbps.to_string(),
        );
    }
    if let Some(container_runtime) = payload
        .core_contract
        .execution_constraints
        .container_runtime
    {
        labels.insert(
            "fitctl.io/container_runtime".to_string(),
            sanitize_token(&container_runtime),
        );
    }

    serde_json::to_value(labels_payload(labels)).map_err(|error| {
        AdapterError::new(
            AdapterErrorCode::AdapterEmitFailed,
            "adapter_emit",
            format!("failed to encode kubernetes_labels export: {error}"),
        )
    })
}

fn export_nomad_attributes(artifact: &ArtifactRecordV1) -> Result<Value, AdapterError> {
    let contract = expect_contract_input(artifact, AdapterTargetV1::NomadAttributes)?;
    let payload = decode_contract_payload(contract)?;

    let mut attributes = Map::new();
    for (capability_class, claim) in payload.core_contract.capability_classes {
        attributes.insert(
            format!(
                "fitctl.capability.{}.admissible",
                sanitize_token(&capability_class)
            ),
            Value::Bool(claim.admissible),
        );
    }
    attributes.insert(
        "fitctl.execution.visibility_scope".to_string(),
        Value::String(
            visibility_scope_as_str(&payload.core_contract.execution_constraints.visibility_scope)
                .to_string(),
        ),
    );
    if let Some(non_loopback_interfaces) = payload
        .core_contract
        .network_summary
        .non_loopback_interfaces
    {
        attributes.insert(
            "fitctl.network.non_loopback_interfaces".to_string(),
            Value::Number((non_loopback_interfaces as u64).into()),
        );
    }
    if let Some(max_observed_speed_mbps) = payload
        .core_contract
        .network_summary
        .max_observed_speed_mbps
    {
        attributes.insert(
            "fitctl.network.max_speed_mbps".to_string(),
            Value::Number(max_observed_speed_mbps.into()),
        );
    }
    if let Some(container_runtime) = payload
        .core_contract
        .execution_constraints
        .container_runtime
    {
        attributes.insert(
            "fitctl.execution.container_runtime".to_string(),
            Value::String(sanitize_token(&container_runtime)),
        );
    }

    let mut export = Map::new();
    export.insert("attributes".to_string(), Value::Object(attributes));
    Ok(Value::Object(export))
}

fn export_gating_summary(artifact: &ArtifactRecordV1) -> Result<Value, AdapterError> {
    let report = expect_validation_report_input(artifact, AdapterTargetV1::GatingSummary)?;
    let mut export = Map::new();
    export.insert(
        "gate_status".to_string(),
        Value::String(gate_status_for_report(report).to_string()),
    );
    export.insert(
        "verdict".to_string(),
        Value::String(report.report.verdict.as_str().to_string()),
    );
    export.insert(
        "primary_reason_code".to_string(),
        Value::String(report.report.primary_reason_code.as_str().to_string()),
    );
    export.insert(
        "validation_mode".to_string(),
        Value::String(report.validation_basis.validation_mode.as_str().to_string()),
    );
    export.insert(
        "warning_count".to_string(),
        Value::Number((report.report.warnings.len() as u64).into()),
    );
    if let Some(selected_degradation_tier) = report.report.selected_degradation_tier.as_ref() {
        export.insert(
            "selected_degradation_tier".to_string(),
            Value::String(selected_degradation_tier.clone()),
        );
    }

    Ok(Value::Object(export))
}

fn export_identity_summary(
    artifact: &ArtifactRecordV1,
    options: &AdapterExportOptionsV1,
) -> Result<Value, AdapterError> {
    let trust_domain = options
        .trust_domain
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            AdapterError::new(
                AdapterErrorCode::AdapterInputInvalid,
                "adapter_source_validate",
                "identity_summary export requires a non-blank trust_domain",
            )
        })?;
    let pseudonym_secret = options
        .pseudonym_secret
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            AdapterError::new(
                AdapterErrorCode::AdapterInputInvalid,
                "adapter_source_validate",
                "identity_summary export requires a non-blank pseudonym_secret",
            )
        })?;
    if artifact
        .envelope()
        .redaction
        .as_ref()
        .is_some_and(|redaction| redaction.profile_id != "local")
    {
        return Err(AdapterError::new(
            AdapterErrorCode::AdapterInputInvalid,
            "adapter_source_validate",
            "identity_summary export requires a local or unredacted source artifact",
        ));
    }

    let summary = match artifact {
        ArtifactRecordV1::Contract(contract) => {
            decode_contract_payload(contract)?
                .core_contract
                .identity_summary
        }
        ArtifactRecordV1::Survey(survey) => {
            decode_survey_payload(survey)?
                .core_evidence
                .identity_summary
        }
        _ => {
            return Err(AdapterError::new(
                AdapterErrorCode::AdapterInputInvalid,
                "adapter_source_validate",
                "identity_summary export requires host-survey.v2 or host-contract.v2 input",
            ));
        }
    };

    let mut export = Map::new();
    export.insert(
        "identity_class".to_string(),
        Value::String("export_pseudonym".to_string()),
    );
    export.insert(
        "export_pseudonym".to_string(),
        Value::String(derive_export_pseudonym_v1(
            &summary.local_stable_id,
            trust_domain,
            pseudonym_secret,
        )),
    );
    export.insert(
        "trust_domain".to_string(),
        Value::String(trust_domain.to_string()),
    );
    export.insert(
        "composition_digest".to_string(),
        Value::String(summary.composition_digest),
    );
    export.insert(
        "provenance_fingerprint".to_string(),
        Value::String(summary.provenance_fingerprint),
    );

    Ok(Value::Object(export))
}

fn expect_contract_input(
    artifact: &ArtifactRecordV1,
    target: AdapterTargetV1,
) -> Result<&crate::artifacts::contract_v1::HostContractV1, AdapterError> {
    match artifact {
        ArtifactRecordV1::Contract(contract) => Ok(contract),
        _ => Err(AdapterError::new(
            AdapterErrorCode::AdapterInputInvalid,
            "adapter_source_validate",
            format!(
                "adapter target {} requires host-contract.v2 input",
                target.as_str()
            ),
        )),
    }
}

fn expect_validation_report_input(
    artifact: &ArtifactRecordV1,
    target: AdapterTargetV1,
) -> Result<&ValidationReportV1, AdapterError> {
    match artifact {
        ArtifactRecordV1::ValidationReport(report) => Ok(report),
        _ => Err(AdapterError::new(
            AdapterErrorCode::AdapterInputInvalid,
            "adapter_source_validate",
            format!(
                "adapter target {} requires validation-report.v2 input",
                target.as_str()
            ),
        )),
    }
}

fn decode_contract_payload(
    contract: &crate::artifacts::contract_v1::HostContractV1,
) -> Result<HostContractPayloadV1, AdapterError> {
    serde_json::from_value(contract.contract.clone()).map_err(|error| {
        AdapterError::new(
            AdapterErrorCode::AdapterInputInvalid,
            "adapter_source_validate",
            format!("failed to decode host-contract payload for adapter export: {error}"),
        )
    })
}

fn decode_survey_payload(
    survey: &crate::artifacts::survey_v1::HostSurveyV1,
) -> Result<HostSurveyPayloadV1, AdapterError> {
    decode_host_survey_payload(&survey.survey).map_err(|error| {
        AdapterError::new(
            AdapterErrorCode::AdapterInputInvalid,
            "adapter_source_validate",
            format!("failed to decode host-survey payload for adapter export: {error}"),
        )
    })
}

fn gate_status_for_report(report: &ValidationReportV1) -> &'static str {
    match report.report.verdict {
        ValidationVerdictV1::Fit => "allow",
        ValidationVerdictV1::FitWithDegradation => "allow_with_degradation",
        ValidationVerdictV1::Unfit => "deny",
        ValidationVerdictV1::Indeterminate => "block",
    }
}

fn visibility_scope_as_str(scope: &VisibilityScopeV1) -> &'static str {
    match scope {
        VisibilityScopeV1::BareMetalLike => "bare_metal_like",
        VisibilityScopeV1::VmLike => "vm_like",
        VisibilityScopeV1::ContainerRestricted => "container_restricted",
        VisibilityScopeV1::Unknown => "unknown",
    }
}

fn sanitize_token(raw: &str) -> String {
    let mut sanitized = String::with_capacity(raw.len());

    for character in raw.chars() {
        if character.is_ascii_alphanumeric() {
            sanitized.push(character.to_ascii_lowercase());
        } else if matches!(character, '-' | '_' | '.') {
            sanitized.push(character);
        } else {
            sanitized.push('-');
        }
    }

    let trimmed = sanitized.trim_matches(|character| matches!(character, '-' | '_' | '.'));
    if trimmed.is_empty() {
        "unknown".to_string()
    } else {
        trimmed.to_string()
    }
}

fn labels_payload(
    labels: BTreeMap<String, String>,
) -> BTreeMap<&'static str, BTreeMap<String, String>> {
    let mut payload = BTreeMap::new();
    payload.insert("labels", labels);
    payload
}
