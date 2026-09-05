// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Helpers for standalone target-bound thermal evidence artifacts.

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::artifacts::envelope_v1::{local_artifact_provenance_v1, ArtifactEnvelopeV1};
use crate::artifacts::schema_ids_v1::{
    THERMAL_EVIDENCE_SCHEMA_ID, TOP_LEVEL_ARTIFACT_SCHEMA_VERSION,
};
use crate::artifacts::thermal_evidence_v1::ThermalEvidenceV1;
use crate::artifacts::validation_v1::{validate_thermal_evidence, ArtifactValidationErrorCode};
use crate::state::thermal_v1::{collect_thermal_resources_v1, ThermalProviderConfigEntryV1};

pub const THERMAL_EVIDENCE_ERROR_MODEL_ID: &str = "fitctl.thermal_evidence.v1";
pub const THERMAL_EVIDENCE_ERROR_MODEL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThermalEvidenceErrorCode {
    ThermalEvidenceInputInvalid,
    ThermalEvidenceProviderInvalid,
    ThermalEvidenceArtifactInvalid,
    ThermalEvidenceEmitFailed,
}

impl ThermalEvidenceErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ThermalEvidenceInputInvalid => "thermal_evidence_input_invalid",
            Self::ThermalEvidenceProviderInvalid => "thermal_evidence_provider_invalid",
            Self::ThermalEvidenceArtifactInvalid => "thermal_evidence_artifact_invalid",
            Self::ThermalEvidenceEmitFailed => "thermal_evidence_emit_failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThermalEvidenceError {
    pub code: ThermalEvidenceErrorCode,
    pub checkpoint_id: &'static str,
    pub message: String,
    pub error_model_id: &'static str,
    pub error_model_version: u32,
}

impl ThermalEvidenceError {
    fn new(
        code: ThermalEvidenceErrorCode,
        checkpoint_id: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            checkpoint_id,
            message: message.into(),
            error_model_id: THERMAL_EVIDENCE_ERROR_MODEL_ID,
            error_model_version: THERMAL_EVIDENCE_ERROR_MODEL_VERSION,
        }
    }
}

impl std::fmt::Display for ThermalEvidenceError {
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

impl std::error::Error for ThermalEvidenceError {}

#[derive(Debug, Clone)]
pub struct ThermalEvidenceCollectRequestV1 {
    pub provider_configs: Vec<ThermalProviderConfigEntryV1>,
    pub collected_at: Option<String>,
    pub required_target_host_id: Option<String>,
}

pub fn collect_thermal_evidence_v1(
    request: ThermalEvidenceCollectRequestV1,
) -> Result<ThermalEvidenceV1, ThermalEvidenceError> {
    if request.provider_configs.is_empty() {
        return Err(ThermalEvidenceError::new(
            ThermalEvidenceErrorCode::ThermalEvidenceProviderInvalid,
            "thermal_collect_provider_config",
            "thermal evidence collection requires at least one provider config",
        ));
    }
    if let Some(required_target_host_id) = request.required_target_host_id.as_deref() {
        validate_required_target_host_id(required_target_host_id, &request.provider_configs)?;
    }

    let collected_at = request.collected_at.unwrap_or_else(current_epoch_marker);
    let collector_host_alias = read_hostname().unwrap_or_else(|| "localhost".to_string());
    let thermal_evidence = collect_thermal_resources_v1(
        &request.provider_configs,
        &collected_at,
        crate::artifacts::state_v1::HostStateThermalCollectorHostV1 {
            host_alias: Some(collector_host_alias.clone()),
            local_stable_id: None,
        },
    )
    .ok_or_else(|| {
        ThermalEvidenceError::new(
            ThermalEvidenceErrorCode::ThermalEvidenceProviderInvalid,
            "thermal_collect_provider_config",
            "thermal evidence collection produced no provider outcomes",
        )
    })?;

    let artifact_id = format!(
        "thermal-evidence-{}",
        sanitize_artifact_id_part(&collector_host_alias)
    );
    let artifact = ThermalEvidenceV1 {
        envelope: ArtifactEnvelopeV1 {
            schema_id: THERMAL_EVIDENCE_SCHEMA_ID.to_string(),
            schema_version: TOP_LEVEL_ARTIFACT_SCHEMA_VERSION,
            artifact_id: artifact_id.clone(),
            provenance: local_artifact_provenance_v1(
                "thermal:collect".to_string(),
                collected_at,
                "thermal",
                artifact_id,
            ),
            redaction: None,
            signatures: vec![],
        },
        thermal_evidence,
    };

    validate_thermal_evidence(&artifact).map_err(|error| {
        ThermalEvidenceError::new(
            ThermalEvidenceErrorCode::ThermalEvidenceEmitFailed,
            "thermal_evidence_emit",
            error.message,
        )
    })?;

    Ok(artifact)
}

fn validate_required_target_host_id(
    required_target_host_id: &str,
    provider_configs: &[ThermalProviderConfigEntryV1],
) -> Result<(), ThermalEvidenceError> {
    if required_target_host_id.trim().is_empty()
        || required_target_host_id.contains(char::is_whitespace)
    {
        return Err(ThermalEvidenceError::new(
            ThermalEvidenceErrorCode::ThermalEvidenceInputInvalid,
            "thermal_collect_target_check",
            "--require-target-host-id must be non-empty and contain no whitespace",
        ));
    }
    for provider in provider_configs {
        let target = &provider.evidence_target;
        let Some(host_id) = target.host_id.as_deref() else {
            return Err(ThermalEvidenceError::new(
                ThermalEvidenceErrorCode::ThermalEvidenceProviderInvalid,
                "thermal_collect_target_check",
                format!(
                    "thermal provider {} does not declare evidence_target.host_id required for target-bound collection",
                    provider.provider_id
                ),
            ));
        };
        if !matches!(
            target.target_kind,
            crate::artifacts::state_v1::ThermalEvidenceTargetKindV1::HostId
        ) || host_id != required_target_host_id
        {
            return Err(ThermalEvidenceError::new(
                ThermalEvidenceErrorCode::ThermalEvidenceProviderInvalid,
                "thermal_collect_target_check",
                format!(
                    "thermal provider {} evidence target {} does not match required target host {}",
                    provider.provider_id, host_id, required_target_host_id
                ),
            ));
        }
    }
    Ok(())
}

pub fn load_thermal_evidence_from_path_v1(
    path: &Path,
) -> Result<ThermalEvidenceV1, ThermalEvidenceError> {
    let text = fs::read_to_string(path).map_err(|error| {
        ThermalEvidenceError::new(
            ThermalEvidenceErrorCode::ThermalEvidenceArtifactInvalid,
            "thermal_evidence_load",
            format!(
                "failed to read thermal evidence artifact {}: {error}",
                path.display()
            ),
        )
    })?;
    let artifact: ThermalEvidenceV1 = serde_json::from_str(&text).map_err(|error| {
        ThermalEvidenceError::new(
            ThermalEvidenceErrorCode::ThermalEvidenceArtifactInvalid,
            "thermal_evidence_load",
            format!(
                "failed to decode thermal evidence artifact {}: {error}",
                path.display()
            ),
        )
    })?;
    validate_thermal_evidence(&artifact).map_err(|error| {
        let code = match error.code {
            ArtifactValidationErrorCode::ArtifactSchemaIdInvalid
            | ArtifactValidationErrorCode::ArtifactSchemaVersionInvalid
            | ArtifactValidationErrorCode::ArtifactPayloadCorrupt
            | ArtifactValidationErrorCode::ContractBasisInvalid => {
                ThermalEvidenceErrorCode::ThermalEvidenceArtifactInvalid
            }
        };
        ThermalEvidenceError::new(code, "thermal_evidence_validate", error.message)
    })?;

    Ok(artifact)
}

fn current_epoch_marker() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    format!("unix:{seconds}")
}

fn read_hostname() -> Option<String> {
    fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn sanitize_artifact_id_part(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
            out.push(character.to_ascii_lowercase());
        } else {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "local".to_string()
    } else {
        trimmed.to_string()
    }
}
