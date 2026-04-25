// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Typed local CUDA environment catalogue loading and deterministic entry resolution.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const CUDA_ENVIRONMENT_CATALOGUE_SCHEMA_ID: &str = "fitctl.cuda-environment-catalogue.v1";
pub const CUDA_ENVIRONMENT_CATALOGUE_ERROR_MODEL_ID: &str = "fitctl.cuda_environment_catalogue.v1";
pub const CUDA_ENVIRONMENT_CATALOGUE_ERROR_MODEL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CudaEnvironmentCatalogueErrorCode {
    CatalogueInputInvalid,
    CatalogueSelectionInvalid,
}

impl CudaEnvironmentCatalogueErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CatalogueInputInvalid => "catalogue_input_invalid",
            Self::CatalogueSelectionInvalid => "catalogue_selection_invalid",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CudaEnvironmentCatalogueError {
    pub code: CudaEnvironmentCatalogueErrorCode,
    pub checkpoint_id: &'static str,
    pub message: String,
    pub error_model_id: &'static str,
    pub error_model_version: u32,
}

impl CudaEnvironmentCatalogueError {
    fn new(
        code: CudaEnvironmentCatalogueErrorCode,
        checkpoint_id: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            checkpoint_id,
            message: message.into(),
            error_model_id: CUDA_ENVIRONMENT_CATALOGUE_ERROR_MODEL_ID,
            error_model_version: CUDA_ENVIRONMENT_CATALOGUE_ERROR_MODEL_VERSION,
        }
    }
}

impl std::fmt::Display for CudaEnvironmentCatalogueError {
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

impl std::error::Error for CudaEnvironmentCatalogueError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CudaEnvironmentSelectionKindV1 {
    DefaultView,
    ToolkitInstallRoot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CudaEnvironmentSelectionV1 {
    pub kind: CudaEnvironmentSelectionKindV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_root: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CudaEnvironmentCatalogueEntryV1 {
    pub environment_id: String,
    pub summary: String,
    pub selection: CudaEnvironmentSelectionV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CudaEnvironmentCatalogueV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub catalogue_id: String,
    pub catalogue_version: String,
    pub summary: String,
    pub environments: Vec<CudaEnvironmentCatalogueEntryV1>,
}

pub fn load_cuda_environment_catalogue_from_path(
    path: &Path,
) -> Result<CudaEnvironmentCatalogueV1, CudaEnvironmentCatalogueError> {
    let raw = fs::read_to_string(path).map_err(|error| {
        CudaEnvironmentCatalogueError::new(
            CudaEnvironmentCatalogueErrorCode::CatalogueInputInvalid,
            "cuda_environment_catalogue_load",
            format!(
                "failed to read CUDA environment catalogue {}: {error}",
                path.display()
            ),
        )
    })?;
    let value: Value = serde_json::from_str(&raw).map_err(|error| {
        CudaEnvironmentCatalogueError::new(
            CudaEnvironmentCatalogueErrorCode::CatalogueInputInvalid,
            "cuda_environment_catalogue_load",
            format!(
                "failed to decode CUDA environment catalogue {}: {error}",
                path.display()
            ),
        )
    })?;
    let catalogue: CudaEnvironmentCatalogueV1 = serde_json::from_value(value).map_err(|error| {
        CudaEnvironmentCatalogueError::new(
            CudaEnvironmentCatalogueErrorCode::CatalogueInputInvalid,
            "cuda_environment_catalogue_load",
            format!(
                "failed to decode CUDA environment catalogue {}: {error}",
                path.display()
            ),
        )
    })?;
    validate_cuda_environment_catalogue(&catalogue)?;
    Ok(catalogue)
}

pub fn resolve_cuda_environment_from_catalogue(
    catalogue: &CudaEnvironmentCatalogueV1,
    environment_id: &str,
) -> Result<CudaEnvironmentCatalogueEntryV1, CudaEnvironmentCatalogueError> {
    validate_cuda_environment_catalogue(catalogue)?;
    let environment_id = environment_id.trim();
    if environment_id.is_empty() {
        return Err(CudaEnvironmentCatalogueError::new(
            CudaEnvironmentCatalogueErrorCode::CatalogueSelectionInvalid,
            "cuda_environment_catalogue_resolve",
            "CUDA environment selection id must be non-blank",
        ));
    }
    catalogue
        .environments
        .iter()
        .find(|entry| entry.environment_id == environment_id)
        .cloned()
        .ok_or_else(|| {
            CudaEnvironmentCatalogueError::new(
                CudaEnvironmentCatalogueErrorCode::CatalogueSelectionInvalid,
                "cuda_environment_catalogue_resolve",
                format!(
                    "CUDA environment catalogue does not define environment id {environment_id}"
                ),
            )
        })
}

pub fn resolve_cuda_environment_from_catalogue_path(
    path: &Path,
    environment_id: &str,
) -> Result<
    (CudaEnvironmentCatalogueV1, CudaEnvironmentCatalogueEntryV1),
    CudaEnvironmentCatalogueError,
> {
    let catalogue = load_cuda_environment_catalogue_from_path(path)?;
    let entry = resolve_cuda_environment_from_catalogue(&catalogue, environment_id)?;
    Ok((catalogue, entry))
}

pub fn validate_cuda_environment_catalogue(
    catalogue: &CudaEnvironmentCatalogueV1,
) -> Result<(), CudaEnvironmentCatalogueError> {
    if catalogue.schema_id != CUDA_ENVIRONMENT_CATALOGUE_SCHEMA_ID || catalogue.schema_version != 1
    {
        return Err(CudaEnvironmentCatalogueError::new(
            CudaEnvironmentCatalogueErrorCode::CatalogueInputInvalid,
            "cuda_environment_catalogue_validate",
            "CUDA environment catalogue must declare the supported schema id and schema version",
        ));
    }
    validate_non_blank(
        &catalogue.catalogue_id,
        "catalogue_id",
        "cuda_environment_catalogue_validate",
    )?;
    validate_non_blank(
        &catalogue.catalogue_version,
        "catalogue_version",
        "cuda_environment_catalogue_validate",
    )?;
    validate_non_blank(
        &catalogue.summary,
        "summary",
        "cuda_environment_catalogue_validate",
    )?;
    if catalogue.environments.is_empty() {
        return Err(CudaEnvironmentCatalogueError::new(
            CudaEnvironmentCatalogueErrorCode::CatalogueInputInvalid,
            "cuda_environment_catalogue_validate",
            "CUDA environment catalogue must define at least one environment entry",
        ));
    }

    let mut ids = BTreeSet::new();
    for entry in &catalogue.environments {
        validate_non_blank(
            &entry.environment_id,
            "environment_id",
            "cuda_environment_catalogue_validate",
        )?;
        validate_non_blank(
            &entry.summary,
            "summary",
            "cuda_environment_catalogue_validate",
        )?;
        if !ids.insert(entry.environment_id.clone()) {
            return Err(CudaEnvironmentCatalogueError::new(
                CudaEnvironmentCatalogueErrorCode::CatalogueInputInvalid,
                "cuda_environment_catalogue_validate",
                "CUDA environment catalogue must not repeat one environment_id",
            ));
        }
        match entry.selection.kind {
            CudaEnvironmentSelectionKindV1::DefaultView => {
                if entry.selection.install_root.is_some() {
                    return Err(CudaEnvironmentCatalogueError::new(
                        CudaEnvironmentCatalogueErrorCode::CatalogueInputInvalid,
                        "cuda_environment_catalogue_validate",
                        "default_view CUDA environment entries must not carry install_root",
                    ));
                }
            }
            CudaEnvironmentSelectionKindV1::ToolkitInstallRoot => {
                let Some(install_root) = entry.selection.install_root.as_deref() else {
                    return Err(CudaEnvironmentCatalogueError::new(
                        CudaEnvironmentCatalogueErrorCode::CatalogueInputInvalid,
                        "cuda_environment_catalogue_validate",
                        "toolkit_install_root CUDA environment entries must carry install_root",
                    ));
                };
                if install_root.trim().is_empty() || !Path::new(install_root).is_absolute() {
                    return Err(CudaEnvironmentCatalogueError::new(
                        CudaEnvironmentCatalogueErrorCode::CatalogueInputInvalid,
                        "cuda_environment_catalogue_validate",
                        "toolkit_install_root CUDA environment entries must use an absolute non-blank install_root",
                    ));
                }
            }
        }
    }

    Ok(())
}

fn validate_non_blank(
    value: &str,
    field_name: &str,
    checkpoint_id: &'static str,
) -> Result<(), CudaEnvironmentCatalogueError> {
    if value.trim().is_empty() {
        return Err(CudaEnvironmentCatalogueError::new(
            CudaEnvironmentCatalogueErrorCode::CatalogueInputInvalid,
            checkpoint_id,
            format!("CUDA environment catalogue field {field_name} must be non-blank"),
        ));
    }
    Ok(())
}
