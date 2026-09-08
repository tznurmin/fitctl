// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Policy ingress preserves raw JSON distinctions before typed decoding.

use super::schema_v1::PolicyDocumentV1;
use super::validation_v1::{validate_policy_document, validate_policy_document_json};
use crate::contract::{ContractDerivationError, ContractDerivationErrorCode};
use serde_json::Value;
use std::fs;
use std::path::Path;

pub fn load_policy_document_from_path(
    path: &Path,
) -> Result<PolicyDocumentV1, ContractDerivationError> {
    let text = fs::read_to_string(path).map_err(|error| {
        ContractDerivationError::new(
            ContractDerivationErrorCode::PolicyDocumentInvalid,
            "policy_load",
            format!("failed to read policy document {}: {error}", path.display()),
        )
    })?;

    let raw: Value = serde_json::from_str(&text).map_err(|error| {
        ContractDerivationError::new(
            ContractDerivationErrorCode::PolicyDocumentInvalid,
            "policy_load",
            format!(
                "failed to decode policy document {}: {error}",
                path.display()
            ),
        )
    })?;
    decode_policy_document(raw, Some(path))
}

/// Validate supplied JSON with the same raw, typed and semantic checks as file ingress.
///
/// Explicit nulls are not omissions. This performs no I/O and supplies no source path.
/// Duplicate object keys already lost by the caller's JSON parser cannot be recovered.
pub fn load_policy_document_from_value(
    raw: Value,
) -> Result<PolicyDocumentV1, ContractDerivationError> {
    decode_policy_document(raw, None)
}

fn decode_policy_document(
    raw: Value,
    source_path: Option<&Path>,
) -> Result<PolicyDocumentV1, ContractDerivationError> {
    validate_policy_document_json(&raw)?;
    let policy: PolicyDocumentV1 = serde_json::from_value(raw).map_err(|error| {
        ContractDerivationError::new(
            ContractDerivationErrorCode::PolicyDocumentInvalid,
            "policy_load",
            match source_path {
                Some(path) => format!(
                    "failed to decode typed policy document {}: {error}",
                    path.display()
                ),
                None => format!("failed to decode typed policy document: {error}"),
            },
        )
    })?;

    validate_policy_document(&policy)?;
    Ok(policy)
}
