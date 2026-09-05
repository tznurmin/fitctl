// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Coherence checks that bind optional contract payloads to their declared semantic basis.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::artifacts::contract_v1::ContractExtensionBasisV1;
use crate::artifacts::validation_v1::{ArtifactValidationError, ArtifactValidationErrorCode};

pub(crate) fn validate_contract_extension_integrity_v1(
    basis: Option<&ContractExtensionBasisV1>,
    extension_contract: &BTreeMap<String, Value>,
) -> Result<(), ArtifactValidationError> {
    let Some(basis) = basis else {
        if extension_contract.is_empty() {
            return Ok(());
        }
        return Err(invalid(
            "host contract extension payload requires an extension basis",
        ));
    };

    let enabled = basis
        .enabled_extension_namespaces
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let semantic_hash_keys = basis
        .extension_semantic_hashes
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();

    if enabled.len() != basis.enabled_extension_namespaces.len() || enabled != semantic_hash_keys {
        return Err(invalid(
            "host contract enabled extension namespaces must exactly match semantic-hash keys",
        ));
    }
    if !basis
        .extension_semantic_hashes
        .values()
        .all(|hash| is_lowercase_sha256_hex(hash))
    {
        return Err(invalid(
            "host contract extension semantic hashes must be 64-character lowercase SHA-256 hex",
        ));
    }

    let payload_namespaces = extension_contract
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if !payload_namespaces.is_subset(&enabled) {
        return Err(invalid(
            "host contract extension payload namespaces must be a subset of enabled namespaces",
        ));
    }

    Ok(())
}

fn invalid(message: &'static str) -> ArtifactValidationError {
    ArtifactValidationError::new(ArtifactValidationErrorCode::ContractBasisInvalid, message)
}

fn is_lowercase_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
