// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Sharing-boundary validation for host-contract extension lineage.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::artifacts::contract_v1::ContractExtensionBasisV1;
use crate::redact::extension_sections_v1::require_extension_contract_redactor_v1;
use crate::redact::profile_v1::BuiltInRedactionProfileV1;
use crate::redact::{RedactionError, RedactionErrorCode};

pub(crate) fn validate_contract_extension_basis_for_sharing_v1(
    basis: Option<&ContractExtensionBasisV1>,
    extension_contract: &BTreeMap<String, Value>,
    profile: BuiltInRedactionProfileV1,
) -> Result<(), RedactionError> {
    if !profile.applies_auditor_redactions() {
        return Ok(());
    }

    let enabled = basis
        .map(|value| value.enabled_extension_namespaces.as_slice())
        .unwrap_or_default();
    let enabled_set = enabled.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let hash_set = basis
        .map(|value| {
            value
                .extension_semantic_hashes
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let payload_set = extension_contract
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();

    for namespace in &payload_set {
        require_extension_contract_redactor_v1(namespace, profile, "extension_contract")?;
    }
    for namespace in enabled_set.iter().chain(hash_set.iter()) {
        require_extension_contract_redactor_v1(namespace, profile, "contract_extension_basis")?;
    }

    let hashes_are_canonical = basis.is_none_or(|value| {
        value
            .extension_semantic_hashes
            .values()
            .all(|hash| is_lowercase_sha256_hex(hash))
    });
    if enabled.len() != enabled_set.len()
        || enabled_set != hash_set
        || !payload_set.is_subset(&enabled_set)
        || !hashes_are_canonical
    {
        return Err(RedactionError::new(
            RedactionErrorCode::ArtifactInputInvalid,
            "contract_extension_basis_validate",
            "contract extension basis names must match semantic-hash keys, payload namespaces must be a subset, and hashes must be canonical lowercase SHA-256",
        ));
    }

    Ok(())
}

fn is_lowercase_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
