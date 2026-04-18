// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Construction of contract-basis metadata that binds survey evidence to effective policy.

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::artifacts::contract_v1::{
    ContractBasisV1, ContractSemanticBasisV1, DerivationProvenanceV1,
};
use crate::artifacts::schema_ids_v1::TOP_LEVEL_ARTIFACT_SCHEMA_VERSION;
use crate::artifacts::semantic_hash_v1::core_semantic_hash_hex_for_survey;
use crate::artifacts::survey_v1::HostSurveyV1;
use crate::contract::{ContractDerivationError, ContractDerivationErrorCode};
use crate::policy::EffectivePolicyV1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationContextV1 {
    pub derived_at: String,
    pub notes: Option<String>,
}

pub(crate) fn build_contract_basis_v1(
    survey: &HostSurveyV1,
    effective_policy: &EffectivePolicyV1,
    derivation_context: &DerivationContextV1,
) -> Result<ContractBasisV1, ContractDerivationError> {
    if effective_policy.selected_policy_layers.is_empty() {
        return Err(ContractDerivationError::new(
            ContractDerivationErrorCode::ContractBasisInvalid,
            "contract_basis_build",
            "effective policy must retain at least one semantic layer",
        ));
    }

    let source_survey_semantic_hash =
        core_semantic_hash_hex_for_survey(survey).map_err(|error| {
            ContractDerivationError::new(
                ContractDerivationErrorCode::ContractBasisInvalid,
                "contract_basis_build",
                error.message,
            )
        })?;
    let policy_semantic_hash = policy_semantic_hash_hex(effective_policy)?;

    Ok(ContractBasisV1 {
        core_semantic_basis: ContractSemanticBasisV1 {
            source_survey_semantic_hash,
            policy_semantic_hash,
            derivation_engine_id: "fitctl.contract.v1".to_string(),
            derivation_engine_version: "1".to_string(),
            contract_schema_version: TOP_LEVEL_ARTIFACT_SCHEMA_VERSION,
            selected_policy_layers: effective_policy.selected_policy_layers.clone(),
        },
        extension_basis: None,
        derivation_provenance: DerivationProvenanceV1 {
            derived_at: derivation_context.derived_at.clone(),
            notes: derivation_context.notes.clone(),
        },
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PolicySemanticProjectionV1 {
    policy_id: String,
    selected_policy_layers: Vec<String>,
    capability_class: String,
    min_cpu_logical_cores: u32,
    min_memory_bytes: u64,
    allow_container_restricted: bool,
    require_network_visibility: bool,
}

fn policy_semantic_hash_hex(
    effective_policy: &EffectivePolicyV1,
) -> Result<String, ContractDerivationError> {
    let projection = PolicySemanticProjectionV1 {
        policy_id: effective_policy.policy_id.clone(),
        selected_policy_layers: effective_policy.selected_policy_layers.clone(),
        capability_class: effective_policy.capability_class.clone(),
        min_cpu_logical_cores: effective_policy.min_cpu_logical_cores,
        min_memory_bytes: effective_policy.min_memory_bytes,
        allow_container_restricted: effective_policy.allow_container_restricted,
        require_network_visibility: effective_policy.require_network_visibility,
    };

    let bytes = serde_cbor::to_vec(&projection).map_err(|error| {
        ContractDerivationError::new(
            ContractDerivationErrorCode::ContractBasisInvalid,
            "contract_basis_build",
            format!("failed to encode policy semantic projection: {error}"),
        )
    })?;

    let digest = Sha256::digest(bytes);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}
