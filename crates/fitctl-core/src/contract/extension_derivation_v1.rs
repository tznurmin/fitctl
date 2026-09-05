// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Derive only extension contracts that the caller explicitly activated and pinned.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::artifacts::contract_v1::ContractExtensionBasisV1;
use crate::artifacts::survey_v1::HostSurveyV1;
use crate::contract::{ContractDerivationError, ContractDerivationErrorCode};
use crate::extensions::{
    derive_cuda_runtime_contract_value_from_survey_v1,
    derive_node_runtime_contract_value_from_survey_v1,
    derive_python_runtime_contract_value_from_survey_v1, CUDA_RUNTIME_NAMESPACE,
    NODE_RUNTIME_NAMESPACE, PYTHON_RUNTIME_NAMESPACE,
};

pub(crate) fn derive_enabled_extension_contract_v1(
    survey: &HostSurveyV1,
    basis: &ContractExtensionBasisV1,
) -> Result<BTreeMap<String, Value>, ContractDerivationError> {
    let enabled = basis
        .enabled_extension_namespaces
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut extension_contract = BTreeMap::new();

    if enabled.contains(PYTHON_RUNTIME_NAMESPACE) {
        if let Some(value) = derive_python_runtime_contract_value_from_survey_v1(survey)
            .map_err(|error| derive_error("python_extension_contract_derive", error.message))?
        {
            extension_contract.insert(PYTHON_RUNTIME_NAMESPACE.to_string(), value);
        }
    }
    if enabled.contains(NODE_RUNTIME_NAMESPACE) {
        if let Some(value) = derive_node_runtime_contract_value_from_survey_v1(survey)
            .map_err(|error| derive_error("node_extension_contract_derive", error.message))?
        {
            extension_contract.insert(NODE_RUNTIME_NAMESPACE.to_string(), value);
        }
    }
    if enabled.contains(CUDA_RUNTIME_NAMESPACE) {
        if let Some(value) = derive_cuda_runtime_contract_value_from_survey_v1(survey)
            .map_err(|error| derive_error("cuda_extension_contract_derive", error.message))?
        {
            extension_contract.insert(CUDA_RUNTIME_NAMESPACE.to_string(), value);
        }
    }

    Ok(extension_contract)
}

fn derive_error(
    checkpoint_id: &'static str,
    message: impl Into<String>,
) -> ContractDerivationError {
    ContractDerivationError::new(
        ContractDerivationErrorCode::ContractDerivationFailed,
        checkpoint_id,
        message,
    )
}
