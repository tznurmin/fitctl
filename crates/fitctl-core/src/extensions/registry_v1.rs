// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Generic extension-evaluator registry used by validation to dispatch requirement checks.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::extensions::cuda_runtime_v1::{
    decode_cuda_runtime_contract_from_value, decode_cuda_runtime_requirement_from_value,
    evaluate_cuda_runtime_requirement_v1, CudaRuntimeEvaluationOutcomeV1, CUDA_RUNTIME_NAMESPACE,
};
use crate::extensions::node_runtime_v1::{
    decode_node_runtime_contract_from_value, decode_node_runtime_requirement_from_value,
    evaluate_node_runtime_requirement_v1, NodeRuntimeEvaluationOutcomeV1, NODE_RUNTIME_NAMESPACE,
};
use crate::extensions::python_runtime_v1::{
    decode_python_runtime_contract_from_value, decode_python_runtime_requirement_from_value,
    evaluate_python_runtime_requirement_v1, PythonRuntimeEvaluationOutcomeV1,
    PYTHON_RUNTIME_NAMESPACE,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionEvaluatorRegistryErrorKindV1 {
    RegistryInvalid,
    ExtensionPayloadInvalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionEvaluatorRegistryErrorV1 {
    pub kind: ExtensionEvaluatorRegistryErrorKindV1,
    pub checkpoint_id: &'static str,
    pub message: String,
}

impl ExtensionEvaluatorRegistryErrorV1 {
    fn new(
        kind: ExtensionEvaluatorRegistryErrorKindV1,
        checkpoint_id: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            checkpoint_id,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ExtensionEvaluatorRegistryErrorV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} [fitctl.extension_registry.v1 at {}]",
            self.message, self.checkpoint_id
        )
    }
}

impl std::error::Error for ExtensionEvaluatorRegistryErrorV1 {}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Namespace-agnostic outcome returned to core validation after one extension check.
pub enum ExtensionRequirementEvaluationOutcomeV1 {
    Satisfied,
    Unsatisfied { summary: String },
}

pub type ExtensionRequirementEvaluatorFnV1 =
    fn(
        &Value,
        &Value,
    ) -> Result<ExtensionRequirementEvaluationOutcomeV1, ExtensionEvaluatorRegistryErrorV1>;

#[derive(Clone, Copy)]
/// One namespace-specific evaluator registered with the built-in registry.
pub struct RegisteredExtensionEvaluatorV1 {
    pub namespace: &'static str,
    pub evaluate_requirement: ExtensionRequirementEvaluatorFnV1,
}

const REGISTERED_EXTENSION_EVALUATORS_V1: &[RegisteredExtensionEvaluatorV1] = &[
    RegisteredExtensionEvaluatorV1 {
        namespace: CUDA_RUNTIME_NAMESPACE,
        evaluate_requirement: evaluate_cuda_runtime_requirement_from_values_v1,
    },
    RegisteredExtensionEvaluatorV1 {
        namespace: NODE_RUNTIME_NAMESPACE,
        evaluate_requirement: evaluate_node_runtime_requirement_from_values_v1,
    },
    RegisteredExtensionEvaluatorV1 {
        namespace: PYTHON_RUNTIME_NAMESPACE,
        evaluate_requirement: evaluate_python_runtime_requirement_from_values_v1,
    },
];

/// Validate that the built-in registry does not register the same namespace twice.
pub fn validate_extension_evaluator_registry_v1(
    evaluators: &[RegisteredExtensionEvaluatorV1],
) -> Result<(), ExtensionEvaluatorRegistryErrorV1> {
    let mut seen = BTreeSet::new();
    for evaluator in evaluators {
        if !seen.insert(evaluator.namespace) {
            return Err(ExtensionEvaluatorRegistryErrorV1::new(
                ExtensionEvaluatorRegistryErrorKindV1::RegistryInvalid,
                "extension_registry_validate",
                format!(
                    "duplicate extension evaluator registration is invalid for namespace {}",
                    evaluator.namespace
                ),
            ));
        }
    }
    Ok(())
}

pub fn registered_extension_evaluator_namespaces_v1(
) -> Result<Vec<&'static str>, ExtensionEvaluatorRegistryErrorV1> {
    validate_extension_evaluator_registry_v1(REGISTERED_EXTENSION_EVALUATORS_V1)?;
    let mut namespaces = REGISTERED_EXTENSION_EVALUATORS_V1
        .iter()
        .map(|evaluator| evaluator.namespace)
        .collect::<Vec<_>>();
    namespaces.sort_unstable();
    Ok(namespaces)
}

/// Evaluate one extension requirement through the registry.
///
/// None means the namespace is not registered in the built-in evaluator set.
pub fn evaluate_registered_extension_requirement_v1(
    namespace: &str,
    contract_value: &Value,
    requirement_value: &Value,
) -> Result<Option<ExtensionRequirementEvaluationOutcomeV1>, ExtensionEvaluatorRegistryErrorV1> {
    validate_extension_evaluator_registry_v1(REGISTERED_EXTENSION_EVALUATORS_V1)?;
    let evaluator = REGISTERED_EXTENSION_EVALUATORS_V1
        .iter()
        .find(|evaluator| evaluator.namespace == namespace);

    match evaluator {
        Some(evaluator) => {
            (evaluator.evaluate_requirement)(contract_value, requirement_value).map(Some)
        }
        None => Ok(None),
    }
}

fn evaluate_python_runtime_requirement_from_values_v1(
    contract_value: &Value,
    requirement_value: &Value,
) -> Result<ExtensionRequirementEvaluationOutcomeV1, ExtensionEvaluatorRegistryErrorV1> {
    let contract = decode_python_runtime_contract_from_value(contract_value).map_err(|error| {
        ExtensionEvaluatorRegistryErrorV1::new(
            ExtensionEvaluatorRegistryErrorKindV1::ExtensionPayloadInvalid,
            "extension_registry_python_contract_decode",
            error.message,
        )
    })?;
    let requirement =
        decode_python_runtime_requirement_from_value(requirement_value).map_err(|error| {
            ExtensionEvaluatorRegistryErrorV1::new(
                ExtensionEvaluatorRegistryErrorKindV1::ExtensionPayloadInvalid,
                "extension_registry_python_requirement_decode",
                error.message,
            )
        })?;

    let outcome =
        evaluate_python_runtime_requirement_v1(&contract, &requirement).map_err(|error| {
            ExtensionEvaluatorRegistryErrorV1::new(
                ExtensionEvaluatorRegistryErrorKindV1::ExtensionPayloadInvalid,
                "extension_registry_python_evaluate",
                error.message,
            )
        })?;

    Ok(match outcome {
        PythonRuntimeEvaluationOutcomeV1::Satisfied => {
            ExtensionRequirementEvaluationOutcomeV1::Satisfied
        }
        PythonRuntimeEvaluationOutcomeV1::Unsatisfied { summary } => {
            ExtensionRequirementEvaluationOutcomeV1::Unsatisfied { summary }
        }
    })
}

fn evaluate_cuda_runtime_requirement_from_values_v1(
    contract_value: &Value,
    requirement_value: &Value,
) -> Result<ExtensionRequirementEvaluationOutcomeV1, ExtensionEvaluatorRegistryErrorV1> {
    let contract = decode_cuda_runtime_contract_from_value(contract_value).map_err(|error| {
        ExtensionEvaluatorRegistryErrorV1::new(
            ExtensionEvaluatorRegistryErrorKindV1::ExtensionPayloadInvalid,
            "extension_registry_cuda_contract_decode",
            error.message,
        )
    })?;
    let requirement =
        decode_cuda_runtime_requirement_from_value(requirement_value).map_err(|error| {
            ExtensionEvaluatorRegistryErrorV1::new(
                ExtensionEvaluatorRegistryErrorKindV1::ExtensionPayloadInvalid,
                "extension_registry_cuda_requirement_decode",
                error.message,
            )
        })?;

    let outcome =
        evaluate_cuda_runtime_requirement_v1(&contract, &requirement).map_err(|error| {
            ExtensionEvaluatorRegistryErrorV1::new(
                ExtensionEvaluatorRegistryErrorKindV1::ExtensionPayloadInvalid,
                "extension_registry_cuda_evaluate",
                error.message,
            )
        })?;

    Ok(match outcome {
        CudaRuntimeEvaluationOutcomeV1::Satisfied => {
            ExtensionRequirementEvaluationOutcomeV1::Satisfied
        }
        CudaRuntimeEvaluationOutcomeV1::Unsatisfied { summary } => {
            ExtensionRequirementEvaluationOutcomeV1::Unsatisfied { summary }
        }
    })
}

fn evaluate_node_runtime_requirement_from_values_v1(
    contract_value: &Value,
    requirement_value: &Value,
) -> Result<ExtensionRequirementEvaluationOutcomeV1, ExtensionEvaluatorRegistryErrorV1> {
    let contract = decode_node_runtime_contract_from_value(contract_value).map_err(|error| {
        ExtensionEvaluatorRegistryErrorV1::new(
            ExtensionEvaluatorRegistryErrorKindV1::ExtensionPayloadInvalid,
            "extension_registry_node_contract_decode",
            error.message,
        )
    })?;
    let requirement =
        decode_node_runtime_requirement_from_value(requirement_value).map_err(|error| {
            ExtensionEvaluatorRegistryErrorV1::new(
                ExtensionEvaluatorRegistryErrorKindV1::ExtensionPayloadInvalid,
                "extension_registry_node_requirement_decode",
                error.message,
            )
        })?;

    let outcome =
        evaluate_node_runtime_requirement_v1(&contract, &requirement).map_err(|error| {
            ExtensionEvaluatorRegistryErrorV1::new(
                ExtensionEvaluatorRegistryErrorKindV1::ExtensionPayloadInvalid,
                "extension_registry_node_evaluate",
                error.message,
            )
        })?;

    Ok(match outcome {
        NodeRuntimeEvaluationOutcomeV1::Satisfied => {
            ExtensionRequirementEvaluationOutcomeV1::Satisfied
        }
        NodeRuntimeEvaluationOutcomeV1::Unsatisfied { summary } => {
            ExtensionRequirementEvaluationOutcomeV1::Unsatisfied { summary }
        }
    })
}
