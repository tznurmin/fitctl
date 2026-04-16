// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Optional extension namespaces and evaluator registry.
//!
//! Extensions live outside the closed Ring 1 core. They can contribute evidence, contract
//! fragments, and requirement evaluation through a registry seam without silently widening the
//! core host model.

pub mod node_runtime_v1;
pub mod python_runtime_v1;
pub mod registry_v1;

pub use node_runtime_v1::{
    apply_node_runtime_extension_to_survey_v1, decode_node_runtime_contract_from_value,
    decode_node_runtime_evidence_from_value, decode_node_runtime_requirement_from_value,
    derive_node_runtime_contract_value_from_survey_v1, evaluate_node_runtime_requirement_v1,
    format_node_runtime_contract_for_inspect, format_node_runtime_evidence_for_inspect,
    format_node_runtime_requirement_for_inspect, redact_node_runtime_evidence_export_v1,
    NodeRuntimeContractV1, NodeRuntimeEvaluationOutcomeV1, NodeRuntimeEvidenceStateV1,
    NodeRuntimeEvidenceV1, NodeRuntimeExtensionError, NodeRuntimeRequirementV1,
    NodeRuntimeVersionRangeV1, NodeRuntimeVersionV1, NODE_RUNTIME_CONTRACT_SCHEMA_ID,
    NODE_RUNTIME_EVIDENCE_SCHEMA_ID, NODE_RUNTIME_NAMESPACE, NODE_RUNTIME_REQUIREMENT_SCHEMA_ID,
};
pub use python_runtime_v1::{
    apply_python_runtime_extension_to_survey_v1, decode_python_runtime_contract_from_value,
    decode_python_runtime_evidence_from_value, decode_python_runtime_requirement_from_value,
    derive_python_runtime_contract_value_from_survey_v1, evaluate_python_runtime_requirement_v1,
    format_python_runtime_contract_for_inspect, format_python_runtime_evidence_for_inspect,
    format_python_runtime_requirement_for_inspect, redact_python_runtime_evidence_export_v1,
    PythonRuntimeContractV1, PythonRuntimeEvaluationOutcomeV1, PythonRuntimeEvidenceStateV1,
    PythonRuntimeEvidenceV1, PythonRuntimeExtensionError, PythonRuntimeRequirementV1,
    PythonRuntimeVersionRangeV1, PythonRuntimeVersionV1, PYTHON_RUNTIME_CONTRACT_SCHEMA_ID,
    PYTHON_RUNTIME_EVIDENCE_SCHEMA_ID, PYTHON_RUNTIME_NAMESPACE,
    PYTHON_RUNTIME_REQUIREMENT_SCHEMA_ID,
};
pub use registry_v1::{
    evaluate_registered_extension_requirement_v1, registered_extension_evaluator_namespaces_v1,
    validate_extension_evaluator_registry_v1, ExtensionEvaluatorRegistryErrorKindV1,
    ExtensionEvaluatorRegistryErrorV1, ExtensionRequirementEvaluationOutcomeV1,
    RegisteredExtensionEvaluatorV1,
};
