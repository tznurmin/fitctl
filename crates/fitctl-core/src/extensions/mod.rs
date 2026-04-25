// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Optional extension namespaces and evaluator registry.
//!
//! Extensions live outside the closed core host model. They can contribute evidence, contract
//! fragments, and requirement evaluation through a registry seam without silently widening that
//! model.

pub mod cuda_runtime_v1;
pub mod node_runtime_v1;
pub mod python_runtime_v1;
pub mod registry_v1;

pub use cuda_runtime_v1::{
    apply_cuda_runtime_extension_to_state_v1,
    apply_cuda_runtime_extension_to_state_with_selection_v1,
    apply_cuda_runtime_extension_to_survey_v1,
    apply_cuda_runtime_extension_to_survey_with_selection_v1,
    decode_cuda_runtime_contract_from_value, decode_cuda_runtime_evidence_from_value,
    decode_cuda_runtime_requirement_from_value, decode_cuda_runtime_state_from_value,
    decode_cuda_runtime_validation_diagnostic_from_value,
    derive_cuda_runtime_contract_value_from_survey_v1, evaluate_cuda_runtime_requirement_v1,
    format_cuda_runtime_contract_for_inspect, format_cuda_runtime_evidence_for_inspect,
    format_cuda_runtime_requirement_for_inspect, format_cuda_runtime_state_for_inspect,
    format_cuda_runtime_validation_diagnostic_for_inspect,
    load_cuda_selected_environment_input_from_path, redact_cuda_runtime_evidence_export_v1,
    CudaRuntimeContractV1, CudaRuntimeDeviceStateV1, CudaRuntimeEvaluationOutcomeV1,
    CudaRuntimeEvidenceStateV1, CudaRuntimeEvidenceV1, CudaRuntimeExtensionError,
    CudaRuntimeRequirementV1, CudaRuntimeStateV1, CudaRuntimeValidationCheckpointV1,
    CudaRuntimeValidationDetailCodeV1, CudaRuntimeValidationDiagnosticV1,
    CudaRuntimeVersionRangeV1, CudaRuntimeVersionV1, CudaSelectedEnvironmentInputV1,
    CudaSelectedEnvironmentRequestV1, CudaSelectedEnvironmentV1, CUDA_RUNTIME_CONTRACT_SCHEMA_ID,
    CUDA_RUNTIME_EVIDENCE_SCHEMA_ID, CUDA_RUNTIME_NAMESPACE, CUDA_RUNTIME_REQUIREMENT_SCHEMA_ID,
    CUDA_RUNTIME_STATE_SCHEMA_ID, CUDA_RUNTIME_VALIDATION_DIAGNOSTIC_MODEL_ID,
    CUDA_SELECTED_ENVIRONMENT_INPUT_SCHEMA_ID,
};
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
