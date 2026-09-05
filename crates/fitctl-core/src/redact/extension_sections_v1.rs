// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Closed, section-aware dispatch for redacting typed extension maps.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

use crate::extensions::{
    decode_cuda_runtime_contract_from_value, decode_cuda_runtime_evidence_from_value,
    decode_cuda_runtime_requirement_from_value, decode_cuda_runtime_state_from_value,
    decode_cuda_runtime_validation_diagnostic_from_value, decode_node_runtime_contract_from_value,
    decode_node_runtime_evidence_from_value, decode_node_runtime_requirement_from_value,
    decode_python_runtime_contract_from_value, decode_python_runtime_evidence_from_value,
    decode_python_runtime_requirement_from_value, CUDA_RUNTIME_NAMESPACE, NODE_RUNTIME_NAMESPACE,
    PYTHON_RUNTIME_NAMESPACE,
};
use crate::redact::extension_payloads_v1::{
    redact_cuda_contract_v1, redact_cuda_diagnostic_v1, redact_cuda_evidence_v1,
    redact_cuda_state_v1, redact_node_contract_v1, redact_node_evidence_v1,
    redact_python_contract_v1, redact_python_evidence_v1,
};
use crate::redact::profile_v1::BuiltInRedactionProfileV1;
use crate::redact::{RedactionError, RedactionErrorCode};

pub(crate) fn redact_extension_evidence_v1(
    values: &mut BTreeMap<String, Value>,
    profile: BuiltInRedactionProfileV1,
) -> Result<(), RedactionError> {
    for namespace in values.keys().cloned().collect::<Vec<_>>() {
        let value = values
            .get_mut(&namespace)
            .expect("extension key must remain");
        match namespace.as_str() {
            CUDA_RUNTIME_NAMESPACE => {
                let mut typed = decode_cuda_runtime_evidence_from_value(value)
                    .map_err(|error| input_error("extension_evidence", &namespace, error))?;
                redact_cuda_evidence_v1(&mut typed, profile);
                *value = encode_and_validate(
                    typed,
                    "extension_evidence",
                    &namespace,
                    decode_cuda_runtime_evidence_from_value,
                )?;
            }
            PYTHON_RUNTIME_NAMESPACE => {
                let mut typed = decode_python_runtime_evidence_from_value(value)
                    .map_err(|error| input_error("extension_evidence", &namespace, error))?;
                redact_python_evidence_v1(&mut typed, profile);
                *value = encode_and_validate(
                    typed,
                    "extension_evidence",
                    &namespace,
                    decode_python_runtime_evidence_from_value,
                )?;
            }
            NODE_RUNTIME_NAMESPACE => {
                let mut typed = decode_node_runtime_evidence_from_value(value)
                    .map_err(|error| input_error("extension_evidence", &namespace, error))?;
                redact_node_evidence_v1(&mut typed, profile);
                *value = encode_and_validate(
                    typed,
                    "extension_evidence",
                    &namespace,
                    decode_node_runtime_evidence_from_value,
                )?;
            }
            _ => reject_unregistered("extension_evidence", &namespace, profile)?,
        }
    }
    Ok(())
}

pub(crate) fn redact_extension_contract_v1(
    values: &mut BTreeMap<String, Value>,
    profile: BuiltInRedactionProfileV1,
) -> Result<(), RedactionError> {
    for namespace in values.keys().cloned().collect::<Vec<_>>() {
        require_extension_contract_redactor_v1(&namespace, profile, "extension_contract")?;
        let value = values
            .get_mut(&namespace)
            .expect("extension key must remain");
        match namespace.as_str() {
            CUDA_RUNTIME_NAMESPACE => {
                let mut typed = decode_cuda_runtime_contract_from_value(value)
                    .map_err(|error| input_error("extension_contract", &namespace, error))?;
                redact_cuda_contract_v1(&mut typed, profile);
                *value = encode_and_validate(
                    typed,
                    "extension_contract",
                    &namespace,
                    decode_cuda_runtime_contract_from_value,
                )?;
            }
            PYTHON_RUNTIME_NAMESPACE => {
                let mut typed = decode_python_runtime_contract_from_value(value)
                    .map_err(|error| input_error("extension_contract", &namespace, error))?;
                redact_python_contract_v1(&mut typed, profile);
                *value = encode_and_validate(
                    typed,
                    "extension_contract",
                    &namespace,
                    decode_python_runtime_contract_from_value,
                )?;
            }
            NODE_RUNTIME_NAMESPACE => {
                let mut typed = decode_node_runtime_contract_from_value(value)
                    .map_err(|error| input_error("extension_contract", &namespace, error))?;
                redact_node_contract_v1(&mut typed, profile);
                *value = encode_and_validate(
                    typed,
                    "extension_contract",
                    &namespace,
                    decode_node_runtime_contract_from_value,
                )?;
            }
            _ => {}
        }
    }
    Ok(())
}

pub(crate) fn require_extension_contract_redactor_v1(
    namespace: &str,
    profile: BuiltInRedactionProfileV1,
    section: &'static str,
) -> Result<(), RedactionError> {
    match namespace {
        CUDA_RUNTIME_NAMESPACE | PYTHON_RUNTIME_NAMESPACE | NODE_RUNTIME_NAMESPACE => Ok(()),
        _ => reject_unregistered(section, namespace, profile),
    }
}

pub(crate) fn redact_extension_requirements_v1(
    values: &mut BTreeMap<String, Value>,
    profile: BuiltInRedactionProfileV1,
) -> Result<(), RedactionError> {
    for namespace in values.keys().cloned().collect::<Vec<_>>() {
        let value = values
            .get_mut(&namespace)
            .expect("extension key must remain");
        match namespace.as_str() {
            CUDA_RUNTIME_NAMESPACE => {
                let typed = decode_cuda_runtime_requirement_from_value(value)
                    .map_err(|error| input_error("extension_requirements", &namespace, error))?;
                *value = encode_and_validate(
                    typed,
                    "extension_requirements",
                    &namespace,
                    decode_cuda_runtime_requirement_from_value,
                )?;
            }
            PYTHON_RUNTIME_NAMESPACE => {
                let typed = decode_python_runtime_requirement_from_value(value)
                    .map_err(|error| input_error("extension_requirements", &namespace, error))?;
                *value = encode_and_validate(
                    typed,
                    "extension_requirements",
                    &namespace,
                    decode_python_runtime_requirement_from_value,
                )?;
            }
            NODE_RUNTIME_NAMESPACE => {
                let typed = decode_node_runtime_requirement_from_value(value)
                    .map_err(|error| input_error("extension_requirements", &namespace, error))?;
                *value = encode_and_validate(
                    typed,
                    "extension_requirements",
                    &namespace,
                    decode_node_runtime_requirement_from_value,
                )?;
            }
            _ => reject_unregistered("extension_requirements", &namespace, profile)?,
        }
    }
    Ok(())
}

pub(crate) fn redact_extension_state_v1(
    values: &mut BTreeMap<String, Value>,
    profile: BuiltInRedactionProfileV1,
) -> Result<(), RedactionError> {
    for namespace in values.keys().cloned().collect::<Vec<_>>() {
        let value = values
            .get_mut(&namespace)
            .expect("extension key must remain");
        match namespace.as_str() {
            CUDA_RUNTIME_NAMESPACE => {
                let mut typed = decode_cuda_runtime_state_from_value(value)
                    .map_err(|error| input_error("extension_state", &namespace, error))?;
                redact_cuda_state_v1(&mut typed, profile);
                *value = encode_and_validate(
                    typed,
                    "extension_state",
                    &namespace,
                    decode_cuda_runtime_state_from_value,
                )?;
            }
            _ => reject_unregistered("extension_state", &namespace, profile)?,
        }
    }
    Ok(())
}

pub(crate) fn redact_extension_diagnostics_v1(
    values: &mut BTreeMap<String, Value>,
    profile: BuiltInRedactionProfileV1,
) -> Result<(), RedactionError> {
    for namespace in values.keys().cloned().collect::<Vec<_>>() {
        let value = values
            .get_mut(&namespace)
            .expect("extension key must remain");
        match namespace.as_str() {
            CUDA_RUNTIME_NAMESPACE => {
                let mut typed = decode_cuda_runtime_validation_diagnostic_from_value(value)
                    .map_err(|error| input_error("extension_diagnostics", &namespace, error))?;
                redact_cuda_diagnostic_v1(&mut typed, profile);
                *value = encode_and_validate(
                    typed,
                    "extension_diagnostics",
                    &namespace,
                    decode_cuda_runtime_validation_diagnostic_from_value,
                )?;
            }
            _ => reject_unregistered("extension_diagnostics", &namespace, profile)?,
        }
    }
    Ok(())
}

fn reject_unregistered(
    section: &'static str,
    namespace: &str,
    profile: BuiltInRedactionProfileV1,
) -> Result<(), RedactionError> {
    if profile.applies_auditor_redactions() {
        return Err(RedactionError::new(
            RedactionErrorCode::ExtensionRedactorUnavailable,
            "extension_redaction_dispatch",
            format!(
                "{section} namespace '{namespace}' has no registered redactor for profile '{}'",
                profile.as_str()
            ),
        ));
    }
    Ok(())
}

fn encode_and_validate<T, E, D>(
    typed: T,
    section: &'static str,
    namespace: &str,
    decode: D,
) -> Result<Value, RedactionError>
where
    T: Serialize,
    E: std::fmt::Display,
    D: FnOnce(&Value) -> Result<T, E>,
{
    let value = serde_json::to_value(typed).map_err(|error| {
        RedactionError::new(
            RedactionErrorCode::RedactionApplyFailed,
            "extension_redaction_encode",
            format!("failed to encode {section} namespace '{namespace}': {error}"),
        )
    })?;
    decode(&value).map_err(|error| {
        RedactionError::new(
            RedactionErrorCode::RedactionOutputInvalid,
            "extension_redaction_validate",
            format!("redacted {section} namespace '{namespace}' is invalid: {error}"),
        )
    })?;
    Ok(value)
}

fn input_error(
    section: &'static str,
    namespace: &str,
    error: impl std::fmt::Display,
) -> RedactionError {
    RedactionError::new(
        RedactionErrorCode::ArtifactInputInvalid,
        "extension_redaction_decode",
        format!("invalid {section} namespace '{namespace}': {error}"),
    )
}
