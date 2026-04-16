// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Host-contract derivation.
//!
//! The contract layer turns observed survey evidence plus policy into a reusable host promise.
//! Validation then compares workload requirements against that promise instead of reinterpreting
//! raw survey evidence on every request.

pub mod contract_basis_v1;
pub mod derivation_v1;
pub mod payload_v1;

pub use contract_basis_v1::DerivationContextV1;
pub use derivation_v1::{
    derive_host_contract_v1, load_host_contract_artifact_from_path,
    load_host_survey_artifact_from_path, ContractDerivationRequestV1,
};
pub use payload_v1::{ExecutionConstraintsV1, HostContractPayloadV1};

pub const CONTRACT_DERIVATION_ERROR_MODEL_ID: &str = "fitctl.contract_derivation.v1";
pub const CONTRACT_DERIVATION_ERROR_MODEL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractDerivationErrorCode {
    PolicyDocumentInvalid,
    PolicyLayerConflict,
    CapabilityClassUnresolved,
    ContractDerivationFailed,
    ContractBasisInvalid,
    PolicyExplanationMissing,
}

impl ContractDerivationErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PolicyDocumentInvalid => "policy_document_invalid",
            Self::PolicyLayerConflict => "policy_layer_conflict",
            Self::CapabilityClassUnresolved => "capability_class_unresolved",
            Self::ContractDerivationFailed => "contract_derivation_failed",
            Self::ContractBasisInvalid => "contract_basis_invalid",
            Self::PolicyExplanationMissing => "policy_explanation_missing",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractDerivationError {
    pub code: ContractDerivationErrorCode,
    pub checkpoint_id: &'static str,
    pub message: String,
    pub error_model_id: &'static str,
    pub error_model_version: u32,
}

impl ContractDerivationError {
    pub(crate) fn new(
        code: ContractDerivationErrorCode,
        checkpoint_id: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            checkpoint_id,
            message: message.into(),
            error_model_id: CONTRACT_DERIVATION_ERROR_MODEL_ID,
            error_model_version: CONTRACT_DERIVATION_ERROR_MODEL_VERSION,
        }
    }
}

impl std::fmt::Display for ContractDerivationError {
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

impl std::error::Error for ContractDerivationError {}
