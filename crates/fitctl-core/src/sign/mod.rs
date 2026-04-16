// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Signature-envelope application and detached semantic-payload signing helpers.
//!
//! Signing is intentionally separate from trust evaluation: this module produces and checks
//! signature material, while the verify module decides whether that material is trusted.

pub mod openssh_v1;

pub use openssh_v1::{
    load_artifact_record_for_signing, sign_artifact_v1, sign_detached_semantic_payload_v1,
    verify_artifact_signatures_v1, verify_detached_semantic_payload_signature_v1,
    DetachedSignatureRequestV1, SignatureRequestV1, PAYLOAD_ENCODING_V1, SIGNATURE_FORMAT_V1,
    SIGNATURE_NAMESPACE_V1,
};

pub const SIGN_ERROR_MODEL_ID: &str = "fitctl.sign.v1";
pub const SIGN_ERROR_MODEL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignErrorCode {
    ArtifactInputInvalid,
    SigningToolUnavailable,
    SigningKeyInvalid,
    SignatureDuplicate,
    SignatureEmitFailed,
    SignatureVerifyFailed,
    SignatureOutputInvalid,
}

impl SignErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ArtifactInputInvalid => "artifact_input_invalid",
            Self::SigningToolUnavailable => "signing_tool_unavailable",
            Self::SigningKeyInvalid => "signing_key_invalid",
            Self::SignatureDuplicate => "signature_duplicate",
            Self::SignatureEmitFailed => "signature_emit_failed",
            Self::SignatureVerifyFailed => "signature_verify_failed",
            Self::SignatureOutputInvalid => "signature_output_invalid",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignError {
    pub code: SignErrorCode,
    pub checkpoint_id: &'static str,
    pub message: String,
    pub error_model_id: &'static str,
    pub error_model_version: u32,
}

impl SignError {
    pub(crate) fn new(
        code: SignErrorCode,
        checkpoint_id: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            checkpoint_id,
            message: message.into(),
            error_model_id: SIGN_ERROR_MODEL_ID,
            error_model_version: SIGN_ERROR_MODEL_VERSION,
        }
    }
}

impl std::fmt::Display for SignError {
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

impl std::error::Error for SignError {}
