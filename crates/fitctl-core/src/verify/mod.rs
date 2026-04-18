// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Signature verification and local trust-policy evaluation.
//!
//! This module decides whether signature material and optional external evidence are acceptable
//! under local policy. It is intentionally separate from the lower-level signing helpers.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

mod validation;

pub(crate) use self::validation::validate_trust_policy as validate_trust_policy_document_v1;
use self::validation::*;

use crate::artifacts::record_v1::{load_artifact_record_from_path, ArtifactRecordV1};
use crate::sign::{verify_artifact_signatures_v1, SignErrorCode};

pub const VERIFY_ERROR_MODEL_ID: &str = "fitctl.verify.v1";
pub const VERIFY_ERROR_MODEL_VERSION: u32 = 1;
pub const TRUST_POLICY_SCHEMA_ID: &str = "fitctl.trust-policy.v1";
pub const TRUST_POLICY_BUNDLE_SCHEMA_ID: &str = "fitctl.trust-policy-bundle.v1";
pub const LOCAL_SIGNER_KEYRING_SCHEMA_ID: &str = "fitctl.local-signer-keyring.v1";
pub const VERIFY_REPORT_SCHEMA_ID: &str = "fitctl.verify.report.v1";
pub const EXTERNAL_TRUST_EVIDENCE_SCHEMA_ID: &str = "fitctl.external-trust-evidence.v1";
pub const VERIFICATION_BUNDLE_SCHEMA_ID: &str = "fitctl.verification-bundle.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyErrorCode {
    VerifyInputInvalid,
    TrustPolicyInvalid,
    ExternalTrustEvidenceInvalid,
}

impl VerifyErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VerifyInputInvalid => "verify_input_invalid",
            Self::TrustPolicyInvalid => "trust_policy_invalid",
            Self::ExternalTrustEvidenceInvalid => "external_trust_evidence_invalid",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyError {
    pub code: VerifyErrorCode,
    pub checkpoint_id: &'static str,
    pub message: String,
    pub error_model_id: &'static str,
    pub error_model_version: u32,
}

impl VerifyError {
    fn new(code: VerifyErrorCode, checkpoint_id: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            checkpoint_id,
            message: message.into(),
            error_model_id: VERIFY_ERROR_MODEL_ID,
            error_model_version: VERIFY_ERROR_MODEL_VERSION,
        }
    }
}

impl std::fmt::Display for VerifyError {
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

impl std::error::Error for VerifyError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsignedActionV1 {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UntrustedSignerActionV1 {
    Warn,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ExternalEvidenceTrustActionV1 {
    #[default]
    Ignore,
    Promote,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustPolicyV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub policy_id: String,
    pub trusted_signers: Vec<String>,
    pub accepted_signature_namespaces: Vec<String>,
    pub unsigned_action: UnsignedActionV1,
    pub untrusted_signer_action: UntrustedSignerActionV1,
    pub allow_self_signed: bool,
    #[serde(default)]
    pub accepted_external_evidence_types: Vec<ExternalTrustEvidenceKindV1>,
    #[serde(default)]
    pub external_evidence_trust_action: ExternalEvidenceTrustActionV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_external_evidence_age_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalSignerKeyringV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub keyring_id: String,
    pub trusted_signers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustPolicyBundleV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub bundle_id: String,
    pub policy: TrustPolicyV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_keyring: Option<LocalSignerKeyringV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyOutcomeV1 {
    VerifiedAndTrusted,
    VerifiedButUntrusted,
    Unsigned,
    SignatureInvalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationTrustBasisV1 {
    TrustedSigners,
    ExternalEvidencePromotion,
    UnsignedPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalTrustEvidenceKindV1 {
    TpmQuote,
    ImaMeasurementSet,
    ImportedVerificationBundle,
}

impl ExternalTrustEvidenceKindV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TpmQuote => "tpm_quote",
            Self::ImaMeasurementSet => "ima_measurement_set",
            Self::ImportedVerificationBundle => "imported_verification_bundle",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalTrustEvidenceAssessmentOutcomeV1 {
    Accepted,
    IgnoredByPolicy,
    RejectedFutureDated,
    RejectedStale,
    RejectedMissingSubjectBinding,
    RejectedArtifactIdMismatch,
    RejectedArtifactSchemaMismatch,
    RejectedArtifactSemanticMismatch,
}

impl ExternalTrustEvidenceAssessmentOutcomeV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::IgnoredByPolicy => "ignored_by_policy",
            Self::RejectedFutureDated => "rejected_future_dated",
            Self::RejectedStale => "rejected_stale",
            Self::RejectedMissingSubjectBinding => "rejected_missing_subject_binding",
            Self::RejectedArtifactIdMismatch => "rejected_artifact_id_mismatch",
            Self::RejectedArtifactSchemaMismatch => "rejected_artifact_schema_mismatch",
            Self::RejectedArtifactSemanticMismatch => "rejected_artifact_semantic_mismatch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalTrustEvidenceAssessmentV1 {
    pub evidence_id: String,
    pub evidence_type: ExternalTrustEvidenceKindV1,
    pub outcome: ExternalTrustEvidenceAssessmentOutcomeV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_artifact_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_artifact_schema_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_artifact_semantic_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationReportV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub verified_at: String,
    pub outcome: VerifyOutcomeV1,
    pub accepted_by_policy: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_basis: Option<VerificationTrustBasisV1>,
    pub artifact_schema_id: String,
    pub artifact_id: String,
    pub trust_policy_id: String,
    pub signature_count: usize,
    pub verified_signature_namespaces: Vec<String>,
    pub verified_signers: Vec<String>,
    pub trusted_signers: Vec<String>,
    pub untrusted_signers: Vec<String>,
    #[serde(default)]
    pub external_trust_evidence_ids: Vec<String>,
    #[serde(default)]
    pub external_trust_evidence_types: Vec<String>,
    #[serde(default)]
    pub accepted_external_trust_evidence_ids: Vec<String>,
    #[serde(default)]
    pub accepted_external_trust_evidence_types: Vec<String>,
    #[serde(default)]
    pub external_trust_evidence_assessments: Vec<ExternalTrustEvidenceAssessmentV1>,
    pub warnings: Vec<String>,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationBundleV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub bundle_id: String,
    pub produced_at: String,
    pub artifact_schema_id: String,
    pub artifact_id: String,
    pub artifact_semantic_hash: String,
    pub trust_policy_id: String,
    pub verification_report: VerificationReportV1,
    #[serde(default)]
    pub external_trust_evidence_ids: Vec<String>,
    #[serde(default)]
    pub external_trust_evidence_types: Vec<String>,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalTrustEvidenceV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub evidence_id: String,
    pub evidence_type: ExternalTrustEvidenceKindV1,
    pub collected_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_artifact_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_artifact_schema_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_artifact_semantic_hash: Option<String>,
    pub summary: String,
}

pub fn load_artifact_record_for_verification(path: &Path) -> Result<ArtifactRecordV1, VerifyError> {
    load_artifact_record_from_path(path).map_err(|error| {
        VerifyError::new(
            VerifyErrorCode::VerifyInputInvalid,
            "verify_load",
            error.message,
        )
    })
}

pub fn load_trust_policy_from_path(path: &Path) -> Result<TrustPolicyV1, VerifyError> {
    let raw = load_json_value_from_path(
        path,
        VerifyErrorCode::TrustPolicyInvalid,
        "trust_policy_load",
        "trust policy",
    )?;
    let schema_id = raw
        .get("schema_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            VerifyError::new(
                VerifyErrorCode::TrustPolicyInvalid,
                "trust_policy_load",
                format!("trust policy {} must include schema_id", path.display()),
            )
        })?;

    match schema_id {
        TRUST_POLICY_SCHEMA_ID => {
            let policy: TrustPolicyV1 = serde_json::from_value(raw).map_err(|error| {
                VerifyError::new(
                    VerifyErrorCode::TrustPolicyInvalid,
                    "trust_policy_load",
                    format!("failed to decode trust policy {}: {error}", path.display()),
                )
            })?;
            validate_trust_policy(&policy)?;
            Ok(policy)
        }
        TRUST_POLICY_BUNDLE_SCHEMA_ID => {
            let bundle: TrustPolicyBundleV1 = serde_json::from_value(raw).map_err(|error| {
                VerifyError::new(
                    VerifyErrorCode::TrustPolicyInvalid,
                    "trust_policy_load",
                    format!(
                        "failed to decode trust policy bundle {}: {error}",
                        path.display()
                    ),
                )
            })?;
            validate_trust_policy_bundle(&bundle)?;
            Ok(resolve_trust_policy_bundle(bundle))
        }
        _ => Err(VerifyError::new(
            VerifyErrorCode::TrustPolicyInvalid,
            "trust_policy_load",
            format!("unsupported trust policy schema_id {schema_id}"),
        )),
    }
}

pub fn load_external_trust_evidence_from_path(
    path: &Path,
) -> Result<ExternalTrustEvidenceV1, VerifyError> {
    let raw = load_json_value_from_path(
        path,
        VerifyErrorCode::ExternalTrustEvidenceInvalid,
        "trust_evidence_load",
        "external trust evidence",
    )?;
    let schema_id = raw
        .get("schema_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            VerifyError::new(
                VerifyErrorCode::ExternalTrustEvidenceInvalid,
                "trust_evidence_load",
                format!(
                    "external trust evidence {} must include schema_id",
                    path.display()
                ),
            )
        })?;

    match schema_id {
        EXTERNAL_TRUST_EVIDENCE_SCHEMA_ID => {
            let document: ExternalTrustEvidenceV1 =
                serde_json::from_value(raw).map_err(|error| {
                    VerifyError::new(
                        VerifyErrorCode::ExternalTrustEvidenceInvalid,
                        "trust_evidence_load",
                        format!(
                            "failed to decode external trust evidence {}: {error}",
                            path.display()
                        ),
                    )
                })?;
            validate_external_trust_evidence(&document)?;
            Ok(document)
        }
        VERIFICATION_BUNDLE_SCHEMA_ID => {
            let bundle: VerificationBundleV1 = serde_json::from_value(raw).map_err(|error| {
                VerifyError::new(
                    VerifyErrorCode::ExternalTrustEvidenceInvalid,
                    "trust_evidence_load",
                    format!(
                        "failed to decode verification bundle {}: {error}",
                        path.display()
                    ),
                )
            })?;
            validate_verification_bundle(&bundle)?;
            Ok(verification_bundle_as_external_evidence_v1(&bundle))
        }
        _ => Err(VerifyError::new(
            VerifyErrorCode::ExternalTrustEvidenceInvalid,
            "trust_evidence_load",
            format!("unsupported external trust evidence schema_id {schema_id}"),
        )),
    }
}

pub fn load_verification_bundle_from_path(
    path: &Path,
) -> Result<VerificationBundleV1, VerifyError> {
    let raw = load_json_value_from_path(
        path,
        VerifyErrorCode::ExternalTrustEvidenceInvalid,
        "verification_bundle_load",
        "verification bundle",
    )?;
    let bundle: VerificationBundleV1 = serde_json::from_value(raw).map_err(|error| {
        VerifyError::new(
            VerifyErrorCode::ExternalTrustEvidenceInvalid,
            "verification_bundle_load",
            format!(
                "failed to decode verification bundle {}: {error}",
                path.display()
            ),
        )
    })?;
    validate_verification_bundle(&bundle)?;
    Ok(bundle)
}

pub fn validate_verification_bundle_v1(bundle: &VerificationBundleV1) -> Result<(), VerifyError> {
    validate_verification_bundle(bundle)
}

pub fn build_verification_bundle_v1(
    artifact: &ArtifactRecordV1,
    report: &VerificationReportV1,
    produced_at: impl Into<String>,
) -> Result<VerificationBundleV1, VerifyError> {
    // Freeze a verification decision next to the artifact identity so later workflows can import
    // that decision as external evidence without re-running local verification.
    validate_verification_report(report)?;
    let produced_at = produced_at.into();
    let semantic_hash = artifact.semantic_hash_hex().map_err(|error| {
        VerifyError::new(
            VerifyErrorCode::VerifyInputInvalid,
            "verification_bundle_build",
            error.message,
        )
    })?;

    let bundle = VerificationBundleV1 {
        schema_id: VERIFICATION_BUNDLE_SCHEMA_ID.to_string(),
        schema_version: 1,
        bundle_id: format!(
            "verification-bundle-{}-{}",
            artifact.artifact_id(),
            report.trust_policy_id
        ),
        produced_at,
        artifact_schema_id: artifact.schema_id().to_string(),
        artifact_id: artifact.artifact_id().to_string(),
        artifact_semantic_hash: semantic_hash,
        trust_policy_id: report.trust_policy_id.clone(),
        verification_report: report.clone(),
        external_trust_evidence_ids: report.external_trust_evidence_ids.clone(),
        external_trust_evidence_types: report.external_trust_evidence_types.clone(),
        summary: report.summary.clone(),
    };
    validate_verification_bundle(&bundle)?;
    Ok(bundle)
}

/// Default local verification path: use the current time and no imported external evidence.
pub fn verify_artifact_with_policy_v1(
    artifact: &ArtifactRecordV1,
    policy: &TrustPolicyV1,
) -> Result<VerificationReportV1, VerifyError> {
    verify_artifact_with_policy_and_evidence_at_v1(artifact, policy, &[], &current_epoch_marker())
}

pub fn verify_artifact_with_policy_and_evidence_v1(
    artifact: &ArtifactRecordV1,
    policy: &TrustPolicyV1,
    external_trust_evidence: &[ExternalTrustEvidenceV1],
) -> Result<VerificationReportV1, VerifyError> {
    verify_artifact_with_policy_and_evidence_at_v1(
        artifact,
        policy,
        external_trust_evidence,
        &current_epoch_marker(),
    )
}

pub fn verify_artifact_with_policy_and_evidence_at_v1(
    artifact: &ArtifactRecordV1,
    policy: &TrustPolicyV1,
    external_trust_evidence: &[ExternalTrustEvidenceV1],
    verified_at: &str,
) -> Result<VerificationReportV1, VerifyError> {
    // Verification is staged deliberately: validate inputs, verify signatures against semantic
    // bytes, then apply local trust policy and optional external evidence promotion.
    validate_trust_policy(policy)?;
    for evidence in external_trust_evidence {
        validate_external_trust_evidence(evidence)?;
    }
    ensure_unique_external_evidence_ids(external_trust_evidence)?;
    let verified_at_seconds = parse_timestamp_seconds(verified_at).ok_or_else(|| {
        VerifyError::new(
            VerifyErrorCode::VerifyInputInvalid,
            "trust_evidence_evaluate",
            "verify timestamp must be epoch:<seconds>, unix:<seconds>, or UTC RFC3339",
        )
    })?;

    match verify_artifact_signatures_v1(artifact) {
        Ok(()) => {}
        Err(error) if error.code == SignErrorCode::ArtifactInputInvalid => {
            return Err(VerifyError::new(
                VerifyErrorCode::VerifyInputInvalid,
                "signature_verify",
                error.message,
            ));
        }
        Err(error) => {
            return Ok(signature_invalid_report(
                artifact,
                policy,
                artifact.envelope().signatures.len(),
                error.message,
                external_trust_evidence,
                verified_at,
            ));
        }
    }

    let signatures = &artifact.envelope().signatures;
    if signatures.is_empty() {
        return Ok(unsigned_report(
            artifact,
            policy,
            external_trust_evidence,
            verified_at,
        ));
    }

    let trusted_signer_set: BTreeSet<_> = policy.trusted_signers.iter().cloned().collect();
    let accepted_namespace_set: BTreeSet<_> = policy
        .accepted_signature_namespaces
        .iter()
        .cloned()
        .collect();
    let accepted_external_evidence_type_set: BTreeSet<_> = policy
        .accepted_external_evidence_types
        .iter()
        .map(|kind| kind.as_str().to_string())
        .collect();
    let artifact_semantic_hash = artifact.semantic_hash_hex().map_err(|error| {
        VerifyError::new(
            VerifyErrorCode::VerifyInputInvalid,
            "trust_evidence_evaluate",
            error.message,
        )
    })?;

    let mut verified_signers = BTreeSet::new();
    let mut verified_signature_namespaces = BTreeSet::new();
    let mut disallowed_namespaces = BTreeSet::new();
    let mut saw_self_signed = false;

    for signature in signatures {
        verified_signers.insert(signature.key_id.clone());
        let namespace = signature
            .signature_namespace
            .as_deref()
            .unwrap_or_default()
            .to_string();
        if !namespace.is_empty() {
            verified_signature_namespaces.insert(namespace.clone());
            if !accepted_namespace_set.contains(&namespace) {
                disallowed_namespaces.insert(namespace);
            }
        }
        if signature.signer_identity.as_deref() == Some(signature.key_id.as_str()) {
            saw_self_signed = true;
        }
    }

    let mut trusted_signers = Vec::new();
    let mut untrusted_signers = Vec::new();
    for signer in verified_signers.iter() {
        if trusted_signer_set.contains(signer) {
            trusted_signers.push(signer.clone());
        } else {
            untrusted_signers.push(signer.clone());
        }
    }

    let self_signed_not_allowed = saw_self_signed && !policy.allow_self_signed;
    let external_trust_evidence_assessments = assess_external_trust_evidence(
        external_trust_evidence,
        &accepted_external_evidence_type_set,
        artifact,
        &artifact_semantic_hash,
        verified_at_seconds,
        policy.max_external_evidence_age_seconds,
    )?;
    let accepted_external_evidence = external_trust_evidence
        .iter()
        .zip(external_trust_evidence_assessments.iter())
        .filter_map(|(evidence, assessment)| {
            matches!(
                assessment.outcome,
                ExternalTrustEvidenceAssessmentOutcomeV1::Accepted
            )
            .then_some(evidence)
        })
        .collect::<Vec<_>>();
    let rejected_or_ignored_assessments = external_trust_evidence_assessments
        .iter()
        .filter(|assessment| {
            !matches!(
                assessment.outcome,
                ExternalTrustEvidenceAssessmentOutcomeV1::Accepted
            )
        })
        .collect::<Vec<_>>();

    let mut warnings = Vec::new();
    if !untrusted_signers.is_empty() {
        warnings.push(format!(
            "verified signer set is not fully trusted by policy: {}",
            untrusted_signers.join(", ")
        ));
    }
    if !disallowed_namespaces.is_empty() {
        warnings.push(format!(
            "signature namespaces are outside the policy allowlist: {}",
            disallowed_namespaces
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if self_signed_not_allowed {
        warnings
            .push("self-signed artefacts are not accepted by the current trust policy".to_string());
    }
    if !accepted_external_evidence.is_empty()
        && matches!(
            policy.external_evidence_trust_action,
            ExternalEvidenceTrustActionV1::Ignore
        )
    {
        warnings.push(
            "accepted external trust evidence is present but policy does not permit trust promotion"
                .to_string(),
        );
    }
    if !rejected_or_ignored_assessments.is_empty() {
        warnings.push(format!(
            "external trust evidence not accepted for promotion: {}",
            rejected_or_ignored_assessments
                .iter()
                .map(|assessment| {
                    format!("{}:{}", assessment.evidence_id, assessment.outcome.as_str())
                })
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    let namespace_rules_satisfied = disallowed_namespaces.is_empty();
    let fully_trusted = untrusted_signers.is_empty()
        && namespace_rules_satisfied
        && !self_signed_not_allowed
        && !verified_signers.is_empty();
    let externally_promoted = !fully_trusted
        && namespace_rules_satisfied
        && !self_signed_not_allowed
        && !accepted_external_evidence.is_empty()
        && matches!(
            policy.external_evidence_trust_action,
            ExternalEvidenceTrustActionV1::Promote
        );
    let accepted_by_policy = if fully_trusted || externally_promoted {
        true
    } else if self_signed_not_allowed || !namespace_rules_satisfied {
        false
    } else {
        matches!(
            policy.untrusted_signer_action,
            UntrustedSignerActionV1::Warn
        )
    };

    let report = VerificationReportV1 {
        schema_id: VERIFY_REPORT_SCHEMA_ID.to_string(),
        schema_version: 1,
        verified_at: verified_at.to_string(),
        outcome: if fully_trusted || externally_promoted {
            VerifyOutcomeV1::VerifiedAndTrusted
        } else {
            VerifyOutcomeV1::VerifiedButUntrusted
        },
        accepted_by_policy,
        trust_basis: if fully_trusted {
            Some(VerificationTrustBasisV1::TrustedSigners)
        } else if externally_promoted {
            Some(VerificationTrustBasisV1::ExternalEvidencePromotion)
        } else {
            None
        },
        artifact_schema_id: artifact.schema_id().to_string(),
        artifact_id: artifact.artifact_id().to_string(),
        trust_policy_id: policy.policy_id.clone(),
        signature_count: signatures.len(),
        verified_signature_namespaces: verified_signature_namespaces.into_iter().collect(),
        verified_signers: verified_signers.into_iter().collect(),
        trusted_signers,
        untrusted_signers,
        external_trust_evidence_ids: external_trust_evidence
            .iter()
            .map(|evidence| evidence.evidence_id.clone())
            .collect(),
        external_trust_evidence_types: external_trust_evidence
            .iter()
            .map(|evidence| evidence.evidence_type.as_str().to_string())
            .collect(),
        accepted_external_trust_evidence_ids: accepted_external_evidence
            .iter()
            .map(|evidence| evidence.evidence_id.clone())
            .collect(),
        accepted_external_trust_evidence_types: accepted_external_evidence
            .iter()
            .map(|evidence| evidence.evidence_type.as_str().to_string())
            .collect(),
        external_trust_evidence_assessments,
        warnings,
        summary: if fully_trusted {
            "all signatures verified and the signer set is trusted by local policy".to_string()
        } else if externally_promoted {
            "signatures verified and local policy promoted trust via accepted external evidence"
                .to_string()
        } else if accepted_by_policy {
            "signatures verified but local trust policy treats the untrusted signer set as advisory"
                .to_string()
        } else {
            "signatures verified but local trust policy does not accept the signer set".to_string()
        },
    };
    validate_verification_report(&report)?;
    Ok(report)
}

fn verification_bundle_as_external_evidence_v1(
    bundle: &VerificationBundleV1,
) -> ExternalTrustEvidenceV1 {
    // Imported verification bundles enter the same assessment path as other external evidence so
    // trust promotion rules stay uniform.
    ExternalTrustEvidenceV1 {
        schema_id: EXTERNAL_TRUST_EVIDENCE_SCHEMA_ID.to_string(),
        schema_version: 1,
        evidence_id: bundle.bundle_id.clone(),
        evidence_type: ExternalTrustEvidenceKindV1::ImportedVerificationBundle,
        collected_at: bundle.produced_at.clone(),
        issuer: Some(bundle.trust_policy_id.clone()),
        subject_artifact_id: Some(bundle.artifact_id.clone()),
        subject_artifact_schema_id: Some(bundle.artifact_schema_id.clone()),
        subject_artifact_semantic_hash: Some(bundle.artifact_semantic_hash.clone()),
        summary: bundle.summary.clone(),
    }
}

fn resolve_trust_policy_bundle(bundle: TrustPolicyBundleV1) -> TrustPolicyV1 {
    let mut policy = bundle.policy;

    if let Some(keyring) = bundle.local_keyring {
        let mut trusted_signers = policy.trusted_signers.into_iter().collect::<BTreeSet<_>>();
        trusted_signers.extend(keyring.trusted_signers);
        policy.trusted_signers = trusted_signers.into_iter().collect();
    }

    policy
}

fn load_json_value_from_path(
    path: &Path,
    code: VerifyErrorCode,
    checkpoint_id: &'static str,
    document_kind: &str,
) -> Result<Value, VerifyError> {
    let text = fs::read_to_string(path).map_err(|error| {
        VerifyError::new(
            code,
            checkpoint_id,
            format!("failed to read {document_kind} {}: {error}", path.display()),
        )
    })?;
    serde_json::from_str(&text).map_err(|error| {
        VerifyError::new(
            code,
            checkpoint_id,
            format!(
                "failed to decode {document_kind} {}: {error}",
                path.display()
            ),
        )
    })
}

fn unsigned_report(
    artifact: &ArtifactRecordV1,
    policy: &TrustPolicyV1,
    external_trust_evidence: &[ExternalTrustEvidenceV1],
    verified_at: &str,
) -> VerificationReportV1 {
    // Unsigned artifacts remain explicit outcomes rather than hard errors so local policy can
    // choose between permissive and fail-closed handling.
    let accepted_by_policy = matches!(policy.unsigned_action, UnsignedActionV1::Allow);
    VerificationReportV1 {
        schema_id: VERIFY_REPORT_SCHEMA_ID.to_string(),
        schema_version: 1,
        verified_at: verified_at.to_string(),
        outcome: VerifyOutcomeV1::Unsigned,
        accepted_by_policy,
        trust_basis: if accepted_by_policy {
            Some(VerificationTrustBasisV1::UnsignedPolicy)
        } else {
            None
        },
        artifact_schema_id: artifact.schema_id().to_string(),
        artifact_id: artifact.artifact_id().to_string(),
        trust_policy_id: policy.policy_id.clone(),
        signature_count: 0,
        verified_signature_namespaces: vec![],
        verified_signers: vec![],
        trusted_signers: vec![],
        untrusted_signers: vec![],
        external_trust_evidence_ids: external_trust_evidence
            .iter()
            .map(|evidence| evidence.evidence_id.clone())
            .collect(),
        external_trust_evidence_types: external_trust_evidence
            .iter()
            .map(|evidence| evidence.evidence_type.as_str().to_string())
            .collect(),
        accepted_external_trust_evidence_ids: vec![],
        accepted_external_trust_evidence_types: vec![],
        external_trust_evidence_assessments: vec![],
        warnings: if accepted_by_policy {
            vec![
                "artifact is unsigned but the current trust policy allows unsigned input"
                    .to_string(),
            ]
        } else {
            vec![
                "artifact is unsigned and the current trust policy rejects unsigned input"
                    .to_string(),
            ]
        },
        summary: if accepted_by_policy {
            "artifact is unsigned and allowed by local trust policy".to_string()
        } else {
            "artifact is unsigned and not accepted by local trust policy".to_string()
        },
    }
}

fn signature_invalid_report(
    artifact: &ArtifactRecordV1,
    policy: &TrustPolicyV1,
    signature_count: usize,
    message: String,
    external_trust_evidence: &[ExternalTrustEvidenceV1],
    verified_at: &str,
) -> VerificationReportV1 {
    // Cryptographically invalid signatures never become a trusted-but-warning state.
    VerificationReportV1 {
        schema_id: VERIFY_REPORT_SCHEMA_ID.to_string(),
        schema_version: 1,
        verified_at: verified_at.to_string(),
        outcome: VerifyOutcomeV1::SignatureInvalid,
        accepted_by_policy: false,
        trust_basis: None,
        artifact_schema_id: artifact.schema_id().to_string(),
        artifact_id: artifact.artifact_id().to_string(),
        trust_policy_id: policy.policy_id.clone(),
        signature_count,
        verified_signature_namespaces: vec![],
        verified_signers: vec![],
        trusted_signers: vec![],
        untrusted_signers: vec![],
        external_trust_evidence_ids: external_trust_evidence
            .iter()
            .map(|evidence| evidence.evidence_id.clone())
            .collect(),
        external_trust_evidence_types: external_trust_evidence
            .iter()
            .map(|evidence| evidence.evidence_type.as_str().to_string())
            .collect(),
        accepted_external_trust_evidence_ids: vec![],
        accepted_external_trust_evidence_types: vec![],
        external_trust_evidence_assessments: vec![],
        warnings: vec![message.clone()],
        summary: message,
    }
}

fn current_epoch_marker() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after the Unix epoch")
        .as_secs();
    format!("epoch:{seconds}")
}

fn parse_timestamp_seconds(value: &str) -> Option<u64> {
    if let Some(rest) = value
        .strip_prefix("epoch:")
        .or_else(|| value.strip_prefix("unix:"))
    {
        return rest.parse::<u64>().ok();
    }
    parse_rfc3339_utc_seconds(value)
}

fn parse_rfc3339_utc_seconds(value: &str) -> Option<u64> {
    let year = value.get(0..4)?.parse::<i32>().ok()?;
    let month = value.get(5..7)?.parse::<u32>().ok()?;
    let day = value.get(8..10)?.parse::<u32>().ok()?;
    let hour = value.get(11..13)?.parse::<u32>().ok()?;
    let minute = value.get(14..16)?.parse::<u32>().ok()?;
    let second = value.get(17..19)?.parse::<u32>().ok()?;

    if value.get(4..5) != Some("-")
        || value.get(7..8) != Some("-")
        || value.get(10..11) != Some("T")
        || value.get(13..14) != Some(":")
        || value.get(16..17) != Some(":")
        || value.get(19..20) != Some("Z")
        || value.len() != 20
    {
        return None;
    }

    let days = days_from_civil(year, month, day)?;
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(u64::from(hour).checked_mul(3_600)?)?
        .checked_add(u64::from(minute).checked_mul(60)?)?
        .checked_add(u64::from(second))?;
    Some(seconds)
}

fn days_from_civil(year: i32, month: u32, day: u32) -> Option<u64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    let adjusted_year = year - i32::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year / 400
    } else {
        (adjusted_year - 399) / 400
    };
    let year_of_era = adjusted_year - era * 400;
    let month_index = i32::try_from(month).ok()?;
    let day_index = i32::try_from(day).ok()?;
    let day_of_year =
        (153 * (month_index + if month > 2 { -3 } else { 9 }) + 2) / 5 + day_index - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days_since_unix_epoch = i64::from(era) * 146_097 + i64::from(day_of_era) - 719_468;
    u64::try_from(days_since_unix_epoch).ok()
}

fn is_blank(value: &str) -> bool {
    value.trim().is_empty()
}
