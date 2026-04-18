// Copyright 2026 fitctl contributors
// SPDX-License-Identifier: Apache-2.0

//! Trust-policy and external-evidence validation helpers used by the verification pipeline.

use super::*;

/// Validate the trust-policy document before signature verification and policy evaluation begin.
pub(crate) fn validate_trust_policy(policy: &TrustPolicyV1) -> Result<(), VerifyError> {
    if policy.schema_id != TRUST_POLICY_SCHEMA_ID {
        return Err(VerifyError::new(
            VerifyErrorCode::TrustPolicyInvalid,
            "trust_policy_load",
            "trust policy schema_id must be fitctl.trust-policy.v1",
        ));
    }
    if policy.schema_version != 1 {
        return Err(VerifyError::new(
            VerifyErrorCode::TrustPolicyInvalid,
            "trust_policy_load",
            "trust policy schema_version must be 1",
        ));
    }
    if is_blank(&policy.policy_id) {
        return Err(VerifyError::new(
            VerifyErrorCode::TrustPolicyInvalid,
            "trust_policy_load",
            "trust policy policy_id must be populated",
        ));
    }
    if policy.accepted_signature_namespaces.is_empty() {
        return Err(VerifyError::new(
            VerifyErrorCode::TrustPolicyInvalid,
            "trust_policy_load",
            "trust policy accepted_signature_namespaces must not be empty",
        ));
    }
    ensure_unique_non_blank(
        &policy.trusted_signers,
        "trusted_signers",
        "trust_policy_load",
        VerifyErrorCode::TrustPolicyInvalid,
    )?;
    ensure_unique_non_blank(
        &policy.accepted_signature_namespaces,
        "accepted_signature_namespaces",
        "trust_policy_load",
        VerifyErrorCode::TrustPolicyInvalid,
    )?;
    ensure_unique_external_evidence_types(
        &policy.accepted_external_evidence_types,
        "accepted_external_evidence_types",
        "trust_policy_load",
    )?;
    if matches!(
        policy.external_evidence_trust_action,
        ExternalEvidenceTrustActionV1::Promote
    ) && policy.max_external_evidence_age_seconds.is_none()
    {
        return Err(VerifyError::new(
            VerifyErrorCode::TrustPolicyInvalid,
            "trust_policy_load",
            "trust policy must declare max_external_evidence_age_seconds when external evidence promotion is enabled",
        ));
    }
    if policy.max_external_evidence_age_seconds == Some(0) {
        return Err(VerifyError::new(
            VerifyErrorCode::TrustPolicyInvalid,
            "trust_policy_load",
            "trust policy max_external_evidence_age_seconds must be greater than zero",
        ));
    }
    Ok(())
}

pub(super) fn validate_local_signer_keyring(
    keyring: &LocalSignerKeyringV1,
) -> Result<(), VerifyError> {
    if keyring.schema_id != LOCAL_SIGNER_KEYRING_SCHEMA_ID {
        return Err(VerifyError::new(
            VerifyErrorCode::TrustPolicyInvalid,
            "trust_policy_load",
            "local signer keyring schema_id must be fitctl.local-signer-keyring.v1",
        ));
    }
    if keyring.schema_version != 1 {
        return Err(VerifyError::new(
            VerifyErrorCode::TrustPolicyInvalid,
            "trust_policy_load",
            "local signer keyring schema_version must be 1",
        ));
    }
    if is_blank(&keyring.keyring_id) {
        return Err(VerifyError::new(
            VerifyErrorCode::TrustPolicyInvalid,
            "trust_policy_load",
            "local signer keyring keyring_id must be populated",
        ));
    }
    ensure_unique_non_blank(
        &keyring.trusted_signers,
        "trusted_signers",
        "trust_policy_load",
        VerifyErrorCode::TrustPolicyInvalid,
    )?;
    Ok(())
}

pub(super) fn validate_trust_policy_bundle(
    bundle: &TrustPolicyBundleV1,
) -> Result<(), VerifyError> {
    if bundle.schema_id != TRUST_POLICY_BUNDLE_SCHEMA_ID {
        return Err(VerifyError::new(
            VerifyErrorCode::TrustPolicyInvalid,
            "trust_policy_load",
            "trust policy bundle schema_id must be fitctl.trust-policy-bundle.v1",
        ));
    }
    if bundle.schema_version != 1 {
        return Err(VerifyError::new(
            VerifyErrorCode::TrustPolicyInvalid,
            "trust_policy_load",
            "trust policy bundle schema_version must be 1",
        ));
    }
    if is_blank(&bundle.bundle_id) {
        return Err(VerifyError::new(
            VerifyErrorCode::TrustPolicyInvalid,
            "trust_policy_load",
            "trust policy bundle bundle_id must be populated",
        ));
    }
    validate_trust_policy(&bundle.policy)?;

    if let Some(keyring) = bundle.local_keyring.as_ref() {
        validate_local_signer_keyring(keyring)?;
        let mut all_signers = bundle
            .policy
            .trusted_signers
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        for signer in &keyring.trusted_signers {
            if !all_signers.insert(signer.clone()) {
                return Err(VerifyError::new(
                    VerifyErrorCode::TrustPolicyInvalid,
                    "trust_policy_load",
                    "trust policy bundle must not duplicate trusted signer ids across the inline policy and local keyring",
                ));
            }
        }
    }

    Ok(())
}

pub(super) fn validate_external_trust_evidence(
    evidence: &ExternalTrustEvidenceV1,
) -> Result<(), VerifyError> {
    if evidence.schema_id != EXTERNAL_TRUST_EVIDENCE_SCHEMA_ID
        || evidence.schema_version != 1
        || is_blank(&evidence.evidence_id)
        || is_blank(&evidence.collected_at)
        || parse_timestamp_seconds(&evidence.collected_at).is_none()
        || is_blank(&evidence.summary)
        || evidence
            .issuer
            .as_ref()
            .is_some_and(|value| is_blank(value))
        || evidence
            .subject_artifact_id
            .as_ref()
            .is_some_and(|value| is_blank(value))
        || evidence
            .subject_artifact_schema_id
            .as_ref()
            .is_some_and(|value| is_blank(value))
        || evidence
            .subject_artifact_semantic_hash
            .as_ref()
            .is_some_and(|value| is_blank(value))
    {
        return Err(VerifyError::new(
            VerifyErrorCode::ExternalTrustEvidenceInvalid,
            "trust_evidence_load",
            "external trust evidence must declare the supported schema, parseable timestamps, and non-blank required fields",
        ));
    }

    if evidence.evidence_type == ExternalTrustEvidenceKindV1::ImportedVerificationBundle
        && (evidence.subject_artifact_id.is_none()
            || evidence.subject_artifact_schema_id.is_none()
            || evidence.subject_artifact_semantic_hash.is_none())
    {
        return Err(VerifyError::new(
            VerifyErrorCode::ExternalTrustEvidenceInvalid,
            "trust_evidence_load",
            "imported verification bundle evidence must retain artifact id, schema, and semantic-hash binding",
        ));
    }

    Ok(())
}

pub(super) fn validate_verification_bundle(
    bundle: &VerificationBundleV1,
) -> Result<(), VerifyError> {
    if bundle.schema_id != VERIFICATION_BUNDLE_SCHEMA_ID
        || bundle.schema_version != 1
        || is_blank(&bundle.bundle_id)
        || is_blank(&bundle.produced_at)
        || parse_timestamp_seconds(&bundle.produced_at).is_none()
        || is_blank(&bundle.artifact_schema_id)
        || is_blank(&bundle.artifact_id)
        || is_blank(&bundle.artifact_semantic_hash)
        || is_blank(&bundle.trust_policy_id)
        || is_blank(&bundle.summary)
    {
        return Err(VerifyError::new(
            VerifyErrorCode::ExternalTrustEvidenceInvalid,
            "verification_bundle_load",
            "verification bundle must declare the supported schema, parseable produced_at, and non-blank required fields",
        ));
    }

    let report = &bundle.verification_report;
    validate_verification_report(report)?;
    if report.outcome != VerifyOutcomeV1::VerifiedAndTrusted
        || !report.accepted_by_policy
        || report.trust_basis.is_none()
        || report.artifact_schema_id != bundle.artifact_schema_id
        || report.artifact_id != bundle.artifact_id
        || report.trust_policy_id != bundle.trust_policy_id
        || is_blank(&report.summary)
    {
        return Err(VerifyError::new(
            VerifyErrorCode::ExternalTrustEvidenceInvalid,
            "verification_bundle_load",
            "verification bundle must embed a positive trusted verification report that matches the top-level bundle identity",
        ));
    }

    ensure_unique_non_blank(
        &bundle.external_trust_evidence_ids,
        "external_trust_evidence_ids",
        "verification_bundle_load",
        VerifyErrorCode::ExternalTrustEvidenceInvalid,
    )?;
    ensure_non_blank_values(
        &bundle.external_trust_evidence_types,
        "external_trust_evidence_types",
        "verification_bundle_load",
        VerifyErrorCode::ExternalTrustEvidenceInvalid,
    )?;

    Ok(())
}

pub(super) fn validate_verification_report(
    report: &VerificationReportV1,
) -> Result<(), VerifyError> {
    if report.schema_id != VERIFY_REPORT_SCHEMA_ID
        || report.schema_version != 1
        || is_blank(&report.verified_at)
        || parse_timestamp_seconds(&report.verified_at).is_none()
        || is_blank(&report.artifact_schema_id)
        || is_blank(&report.artifact_id)
        || is_blank(&report.trust_policy_id)
        || is_blank(&report.summary)
    {
        return Err(VerifyError::new(
            VerifyErrorCode::ExternalTrustEvidenceInvalid,
            "verify_report_emit",
            "verification report must declare the supported schema, verification timestamp, and non-blank required fields",
        ));
    }

    ensure_unique_non_blank(
        &report.external_trust_evidence_ids,
        "external_trust_evidence_ids",
        "verify_report_emit",
        VerifyErrorCode::ExternalTrustEvidenceInvalid,
    )?;
    ensure_non_blank_values(
        &report.external_trust_evidence_types,
        "external_trust_evidence_types",
        "verify_report_emit",
        VerifyErrorCode::ExternalTrustEvidenceInvalid,
    )?;
    ensure_unique_non_blank(
        &report.accepted_external_trust_evidence_ids,
        "accepted_external_trust_evidence_ids",
        "verify_report_emit",
        VerifyErrorCode::ExternalTrustEvidenceInvalid,
    )?;
    ensure_non_blank_values(
        &report.accepted_external_trust_evidence_types,
        "accepted_external_trust_evidence_types",
        "verify_report_emit",
        VerifyErrorCode::ExternalTrustEvidenceInvalid,
    )?;
    validate_external_evidence_assessments(&report.external_trust_evidence_assessments)?;
    validate_verification_report_semantics(report)?;

    Ok(())
}

pub(super) fn validate_verification_report_semantics(
    report: &VerificationReportV1,
) -> Result<(), VerifyError> {
    match report.outcome {
        VerifyOutcomeV1::VerifiedAndTrusted => {
            if !report.accepted_by_policy
                || report.signature_count == 0
                || report.verified_signers.is_empty()
                || report.trust_basis.is_none()
            {
                return Err(VerifyError::new(
                    VerifyErrorCode::ExternalTrustEvidenceInvalid,
                    "verify_report_emit",
                    "verified_and_trusted reports must remain accepted, signed, and backed by a trust basis",
                ));
            }

            match report.trust_basis {
                Some(VerificationTrustBasisV1::TrustedSigners) => {
                    if report.trusted_signers.is_empty() {
                        return Err(VerifyError::new(
                            VerifyErrorCode::ExternalTrustEvidenceInvalid,
                            "verify_report_emit",
                            "trusted-signer verification reports must retain trusted signer ids",
                        ));
                    }
                }
                Some(VerificationTrustBasisV1::ExternalEvidencePromotion) => {
                    if report.accepted_external_trust_evidence_ids.is_empty() {
                        return Err(VerifyError::new(
                            VerifyErrorCode::ExternalTrustEvidenceInvalid,
                            "verify_report_emit",
                            "externally promoted verification reports must retain accepted external evidence ids",
                        ));
                    }
                }
                Some(VerificationTrustBasisV1::UnsignedPolicy) | None => {
                    return Err(VerifyError::new(
                        VerifyErrorCode::ExternalTrustEvidenceInvalid,
                        "verify_report_emit",
                        "verified_and_trusted reports must not use unsigned-policy or missing trust basis",
                    ));
                }
            }
        }
        VerifyOutcomeV1::VerifiedButUntrusted => {
            if report.accepted_by_policy
                || report.signature_count == 0
                || report.verified_signers.is_empty()
                || report.trust_basis.is_some()
            {
                return Err(VerifyError::new(
                    VerifyErrorCode::ExternalTrustEvidenceInvalid,
                    "verify_report_emit",
                    "verified_but_untrusted reports must remain signed, unaccepted, and free of trust basis promotion",
                ));
            }
        }
        VerifyOutcomeV1::Unsigned => {
            if report.signature_count != 0
                || !report.verified_signers.is_empty()
                || !report.trusted_signers.is_empty()
                || !report.untrusted_signers.is_empty()
            {
                return Err(VerifyError::new(
                    VerifyErrorCode::ExternalTrustEvidenceInvalid,
                    "verify_report_emit",
                    "unsigned reports must not retain signature-derived signer state",
                ));
            }
            if report.accepted_by_policy
                && report.trust_basis != Some(VerificationTrustBasisV1::UnsignedPolicy)
            {
                return Err(VerifyError::new(
                    VerifyErrorCode::ExternalTrustEvidenceInvalid,
                    "verify_report_emit",
                    "unsigned reports accepted by policy must use the unsigned_policy trust basis",
                ));
            }
            if !report.accepted_by_policy && report.trust_basis.is_some() {
                return Err(VerifyError::new(
                    VerifyErrorCode::ExternalTrustEvidenceInvalid,
                    "verify_report_emit",
                    "unsigned reports rejected by policy must not retain a trust basis",
                ));
            }
        }
        VerifyOutcomeV1::SignatureInvalid => {
            if report.accepted_by_policy
                || report.signature_count == 0
                || report.trust_basis.is_some()
                || !report.verified_signers.is_empty()
                || !report.trusted_signers.is_empty()
                || !report.untrusted_signers.is_empty()
            {
                return Err(VerifyError::new(
                    VerifyErrorCode::ExternalTrustEvidenceInvalid,
                    "verify_report_emit",
                    "signature_invalid reports must remain unaccepted and must not retain trusted or verified signer state",
                ));
            }
        }
    }

    Ok(())
}

pub(super) fn validate_external_evidence_assessments(
    assessments: &[ExternalTrustEvidenceAssessmentV1],
) -> Result<(), VerifyError> {
    let mut seen = BTreeSet::new();
    for assessment in assessments {
        if is_blank(&assessment.evidence_id) {
            return Err(VerifyError::new(
                VerifyErrorCode::ExternalTrustEvidenceInvalid,
                "verify_report_emit",
                "verification report evidence assessments must not contain blank ids",
            ));
        }
        if !seen.insert(assessment.evidence_id.clone()) {
            return Err(VerifyError::new(
                VerifyErrorCode::ExternalTrustEvidenceInvalid,
                "verify_report_emit",
                "verification report evidence assessments must not contain duplicate ids",
            ));
        }
        if assessment
            .subject_artifact_id
            .as_ref()
            .is_some_and(|value| is_blank(value))
            || assessment
                .subject_artifact_schema_id
                .as_ref()
                .is_some_and(|value| is_blank(value))
            || assessment
                .subject_artifact_semantic_hash
                .as_ref()
                .is_some_and(|value| is_blank(value))
        {
            return Err(VerifyError::new(
                VerifyErrorCode::ExternalTrustEvidenceInvalid,
                "verify_report_emit",
                "verification report evidence assessments must not contain blank subject binding fields",
            ));
        }
    }

    Ok(())
}

pub(super) fn assess_external_trust_evidence(
    external_trust_evidence: &[ExternalTrustEvidenceV1],
    accepted_external_evidence_type_set: &BTreeSet<String>,
    artifact: &ArtifactRecordV1,
    artifact_semantic_hash: &str,
    verified_at_seconds: u64,
    max_external_evidence_age_seconds: Option<u64>,
) -> Result<Vec<ExternalTrustEvidenceAssessmentV1>, VerifyError> {
    let mut assessments = Vec::new();

    for evidence in external_trust_evidence {
        let outcome = if !accepted_external_evidence_type_set
            .contains(evidence.evidence_type.as_str())
        {
            ExternalTrustEvidenceAssessmentOutcomeV1::IgnoredByPolicy
        } else if evidence.subject_artifact_id.is_none() {
            ExternalTrustEvidenceAssessmentOutcomeV1::RejectedMissingSubjectBinding
        } else if evidence.subject_artifact_id.as_deref() != Some(artifact.artifact_id()) {
            ExternalTrustEvidenceAssessmentOutcomeV1::RejectedArtifactIdMismatch
        } else if evidence
            .subject_artifact_schema_id
            .as_deref()
            .is_some_and(|value| value != artifact.schema_id())
        {
            ExternalTrustEvidenceAssessmentOutcomeV1::RejectedArtifactSchemaMismatch
        } else if evidence
            .subject_artifact_semantic_hash
            .as_deref()
            .is_some_and(|value| value != artifact_semantic_hash)
        {
            ExternalTrustEvidenceAssessmentOutcomeV1::RejectedArtifactSemanticMismatch
        } else {
            let collected_at_seconds =
                parse_timestamp_seconds(&evidence.collected_at).ok_or_else(|| {
                    VerifyError::new(
                        VerifyErrorCode::ExternalTrustEvidenceInvalid,
                        "trust_evidence_evaluate",
                        "external trust evidence timestamp must be epoch:<seconds>, unix:<seconds>, or UTC RFC3339",
                    )
                })?;

            if collected_at_seconds > verified_at_seconds {
                ExternalTrustEvidenceAssessmentOutcomeV1::RejectedFutureDated
            } else if max_external_evidence_age_seconds.is_some_and(|max_age| {
                verified_at_seconds.saturating_sub(collected_at_seconds) > max_age
            }) {
                ExternalTrustEvidenceAssessmentOutcomeV1::RejectedStale
            } else {
                ExternalTrustEvidenceAssessmentOutcomeV1::Accepted
            }
        };

        assessments.push(ExternalTrustEvidenceAssessmentV1 {
            evidence_id: evidence.evidence_id.clone(),
            evidence_type: evidence.evidence_type,
            outcome,
            subject_artifact_id: evidence.subject_artifact_id.clone(),
            subject_artifact_schema_id: evidence.subject_artifact_schema_id.clone(),
            subject_artifact_semantic_hash: evidence.subject_artifact_semantic_hash.clone(),
        });
    }

    Ok(assessments)
}

pub(super) fn ensure_unique_non_blank(
    values: &[String],
    field_name: &str,
    checkpoint_id: &'static str,
    code: VerifyErrorCode,
) -> Result<(), VerifyError> {
    let mut seen = BTreeSet::new();
    for value in values {
        if is_blank(value) {
            return Err(VerifyError::new(
                code,
                checkpoint_id,
                format!("{field_name} must not contain blank entries"),
            ));
        }
        if !seen.insert(value.clone()) {
            return Err(VerifyError::new(
                code,
                checkpoint_id,
                format!("{field_name} must not contain duplicates"),
            ));
        }
    }
    Ok(())
}

pub(super) fn ensure_unique_external_evidence_types(
    values: &[ExternalTrustEvidenceKindV1],
    field_name: &str,
    checkpoint_id: &'static str,
) -> Result<(), VerifyError> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value.as_str().to_string()) {
            return Err(VerifyError::new(
                VerifyErrorCode::TrustPolicyInvalid,
                checkpoint_id,
                format!("trust policy field {field_name} must not contain duplicates"),
            ));
        }
    }
    Ok(())
}

pub(super) fn ensure_non_blank_values(
    values: &[String],
    field_name: &str,
    checkpoint_id: &'static str,
    code: VerifyErrorCode,
) -> Result<(), VerifyError> {
    for value in values {
        if is_blank(value) {
            return Err(VerifyError::new(
                code,
                checkpoint_id,
                format!("{field_name} must not contain blank entries"),
            ));
        }
    }
    Ok(())
}

pub(super) fn ensure_unique_external_evidence_ids(
    evidence: &[ExternalTrustEvidenceV1],
) -> Result<(), VerifyError> {
    let mut seen = BTreeSet::new();
    for entry in evidence {
        if !seen.insert(entry.evidence_id.clone()) {
            return Err(VerifyError::new(
                VerifyErrorCode::ExternalTrustEvidenceInvalid,
                "trust_evidence_evaluate",
                "external trust evidence ids must be unique per verification invocation",
            ));
        }
    }
    Ok(())
}
